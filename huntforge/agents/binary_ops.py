"""二进制漏洞挖掘 Agent：静态分析（魔数/strings/危险函数）→ LLM 审计（可选增强）。

目标形态：文件路径（平台下发）或 URL（下载）。
动态分析（gdb/fuzz）在工具可用时启用；8核16G 预算内默认短周期静态先行。
规则引擎零 LLM 可跑通；配置了模型 key 时用 deep tier 做反汇编级审计。
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

from ..core.state import StateDB
from ..web.common import extract_flag
from ..web.gate import evaluate_and_persist

log = logging.getLogger("huntforge.binary")

# 危险函数特征（strings/符号表出现即提示审计）
DANGEROUS_FUNCS = ["strcpy", "strcat", "sprintf", "gets", "scanf", "memcpy",
                   "system", "popen", "exec", "eval", "alloca", "malloc",
                   "free", "setuid", "strncpy", "printf"]

# 漏洞模式启发规则（函数名 → 建议判定）
HEURISTICS: list[tuple[str, str, str]] = [
    ("strcpy", "栈溢出风险", "strcpy 无边界复制，可导致栈缓冲区溢出"),
    ("strcat", "栈溢出风险", "strcat 拼接无边界检查"),
    ("sprintf", "格式化字符串/溢出风险", "sprintf 无长度限制"),
    ("gets", "缓冲区溢出", "gets 读取无边界"),
    ("system", "命令执行面", "system 调用存在命令注入面（参数来源需审计）"),
    ("popen", "命令执行面", "popen 执行外部命令"),
    ("eval", "代码执行面", "eval 动态执行，参数来源需审计"),
]


class BinaryOpsAgent:
    def __init__(self, db: StateDB, timebox: float = 600.0,
                 submitter: Optional[Callable[[str, str], None]] = None,
                 gateway=None, planner=None):
        self.db = db
        self.timebox = timebox
        self.submitter = submitter
        self.gateway = gateway   # 旧接口保留兼容
        self.planner = planner   # 新：PentestPlanner（主路径）
        self._started = 0.0

    def run(self, task: dict) -> dict:
        ch = self.db.get_challenge(task["challenge_id"])
        if ch is None:
            return {"ok": False, "outcome": "no_challenge"}
        self._started = time.time()
        target = ch.get("target") or ""

        tmp = tempfile.mkdtemp(prefix="hf-bin-")
        try:
            path = self._acquire(target, tmp)
            if path is None:
                self.db.event("task.info", "challenge", ch["id"],
                              {"msg": f"binary-ops: 无法获取目标 {target[:60]}"})
                return {"ok": True, "outcome": "acquire_failed"}
            info = self._analyze(Path(path))
            candidates = self._heuristic_candidates(info, ch["id"])

            # LLM 深度审计：规则未直接命中 flag 时才调用（避免无谓消耗预算）
            llm_used = False
            if self.planner and self._time_left() > 10 and not any(c.get("value") for c in candidates):
                llm_used = True
                llm_result = self.planner.audit_binary(
                    info.get("format", "unknown"),
                    info.get("strings", []),
                    info.get("dangerous", []),
                )
                candidates.extend(self._process_llm_result(llm_result))
                if llm_result:
                    self.db.event("llm.binary_audit", "challenge", ch["id"],
                                  {"flag_found": llm_result.get("flag_found"),
                                   "encoded": llm_result.get("encoded_hint")})

            findings = self._persist(ch, task["id"], candidates)
            return {
                "ok": True,
                "outcome": "flag_found" if findings["flags"] else "analyzed",
                "format": info.get("format"),
                "strings_found": len(info.get("strings", [])),
                "dangerous": info.get("dangerous", []),
                "llm_used": llm_used,
                **findings,
            }
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _process_llm_result(self, result: dict) -> list[dict]:
        """把 LLM 审计结果转换为 finding candidates。"""
        if not result:
            return []
        out: list[dict] = []
        # 1) LLM 直接给出 flag
        flag = result.get("flag_found") or result.get("decoded_flag")
        flag_value = extract_flag(flag or "")
        if flag_value:
            out.append({
                "type": "flag_llm_decoded", "confidence": 0.90,
                "request": "LLM binary audit",
                "response": flag,
                "impact": "LLM 从字符串中识别/解码出 flag",
                "value": flag_value,
                "confirm": {"note": result.get("encoded_hint", "direct")},
            })
        # 2) LLM 给出漏洞路径
        hint = result.get("exploit_hint") or result.get("vuln_path", "")
        if hint:
            out.append({
                "type": "binary_vuln_path", "confidence": 0.5,
                "request": "LLM static audit",
                "response": hint[:400],
                "impact": hint[:200],
                "confirm": {"note": "LLM 深度分析"},
            })
        return out

    # ---------- 获取目标 ----------
    def _acquire(self, target: str, tmp: str) -> Optional[str]:
        if target.startswith(("http://", "https://")):
            import requests
            try:
                r = requests.get(target, timeout=15, verify=False)
                if r.status_code != 200:
                    return None
                p = Path(tmp) / "target.bin"
                p.write_bytes(r.content)
                return str(p)
            except requests.RequestException:
                return None
        if Path(target).is_file():
            return target
        # 相对工作目录
        if Path(target).exists():
            return target
        return None

    # ---------- 静态分析 ----------
    def _analyze(self, path: Path) -> dict:
        data = path.read_bytes()
        info: dict = {"format": _identify_format(data), "size": len(data),
                      "strings": [], "dangerous": [], "magic": data[:16].hex()}
        info["strings"] = _extract_strings(data)
        joined = "\n".join(info["strings"]).lower()
        info["dangerous"] = sorted({f for f in DANGEROUS_FUNCS if f in joined})
        # 工具链（可用时增强）
        for tool in ("file", "readelf", "objdump", "checksec"):
            if shutil.which(tool):
                info.setdefault("tools", []).append(tool)
        if shutil.which("file"):
            try:
                r = subprocess.run(["file", str(path)], capture_output=True,
                                   text=True, timeout=10)
                info["file_out"] = r.stdout.strip()[:300]
            except (subprocess.SubprocessError, OSError):
                pass
        return info

    def _heuristic_candidates(self, info: dict, challenge_id: str) -> list[dict]:
        out = []
        # 1) strings 里的 flag
        flag = None
        for s in info.get("strings", []):
            flag = extract_flag(s)
            if flag:
                break
        if flag:
            out.append({"type": "flag_in_strings", "confidence": 0.95,
                        "request": "strings 扫描", "response": flag,
                        "impact": "二进制文件 strings 中直接包含 flag",
                        "value": flag, "confirm": {"note": "strings 提取命中"}})
            return out
        # 2) 危险函数启发
        for fn in info.get("dangerous", []):
            for name, risk, desc in HEURISTICS:
                if fn == name:
                    out.append({"type": f"dangerous:{fn}", "confidence": 0.6,
                                "request": f"符号/字符串扫描 {fn}",
                                "response": fn,
                                "impact": f"{risk}：{desc}",
                                "confirm": {"note": f"静态特征 {fn} 出现"}})
                    break
        return out

    def _persist(self, ch: dict, task_id: int, candidates: list[dict]) -> dict:
        n_verified = n_flag = 0
        seen: set[tuple[str, str]] = set()
        for c in candidates:
            key = (c["type"], str(c.get("value") or c.get("response", ""))[:120])
            if key in seen:
                continue
            seen.add(key)
            fid = self.db.add_finding(
                ch["id"], task_id, c["type"], c["confidence"],
                {k: v for k, v in c.items() if k != "value"},
            )
            result = evaluate_and_persist(self.db, fid, {**c, "url": ch.get("target", "")})
            if result.passed:
                n_verified += 1
            if c.get("value") and result.passed:
                n_flag += 1
                if self.submitter:
                    self.submitter(ch["id"], c["value"])
        return {"verified": n_verified, "flags": n_flag}

    def _time_left(self) -> float:
        return self.timebox - (time.time() - self._started)


def _identify_format(data: bytes) -> str:
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\xca\xfe\xba\xbe") or data.startswith(b"\xcf\xfa\xed\xfe"):
        return "mach-o"
    if data.startswith(b"PK"):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    return "unknown"


def _extract_strings(data: bytes, min_len: int = 4, limit: int = 5000) -> list[str]:
    """ASCII + UTF-16LE 可打印序列提取（strings 等价实现，无外部依赖）。"""
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(bytes(cur).decode("ascii"))
    # UTF-16LE
    cur = bytearray()
    i = 0
    while i + 1 < len(data):
        ch, nxt = data[i], data[i + 1]
        if nxt == 0 and 32 <= ch < 127:
            cur.append(ch)
            i += 2
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii"))
            cur = bytearray()
            i += 1
    if len(cur) >= min_len:
        out.append(bytes(cur).decode("ascii"))
    return out[:limit]
