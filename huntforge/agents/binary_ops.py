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
from ..web.common import FLAG_RE, extract_flag
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
                 gateway=None):
        self.db = db
        self.timebox = timebox
        self.submitter = submitter
        self.gateway = gateway  # ModelGateway（可选，LLM 审计用）
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
            findings = self._persist(ch, task["id"], candidates)
            llm_note = ""
            if self.gateway and not findings["flags"]:
                llm_note = self._llm_audit(Path(path), info, ch["id"], task["id"])
            return {"ok": True, "outcome": "flag_found" if findings["flags"] else "analyzed",
                    "format": info.get("format"), "strings_found": len(info.get("strings", [])),
                    "dangerous": info.get("dangerous", []), "llm_audit": llm_note,
                    **findings}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

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

    # ---------- LLM 审计（可选） ----------
    def _llm_audit(self, path: Path, info: dict, challenge_id: str,
                   task_id: int) -> str:
        try:
            ctx = ("你是一名二进制安全审计专家。以下是目标文件的静态分析信息：\n"
                   f"格式: {info.get('format')}\n大小: {info.get('size')} 字节\n"
                   f"危险函数: {info.get('dangerous')}\n"
                   f"前 200 条字符串: {info.get('strings', [])[:200]}\n"
                   "请识别潜在漏洞（缓冲区溢出/命令注入/逻辑漏洞），输出 JSON："
                   '{"vulns":[{"type":"...","location":"...","analysis":"...","exploitability":"..."}]}')
            resp = self.gateway.chat_json([{"role": "user", "content": ctx}],
                                          tier="deep")
            vulns = resp.get("vulns", [])
            for v in vulns[:3]:
                self.db.add_finding(
                    challenge_id, task_id, "llm:" + str(v.get("type", "unknown"))[:40],
                    0.5,
                    {"url": str(path), "request": "LLM 静态审计",
                     "response": str(v.get("analysis", ""))[:400],
                     "impact": str(v.get("exploitability", "需人工确认")),
                     "confirm": {"note": "LLM 审计（deep tier）"}},
                )
                self.db.event("finding.llm", "challenge", challenge_id,
                              {"type": v.get("type"), "note": "llm audit"})
            return f"llm:{len(vulns)}"
        except Exception as exc:  # noqa: BLE001 - LLM 不可用静默降级
            log.info("llm audit unavailable: %s", exc)
            return "llm:unavailable"

    def _persist(self, ch: dict, task_id: int, candidates: list[dict]) -> dict:
        n_verified = n_flag = 0
        for c in candidates:
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
