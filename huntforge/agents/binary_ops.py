"""二进制漏洞挖掘 Agent：静态分析（魔数/strings/危险函数）→ LLM 审计（可选增强）。

目标形态：文件路径（平台下发）或 URL（下载）。
动态分析（gdb/fuzz）在工具可用时启用；8核16G 预算内默认短周期静态先行。
规则引擎零 LLM 可跑通；配置了模型 key 时用 deep tier 做反汇编级审计。
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
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
            p = Path(path)
            info = self._analyze(p)
            # Kali 二进制分析链（radare2/checksec）：静态信息直接并入 LLM 审计上下文
            info["kali"] = self._kali_analysis(p)
            candidates = self._heuristic_candidates(info, ch["id"])

            # 0) rev 工具链静态勘查（r2 导入/函数数/高熵段），并入上下文
            triage = self._rev_triage(p, info)
            if triage:
                info["kali"] = f"{info.get('kali', '')}\n[rev-triage]\n{triage}"[:4000]

            # 1) 确定性解密流水线（无 LLM：XOR/keystream/查表/RC4/LCG + 本地回放）；
            #    规则层已直接命中 flag 时跳过（省预算）
            if self._time_left() > 20 and not any(c.get("value") for c in candidates):
                self._auto_decrypt(p, candidates, ch["id"])
            if any(c.get("value") for c in candidates):
                self._persist(ch, task["id"], candidates)
                return {"ok": True, "outcome": "flag_found",
                        "format": info.get("format"),
                        "llm_used": False, "method": "deterministic"}

            # 2) LLM 闭环审计：脚本→执行→回灌（≤3 轮），规则未命中时才调用
            llm_used = False
            if self.planner and self._time_left() > 30:
                llm_used = self._llm_rounds(p, info, candidates, ch["id"])

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

    # ---------- rev 工具链（离线容器原生，缺失降级） ----------
    def _rev_triage(self, path: Path, info: dict) -> str:
        try:
            from ..tools import rev
        except ImportError:
            return ""
        try:
            t = rev.bin_triage(str(path))
        except (OSError, ValueError):
            return ""
        info["rev_triage"] = t
        lines = [f"format={t.get('format')} size={t.get('size')} "
                 f"sha256={t.get('sha256')} funcs={t.get('functions')}",
                 f"file: {t.get('file_out', '')[:200]}",
                 f"checksec: {t.get('checksec', '')[:400]}"]
        imp = t.get("imports") or []
        if imp:
            lines.append("imports: " + ", ".join(imp[:40]))
        fs = t.get("flag_strings") or []
        if fs:
            lines.append("flag-ish strings: " + " | ".join(fs[:30]))
        return "\n".join(lines)

    def _auto_decrypt(self, path: Path, candidates: list[dict],
                      challenge_id: str) -> None:
        """确定性解密 + 本地回放（f2 license/自解密形态，全程无 LLM）。"""
        try:
            from ..tools import rev
        except ImportError:
            return
        budget = min(90.0, self._time_left() - 10)
        if budget < 20:
            return
        triage = {"path": str(path)}
        try:
            triage = rev.bin_triage(str(path))
        except (OSError, ValueError):
            pass
        try:
            results = rev.auto_pipeline(str(path), triage, budget=budget * 0.6)
        except (OSError, ValueError):
            results = []
        for r in results:
            plain = r.get("plain") or b""
            flag = extract_flag(plain.decode("latin1", "ignore"))
            if flag:
                candidates.append({
                    "type": f"rev:{r.get('method')}", "confidence": 0.85,
                    "request": f"确定性解密 {r.get('method')} "
                               f"key={str(r.get('key'))[:40]}",
                    "response": flag,
                    "impact": f"自动解密命中（{r.get('evidence')}）",
                    "value": flag,
                    "confirm": {"note": r.get("evidence", "auto-rev")},
                })
        # 候选密钥本地回放（"License accepted." 即证据；输出中的 flag 直接收）
        keys = [str(r.get("key")) for r in results if r.get("key") is not None
                and not isinstance(r.get("key"), bytes)]
        keys = [k for k in keys if k][:40]
        if keys and self._time_left() > 30:
            try:
                probes = rev.license_probe(str(path), keys,
                                           budget=min(50.0, self._time_left() - 20))
            except (OSError, ValueError):
                probes = []
            for pr in probes:
                flag = extract_flag(pr.get("output", ""))
                candidates.append({
                    "type": "rev:replay", "confidence": 0.9 if flag else 0.55,
                    "request": f"本地回放 key={pr.get('key')} mode={pr.get('mode')}",
                    "response": pr.get("output", "")[:300],
                    "impact": "二进制本地回放验证" + ("（输出含 flag）" if flag else ""),
                    **({"value": flag} if flag else {}),
                    "confirm": {"note": f"rc={pr.get('rc')}"},
                })
        self.db.event("rev.auto", "challenge", challenge_id,
                      {"methods": [r.get("method") for r in results],
                       "n_probes": len([c for c in candidates
                                        if c.get("type") == "rev:replay"])})

    def _llm_rounds(self, path: Path, info: dict, candidates: list[dict],
                    challenge_id: str) -> bool:
        """LLM 闭环：静态审计 → 生成脚本 → 受限执行 → 输出回灌（≤3 轮）。"""
        used = False
        script_out = ""
        for rnd in range(1, 4):
            if self._time_left() < 45:
                break
            llm_result = self.planner.audit_binary(
                info.get("format", "unknown"),
                info.get("strings", []),
                info.get("dangerous", []),
                kali_info=info.get("kali", ""),
                script_output=script_out,
                round_no=rnd,
            )
            if not llm_result:
                break
            used = True
            cands = self._process_llm_result(llm_result)
            candidates.extend(cands)
            if any(c.get("value") for c in cands):
                break   # LLM 直接解码出 flag，无需继续
            script = llm_result.get("script") or ""
            if not script or script_out == script:
                break
            # 受限执行：cwd=临时目录，超时 60s，输出截断后回灌下一轮
            try:
                sp = Path(path).parent / f"llm_r{rnd}.py"
                sp.write_text(script, encoding="utf-8")
                r = subprocess.run(
                    [sys.executable, str(sp)],
                    capture_output=True, text=True, timeout=60,
                    cwd=str(sp.parent),
                    env={k: v for k, v in os.environ.items()
                         if k in ("PATH", "HOME", "TMPDIR", "LANG",
                                  "PYTHONPATH", "KEY")} | {"BIN": str(path)},
                )
                script_out = ((r.stdout or "") + (r.stderr or ""))[:3000]
                flag = extract_flag(script_out)
                if flag:
                    candidates.append({
                        "type": "llm_script_flag", "confidence": 0.9,
                        "request": f"LLM 脚本第 {rnd} 轮输出",
                        "response": flag, "impact": "LLM 生成脚本执行命中 flag",
                        "value": flag, "confirm": {"note": "exec round"}})
                    break
            except (OSError, subprocess.SubprocessError):
                script_out = f"(script exec failed: 语法或运行时错误)"
        self.db.event("llm.binary_rounds", "challenge", challenge_id,
                      {"rounds": rnd, "script_ran": bool(script_out)})
        return used

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

    def _kali_analysis(self, path: Path) -> str:
        """Kali 二进制分析链（r2/checksec），失败静默降级。"""
        if os.environ.get("HUNTFORGE_KALI", "1") == "0":
            return ""
        try:
            from ..tools import kali
        except ImportError:
            return ""
        if not kali.available():
            return ""
        blocks = []
        for tool, label in (("kali_r2_info", "r2 文件信息"),
                            ("kali_r2_flags", "r2 关键词字符串"),
                            ("kali_checksec", "checksec 加固")):
            res = kali.run(tool, str(path), timeout=45)
            if res.get("ok") and (res.get("stdout") or "").strip():
                blocks.append(f"[{label}]\n{res['stdout'].strip()[:1500]}")
        return "\n".join(blocks)

    # ---------- 获取目标 ----------
    def _acquire(self, target: str, tmp: str) -> Optional[str]:
        if target.startswith(("http://", "https://")):
            import requests
            # f2 题容器首页挂 /download 下发 ELF：先试直链，返回 HTML
            # （非已知二进制格式）时自动改拉 /download。
            urls = [target]
            if not target.rstrip("/").endswith("/download"):
                urls.append(target.rstrip("/") + "/download")
            for u in urls:
                try:
                    r = requests.get(u, timeout=15, verify=False)
                    if r.status_code != 200:
                        continue
                    if _identify_format(r.content) == "unknown" and u != urls[-1]:
                        continue   # 首页 HTML → 换 /download
                    p = Path(tmp) / "target.bin"
                    p.write_bytes(r.content)
                    return str(p)
                except requests.RequestException:
                    continue
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
        # 3) 校验器/自解密壳特征（f2 系列常见形态，提示 LLM 走静态求解路径）
        joined = "\n".join(info.get("strings", []))
        jl = joined.lower()
        if "license accepted" in jl or "invalid license key" in jl \
                or "license_key" in jl:
            out.append({
                "type": "license_checker", "confidence": 0.55,
                "request": "strings 特征：许可证校验器",
                "response": "license checker",
                "impact": "校验器形态：找 .data 高熵加密 blob 与校验逻辑，"
                          "用已知明文（FLAG{/flag{）反推 keystream 或逆校验条件，"
                          "构造合法密钥回放验证（见 binary-pwn-playbook f2 章节）",
                "confirm": {"note": "license 校验特征出现"},
            })
        if "packed elf self-decrypt" in jl or "unpacker activated" in jl:
            out.append({
                "type": "self_decrypt_packer", "confidence": 0.55,
                "request": "strings 特征：自解密 unpacker",
                "response": "self-decrypt packer",
                "impact": "自解密壳形态：口令常与常量 XOR 比较，密钥由口令"
                          "派生（hash/PRNG），内嵌代码经 mprotect 后执行，"
                          "flag 常在被解密代码的尾部数据中",
                "confirm": {"note": "自解密特征出现"},
            })
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
                {**{k: v for k, v in c.items() if k != "value"},
                 "source": c.get("type", "binary-ops")},
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
