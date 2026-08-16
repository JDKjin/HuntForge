"""二进制逆向自动化工具（离线容器内可用，零外部依赖，工具缺失时优雅降级）。

覆盖 TSecBench f2 类形态（license checker / 自解密壳 / 简单校验器）：
1. bin_triage   一键静态勘查（file/checksec/r2 导入/函数数/flag 字符串/高熵段）
2. 确定性解密流水线：单字节 XOR → 已知明文推 keystream（含周期检测）→
   查表置换 → RC4 候选口令 → LCG 密钥流恢复 → 候选明文
3. license_probe 本地回放二进制验证候选密钥（"License accepted." 即证据）
4. angr_solve   angr 符号执行自动求解合法输入（未装 angr 时提示缺失）
5. auto_pipeline 上述步骤编排，预算内一步到位

MCP 入口：triage_tool / run_tool / angr_tool（tools.yaml + TOOLS 注册）。
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Optional

_FLAG_MARKERS = (b"flag{", b"FLAG{", b"ctf{", b"CTF{")


def _extract_strings(data: bytes, min_len: int = 4, limit: int = 5000) -> list[str]:
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
    return out[:limit]


def _sh(cmd: list[str], timeout: float = 30) -> str:
    """跑外部工具，失败/超时返回空串（离线容器工具缺失是常态，降级）。"""
    if shutil.which(cmd[0]) is None:
        return ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except (subprocess.SubprocessError, OSError):
        return ""


def _entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    cnt = Counter(blob)
    n = len(blob)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


def _high_entropy_regions(data: bytes, min_len: int = 16,
                          max_regions: int = 8) -> list[bytes]:
    """高熵连续区域（加密 blob / 查找表 / 密文 flag 候选位置）。"""
    regions = []
    start = None
    for i, b in enumerate(data):
        if start is None and 0 < b < 128:
            start = i
        elif start is not None and not (0 < b < 128):
            if i - start >= min_len:
                regions.append((start, i))
            start = None
    if start is not None and len(data) - start >= min_len:
        regions.append((start, len(data)))
    blobs = []
    for s, e in regions:
        blob = data[s:e]
        if _entropy(blob[:4096]) >= 6.5:
            blobs.append((s, blob[:4096]))
    return [b for _, b in sorted(blobs, key=lambda x: -len(x[1]))[:max_regions]]


# ---------------- 确定性解密 ----------------


def xor_single(data: bytes, max_len: int = 8192) -> list[dict]:
    """单字节 XOR 穷举：候选明文含 flag 标志或可打印率高。"""
    out = []
    head = data[:max_len]
    for k in range(256):
        dec = bytes(b ^ k for b in head)
        if any(m in dec for m in _FLAG_MARKERS):
            out.append({"method": "xor_single", "key": k, "plain": dec,
                        "evidence": "flag marker"})
        elif len(dec) > 32 and sum(32 <= b < 127 for b in dec) / len(dec) > 0.95:
            out.append({"method": "xor_single", "key": k, "plain": dec,
                        "evidence": "printable"})
    return out[:4]


def _marker_idx(dec: bytes) -> int:
    for m in _FLAG_MARKERS:
        i = dec.find(m)
        if i >= 0:
            return i
    return -1


def keystream_recover(data: bytes, known: bytes = b"FLAG{",
                      max_scan: int = 65536) -> list[dict]:
    """已知明文反推密钥流：定位明文偏移 → 恢复周期 key（含相位轮转对齐）
    → 全量解密。判别器：flag 标记后跟 8 字节可打印 flag 体（真阳性必然
    可打印；噪声几乎不可能）——"FLAG{ 出现在窗口开头"本身是构造性假象，
    不能作为证据。"""
    out = []
    scan = data[:max_scan]
    n = len(known)
    seen: set[bytes] = set()
    for off in range(len(scan) - n + 1):
        ks = bytes(scan[off + i] ^ known[i] for i in range(n))
        period = None
        for p in range(1, len(ks)):     # 严格小于窗口长，避免平凡周期
            if all(ks[i] == ks[i % p] for i in range(len(ks))):
                period = p
                break
        if period is None:
            continue
        # 已知明文在周期内的相位未知 → 轮转全部相位尝试解密
        base = ks[:period]
        for r in range(period):
            key = base[r:] + base[:r]
            if key in seen:
                continue
            seen.add(key)
            dec = bytes(data[i] ^ key[i % len(key)]
                        for i in range(len(data)))
            idx = _marker_idx(dec)
            if idx >= 0:
                tail = dec[idx + 5: idx + 13]
                if tail and all(32 <= b < 127 for b in tail):
                    out.append({"method": "keystream", "offset": off,
                                "key": key, "plain": dec,
                                "evidence": "flag marker + printable body"})
    return out[:4]


def table_invert(data: bytes, max_blobs: int = 8) -> list[dict]:
    """查表置换（256 字节映射表）：正反两个方向套表，找 flag 明文。"""
    out = []
    blobs = [data[:4096]] + _high_entropy_regions(data)
    seen: set[bytes] = set()
    for blob in blobs[:max_blobs]:
        for s in range(0, max(1, len(blob) - 256), 64):
            tbl = blob[s:s + 256]
            if len(tbl) != 256 or len(set(tbl)) < 200 or tbl in seen:
                continue
            seen.add(tbl)
            fwd = bytes(tbl[b] for b in blob if b < 256)
            inv = {v: i for i, v in enumerate(tbl)}
            rev = bytes(inv.get(b, 0) for b in blob)
            for plain in (fwd, rev):
                if any(m in plain for m in _FLAG_MARKERS):
                    out.append({"method": "table", "key": tbl.hex()[:32] + "..",
                                "plain": plain, "evidence": "flag marker"})
    return out[:4]


def rc4_candidates(data: bytes, keys: list[bytes],
                   max_len: int = 8192) -> list[dict]:
    """RC4 候选口令解密（口令来源：二进制内字符串 + 常见弱口令）。"""
    out = []
    head = data[:max_len]
    for key in keys:
        if not 1 <= len(key) <= 64:
            continue
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xFF
            s[i], s[j] = s[j], s[i]
        i = j = 0
        ks = bytearray()
        for _ in range(len(head)):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            ks.append(s[(s[i] + s[j]) & 0xFF])
        dec = bytes(head[k] ^ ks[k] for k in range(len(head)))
        if any(m in dec for m in _FLAG_MARKERS):
            out.append({"method": "rc4", "key": key, "plain": dec,
                        "evidence": "flag marker"})
    return out[:4]


def lcg_predict(ks: bytes) -> Optional[list[int]]:
    """从密钥流前 3 字节解 LCG（mod 256）参数并预测（验证后返回流）。"""
    if len(ks) < 12:
        return None

    def _inv(x: int) -> Optional[int]:
        for i in range(256):
            if (x * i) & 0xFF == 1:
                return i
        return None

    x0, x1, x2 = ks[0], ks[1], ks[2]
    inv = _inv((x1 - x0) & 0xFF)
    if inv is None:
        return None
    a = ((x2 - x1) & 0xFF) * inv & 0xFF
    c = (x1 - a * x0) & 0xFF
    stream = [x0]
    for _ in range(len(ks) - 1):
        stream.append((a * stream[-1] + c) & 0xFF)
    if sum(1 for i in range(len(ks)) if ks[i] == stream[i]) / len(ks) > 0.9:
        return stream
    return None


def _collect_keys(triage: dict) -> list[bytes]:
    keys = [b"key", b"secret", b"license", b"flag", b"ctf", b"password",
            b"admin", b"hunter", b"huntforge", b"123456", b"1234", b"0000",
            b"test", b"guest", b"root"]
    for s in (triage.get("strings") or [])[:200]:
        if 3 <= len(s) <= 16 and s.isprintable():
            keys.append(s.encode("ascii", "ignore"))
    stem = Path(triage.get("path", "")).stem
    if 3 <= len(stem) <= 16:
        keys.append(stem.encode("ascii", "ignore"))
    return keys[:80]


def auto_pipeline(path: str, triage: Optional[dict] = None,
                  budget: float = 120.0) -> list[dict]:
    """f2 类题确定性解密流水线：预算内自动跑完所有无 LLM 手段。"""
    started = time.time()
    triage = triage or {}
    data = Path(path).read_bytes()
    results: list[dict] = []
    blobs = [data[:8192]] + _high_entropy_regions(data)

    def _left() -> float:
        return budget - (time.time() - started)

    for blob in blobs:
        if _left() < 5:
            break
        results.extend(xor_single(blob))
        results.extend(keystream_recover(blob))
        results.extend(table_invert(blob))
    if _left() > 5:
        results.extend(rc4_candidates(data, _collect_keys(triage)))
    # 去重 + 保序
    uniq: list[dict] = []
    seen: set[str] = set()
    for r in results:
        k = r["method"] + str(r.get("key", ""))[:40] + str(r.get("offset", ""))
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq[:12]


# ---------------- 本地回放验证 ----------------


def license_probe(path: str, keys: list[str], timeout: float = 8.0,
                  budget: float = 60.0) -> list[dict]:
    """本地执行二进制验证候选密钥：argv 传入 + stdin 传入两种形态。
    成功判据：输出含 accepted/correct/valid/success/flag 且无 invalid/denied。"""
    started = time.time()
    ok_markers = ("accepted", "accept", "correct", "valid", "success", "flag")
    bad_markers = ("invalid", "denied", "wrong", "incorrect", "refused")
    out = []
    for key in keys[:60]:
        if time.time() - started > budget:
            break
        for mode in ("argv", "stdin"):
            try:
                r = subprocess.run(
                    [path, str(key)],
                    input=str(key) + "\n" if mode == "stdin" else None,
                    capture_output=True, text=True, timeout=timeout,
                    env={**os.environ, "KEY": str(key)})
            except (subprocess.SubprocessError, OSError):
                # 非可执行文件（如 python 校验脚本）回退解释器执行
                try:
                    r = subprocess.run(
                        [sys.executable, path, str(key)],
                        input=str(key) + "\n" if mode == "stdin" else None,
                        capture_output=True, text=True, timeout=timeout,
                        env={**os.environ, "KEY": str(key)})
                except (subprocess.SubprocessError, OSError):
                    continue
            text = (r.stdout or "") + (r.stderr or "")
            score = sum(m in text.lower() for m in ok_markers) - \
                2 * sum(m in text.lower() for m in bad_markers)
            if score > 0:
                out.append({"key": key, "mode": mode, "rc": r.returncode,
                            "output": text[:600], "evidence": "binary replay"})
                break
    return out[:8]


def angr_solve(path: str, stdin_len: int = 32, timeout: float = 150.0) -> dict:
    """angr 符号执行：stdin 符号化，找输出含 accepted 的状态、避开 invalid。
    angr 未安装时返回缺失提示（镜像 pip 层保证存在；本地降级不崩溃）。"""
    try:
        import angr  # noqa: F401
        import claripy  # noqa: F401
    except ImportError:
        return {"ok": False,
                "error": "angr/claripy 未安装（容器镜像内置；本机降级）"}
    script = f'''
import sys, angr, claripy
p = angr.Project({path!r}, auto_load_libs=False)
flag = claripy.BVS("flag", {stdin_len} * 8)
st = p.factory.full_init_state(stdin=flag)
for b in flag.chop(8):
    st.add_constraints(b >= 0x20)
    st.add_constraints(b <= 0x7e)
sm = p.factory.simulation_manager(st)
sm.explore(find=lambda s: b"accepted" in s.posix.dumps(1),
           avoid=lambda s: b"invalid" in s.posix.dumps(1)
           or b"denied" in s.posix.dumps(1))
for s in sm.found[:3]:
    print("ANG:" + s.solver.eval(flag, cast_to=bytes).decode("latin1"))
if not sm.found:
    print("ANG:none", file=sys.stderr)
'''
    try:
        r = subprocess.run([sys.executable, "-c", script], capture_output=True,
                           text=True, timeout=timeout + 30)
    except subprocess.SubprocessError as exc:
        return {"ok": False, "error": f"angr run failed: {exc}"}
    sols = [ln[4:] for ln in (r.stdout or "").splitlines()
            if ln.startswith("ANG:") and ln[4:] != "none"]
    return {"ok": True, "solutions": sols,
            "stderr": (r.stderr or "")[:400]}


# ---------------- 静态勘查 ----------------


def bin_triage(path: str) -> dict:
    p = Path(path)
    data = p.read_bytes()
    fmt = _identify_format(data)
    info = {
        "ok": True, "path": str(p), "format": fmt, "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest()[:16],
        "strings": [], "flag_strings": [], "imports": [], "functions": 0,
        "checksec": "", "file_out": "", "entropy_blobs": [],
        "tools_missing": [],
    }
    if shutil.which("file"):
        info["file_out"] = _sh(["file", str(p)], 10).strip()[:300]
    else:
        info["tools_missing"].append("file")
    cs = _sh(["checksec", f"--file={p}"], 20)
    if not cs:
        cs = _sh(["r2", "-q", "-c", "iI", str(p)], 30)
    if not cs:
        info["tools_missing"].append("checksec/r2")
    info["checksec"] = cs.strip()[:1200]
    imp = _sh(["r2", "-q", "-c", "ii~imp", str(p)], 30)
    info["imports"] = [ln for ln in imp.splitlines() if ln.strip()][:60]
    fnc = _sh(["r2", "-q", "-c", "aflc", str(p)], 60)
    info["functions"] = int(fnc.strip()) if fnc.strip().isdigit() else 0
    strings = _extract_strings(data)
    info["strings"] = strings[:500]
    info["flag_strings"] = [s for s in strings
                            if any(k in s.lower() for k in
                                   ("flag", "key", "license", "secret",
                                    "password", "accepted"))][:80]
    info["entropy_blobs"] = [{"offset": 0, "len": len(b), "hex": b[:24].hex()}
                             for b in _high_entropy_regions(data)]
    return info


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


# ---------------- MCP 工具入口 ----------------


def triage_tool(file: str) -> dict:
    """MCP：bin_triage 二进制静态勘查。"""
    try:
        return bin_triage(file)
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}


def run_tool(file: str, key: str = "", timeout: float = 15.0) -> dict:
    """MCP：本地执行二进制（可选候选密钥），返回输出与 flag 扫描。"""
    out = {}
    try:
        cmd = [file] if not key else [file, str(key)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout,
                               env={**os.environ, "KEY": str(key)})
        except OSError:
            r = subprocess.run([sys.executable] + cmd, capture_output=True,
                               text=True, timeout=timeout,
                               env={**os.environ, "KEY": str(key)})
        text = (r.stdout or "") + (r.stderr or "")
        out = {"ok": True, "rc": r.returncode, "output": text[:2000]}
        flags = [m.group(0) for m in re.finditer(
            r"(?:flag|FLAG|ctf|CTF)\{[^\s}]{4,}\}", text)]
        out["flags"] = flags[:5]
    except subprocess.SubprocessError as exc:
        out = {"ok": False, "error": f"run failed: {exc}"}
    return out


def angr_tool(file: str, stdin_len: int = 32, timeout: float = 150.0) -> dict:
    """MCP：angr 符号执行求解。"""
    return angr_solve(file, stdin_len=stdin_len, timeout=timeout)
