"""Kali 工具桥（目录驱动版，借鉴 VulHunter kali_remote 声明式降级）。

- 工具定义统一在 config/tools.yaml（catalog.py 加载校验），本模块只负责执行。
- 目标校验：只允许靶场网段（10./127./192.168./172./localhost），防 SSRF 类滥用。
- argv 模板 + 占位符替换 + shlex 引用 → bash -lc 单命令，bytes 捕获 + utf-8 解码。
- ffuf 词表优先使用内置精炼词表（huntforge/tools/wordlists/，经 /mnt 路径挂给 Kali）。

双模式执行：
- WSL 模式（本机开发）：wsl -d Kali-Linux bash -lc ...，路径转 /mnt；
- 原生模式（Docker 托管沙箱）：工具已随镜像安装，直接 bash -lc 执行，
  词表/模板用容器内路径（沙箱无 WSL，此前会整体哑火）。

配置：HUNTFORGE_KALI=0 禁用；HUNTFORGE_KALI_DISTRO 覆盖发行版名。
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from .catalog import CATALOG

DEFAULT_DISTRO = "Kali-Linux"

_ALLOWED_NETS = ("10.", "127.", "192.168.", "172.", "localhost")

# 原生模式判定：这些工具二进制在 PATH 里即认为镜像已内置 Kali 工具链
_NATIVE_BIN_PROBE = ("katana", "ffuf", "nuclei", "sqlmap", "dirsearch",
                     "nmap", "httpx", "r2")

# 旧别名 → 目录 slug（向后兼容历史调用与测试）
ALIASES = {
    "katana": "kali_katana",
    "ffuf_dirs": "kali_ffuf_dirs",
    "nuclei_tech": "kali_nuclei_tech",
    "nuclei_low": "kali_nuclei_low",
    "sqlmap_check": "kali_sqlmap_check",
    "dirsearch": "kali_dirsearch",
    "nmap_top": "kali_nmap_top",
    "httpx_probe": "kali_httpx_probe",
}

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_PATH_RE = re.compile(r"(?<![A-Za-z0-9])/[A-Za-z0-9_\-./]{2,60}(?=[\s\"'<>]|$)")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_cached_mode: Optional[str] = None


def enabled() -> bool:
    return os.environ.get("HUNTFORGE_KALI", "1") not in ("0", "false", "no")


def distro() -> str:
    return os.environ.get("HUNTFORGE_KALI_DISTRO", DEFAULT_DISTRO)


def mode() -> str:
    """执行模式：'wsl'（WSL Kali）| 'native'（容器内原生工具）| ''（不可用）。缓存。"""
    global _cached_mode
    if _cached_mode is not None:
        return _cached_mode
    # 1) WSL + Kali 发行版
    if shutil.which("wsl") is not None:
        try:
            r = subprocess.run(["wsl", "-l", "-q"], capture_output=True,
                               timeout=15)
            raw = r.stdout
            # wsl.exe 输出为 UTF-16LE（无 BOM）：用 NUL 字节启发式判别
            lines = raw.decode("utf-16-le", "replace") if b"\x00" in raw[:64] \
                else raw.decode("utf-8", "replace")
            names = [ln.strip() for ln in lines.splitlines() if ln.strip()]
            low = {n.lower(): n for n in names}
            if distro().lower() in low:
                _cached_mode = "wsl"
                return _cached_mode
        except Exception:  # noqa: BLE001
            pass
    # 2) 原生工具链（Docker 托管沙箱：无 WSL，工具已随镜像安装）
    found = [b for b in _NATIVE_BIN_PROBE if shutil.which(b)]
    if len(found) >= 4:
        _cached_mode = "native"
        return _cached_mode
    _cached_mode = ""
    return _cached_mode


def available() -> bool:
    """Kali 工具链是否可用（WSL 或原生，结果缓存）。"""
    return mode() != ""


def validate_target(target: str) -> Optional[str]:
    """目标只允许靶场网段/本机；返回净化后的目标或 None。"""
    t = (target or "").strip()
    if not t:
        return None
    if t.startswith(("http://", "https://")):
        host = t.split("://", 1)[1].split("/")[0].split(":")[0].lower()
        if not host.startswith(_ALLOWED_NETS):
            return None
        return t.rstrip("/")
    host = t.split(":")[0].lower()
    if not host.startswith(_ALLOWED_NETS):
        return None
    return t


def _mnt_path(win_path: Path) -> str:
    """Windows 路径 → WSL /mnt 路径。"""
    return "/mnt/" + win_path.drive[0].lower() + win_path.as_posix()[2:]


def _wordlist_path() -> str:
    """ffuf 词表：优先内置精炼词表（VulHunter wordlists 移植），
    缺失回退 seclists。返回当前执行模式视角路径（wsl=/mnt，native=容器路径）。"""
    local = Path(__file__).resolve().parent / "wordlists" / "deep_paths.txt"
    if local.is_file():
        return _mnt_path(local) if mode() == "wsl" else str(local)
    for c in ("/usr/share/seclists/Discovery/Web-Content/common.txt",
              "/usr/share/wordlists/dirb/common.txt"):
        if os.path.exists(c):
            return c
    return "/usr/share/seclists/Discovery/Web-Content/common.txt"


def _nuclei_templates_path() -> str:
    """nuclei 模板目录（仓库内置稀疏克隆），按执行模式给路径。"""
    local = Path(__file__).resolve().parent / "nuclei-templates"
    return _mnt_path(local) if mode() == "wsl" else str(local)


def _spec(tool: str):
    """目录 slug 或旧别名 → ToolRecord（integration=kali）。"""
    slug = tool if tool.startswith("kali_") else ALIASES.get(tool, tool)
    rec = CATALOG.get(slug)
    if not rec or rec.integration != "kali":
        return None
    return rec


def run(tool: str, target: str, timeout: Optional[float] = None,
        extra_args: str = "", *, allow_side_effects=None) -> dict:
    """执行目录内白名单工具（WSL Kali 或容器内原生工具）。返回
    {ok, tool, stdout, stderr, returncode}。"""
    if not enabled():
        return {"ok": False, "error": "kali disabled (HUNTFORGE_KALI=0)",
                "stdout": "", "stderr": ""}
    rec = _spec(tool)
    if rec is None:
        return {"ok": False, "error": f"unknown kali tool: {tool}",
                "stdout": "", "stderr": ""}
    auth_err = CATALOG.authorize(rec.slug, allow_side_effects)
    if auth_err:
        return {"ok": False, "error": auth_err, "stdout": "", "stderr": ""}
    m = mode()
    # 二进制类工具（{file} 占位符）：目标是文件路径 → 校验存在后按模式
    # 转路径；网络类工具（{target}）走沙箱网段校验
    if "file" in rec.required_placeholders:
        win_path = Path(target)
        if not win_path.is_file():
            return {"ok": False, "error": f"file not found: {target}",
                    "stdout": "", "stderr": ""}
        file_arg = (_mnt_path(win_path.resolve()) if m == "wsl"
                    else str(win_path.resolve()))
        placeholders = {"file": file_arg, "target": "", "host": "",
                        "wordlist": "", "templates": _nuclei_templates_path()}
    else:
        safe = validate_target(target)
        if safe is None:
            return {"ok": False,
                    "error": f"target rejected (not sandbox net): {target[:80]}",
                    "stdout": "", "stderr": ""}
        host = safe.split("://", 1)[-1].split("/")[0] if "://" in safe else safe
        placeholders = {"target": safe, "host": host,
                        "wordlist": _wordlist_path(), "script": "",
                        "templates": _nuclei_templates_path()}
    if not m:
        return {"ok": False, "error": "wsl/kali unavailable",
                "stdout": "", "stderr": ""}
    missing = CATALOG.check_placeholders(rec.slug, placeholders)
    if missing:
        return {"ok": False, "error": f"missing placeholders: {missing}",
                "stdout": "", "stderr": ""}
    parts = [str(a).format(**placeholders) for a in rec.argv]
    cmd = " ".join(shlex.quote(p) for p in parts)
    if extra_args:
        cmd += " " + extra_args
    if m == "wsl":
        full = ["wsl", "-d", distro(), "-u", "kali", "--", "bash", "-lc", cmd]
    else:
        full = ["bash", "-lc", cmd]   # 容器原生工具（镜像已内置）
    started = time.time()
    try:
        r = subprocess.run(full, capture_output=True,
                           timeout=timeout or rec.effective_timeout())
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "tool": rec.slug,
                "stdout": "", "stderr": ""}
    out = r.stdout.decode("utf-8", "replace")[-12000:]
    err = (_strip_wsl_noise(r.stderr) if m == "wsl"
           else r.stderr.decode("utf-8", "replace"))[-2000:]
    out = _ANSI_RE.sub("", out)
    err = _ANSI_RE.sub("", err)
    return {"ok": r.returncode == 0, "tool": rec.slug,
            "stdout": out, "stderr": err, "returncode": r.returncode,
            "duration_ms": int((time.time() - started) * 1000)}


def _strip_wsl_noise(raw: bytes) -> str:
    """剥离 wsl.exe 自身的 UTF-16LE 噪声头（localhost 代理警告等），
    只保留 bash 命令的真实 stderr（UTF-8 尾段）。"""
    if b"\x00" in raw[:64]:     # 头部是 UTF-16LE（无 BOM，靠 NUL 字节判别）
        cut = raw.rfind(b"\x00")
        if cut >= 0:
            raw = raw[cut + 1:]
    return raw.decode("utf-8", "replace")


def extract_endpoints(text: str, base: str) -> list[str]:
    """从工具输出抽取 URL 与路径（喂黑板 Fact/Intent）。

    过滤工具横幅里的示例域名与 FUZZ 占位符。
    """
    urls = _URL_RE.findall(text or "")
    out = []
    for u in urls:
        host = u.split("://", 1)[-1].split("/")[0].lower()
        if "example." in host or host == "localhost" or host == "0.0.0.0":
            continue
        if validate_target(u):
            out.append(u)
    base_host = (base or "").split("://", 1)[-1].split("/")[0]
    stripped = _URL_RE.sub(" ", text or "")
    for p in _PATH_RE.findall(stripped):
        if "fuzz" in p.lower() or p.startswith("//"):
            continue
        if any(ext in p for ext in (".css", ".js", ".png", ".jpg", ".ico", ".svg", ".woff")):
            continue
        out.append(f"http://{base_host}{p}")
    seen = set()
    return [x for x in out if not (x in seen or seen.add(x))][:40]


def scan_suite(target: str, budget: float = 90.0) -> dict:
    """轻量组合侦察：katana 爬端点 + ffuf 目录 + nuclei 指纹。

    工具与时间盒由目录 tier 决定，按预算顺序执行到点即收。
    """
    if validate_target(target) is None or not available():
        return {"endpoints": [], "dirs": [], "tech": [], "tools_ran": []}
    endpoints: list[str] = []
    dirs: list[str] = []
    tech: list[str] = []
    ran: list[str] = []
    plan = ["kali_katana", "kali_ffuf_dirs", "kali_nuclei_tech"]
    deadline = time.time() + budget
    for slug in plan:
        if time.time() > deadline:
            break
        rec = _spec(slug)
        if rec is None:
            continue
        tb = min(rec.effective_timeout(), max(deadline - time.time(), 5))
        res = run(slug, target, timeout=tb)
        ran.append(slug)
        text = res.get("stdout") or ""
        if slug == "kali_katana":
            endpoints += extract_endpoints(text, target)
        elif slug == "kali_ffuf_dirs":
            stripped = _URL_RE.sub(" ", text)
            for p in _PATH_RE.findall(stripped):
                if "fuzz" not in p.lower() and p not in dirs:
                    dirs.append(p)
        elif slug == "kali_nuclei_tech":
            tech += [ln.strip() for ln in text.splitlines() if ln.strip()][:20]
    return {"endpoints": endpoints, "dirs": dirs, "tech": tech,
            "tools_ran": ran}
