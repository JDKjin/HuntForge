"""指纹 → 定向 POC 自动执行层（借鉴 VulHunter tools/phases/ 的 targeted 层）。

指纹命中（Shiro / SpringBoot / 泛微 OA）后自动跑对应成熟 POC 脚本，
产物中的 flag 直接走 7Q Gate → 提交。POC 脚本从 VulHunter 移植
（huntforge/tools/pocs/），执行时经目录授权（side_effect=exploit 需显式允许）。

这是高分选手 flash 模型出分的核心机制之一：国产组件题（b 系列 1200 分）
不靠 LLM 盲打，靠成熟 POC 直击。
"""
from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from ..web.common import Candidate, extract_flag
from ..web.sse import emit_event
from .catalog import CATALOG

_POC_DIR = Path(__file__).resolve().parent / "pocs"

_FLAG_RE = re.compile(r"(?:flag|ctf|hf)[\{\(\[][^\]\}\)]{1,128}[\}\)\]]", re.I)

# 指纹 → (POC slug, 匹配函数)
TARGETED_RULES: list[tuple[str, list[str], object]] = [
    ("shiro", ["poc_shiro"],
     lambda tags, body: ("shiro" in " ".join(tags).lower()
                         or "rememberme" in body.lower()
                         or "deleteMe" in body)),
    ("springboot", ["poc_springboot"],
     lambda tags, body: any(t in tags for t in ("spring", "spring-actuator"))
     or "actuator" in body.lower()),
    ("seeyon", ["poc_seeyon"],
     lambda tags, body: any(k in body.lower()
                            for k in ("seeyon", "致远", "/seeyon/", "a8-v5"))),
    ("weaver", ["poc_weaver_sqli"],
     lambda tags, body: ("weaver" in body.lower()
                         or "e-cology" in body.lower()
                         or "/wui/" in body.lower())),
]


def _resolve_script(rec) -> Path:
    """解析 POC 脚本绝对路径。防御性剥离 YAML 里误带的 pocs/ 前缀
    （历史 bug：script 写 pocs/xxx 与 _POC_DIR 重复拼接 → POC 全部哑火）。"""
    rel = rec.script.replace("\\", "/")
    if rel.startswith("pocs/"):
        rel = rel[len("pocs/"):]
    return (_POC_DIR / rel).resolve()


def _run_poc(rec, target: str, timeout: float) -> dict:
    """执行一个 POC 脚本（本机 Python，bytes 捕获 + utf-8 解码）。

    部分 POC 把证据写进 -o 指定文件（如 seeyon）：执行后回读该文件一并纳入
    flag 扫描。outfile 占位符解析为系统临时目录，用完即删。
    """
    import os
    import tempfile
    script = _resolve_script(rec)
    outfile = os.path.join(tempfile.gettempdir(),
                           f"hf-poc-{rec.slug}-{int(time.time() * 1000)}.txt")
    placeholders = {"target": target,
                    "host": target.split("://", 1)[-1].split("/")[0],
                    "script": str(script), "outfile": outfile}
    missing = CATALOG.check_placeholders(rec.slug, placeholders)
    if missing:
        return {"ok": False, "error": f"missing placeholders: {missing}"}
    cmd = [sys.executable, script] + [
        str(a).format(**placeholders) for a in rec.argv[1:]
    ]
    started = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "stdout": ""}
    out = (r.stdout or b"").decode("utf-8", "replace")[-16000:]
    err = (r.stderr or b"").decode("utf-8", "replace")[-1500:]
    # 回读证据文件（seeyon 等把结果写文件而非 stdout）
    try:
        evidence = Path(outfile).read_text(encoding="utf-8",
                                           errors="replace")[:16000]
        out = out + "\n" + evidence
        Path(outfile).unlink(missing_ok=True)
    except OSError:
        pass
    return {"ok": r.returncode == 0, "stdout": out, "stderr": err,
            "returncode": r.returncode,
            "duration_ms": int((time.time() - started) * 1000)}


def run_targeted(db, target: str, tags: list, body: str,
                 budget: float = 150.0, ref_id: str = "") -> list[Candidate]:
    """按指纹跑定向 POC，返回带 flag 的 Candidate 列表。"""
    out: list[Candidate] = []
    tag_lower = [t.lower() for t in (tags or [])]
    body_lower = (body or "").lower()
    for rule_name, slugs, matcher in TARGETED_RULES:
        if not matcher(tag_lower, body_lower):
            continue
        for slug in slugs:
            rec = CATALOG.get(slug)
            if not rec:
                continue
            tb = min(rec.effective_timeout(), max(budget, 10))
            res = _run_poc(rec, target, tb)
            text = (res.get("stdout") or "") + "\n" + (res.get("stderr") or "")
            emit_event(db, "poc.executed", "challenge", ref_id,
                       tool=slug, agent_id="targeted",
                       params={"target": target},
                       result={"ok": res.get("ok"),
                               "out_head": text[:300]},
                       duration_ms=res.get("duration_ms"))
            flag = extract_flag(text)
            if flag:
                out.append(Candidate(
                    type=f"poc_{rule_name}", url=target,
                    request=f"POC {slug}",
                    response=text[:400],
                    impact=f"定向 POC（{rec.title}）直接命中 flag",
                    confidence=0.95, value=flag,
                    confirm={"note": f"{slug} 执行命中"}))
    return out
