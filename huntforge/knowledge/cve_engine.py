"""CVE 识别引擎（离线，托管环境无外网）。

- 指纹 + 题面/正文匹配内置 CVE 库（knowledge/cve_db.yaml）
- 命中且有内置 payload 模板 → 规则级直击（不花 LLM）
- 命中但无模板 / 规则直击未出 flag → 交给 LLM 现场编写 POC
  （planner.compose_exploit → script 动作，复用受限沙箱）
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import yaml

from ..web.common import Candidate, extract_flag, get, post, body_of
from ..web.sse import emit_event

_DB_PATH = Path(__file__).resolve().parent / "cve_db.yaml"
# 由 scripts/build_cve_index.py 从内置 nuclei-templates 生成（4773 个 CVE）
_INDEX_PATH = Path(__file__).resolve().parent / "cve_index.json"

_cached: Optional[list[dict]] = None
_index_cached: Optional[dict] = None


def load_db() -> list[dict]:
    global _cached
    if _cached is not None:
        return _cached
    data = yaml.safe_load(_DB_PATH.read_text(encoding="utf-8")) or {}
    _cached = [e for e in (data.get("cves") or []) if isinstance(e, dict)]
    return _cached


def load_index() -> dict:
    """离线 nuclei CVE 索引：CVE → {templates, products, severity}。"""
    global _index_cached
    if _index_cached is not None:
        return _index_cached
    try:
        import json
        _index_cached = json.loads(
            _INDEX_PATH.read_text(encoding="utf-8")).get("cves", {})
    except (OSError, ValueError):
        _index_cached = {}
    return _index_cached


def cve_templates(cve: str, limit: int = 3) -> list[str]:
    """命中 CVE 的可用本地 nuclei 模板路径（供定向扫描）。"""
    e = load_index().get(cve.upper())
    return (e or {}).get("templates", [])[:limit]


def _compile_patterns(entry: dict) -> list[re.Pattern]:
    return [re.compile(p, re.I) for p in entry.get("patterns", []) if p]


def match_cves(title: str = "", body: str = "", headers_blob: str = "",
               path: str = "") -> list[dict]:
    """在指纹文本上匹配 CVE 库，按严重度排序返回命中条目。"""
    blob = "\n".join([title or "", body or "", headers_blob or "", path or ""])
    blob_lower = blob.lower()
    hits = []
    for entry in load_db():
        for pat in _compile_patterns(entry):
            if pat.search(blob_lower):
                hits.append(entry)
                break
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    hits.sort(key=lambda e: sev.get(e.get("severity", "low"), 3))
    return hits


def _fmt_placeholders(value, target: str) -> object:
    """递归替换 {target} 占位符。"""
    if isinstance(value, str):
        return value.replace("{target}", target.rstrip("/"))
    if isinstance(value, dict):
        return {k: _fmt_placeholders(v, target) for k, v in value.items()}
    if isinstance(value, list):
        return [_fmt_placeholders(v, target) for v in value]
    return value


def run_payload(db, challenge_id: str, target: str,
                entry: dict) -> Optional[Candidate]:
    """执行一条 CVE 内置 payload 模板，命中 flag 则产出 Candidate。"""
    for tpl in entry.get("payloads") or []:
        path = str(tpl.get("path", "/"))
        headers = _fmt_placeholders(tpl.get("headers") or {}, target)
        data = _fmt_placeholders(tpl.get("data"), target)
        method = str(tpl.get("method", "GET")).upper()
        started = __import__("time").time()
        if method == "POST":
            resp = post(target.rstrip("/") + path, 10, data=data or None,
                        headers=headers)
        elif method == "PUT":
            import requests
            try:
                resp = requests.put(target.rstrip("/") + path, data=data,
                                    headers=headers, timeout=10, verify=False)
            except requests.RequestException:
                resp = None
        else:
            resp = get(target.rstrip("/") + path, 10, headers=headers)
        ms = (__import__("time").time() - started) * 1000
        body = body_of(resp)
        status = resp.status_code if resp is not None else 0
        emit_event(db, "cve.payload", "challenge", challenge_id,
                   tool=f"{entry.get('cve')}", agent_id="cve-engine",
                   params={"path": path, "method": method},
                   result={"status": status, "len": len(body)},
                   duration_ms=ms)
        flag = extract_flag(body)
        if flag:
            return Candidate(
                type=f"cve_{entry.get('cve', 'x').lower()}",
                url=target.rstrip("/") + path,
                request=f"{method} {path}",
                response=body[:400],
                impact=f"{entry.get('product')} {entry.get('cve')} 内置 payload 直击",
                confidence=0.95, value=flag,
                confirm={"note": f"cve {entry.get('cve')} payload 命中"})


def run_cve_scan(db, challenge_id: str, target: str, *,
                 title: str = "", body: str = "", headers_blob: str = "",
                 path: str = "", budget: float = 60.0) -> list[Candidate]:
    """CVE 引擎入口：匹配 → 规则直击 → 返回 flag 候选（供 web_ops 落库）。"""
    hits = match_cves(title, body, headers_blob, path)
    if not hits:
        return []
    emit_event(db, "cve.matched", "challenge", challenge_id,
               tool="cve-engine", agent_id="cve-engine",
               result={"cves": [h.get("cve") for h in hits[:5]]})
    out: list[Candidate] = []
    import time as _t
    deadline = _t.time() + budget
    for entry in hits[:5]:
        if _t.time() > deadline:
            break
        if not entry.get("payloads"):
            continue
        cand = run_payload(db, challenge_id, target, entry)
        if cand:
            out.append(cand)
    return out


def cve_briefs(title: str = "", body: str = "", headers_blob: str = "",
               path: str = "", limit: int = 3) -> list[dict]:
    """给 planner 的 CVE 情报摘要（供 LLM 编写 POC / 定向跑 nuclei）。"""
    out = []
    for e in match_cves(title, body, headers_blob, path)[:limit]:
        brief = {"cve": e.get("cve"), "product": e.get("product"),
                 "attack": e.get("attack", ""), "severity": e.get("severity")}
        tpls = cve_templates(e.get("cve", ""), limit=2)
        if tpls:
            brief["nuclei_templates"] = tpls
        out.append(brief)
    return out
