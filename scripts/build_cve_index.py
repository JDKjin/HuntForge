"""从内置 nuclei-templates 生成离线 CVE 索引（huntforge/knowledge/cve_index.json）。

托管环境无外网 → 本地 1.1 万条 nuclei 模板就是最大的 CVE 知识库：
扫描模板目录，按 CVE 编号归类（id/名称/tags/严重度/模板路径），
cve_engine 命中指纹后可直接给出可用模板路径，定向打靶不用猜。

用法：python scripts/build_cve_index.py
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TPL_ROOT = Path(__file__).resolve().parents[1] / "huntforge" / "tools" / "nuclei-templates"
OUT = Path(__file__).resolve().parents[1] / "huntforge" / "knowledge" / "cve_index.json"

_CVE_RE = re.compile(r"(?<![A-Z0-9])CVE-\d{4}-\d{4,7}", re.I)
_ID_RE = re.compile(r"^id:\s*([^\s#]+)", re.M)


def _yaml_head(text: str) -> dict:
    try:
        return yaml.safe_load(text) or {}
    except Exception:  # noqa: BLE001
        return {}


def main() -> int:
    index: dict[str, dict] = defaultdict(
        lambda: {"templates": [], "products": [], "severity": "unknown"})
    files = sorted(TPL_ROOT.rglob("*.yaml")) + sorted(TPL_ROOT.rglob("*.yml"))
    scanned = 0
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")[:40000]
        except OSError:
            continue
        cves = set(_CVE_RE.findall(text))
        if not cves:
            continue
        m = _ID_RE.search(text)
        tpl_id = m.group(1) if m else f.stem
        head = _yaml_head(text)
        info = head.get("info") or {}
        name = str(info.get("name") or f.stem)
        tags = info.get("tags") or ""
        sev = (info.get("severity") or "unknown").lower()
        rel = str(f.relative_to(TPL_ROOT)).replace("\\", "/")
        scanned += 1
        for c in cves:
            e = index[c]
            if rel not in e["templates"]:
                e["templates"].append(rel)
            if name and name not in e["products"]:
                e["products"].append(name[:80])
            e["tags"] = str(tags)[:120]
            if sev in ("critical", "high", "medium", "low"):
                order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                if order.get(sev, 9) < order.get(e["severity"], 9):
                    e["severity"] = sev
    out = {"count": len(index), "templates_scanned": scanned,
           "cves": {k: v for k, v in sorted(index.items())}}
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=0),
                   encoding="utf-8")
    print(f"CVE 索引生成：{len(index)} 个 CVE，扫描模板 {scanned} 个 → {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
