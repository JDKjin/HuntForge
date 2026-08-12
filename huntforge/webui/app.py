"""Web 控制台：任务/发现/提交/事件/成本 实时看板（本地与托管均可运行）。

用法：python -m huntforge.webui.app [--port 18080] [--db data/huntforge.db]
"""
from __future__ import annotations

import argparse
import json

from flask import Flask, jsonify, render_template_string

from ..core.state import StateDB
from ..report import build_report

INDEX_HTML = """<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8"><title>HuntForge 铸猎 · 控制台</title>
<style>
  body{font-family:system-ui;margin:0;background:#0f1420;color:#d7dde8}
  header{padding:16px 24px;background:#151b2b;border-bottom:1px solid #26304a}
  header h1{margin:0;font-size:18px;color:#7ab8ff}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;padding:18px 24px}
  .card{background:#151b2b;border:1px solid #26304a;border-radius:10px;padding:14px}
  .card h3{margin:0 0 10px;font-size:14px;color:#9fb4d8}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #1f2840}
  th{color:#7f93b8;font-weight:600}
  .ok{color:#4ade80}.bad{color:#f87171}.warn{color:#fbbf24}
  .mono{font-family:ui-monospace,monospace;font-size:12px}
  pre{background:#0b0f1a;padding:10px;border-radius:8px;overflow:auto;max-height:260px;font-size:12px}
  .stat{font-size:26px;font-weight:700;color:#7ab8ff}
  .label{font-size:12px;color:#7f93b8}
</style></head>
<body>
<header><h1>⚒ HuntForge 铸猎 · 全流程自动化看板</h1>
  <span id="ts" style="color:#5c6b8a;font-size:12px"></span></header>
<div class="grid">
  <div class="card"><h3>总览</h3>
    <div class="stat" id="solved">-</div><div class="label" id="solved_label"></div>
    <p class="mono" id="overview" style="white-space:pre"></p></div>
  <div class="card"><h3>提交</h3>
    <div class="stat" id="subs">-</div>
    <p class="mono" id="subs_detail"></p></div>
  <div class="card"><h3>大模型成本</h3>
    <div class="stat" id="llm">-</div>
    <p class="mono" id="llm_detail"></p></div>
  <div class="card"><h3>事件流（全流程自动化证据）</h3><pre id="events"></pre></div>
</div>
<script>
async function tick(){
  const r = await fetch('/api/summary'); const d = await r.json();
  document.getElementById('ts').textContent = new Date().toLocaleTimeString();
  const s = d.summary.challenges;
  document.getElementById('solved').textContent = s.solved + ' / ' + s.total;
  document.getElementById('solved_label').textContent = '已解出 / 总数（挂起 ' + s.pending + '，闲置 ' + s.idle + '）';
  document.getElementById('overview').textContent = JSON.stringify(d.report, null, 1);
  const su = d.summary.submissions;
  document.getElementById('subs').textContent = su.accepted;
  document.getElementById('subs_detail').textContent =
    'accepted ' + su.accepted + ' · rejected ' + su.rejected + ' · pending ' + su.pending;
  const u = d.summary.llm_usage;
  document.getElementById('llm').textContent = u.calls;
  document.getElementById('llm_detail').textContent =
    '输入 ' + u.in_t + ' · 输出 ' + u.out_t + ' · 缓存 ' + u.cache_t + ' tokens';
  document.getElementById('events').textContent =
    d.events.slice(0, 40).map(e =>
      new Date(e.ts * 1000).toLocaleTimeString() + '  ' + e.event_type +
      (e.ref_id ? '  [' + e.ref_id + ']' : '') + '  ' + JSON.stringify(e.payload)
    ).join('\\n');
}
tick(); setInterval(tick, 3000);
</script></body></html>"""


def create_app(db_path) -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template_string(INDEX_HTML)

    @app.get("/api/summary")
    def summary():
        db = StateDB(db_path)
        try:
            return jsonify({
                "summary": _summary(db),
                "report": build_report(db),
                "events": db.list_events(limit=100),
            })
        finally:
            db.close()

    @app.get("/api/challenges")
    def challenges():
        db = StateDB(db_path)
        try:
            return jsonify({"challenges": db.list_challenges(),
                            "findings": db.list_findings(),
                            "submissions": db.list_submissions()})
        finally:
            db.close()
    return app


def _summary(db: StateDB) -> dict:
    challenges = db.list_challenges()
    subs = db.list_submissions()
    return {
        "challenges": {
            "total": len(challenges),
            "solved": sum(1 for c in challenges if c["status"] == "solved"),
            "pending": sum(1 for c in challenges if c["status"] in ("pending", "solving")),
            "idle": sum(1 for c in challenges if c["status"] == "idle"),
        },
        "submissions": {k: sum(1 for s in subs if s["status"] == k)
                        for k in ("accepted", "rejected", "pending")},
        "llm_usage": db.usage_summary(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(prog="huntforge-webui")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--db", default="data/huntforge.db")
    args = parser.parse_args()
    app = create_app(args.db)
    print(f"HuntForge WebUI at http://127.0.0.1:{args.port} (db: {args.db})")
    app.run(host="0.0.0.0", port=args.port, threaded=True)


if __name__ == "__main__":
    main()
