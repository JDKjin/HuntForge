"""Web 控制台：任务/发现/提交/事件/成本 实时看板（本地与托管均可运行）。

架构升级（借鉴 ctfSolver 日志流 + Cairn 图 + D0Pagent 证据）：
- /api/stream  SSE 实时原子操作日志流（events 表为唯一事实源，零模拟日志）
- /api/agents  每道题的 Agent 状态卡片（FSM 状态 + 角色计数 + LLM 预算）
- /api/graph   黑板 Fact-Intent 快照（前端力导向图）
- /static/graph.js  前端力导向图（frontend/graph.js）

用法：python -m huntforge.webui.app [--port 18080] [--db data/huntforge.db]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from flask import Flask, Response, jsonify, render_template_string, request

from ..core.state import StateDB
from ..report import build_report
from ..web.sse import poll_events

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

INDEX_HTML = """<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HuntForge 铸猎 · 作战台</title>
<style>
  :root{
    --bg:#060a13; --bg2:#0a1020; --panel:rgba(15,23,42,.72); --panel-solid:#0d1526;
    --line:rgba(56,189,248,.16); --line2:rgba(148,163,184,.14);
    --txt:#e2e8f0; --dim:#8fa3c0; --faint:#5c6c8a;
    --c1:#38bdf8; --c2:#a78bfa; --c3:#f472b6; --ok:#34d399; --bad:#fb7185;
    --warn:#fbbf24; --grad:linear-gradient(90deg,var(--c1),var(--c2),var(--c3));
    --mono:ui-monospace,"Cascadia Mono","JetBrains Mono",Consolas,monospace;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:"Segoe UI",system-ui,-apple-system,sans-serif;background:
    radial-gradient(1200px 600px at 15% -10%,rgba(56,189,248,.10),transparent 55%),
    radial-gradient(1000px 500px at 95% 0%,rgba(244,114,182,.08),transparent 50%),
    var(--bg);color:var(--txt);min-height:100vh;overflow-x:hidden}
  ::-webkit-scrollbar{width:8px;height:8px}
  ::-webkit-scrollbar-thumb{background:#1c2a44;border-radius:8px}
  ::-webkit-scrollbar-track{background:transparent}

  header{position:sticky;top:0;z-index:40;display:flex;align-items:center;gap:18px;
    padding:12px 22px;background:rgba(6,10,19,.85);backdrop-filter:blur(14px);
    border-bottom:1px solid var(--line)}
  .logo{display:flex;align-items:center;gap:10px;font-weight:800;font-size:17px;
    letter-spacing:.5px}
  .logo .mark{width:34px;height:34px;border-radius:10px;background:var(--grad);
    display:grid;place-items:center;font-size:18px;box-shadow:0 0 22px rgba(56,189,248,.45)}
  .logo em{font-style:normal;background:var(--grad);-webkit-background-clip:text;
    background-clip:text;color:transparent}
  .spacer{flex:1}
  .clock{font-family:var(--mono);color:var(--dim);font-size:13px}
  .score-pill{display:flex;align-items:center;gap:8px;padding:7px 14px;border-radius:999px;
    background:rgba(52,211,153,.10);border:1px solid rgba(52,211,153,.35);
    font-family:var(--mono);font-weight:700;color:var(--ok)}
  .score-pill .dot{width:8px;height:8px;border-radius:50%;background:var(--ok);
    box-shadow:0 0 8px var(--ok);animation:blink 1.6s infinite}
  @keyframes blink{50%{opacity:.35}}
  select{appearance:none;background:var(--panel-solid);color:var(--txt);
    border:1px solid var(--line2);border-radius:9px;padding:7px 30px 7px 12px;
    font-size:13px;cursor:pointer;background-image:
      url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%238fa3c0' fill='none' stroke-width='1.5'/%3E%3C/svg%3E");
    background-repeat:no-repeat;background-position:right 10px center}

  .wrap{padding:18px 22px 28px;display:flex;flex-direction:column;gap:16px;max-width:1680px;margin:0 auto}

  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
  .kpi{background:var(--panel);border:1px solid var(--line2);border-radius:14px;
    padding:13px 16px;backdrop-filter:blur(8px);position:relative;overflow:hidden}
  .kpi::after{content:"";position:absolute;inset:0 0 auto 0;height:2px;background:var(--grad);
    opacity:.5}
  .kpi .v{font-size:25px;font-weight:800;font-family:var(--mono);margin-top:3px}
  .kpi .l{font-size:11.5px;color:var(--dim);letter-spacing:.6px;text-transform:uppercase}
  .kpi.accent .v{background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent}

  .main{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(340px,1fr);gap:16px}
  @media(max-width:1100px){.main{grid-template-columns:1fr}}

  .panel{background:var(--panel);border:1px solid var(--line2);border-radius:16px;
    backdrop-filter:blur(8px);display:flex;flex-direction:column;min-width:0;overflow:hidden}
  .panel-h{display:flex;align-items:center;gap:10px;padding:13px 16px;
    border-bottom:1px solid var(--line2)}
  .panel-h h3{font-size:13.5px;font-weight:700;color:#c7d6ef;letter-spacing:.4px}
  .panel-h .sub{font-size:11px;color:var(--faint);margin-left:auto}
  .panel-b{padding:14px 16px}

  #graphbox{height:460px;background:
    radial-gradient(600px 300px at 50% 0%,rgba(56,189,248,.06),transparent 60%),#070d18}
  .legend{display:flex;gap:14px;font-size:11px;color:var(--dim)}
  .legend i{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}

  #agents{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px;padding:2px}
  .agent{background:rgba(10,16,32,.75);border:1px solid var(--line2);border-radius:12px;
    padding:11px 13px;transition:border-color .2s}
  .agent:hover{border-color:var(--line)}
  .agent .row1{display:flex;justify-content:space-between;align-items:center;gap:8px}
  .agent .cid{font-family:var(--mono);font-weight:700;font-size:13px}
  .pill{font-size:10.5px;font-weight:700;padding:3px 10px;border-radius:999px;
    letter-spacing:.8px;text-transform:uppercase;border:1px solid}
  .st-idle{color:#8fa3c0;border-color:#33415e;background:rgba(143,163,192,.08)}
  .st-exploring{color:#7dd3fc;border-color:rgba(56,189,248,.4);background:rgba(56,189,248,.10)}
  .st-scanning{color:#c4b5fd;border-color:rgba(167,139,250,.4);background:rgba(167,139,250,.10)}
  .st-exploiting{color:#fcd34d;border-color:rgba(251,191,36,.4);background:rgba(251,191,36,.10)}
  .st-validating{color:#f9a8d4;border-color:rgba(244,114,182,.4);background:rgba(244,114,182,.10)}
  .st-solved{color:#6ee7b7;border-color:rgba(52,211,153,.45);background:rgba(52,211,153,.10)}
  .st-failed{color:#fda4af;border-color:rgba(251,113,133,.45);background:rgba(251,113,133,.10)}
  .agent .meta{display:flex;gap:12px;margin-top:9px;font-family:var(--mono);
    font-size:11px;color:var(--dim)}
  .bar{height:4px;border-radius:4px;background:#16223a;margin-top:9px;overflow:hidden}
  .bar i{display:block;height:100%;background:var(--grad);border-radius:4px;
    transition:width .6s ease}

  #timeline{height:460px;overflow-y:auto;padding:6px 10px 10px}
  .tl{position:relative;border:1px solid transparent;border-radius:10px;
    padding:7px 10px 7px 12px;margin-bottom:5px;cursor:pointer;font-family:var(--mono);
    font-size:11.5px;line-height:1.55;background:rgba(10,16,32,.55);
    transition:border-color .15s,background .15s}
  .tl:hover{border-color:var(--line);background:rgba(17,27,48,.9)}
  .tl::before{content:"";position:absolute;left:0;top:9px;bottom:9px;width:3px;
    border-radius:3px;background:var(--c1);opacity:.7}
  .tl.k-llm::before{background:var(--c2)}.tl.k-submit::before{background:var(--ok)}
  .tl.k-abandon::before{background:var(--bad);animation:blink 1.2s infinite}
  .tl.k-kali::before{background:var(--warn)}
  .tl .t{color:var(--faint);font-size:10.5px}
  .tl .type{font-weight:700;color:#a5c4ef}
  .tl .abandon{color:var(--bad);font-weight:800}
  .tl .tool{color:#7fb3e8}

  #drawer{position:fixed;right:0;top:0;bottom:0;width:min(480px,94vw);z-index:60;
    background:#0a1222;border-left:1px solid var(--line);box-shadow:-24px 0 60px rgba(0,0,0,.6);
    display:none;flex-direction:column;animation:slidein .22s ease}
  @keyframes slidein{from{transform:translateX(40px);opacity:0}}
  .d-h{display:flex;align-items:center;padding:16px 18px;border-bottom:1px solid var(--line2)}
  .d-h h3{font-size:14px;color:var(--c1)}
  .d-h .close{margin-left:auto;cursor:pointer;color:var(--dim);font-size:18px}
  .d-h .close:hover{color:var(--txt)}
  .d-tabs{display:flex;gap:6px;padding:10px 18px 0}
  .d-tabs button{background:transparent;border:1px solid var(--line2);color:var(--dim);
    padding:6px 14px;border-radius:8px 8px 0 0;cursor:pointer;font-size:12px}
  .d-tabs button.on{color:var(--txt);background:rgba(56,189,248,.08);
    border-color:var(--line)}
  .d-b{flex:1;overflow:auto;padding:14px 18px}
  pre{background:#070d18;border:1px solid var(--line2);border-radius:10px;
    padding:12px;font-family:var(--mono);font-size:11.5px;line-height:1.6;
    white-space:pre-wrap;word-break:break-all;color:#b8c9e4}
  .kv{display:grid;grid-template-columns:110px 1fr;gap:6px 12px;font-size:12.5px}
  .kv dt{color:var(--faint)}.kv dd{font-family:var(--mono);color:#c9d8ef;word-break:break-all}
  .empty{color:var(--faint);text-align:center;padding:40px 0;font-size:13px}
</style></head>
<body>
<header>
  <div class="logo"><span class="mark">⚒</span><span>HuntForge <em>铸猎</em> · 作战台</span></div>
  <select id="chal" onchange="pickChallenge()"></select>
  <span class="clock" id="ts">--:--:--</span>
  <div class="spacer"></div>
  <div class="score-pill"><span class="dot"></span><span id="score">0</span> 分</div>
</header>
<div class="wrap">
  <div class="kpis">
    <div class="kpi accent"><div class="l">总分</div><div class="v" id="k_score">-</div></div>
    <div class="kpi"><div class="l">已解出</div><div class="v" id="k_solved">-</div></div>
    <div class="kpi"><div class="l">提交 Accepted</div><div class="v" id="k_subs">-</div></div>
    <div class="kpi"><div class="l">LLM 调用</div><div class="v" id="k_llm">-</div></div>
    <div class="kpi"><div class="l">缓存命中率</div><div class="v" id="k_cache" style="color:var(--ok)">-</div></div>
    <div class="kpi"><div class="l">Token 输入/输出</div><div class="v" id="k_tok" style="font-size:17px">-</div></div>
    <div class="kpi"><div class="l">预算</div><div class="v" id="k_budget" style="font-size:17px">-</div></div>
  </div>
  <div class="main">
    <div style="display:flex;flex-direction:column;gap:16px;min-width:0">
      <div class="panel">
        <div class="panel-h"><h3>🧭 Fact-Intent 探索图</h3>
          <span class="legend"><span><i style="background:#34d399"></i>Fact 已确认</span>
          <span><i style="background:#60a5fa"></i>Intent 待办</span>
          <span><i style="background:#fbbf24"></i>执行中</span>
          <span><i style="background:#64748b"></i>完成</span></span>
          <span class="sub" id="g_sub"></span></div>
        <div id="graphbox"></div>
      </div>
      <div class="panel">
        <div class="panel-h"><h3>🤖 Agent 状态卡片</h3><span class="sub">FSM 状态机 · 每 3s 刷新</span></div>
        <div class="panel-b" id="agents"></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-h"><h3>⚡ 实时原子操作日志流</h3><span class="sub">SSE · 每条对应一次真实调用</span></div>
      <div id="timeline"><div class="empty">等待事件…</div></div>
    </div>
  </div>
</div>
<div id="drawer">
  <div class="d-h"><h3>🔍 调用详情</h3><span class="close" onclick="closeDrawer()">✕</span></div>
  <div class="d-tabs">
    <button class="on" onclick="dt(this,'sum')">概览</button>
    <button onclick="dt(this,'params')">入参</button>
    <button onclick="dt(this,'result')">返回值</button>
    <button onclick="dt(this,'challenge')">解题</button>
  </div>
  <div class="d-b" id="drawerBody"></div>
</div>
<script src="/static/graph.js"></script>
<script>
var CUR = null, CUR_EV = null, CUR_CH = null, MAX_ID = 0;
var graph = new HuntForgeGraph("graphbox");
function pickChallenge(){ CUR = document.getElementById('chal').value || null; refreshGraph(); }
function closeDrawer(){ document.getElementById('drawer').style.display='none'; }
function fmtTime(ts){ return new Date(ts*1000).toLocaleTimeString(); }
function esc(s){ var d=document.createElement('div'); d.textContent=(s==null?'':String(s)); return d.innerHTML; }
async function openChallenge(cid){
  document.getElementById('chal').value = cid;
  refreshGraph();
  var r = await fetch('/api/challenge/'+encodeURIComponent(cid));
  CUR_CH = await r.json();
  document.getElementById('drawer').style.display='flex';
  var btns = document.querySelectorAll('.d-tabs button');
  btns.forEach(function(b){ b.classList.remove('on'); });
  btns[3].classList.add('on');
  dt(btns[3], 'challenge');
}
function dt(btn, tab){
  document.querySelectorAll('.d-tabs button').forEach(function(b){ b.classList.remove('on'); });
  btn.classList.add('on');
  var body=document.getElementById('drawerBody'), e=CUR_EV; if(!e) return;
  var html='';
  if(tab==='sum'){
    html='<div class="kv">'+
      '<dt>时间</dt><dd>'+fmtTime(e.ts)+'</dd>'+
      '<dt>事件</dt><dd>'+esc(e.type)+'</dd>'+
      '<dt>Agent</dt><dd>'+esc(e.agent_id||'-')+'</dd>'+
      '<dt>工具</dt><dd>'+esc(e.tool||'-')+'</dd>'+
      '<dt>耗时</dt><dd>'+(e.duration_ms!=null?e.duration_ms+' ms':'-')+'</dd>'+
      '<dt>ABANDON</dt><dd>'+(e.abandoned?esc(e.abandoned):'-')+'</dd>'+
      '</div>';
  } else if(tab==='params'){
    html='<pre>'+esc(JSON.stringify(e.params,null,1))+'</pre>';
  } else if(tab==='result'){
    html='<pre>'+esc(JSON.stringify(e.result,null,1))+'</pre>';
  } else if(tab==='challenge'){
    var c=CUR_CH; if(!c) return;
    var rows='';
    (c.events||[]).forEach(function(ev){
      var r2=ev.payload||{};
      rows+='<div class="tl" style="cursor:default"><span class="t">'+fmtTime(ev.ts)+'</span> '+
        '<b>'+esc(ev.event_type)+'</b> '+esc(r2.agent_id||'')+' '+esc(r2.tool||'')+
        (r2.abandoned?' <span class="abandon">ABANDON</span>':'')+'</div>';
    });
    var finds=(c.findings||[]).map(function(f){
      return '<div class="tl" style="cursor:default">['+esc(f.status)+'] <b>'+esc(f.vuln_type)+
        '</b> conf '+((f.confidence||0)*100).toFixed(0)+'%'+
        (f.evidence&&f.evidence.value?' <span style="color:var(--ok)">value: '+esc(String(f.evidence.value).slice(0,28))+'</span>':'')+'</div>';
    }).join('');
    var subs=(c.submissions||[]).map(function(sm){
      return '<div class="tl" style="cursor:default"><b>'+esc(sm.status)+'</b> attempts '+sm.attempts+
        ' <span class="t">'+esc((sm.value||'').slice(0,24))+'…</span></div>';
    }).join('');
    html='<div class="kv">'+
      '<dt>题目</dt><dd>'+esc((c.challenge&&c.challenge.title)||c.challenge.id)+'</dd>'+
      '<dt>类别/难度</dt><dd>'+esc(c.challenge.category)+' / '+esc(c.challenge.difficulty)+'</dd>'+
      '<dt>FSM 状态</dt><dd>'+esc(c.state)+'</dd>'+
      '<dt>Facts / Intents</dt><dd>'+c.facts.length+' / '+c.intents.length+'</dd>'+
      '</div>'+
      '<h4 style="margin:14px 0 6px;color:#9fb4d8">Findings ('+(c.findings||[]).length+')</h4>'+(finds||'<div class="meta">无</div>')+
      '<h4 style="margin:14px 0 6px;color:#9fb4d8">Submissions ('+(c.submissions||[]).length+')</h4>'+(subs||'<div class="meta">无</div>')+
      '<h4 style="margin:14px 0 6px;color:#9fb4d8">本题事件 ('+(c.events||[]).length+')</h4>'+rows;
  }
  body.innerHTML=html;
}
function openDrawer(e){
  CUR_EV=e;
  document.getElementById('drawer').style.display='flex';
  document.querySelectorAll('.d-tabs button')[0].classList.add('on');
  document.querySelectorAll('.d-tabs button').forEach(function(b,i){ if(i>0)b.classList.remove('on'); });
  dt(document.querySelectorAll('.d-tabs button')[0],'sum');
}
function kindOf(e){
  if(e.abandoned) return 'k-abandon';
  if((e.tool||'').indexOf('llm:')===0) return 'k-llm';
  if((e.tool||'').indexOf('kali')===0||e.type==='kali.recon') return 'k-kali';
  if((e.type||'').indexOf('submission')===0||(e.tool||'').indexOf('platform')===0) return 'k-submit';
  return '';
}
function addLog(e){
  if (e.id != null) {           // 去重：backlog 与 SSE 回放共用同一事件源
    if (e.id <= MAX_ID) return;
    MAX_ID = e.id;
  }
  var t=document.getElementById('timeline');
  var d=document.createElement('div');
  d.className='tl '+kindOf(e);
  var ab=e.abandoned?'<span class="abandon">⛔'+esc(e.abandoned)+'</span> ':'';
  var tool=e.tool?'<span class="tool">'+esc(e.tool)+'</span> ':'';
  var r=e.result||{};
  var detail='';
  if (r.status!=null) detail+=' <span class="t">HTTP '+r.status+'</span>';
  if (r.flag) detail+=' <span style="color:var(--ok)">FLAG!</span>';
  if (r.out_len!=null) detail+=' <span class="t">'+r.out_len+'B</span>';
  if (r.cache!=null) detail+=' <span class="t" style="color:var(--ok)">cache '+r.cache+'</span>';
  if (e.reason) detail+=' <span class="t">'+esc(String(e.reason).slice(0,40))+'</span>';
  d.innerHTML='<span class="t">'+fmtTime(e.ts)+'</span> '+
    '<span class="type">'+esc(e.type)+'</span> '+esc(e.agent_id||'')+' '+tool+ab+detail+
    (e.duration_ms!=null?'<span class="t">'+e.duration_ms+'ms</span>':'');
  d.onclick=function(){ openDrawer(e); };
  var empty=t.querySelector('.empty'); if(empty) empty.remove();
  t.prepend(d);
  while(t.children.length>300) t.removeChild(t.lastChild);
}
async function loadBacklog(){
  try{
    var r=await fetch('/api/events?limit=300');
    var d=await r.json();
    (d.events||[]).slice().reverse().forEach(addLog);
  }catch(e){}
}
async function tick(){
  const r=await fetch('/api/summary'); const d=await r.json();
  document.getElementById('ts').textContent=new Date().toLocaleTimeString();
  var s=d.summary.challenges, su=d.summary.submissions, u=d.summary.llm_usage;
  document.getElementById('k_solved').textContent=s.solved+' / '+s.total;
  document.getElementById('k_subs').textContent=su.accepted;
  document.getElementById('k_llm').textContent=u.calls;
  var rate = u.in_t ? (100*u.cache_t/u.in_t).toFixed(1) : '0.0';
  document.getElementById('k_cache').textContent = rate+'% ('+(u.cache_t/1000).toFixed(1)+'k)';
  document.getElementById('k_tok').textContent=(u.in_t/1000).toFixed(1)+'k / '+(u.out_t/1000).toFixed(1)+'k';
  var score = d.summary.score != null ? d.summary.score : s.solved;
  document.getElementById('score').textContent=score;
  document.getElementById('k_score').textContent=score;
}
async function refreshAgents(){
  const r=await fetch('/api/agents'); const d=await r.json();
  const box=document.getElementById('agents'); box.innerHTML='';
  const sel=document.getElementById('chal'), cur=sel.value;
  sel.innerHTML='';
  (d.challenges||[]).forEach(function(a){
    var o=document.createElement('option'); o.value=a.id; o.textContent=a.id;
    if(cur===a.id)o.selected=true; sel.appendChild(o);
  });
  (d.agents||[]).forEach(function(a){
    var st=a.state||'idle';
    var div=document.createElement('div'); div.className='agent';
    div.style.cursor='pointer';
    var pct=a.budget_limit?(Math.min(100,(a.budget_used||0)/a.budget_limit*100)).toFixed(0):0;
    var scoreLine = a.score!=null ? '<div class="meta" style="color:var(--ok)">得分 '+a.score+(a.correct!=null?' · flags '+a.correct+'/'+a.total:'')+'</div>' : '';
    div.innerHTML='<div class="row1"><span class="cid">'+esc(a.id)+'</span>'+
      '<span class="pill st-'+st+'">'+st+'</span></div>'+
      '<div class="meta" style="color:var(--faint)">'+esc(a.title||'')+'</div>'+
      '<div class="meta"><span>facts '+a.facts+'</span><span>intents '+a.intents+'</span>'+
      '<span>LLM '+a.llm_calls+'</span></div>'+
      scoreLine+
      '<div class="bar"><i style="width:'+pct+'%"></i></div>';
    div.onclick=function(){ openChallenge(a.id); };
    box.appendChild(div);
  });
}
async function refreshGraph(){
  const cid=document.getElementById('chal').value||null;
  const r=await fetch('/api/graph'+(cid?'?challenge='+encodeURIComponent(cid):''));
  const d=await r.json();
  graph.load(d.graph||{facts:[],intents:[]});
  document.getElementById('g_sub').textContent=d.challenge?('题 '+d.challenge):'';
  graph.onNodeClick=function(n){ openDrawer({type:'graph:'+n.status,agent_id:n.label,
    ts:Date.now()/1000,params:n.raw&&n.raw.payload,result:n.raw}); };
}
function startSSE(){
  var es=new EventSource('/api/stream');
  es.onmessage=function(m){ try{ addLog(JSON.parse(m.data)); }catch(e){} };
  es.onerror=function(){};
}
tick(); refreshAgents(); refreshGraph(); loadBacklog(); startSSE();
setInterval(tick,3000); setInterval(refreshAgents,3000); setInterval(refreshGraph,3000);
</script></body></html>"""


def create_app(db_path) -> Flask:
    app = Flask(__name__, static_folder=str(FRONTEND_DIR),
                static_url_path="/static")

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

    @app.get("/api/stream")
    def stream():
        """SSE 原子操作日志流：events 表为唯一事实源，每条日志对应真实调用。"""
        after = int(request.args.get("after", 0) or 0)

        def gen():
            yield "retry: 1000\n\n"
            for ev in poll_events(str(db_path), after_id=after):
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
        return Response(gen(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})

    @app.get("/api/agents")
    def agents():
        db = StateDB(db_path)
        try:
            challenges = db.list_challenges()
            platform = {m["key"]: m["value"] for m in db.get_memory("platform")}
            out = []
            for ch in challenges:
                cid = ch["id"]
                rows = db.list_events(limit=400)
                mine = [e for e in rows if e.get("ref_id") == cid]
                llm_calls = sum(1 for e in mine
                                if str(e.get("payload", {}).get("tool", "")).startswith("llm:"))
                budget_used = budget_limit = None
                for e in mine:
                    p = e.get("payload", {})
                    if p.get("budget_used") is not None:
                        budget_used = p["budget_used"]
                        budget_limit = p.get("budget_limit")
                        break
                plat = platform.get(f"platform:{cid}", {})
                out.append({
                    "id": cid,
                    "title": ch.get("title", "")[:60],
                    "state": db.get_challenge_state(cid),
                    "facts": len(db.list_facts(cid)),
                    "intents": len(db.list_intents(cid)),
                    "llm_calls": llm_calls,
                    "budget_used": budget_used,
                    "budget_limit": budget_limit,
                    "score": plat.get("score"),
                    "correct": plat.get("correct"),
                    "total": plat.get("total"),
                })
            return jsonify({"challenges": [{"id": c["id"]} for c in challenges],
                            "agents": out})
        finally:
            db.close()

    @app.get("/api/events")
    def events_backlog():
        """最近 N 条事件（页面加载即填充时间轴，不等 SSE 慢速回放）。"""
        limit = min(int(request.args.get("limit", 300) or 300), 1000)
        db = StateDB(db_path)
        try:
            return jsonify({"events": db.list_events(limit=limit)})
        finally:
            db.close()

    @app.get("/api/challenge/<cid>")
    def challenge_detail(cid: str):
        """单题解题详情：状态/黑板/发现/提交/事件（Agent 卡片点击跳转）。"""
        db = StateDB(db_path)
        try:
            ch = db.get_challenge(cid)
            if not ch:
                return jsonify({"error": "not found"}), 404
            events = [e for e in db.list_events(limit=800)
                      if e.get("ref_id") == cid][:60]
            return jsonify({
                "challenge": ch,
                "state": db.get_challenge_state(cid),
                "facts": db.list_facts(cid),
                "intents": db.list_intents(cid),
                "findings": db.list_findings(cid),
                "submissions": db.list_submissions(cid),
                "events": events,
            })
        finally:
            db.close()

    @app.get("/api/graph")
    def graph():
        db = StateDB(db_path)
        try:
            cid = request.args.get("challenge") or None
            if cid is None:
                challenges = [c for c in db.list_challenges()
                              if c["status"] in ("pending", "solving", "solved")]
                if challenges:
                    cid = challenges[0]["id"]
            facts, intents = [], []
            if cid:
                facts = [{"id": f["id"], "key": f["key"], "payload": f["payload"],
                          "status": f["status"], "confidence": f["confidence"]}
                         for f in db.list_facts(cid)]
                intents = [{"id": i["id"], "key": i["key"], "payload": i["payload"],
                            "status": i["status"], "priority": i["confidence"]}
                           for i in db.list_intents(cid)]
            return jsonify({"challenge": cid,
                            "graph": {"facts": facts, "intents": intents}})
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
    # 实盘分数：跑分进程把平台进度写入 memory(kind=platform)，看板据此显示真实总分；
    # 通用模式（无 platform 记录）回退为已解出题数。
    score = sum(int((m.get("value") or {}).get("score") or 0)
                for m in db.get_memory("platform"))
    solved = sum(1 for c in challenges if c["status"] == "solved")
    return {
        "challenges": {
            "total": len(challenges),
            "solved": solved,
            "pending": sum(1 for c in challenges if c["status"] in ("pending", "solving")),
            "idle": sum(1 for c in challenges if c["status"] == "idle"),
        },
        "score": score or solved,
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
