/* HuntForge Fact-Intent 探索图（借鉴 Cairn 黑板 + 图可视化）
 * 纯原生 JS 力导向布局，无外部依赖（离线可用）。
 * 节点：Fact=绿（已确认发现）、Intent=蓝（待办）、claimed=橙（执行中）、done=灰。
 * 边：Intent -> 其 payload.fact_keys 引用的 Fact（决策依据链）。
 * 数据源：/api/graph（后端读黑板表，与 SSE 日志同源，零模拟）。
 */
(function () {
  "use strict";

  var COLORS = {
    fact: "#34d399",
    intent: "#60a5fa",
    "intent-claimed": "#fbbf24",
    "intent-done": "#64748b",
    "intent-skipped": "#64748b",
    edge: "#2a3a5c",
    label: "#c7d6ef",
  };

  function GraphView(containerId) {
    this.container = document.getElementById(containerId);
    this.nodes = [];
    this.links = [];
    this.selected = null;
    this.onNodeClick = null;
  }

  GraphView.prototype.load = function (data) {
    var self = this;
    var facts = (data.facts || []).map(function (f) {
      return { id: "f" + f.id, kind: "fact", label: f.key,
               status: f.status, conf: f.confidence, raw: f };
    });
    var intents = (data.intents || []).map(function (i) {
      return { id: "i" + i.id, kind: "intent", label: i.key,
               status: i.status, conf: i.priority, raw: i };
    });
    var byKey = {};
    facts.forEach(function (f) { byKey[f.label] = f.id; });
    var links = [];
    intents.forEach(function (n) {
      var keys = (n.raw.payload && n.raw.payload.fact_keys) || [];
      keys.forEach(function (k) {
        if (byKey[k]) {
          links.push({ source: n.id, target: byKey[k], kind: "edge" });
        }
      });
    });
    this.nodes = facts.concat(intents);
    this.links = links;
    this._layout();
    this._render();
  };

  GraphView.prototype._layout = function () {
    // 力导向布局（带速度与冷却的经典算法）：斥力撑开 + 弹簧维持边距 +
    // 弱中心引力收拢 + 每轮阻尼。旧版把中心引力开太大导致全部蜷缩成团。
    var nodes = this.nodes;
    var links = this.links;
    var W = this.container.clientWidth || 700;
    var H = this.container.clientHeight || 460;
    var cx = W / 2, cy = H / 2;
    var i, j;
    // 初始位置：均匀圆形铺开（不再是中心随机点）
    var radius0 = Math.min(W, H) / 2.6;
    for (i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      if (typeof n.x !== "number") {
        var ang = (i / Math.max(nodes.length, 1)) * Math.PI * 2;
        n.x = cx + radius0 * Math.cos(ang) * (0.7 + Math.random() * 0.4);
        n.y = cy + radius0 * Math.sin(ang) * (0.7 + Math.random() * 0.4);
        n.vx = 0; n.vy = 0;
      }
    }
    var REPULSION = 4200, SPRING_LEN = 120, SPRING_K = 0.045,
        CENTER = 0.006, DAMP = 0.82, ITER = 260, CAP = 6;
    var idx = {};
    for (i = 0; i < nodes.length; i++) idx[nodes[i].id] = nodes[i];
    for (var it = 0; it < ITER; it++) {
      var cool = 1 - it / ITER;   // 模拟退火：先猛后稳
      // 两两斥力
      for (i = 0; i < nodes.length; i++) {
        for (j = i + 1; j < nodes.length; j++) {
          var a = nodes[i], b = nodes[j];
          var dx = a.x - b.x, dy = a.y - b.y;
          var d2 = dx * dx + dy * dy;
          if (d2 < 1) { dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); d2 = 1; }
          var d = Math.sqrt(d2);
          var f = Math.min(REPULSION * cool / d2, CAP);
          var fx = (dx / d) * f, fy = (dy / d) * f;
          a.vx += fx; a.vy += fy;
          b.vx -= fx; b.vy -= fy;
        }
      }
      // 边弹簧
      for (i = 0; i < links.length; i++) {
        var s = typeof links[i].source === "string" ? idx[links[i].source] : links[i].source;
        var t = typeof links[i].target === "string" ? idx[links[i].target] : links[i].target;
        if (!s || !t) continue;
        var ex = s.x - t.x, ey = s.y - t.y;
        var el = Math.sqrt(ex * ex + ey * ey) || 1;
        var pull = (el - SPRING_LEN) * SPRING_K * cool;
        var px = (ex / el) * pull, py = (ey / el) * pull;
        s.vx -= px; s.vy -= py;
        t.vx += px; t.vy += py;
      }
      // 弱中心引力 + 积分 + 阻尼 + 边界
      for (i = 0; i < nodes.length; i++) {
        var m = nodes[i];
        m.vx += (cx - m.x) * CENTER * cool;
        m.vy += (cy - m.y) * CENTER * cool;
        m.vx *= DAMP; m.vy *= DAMP;
        m.x += m.vx; m.y += m.vy;
        m.x = Math.max(18, Math.min(W - 18, m.x));
        m.y = Math.max(18, Math.min(H - 18, m.y));
      }
    }
    // 收尾：距离过近的节点对强制推开（消除残余重叠）
    for (var pass = 0; pass < 4; pass++) {
      var moved = false;
      for (i = 0; i < nodes.length; i++) {
        for (j = i + 1; j < nodes.length; j++) {
          var p = nodes[i], q = nodes[j];
          var dx2 = p.x - q.x, dy2 = p.y - q.y;
          var dist = Math.sqrt(dx2 * dx2 + dy2 * dy2);
          if (dist < 34 && dist > 0.01) {
            var push = (34 - dist) / 2;
            p.x += (dx2 / dist) * push; p.y += (dy2 / dist) * push;
            q.x -= (dx2 / dist) * push; q.y -= (dy2 / dist) * push;
            moved = true;
          }
        }
      }
      if (!moved) break;
    }
  };

  GraphView.prototype._find = function (id) {
    for (var i = 0; i < this.nodes.length; i++) {
      if (this.nodes[i].id === id) return this.nodes[i];
    }
    return null;
  };

  GraphView.prototype._color = function (n) {
    if (n.kind === "fact") return COLORS.fact;
    if (n.status === "claimed") return COLORS["intent-claimed"];
    if (n.status === "done" || n.status === "skipped") return COLORS["intent-done"];
    return COLORS.intent;
  };

  GraphView.prototype._render = function () {
    var self = this;
    var svg = this.svg;
    if (!svg) {
      svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("width", "100%");
      svg.setAttribute("height", "100%");
      this.container.innerHTML = "";
      this.container.appendChild(svg);
      this.svg = svg;
      svg.addEventListener("click", function (ev) {
        if (ev.target.__hfNode && self.onNodeClick) {
          self.onNodeClick(ev.target.__hfNode.raw);
        }
      });
    }
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    var i, l;
    for (i = 0; i < this.links.length; i++) {
      l = this.links[i];
      var s = typeof l.source === "string" ? this._find(l.source) : l.source;
      var t = typeof l.target === "string" ? this._find(l.target) : l.target;
      if (!s || !t) continue;
      var line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("x1", s.x); line.setAttribute("y1", s.y);
      line.setAttribute("x2", t.x); line.setAttribute("y2", t.y);
      line.setAttribute("stroke", COLORS.edge);
      line.setAttribute("stroke-width", "1");
      line.setAttribute("stroke-dasharray", "3,3");
      svg.appendChild(line);
    }
    for (i = 0; i < this.nodes.length; i++) {
      var n = this.nodes[i];
      var g = document.createElementNS("http://www.w3.org/2000/svg", "g");
      var circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", n.x); circle.setAttribute("cy", n.y);
      circle.setAttribute("r", n.kind === "fact" ? 11 : 8);
      circle.setAttribute("fill", this._color(n));
      circle.setAttribute("stroke", "#060a13");
      circle.setAttribute("stroke-width", "2");
      if (n.kind === "intent" && n.status === "claimed") {
        var glow = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        glow.setAttribute("cx", n.x); glow.setAttribute("cy", n.y);
        glow.setAttribute("r", "14");
        glow.setAttribute("fill", "none");
        glow.setAttribute("stroke", "#fbbf24");
        glow.setAttribute("stroke-width", "1.5");
        glow.setAttribute("opacity", "0.5");
        var pulse = document.createElementNS("http://www.w3.org/2000/svg", "animate");
        pulse.setAttribute("attributeName", "r");
        pulse.setAttribute("values", "10;18;10");
        pulse.setAttribute("dur", "1.2s");
        pulse.setAttribute("repeatCount", "indefinite");
        glow.appendChild(pulse);
        g.appendChild(glow);
      }
      var text = document.createElementNS("http://www.w3.org/2000/svg", "text");
      text.setAttribute("x", n.x + 14); text.setAttribute("y", n.y + 4);
      text.setAttribute("fill", COLORS.label);
      text.setAttribute("font-size", "11.5");
      text.setAttribute("font-family", "ui-monospace,Consolas,monospace");
      text.textContent = n.label.length > 28 ? n.label.slice(0, 28) + "…" : n.label;
      circle.__hfNode = n;
      text.__hfNode = n;
      g.appendChild(circle); g.appendChild(text);
      svg.appendChild(g);
    }
  };

  window.HuntForgeGraph = GraphView;
})();
