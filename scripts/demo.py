"""HuntForge 一键 Demo（本地可复现，无外部依赖、无模型密钥）。

按顺序演示：
  1) 环境自检
  2) MCP 工具链冒烟（25 工具）
  3) 知识库演示：方法论召回 + 离线 CVE 情报
  4) 本地 mock 全自动解题（7 靶场：拉题→挖掘→门禁→幂等提交→报表）
  5) 驾驶舱编排循环演示（stub 平台：next 选题 → brief 开容器 →
     单题会话 → harvest 收割关容器——与托管沙箱同一套机制）

用法：python scripts/demo.py [--skip-mock] [--skip-loop]
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

GREEN, CYAN, YELLOW, RESET = "\033[32m", "\033[36m", "\033[33m", "\033[0m"


def sec(title: str):
    print(f"\n{CYAN}{'=' * 66}\n▶ {title}\n{'=' * 66}{RESET}", flush=True)


def run(cmd: list[str], timeout: float = 300, ok_codes=(0,)) -> str:
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode not in ok_codes:
        print(f"{YELLOW}[warn] rc={r.returncode}{RESET}", flush=True)
    return out


# ---------- stub 平台（与容器编排演示配套）----------
class Stub(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/openapi/v1/challenges":
            return self._send(self.server.chs)
        self._send({"detail": "nf"}, 404)

    def do_POST(self):
        from urllib.parse import parse_qs, urlparse
        p = urlparse(self.path)
        q = parse_qs(p.query)
        code = (q.get("unique_code") or [None])[0]
        if p.path.endswith("/start"):
            return self._send({"unique_code": code,
                               "container_addr": ["127.0.0.1:18080"]})
        if p.path.endswith("/close"):
            return self._send({"unique_code": code, "closed": True})
        if p.path.endswith("/submit"):
            ln = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(ln))
            if body.get("flag") == "FLAG{demo}":
                return self._send({"correct": True, "awarded": 300,
                                   "cumulative_score": 300,
                                   "correct_flag_count": 1,
                                   "total_flag_count": 1})
            return self._send({"correct": False, "awarded": 0,
                               "cumulative_score": 0,
                               "correct_flag_count": 0,
                               "total_flag_count": 1})
        self._send({"detail": "nf"}, 404)


def demo_loop():
    """编排循环：next → brief → （模拟单题会话产物）→ harvest。"""
    srv = ThreadingHTTPServer(("127.0.0.1", 19001), Stub)
    srv.chs = [
        {"unique_code": "demo-01", "total_score": 300, "flag_count": 1,
         "correct_flag_count": 0, "is_completed": False,
         "difficulty": "easy", "container_status": "stopped",
         "container_addr": [], "description": "企业报表系统，支持导出报表"},
        {"unique_code": "demo-02", "total_score": 1200, "flag_count": 4,
         "correct_flag_count": 0, "is_completed": False,
         "difficulty": "hard", "container_status": "stopped",
         "container_addr": [], "description": "官网渗透进内网取机密数据"},
    ]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    import os
    os.environ["BENCHMARK_BASE_URL"] = "http://127.0.0.1:19001"
    os.environ["BENCHMARK_TOKEN"] = "demo-token"
    demo_art = ROOT / "artifacts-demo"
    os.environ.setdefault("HUNTFORGE_ARTIFACTS_DIR", str(demo_art))
    # 每次演示从干净状态开始（选题尝试计数/冷却不跨次残留）
    import shutil
    shutil.rmtree(demo_art, ignore_errors=True)

    print("① 选题（期望值 + 冷却 + 公平调度）：", flush=True)
    out = run([sys.executable, "-m", "huntforge.driver", "next"])
    print("   " + out.strip().splitlines()[-1], flush=True)
    print("② 长耗时题排除通道：", flush=True)
    out = run([sys.executable, "-m", "huntforge.driver", "next",
               "--exclude-longhaul"])
    print("   " + out.strip().splitlines()[-1], flush=True)

    print("③ brief：开容器 + 题面 + 知识召回（输出截断）：", flush=True)
    out = run([sys.executable, "-m", "huntforge.driver", "brief", "demo-01"])
    d = json.loads(out.strip().splitlines()[-1])
    print(f"   code={d.get('code')} target={d.get('target')} "
          f"playbook={str(d.get('playbook'))[:40]}...", flush=True)

    print("④ 模拟单题会话产物 → harvest 收割提交：", flush=True)
    art = Path(os.environ["HUNTFORGE_ARTIFACTS_DIR"]) / "demo-01"
    art.mkdir(parents=True, exist_ok=True)
    (art / "session.log").write_text(
        "假设：导出文件名未过滤 → 注入 cat /challenge/flag.txt\n"
        "FLAG: FLAG{demo}\n", encoding="utf-8")
    out = run([sys.executable, "-m", "huntforge.driver", "harvest",
               "demo-01"])
    print("   " + out.strip().splitlines()[-2], flush=True)
    print("   " + out.strip().splitlines()[-1], flush=True)
    srv.shutdown()


def main():
    sec("HuntForge（铸猎）一键 Demo")
    skip_mock = "--skip-mock" in sys.argv
    skip_loop = "--skip-loop" in sys.argv

    sec("1) 环境自检")
    import platform
    print(f"   Python {platform.python_version()} @ {sys.executable}")

    sec("2) MCP 工具链冒烟")
    out = run([sys.executable, "scripts/mcp_handshake.py"])
    print("   " + out.strip().splitlines()[-1])

    sec("3) 知识库演示（离线）")
    print("   方法论召回（报表导出类题面）：", flush=True)
    out = run([sys.executable, "-m", "huntforge.driver", "skill",
               "企业报表系统支持导出报表"])
    last = out.strip().splitlines()[-1]
    d = json.loads(last)
    print(f"   手册类型={d['hint']['type']} 召回 skill {len(d['skills'])} 份",
          flush=True)
    print("   离线 CVE 情报（泛微指纹）：", flush=True)
    out = run([sys.executable, "-m", "huntforge.driver", "cve", "泛微 e-cology"])
    d = json.loads(out.strip().splitlines()[-1])
    print(f"   命中 {len(d['hits'])} 条 / 索引 {d['index_cves']} 个 CVE"
          f" / 模板示例 {d['hits'][0].get('nuclei_templates')}", flush=True)

    if not skip_mock:
        sec("4) 本地 mock 全自动解题（7 靶场闭环）")
        out = run([sys.executable, "-m", "huntforge.main", "--mock",
                   "--max-time", "300"])
        for ln in out.strip().splitlines():
            if "HUNTFORGE_SUMMARY" in ln or "solved" in ln:
                print("   " + ln[:400], flush=True)

    if not skip_loop:
        sec("5) 驾驶舱编排循环演示（stub 平台，与托管沙箱同机制）")
        demo_loop()

    sec("Demo 完成")
    print(f"{GREEN}以上均为本地真实执行：拉题→选题→开容器→会话→收割提交→"
          f"报表全链路。{RESET}", flush=True)
    print("  托管模式：docker build -t huntforge:latest . 后平台注入环境变量"
          "即全自动运行；详见 docs/demo-cases.md", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
