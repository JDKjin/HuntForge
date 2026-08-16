"""MCP stdio 自检：按 Claude Code 握手顺序验证 huntforge MCP server（容器内用）。"""
import json
import subprocess
import sys

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))


def handshake() -> bool:
    proc = subprocess.Popen(
        [sys.executable, "scripts/mcp_server.py"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", bufsize=1,
        cwd=str(__import__("pathlib").Path(__file__).resolve().parents[1]),
    )

    def call(method, params=None, id_=1):
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method,
                                     "params": params or {}, "id": id_}) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline().strip()
        return json.loads(line)

    ok = True
    try:
        r = call("initialize", {"protocolVersion": "2024-11-05"})
        assert r["result"]["serverInfo"]["name"] == "huntforge", r
        call("notifications/initialized", {}, 0)
        r = call("ping")
        assert r["result"] == {}
        r = call("tools/list")
        names = {t["name"] for t in r["result"]["tools"]}
        assert "tcp_probe" in names and "kali_katana" in names, names
        print(f"MCP OK: {len(names)} tools")
    except Exception as exc:  # noqa: BLE001
        ok = False
        print(f"MCP FAIL: {exc}")
    finally:
        try:
            proc.stdin.close()
            proc.wait(timeout=8)
        except Exception:  # noqa: BLE001
            proc.kill()
    return ok


if __name__ == "__main__":
    sys.exit(0 if handshake() else 1)
