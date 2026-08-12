"""tools 包测试：TCP 探测 / telnet 登录 / 注册表调用。"""
import socket
import threading

from huntforge.tools import call_tool
from huntforge.tools.tcp_service import extract_flags, probe, run


def _serve_once(payload_responses: dict[bytes, bytes], port: int = 0):
    """起一个一次性 TCP 服务：按收到的首行返回预置响应。"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", port))
    srv.listen(5)
    srv.settimeout(10)
    port = srv.getsockname()[1]
    errors = []

    def worker():
        while True:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                break
            except OSError:
                break
            try:
                data = conn.recv(2048)
                first = data.split(b"\n", 1)[0].strip()
                resp = payload_responses.get(first, b"unknown\n")
                if b"<banner>" in payload_responses and not data:
                    resp = payload_responses[b"<banner>"]
                conn.sendall(resp)
            except OSError as exc:
                errors.append(str(exc))
            finally:
                conn.close()
        srv.close()

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return port, t, errors


def test_extract_flags():
    text = "ok flag{abc_123} x FLAG{xyz} again flag{abc_123}"
    assert extract_flags(text) == ["flag{abc_123}", "FLAG{xyz}"]


def test_probe_finds_flag_in_response():
    port, t, _ = _serve_once({b"GET flag": b"secret: flag{tcp_protocol_secret}\n"})
    results = probe("127.0.0.1", port, payloads=[b"GET flag\r\n"], timeout=5)
    t.join(timeout=11)
    assert any("flag{tcp_protocol_secret}" in r["response"] for r in results)


def test_tool_registry_call():
    port, t, _ = _serve_once({b"GET flag": b"flag{tool_registry_ok}\n"})
    result = call_tool("tcp_probe", host="127.0.0.1", port=port, timeout=5)
    t.join(timeout=11)
    assert result["ok"] is True
    assert "flag{tool_registry_ok}" in result["flags"]


def test_unknown_tool_raises():
    import pytest
    with pytest.raises(ValueError):
        call_tool("no_such_tool")


def test_tcp_service_cli_module_runs():
    # run() 聚合入口
    port, t, _ = _serve_once({b"GET flag": b"flag{run_entry}\n"})
    out = run("127.0.0.1", port, timeout=5)
    t.join(timeout=11)
    assert out["ok"] is True and "flag{run_entry}" in out["flags"]
