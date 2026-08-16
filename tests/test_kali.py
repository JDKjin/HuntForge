"""Kali 工具桥测试：目标校验、禁用降级、端点抽取、MCP 协议往返。"""
from huntforge.tools import kali


def test_validate_target():
    assert kali.validate_target("http://10.0.1.5:8080/x") == "http://10.0.1.5:8080/x"
    assert kali.validate_target("https://evil.com") is None
    assert kali.validate_target("192.168.1.1") == "192.168.1.1"
    assert kali.validate_target("") is None
    assert kali.validate_target("http://localhost:8000/") == "http://localhost:8000"


def test_run_rejects_unknown_tool(monkeypatch):
    monkeypatch.setenv("HUNTFORGE_KALI", "1")
    r = kali.run("not_a_tool", "http://10.0.0.1")
    assert not r["ok"] and "unknown" in r["error"]


def test_run_disabled(monkeypatch):
    monkeypatch.setenv("HUNTFORGE_KALI", "0")
    r = kali.run("katana", "http://10.0.0.1")
    assert not r["ok"] and "disabled" in r["error"]


def test_run_rejects_non_sandbox_target(monkeypatch):
    monkeypatch.setenv("HUNTFORGE_KALI", "1")
    r = kali.run("katana", "https://evil.com")
    assert not r["ok"] and "rejected" in r["error"]


def test_extract_endpoints():
    eps = kali.extract_endpoints(
        "http://10.0.1.5/admin http://10.0.1.5/api/v1/users /login /style.css",
        "http://10.0.1.5:80")
    assert "http://10.0.1.5/admin" in eps
    assert any("api/v1/users" in e for e in eps)
    assert not any(".css" in e for e in eps)


def test_mcp_server_roundtrip():
    from scripts import mcp_server
    r = mcp_server.handle("tools/list", None, 1)
    names = [t["name"] for t in r["result"]["tools"]]
    assert "kali_katana" in names and "tcp_probe" in names
    # 非法目标被 Kali 校验拒绝 → isError
    r2 = mcp_server.handle(
        "tools/call",
        {"name": "kali_nmap", "arguments": {"target": "https://evil.com"}}, 2)
    assert r2["result"]["isError"] is True
    # 未知工具 → JSON-RPC 错误
    r3 = mcp_server.handle("tools/call", {"name": "nope"}, 3)
    assert r3["error"]["code"] == -32602
