"""HuntForge 工具链 MCP Server（stdio JSON-RPC，供 Claude Code 等 MCP 客户端连接）。

协议：Model Context Protocol（initialize / tools/list / tools/call / ping）。
工具面 = huntforge.tools.TOOLS 注册表（TCP/telnet + WSL Kali 全工具链）。

用法：
    python scripts/mcp_server.py                      # 标准 stdio
    python -m huntforge.tools.mcp_server              # 同入口

配置到 Claude Code 示例（claude mcp add）：
    claude mcp add huntforge -- python E:\\traexiangmu\\baidu-agent\\scripts\\mcp_server.py
"""
from __future__ import annotations

import json
import sys
from typing import Any, Optional

# Windows 控制台默认 GBK 会污染 JSON-RPC 字节流（MCP 客户端一律按 UTF-8 解析）；
# 服务器进程强制 UTF-8 输出，与协议要求一致。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from huntforge.tools import TOOLS, call_tool  # noqa: E402
from huntforge.tools.catalog import CATALOG  # noqa: E402

NAME = "huntforge"
VERSION = "1.1.0"
PROTOCOL = "2024-11-05"


def _jsonrpc(method: str, params: dict, id_: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": None,
            "method": method, "params": params}


def handle(method: str, params: Optional[dict], id_: Any) -> dict:
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": id_, "result": {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": NAME, "version": VERSION},
        }}
    if method == "notifications/initialized":
        return {"jsonrpc": "2.0", "id": id_, "result": None}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": id_, "result": {}}
    if method == "tools/list":
        tools = [{
            "name": name,
            "description": meta["description"],
            "inputSchema": {
                "type": "object",
                "properties": _params_schema(meta.get("params", {})),
                "required": (["tool", "target"] if name.startswith("kali_")
                             else [k for k, v in meta.get("params", {}).items()
                                   if "=" not in v]),
            },
        } for name, meta in TOOLS.items()]
        # 声明式目录条目（kali/generator/poc）
        for rec in CATALOG.tools:
            if rec.slug in {t["name"] for t in tools}:
                continue
            props = {"target": {"type": "string", "description": "目标 URL/主机"}}
            if rec.integration == "generator":
                props = {"format": {"type": "string"},
                         "cmd": {"type": "string"},
                         "token": {"type": "string"},
                         "attack": {"type": "string"},
                         "gadget": {"type": "string"},
                         "method": {"type": "string"},
                         "payload": {"type": "string"}}
                props["target"] = {"type": "string"}
            required = ["target"] if rec.integration in ("kali", "poc") else []
            tools.append({
                "name": rec.slug,
                "description": f"{rec.description}（tier={rec.tier}, side_effect={rec.side_effect}）",
                "inputSchema": {"type": "object", "properties": props,
                                "required": required},
            })
        return {"jsonrpc": "2.0", "id": id_, "result": {"tools": tools}}
    if method == "tools/call":
        name = (params or {}).get("name")
        args = (params or {}).get("arguments") or {}
        meta = TOOLS.get(name)
        if not meta:
            return _err(id_, -32602, f"unknown tool: {name}")
        # params spec 里的固定标量默认值（如 kali 系列的 tool=katana）自动补进参数
        merged = dict(args)
        for k, v in (meta.get("params") or {}).items():
            if k not in merged and "=" not in v and v not in ("str", "int", "float", "bool"):
                merged[k] = v
        try:
            result = call_tool(name, **merged)
        except Exception as exc:  # noqa: BLE001
            return _err(id_, -32000, str(exc))
        text = json.dumps(result, ensure_ascii=False)[:8000]
        return {"jsonrpc": "2.0", "id": id_, "result": {
            "content": [{"type": "text", "text": text}],
            "isError": not result.get("ok", False)}}
    return _err(id_, -32601, f"method not found: {method}")


def _params_schema(params: dict) -> dict:
    props = {}
    for k, v in params.items():
        t = v.split("=")[0].lower()
        props[k] = {"type": {"int": "integer", "float": "number", "bool": "boolean"}.get(t, "string")}
    return props


def _err(id_: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(msg.get("method"), msg.get("params"), msg.get("id"))
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
