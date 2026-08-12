"""Agent 可调用工具包（MCP 风格注册表）。

非 HTTP 靶场（TCP 协议 pwn / telnet 远程登录等）超出 web 流水线能力，
这里提供原生 socket 实现的工具，agent 通过 call_tool(name, **kwargs) 统一调用。

新增工具：在下方 TOOLS 注册（name/description/参数），实现放独立模块。
"""
from __future__ import annotations

import importlib
import logging

log = logging.getLogger("huntforge.tools")

# 工具注册表（MCP 风格：name → 元数据 + 实现入口）
TOOLS = {
    "tcp_probe": {
        "description": "连接 TCP 协议服务，读 banner、发送通用探测载荷，扫描响应中的 flag{}",
        "module": "huntforge.tools.tcp_service",
        "fn": "run",
        "params": {"host": "str", "port": "int", "timeout": "float=8"},
    },
    "telnet_login": {
        "description": "极小 telnet 客户端：默认凭据登录 + 命令枚举找 flag{}",
        "module": "huntforge.tools.telnet_login",
        "fn": "run",
        "params": {"host": "str", "port": "int", "timeout": "float=30"},
    },
}


def call_tool(name: str, **kwargs) -> dict:
    """MCP 风格统一调用入口。未知工具抛 ValueError。"""
    meta = TOOLS.get(name)
    if not meta:
        raise ValueError(f"unknown tool: {name}")
    try:
        module = importlib.import_module(meta["module"])
        fn = getattr(module, meta["fn"])
        return fn(**kwargs)
    except Exception as exc:  # noqa: BLE001 - 工具失败不拖垮主流程
        log.warning("tool %s failed: %s", name, exc)
        return {"ok": False, "error": str(exc), "flags": []}
