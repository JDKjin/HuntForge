"""Agent 可调用工具包（MCP 风格注册表）。

非 HTTP 靶场（TCP 协议 pwn / telnet 远程登录等）超出 web 流水线能力，
这里提供原生 socket 实现的工具，agent 通过 call_tool(name, **kwargs) 统一调用。

新增工具：在下方 TOOLS 注册（name/description/参数），实现放独立模块。
"""
from __future__ import annotations

import importlib
import logging

from .catalog import CATALOG

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
    # ---- WSL Kali 工具链（katana/ffuf/nuclei/sqlmap/dirsearch/nmap/httpx）----
    "kali_katana": {
        "description": "Kali 内 katana 爬虫：爬取目标站点全部端点（-jc 含 JS 提取）",
        "module": "huntforge.tools.kali",
        "fn": "run",
        "params": {"tool": "katana", "target": "str", "timeout": "float=60"},
    },
    "kali_ffuf_dirs": {
        "description": "Kali 内 ffuf 目录爆破（seclists 词表，40 并发）",
        "module": "huntforge.tools.kali",
        "fn": "run",
        "params": {"tool": "ffuf_dirs", "target": "str", "timeout": "float=90"},
    },
    "kali_nuclei": {
        "description": "Kali 内 nuclei 扫描（technologies 指纹模板或低危模板）",
        "module": "huntforge.tools.kali",
        "fn": "run",
        "params": {"tool": "nuclei_tech", "target": "str", "timeout": "float=120"},
    },
    "kali_sqlmap": {
        "description": "Kali 内 sqlmap 智能检测（level1/risk1 + crawl2，batch 模式）",
        "module": "huntforge.tools.kali",
        "fn": "run",
        "params": {"tool": "sqlmap_check", "target": "str", "timeout": "float=180"},
    },
    "kali_dirsearch": {
        "description": "Kali 内 dirsearch 多扩展名目录枚举",
        "module": "huntforge.tools.kali",
        "fn": "run",
        "params": {"tool": "dirsearch", "target": "str", "timeout": "float=90"},
    },
    "kali_nmap": {
        "description": "Kali 内 nmap 端口扫描（top-100 端口，-Pn -sT）",
        "module": "huntforge.tools.kali",
        "fn": "run",
        "params": {"tool": "nmap_top", "target": "str", "timeout": "float=90"},
    },
    "kali_httpx": {
        "description": "Kali 内 httpx 探测（状态码/标题/技术栈指纹）",
        "module": "huntforge.tools.kali",
        "fn": "run",
        "params": {"tool": "httpx_probe", "target": "str", "timeout": "float=60"},
    },
    # ---- 逆向自动化（容器原生：triage/本地回放/angr 求解）----
    "bin_triage": {
        "description": "二进制静态勘查：file/checksec/r2 导入与函数数/flag 相关字符串/高熵加密段",
        "module": "huntforge.tools.rev",
        "fn": "triage_tool",
        "params": {"file": "str"},
    },
    "bin_run": {
        "description": "本地执行二进制（可选候选密钥），输出扫描 flag{}",
        "module": "huntforge.tools.rev",
        "fn": "run_tool",
        "params": {"file": "str", "key": "str=", "timeout": "float=15"},
    },
    "bin_angr": {
        "description": "angr 符号执行求解合法输入（license 校验类 keygen）",
        "module": "huntforge.tools.rev",
        "fn": "angr_tool",
        "params": {"file": "str", "stdin_len": "int=32", "timeout": "float=150"},
    },
}


def call_tool(name: str, **kwargs) -> dict:
    """MCP 风格统一调用入口。

    优先查旧注册表（TOOLS），再查声明式目录（CATALOG）——
    kali/generator/poc 三类工具都从 config/tools.yaml 驱动。
    未知工具抛 ValueError；stateful/exploit 未授权被门禁拒绝。
    """
    meta = TOOLS.get(name)
    if not meta:
        rec = CATALOG.get(name)
        if rec is None:
            raise ValueError(f"unknown tool: {name}")
        auth_err = CATALOG.authorize(name, kwargs.pop("allow_side_effects", None))
        if auth_err:
            return {"ok": False, "error": auth_err}
        try:
            if rec.integration == "kali":
                from . import kali
                return kali.run(rec.slug, kwargs.get("target", ""),
                                timeout=kwargs.get("timeout"),
                                allow_side_effects=kwargs.get("allow_side_effects"))
            if rec.integration == "generator":
                module = importlib.import_module(rec.module)
                fn = getattr(module, rec.fn)
                return fn(**kwargs)
            if rec.integration == "poc":
                from . import targeted
                return targeted._run_poc(rec, kwargs.get("target", ""),
                                         rec.effective_timeout())
            raise ValueError(f"unsupported integration: {rec.integration}")
        except Exception as exc:  # noqa: BLE001
            log.warning("tool %s failed: %s", name, exc)
            return {"ok": False, "error": str(exc), "flags": []}
    try:
        module = importlib.import_module(meta["module"])
        fn = getattr(module, meta["fn"])
        return fn(**kwargs)
    except Exception as exc:  # noqa: BLE001 - 工具失败不拖垮主流程
        log.warning("tool %s failed: %s", name, exc)
        return {"ok": False, "error": str(exc), "flags": []}
