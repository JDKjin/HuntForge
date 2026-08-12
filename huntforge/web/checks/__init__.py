"""专项漏洞检查集：unauth / sqli / lfi / ssrf / rce。

每个检查模块导出 `run(ctx) -> list[Candidate]`。
ctx: {base, timeout, time_left, headers} — 统一执行上下文（见 web_ops）。
"""
from . import lfi, rce, sqli, ssrf, unauth

CHECKS = {
    "unauth": unauth.run,
    "sqli": sqli.run,
    "lfi": lfi.run,
    "ssrf": ssrf.run,
    "rce": rce.run,
}

__all__ = ["CHECKS", "unauth", "sqli", "lfi", "ssrf", "rce"]
