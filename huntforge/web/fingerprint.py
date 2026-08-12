"""Web 指纹识别：HTTP 头 + 页面特征 + 路径特征 → 技术栈标签。

指纹命中结果写入 challenge memory，供专项检查排序（指纹感知的探测优先级）。
规则库离线内置，匹配成本极低（字符串比较），不消耗 LLM。
"""
from __future__ import annotations

import re
from typing import Optional

# (匹配类型, 匹配模式, 标签, 优先级)
#   header: 在响应头中找子串（大小写不敏感）
#   body:   在页面正文中找子串
#   path:   路径探测确认（仅当响应 200/301）
FINGERPRINTS: list[tuple[str, str, str, int]] = [
    ("header", "server: nginx", "nginx", 90),
    ("header", "server: apache", "apache", 90),
    ("header", "server: openresty", "openresty", 95),
    ("header", "server: iis", "iis", 90),
    ("header", "server: tomcat", "tomcat", 95),
    ("header", "x-powered-by: php", "php", 90),
    ("header", "x-powered-by: asp.net", "aspnet", 90),
    ("header", "x-generator: jeecg", "jeecg", 95),
    ("header", "x-application-context", "spring", 95),
    ("body", "thinkphp", "thinkphp", 90),
    ("body", "layui", "layui", 70),
    ("body", "element-ui", "vue", 70),
    ("body", "react", "react", 60),
    ("body", "shiro", "shiro", 80),
    ("body", "swagger", "swagger", 80),
    ("body", "dify", "dify", 90),           # AI 应用（P2 联动）
    ("body", "langflow", "langflow", 90),   # AI 应用（P2 联动）
    ("body", "django", "django", 70),
    ("body", "flask", "flask", 60),
    ("body", "wordpress", "wordpress", 85),
    ("body", "grafana", "grafana", 90),
    ("body", "jenkins", "jenkins", 90),
    ("body", "nacos", "nacos", 90),
    ("body", "druid", "druid", 85),
    ("body", "actuator", "spring-actuator", 90),
    ("path", "/wp-content", "wordpress", 85),
    ("path", "/actuator", "spring-actuator", 90),
    ("path", "/nacos", "nacos", 90),
    ("path", "/api-docs", "swagger", 85),
]

# 指纹 → 建议专项检查排序（先打最容易出结果的）
FINGERPRINT_TO_CHECKS: dict[str, list[str]] = {
    "nginx": ["unauth", "lfi", "sqli", "ssrf"],
    "apache": ["lfi", "unauth", "sqli"],
    "tomcat": ["unauth", "rce", "lfi"],
    "spring-actuator": ["unauth", "rce"],
    "spring": ["unauth", "sqli", "rce"],
    "thinkphp": ["rce", "sqli", "unauth"],
    "jeecg": ["unauth", "sqli", "rce"],
    "swagger": ["unauth", "sqli"],
    "shiro": ["rce", "unauth"],
    "druid": ["unauth"],
    "wordpress": ["rce", "lfi", "sqli"],
    "nacos": ["unauth", "rce"],
    "jenkins": ["unauth", "rce"],
    "grafana": ["unauth"],
}

DEFAULT_CHECK_ORDER = ["unauth", "sqli", "lfi", "ssrf", "rce"]


class Fingerprinter:
    """收集 header/body 特征，输出技术栈标签集合。"""

    def __init__(self, http_timeout: float = 8.0):
        self.http_timeout = http_timeout

    def identify(self, base_url: str, headers: dict | None = None,
                 body: str = "", status: int = 0,
                 path_status: Optional[dict[str, int]] = None) -> list[str]:
        """基于一次主页请求的 headers/body + 若干路径状态码输出标签。"""
        found: set[str] = set()
        headers = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
        header_blob = ";".join(f"{k}: {v}" for k, v in headers.items())
        body_lower = (body or "").lower()[:20000]

        for kind, pattern, tag, prio in FINGERPRINTS:
            if kind == "header" and pattern in header_blob:
                found.add(tag)
            elif kind == "body" and pattern in body_lower:
                found.add(tag)
            elif kind == "path" and path_status and pattern in (path_status or {}):
                if path_status.get(pattern, 0) in (200, 301):
                    found.add(tag)
        return sorted(found)

    def check_order(self, tags: list[str]) -> list[str]:
        """指纹 → 专项检查执行顺序（去重，保持 DEFAULT 顺序兜底）。"""
        order: list[str] = []
        for tag in tags:
            for c in FINGERPRINT_TO_CHECKS.get(tag, []):
                if c not in order:
                    order.append(c)
        for c in DEFAULT_CHECK_ORDER:
            if c not in order:
                order.append(c)
        return order
