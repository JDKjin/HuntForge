"""Web 检查共享工具：flag 正则、请求封装、候选结构。"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import unquote_plus

import requests

# 保守 flag 正则（与 probe 一致）：必须带定界符
FLAG_RE = re.compile(r"(?:flag|ctf|hf)[\{\(\[]([^\]\}\)]{1,128})[\}\)\]]", re.IGNORECASE)

DEFAULT_UA = "Mozilla/5.0 (HuntForge/0.1)"


@dataclass
class Candidate:
    """一次漏洞检查的候选发现。"""
    type: str                      # sqli / lfi / unauth / ssrf / rce / flag_leak
    url: str
    request: str                   # 请求摘要（方法+路径+关键参数）
    response: str                  # 响应证据（截断）
    impact: str                    # 影响描述
    confidence: float = 0.6
    value: Optional[str] = None    # 若直接命中 flag
    confirm: Optional[dict] = None # 二次复现验证（Gate Q2）

    def evidence(self) -> dict:
        return {"url": self.url, "request": self.request[:800],
                "response": self.response[:800], "impact": self.impact,
                "confirm": self.confirm}


def extract_flag(text: str) -> Optional[str]:
    """从文本抽 flag；明文没命中时再试 URL 解码 / unicode 转义 / base64 / hex。

    实盘 d-01 一类题 flag 常藏在 JSON 字段或一层编码里，只扫明文会漏提交。
    """
    if not text:
        return None
    m = FLAG_RE.search(text)
    if m:
        return m.group(0)
    try:
        decoded = unquote_plus(text)
        if decoded != text:
            m = FLAG_RE.search(decoded)
            if m:
                return m.group(0)
    except Exception:
        pass
    if "\\u" in text or "\\x" in text:
        try:
            unesc = bytes(text, "utf-8").decode("unicode_escape")
            m = FLAG_RE.search(unesc)
            if m:
                return m.group(0)
        except Exception:
            pass
    sample = text[:8000]
    for tok in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", sample):
        pad = tok + "=" * ((4 - len(tok) % 4) % 4)
        try:
            raw = base64.b64decode(pad, validate=False)
            s = raw.decode("utf-8", "ignore")
        except Exception:
            continue
        m = FLAG_RE.search(s)
        if m:
            return m.group(0)
    for tok in re.findall(r"(?:0x)?([0-9a-fA-F]{16,256})", sample):
        if len(tok) % 2:
            continue
        try:
            s = bytes.fromhex(tok).decode("utf-8", "ignore")
        except Exception:
            continue
        m = FLAG_RE.search(s)
        if m:
            return m.group(0)
    return None


def classify_flag_source(value: str, evidence: dict) -> str:
    """flag 来源分级（移植 D0Pagent _classify_flag_source 语义）：high/medium/low。

    - high：flag 值出现在目标实际响应正文中（证据链完整，最可信）
    - medium：无响应佐证但有复现确认 / 请求路径指向 response 类输出
    - low：仅模型声称（LLM 自报），需平台终判
    """
    v = str(value or "")
    response = str(evidence.get("response") or "")
    if v and v in response:
        return "high"
    if evidence.get("confirm"):
        return "medium"
    req = str(evidence.get("request") or "").lower()
    if any(m in req for m in ("response", "body", "json")):
        return "medium"
    return "low"


def extract_session(text: str) -> Optional[str]:
    """从响应中提取会话凭据（JSON session/token 字段或 cookie）。"""
    m = re.search(r'["\'](?:session|token|access_token|sessid)["\']\s*[:=]\s*["\']([^"\']{4,128})["\']', text or "", re.I)
    if m:
        return m.group(1)
    m = re.search(r"Set-Cookie:\s*([A-Za-z0-9_\-]+\s*=\s*[A-Za-z0-9_\-\.]+)", text or "", re.I)
    return m.group(1).strip() if m else None


def follow_session(base: str, session: str, timeout: float,
                   paths: Optional[list[str]] = None) -> Optional[tuple[str, str, str]]:
    """带会话凭据跟随访问敏感路径，返回 (url, body, header_note) 或 None。

    用于漏洞链：SQLi 登录绕过 → 会话 → 管理页 flag。
    同时尝试 X-Session 头与 Cookie 两种携带方式。
    """
    for path in paths or ("/admin", "/api/admin", "/api/admin/flag",
                          "/api/v1/admin", "/flag", "/dashboard", "/home"):
        for headers in ({"X-Session": session}, {"Cookie": session}):
            r = get(base + path, timeout, headers=headers)
            if r is None:
                continue
            body = body_of(r)
            if extract_flag(body):
                return (base + path, body, f"session-follow {list(headers.keys())[0]}")
            if r.status_code in (200, 301) and _looks_admin(body):
                return (base + path, body, f"session-follow {list(headers.keys())[0]}")
    return None


def _looks_admin(body: str) -> bool:
    b = body.lower()
    return any(m in b for m in ("admin", "dashboard", "user", "manage", "flag", "系统管理"))


def get(url: str, timeout: float, params: Optional[dict] = None,
        headers: Optional[dict] = None) -> Optional[requests.Response]:
    try:
        h = {"User-Agent": DEFAULT_UA}
        h.update(headers or {})
        return requests.get(url, params=params, headers=h, timeout=timeout,
                            allow_redirects=True, verify=False)
    except requests.RequestException:
        return None


def post(url: str, timeout: float, data=None, json=None,
         headers: Optional[dict] = None) -> Optional[requests.Response]:
    try:
        h = {"User-Agent": DEFAULT_UA}
        h.update(headers or {})
        return requests.post(url, data=data, json=json, headers=h, timeout=timeout,
                             allow_redirects=True, verify=False)
    except requests.RequestException:
        return None


def body_of(resp: Optional[requests.Response]) -> str:
    return resp.text if resp is not None else ""
