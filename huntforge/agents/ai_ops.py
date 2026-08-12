"""AI 应用安全挖掘 Agent：提示词注入 / RAG投毒 / 工具越权 / API安全 / 逻辑绕过。

规则为主（210 条内置攻击技术遍历），LLM 仅可选增强（payload 定制，P5 接模型网关）。
交互适配：OpenAI 兼容 / /chat / form / GET 反射 四种形态。
响应分析分层（借鉴 lingops）：严格 flag 命中 > 敏感泄露线索 > 拒绝识别。
"""
from __future__ import annotations

import logging
import re
import time
from typing import Callable, Optional

import requests

from ..core.state import StateDB
from ..knowledge import ALL_TECHNIQUES, CATEGORY_LABELS
from ..web.common import FLAG_RE, extract_flag
from ..web.gate import evaluate_and_persist

log = logging.getLogger("huntforge.aiops")

# 交互端点候选
CHAT_ENDPOINTS = ["/chat", "/api/chat", "/api/v1/chat", "/message", "/api/message",
                  "/ask", "/api/ask", "/completions", "/v1/chat/completions",
                  "/api/v1/chat/completions"]

# 敏感泄露线索（不含 flag 但值得上报）
LEAK_MARKS = {
    "password": "口令泄露线索", "api_key": "API 密钥泄露线索",
    "secret": "密钥泄露线索", "private key": "私钥泄露线索",
    "os.environ": "环境变量内容泄露", "token=": "token 泄露线索",
}
REFUSED_MARKS = ("抱歉", "不能", "无法", "拒绝", "i cannot", "i'm sorry", "not allowed",
                 "cannot assist", "isn't allowed")

# 分类执行顺序（最高价值在前）
CATEGORY_ORDER = ["prompt_injection", "rag_poisoning", "tool_abuse",
                  "api_security", "logic_bypass"]


class AIOpsAgent:
    def __init__(self, db: StateDB, http_timeout: float = 10.0,
                 timebox: float = 600.0, max_requests: int = 120,
                 submitter: Optional[Callable[[str, str], None]] = None):
        self.db = db
        self.http_timeout = http_timeout
        self.timebox = timebox
        self.max_requests = max_requests
        self.submitter = submitter
        self._started = 0.0
        self._requests = 0

    def run(self, task: dict) -> dict:
        ch = self.db.get_challenge(task["challenge_id"])
        if ch is None:
            return {"ok": False, "outcome": "no_challenge"}
        self._started = time.time()
        target = ch.get("target") or ""
        if not target.startswith(("http://", "https://")):
            self.db.event("task.info", "challenge", ch["id"],
                          {"msg": "ai-ops: 非 HTTP 目标，跳过"})
            return {"ok": True, "outcome": "not_http"}

        # 1) 交互端点探测
        endpoint = self._discover_endpoint(target)
        if endpoint is None:
            self.db.event("task.info", "challenge", ch["id"],
                          {"msg": "ai-ops: 未发现可用对话端点"})
            return {"ok": True, "outcome": "no_endpoint"}
        mode = endpoint[1]
        self.db.event("task.info", "challenge", ch["id"],
                      {"msg": f"ai-ops: endpoint {endpoint[0]} mode={mode}"})

        # 2) 知识库遍历
        hits: list[dict] = []
        got_flag = False
        for cat in CATEGORY_ORDER:
            if got_flag or self._time_left() <= 0 or self._requests >= self.max_requests:
                break
            for tech in ALL_TECHNIQUES.get(cat, []):
                if got_flag or self._time_left() <= 0 or self._requests >= self.max_requests:
                    break
                for payload in tech.get("payloads", []):
                    if self._requests >= self.max_requests:
                        break
                    self._requests += 1
                    hit = self._probe(endpoint, payload)
                    if hit:
                        hit["category"] = cat
                        hit["tech"] = tech["name"]
                        hits.append(hit)
                        log.info("AI HIT cat=%s tech=%s payload=%r", cat,
                                 tech["name"], payload[:60])
                        if hit.get("value"):
                            got_flag = True  # flag 已到手，停止全部探测
                            break
                        break  # 技术命中（无 flag）→ 下一条技术
        # 3) 落库 + 提交
        n_verified, n_flag = self._persist(ch, task["id"], hits)
        return {"ok": True, "outcome": "flag_found" if n_flag else "scanned",
                "endpoint": endpoint[0], "requests": self._requests,
                "hits": len(hits), "verified": n_verified, "flags": n_flag}

    # ---------- 端点探测 ----------
    def _discover_endpoint(self, base: str):
        """返回 (endpoint_url, mode) 或 None。mode: openai/chat/form/get。"""
        s = requests.Session()
        # OpenAI 兼容
        for p in ("/v1/chat/completions", "/api/v1/chat/completions"):
            r = self._try(s, base + p, "openai", {"messages": [{"role": "user",
                                                                 "content": "hi"}]})
            if r:
                return (base + p, "openai")
        # /chat JSON
        for p in CHAT_ENDPOINTS:
            if p.endswith("chat/completions"):
                continue
            for body_key in ("prompt", "message", "input"):
                r = self._try(s, base + p, "chat", {body_key: "hi"})
                if r:
                    return (base + p, "chat")
            r = self._try(s, base + p, "form", {"prompt": "hi"})
            if r:
                return (base + p, "form")
        # GET 反射
        try:
            r = s.get(base + "/", params={"q": "hi"}, timeout=self.http_timeout,
                      verify=False)
            if r is not None and r.status_code == 200 and len(r.text) < 5000:
                return (base + "/", "get")
        except requests.RequestException:
            pass
        return None

    def _try(self, s: requests.Session, url: str, kind: str, payload):
        try:
            if kind in ("openai", "chat"):
                r = s.post(url, json=payload, timeout=self.http_timeout, verify=False)
            else:
                r = s.post(url, data=payload, timeout=self.http_timeout, verify=False)
            if r.status_code in (200, 201) and len(r.text) > 0:
                return r
        except requests.RequestException:
            pass
        return None

    # ---------- 单次探测 ----------
    def _probe(self, endpoint, payload: str) -> Optional[dict]:
        url, mode = endpoint
        try:
            if mode == "openai":
                r = requests.post(url, json={"messages": [{"role": "user",
                                                           "content": payload}]},
                                  timeout=self.http_timeout, verify=False)
            elif mode == "chat":
                r = requests.post(url, json={"prompt": payload},
                                  timeout=self.http_timeout, verify=False)
            elif mode == "form":
                r = requests.post(url, data={"prompt": payload},
                                  timeout=self.http_timeout, verify=False)
            else:
                r = requests.get(url, params={"q": payload},
                                 timeout=self.http_timeout, verify=False)
        except requests.RequestException:
            return None
        if r is None:
            return None
        text = self._extract_reply(r)
        flag = extract_flag(text)
        if flag:
            return {"type": "ai_prompt_leak", "payload": payload[:120],
                    "response": text[:400], "impact": "AI 对话应用泄露 flag",
                    "confidence": 0.95, "value": flag,
                    "confirm": {"note": "注入 payload 直接命中"}}
        # 敏感泄露线索
        lower = text.lower()
        for mark, desc in LEAK_MARKS.items():
            if mark in lower and not any(m in lower for m in REFUSED_MARKS):
                return {"type": "ai_sensitive_leak", "payload": payload[:120],
                        "response": text[:400], "impact": f"AI 对话泄露 {desc}",
                        "confidence": 0.7, "value": None,
                        "confirm": {"note": f"响应含特征 {mark!r}"}}
        return None

    def _extract_reply(self, r: requests.Response) -> str:
        """兼容多种响应结构提取文本。"""
        try:
            body = r.json()
        except ValueError:
            return r.text or ""
        # OpenAI 兼容
        try:
            return body["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            pass
        for key in ("reply", "response", "answer", "content", "result", "text",
                    "output", "data", "message", "msg"):
            v = body.get(key)
            if isinstance(v, str):
                return v
            if isinstance(v, dict):
                for k2 in ("content", "text", "reply", "answer"):
                    if isinstance(v.get(k2), str):
                        return v[k2]
        return str(body)[:1000]

    # ---------- 落库 ----------
    def _persist(self, ch: dict, task_id: int, hits: list[dict]) -> tuple[int, int]:
        n_verified = n_flag = 0
        seen: set[str] = set()
        for h in hits:
            key = f"{h['type']}:{h.get('payload','')[:40]}"
            if key in seen:
                continue
            seen.add(key)
            evidence = {**h, "url": ch.get("target", ""),
                        "request": f"POST 对话接口 prompt={h.get('payload','')[:80]}"}
            fid = self.db.add_finding(
                ch["id"], task_id, h["type"], h["confidence"],
                {k: v for k, v in evidence.items() if k not in ("value",)},
            )
            result = evaluate_and_persist(self.db, fid, evidence)
            if result.passed:
                n_verified += 1
                self.db.put_memory("hit", f"ai:{h['type']}", {"how": h["type"]})
            if h.get("value") and result.passed:
                n_flag += 1
                if self.submitter:
                    self.submitter(ch["id"], h["value"])
        return n_verified, n_flag

    def _time_left(self) -> float:
        return self.timebox - (time.time() - self._started)
