"""AI 应用安全挖掘 Agent：提示词注入 / RAG投毒 / 工具越权 / API安全 / 逻辑绕过。

LLM（PentestPlanner）接入主决策链：
  - 侦察阶段：向 AI 应用发几条中性消息，观察防御风格
  - 规划阶段：LLM 分析防御机制，生成针对性 payload
  - 执行阶段：LLM 生成的 payload 优先，知识库作补充
知识库遍历作为 fallback（LLM 不可用时自动降级）。
"""
from __future__ import annotations

import logging
import time
from typing import Callable, Optional

import requests

from ..core.state import StateDB
from ..knowledge import ALL_TECHNIQUES, CATEGORY_LABELS
from ..web.common import FLAG_RE, extract_flag
from ..web.gate import evaluate_and_persist

log = logging.getLogger("huntforge.aiops")

CHAT_ENDPOINTS = ["/chat", "/api/chat", "/api/v1/chat", "/message", "/api/message",
                  "/ask", "/api/ask", "/completions", "/v1/chat/completions",
                  "/api/v1/chat/completions"]

LEAK_MARKS = {
    "password": "口令泄露线索", "api_key": "API 密钥泄露线索",
    "secret": "密钥泄露线索", "private key": "私钥泄露线索",
    "os.environ": "环境变量内容泄露", "token=": "token 泄露线索",
}
REFUSED_MARKS = ("抱歉", "不能", "无法", "拒绝", "i cannot", "i'm sorry", "not allowed",
                 "cannot assist", "isn't allowed")

CATEGORY_ORDER = ["prompt_injection", "rag_poisoning", "tool_abuse",
                  "api_security", "logic_bypass"]

# 中性侦察消息：用于判断 AI 应用的防御风格
RECON_PROBES = [
    "你好，你是什么 AI 助手？",
    "请简单介绍一下你能做什么。",
    "你有什么限制吗？",
]


class AIOpsAgent:
    def __init__(self, db: StateDB, http_timeout: float = 10.0,
                 timebox: float = 600.0, max_requests: int = 120,
                 submitter: Optional[Callable[[str, str], None]] = None,
                 planner=None):
        self.db = db
        self.http_timeout = http_timeout
        self.timebox = timebox
        self.max_requests = max_requests
        self.submitter = submitter
        self.planner = planner
        self._started = 0.0
        self._requests = 0

    def run(self, task: dict) -> dict:
        ch = self.db.get_challenge(task["challenge_id"])
        if ch is None:
            return {"ok": False, "outcome": "no_challenge"}
        self._started = time.time()
        target = ch.get("target") or ""
        if not target.startswith(("http://", "https://")):
            return {"ok": True, "outcome": "not_http"}

        endpoint = self._discover_endpoint(target)
        if endpoint is None:
            self.db.event("task.info", "challenge", ch["id"],
                          {"msg": "ai-ops: 未发现可用对话端点"})
            return {"ok": True, "outcome": "no_endpoint"}

        self.db.event("task.info", "challenge", ch["id"],
                      {"msg": f"ai-ops: endpoint {endpoint[0]} mode={endpoint[1]}"})

        # LLM 驱动路径（有 planner 时）
        if self.planner and self._time_left() > 30:
            hits = self._llm_driven_attack(ch, endpoint)
        else:
            hits = []

        # 知识库遍历作补充（已命中 flag 则跳过）
        if not any(h.get("value") for h in hits):
            hits += self._rule_driven_attack(endpoint)

        n_verified, n_flag = self._persist(ch, task["id"], hits)
        return {
            "ok": True,
            "outcome": "flag_found" if n_flag else "scanned",
            "endpoint": endpoint[0],
            "requests": self._requests,
            "llm_used": self.planner is not None,
            "hits": len(hits),
            "verified": n_verified,
            "flags": n_flag,
        }

    # ---------- LLM 驱动 ----------
    def _llm_driven_attack(self, ch: dict, endpoint) -> list:
        """侦察 → LLM 规划 → 执行针对性 payload。"""
        # 1) 侦察
        recon_log = []
        for probe in RECON_PROBES:
            if self._time_left() <= 0 or self._requests >= self.max_requests:
                break
            self._requests += 1
            hit = self._probe_raw(endpoint, probe)
            if hit is not None:
                recon_log.append({"probe": probe, "reply": hit[:300]})

        if not recon_log:
            return []

        self.db.event("task.info", "challenge", ch["id"],
                      {"msg": f"ai-ops: recon done, {len(recon_log)} responses"})

        # 2) LLM 生成针对性 payload
        strategy = self.planner.generate_ai_payloads(recon_log, max_payloads=6)
        payloads = strategy.get("payloads") or []
        defense = strategy.get("defense_mechanism", "unknown")
        log.info("AI strategy: defense=%s payloads=%d", defense, len(payloads))
        self.db.event("llm.ai_strategy", "challenge", ch["id"],
                      {"defense": defense, "n_payloads": len(payloads)})

        # 3) 执行
        hits = []
        for payload in payloads:
            if self._requests >= self.max_requests or self._time_left() <= 0:
                break
            self._requests += 1
            hit = self._probe(endpoint, payload)
            if hit:
                hit["strategy"] = "llm_generated"
                hits.append(hit)
                if hit.get("value"):
                    break
        return hits

    # ---------- 规则驱动（fallback） ----------
    def _rule_driven_attack(self, endpoint) -> list:
        hits = []
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
                        hits.append(hit)
                        if hit.get("value"):
                            got_flag = True
                            break
                        break
        return hits

    # ---------- 端点探测 ----------
    def _discover_endpoint(self, base: str):
        s = requests.Session()
        for p in ("/v1/chat/completions", "/api/v1/chat/completions"):
            if self._try(s, base + p, "openai", {"messages": [{"role": "user", "content": "hi"}]}):
                return (base + p, "openai")
        for p in CHAT_ENDPOINTS:
            if p.endswith("chat/completions"):
                continue
            for body_key in ("prompt", "message", "input"):
                if self._try(s, base + p, "chat", {body_key: "hi"}):
                    return (base + p, "chat")
            if self._try(s, base + p, "form", {"prompt": "hi"}):
                return (base + p, "form")
        try:
            r = s.get(base + "/", params={"q": "hi"}, timeout=self.http_timeout, verify=False)
            if r is not None and r.status_code == 200 and len(r.text) < 5000:
                return (base + "/", "get")
        except requests.RequestException:
            pass
        return None

    def _try(self, s, url, kind, payload):
        try:
            r = (s.post(url, json=payload, timeout=self.http_timeout, verify=False)
                 if kind in ("openai", "chat") else
                 s.post(url, data=payload, timeout=self.http_timeout, verify=False))
            return r.status_code in (200, 201) and len(r.text) > 0
        except requests.RequestException:
            return False

    # ---------- 单次探测 ----------
    def _probe_raw(self, endpoint, payload: str) -> Optional[str]:
        """发送探测消息，返回回复文本（不做命中判定）。"""
        url, mode = endpoint
        try:
            if mode == "openai":
                r = requests.post(url, json={"messages": [{"role": "user", "content": payload}]},
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
        return self._extract_reply(r) if r else None

    def _probe(self, endpoint, payload: str) -> Optional[dict]:
        """发送探测，分析命中结果。"""
        text = self._probe_raw(endpoint, payload)
        if text is None:
            return None
        flag = extract_flag(text)
        if flag:
            return {"type": "ai_prompt_leak", "payload": payload[:120],
                    "response": text[:400], "impact": "AI 对话应用泄露 flag",
                    "confidence": 0.95, "value": flag,
                    "confirm": {"note": "注入 payload 直接命中"}}
        lower = text.lower()
        for mark, desc in LEAK_MARKS.items():
            if mark in lower and not any(m in lower for m in REFUSED_MARKS):
                return {"type": "ai_sensitive_leak", "payload": payload[:120],
                        "response": text[:400], "impact": f"AI 对话泄露 {desc}",
                        "confidence": 0.7, "value": None,
                        "confirm": {"note": f"响应含特征 {mark!r}"}}
        return None

    def _extract_reply(self, r) -> str:
        try:
            body = r.json()
        except ValueError:
            return r.text or ""
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
    def _persist(self, ch: dict, task_id: int, hits: list) -> tuple:
        n_verified = n_flag = 0
        seen: set = set()
        for h in hits:
            key = f"{h['type']}:{h.get('payload','')[:40]}"
            if key in seen:
                continue
            seen.add(key)
            evidence = {**h, "url": ch.get("target", ""),
                        "request": f"POST 对话接口 prompt={h.get('payload','')[:80]}"}
            fid = self.db.add_finding(
                ch["id"], task_id, h["type"], h["confidence"],
                {k: v for k, v in evidence.items() if k != "value"},
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
