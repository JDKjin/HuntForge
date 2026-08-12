"""模型网关：OpenAI 兼容协议 + 平台网关 URL 转换 + tier 路由 + failover + token 计量。

托管模式网关规则（平台要求）：
  原域名添加 .tsecbench.gw 后缀，https 改为 http。
  例：https://api.deepseek.com/v1 → http://api.deepseek.com.tsecbench.gw/v1
本地模式直连原始 URL。

api_key 一律从环境变量读取（平台注入），禁止硬编码。
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional

import requests

from ..core.state import StateDB

log = logging.getLogger("huntforge.llm")


class LLMError(Exception):
    pass


class NoModelConfigured(LLMError):
    pass


class ModelGateway:
    def __init__(self, llm_cfg: dict, db: Optional[StateDB] = None,
                 task_id: Optional[int] = None):
        self.cfg = llm_cfg
        self.db = db
        self.task_id = task_id
        self._gateway_on = bool((llm_cfg.get("gateway") or {}).get("enabled"))
        self._suffix = (llm_cfg.get("gateway") or {}).get("suffix", ".tsecbench.gw")
        self._force_http = bool((llm_cfg.get("gateway") or {}).get("force_http", True))
        self._chat_cfg = llm_cfg.get("chat") or {}
        self.call_budget = int(os.environ.get("HUNTFORGE_LLM_CALL_BUDGET", "0")) or None

    # ---------- URL 转换 ----------
    def _rewrite_url(self, url: str) -> str:
        """按平台规则重写模型 API 地址；未启用网关时原样返回。"""
        if not self._gateway_on:
            return url
        rewritten = url
        if self._force_http and rewritten.startswith("https://"):
            rewritten = "http://" + rewritten[len("https://"):]
        # 域名后追加后缀（仅对域名部分）
        head, _, tail = rewritten.partition("://")
        host, _, rest = tail.partition("/")
        if not host.endswith(self._suffix):
            host = host + self._suffix
        return f"{head}://{host}/{rest}"

    # ---------- 模型解析 ----------
    def _tier_models(self, tier: str) -> list[dict]:
        models = (self.cfg.get("tiers") or {}).get(tier) or []
        out = []
        for m in models:
            key = os.environ.get(m.get("api_key_env", ""))
            if not key:
                continue
            out.append({
                "id": m["id"],
                "base_url": self._rewrite_url(m["base_url"]),
                "api_key": key,
            })
        return out

    def _available_tier(self, tier: str) -> str:
        """tier 不可用时降级：deep→standard→fast。"""
        for t in (tier, "standard", "fast"):
            if self._tier_models(t):
                return t
        return ""

    # ---------- 调用 ----------
    def chat(self, messages: list[dict], tier: str = "standard",
             max_tokens: int | None = None) -> dict:
        """返回 {text, model, usage:{...}}；全部模型失败抛 LLMError。"""
        tier = self._available_tier(tier)
        if not tier:
            raise NoModelConfigured("no LLM api key configured (env HUNTFORGE_GATEWAY/keys)")
        errors: list[str] = []
        for model in self._tier_models(tier):
            try:
                return self._call_one(model, messages, max_tokens, tier)
            except LLMError as exc:
                errors.append(f"{model['id']}: {exc}")
        raise LLMError("all models failed; " + "; ".join(errors))

    def _call_one(self, model: dict, messages: list[dict],
                  max_tokens: int | None, tier: str) -> dict:
        url = f"{model['base_url']}/chat/completions"
        payload: dict[str, Any] = {
            "model": model["id"],
            "messages": messages,
            "temperature": self._chat_cfg.get("temperature", 0.2),
            "max_tokens": max_tokens or self._chat_cfg.get("max_tokens", 2048),
            "stream": False,
        }
        started = time.time()
        try:
            resp = requests.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {model['api_key']}"},
                timeout=self._chat_cfg.get("timeout", 60),
            )
        except requests.RequestException as exc:
            raise LLMError(f"network: {exc}") from exc
        latency_ms = int((time.time() - started) * 1000)
        if resp.status_code != 200:
            raise LLMError(f"http {resp.status_code}: {resp.text[:200]}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise LLMError(f"bad json: {resp.text[:200]}") from exc
        try:
            text = body["choices"][0]["message"]["content"] or ""
            usage = body.get("usage") or {}
        except (KeyError, IndexError) as exc:
            raise LLMError(f"unexpected shape: {str(body)[:200]}") from exc
        self._record_usage(model, tier=tier, usage=usage, latency_ms=latency_ms)
        return {"text": text, "model": model["id"], "usage": usage}

    def _record_usage(self, model: dict, tier: str, usage: dict, latency_ms: int) -> None:
        if not self.db:
            return
        try:
            self.db.record_usage(
                self.task_id, tier, model["id"],
                int(usage.get("prompt_tokens", 0)),
                int(usage.get("completion_tokens", 0)),
                int(usage.get("prompt_tokens_details", {}).get("cached_tokens", 0))
                if isinstance(usage.get("prompt_tokens_details"), dict) else 0,
                latency_ms,
            )
        except Exception:  # noqa: BLE001 - 计量失败不影响主流程
            log.exception("record_usage failed")

    # ---------- 结构化输出辅助 ----------
    def chat_json(self, messages: list[dict], tier: str = "standard") -> dict:
        """要求模型输出纯 JSON，取第一个 {...} 解析（借鉴 lingops 的 _chat_json）。"""
        guarded = list(messages)
        if guarded and guarded[-1].get("role") == "user":
            guarded[-1]["content"] += (
                "\n\n只输出 JSON，不要任何其他文字（不要 markdown 代码块）。"
            )
        try:
            resp = self.chat(guarded, tier=tier)
        except LLMError:
            raise
        return _extract_json(resp["text"])


def _extract_json(text: str) -> dict:
    """从文本中提取第一个 {…} 并解析（容错模型输出 markdown）。"""
    start = text.find("{")
    if start == -1:
        raise LLMError(f"no JSON in model output: {text[:200]}")
    depth, i = 0, start
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError as exc:
                    raise LLMError(f"bad JSON from model: {text[start:i+1][:200]}") from exc
        i += 1
    raise LLMError(f"unterminated JSON in model output: {text[:200]}")
