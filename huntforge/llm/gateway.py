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
import threading
import time
from typing import Any, Optional

import requests

from ..core.state import StateDB
from ..web.sse import emit_event

log = logging.getLogger("huntforge.llm")


class LLMError(Exception):
    pass


class NoModelConfigured(LLMError):
    pass


class CallBudget:
    """线程安全的调用预算计数器（可跨多个 gateway 实例共享）。"""

    def __init__(self, limit: Optional[int] = None):
        self.limit = limit
        self.used = 0
        self._lock = threading.Lock()

    def take(self) -> bool:
        with self._lock:
            if self.limit is not None and self.limit <= 0:
                return False
            if self.limit is not None:
                self.limit -= 1
            self.used += 1
            return True


class ModelGateway:
    def __init__(self, llm_cfg: dict, db: Optional[StateDB] = None,
                 task_id: Optional[int] = None,
                 budget: Optional[CallBudget] = None):
        self.cfg = llm_cfg
        self.db = db
        self.task_id = task_id
        self._gateway_on = bool((llm_cfg.get("gateway") or {}).get("enabled"))
        self._suffix = (llm_cfg.get("gateway") or {}).get("suffix", ".tsecbench.gw")
        self._force_http = bool((llm_cfg.get("gateway") or {}).get("force_http", True))
        self._chat_cfg = llm_cfg.get("chat") or {}
        # 超高缓存框架（参考 deepseek-harness 的 cache-safe snapshot 设计）：
        # - 对话缓存：同 conv_key 的消息序列只追加不重写 → 全历史前缀命中 KV 缓存
        # - 请求去重：完全相同的请求直接短路（零 API 调用、零计费）
        self._conv: dict = {}          # conv_key -> [messages]
        self._conv_lock = threading.Lock()
        self._dedup: dict = {}         # sha256 -> {text, model, usage}
        self._dedup_order: list = []
        self._dedup_lock = threading.Lock()
        if budget is not None:
            self.budget = budget
        else:
            budget_raw = os.environ.get("HUNTFORGE_LLM_CALL_BUDGET")
            if budget_raw in (None, ""):
                budget_raw = llm_cfg.get("per_challenge_call_budget")
            try:
                limit = int(budget_raw) if budget_raw not in (None, "") else None
            except (TypeError, ValueError):
                limit = None
            self.budget = CallBudget(limit)

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

    def _chat_cfg_for(self, tier: str) -> dict:
        """单次调用参数 = chat 全局默认 + tier_chat.<tier> 覆盖
        （干活 tier 降 reasoning_effort，大脑 tier 保持 max）。"""
        cfg = dict(self._chat_cfg)
        overrides = (self.cfg.get("tier_chat") or {}).get(tier) or {}
        cfg.update(overrides)
        return cfg

    def supports(self, tier: str = "standard") -> bool:
        return bool(self._available_tier(tier))

    # ---------- 调用 ----------
    def chat(self, messages: list[dict], tier: str = "standard",
             max_tokens: int | None = None) -> dict:
        """返回 {text, model, usage:{...}}；全部模型失败抛 LLMError。

        请求级去重：完全相同的 (tier, max_tokens, messages) 直接返回上次结果，
        不消耗调用预算、不产生 API 费用。
        """
        tier = self._available_tier(tier)
        if not tier:
            raise NoModelConfigured("no LLM api key configured (env HUNTFORGE_GATEWAY/keys)")
        dedup_key = self._dedup_key(tier, max_tokens, messages)
        cached = self._dedup_get(dedup_key)
        if cached is not None:
            # usage 原样回显（代表首次真实调用的成本），打 dedup 标记供上层观测零成本短路
            out = dict(cached)
            out["dedup"] = True
            return out
        if not self.budget.take():
            raise LLMError("LLM call budget exhausted")
        errors: list[str] = []
        for model in self._tier_models(tier):
            try:
                result = self._call_one(model, messages, max_tokens, tier)
                self._dedup_put(dedup_key, result)
                return result
            except LLMError as exc:
                errors.append(f"{model['id']}: {exc}")
        raise LLMError("all models failed; " + "; ".join(errors))

    @staticmethod
    def _dedup_key(tier: str, max_tokens, messages) -> str:
        import hashlib
        payload = json.dumps({"tier": tier, "mt": max_tokens, "msgs": messages},
                             ensure_ascii=False, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def _dedup_get(self, key: str):
        with self._dedup_lock:
            return self._dedup.get(key)

    def _dedup_put(self, key: str, result: dict) -> None:
        with self._dedup_lock:
            self._dedup[key] = {"text": result.get("text"),
                                "model": result.get("model"),
                                "usage": result.get("usage")}
            self._dedup_order.append(key)
            while len(self._dedup_order) > 128:   # LRU 封顶
                old = self._dedup_order.pop(0)
                self._dedup.pop(old, None)

    # ---------- 对话式调用（超高缓存框架） ----------
    def conv_len(self, conv_key: str) -> int:
        with self._conv_lock:
            msgs = self._conv.get(conv_key)
            return len(msgs) if msgs else 0

    def chat_conv(self, conv_key: str, system: str, user_delta: str,
                  tier: str = "standard", max_tokens: int | None = None) -> dict:
        """同 conv_key 的消息序列只追加不重写（cache-safe 设计）：

        - 首轮：seed [system, user_delta]
        - 后续轮：append user_delta → 调用 → append assistant 回复
        全历史前缀（system + 每轮 user/assistant）逐字节稳定，
        DeepSeek KV 缓存对除尾部新增外的全部输入命中。
        system 内容若变化则重建会话（防串话）。

        实测（2026-XX 直连 API 对照实验）：
        - assistant 轮次同样进入可命中前缀（call3 命中 call2 全部 1922 token，
          含 667 token 的 assistant 回复），会话模式已达理论上限；
        - cached_tokens 按 128-token 块粒度取整（⌊前缀长度/128⌋×128），
          单轮 delta 小于 128 token 时命中数可能"不增长"，这是报告粒度而非未命中；
        - 完全相同的请求由 chat() 的请求级去重短路（零 API 调用）。
        """
        with self._conv_lock:
            msgs = self._conv.get(conv_key)
            if msgs is None or not msgs or msgs[0]["content"] != system:
                msgs = [{"role": "system", "content": system}]
                self._conv[conv_key] = msgs
                if len(self._conv) > 64:   # LRU 封顶
                    oldest = next(iter(self._conv))
                    self._conv.pop(oldest, None)
            msgs.append({"role": "user", "content": user_delta})
            snapshot = list(msgs)
        try:
            resp = self.chat(snapshot, tier=tier, max_tokens=max_tokens)
        except LLMError:
            with self._conv_lock:
                if msgs and msgs[-1]["role"] == "user":
                    msgs.pop()   # 失败回滚本轮 delta，避免重复追加
            raise
        with self._conv_lock:
            if msgs and msgs[-1]["role"] == "user":
                msgs.append({"role": "assistant",
                             "content": resp.get("text", "")})
        return resp

    def _call_one(self, model: dict, messages: list[dict],
                  max_tokens: int | None, tier: str) -> dict:
        """单模型调用。推理模型偶发把 max_tokens 全耗在 reasoning 上导致 content 为空，
        此时翻倍 max_tokens 重试一次（实测 deepseek-v4-flash 约 1/3 概率触发）。"""
        url = f"{model['base_url']}/chat/completions"
        # 输出预算：显式传入 > tier 专属预算 > chat 默认（同 tier 每次一致，
        # 不破坏缓存键友好性；reasoning 空内容重试的翻倍是例外路径）
        cfg = self._chat_cfg_for(tier)
        tier_budget = (self.cfg.get("tier_max_tokens") or {}).get(tier)
        token_budget = max_tokens or tier_budget or cfg.get("max_tokens", 2048)
        for _attempt in range(2):
            payload: dict[str, Any] = {
                "model": model["id"],
                "messages": messages,
                "temperature": cfg.get("temperature", 0.2),
                "max_tokens": token_budget,
                "stream": False,
            }
            # 推理强度：deepseek 推理模型支持 reasoning_effort=low..max，
            # 隐性 reasoning 输出（最贵计费项）大幅缩减；非推理模型忽略该字段。
            re_effort = cfg.get("reasoning_effort")
            mid = str(model.get("id", "")).lower()
            if re_effort and ("deepseek" in mid or "glm" in mid):
                payload["reasoning_effort"] = re_effort
            started = time.time()
            try:
                resp = requests.post(
                    url,
                    json=payload,
                    headers={"Authorization": f"Bearer {model['api_key']}"},
                    timeout=cfg.get("timeout", 60),
                )
            except requests.RequestException as exc:
                raise LLMError(f"network: {exc}") from exc
            latency_ms = int((time.time() - started) * 1000)
            if resp.status_code == 429:
                # 网关限流（比赛网关文档：429 退避重试）：同模型退避 3 次
                for backoff in (2.0, 5.0, 10.0):
                    time.sleep(backoff)
                    try:
                        resp = requests.post(
                            url, json=payload,
                            headers={"Authorization": f"Bearer {model['api_key']}"},
                            timeout=cfg.get("timeout", 60),
                        )
                    except requests.RequestException as exc:
                        raise LLMError(f"network: {exc}") from exc
                    if resp.status_code != 429:
                        break
                else:
                    raise LLMError("http 429: rate limited after retries")
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
            # 每次 HTTP 200 都计量（重试的消耗也要入账）
            self._record_usage(model, tier=tier, usage=usage, latency_ms=latency_ms)
            cached = (int(usage.get("prompt_tokens_details", {}).get("cached_tokens", 0))
                      if isinstance(usage.get("prompt_tokens_details"), dict) else 0)
            # SSE 事件：一次真实 LLM 调用 = 一条真实日志（含预算与缓存命中归因）
            emit_event(self.db, "llm.call", "task", str(self.task_id or ""),
                       tool=f"llm:{model['id']}", agent_id="gateway",
                       params={"tier": tier, "max_tokens": token_budget},
                       result={"model": model["id"],
                               "in": int(usage.get("prompt_tokens", 0)),
                               "out": int(usage.get("completion_tokens", 0)),
                               "cache": cached,
                               "empty": not bool(text and text.strip())},
                       duration_ms=latency_ms,
                       extra={"budget_used": self.budget.used,
                              "budget_limit": self.budget.limit})
            if text.strip():
                return {"text": text, "model": model["id"], "usage": usage}
            token_budget = min(token_budget * 2, 16384)  # 翻倍重试但封顶，防超模型输出上限
        raise LLMError("empty content after retry (reasoning overflow?)")

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
    def chat_json(self, messages: list[dict], tier: str = "standard",
                  max_tokens: Optional[int] = None) -> dict:
        """要求模型输出纯 JSON，取第一个 {...} 解析（借鉴 lingops 的 _chat_json）。

        解析失败（输出被 max_tokens 截断是实盘高频失败模式）时带修复指令
        翻倍预算重试一次，而不是让整条决策链静默降级。
        """
        guarded = list(messages)
        if guarded and guarded[-1].get("role") == "user":
            guarded[-1]["content"] += (
                "\n\n只输出 JSON，不要任何其他文字（不要 markdown 代码块）。"
            )
        resp = self.chat(guarded, tier=tier, max_tokens=max_tokens)
        try:
            return _extract_json(resp["text"])
        except LLMError as exc:
            log.warning("JSON parse failed (%s); retry with repair instruction", exc)
            guarded2 = list(guarded) + [{
                "role": "user",
                "content": (
                    "你上一次的输出不是可解析的 JSON（很可能被截断）。"
                    "请重新输出完整 JSON：字段更短、script 字段用单行紧凑写法、"
                    "不要省略闭合引号和括号，只输出 JSON。"
                ),
            }]
            base = max_tokens or self._chat_cfg.get("max_tokens", 2048)
            resp2 = self.chat(guarded2, tier=tier, max_tokens=base * 2)
            return _extract_json(resp2["text"])

    def chat_json_conv(self, conv_key: str, system: str, user_delta: str,
                       tier: str = "standard",
                       max_tokens: Optional[int] = None) -> dict:
        """对话式 JSON 调用：与 chat_json 同语义，但走 chat_conv 的追加式
        消息序列（全历史前缀命中缓存）。JSON 解析失败时把修复指令作为
        新 delta 追加重试（前一条坏输出已入历史，模型可见）。"""
        delta = user_delta + "\n\n只输出 JSON，不要任何其他文字（不要 markdown 代码块）。"
        resp = self.chat_conv(conv_key, system, delta, tier=tier,
                              max_tokens=max_tokens)
        try:
            return _extract_json(resp["text"])
        except LLMError as exc:
            log.warning("conv JSON parse failed (%s); retry with repair delta", exc)
            base = max_tokens or self._chat_cfg.get("max_tokens", 2048)
            resp2 = self.chat_conv(
                conv_key, system,
                "你上一次的输出不是可解析的 JSON（很可能被截断）。请重新输出完整 JSON："
                "字段更短、script 字段用单行紧凑写法、不要省略闭合引号和括号。",
                tier=tier, max_tokens=base * 2)
            return _extract_json(resp2["text"])


def _extract_json(text: str) -> dict:
    """从文本中提取第一个 {…} 并解析（容错模型输出 markdown 与被截断的输出）。"""
    start = text.find("{")
    if start == -1:
        raise LLMError(f"no JSON in model output: {text[:200]}")

    # 1) 第一个完整闭合的对象直接解析
    end = _balanced_end(text, start)
    if end is not None:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass

    # 2) 截断修复：补全未闭合的字符串与括号
    repaired = _repair_truncated(text[start:])
    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        pass

    # 3) 逐刀砍掉尾部不完整的字段再补全重试（最多 8 刀）
    for _ in range(8):
        cut = repaired.rfind('",')
        if cut <= 0:
            break
        repaired = _repair_truncated(repaired[:cut + 1])
        try:
            return json.loads(repaired)
        except json.JSONDecodeError:
            continue
    raise LLMError(f"bad JSON from model: {text[start:start + 200]}")


def _balanced_end(text: str, start: int) -> Optional[int]:
    """从 start（'{'）出发找匹配的闭合 '}'；未闭合返回 None。"""
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def _repair_truncated(s: str) -> str:
    """把被截断的 JSON 尽力补全：闭合未完成的字符串与括号。"""
    out = list(s)
    in_str = False
    esc = False
    stack: list[str] = []
    for ch in out:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            stack.append("}")
        elif ch == "[":
            stack.append("]")
        elif ch in "}]" and stack and stack[-1] == ch:
            stack.pop()
    if in_str:
        out.append('"')
    while stack:
        out.append(stack.pop())
    return "".join(out)
