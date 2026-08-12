"""BenchClient：比赛平台答题 API 适配层。

- 地址/令牌来自环境变量 BENCHMARK_BASE_URL / BENCHMARK_TOKEN（平台注入），
  或 config/settings.yaml 的 platform 段（本地自定义）。
- 接口路径可配置（默认 /api/v1/assets 拉题、/api/v1/flag/collect 提交，
  拿到比赛 API 文档后改配置即可，无需改代码）。
- 网络失败抛 BenchError，由上层决定重试（提交幂等性在 submission 层保证）。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

log = logging.getLogger("huntforge.bench")

DEFAULT_HEADERS = {"User-Agent": "HuntForge/0.1 (benchmark-agent)"}


class BenchError(Exception):
    pass


@dataclass
class Challenge:
    """平台下发的题目。字段名与平台 API 可能不同——通过 parse_challenge 归一化。"""
    id: str
    title: str = ""
    category: str = "web"
    difficulty: str = "medium"
    target: str = ""           # 靶场入口（URL / 源码路径 / 附件）
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "category": self.category,
                "difficulty": self.difficulty, "target": self.target, "meta": self.meta}

    @classmethod
    def from_unknown(cls, raw: dict) -> "Challenge":
        """宽容归一化：兼容多种字段命名（id/_id/name、url/target/host、type/category…）。"""
        def pick(*keys: str, default: str = "") -> str:
            for k in keys:
                v = raw.get(k)
                if v is not None and v != "":
                    return str(v)
            return default

        cid = pick("id", "_id", "challenge_id", "task_id", "name", "title")
        target = pick("target", "url", "uri", "host", "addr", "address",
                      "attachment", "file", "source")
        return cls(
            id=cid,
            title=pick("title", "name", "desc", "description", default=cid),
            category=pick("category", "type", "tag", "kind", default="web").lower(),
            difficulty=pick("difficulty", "level", "score_level", default="medium").lower(),
            target=target,
            meta=raw,
        )


@dataclass
class SubmitResult:
    ok: bool
    status: str            # accepted / rejected / unknown
    raw: Any = None
    error: str = ""


class BenchClient:
    def __init__(self, base_url: str | None, token: str | None,
                 list_path: str = "/api/v1/assets",
                 submit_path: str = "/api/v1/flag/collect",
                 value_field: str = "flag", timeout: float = 15.0):
        self.base_url = base_url
        self.token = token
        self.list_path = list_path
        self.submit_path = submit_path
        self.value_field = value_field
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.base_url)

    def _headers(self) -> dict:
        h = dict(DEFAULT_HEADERS)
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    # ---------- 拉题 ----------
    def list_challenges(self) -> list[Challenge]:
        if not self.configured:
            raise BenchError("bench base_url not configured (BENCHMARK_BASE_URL)")
        url = self.base_url + self.list_path
        try:
            resp = requests.get(url, headers=self._headers(), timeout=self.timeout)
        except requests.RequestException as exc:
            raise BenchError(f"list_challenges network: {exc}") from exc
        if resp.status_code != 200:
            raise BenchError(f"list_challenges http {resp.status_code}: {resp.text[:200]}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise BenchError(f"list_challenges bad json: {resp.text[:200]}") from exc
        items = _unwrap_list(body)
        return [Challenge.from_unknown(it) for it in items if isinstance(it, dict)]

    # ---------- 提交 ----------
    def submit(self, challenge_id: str, value: str) -> SubmitResult:
        if not self.configured:
            raise BenchError("bench base_url not configured (BENCHMARK_BASE_URL)")
        payload = {"challenge_id": challenge_id, self.value_field: value}
        url = self.base_url + self.submit_path
        try:
            resp = requests.post(url, json=payload, headers=self._headers(),
                                 timeout=self.timeout)
        except requests.RequestException as exc:
            return SubmitResult(ok=False, status="unknown", error=f"network: {exc}")
        try:
            body = resp.json() if resp.content else {}
        except ValueError:
            body = {"text": resp.text[:200]}
        status = _classify_submit(resp.status_code, body)
        ok = status == "accepted"
        return SubmitResult(ok=ok, status=status, raw=body)


def _unwrap_list(body: Any) -> list:
    """兼容多种返回形态：{items:[...]} / {data:[...]} / {list:[...]} / 直接数组。"""
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for k in ("items", "data", "list", "challenges", "tasks", "result", "rows"):
            v = body.get(k)
            if isinstance(v, list):
                return v
            if isinstance(v, dict) and k == "data":
                inner = v.get("list") or v.get("items")
                if isinstance(inner, list):
                    return inner
    return []


def _classify_submit(status_code: int, body: dict) -> str:
    """提交结果分类：accepted / rejected / unknown。

    - 响应体中的显式状态字段优先：部分平台即使答错也返回 HTTP 200，
      必须看 body 里的 status/ok 字段，否则会把 rejected 误判为 accepted 而停止挖掘
    - 2xx 且无显式状态：accepted
    - 429（频率限制）：unknown → 提交管理器按冷却序列退避重试，不放弃正确答案
    - 明确的 4xx（参数错/未授权）：rejected
    - 其余（网络超时、5xx）：unknown → 可安全重试（平台侧幂等去重，重复提交无害）
    """
    if isinstance(body, dict):
        for key in ("status", "result", "verdict"):
            value = body.get(key)
            if isinstance(value, str):
                value = value.strip().lower()
                if value in ("accepted", "ok", "success", "correct", "true"):
                    return "accepted"
                if value in ("rejected", "wrong", "incorrect", "failed", "false") \
                        and status_code < 500:
                    return "rejected"
        for key in ("ok", "success"):
            value = body.get(key)
            if isinstance(value, bool):
                return "accepted" if value else "rejected"
    if status_code in (200, 201):
        return "accepted"
    if status_code == 429:
        return "unknown"
    if status_code in (400, 401, 403, 404):
        return "rejected"
    return "unknown"
