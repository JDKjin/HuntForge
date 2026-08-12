"""TSecBench 真实平台客户端：按官方 Challenges API 文档实现。

- 认证：HTTP 头 BENCHMARK_TOKEN: <uuid>（平台创建跑分任务时下发）
- 接口：GET /openapi/v1/challenges | POST start/close/submit | GET hint
- 错误统一 {"code","message","detail"}，映射为类型化异常
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

import requests

log = logging.getLogger("huntforge.tsec")

DEFAULT_HEADERS = {"User-Agent": "HuntForge/0.1 (tsec-benchmark-agent)"}


class TsecError(Exception):
    def __init__(self, code: str, message: str, detail: Any = None,
                 status_code: int = 0):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.detail = detail
        self.status_code = status_code


class TaskNotFound(TsecError):
    pass


class ChallengeNotFound(TsecError):
    pass


class InvalidState(TsecError):
    """任务已结束（超时）或活跃题目达上限。message 含 "max active" 时是后者。"""

    @property
    def max_active(self) -> bool:
        return "max active" in (self.message or "").lower()


class DuplicateSubmit(TsecError):
    pass


class ResourceUnavailable(TsecError):
    pass


class TsecConnectionError(TsecError):
    pass


_ERROR_TYPES = {
    "task_not_found": TaskNotFound,
    "challenge_not_found": ChallengeNotFound,
    "invalid_state": InvalidState,
    "duplicate": DuplicateSubmit,
    "resource_unavailable": ResourceUnavailable,
}


class TsecBenchClient:
    def __init__(self, base_url: str, token: str, timeout: float = 20.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> dict:
        h = dict(DEFAULT_HEADERS)
        if self.token:
            h["BENCHMARK_TOKEN"] = self.token
        return h

    def _request(self, method: str, path: str, *, params: Optional[dict] = None,
                 json_body: Optional[dict] = None, timeout: Optional[float] = None,
                 retries: int = 2) -> requests.Response:
        url = self.base_url + path
        last_exc: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                resp = requests.request(
                    method, url, params=params, json=json_body,
                    headers=self._headers(),
                    timeout=timeout or self.timeout,
                )
                if resp.status_code < 500:
                    return resp
                last_exc = TsecError("internal_error", resp.text[:200], status_code=resp.status_code)
            except requests.RequestException as exc:
                last_exc = TsecConnectionError("network", f"{exc}")
            if attempt < retries:
                time.sleep(1 + attempt)
        raise last_exc or TsecConnectionError("network", "request failed")

    def _raise_for_error(self, resp: requests.Response) -> None:
        """非 2xx 响应 → 解析平台错误结构抛类型化异常。"""
        if 200 <= resp.status_code < 300:
            return
        code, message, detail = "http_error", resp.text[:200], {}
        try:
            body = resp.json()
            if isinstance(body, dict):
                code = body.get("code", code)
                message = body.get("message", message)
                detail = body.get("detail", detail)
        except ValueError:
            pass
        exc_cls = _ERROR_TYPES.get(code, TsecError)
        raise exc_cls(code, message, detail, status_code=resp.status_code)

    # ---------- 题目列表 ----------
    def list_challenges(self) -> list[dict]:
        resp = self._request("GET", "/openapi/v1/challenges")
        self._raise_for_error(resp)
        body = resp.json()
        if not isinstance(body, list):
            raise TsecError("bad_body", f"expected list, got {type(body).__name__}")
        return body

    # ---------- 容器生命周期 ----------
    def start(self, unique_code: str) -> dict:
        resp = self._request("POST", "/openapi/v1/challenges/start",
                             params={"unique_code": unique_code})
        self._raise_for_error(resp)
        return resp.json()

    def close(self, unique_code: str) -> bool:
        resp = self._request("POST", "/openapi/v1/challenges/close",
                             params={"unique_code": unique_code})
        self._raise_for_error(resp)
        return bool(resp.json().get("closed"))

    def hint(self, unique_code: str) -> Optional[str]:
        resp = self._request("GET", "/openapi/v1/challenges/hint",
                             params={"unique_code": unique_code})
        self._raise_for_error(resp)
        return resp.json().get("hint")

    # ---------- 提交 ----------
    def submit(self, unique_code: str, flag: str) -> dict:
        """返回 {correct, awarded, cumulative_score, correct_flag_count,
        total_flag_count, matched_flag_index, duplicate}。

        duplicate=True 表示该 flag 之前已正确提交（幂等），视为已得分。
        """
        resp = self._request("POST", "/openapi/v1/challenges/submit",
                             json_body={"unique_code": unique_code, "flag": flag})
        try:
            self._raise_for_error(resp)
        except DuplicateSubmit as exc:
            return {"correct": True, "awarded": 0, "duplicate": True,
                    "cumulative_score": 0, "correct_flag_count": 0,
                    "total_flag_count": 0, "matched_flag_index": None,
                    "_exc": exc}
        body = resp.json()
        return {**body, "duplicate": False}
