"""幂等提交管理器（借鉴 lingops 的提交状态机 + CTF-Hunter 的 SubmitGate 冷却）。

状态机：pending → submitting → accepted | rejected | unknown
  - accepted：终态，题目标记 solved
  - rejected：终态（错误 flag，不再重试同一值）
  - unknown：网络不确定 → 冷却后自动重试
  - 同一 (challenge, flag) 由 dedup_key 唯一约束，绝不重复提交

冷却：attempts 递增 → cooldowns=[0,30,120,300,600] 递增等待，防提交风暴。
"""
from __future__ import annotations

import logging
import threading
import time

from ..core.state import StateDB
from .client import BenchClient

log = logging.getLogger("huntforge.submission")


class SubmissionManager:
    def __init__(self, db: StateDB, bench: BenchClient,
                 cooldowns: list[int] | None = None, max_attempts: int = 5):
        self.db = db
        self.bench = bench
        self.cooldowns = cooldowns or [0, 30, 120, 300, 600]
        self.max_attempts = max_attempts
        self._lock = threading.Lock()

    # ---------- 入队 ----------
    def queue(self, challenge_id: str, value: str) -> bool:
        """提交候选入队（去重）。返回是否新入队。"""
        value = (value or "").strip()
        if not value:
            return False
        with self._lock:
            added = self.db.queue_submission(challenge_id, value)
        if added:
            self.db.event("submission.queued", "challenge", challenge_id,
                          {"value": _mask(value)})
        return added

    # ---------- 刷新（主循环调用） ----------
    def flush(self) -> int:
        """把到期未决的提交发给平台。返回本轮处理条数。"""
        if not self.bench.configured:
            log.info("bench not configured, submissions pending (local mode)")
            return 0
        processed = 0
        for sub in self.db.peek_submissions():
            if not self._cooldown_ok(sub):
                continue
            if not self.db.mark_submitting(sub["id"]):  # CAS，防多线程重复提交
                continue
            processed += 1
            result = self._submit_one(sub)
            self._after(sub, result)
        return processed

    # ---------- 单条提交 ----------
    def _submit_one(self, sub: dict) -> object:
        self.db.event("submission.submitting", "challenge", sub["challenge_id"],
                      {"sub_id": sub["id"], "attempt": sub["attempts"]})
        try:
            return self.bench.submit(sub["challenge_id"], sub["value"])
        except Exception as exc:  # noqa: BLE001 - 兜底转 unknown
            log.exception("submit %s crashed", sub["id"])
            return type("R", (), {"ok": False, "status": "unknown",
                                  "error": f"{type(exc).__name__}: {exc}"})()

    def _after(self, sub: dict, result) -> None:
        status = result.status
        attempts = sub["attempts"] + 1  # mark_submitting 已 +1
        if status == "unknown" and attempts >= self.max_attempts:
            status = "rejected"  # 超过重试上限，放弃（避免无限挂起）
        self.db.finish_submission(sub["id"], status, sub["challenge_id"])
        self.db.event("submission.result", "challenge", sub["challenge_id"],
                      {"sub_id": sub["id"], "status": status,
                       "attempts": attempts, "error": getattr(result, "error", "")})
        if status == "accepted":
            log.info("FLAG ACCEPTED challenge=%s", sub["challenge_id"])

    # ---------- 冷却 ----------
    def _cooldown_ok(self, sub: dict) -> bool:
        """已尝试 attempts 次 → 下次提交前等待 cooldowns[attempts]（首次立即）。"""
        idx = min(sub["attempts"], len(self.cooldowns) - 1)
        wait = self.cooldowns[idx]
        last = sub.get("last_attempt_at") or 0
        return (time.time() - last) >= wait


def _mask(value: str, keep: int = 8) -> str:
    """提交值脱敏（审计日志里不全量暴露 flag）。"""
    if len(value) <= keep:
        return value
    return value[:keep] + "…"
