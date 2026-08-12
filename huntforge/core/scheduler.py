"""规则调度器（权威）：任务领取/完成全部 CAS + lease，保证不重不漏。

借鉴 lingops-agent 的 SQLite 协调设计（claim + lease 续租 + 过期回收），
借鉴 CTF-Hunter 的"调度器权威、LLM 不做调度决策"原则。
"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from .state import StateDB

log = logging.getLogger("huntforge.scheduler")


class Scheduler:
    """以 StateDB 为唯一事实源的任务调度器。

    用法：
        sched = Scheduler(db, workers=3)
        sched.start()
        sched.submit(challenge_id, agent_type)   # 入队
        sched.run_task(handler)                  # 领取+执行+CAS 落账（单线程版）
        sched.drain(handler)                     # 并行版：直到无任务
    """

    def __init__(self, db: StateDB, workers: int = 3, lease_seconds: int = 300):
        self.db = db
        self.workers = workers
        self.lease_seconds = lease_seconds
        self._pool: Optional[ThreadPoolExecutor] = None
        self._renew_stop = threading.Event()
        self._renew_thread: Optional[threading.Thread] = None

    # ---------- 生命周期 ----------
    def start(self) -> None:
        self._pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="hf-worker")
        self._renew_thread = threading.Thread(target=self._renew_loop, daemon=True,
                                              name="hf-lease-renews")
        self._renew_thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._renew_stop.set()
        if self._renew_thread:
            self._renew_thread.join(timeout)
        if self._pool:
            self._pool.shutdown(wait=True)

    # ---------- 任务提交 ----------
    def submit(self, challenge_id: str, agent_type: str = "probe") -> int:
        task_id = self.db.create_task(challenge_id, agent_type)
        self.db.event("task.created", "challenge", challenge_id,
                      {"task_id": task_id, "agent_type": agent_type})
        return task_id

    # ---------- 单个任务执行（含完整 CAS 闭环） ----------
    def run_task(self, handler: Callable[[dict], dict]) -> bool:
        """领取一个任务并执行，返回是否执行了（无任务返回 False）。

        handler 接收 task 字典，返回 result 字典（含 ok 等字段）。
        """
        task = self.db.claim_task()
        if task is None:
            return False
        task_id, token = task["id"], task["lease_token"]
        self.db.start_task(task_id, token, self.lease_seconds)
        self.db.event("task.claimed", "task", str(task_id),
                      {"challenge_id": task["challenge_id"], "agent_type": task["agent_type"]})
        try:
            result = handler(task) or {"ok": False}
            done = self.db.complete_task(task_id, token, result)
            self.db.event("task.completed", "task", str(task_id),
                          {"challenge_id": task["challenge_id"], "ok": bool(result.get("ok")),
                           "outcome": result.get("outcome", "")})
            return done
        except Exception as exc:  # noqa: BLE001 - worker 兜底
            log.exception("task %s handler crashed", task_id)
            self.db.fail_task(task_id, token, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            self.db.event("task.failed", "task", str(task_id),
                          {"challenge_id": task["challenge_id"], "error": f"{type(exc).__name__}"})
            return True

    # ---------- 并行 drain ----------
    def drain(self, handler: Callable[[dict], dict], idle_sleep: float = 0.5,
              max_idle_rounds: int = 3, max_seconds: float | None = None) -> int:
        """并行领取执行直到无任务（或超时），返回执行任务数。"""
        assert self._pool is not None, "scheduler.start() 未调用"
        deadline = time.time() + max_seconds if max_seconds else None
        executed = 0
        idle_rounds = 0
        while True:
            if deadline and time.time() > deadline:
                break
            claimed = 0
            futures = []
            for _ in range(self.workers):
                task = self.db.claim_task()
                if task is None:
                    break
                claimed += 1
                self.db.start_task(task["id"], task["lease_token"], self.lease_seconds)
                futures.append(self._pool.submit(self._run_claimed, handler, task))
            for f in futures:
                f.result()
            executed += claimed
            if claimed:
                idle_rounds = 0
            else:
                idle_rounds += 1
                if idle_rounds >= max_idle_rounds:
                    break
                time.sleep(idle_sleep)
        return executed

    def _run_claimed(self, handler: Callable[[dict], dict], task: dict) -> None:
        """对已领取（status=claimed）的任务执行并 CAS 落账。"""
        task_id, token = task["id"], task["lease_token"]
        try:
            result = handler(task) or {"ok": False}
            self.db.complete_task(task_id, token, result)
            self.db.event("task.completed", "task", str(task_id),
                          {"challenge_id": task["challenge_id"], "ok": bool(result.get("ok")),
                           "outcome": result.get("outcome", "")})
        except Exception as exc:  # noqa: BLE001
            log.exception("task %s handler crashed", task_id)
            self.db.fail_task(task_id, token, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            self.db.event("task.failed", "task", str(task_id),
                          {"challenge_id": task["challenge_id"], "error": f"{type(exc).__name__}"})

    # ---------- lease 续租 ----------
    def renew_lease(self, task_id: int, token: str) -> bool:
        return self.db.renew_lease(task_id, token, self.lease_seconds)

    def _renew_loop(self) -> None:
        """兜底续租：长时间任务防 lease 过期被回收。"""
        interval = max(1.0, self.lease_seconds / 3)
        while not self._renew_stop.wait(interval):
            for t in self.db.list_tasks():
                if t["status"] == "running" and t["lease_token"]:
                    self.db.renew_lease(t["id"], t["lease_token"], self.lease_seconds)
