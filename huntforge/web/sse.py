"""SSE 事件流（借鉴 ctfSolver 的实时日志流）。

设计原则：**每一个推送到前端的事件，都对应一次真实的系统调用/网络请求/LLM 调用**，
事件正文写入 StateDB.events（审计事实源），前端零模拟日志。

- 进程内：EventBus 广播（订阅者 <500ms 收到，测试覆盖）。
- 跨进程：WebUI 通过 poll_events 轮询 events 表增量（id > cursor），
  agent 与 WebUI 分属两个进程也能流式可见。

事件标准字段：type / ref_type / ref_id / tool / params / result /
duration_ms / agent_id / abandoned / ts。敏感值脱敏后才入参。
"""
from __future__ import annotations

import queue
import threading
import time
from collections import deque
from typing import Optional

_SENSITIVE_KEYS = ("authorization", "token", "api_key", "apikey", "password",
                   "passwd", "secret", "cookie", "set-cookie", "session")


class EventBus:
    """进程内广播总线：publish 写入最近历史并唤醒全部订阅者。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._subs: list[queue.Queue] = []
        self._recent: deque = deque(maxlen=2000)

    def publish(self, event: dict) -> None:
        e = dict(event)
        e.setdefault("ts", time.time())
        with self._lock:
            self._recent.append(e)
            for q in list(self._subs):
                try:
                    q.put_nowait(e)
                except queue.Full:
                    pass  # 慢消费者丢增量不阻塞生产者（历史可从 db 补）

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def recent(self, limit: int = 200) -> list[dict]:
        with self._lock:
            return list(self._recent)[-limit:]


BUS = EventBus()


def _sanitize(value, depth: int = 0) -> object:
    """脱敏：已知敏感键的值打码，长文本截断（防拖垮前端）。"""
    if depth > 2:
        return str(value)[:200]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if str(k).lower().replace("-", "_") in _SENSITIVE_KEYS:
                out[k] = "***"
            else:
                out[k] = _sanitize(v, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [_sanitize(v, depth + 1) for v in value[:20]]
    if isinstance(value, str) and len(value) > 2000:
        return value[:2000] + f"...[{len(value)} chars]"
    return value


def emit_event(db, event_type: str, ref_type: str = "", ref_id: str = "",
               payload: Optional[dict] = None, *, tool: Optional[str] = None,
               params=None, result=None, duration_ms: Optional[float] = None,
               agent_id: Optional[str] = None, abandoned: Optional[str] = None,
               extra: Optional[dict] = None) -> dict:
    """标准原子操作事件：写 StateDB.events（事实源）并广播到进程内总线。

    db 为 None 时只走进程内总线（仍真实：事件由真实调用方主动发布）。
    """
    p = dict(payload or {})
    if tool is not None:
        p["tool"] = tool
    if params is not None:
        p["params"] = _sanitize(params)
    if result is not None:
        p["result"] = _sanitize(result)
    if duration_ms is not None:
        p["duration_ms"] = round(float(duration_ms), 1)
    if agent_id is not None:
        p["agent_id"] = agent_id
    if abandoned is not None:
        p["abandoned"] = abandoned
    if extra:
        p.update(_sanitize(extra))
    if db is not None:
        db.event(event_type, ref_type, ref_id, p)
    BUS.publish({"type": event_type, "ref_type": ref_type, "ref_id": ref_id,
                 "ts": time.time(), **p})
    return p


def poll_events(db_path: str, after_id: int = 0, interval: float = 0.5):
    """SSE 生成器：轮询 events 表增量（跨进程 WebUI 用）。

    只有真实写入 events 表的事件才会被推出去；轮询间隔默认 500ms
    （验收：推送延迟 < 500ms + 一次轮询开销）。
    """
    from ..core.state import StateDB  # 延迟导入：避免模块级依赖
    db = StateDB(db_path)
    last = after_id
    try:
        while True:
            rows = db.list_events_after(last, limit=200)
            for r in rows:
                last = max(last, r["id"])
                yield r
            time.sleep(interval)
    finally:
        db.close()
