"""SSE 事件流测试：低延迟广播、脱敏、零模拟（事件只来自真实发布）。"""
import queue
import time

from huntforge.web.sse import BUS, EventBus, _sanitize, emit_event


def test_bus_publish_latency_under_500ms(db):
    """验收：SSE 推送延迟 < 500ms。"""
    q = BUS.subscribe()
    try:
        started = time.time()
        emit_event(db, "probe.executed", "challenge", "c1",
                   tool="GET /flag", result={"status": 200})
        ev = q.get(timeout=0.5)   # 超 500ms 即失败
        latency = time.time() - started
        assert latency < 0.5
        assert ev["type"] == "probe.executed" and ev["tool"] == "GET /flag"
    finally:
        BUS.unsubscribe(q)


def test_sanitize_masks_secrets_and_truncates():
    ev = _sanitize({"Authorization": "Bearer sk-secret", "q": "x" * 5000})
    assert ev["Authorization"] == "***"
    assert len(ev["q"]) < 2500 and "chars" in ev["q"]
    assert _sanitize({"nested": {"API_KEY": "k"}})["nested"]["API_KEY"] == "***"


def test_emit_event_writes_db_and_bus(db):
    q = BUS.subscribe()
    try:
        p = emit_event(db, "llm.call", "task", "7", tool="llm:m-fast",
                       params={"tier": "deep"}, result={"out": 3},
                       duration_ms=123, agent_id="gateway",
                       abandoned="signature 失败", extra={"budget_used": 2})
        # db 事件 = 前端事件（同一事实源，零模拟）
        rows = db.list_events(event_type="llm.call")
        assert rows and rows[0]["payload"]["tool"] == "llm:m-fast"
        assert rows[0]["payload"]["abandoned"] == "signature 失败"
        bus_ev = q.get(timeout=0.5)
        assert bus_ev["duration_ms"] == 123
        assert bus_ev["ref_id"] == "7"
        assert p["params"]["tier"] == "deep"
    finally:
        BUS.unsubscribe(q)


def test_poll_events_yields_only_real_rows(db_path):
    """poll_events 只吐 events 表中真实存在的行（跨进程 WebUI 的事实源）。"""
    from huntforge.core.state import StateDB
    from huntforge.web.sse import poll_events
    s = StateDB(db_path)
    s.event("real.one", payload={"n": 1})
    s.event("real.two", payload={"n": 2})
    s.close()
    gen = poll_events(str(db_path), after_id=0, interval=0.01)
    ev = next(gen)
    gen.close() if hasattr(gen, "close") else None
    assert ev["event_type"] == "real.one" and ev["id"] > 0


def test_bus_history_ring():
    bus = EventBus()
    for i in range(5):
        bus.publish({"type": "t", "i": i})
    recent = bus.recent(3)
    assert [r["i"] for r in recent] == [2, 3, 4]
