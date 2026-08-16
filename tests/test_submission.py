"""幂等提交管理器测试：状态机、冷却、未知态重试。"""


class FakeBench:
    """可编程的假平台：记录提交、可注入失败。"""

    def __init__(self, configured=True):
        self.configured = configured
        self.calls = []
        self._results = []

    def submit(self, challenge_id, value):
        self.calls.append((challenge_id, value))
        if self._results:
            r = self._results.pop(0)
        else:
            r = type("R", (), {"ok": True, "status": "accepted", "error": ""})()
        return r


def _mk(db, bench, **kw):
    from huntforge.bench.submission import SubmissionManager
    defaults = {"cooldowns": [0, 1, 60], "max_attempts": 3}
    defaults.update(kw)
    return SubmissionManager(db, bench, **defaults)


def _mk_ch(db, cid="c1"):
    db.upsert_challenge({"id": cid, "title": "T", "category": "web",
                         "difficulty": "easy", "target": ""})


def test_queue_dedup_and_accepted(db):
    _mk_ch(db)
    bench = FakeBench()
    mgr = _mk(db, bench)
    assert mgr.queue("c1", "flag{a}") is True
    assert mgr.queue("c1", "flag{a}") is False
    assert mgr.queue("c1", "") is False
    mgr.flush()
    assert bench.calls == [("c1", "flag{a}")]
    assert db.list_submissions()[0]["status"] == "accepted"
    assert db.get_challenge("c1")["status"] == "solved"


def test_unknown_retried_then_dropped(db):
    _mk_ch(db)
    bench = FakeBench()
    bench._results = [
        type("R", (), {"ok": False, "status": "unknown", "error": "timeout"})(),
        type("R", (), {"ok": False, "status": "unknown", "error": "timeout"})(),
        type("R", (), {"ok": False, "status": "unknown", "error": "timeout"})(),
        type("R", (), {"ok": False, "status": "unknown", "error": "timeout"})(),
    ]
    mgr = _mk(db, bench, cooldowns=[0, 0, 0, 0])  # 冷却全 0 才能测重试
    mgr.queue("c1", "flag{a}")
    for _ in range(4):
        mgr.flush()
    # 超过 max_attempts=3 → 放弃，不再提交
    assert len(bench.calls) == 3
    assert db.list_submissions()[0]["status"] == "rejected"


def test_rejected_not_retried(db):
    _mk_ch(db)
    bench = FakeBench()
    bench._results = [type("R", (), {"ok": False, "status": "rejected", "error": ""})()]
    mgr = _mk(db, bench)
    mgr.queue("c1", "flag{a}")
    mgr.flush()
    mgr.flush()
    assert len(bench.calls) == 1


def test_rejected_writes_disproven_lesson(db):
    """D0Pagent disproven_hypotheses 语义：被平台拒绝的 flag 值写入 lessons 反证。"""
    _mk_ch(db)
    bench = FakeBench()
    bench._results = [type("R", (), {"ok": False, "status": "rejected", "error": ""})()]
    mgr = _mk(db, bench)
    mgr.queue("c1", "flag{wrong-answer}")
    mgr.flush()
    lessons = db.get_memory("lesson")
    assert lessons, "被拒后应写入反证教训"
    assert lessons[0]["value"].get("disproven") is True
    assert "flag{wrong-answer" in lessons[0]["value"]["summary"]


def test_cooldown_gating(db, monkeypatch):
    import time as _t
    _mk_ch(db)
    bench = FakeBench()
    bench._results = [type("R", (), {"ok": False, "status": "unknown", "error": "x"})()]
    mgr = _mk(db, bench)  # cooldowns=[0,1,60]
    mgr.queue("c1", "flag{a}")
    mgr.flush()  # 第 1 次（首次冷却 0）
    assert len(bench.calls) == 1
    # 已失败 1 次 → 冷却 1 秒未到 → 不提交
    mgr.flush()
    assert len(bench.calls) == 1
    # 模拟时间前进 2 秒 → 第 2 次提交
    real_time = _t.time
    monkeypatch.setattr(_t, "time", lambda: real_time() + 2)
    mgr.flush()
    assert len(bench.calls) == 2
    # 已失败 2 次 → 冷却 60 秒 → 不提交
    mgr.flush()
    assert len(bench.calls) == 2
