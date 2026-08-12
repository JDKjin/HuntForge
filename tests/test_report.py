"""量化报表测试。"""
from huntforge.report import build_report


def test_report_structure(db, sample_challenge):
    db.upsert_challenge(sample_challenge)
    db.event("system.start", payload={})
    db.add_finding("test-1", None, "sqli", 0.9,
                   {"url": "u", "request": "r", "response": "s", "impact": "i"})
    db.add_finding("test-1", None, "lfi", 0.9,
                   {"url": "u", "request": "r", "response": "s", "impact": "i"})
    db.update_finding(1, "verified", {"passed": True})
    db.update_finding(2, "killed", {})
    db.queue_submission("test-1", "flag{a}")
    sub = db.peek_submissions()[0]
    db.mark_submitting(sub["id"])
    db.finish_submission(sub["id"], "accepted", "test-1")
    db.event("system.end", payload={})

    rep = build_report(db)
    assert rep["发现率"]["题目总数"] == 1
    assert rep["发现率"]["已解出"] == 1
    assert rep["误报率"]["killed"] == 1
    assert rep["误报率"]["verified"] == 1
    assert rep["误报率"]["Gate拦截率"] == 0.5
    assert rep["大模型成本"]["calls"] == 0
    assert rep["人机比"]["人工干预次数"] == 0
    assert rep["运行时长_秒"] is not None
