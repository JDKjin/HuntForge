"""StateDB 单元测试：CRUD、去重、恢复。"""
import time


def test_challenge_upsert_and_get(db, sample_challenge):
    db.upsert_challenge(sample_challenge)
    ch = db.get_challenge("test-1")
    assert ch["id"] == "test-1"
    assert ch["status"] == "pending"

    # 已 solved 的题：upsert 不再改动（防平台重下发覆盖已解信息）
    db.set_challenge_status("test-1", "solved")
    db.upsert_challenge({**sample_challenge, "title": "T1-new"})
    assert db.get_challenge("test-1")["status"] == "solved"
    assert db.get_challenge("test-1")["title"] == "T1"


def test_submission_dedup(db, sample_challenge):
    db.upsert_challenge(sample_challenge)
    assert db.queue_submission("test-1", "flag{abc}") is True
    assert db.queue_submission("test-1", "flag{abc}") is False   # 同值去重
    assert db.queue_submission("test-1", "Flag{ABC}") is False   # 大小写不敏感去重
    assert db.queue_submission("test-1", "flag{def}") is True    # 不同值可入
    assert db.dedup_key("test-1", "flag{abc}") == db.dedup_key("test-1", "FLAG{ABC}")


def test_mark_submitting_cas(db, sample_challenge):
    db.upsert_challenge(sample_challenge)
    db.queue_submission("test-1", "flag{abc}")
    sub = db.peek_submissions()[0]
    assert db.mark_submitting(sub["id"]) is True
    assert db.mark_submitting(sub["id"]) is False   # 第二次抢不到
    again = db.peek_submissions()
    assert again == []                               # submitting 不在未决列表


def test_finish_accepted_marks_solved(db, sample_challenge):
    db.upsert_challenge(sample_challenge)
    db.queue_submission("test-1", "flag{abc}")
    sub = db.peek_submissions()[0]
    db.mark_submitting(sub["id"])
    db.finish_submission(sub["id"], "accepted", "test-1")
    assert db.get_challenge("test-1")["status"] == "solved"
    assert db.list_submissions()[0]["status"] == "accepted"


def test_recover_interrupted(db, sample_challenge):
    db.upsert_challenge(sample_challenge)
    db.create_task("test-1", "probe")
    task = db.claim_task()
    db.start_task(task["id"], task["lease_token"], 300)
    db.set_challenge_status("test-1", "solving")
    recovered = db.recover_interrupted()
    assert recovered["recovered_tasks"] >= 1
    assert db.list_tasks("test-1")[0]["status"] == "pending"
    assert db.get_challenge("test-1")["status"] == "pending"


def test_events_and_usage(db):
    db.event("unit.test", "challenge", "c1", {"n": 1})
    assert db.list_events()[0]["event_type"] == "unit.test"
    db.record_usage(None, "fast", "deepseek-chat", 10, 5, 2, 100)
    s = db.usage_summary()
    assert s["calls"] == 1 and s["in_t"] == 10 and s["cache_t"] == 2


def test_memory(db):
    db.put_memory("hit", "web:sqli", {"how": "x"})
    db.put_memory("hit", "web:sqli", {"how": "y"}, strength=2.0)
    mem = db.get_memory("hit")
    assert len(mem) == 1 and mem[0]["value"]["how"] == "y"
