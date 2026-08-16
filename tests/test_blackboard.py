"""黑板（Fact-Intent）测试：生命周期、去重、线程安全。"""
import threading

from huntforge.core.blackboard import Blackboard, record_probe_fact


def test_fact_upsert_dedup(db):
    bb = Blackboard(db)
    bb.add_fact("c1", "GET /admin", {"status": 403}, confidence=1.0, source="t")
    bb.add_fact("c1", "GET /admin", {"status": 200}, confidence=1.0, source="t2")
    facts = bb.get_facts("c1")
    assert len(facts) == 1
    assert facts[0]["payload"]["status"] == 200  # 重复 key 合并为最新值


def test_intent_lifecycle_and_priority(db):
    bb = Blackboard(db)
    assert bb.add_intent("c1", "scan:sqli", {"check": "sqli"}, priority=0.3)
    assert not bb.add_intent("c1", "scan:sqli", {"check": "sqli"}, priority=0.9)  # 去重
    assert bb.add_intent("c1", "GET /api/flag", {"path": "/api/flag"}, priority=0.9)
    it = bb.claim_next_intent("c1")
    assert it is not None and it["key"] == "GET /api/flag"  # 高优先级先领
    assert bb.claim_next_intent("c1")["key"] == "scan:sqli"
    bb.resolve_intent(it["id"], "done", {"flag": "flag{x}"})
    assert bb.open_intents("c1") == []
    assert len(bb.get_facts("c1")) == 0


def test_intent_lease_expiry_recovers(db):
    """Cairn expire_workers 语义：claimed 且租约过期的 Intent 自动回 open。"""
    bb = Blackboard(db)
    bb.add_intent("c1", "scan:sqli", {"check": "sqli"}, priority=0.5)
    it = bb.claim_next_intent("c1", lease_seconds=300)
    assert it is not None
    assert bb.claim_next_intent("c1") is None  # 已领取，无其他待办
    # 模拟租约过期（崩溃残留）
    db._execute("UPDATE blackboard SET lease_expires=1 WHERE id=?", (it["id"],))
    it2 = bb.claim_next_intent("c1")
    assert it2 is not None and it2["id"] == it["id"]  # 过期自动回 open 再次领取
    bb.resolve_intent(it2["id"], "done")
    assert bb.claim_next_intent("c1") is None


def test_blackboard_thread_safety(db):
    """并行写 Fact 不冲突、不丢数据（StateDB 单连接锁）。"""
    bb = Blackboard(db)

    def writer(n):
        for i in range(20):
            bb.add_fact("c1", f"f{n}-{i}", {"n": n}, confidence=0.5)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(bb.get_facts("c1")) == 80


def test_record_probe_fact_key_format(db):
    bb = Blackboard(db)
    key = record_probe_fact(bb, "c1", "POST", "/login", 302, "body", True,
                            source="solver")
    assert key == "POST /login"
    f = bb.fact("c1", "POST /login")
    assert f["payload"]["status"] == 302 and f["confidence"] == 1.0


def test_facts_for_prompt_and_snapshot(db):
    bb = Blackboard(db)
    bb.add_fact("c1", "fingerprint", {"text": "nginx"}, confidence=0.9)
    bb.add_intent("c1", "scan:unauth", {"check": "unauth", "fact_keys": ["fingerprint"]},
                  priority=0.8)
    assert "fingerprint" in bb.facts_for_prompt("c1")
    snap = bb.snapshot("c1")
    assert len(snap["facts"]) == 1 and len(snap["intents"]) == 1
    assert snap["intents"][0]["payload"]["fact_keys"] == ["fingerprint"]
