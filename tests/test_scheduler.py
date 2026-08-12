"""调度器测试：CAS 领取不重不漏、lease 过期回收、崩溃恢复。"""
import threading
import time


def _mk_task(db, cid="c1"):
    db.upsert_challenge({"id": cid, "title": "T", "category": "web",
                         "difficulty": "easy", "target": ""})
    return db.create_task(cid, "probe")


def test_claim_is_atomic(db):
    t = _mk_task(db)
    task1 = db.claim_task()
    assert task1["id"] == t
    assert db.claim_task() is None  # 第二个人领不到


def test_concurrent_claims_no_duplicate(db):
    """多线程并发领取：每个任务只被领一次。"""
    for i in range(10):
        _mk_task(db, f"c{i}")
    claimed = []
    lock = threading.Lock()

    def worker():
        while True:
            t = db.claim_task()
            if t is None:
                break
            with lock:
                claimed.append(t["id"])

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert len(claimed) == 10
    assert len(set(claimed)) == 10


def test_lease_expiry_reclaim(db):
    t = _mk_task(db)
    task = db.claim_task()
    db.start_task(task["id"], task["lease_token"], 300)
    # 伪造过期
    db._execute("UPDATE tasks SET lease_expires=? WHERE id=?", (time.time() - 1, task["id"]))
    re_claimed = db.claim_task()
    assert re_claimed is not None
    assert re_claimed["id"] == t
    assert re_claimed["lease_token"] != task["lease_token"]


def test_complete_with_wrong_token_fails(db):
    t = _mk_task(db)
    task = db.claim_task()
    assert db.complete_task(t, "wrong-token", {"ok": True}) is False
    assert db.complete_task(t, task["lease_token"], {"ok": True}) is True


def test_fail_task_retry_then_give_up(db):
    t = _mk_task(db)
    for attempt in range(1, 4):  # max_attempts=3 → 只允许 3 次尝试
        task = db.claim_task()
        db.start_task(task["id"], task["lease_token"], 300)
        db.fail_task(task["id"], task["lease_token"], {"ok": False, "error": "x"})
        assert task["attempt"] == attempt
    assert db.list_tasks()[0]["status"] == "failed"
    assert db.claim_task() is None  # 已放弃，不可再领
