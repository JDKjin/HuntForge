"""EvidenceStore 测试：结构化证据（confidence/source）与平台结果回校准。"""
from huntforge.core.evidence_store import EvidenceStore


def _ev(value=None):
    return {"url": "http://x/flag", "request": "GET /flag",
            "response": "flag{abc}" if value is None else value,
            "impact": "未授权泄露 flag",
            "value": value or "flag{abc}"}


def test_record_stores_source_and_confidence(db, sample_challenge):
    db.upsert_challenge(sample_challenge)
    es = EvidenceStore(db)
    fid, result = es.record("test-1", None, "unauth", 0.95, _ev(), source="scanner")
    assert result.passed
    f = db.list_findings("test-1")[0]
    assert f["evidence"]["source"] == "scanner"
    assert f["evidence"]["confidence"] == 0.95
    assert f["confidence"] == 0.95
    assert f["status"] == "verified"


def test_calibrate_accepted_promotes_candidates(db):
    es = EvidenceStore(db)
    for i in range(3):
        es.record("c1", None, "sqli", 0.8, _ev(), source=f"tool{i}",
                  gate=False)  # gate=False → 直接落 candidate
    affected = es.calibrate("c1", "flag{abc}", accepted=True)
    assert affected["verified"] == 3
    assert all(f["status"] == "verified" for f in db.list_findings("c1"))


def test_calibrate_rejected_kills_matching_value(db):
    es = EvidenceStore(db)
    es.record("c1", None, "sqli", 0.8, _ev("flag{wrong}"), source="llm",
              gate=False)
    es.record("c1", None, "lfi", 0.7, _ev("flag{other}"), source="rule",
              gate=False)
    affected = es.calibrate("c1", "flag{wrong}", accepted=False)
    assert affected["killed"] == 1
    statuses = {f["vuln_type"]: f["status"] for f in db.list_findings("c1")}
    assert statuses["sqli"] == "killed"
    assert statuses["lfi"] == "candidate"  # 无关证据不受影响


def test_calibrate_writes_audit_event(db):
    es = EvidenceStore(db)
    es.record("c1", None, "sqli", 0.8, _ev(), source="llm", gate=False)
    es.calibrate("c1", "flag{abc}", accepted=True)
    events = db.list_events(event_type="evidence.calibrated")
    assert events and events[0]["payload"]["accepted"] is True
