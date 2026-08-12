"""专项检查对 mock 靶场的命中测试（规则引擎零 LLM 验证）。"""
import pytest

from huntforge.bench.mock_server import FLAGS, MockBench, TARGET_PORTS


@pytest.fixture(scope="module")
def mb():
    m = MockBench()
    m.start()
    yield m
    m.stop()


def _make_timeleft(budget=60):
    import time
    start = time.time()
    return lambda: budget - (time.time() - start)


def _ctx(port, budget=60):
    return {"base": f"http://127.0.0.1:{port}", "timeout": 5,
            "time_left": _make_timeleft(budget)}


def test_unauth_header_bypass(mb):
    from huntforge.web.checks import unauth
    cands = unauth.run(_ctx(TARGET_PORTS["unauth"]))
    hits = [c for c in cands if c.value == FLAGS["unauth-demo"]]
    assert hits, [c.impact for c in cands]
    assert hits[0].type == "unauth"


def test_sqli_login_bypass_chain(mb):
    from huntforge.web.checks import sqli
    cands = sqli.run(_ctx(TARGET_PORTS["sqli"]))
    hits = [c for c in cands if c.value == FLAGS["sqli-demo"]]
    assert hits, [c.impact for c in cands]
    assert "session" in (hits[0].confirm or {}).get("note", "")


def test_lfi_traversal(mb):
    from huntforge.web.checks import lfi
    cands = lfi.run(_ctx(TARGET_PORTS["lfi"]))
    hits = [c for c in cands if c.value == FLAGS["lfi-demo"]]
    assert hits, [c.impact for c in cands]
    assert hits[0].type == "lfi"


def test_leak_flag_via_probe_paths():
    from huntforge.agents.probe import ProbeAgent, COMMON_PATHS
    from huntforge.core.state import StateDB
    import tempfile, os
    db = StateDB(os.path.join(tempfile.mkdtemp(), "t.db"))
    db.upsert_challenge({"id": "leak-demo", "title": "l", "category": "web",
                         "difficulty": "easy",
                         "target": f"http://127.0.0.1:{TARGET_PORTS['leak']}"})
    agent = ProbeAgent(db, submitter=None)
    r = agent.run({"id": 1, "challenge_id": "leak-demo", "agent_type": "probe"})
    assert r["outcome"] == "flag_found"
    db.close()
