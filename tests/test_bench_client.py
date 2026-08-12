"""BenchClient + mock 平台集成测试。"""
import pytest

from huntforge.bench.client import BenchClient, Challenge, _classify_submit
from huntforge.bench.mock_server import FLAGS, MockBench


@pytest.fixture(scope="module")
def mock_bench():
    mb = MockBench()
    mb.start()
    yield mb
    mb.stop()


def test_list_challenges_and_submit(mock_bench):
    client = BenchClient(mock_bench.base_url, None)
    challenges = client.list_challenges()
    assert {c.id for c in challenges} == {"unauth-demo", "sqli-demo", "lfi-demo",
                                          "leak-demo", "ai-demo", "binary-demo",
                                          "chain-demo"}
    for c in challenges:
        if c.category in ("web", "ai"):
            assert c.target.startswith("http://127.0.0.1:")
        else:
            assert c.target.endswith((".elf", ".sol"))

    # 正确 flag → accepted
    r = client.submit("unauth-demo", FLAGS["unauth-demo"])
    assert r.status == "accepted" and r.ok
    # 错误 flag → rejected
    r = client.submit("unauth-demo", "flag{wrong}")
    assert r.status == "rejected" and not r.ok


def test_classify_submit():
    assert _classify_submit(200, {"ok": True}) == "accepted"
    assert _classify_submit(201, {}) == "accepted"
    assert _classify_submit(400, {}) == "rejected"
    assert _classify_submit(500, {}) == "unknown"
    assert _classify_submit(0, {}) == "unknown"


def test_classify_submit_body_status_wins_over_http_code():
    """真实平台可能答错也返回 200 —— body 的 rejected 必须优先，否则假 accepted 停止挖掘。"""
    assert _classify_submit(200, {"status": "rejected"}) == "rejected"
    assert _classify_submit(200, {"ok": False}) == "rejected"
    assert _classify_submit(200, {"status": "accepted"}) == "accepted"
    # 5xx 携带 error 字样是服务器错误，不应误判为永久 rejected（可重试）
    assert _classify_submit(500, {"status": "error"}) == "unknown"


def test_classify_submit_rate_limit_is_retryable():
    """429 是频率限制，不是答案错误 —— 必须判 unknown 走冷却重试，不能放弃正确答案。"""
    assert _classify_submit(429, {}) == "unknown"
    assert _classify_submit(429, {"status": "rate_limited"}) == "unknown"


def test_challenge_from_unknown_field_names():
    c = Challenge.from_unknown({"task_id": "t9", "type": "AI", "host": "http://x:1"})
    assert c.id == "t9" and c.category == "ai" and c.target == "http://x:1"

    c = Challenge.from_unknown({"name": "n", "url": "u"})
    assert c.id == "n" and c.target == "u"
