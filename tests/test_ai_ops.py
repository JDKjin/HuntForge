"""AI 应用安全 agent 测试（提示词注入打 mock AI 靶场）。"""
import pytest

from huntforge.bench.mock_server import FLAGS, MockBench, TARGET_PORTS


@pytest.fixture(scope="module")
def mb():
    m = MockBench()
    m.start()
    yield m
    m.stop()


def _run(db, cid, target):
    from huntforge.agents.ai_ops import AIOpsAgent
    submitted = []
    db.upsert_challenge({"id": cid, "title": "a", "category": "ai",
                         "difficulty": "medium", "target": target})
    agent = AIOpsAgent(db, timebox=60,
                       submitter=lambda c, v: submitted.append((c, v)))
    r = agent.run({"id": 1, "challenge_id": cid, "agent_type": "ai-ops"})
    return r, submitted


def test_prompt_injection_finds_flag(db, mb):
    r, submitted = _run(db, "ai-demo", f"http://127.0.0.1:{TARGET_PORTS['ai']}")
    assert r["outcome"] == "flag_found"
    assert r["requests"] <= 3  # 命中即停，不浪费
    assert submitted and submitted[0][1] == FLAGS["ai-demo"]


def test_knowledge_base_loaded():
    from huntforge.knowledge import ALL_TECHNIQUES
    total = sum(len(v) for v in ALL_TECHNIQUES.values())
    assert total >= 200, f"知识库应 ≥200 条，实际 {total}"
    # 每条都有 payload
    for cat, items in ALL_TECHNIQUES.items():
        for t in items:
            assert t["payloads"], f"{t['id']} 缺 payload"
