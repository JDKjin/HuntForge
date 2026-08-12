"""Web 综合 agent 测试：LLM hints 改变检查顺序与路径。"""
import pytest

from huntforge.bench.mock_server import FLAGS, MockBench, TARGET_PORTS


@pytest.fixture(scope="module")
def mb():
    m = MockBench()
    m.start()
    yield m
    m.stop()


class FakePlanner:
    def analyze_web_target(self, url, status, headers, body, tags):
        return {
            "hidden_paths": ["/api/v1/flag"],
            "extra_form_paths": ["/login"],
            "injectable_params": ["id"],
            "priority_checks": ["unauth", "sqli"],
            "waf_detected": "waf",
            "attack_notes": "test",
        }


def test_web_ops_uses_llm_hints(db, mb):
    from huntforge.agents.web_ops import WebOpsAgent

    db.upsert_challenge({"id": "web-llm", "title": "w", "category": "web",
                         "difficulty": "medium", "target": f"http://127.0.0.1:{TARGET_PORTS['leak']}"})
    submitted = []
    agent = WebOpsAgent(db, timebox=60, submitter=lambda c, v: submitted.append((c, v)),
                        planner=FakePlanner())
    r = agent.run({"id": 1, "challenge_id": "web-llm", "agent_type": "web-ops"})
    assert r["llm_used"] is True
    assert r["outcome"] == "flag_found"
    assert submitted and submitted[0][1] == FLAGS["leak-demo"]
