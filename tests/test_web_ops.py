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


def test_run_script_sandbox_allows_target_only():
    from huntforge.agents.web_ops import _run_script
    # 访问允许网段的本地 mock（127.0.0.1）应成功
    out = _run_script(
        "import requests; r = requests.get('http://127.0.0.1:1/'); print('unreachable')",
        "http://127.0.0.1:1", timeout=10,
    )
    assert "unreachable" not in out   # 端口 1 拒绝连接 → 脚本报错，不 print
    # 访问公网（被沙箱拦截）—— github.com 不在允许网段
    out2 = _run_script(
        "import requests\n"
        "try:\n"
        "    requests.get('https://github.com', timeout=3)\n"
        "    print('LEAKED')\n"
        "except OSError as e:\n"
        "    print('BLOCKED')\n",
        "http://127.0.0.1:1", timeout=15,
    )
    assert "BLOCKED" in out2 and "LEAKED" not in out2


def test_run_script_can_hit_mock_target(db, mb):
    from huntforge.agents.web_ops import _run_script
    from huntforge.bench.mock_server import FLAGS, TARGET_PORTS
    out = _run_script(
        "import requests\n"
        "r = requests.get(f\"http://127.0.0.1:%d/api/v1/flag\", timeout=10)\n"
        "print(r.text)\n" % TARGET_PORTS['leak'],
        f"http://127.0.0.1:{TARGET_PORTS['leak']}", timeout=15,
    )
    assert FLAGS["leak-demo"] in out


def test_page_summary_extracts_links_forms_comments():
    from huntforge.agents.web_ops import _page_summary
    html = (
        '<html><body>welcome to the portal'
        '<a href="/admin/panel">admin</a><a href="/api/v1/users">api</a>'
        '<form method=post action="/login"><input name="user"><input name="pass"></form>'
        '<!-- TODO: remove debug endpoint /debug -->'
        '</body></html>'
    )
    s = _page_summary(html)
    assert "/admin/panel" in s and "/api/v1/users" in s
    assert "form(action=/login" in s and "user" in s
    assert "/debug" in s
    assert len(s) <= 900


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
