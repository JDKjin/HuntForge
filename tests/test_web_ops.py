"""Web 综合 agent 测试：LLM hints 改变检查顺序与路径。"""
import pytest

from huntforge.bench.mock_server import FLAGS, TARGET_PORTS
TP = {k: v + 100 for k, v in TARGET_PORTS.items()}




class FakePlanner:
    def analyze_web_target(self, url, status, headers, body, tags, brief="",
                           lessons=None):
        return {
            "hidden_paths": ["/api/v1/flag"],
            "extra_form_paths": ["/login"],
            "injectable_params": ["id"],
            "priority_checks": ["unauth", "sqli"],
            "waf_detected": "waf",
            "attack_notes": "test",
        }


def test_script_productive():
    """ABANDON 观察语义：脚本成败看执行产出，不看是否命中 flag。"""
    from huntforge.agents.web_ops import _script_productive
    ok_out = "STATUS 200\nBODY_HEAD " + "x" * 60
    assert _script_productive(ok_out) is True
    assert _script_productive("[script produced no output]") is False
    assert _script_productive("[SCRIPT EXCEPTION] Traceback (most recent call last)") is False
    assert _script_productive("[script timeout]") is False
    assert _script_productive("short") is False


def test_run_script_sandbox_allows_target_only(monkeypatch):
    from huntforge.agents.web_ops import _run_script
    # 清掉代理环境变量：否则 requests 走本地代理（127.0.0.1 被沙箱放行），
    # 公网拦截逻辑被绕过，测试结果依赖机器网络环境。
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
              "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(k, raising=False)
    # 访问允许网段的本地 mock（127.0.0.1）应成功
    out = _run_script(
        "import requests; r = requests.get('http://127.0.0.1:1/'); print('unreachable')",
        "http://127.0.0.1:1", timeout=10,
    )
    assert "unreachable" not in out   # 端口 1 拒绝连接 → 脚本报错，不 print
    # 访问公网（被沙箱拦截）—— github.com 不在允许网段。
    # trust_env=False：忽略系统/注册表代理（本机代理是 127.0.0.1，被沙箱放行，
    # 会绕过拦截逻辑），强制直连以验证 socket 层沙箱。
    out2 = _run_script(
        "import requests\n"
        "s = requests.Session()\n"
        "s.trust_env = False\n"
        "try:\n"
        "    s.get('https://github.com', timeout=3)\n"
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
        "print(r.text)\n" % TP['leak'],
        f"http://127.0.0.1:{TP['leak']}", timeout=15,
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
                         "difficulty": "medium", "target": f"http://127.0.0.1:{TP['leak']}"})
    submitted = []
    agent = WebOpsAgent(db, timebox=60, submitter=lambda c, v: submitted.append((c, v)),
                        planner=FakePlanner())
    r = agent.run({"id": 1, "challenge_id": "web-llm", "agent_type": "web-ops"})
    assert r["llm_used"] is True
    assert r["outcome"] == "flag_found"
    assert submitted and submitted[0][1] == FLAGS["leak-demo"]


def test_load_lessons_injects_playbook(db):
    """预置解题手册强制注入：Web 题拿 Web 打法、协议/固件题拿二进制打法。"""
    from huntforge.agents.web_ops import WebOpsAgent
    from huntforge.knowledge.playbooks import BINARY_PLAYBOOK_HINT, WEB_PLAYBOOK_HINT
    agent = WebOpsAgent(db, timebox=60, planner=None)
    web_lessons = agent._load_lessons("公司内部上线了一个资产管理系统")
    assert web_lessons and web_lessons[0]["summary"] == WEB_PLAYBOOK_HINT
    bin_lessons = agent._load_lessons("自定义 TCP 协议服务，存在内存破坏漏洞")
    assert bin_lessons and bin_lessons[0]["summary"] == BINARY_PLAYBOOK_HINT
    fw_lessons = agent._load_lessons("固件镜像中隐藏后门口令")
    assert fw_lessons and fw_lessons[0]["summary"] == BINARY_PLAYBOOK_HINT


def test_playbooks_recallable_by_skill_store():
    """长版手册可被 match_skills 按题面召回（供 LLM 深挖）。"""
    from huntforge.knowledge import skill_store
    hits = [h["slug"] for h in skill_store.match_skills(
        "某企业门户网站存在安全隐患", limit=3)]
    assert "web-attack-playbook" in hits
    hits2 = [h["slug"] for h in skill_store.match_skills(
        "自定义 TCP 协议服务，存在内存破坏漏洞", limit=3)]
    assert "binary-pwn-playbook" in hits2
