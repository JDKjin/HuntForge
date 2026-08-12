"""LLM planner 归一化与边界测试。"""
from huntforge.llm.planner import PentestPlanner


class DummyGW:
    def __init__(self, resp=None):
        self.resp = resp or {}

    def chat_json(self, messages, tier="standard"):
        return self.resp


def test_web_planner_normalizes_and_filters():
    planner = PentestPlanner(DummyGW({
        "hidden_paths": ["/admin", "http://evil", "../x", "/admin"],
        "extra_form_paths": ["/api/login", "//evil", "/api/login"],
        "injectable_params": ["id", "a" * 40, "user_id", "1id"],
        "priority_checks": ["sqli", "nope", "unauth", "rce"],
        "waf_detected": "waf-signature" * 30,
        "attack_notes": "note" * 100,
    }))
    out = planner.analyze_web_target("http://x", 200, {"Server": "x"}, "body", ["tag"])
    assert out["hidden_paths"] == ["/admin"]
    assert out["extra_form_paths"] == ["/api/login"]
    assert out["injectable_params"] == ["id", "user_id"]
    assert out["priority_checks"] == ["sqli", "unauth", "rce"]
    assert len(out["attack_notes"]) <= 160
    assert out["waf_detected"] is not None


def test_ai_planner_caps_payload_count():
    planner = PentestPlanner(DummyGW({
        "defense_mechanism": "filter",
        "payloads": ["one", "two", "two", "three", "four"],
        "strategy": "s" * 500,
    }))
    out = planner.generate_ai_payloads([], max_payloads=2)
    assert out["payloads"] == ["one", "two"]
    assert len(out["strategy"]) <= 220


def test_step_planner_accepts_script_action():
    planner = PentestPlanner(DummyGW({
        "next_action": "script",
        "script": "import requests\nprint(requests.get('http://x').text[:100])",
        "reason": "多步探测",
        "flag_candidate": None,
    }))
    out = planner.decide_next_step("http://x", [], None)
    assert out["next_action"] == "script"
    assert "import requests" in out["script"]
    # 空脚本 → 降级 stop
    out2 = planner.decide_next_step("http://x", [], None)
    out3 = PentestPlanner(DummyGW({"next_action": "script", "script": ""})).decide_next_step(
        "http://x", [], None)
    assert out3["next_action"] == "stop"
    # 非法动作 → stop
    out4 = PentestPlanner(DummyGW({"next_action": "rm -rf"})).decide_next_step(
        "http://x", [], None)
    assert out4["next_action"] == "stop"


def test_binary_and_contract_planner_shapes():
    planner = PentestPlanner(DummyGW({
        "flag_found": "flag{binary}",
        "encoded_hint": "base64",
        "decoded_flag": "flag{decoded}",
        "vuln_path": "path",
        "exploit_hint": "hint",
        "flag_in_source": "flag{chain}",
        "critical_vulns": [{"type": "reentrancy", "location": "withdraw", "description": "x"}],
        "flag_access_path": "call secret",
        "required_calls": ["deposit(1)", "secret()"],
    }))
    binary = planner.audit_binary("elf", ["x"], ["system"])
    contract = planner.audit_contract("contract X{}")
    assert binary["flag_found"] == "flag{binary}"
    assert binary["decoded_flag"] == "flag{decoded}"
    assert contract["flag_in_source"] == "flag{chain}"
    assert contract["required_calls"] == ["deposit(1)", "secret()"]
