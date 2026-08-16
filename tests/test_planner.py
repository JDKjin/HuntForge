"""LLM planner 归一化与边界测试。"""
from huntforge.llm.planner import PentestPlanner


class DummyGW:
    def __init__(self, resp=None):
        self.resp = resp or {}

    def chat_json(self, messages, tier="standard"):
        return self.resp


def test_extract_flag_decodes_layers():
    from huntforge.web.common import extract_flag
    assert extract_flag("x flag{plain} y") == "flag{plain}"
    assert extract_flag("flag%7burl_enc%7d") == "flag{url_enc}"
    hidden = __import__("base64").b64encode(b"flag{b64_secret}").decode()
    assert extract_flag(f'{{"k": "{hidden}"}}') == "flag{b64_secret}"
    assert extract_flag("nope") is None


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


def test_planner_uses_static_system_dynamic_user():
    """前缀缓存优化：静态指令在 system（逐字节稳定 → DeepSeek 缓存全命中），
    动态数据（历史/题面/教训）只进 user——省钱的关键结构。"""
    captured = {}

    class CaptureGW:
        def __init__(self):
            self.resp = {"next_action": "get", "path": "/x", "reason": "r"}

        def chat_json(self, messages, tier="standard"):
            captured["messages"] = messages
            return self.resp

    p = PentestPlanner(CaptureGW())
    p.decide_next_step("http://x",
                       [{"seq": 1, "method": "GET", "path": "/admin",
                         "status": 404, "snippet": "not found"}],
                       None, brief="S3 云函数", lessons=[], facts=[],
                       state="exploiting")
    msgs = captured["messages"]
    assert msgs[0]["role"] == "system" and msgs[1]["role"] == "user"
    assert "/admin" in msgs[1]["content"] and "S3" in msgs[1]["content"]
    assert "/admin" not in msgs[0]["content"]   # 动态不进 system
    assert "exploiting" in msgs[1]["content"]   # 状态也属动态
    # 同方法第二次调用 system 逐字节一致 → 缓存前缀稳定
    p.decide_next_step("http://x",
                       [{"seq": 2, "method": "GET", "path": "/y",
                         "status": 200, "snippet": "ok"}],
                       None, brief="S3 云函数", lessons=[], facts=[],
                       state="exploiting")
    assert captured["messages"][0]["content"] == msgs[0]["content"]
    assert captured["messages"][1]["content"] != msgs[1]["content"]


def test_decide_conv_delta_mode():
    """超高缓存框架：conv 模式下首轮 seed 全量，后续轮只发 delta（几十 token）。"""

    class ConvGW:
        def __init__(self):
            self.deltas = []
            self._n = 0

        def conv_len(self, key):
            return 3 if self._n else 0

        def chat_json_conv(self, conv_key, system, user_delta, tier="standard"):
            self.deltas.append(user_delta)
            self._n += 1
            return {"next_action": "get", "path": "/p", "reason": "r"}

    p = PentestPlanner(ConvGW())
    h1 = [{"seq": 1, "method": "GET", "path": "/a", "status": 200, "snippet": "x"}]
    p.decide_next_step("http://x", h1, None, brief="S3 云函数", lessons=[],
                       facts=[], state="exploiting", conv_key="c:decide")
    assert "题目说明" in p.gw.deltas[0]          # 首轮全量 seed
    h2 = h1 + [{"seq": 2, "method": "GET", "path": "/b", "status": 404,
                "snippet": "not found"}]
    p.decide_next_step("http://x", h2, None, brief="S3 云函数", lessons=[],
                       facts=[], state="exploiting", conv_key="c:decide")
    assert "新探测" in p.gw.deltas[1]            # 第二轮只发 delta
    assert "题目说明" not in p.gw.deltas[1]
    assert len(p.gw.deltas[1]) < 200             # delta 极小（缓存承载历史）


def test_bootstrap_skips_disproven_flags():
    """被平台证伪的 flag 值不再作为 Bootstrap 候选（D0Pagent 反证语义）。"""
    facts = [{"key": "GET /x", "payload": {"snippet": "flag{wrong}"}}]
    out = PentestPlanner(DummyGW({})).bootstrap(
        "http://x", facts, {},
        lessons=[{"disproven": True, "value": "flag{wrong}", "summary": "s"}])
    assert out is None  # 唯一候选已证伪 → 无快速动作
    out2 = PentestPlanner(DummyGW({})).bootstrap("http://x", facts, {})
    assert out2 and out2["next_action"] == "flag"
    assert out2["flag_candidate"] == "flag{wrong}"


def test_bootstrap_caps_probes_and_skips_static():
    """实盘 b-01 教训：静态资源跳过 + 每轮最多免费探 3 条，其余交给 LLM 深挖。"""
    p = PentestPlanner(DummyGW({}))
    hints = {"hidden_paths": ["/style.css", "/a", "/b", "/c", "/d"]}
    facts: list = []
    out1 = p.bootstrap("http://x", facts, hints)
    assert out1 and out1["path"] == "/a"          # .css 被跳过
    facts += [{"key": "GET /a", "payload": {}}]
    assert p.bootstrap("http://x", facts, hints)["path"] == "/b"
    facts += [{"key": "GET /b", "payload": {}}]
    assert p.bootstrap("http://x", facts, hints)["path"] == "/c"
    facts += [{"key": "GET /c", "payload": {}}]
    assert p.bootstrap("http://x", facts, hints) is None  # 3 条用尽 → 交给 LLM


def test_skip_reason_and_expected_value():
    from huntforge.bench.live_runner import expected_value, skip_reason
    # f1 协议题保留（socket 脚本打法）；f2 固件题不再弃权（/download 下发 ELF，
    # 实盘 f2-01/02/03 均拿分/解出——run-8928 修正）。
    assert not skip_reason({"unique_code": "f1-04", "description": "TCP"})
    assert not skip_reason({"unique_code": "f2-01", "description": "固件"})
    assert not skip_reason({"unique_code": "d-02", "description": "S3 云函数"})
    ev_b = expected_value({"unique_code": "b-01", "difficulty": "medium",
                           "total_score": 1200, "description": "Web"})
    ev_f = expected_value({"unique_code": "f1-04", "difficulty": "easy",
                           "total_score": 200, "description": "TCP"})
    assert ev_b > ev_f > 0


def test_live_runner_select_parallel():
    """并行领取：期望值排序、弃权过滤、in-flight 去重。"""
    from huntforge.bench.live_runner import LiveRunner
    r = LiveRunner("http://x", "t")
    chs = [
        {"unique_code": "b-01", "is_completed": False, "difficulty": "medium",
         "total_score": 1200, "description": "Web", "correct_flag_count": 0},
        {"unique_code": "f1-04", "is_completed": False, "difficulty": "easy",
         "total_score": 200, "description": "TCP", "correct_flag_count": 0},
        {"unique_code": "d-02", "is_completed": True, "difficulty": "easy",
         "total_score": 200, "description": "S3", "correct_flag_count": 1},
        {"unique_code": "a-01", "is_completed": False, "difficulty": "easy",
         "total_score": 100, "description": "web", "correct_flag_count": 0},
    ]
    c1 = r._select(chs)
    assert c1["unique_code"] == "b-01"          # 期望值最高；完成题被过滤
    c2 = r._select(chs)
    assert c2["unique_code"] == "f1-04"         # f1 保留（40 > a-01 20），b-01 已 in-flight
    c3 = r._select(chs)
    assert c3["unique_code"] == "a-01"
    assert r._select(chs) is None               # 全部打满
    r.db.close()


def test_live_runner_select_easy_lane():
    """easy 快速通道：easy worker 只按分值打 easy 题，打完后并入 top 池。"""
    from huntforge.bench.live_runner import LiveRunner
    r = LiveRunner("http://x", "t")
    chs = [
        {"unique_code": "b-01", "is_completed": False, "difficulty": "medium",
         "total_score": 1200, "description": "Web", "correct_flag_count": 0},
        {"unique_code": "a-02", "is_completed": False, "difficulty": "easy",
         "total_score": 150, "description": "web", "correct_flag_count": 0},
        {"unique_code": "a-01", "is_completed": False, "difficulty": "easy",
         "total_score": 100, "description": "web", "correct_flag_count": 0},
    ]
    c1 = r._select(chs, role="easy")
    assert c1["unique_code"] == "a-02"          # easy 通道按分值，不打 medium
    c2 = r._select(chs, role="easy")
    assert c2["unique_code"] == "a-01"
    c3 = r._select(chs, role="easy")
    assert c3["unique_code"] == "b-01"          # easy 打满后并入 top 池
    r.db.close()


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
