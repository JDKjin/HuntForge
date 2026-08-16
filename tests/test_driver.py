"""huntforge.driver CLI 测试：本机 stub 平台（openapi 端点）+ 知识召回。"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

CHALLENGES = [
    {"unique_code": "a-01", "total_score": 500, "flag_count": 1,
     "correct_flag_count": 0, "is_completed": False,
     "difficulty": "medium", "container_status": "stopped",
     "container_addr": [], "description": "资产管理系统，导出报表功能"},
    {"unique_code": "c-99", "total_score": 100, "flag_count": 1,
     "correct_flag_count": 0, "is_completed": False,
     "difficulty": "easy", "container_status": "stopped",
     "container_addr": [], "description": "简单协议题"},
    {"unique_code": "b-01", "total_score": 1200, "flag_count": 2,
     "correct_flag_count": 2, "is_completed": True,
     "difficulty": "hard", "container_status": "stopped",
     "container_addr": [], "description": "内网渗透官网"},
]

ACCEPT = "FLAG{x}"


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静音
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _list(self):
        out = []
        for c in CHALLENGES:
            c = dict(c)
            if c["unique_code"] in self.server.started:
                c["container_status"] = "available"
                c["container_addr"] = ["127.0.0.1:18080"]
            out.append(c)
        return out

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        p = urlparse(self.path)
        if p.path == "/openapi/v1/challenges":
            return self._send(self._list())
        if p.path == "/openapi/v1/challenges/hint":
            q = parse_qs(p.query)
            if q.get("unique_code") == ["b-01"]:
                return self._send({"hint": "防火墙后的服务"})
            return self._send({"hint": None})
        self._send({"code": "not_found", "message": "nf"}, 404)

    def do_POST(self):
        from urllib.parse import parse_qs, urlparse
        p = urlparse(self.path)
        q = parse_qs(p.query)
        code = (q.get("unique_code") or [None])[0]
        if p.path == "/openapi/v1/challenges/start":
            if self.server.block_start:
                return self._send({"code": "invalid_state",
                                   "message": "max active challenge instances reached"},
                                  409)
            self.server.started.add(code)
            return self._send({"unique_code": code,
                               "container_addr": ["127.0.0.1:18080"]})
        if p.path == "/openapi/v1/challenges/close":
            self.server.started.discard(code)
            return self._send({"unique_code": code, "closed": True})
        if p.path == "/openapi/v1/challenges/submit":
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length))
            if body.get("flag") == ACCEPT:
                return self._send({"correct": True, "awarded": 100,
                                   "cumulative_score": 100,
                                   "correct_flag_count": 1,
                                   "total_flag_count": 1,
                                   "matched_flag_index": 0})
            return self._send({"correct": False, "awarded": 0,
                               "cumulative_score": 0,
                               "correct_flag_count": 0,
                               "total_flag_count": 1,
                               "matched_flag_index": None})
        self._send({"code": "not_found", "message": "nf"}, 404)


@pytest.fixture()
def platform(monkeypatch, tmp_path):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    srv.block_start = False
    srv.started = set()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    monkeypatch.setenv("BENCHMARK_BASE_URL", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.setenv("BENCHMARK_TOKEN", "test-token")
    # 每测试独立的 artifacts 目录（state.json 门控状态隔离）
    monkeypatch.setenv("HUNTFORGE_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    yield srv
    srv.shutdown()


def _run(capsys, argv):
    from huntforge import driver
    rc = driver.main(argv)
    out = capsys.readouterr().out
    lines = [json.loads(x) for x in out.strip().splitlines() if x.strip()]
    return rc, lines


def test_list_and_board(platform, capsys):
    rc, lines = _run(capsys, ["list"])
    assert rc == 0
    codes = {l["code"] for l in lines}
    assert codes == {"a-01", "b-01", "c-99"}

    rc, lines = _run(capsys, ["board"])
    assert rc == 0
    b = lines[0]
    assert b["completed"] == 1 and b["partial"] == 0
    # 分数估算模块已移除：board 只报事实计数（平台分数为准）
    assert "awarded" not in b
    unsolved = [u["code"] for u in b["unsolved"]]
    assert "a-01" in unsolved and "c-99" in unsolved


def test_start_wait_close(platform, capsys):
    rc, lines = _run(capsys, ["start", "a-01", "--wait"])
    assert rc == 0 and lines[0]["ok"] and lines[0]["addr"]

    rc, lines = _run(capsys, ["status", "a-01"])
    assert rc == 0 and lines[0]["code"] == "a-01"

    # 洗题门控：开题 3 分钟内且未解出 → 拒绝关闭；--force 放行
    rc, lines = _run(capsys, ["close", "a-01"])
    assert rc == 1 and "禁止关闭" in lines[0]["error"]
    rc, lines = _run(capsys, ["close", "a-01", "--force"])
    assert rc == 0 and lines[0]["closed"] is True


def test_close_allowed_after_solve(platform, capsys):
    rc, lines = _run(capsys, ["start", "a-01", "--wait"])
    assert rc == 0
    rc, lines = _run(capsys, ["submit", "a-01", ACCEPT])
    assert rc == 0
    rc, lines = _run(capsys, ["close", "a-01"])
    assert rc == 0 and lines[0]["closed"] is True


def test_hint_gate_and_force(platform, capsys):
    rc, _ = _run(capsys, ["start", "a-01", "--wait"])
    assert rc == 0
    rc, lines = _run(capsys, ["hint", "a-01"])
    assert rc == 1 and "hint 纪律" in lines[0]["error"]
    rc, lines = _run(capsys, ["hint", "a-01", "--force"])
    assert rc == 0 and lines[0]["ok"] is True


def test_next_picks_distinct(platform, capsys):
    rc, lines = _run(capsys, ["next"])
    assert rc == 0
    first = lines[0]["code"]
    rc, lines = _run(capsys, ["next"])
    assert rc == 0
    second = lines[0]["code"]
    assert first != second
    assert {first, second} == {"a-01", "c-99"}


def test_next_exclude_longhaul_and_prefer_easy(platform, capsys):
    # 通用特征判定：加一道 hard+内网题（长耗时）验证公平调度，不依赖题号
    CHALLENGES.append({
        "unique_code": "x-99", "total_score": 1500, "flag_count": 1,
        "correct_flag_count": 0, "is_completed": False,
        "difficulty": "hard", "container_status": "stopped",
        "container_addr": [], "description": "官网渗透进内网取机密数据"})
    try:
        # 排除长耗时 → 只能选非长耗时题
        rc, lines = _run(capsys, ["next", "--exclude-longhaul"])
        assert rc == 0 and not lines[0]["longhaul"]

        # 无排除 → 长耗时题期望值最高（hard 1500）
        rc, lines = _run(capsys, ["next"])
        assert rc == 0 and lines[0]["code"] == "x-99"
        assert lines[0]["longhaul"] is True

        # prefer easy → c-99（easy 100）优先于 a-01（medium 500）
        rc, lines = _run(capsys, ["next", "--prefer", "easy"])
        assert rc == 0 and lines[0]["code"] == "c-99"
    finally:
        CHALLENGES.pop()


def test_next_virgin_challenges_first(platform, capsys):
    """run-10043 教训：从未打过的题绝对优先，别让难题重打占满车道。"""
    _run(capsys, ["next"])   # a-01
    _run(capsys, ["next"])   # c-99
    # 新增一道从未打过、期望值低于 a-01 的题 → 必须优先于重打旧题
    CHALLENGES.append({
        "unique_code": "z-01", "total_score": 300, "flag_count": 1,
        "correct_flag_count": 0, "is_completed": False,
        "difficulty": "medium", "container_status": "stopped",
        "container_addr": [], "description": "全新目标"})
    try:
        rc, lines = _run(capsys, ["next"])
        assert rc == 0 and lines[0]["code"] == "z-01"
    finally:
        CHALLENGES.pop()


def test_next_hard_cap_no_endless_retry(platform, capsys):
    """run-10043 教训：全部超尝试上限时返回 None，不再无限重打同一题。"""
    from huntforge.driver import _save_state
    for code in ("a-01", "c-99"):
        _save_state(code, {"last_attempt": 0, "attempts": 4,
                           "started_at": 0, "solved": False})
    rc, lines = _run(capsys, ["next"])
    assert rc == 1 and lines[0]["code"] is None


def test_brief_includes_extra_targets(platform, capsys):
    """run-10043 教训：多地址题只打第一个目标会漏攻击面（bctf-25 的
    4873 注册表端口整场没人碰）——brief 必须带全其他目标。"""
    CHALLENGES.append({
        "unique_code": "m-01", "total_score": 500, "flag_count": 1,
        "correct_flag_count": 0, "is_completed": False,
        "difficulty": "medium", "container_status": "available",
        "container_addr": ["10.0.0.1:80", "10.0.0.2:4873"],
        "description": "多地址目标"})
    try:
        rc, lines = _run(capsys, ["brief", "m-01"])
        assert rc == 0
        assert lines[0]["target"] == "http://10.0.0.1:80"
        assert lines[0]["additional_targets"] == ["http://10.0.0.2:4873"]
    finally:
        CHALLENGES.pop()


def test_brief_and_harvest(platform, capsys, tmp_path):
    rc, lines = _run(capsys, ["brief", "a-01"])
    assert rc == 0 and lines[0]["ok"] is True
    assert lines[0]["target"] == "http://127.0.0.1:18080"
    assert "playbook" in lines[0]

    # 会话日志 → harvest 收割候选并提交
    d = tmp_path / "artifacts"
    (d / "a-01").mkdir(parents=True, exist_ok=True)
    (d / "a-01" / "session.log").write_text(
        "探测中...\nFLAG: FLAG{x}\nCANDIDATES: flag{z}|FLAG{w}\n",
        encoding="utf-8")
    rc, lines = _run(capsys, ["harvest", "a-01"])
    assert rc == 0
    acc = [l for l in lines if "accepted" in l]
    assert acc and ACCEPT in acc[0]["accepted"]
    fr = json.loads((d / "a-01" / "final-result.json")
                    .read_text(encoding="utf-8"))
    assert fr["status"] == "solved"
    # 收割后容器必须关闭（防名额泄漏死循环——run-9530 教训）
    assert "a-01" not in platform.started


def test_audit_detects_mismatch(platform, capsys, tmp_path):
    # 本地说接受过（harvest.log），但平台 correct_flag_count==0 → 巡检告警
    d = tmp_path / "artifacts"
    (d / "a-01").mkdir(parents=True, exist_ok=True)
    (d / "a-01" / "harvest.log").write_text(
        '{"ok": true, "code": "a-01", "accepted": ["FLAG{x}"]}\n',
        encoding="utf-8")
    rc, lines = _run(capsys, ["audit"])
    assert rc == 0
    a = lines[0]
    assert a["ok"] is True and a["challenges_checked"] >= 3
    kinds = {i["issue"] for i in a["issues"]}
    assert "local_accepted_but_platform_zero" in kinds


def test_harvest_closes_even_unsolved(platform, capsys, tmp_path):
    rc, lines = _run(capsys, ["brief", "a-01"])
    assert rc == 0
    d = tmp_path / "artifacts"
    (d / "a-01").mkdir(parents=True, exist_ok=True)
    (d / "a-01" / "session.log").write_text(
        "RESULT: unsolved 阻塞原因\n", encoding="utf-8")
    rc, lines = _run(capsys, ["harvest", "a-01"])
    assert rc == 0
    closed = [l for l in lines if "closed" in l]
    assert closed and closed[-1]["closed"] is True
    assert "a-01" not in platform.started
    fr = json.loads((d / "a-01" / "final-result.json")
                    .read_text(encoding="utf-8"))
    assert fr["status"] == "unsolved"


def test_submit_case_fallback(platform, capsys):
    # 先提交小写（判错）→ 自动前缀翻转重试（判对）
    rc, lines = _run(capsys, ["submit", "a-01", "flag{x}"])
    assert rc == 0
    assert lines[0]["ok"] is True and lines[0]["flag"] == ACCEPT


def test_submit_rejected_both(platform, capsys):
    rc, lines = _run(capsys, ["submit", "a-01", "flag{nope}"])
    assert rc == 1
    assert lines[0]["ok"] is False


def test_hint(platform, capsys):
    rc, lines = _run(capsys, ["hint", "b-01"])
    assert rc == 0 and lines[0]["hint"] == "防火墙后的服务"


def test_skill_recall(capsys):
    from huntforge import driver
    rc = driver.main(["skill", "内网渗透官网"])
    out = capsys.readouterr().out
    res = json.loads(out.strip().splitlines()[-1])
    assert rc == 0
    assert res["hint"]["type"] == "multi_stage"
    assert res["skills"], "应召回经验库/手册 skill"


def test_attack_wires_runner(platform, monkeypatch, capsys):
    from huntforge import driver
    calls = {}

    def fake_solve_one(self, ch, deadline, per_challenge, use_llm):
        calls["ch"] = ch["unique_code"]
        calls["timebox"] = per_challenge
        calls["use_llm"] = use_llm
        return False

    monkeypatch.setattr("huntforge.bench.live_runner.LiveRunner._solve_one",
                        fake_solve_one)
    rc = driver.main(["attack", "a-01", "--timebox", "60"])
    assert rc == 0
    assert calls == {"ch": "a-01", "timebox": 60.0, "use_llm": True}


def test_report_flag_candidate(platform, monkeypatch, capsys, tmp_path):
    import json
    from huntforge import driver
    monkeypatch.setenv("HUNTFORGE_ARTIFACTS_DIR", str(tmp_path))
    rc = driver.main(["report", "a-01", "FLAG{x}",
                      "--confidence", "95", "--summary", "exp 验证",
                      "--evidence", "exp.py"])
    assert rc == 0
    out = capsys.readouterr().out
    res = json.loads(out.strip().splitlines()[-1])
    assert res["ok"] is True
    p = json.loads(open(res["path"], encoding="utf-8").read())
    assert p["value"] == "FLAG{x}" and p["confidence"] == 95
    assert p["evidence"] == ["exp.py"]

    # --submit：落盘 + 提交（stub 接受 FLAG{x}）
    rc = driver.main(["report", "a-01", "FLAG{x}", "--submit"])
    assert rc == 0
    out = capsys.readouterr().out
    lines = [json.loads(x) for x in out.strip().splitlines() if x.strip()]
    assert lines[0]["ok"] is True          # report 落盘
    assert lines[-1]["ok"] is True         # submit 成功
