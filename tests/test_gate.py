"""7Q Gate 测试。"""
from huntforge.web.gate import evaluate, evaluate_and_persist


def _ev(**kw):
    base = {"url": "http://x/flag", "request": "GET /flag",
            "response": "flag{abc}", "impact": "未授权泄露 flag"}
    base.update(kw)
    return base


def test_pass_with_full_evidence():
    r = evaluate(_ev())
    assert r.passed and r.score >= 0.5


def test_fail_missing_evidence():
    r = evaluate({"url": "http://x/"})  # 无 request/response/impact
    assert not r.passed
    assert "证据缺失" in r.reasons[0]


def test_fail_empty_response():
    r = evaluate(_ev(response="404 not found", impact=""))
    assert not r.passed


def test_info_type_killed_without_confirm():
    r = evaluate(_ev(vuln_type="info", impact="服务器信息泄露",
                     response="<title>nginx</title>"))
    assert not r.passed  # 纯信息泄露默认不报（防灌水）


def test_info_type_passes_with_confirm():
    r = evaluate(_ev(vuln_type="info", impact="服务器信息泄露",
                     response="<title>nginx</title>",
                     confirm={"note": "curl 复现确认"}))
    assert r.passed and r.score < 0.8


def test_probe_marker_in_request():
    r = evaluate(_ev(request="GET /download?file=../../etc/passwd",
                     response="root:x:0:0:root", impact="任意文件读取"))
    assert r.passed


def test_flag_candidate_passes_even_with_missing_fields():
    """实盘教训：LLM/脚本路径常缺 url/request——带 flag 的候选不得被证据门杀掉。"""
    r = evaluate({"value": "flag{direct}", "type": "llm_flag"})
    assert r.passed
    r2 = evaluate({"value": "flag{b64}", "response": "", "impact": ""})
    assert r2.passed


def test_flag_source_grading():
    """D0Pagent 来源分级语义：目标响应佐证=high，复现=medium，仅声称=low。"""
    # high：flag 值出现在目标实际响应中
    high = evaluate({"value": "flag{real}",
                     "response": "body contains flag{real} here"})
    assert high.passed and high.score == 1.0
    # medium：有复现确认
    med = evaluate({"value": "flag{real}", "confirm": {"note": "curl 复现"}})
    assert med.passed and 0.7 < med.score < 0.9
    # low：仅模型声称 → 仍放行（≥0.5）但降置信
    low = evaluate({"value": "flag{real}"})
    assert low.passed and 0.5 <= low.score < 0.7


def test_persist_updates_db(db, sample_challenge):
    db.upsert_challenge(sample_challenge)
    fid = db.add_finding("test-1", None, "lfi", 0.9, _ev())
    res = evaluate_and_persist(db, fid, _ev())
    assert res.passed
    f = db.list_findings("test-1")[0]
    assert f["status"] == "verified" and f["gate"]["passed"] is True
