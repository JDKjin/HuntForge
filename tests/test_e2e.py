"""端到端测试：mock 平台 + mock 靶场 + 完整主循环。

P0 阶段预期：leak-demo（未授权 API 泄露）被 probe 直接发现并提交 accepted；
其余需漏洞利用的题留给 P1 专项 agent（此处断言其仍 pending，且不崩、不重复提交）。
"""
import pytest


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    from huntforge.core.config import Config
    from huntforge.core.state import StateDB
    from huntforge.main import run

    cfg = Config()
    cfg.data.setdefault("paths", {})["db"] = str(tmp_path_factory.mktemp("e2e") / "e2e.db")
    summary = run(cfg, mock=True, max_rounds=4, poll_interval=0.1)
    db_path = cfg.data["paths"]["db"]
    db = StateDB(db_path)
    events = db.list_events(limit=500)
    subs = db.list_submissions()
    db.close()
    return summary, events, subs


def test_all_mock_challenges_solved(result):
    """P1-P4 完整流水线：全部 7 个 mock 题（web/ai/binary/blockchain）全解。"""
    summary, _, _ = result
    assert summary["challenges"]["total"] == 7
    assert summary["challenges"]["solved"] == 7
    assert summary["challenges"]["pending"] == 0
    assert summary["challenges"]["idle"] == 0
    assert summary["submissions"]["accepted"] == 7
    assert summary["submissions"]["rejected"] == 0


def test_no_duplicate_submissions(result):
    summary, _, subs = result
    values = [s["value"] for s in subs]
    assert len(values) == len(set(values))  # 同一 flag 只提交一次


def test_events_trace_full_pipeline(result):
    summary, events, _ = result
    types = {e["event_type"] for e in events}
    assert "system.start" in types
    assert "challenges.fetched" in types
    assert "task.created" in types
    assert "task.completed" in types
    assert "finding.added" in types
    assert "submission.queued" in types
    assert "submission.result" in types
    assert "system.end" in types


def test_rejected_wrong_flag_is_terminal(result):
    # 通过 mock 平台直接提交错误 flag 应为 rejected（已有单测覆盖），此处确认 e2e 无 rejected 项
    summary, _, subs = result
    assert all(s["status"] != "rejected" for s in subs)
