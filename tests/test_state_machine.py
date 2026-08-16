"""六态状态机测试：合法流转、非法跳转拦截、终态直通、CAS 并发。"""
from huntforge.core.state_machine import ChallengeFSM


def test_linear_flow(db):
    fsm = ChallengeFSM(db)
    assert fsm.state("c1") == "idle"
    ok, _ = fsm.transition("c1", "exploring")
    assert ok and fsm.state("c1") == "exploring"
    assert fsm.transition("c1", "scanning")[0]
    assert fsm.transition("c1", "exploiting")[0]
    assert fsm.transition("c1", "validating")[0]
    assert fsm.transition("c1", "solved")[0]
    assert fsm.state("c1") == "solved"


def test_illegal_jump_rejected(db):
    """没扫出漏洞就直接进验证会被拒绝（触发 ABANDON 联动）。"""
    fsm = ChallengeFSM(db)
    ok, reason = fsm.transition("c1", "validating")
    assert not ok
    assert "非法" in reason
    assert fsm.state("c1") == "idle"
    fsm.transition("c1", "exploring")
    assert not fsm.transition("c1", "validating")[0]  # exploring → validating 跨级
    # rejected 事件已落库（供 WebUI/审计）
    events = db.list_events(event_type="fsm.rejected")
    assert len(events) == 2


def test_terminal_reachable_from_any_state(db):
    fsm = ChallengeFSM(db)
    fsm.transition("c1", "exploring")
    assert fsm.transition("c1", "failed")[0]
    assert fsm.state("c1") == "failed"
    fsm.transition("c2", "scanning")
    fsm.mark_solved("c2", note="test")
    assert fsm.state("c2") == "solved"


def test_bootstrap_direct_exploiting_allowed(db):
    """Bootstrap 快速路径：事实充分时 idle 直跳 exploiting。"""
    fsm = ChallengeFSM(db)
    assert fsm.transition("c1", "exploiting", note="bootstrap")[0]


def test_noop_and_unknown_state(db):
    fsm = ChallengeFSM(db)
    assert fsm.transition("c1", "exploring")[0]
    assert fsm.transition("c1", "exploring")[0]  # no-op
    assert not fsm.transition("c1", "teleporting")[0]
