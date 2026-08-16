"""六态挑战状态机（借鉴 D0Pagent 的状态流转思想，轻量实现）。

IDLE → EXPLORING → SCANNING → EXPLOITING → VALIDATING → SOLVED / FAILED

- 允许 Bootstrap 快速路径从 IDLE 直跳 EXPLOITING（事实已充分时）。
- 禁止跨状态乱跳：如未扫描（SCANNING）直接 VALIDATING、未利用（EXPLOITING）
  直接 VALIDATING 都会被拒绝——拒绝结果可交给 ABANDON 层强制换方向。
- 终态 SOLVED / FAILED 任何状态可进（平台判定为最终权威）。
- 写状态走 StateDB CAS，并发 worker 下后写者不覆盖先写者。
"""
from __future__ import annotations

from typing import Optional

from .state import StateDB

STATES = ("idle", "exploring", "scanning", "exploiting", "validating", "solved", "failed")

# 合法流转表：state -> 可进入的状态集合
LEGAL: dict[str, set[str]] = {
    "idle":       {"exploring", "scanning", "exploiting", "solved", "failed"},
    "exploring":  {"scanning", "exploiting", "idle", "solved", "failed"},
    "scanning":   {"exploiting", "validating", "exploring", "idle", "solved", "failed"},
    "exploiting": {"validating", "scanning", "idle", "solved", "failed"},
    "validating": {"exploiting", "solved", "failed"},
    "solved":     set(),
    "failed":     {"idle"},
}

# 语义校验（比 LEGAL 更严的软规则）：禁止「零产出」跨级直进验证。
# 注意：scanning → validating 合法——规则检查直接命中 flag 是主路径之一；
# exploiting → validating 也合法（LLM 深攻产出候选）。
FORBIDDEN_JUMP = (
    ("idle", "validating"),
    ("exploring", "validating"),
    ("failed", "validating"),
)


class ChallengeFSM:
    def __init__(self, db: StateDB):
        self.db = db

    def state(self, challenge_id: str) -> str:
        return self.db.get_challenge_state(challenge_id)

    def can(self, challenge_id: str, target: str) -> bool:
        return target in LEGAL.get(self.state(challenge_id), set())

    def transition(self, challenge_id: str, target: str, *,
                   note: str = "", allow_any_to_terminal: bool = True) -> tuple[bool, str]:
        """尝试流转。返回 (是否成功, 原因)。

        - 非法流转：返回 (False, 原因) 并写 fsm.rejected 事件（供 ABANDON 联动）。
        - solved/failed 视为平台权威终态：任何状态可直达。
        """
        if target not in STATES:
            return False, f"未知状态: {target}"
        current = self.state(challenge_id)
        if target == current:
            return True, "no-op"
        if allow_any_to_terminal and target in ("solved", "failed"):
            self.db.set_challenge_state(challenge_id, target, expect=current)
            self.db.event("fsm.transition", "challenge", challenge_id,
                          {"from": current, "to": target, "note": note,
                           "legal": True})
            return True, f"{current}->{target}（终态直通）"
        if (current, target) in FORBIDDEN_JUMP:
            reason = f"非法跳转 {current}->{target}（禁止跨状态乱跳）"
            self.db.event("fsm.rejected", "challenge", challenge_id,
                          {"from": current, "to": target, "note": note,
                           "reason": reason})
            return False, reason
        if target not in LEGAL.get(current, set()):
            reason = f"非法流转 {current}->{target}"
            self.db.event("fsm.rejected", "challenge", challenge_id,
                          {"from": current, "to": target, "note": note,
                           "reason": reason})
            return False, reason
        self.db.set_challenge_state(challenge_id, target, expect=current)
        self.db.event("fsm.transition", "challenge", challenge_id,
                      {"from": current, "to": target, "note": note, "legal": True})
        return True, f"{current}->{target}"

    def mark_solved(self, challenge_id: str, note: str = "flag accepted") -> None:
        self.db.set_challenge_state(challenge_id, "solved")
        self.db.event("fsm.transition", "challenge", challenge_id,
                      {"to": "solved", "note": note, "legal": True})

    def mark_failed(self, challenge_id: str, note: str = "attempts exhausted") -> None:
        self.db.set_challenge_state(challenge_id, "failed")
        self.db.event("fsm.transition", "challenge", challenge_id,
                      {"to": "failed", "note": note, "legal": True})

    def reset(self, challenge_id: str, note: str = "new attempt") -> None:
        """新一轮尝试重置到 idle（终态除外由调用方先判断）。"""
        self.db.set_challenge_state(challenge_id, "idle")
        self.db.event("fsm.transition", "challenge", challenge_id,
                      {"to": "idle", "note": note, "legal": True})
