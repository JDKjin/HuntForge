"""Fact-Intent 黑板（借鉴 Cairn 的 Blackboard Architecture）。

- Fact：已确认的客观发现（"端口80开放"、"/admin 返回403"、命中 flag 等），
  以 (challenge_id, key) 唯一，重复写入自动合并。
- Intent：待执行的探索方向（"探测 /api/v1/flag"、"尝试 SQL 注入 login 参数"），
  带优先级，生命周期 open → claimed → done/skipped，CAS 领取防并行覆盖。

线程安全：所有读写经 StateDB 的单连接 + RLock（与任务领取同一套并发约定）。
"""
from __future__ import annotations

import time
from typing import Optional

from .state import StateDB

INTENT_STATUSES = ("open", "claimed", "done", "skipped")


class Blackboard:
    def __init__(self, db: StateDB):
        self.db = db

    # ---------- Fact ----------
    def add_fact(self, challenge_id: str, key: str, payload: dict,
                 confidence: float = 1.0, source: str = "") -> None:
        self.db.upsert_fact(challenge_id, key, dict(payload or {}), confidence, source)

    def get_facts(self, challenge_id: str, limit: int = 200) -> list[dict]:
        return self.db.list_facts(challenge_id)[:limit]

    def fact(self, challenge_id: str, key: str) -> Optional[dict]:
        for f in self.db.list_facts(challenge_id):
            if f["key"] == key:
                return f
        return None

    # ---------- Intent ----------
    def add_intent(self, challenge_id: str, key: str, payload: Optional[dict] = None,
                   priority: float = 0.5, source: str = "") -> bool:
        return self.db.add_intent(challenge_id, key, dict(payload or {}),
                                  priority, source)

    def open_intents(self, challenge_id: str, limit: int = 50) -> list[dict]:
        return self.db.list_intents(challenge_id, status="open")[:limit]

    def claim_next_intent(self, challenge_id: str,
                          lease_seconds: int = 300) -> Optional[dict]:
        """CAS 领取最高优先级 Intent；带租约（崩溃残留自动回 open，Cairn 语义）。"""
        return self.db.claim_next_intent(challenge_id, lease_seconds=lease_seconds)

    def resolve_intent(self, intent_id: int, status: str,
                       result: Optional[dict] = None) -> None:
        if status not in INTENT_STATUSES:
            raise ValueError(f"非法 Intent 状态: {status}")
        self.db.resolve_intent(intent_id, status, result)

    # ---------- 快照 / prompt 视图 ----------
    def facts_for_prompt(self, challenge_id: str, limit: int = 30) -> str:
        """Fact 压缩成一行一条的文本（喂给 planner 的 Observe 段）。"""
        lines = []
        for f in self.db.list_facts(challenge_id)[:limit]:
            p = f.get("payload") or {}
            text = p.get("text") or p.get("summary") or str(p)[:160]
            lines.append(f"- [fact] {f['key']}: {text}")
        return "\n".join(lines)

    def snapshot(self, challenge_id: str) -> dict:
        """WebUI 图可视化的数据源：facts + intents。"""
        facts = [{"id": f["id"], "key": f["key"], "payload": f["payload"],
                  "status": f["status"], "confidence": f["confidence"],
                  "source": f["source"]} for f in self.db.list_facts(challenge_id)]
        intents = [{"id": i["id"], "key": i["key"], "payload": i["payload"],
                    "status": i["status"], "priority": i["confidence"],
                    "source": i["source"]} for i in self.db.list_intents(challenge_id)]
        return {"challenge_id": challenge_id, "facts": facts, "intents": intents}


def record_probe_fact(bb: Blackboard, challenge_id: str, method: str, path: str,
                      status: int, snippet: str, ok: bool,
                      source: str = "") -> str:
    """把一次探测结果落成 Fact（key 归一化去重，用于签名层与图节点）。"""
    key = f"{method.upper()} {path}"
    bb.add_fact(
        challenge_id, key,
        {"method": method.upper(), "path": path, "status": status,
         "ok": ok, "snippet": (snippet or "")[:600]},
        confidence=1.0 if ok else 0.3, source=source,
    )
    return key
