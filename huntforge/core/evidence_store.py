"""EvidenceStore：结构化证据账本（借鉴 D0Pagent 的 EvidenceStore）。

每条证据（finding）带 confidence（置信度）与 source（来源工具/角色）；
平台 submit_flag 的结果作为最终权威判定，自动回校准同题证据：
- accepted → 同题 candidate 证据提为 verified（贡献链成立）
- rejected → 含同 value 的证据标 killed（该假设被平台证伪）

审计可追溯：证据写入与校准都落 events 表。
"""
from __future__ import annotations

from typing import Optional

from ..web.gate import evaluate_and_persist
from .state import StateDB


class EvidenceStore:
    def __init__(self, db: StateDB):
        self.db = db

    def record(self, challenge_id: str, task_id: Optional[int], vuln_type: str,
               confidence: float, evidence: dict, source: str,
               gate: bool = True) -> tuple[int, object]:
        """结构化落证据：confidence + source 固化进 evidence，过 7Q Gate。"""
        enriched = {**evidence, "source": source, "confidence": confidence}
        fid = self.db.add_finding(challenge_id, task_id, vuln_type, confidence, enriched)
        result = None
        if gate:
            result = evaluate_and_persist(self.db, fid, {**enriched,
                                                         "value": evidence.get("value")})
        self.db.event("evidence.recorded", "challenge", challenge_id,
                      {"finding_id": fid, "vuln_type": vuln_type, "source": source,
                       "confidence": confidence,
                       "gate": result.to_dict() if result else None})
        return fid, result

    def calibrate(self, challenge_id: str, value: str, accepted: bool) -> dict:
        """提交结果回校准：返回受影响的 finding 数。"""
        affected = {"verified": 0, "killed": 0}
        for f in self.db.list_findings(challenge_id):
            ev = f.get("evidence") or {}
            if accepted:
                if f["status"] == "candidate":
                    self.db.update_finding(f["id"], "verified",
                                           {**(f.get("gate") or {}),
                                            "note": "平台提交命中，证据回灌确认"})
                    affected["verified"] += 1
            elif ev.get("value") == value:
                self.db.update_finding(f["id"], "killed",
                                       {**(f.get("gate") or {}),
                                        "note": "平台提交被拒绝，证据证伪"})
                affected["killed"] += 1
        self.db.event("evidence.calibrated", "challenge", challenge_id,
                      {"accepted": accepted, **affected})
        return affected

    def top(self, challenge_id: str, status: str | None = None,
            limit: int = 20) -> list[dict]:
        findings = self.db.list_findings(challenge_id)
        if status:
            findings = [f for f in findings if f["status"] == status]
        findings.sort(key=lambda f: -f["confidence"])
        return findings[:limit]
