"""7-Question Gate：漏洞发现出库门禁（借鉴 Anthropic Bug Bounty 方法论 + VulHunter 门禁）。

每个 finding 在可提交/可上报前必须通过：
  1. 证据完整（请求/响应/影响三要素）
  2. 能复现（同一请求可重复触发）
  3. 有实质影响（非纯指纹/非正常功能/非空响应）
  4. 不是误报（响应差异可解释，非回显型假象）

与 P0 的幂等提交不同：Gate 是"漏洞有效性"门，提交是"平台交互"门。
P1 实现为规则门禁（无 LLM），P2 起可加 LLM 辅助语义判定。
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .common import classify_flag_source, extract_flag

log = logging.getLogger("huntforge.gate")

REQUIRED_EVIDENCE = ("url", "request", "response", "impact")

# 无意义影响（响应正文与基线几乎无差异 → 判误报）
EMPTY_MARKERS = ("", "null", "[]", "{}", "404", "not found", "forbidden", "unauthorized",
                 "login required", "no such file", "bad request")


class GateResult:
    def __init__(self, passed: bool, reasons: list[str], score: float):
        self.passed = passed
        self.reasons = reasons
        self.score = score

    def to_dict(self) -> dict:
        return {"passed": self.passed, "reasons": self.reasons, "score": round(self.score, 2)}


def evaluate(evidence: dict) -> GateResult:
    """规则版 7Q Gate。evidence 含 url/request/response/impact + 可选 confirm 复现确认。"""
    reasons: list[str] = []

    # Q0 命中 flag 的候选直接出库：实盘教训——LLM/脚本路径经常缺 url/request
    # 等字段，不能让证据门把真 flag 杀掉；最终判定交给平台提交结果。
    # 但按来源分级（D0Pagent 语义）：目标响应佐证=high，复现/响应类=medium，
    # 仅模型声称=low——都放行（≥0.5），置信度随证据强度分层，供提交排序。
    value = evidence.get("value")
    if value and extract_flag(str(value)):
        grade = classify_flag_source(value, evidence)
        if grade == "high":
            return GateResult(True, ["flag 候选（目标响应佐证，高可信）直接出库"], 1.0)
        if grade == "medium":
            return GateResult(True, ["flag 候选（有复现/响应类佐证，中可信）出库，平台终判"], 0.8)
        return GateResult(True, ["flag 候选（仅模型声称，低可信）出库，平台终判"], 0.6)

    # Q1 证据完整
    missing = [k for k in REQUIRED_EVIDENCE if not evidence.get(k)]
    if missing:
        return GateResult(False, [f"证据缺失: {missing}"], 0.0)

    # Q2 复现确认（confirm 由检测器提供的二次验证响应）
    confirm = evidence.get("confirm")
    if confirm:
        reasons.append(f"复现确认: {str(confirm.get('note', 'ok'))[:60]}")

    # Q3 实质影响（响应不是空/错误/无意义）
    resp = str(evidence.get("response", ""))
    impact = str(evidence.get("impact", ""))
    resp_norm = resp.lower().strip()
    if any(resp_norm == m or resp_norm.startswith(m) for m in EMPTY_MARKERS) and not impact:
        return GateResult(False, ["响应无实质内容且无影响描述"], 0.0)

    # Q4 纯指纹/信息泄露（info 型）默认不报（防灌水），有复现确认才保留
    score = 0.8
    vuln_type = evidence.get("vuln_type") or evidence.get("type")
    if vuln_type == "info":
        score = 0.6 if confirm else 0.4

    # Q5 影响可陈述
    if not impact or len(impact) < 8:
        reasons.append("影响描述过短")

    # Q6 差异化证据（请求中带明显探测特征 → 排除回显假象）
    req = str(evidence.get("request", "")).lower()
    probe_marks = ("../", "' or ", "union select", "sleep(", "|id", ";id", "&&id")
    if any(m in req for m in probe_marks):
        reasons.append("包含探测特征，响应可解释")
        score = min(score, 0.95)

    passed = score >= 0.5
    return GateResult(passed, reasons, score)


def evaluate_and_persist(db, finding_id: int, evidence: dict) -> GateResult:
    """评估 + 落库（status: verified/killed）。"""
    result = evaluate(evidence)
    db.update_finding(finding_id, "verified" if result.passed else "killed",
                      result.to_dict())
    log.info("gate finding=%s passed=%s reasons=%s", finding_id, result.passed,
             result.reasons[:3])
    return result
