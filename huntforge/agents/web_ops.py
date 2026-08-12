"""Web 综合挖掘 Agent：指纹 → LLM 规划 → 专项检查序列 → 7Q Gate → finding/提交。

LLM（PentestPlanner）接入主决策链：
  - 分析目标响应，发现隐藏路径和非标准端点
  - 基于响应语义调整专项检查优先级
  - WAF/过滤检测，传递提示给专项检查
规则引擎作为 fallback（LLM 不可用时自动降级）。
"""
from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from ..core.state import StateDB
from ..web import checks
from ..web.common import get, body_of, extract_flag, Candidate
from ..web.fingerprint import Fingerprinter
from ..web.gate import evaluate_and_persist

log = logging.getLogger("huntforge.webops")


class WebOpsAgent:
    def __init__(self, db: StateDB, http_timeout: float = 8.0,
                 timebox: float = 600.0,
                 submitter: Optional[Callable[[str, str], None]] = None,
                 fingerprint: Optional[Fingerprinter] = None,
                 planner=None):
        self.db = db
        self.http_timeout = http_timeout
        self.timebox = timebox
        self.submitter = submitter
        self.fp = fingerprint or Fingerprinter()
        self.planner = planner
        self._started = 0.0

    def run(self, task: dict) -> dict:
        ch = self.db.get_challenge(task["challenge_id"])
        if ch is None:
            return {"ok": False, "outcome": "no_challenge"}
        self._started = time.time()
        target = ch.get("target") or ""
        if not target.startswith(("http://", "https://")):
            self.db.event("task.info", "challenge", ch["id"],
                          {"msg": "web-ops: 非 HTTP 目标，跳过"})
            return {"ok": True, "outcome": "not_http"}

        # 1) 拉主页 + 指纹识别
        tags, main_resp = self._identify(target, ch["id"])
        self.db.put_memory("fingerprint", target[:120], {"tags": tags}, strength=1.0)

        # 2) LLM 规划（核心新增）
        llm_hints: dict = {}
        if self.planner and main_resp is not None and self._time_left() > 30:
            llm_hints = self.planner.analyze_web_target(
                target,
                main_resp.status_code,
                dict(main_resp.headers),
                body_of(main_resp),
                tags,
            ) or {}
            if llm_hints:
                self.db.event("llm.web_analysis", "challenge", ch["id"],
                              {"hidden_paths": llm_hints.get("hidden_paths", []),
                               "priority": llm_hints.get("priority_checks", []),
                               "waf": llm_hints.get("waf_detected")})
                log.info("LLM analysis: hidden_paths=%s waf=%s",
                         llm_hints.get("hidden_paths"), llm_hints.get("waf_detected"))

        # 3) 构建检查上下文（含 LLM 提示）
        ctx = {
            "base": target,
            "timeout": self.http_timeout,
            "time_left": self._time_left,
            # LLM 发现的隐藏路径 → unauth 检查会优先尝试
            "extra_paths": llm_hints.get("hidden_paths", []),
            # LLM 发现的非标准登录路径 → sqli 检查会尝试
            "extra_form_paths": llm_hints.get("extra_form_paths", []),
            # LLM 发现的可注入参数 → sqli/lfi 优先测这些参数
            "param_hints": llm_hints.get("injectable_params", []),
            # WAF 提示 → sqli 切换到绕过 payload
            "waf_hint": llm_hints.get("waf_detected"),
        }

        # 4) 专项检查（LLM 优先级 > 指纹优先级）
        order = list(dict.fromkeys(
            (llm_hints.get("priority_checks") or []) + self.fp.check_order(tags)
        ))

        candidates = []
        for check_name in order:
            if self._time_left() <= 0:
                break
            fn = checks.CHECKS.get(check_name)
            if not fn:
                continue
            try:
                found = fn(ctx)
            except Exception as exc:  # noqa: BLE001
                log.exception("check %s failed", check_name)
                self.db.event("task.info", "challenge", ch["id"],
                              {"msg": f"check {check_name} error: {exc}"})
                continue
            candidates.extend(found)
            self.db.event("task.info", "challenge", ch["id"],
                          {"msg": f"check {check_name} -> {len(found)} candidate(s)"})
            if any(c.value for c in found):
                break  # flag 已到手，停止

        # 5) 去重 + Gate + 落库 + 提交
        n_verified, n_flag = self._persist(ch, task["id"], candidates)
        return {
            "ok": True,
            "outcome": "flag_found" if n_flag else "scanned",
            "fingerprints": tags,
            "llm_used": bool(llm_hints),
            "candidates": len(candidates),
            "verified": n_verified,
            "flags": n_flag,
        }

    # ---------- 指纹 ----------
    def _identify(self, base: str, challenge_id: str):
        """返回 (tags, response_object)。"""
        resp = get(base, self.http_timeout)
        if resp is None:
            return [], None
        path_status: dict = {}
        for p in ("/api-docs", "/v2/api-docs", "/actuator", "/wp-content",
                  "/nacos", "/swagger-ui.html"):
            r = get(base.rstrip("/") + p, self.http_timeout)
            if r is not None:
                path_status[p] = r.status_code
        tags = self.fp.identify(base, dict(resp.headers), body_of(resp),
                                resp.status_code, path_status)
        if tags:
            self.db.event("fingerprint.identified", "challenge", challenge_id,
                          {"tags": tags})
        return tags, resp

    # ---------- 落库 ----------
    def _persist(self, ch: dict, task_id: int, candidates) -> tuple:
        n_verified = n_flag = 0
        seen: set = set()
        for cand in candidates:
            key = (cand.type, cand.url)
            if key in seen:
                continue
            seen.add(key)
            fid = self.db.add_finding(
                ch["id"], task_id, cand.type, cand.confidence, cand.evidence(),
            )
            result = evaluate_and_persist(self.db, fid, cand.evidence())
            if result.passed:
                n_verified += 1
                self.db.event("finding.verified", "challenge", ch["id"],
                              {"finding_id": fid, "vuln_type": cand.type})
                self.db.put_memory("hit", f"web:{cand.type}",
                                   {"url": cand.url, "how": cand.type}, strength=1.0)
            if cand.value and result.passed:
                n_flag += 1
                if self.submitter:
                    self.submitter(ch["id"], cand.value)
        return n_verified, n_flag

    def _time_left(self) -> float:
        return self.timebox - (time.time() - self._started)
