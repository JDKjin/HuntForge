"""Web 综合挖掘 Agent：指纹 → LLM 多轮决策循环 → 专项检查序列 → 7Q Gate → finding/提交。

LLM（PentestPlanner）接入主决策链：
  - 首轮 analyze_web_target：分析目标响应，发现隐藏路径和非标准端点
  - 多轮 decide_next_step 循环：基于每次探测结果，LLM 生成下一步指令
    （路径/参数/请求头），agent 执行并反馈结果，直到命中 flag 或轮次耗尽
  - WAF/过滤检测，传递提示给专项检查
规则引擎作为 fallback（LLM 不可用时自动降级）。
"""
from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from ..core.state import StateDB
from ..web import checks
from ..web.common import get, post, body_of, extract_flag, Candidate
from ..web.fingerprint import Fingerprinter
from ..web.gate import evaluate_and_persist

log = logging.getLogger("huntforge.webops")

MAX_LLM_STEPS = 6   # LLM 决策循环最大轮次
MIN_LLM_TIME = 45   # 剩余时间低于此值不再启动 LLM 循环


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

        # 2) LLM 首轮分析（核心：理解系统、发现攻击面）
        llm_hints: dict = {}
        llm_used = False
        if self.planner and main_resp is not None and self._time_left() > MIN_LLM_TIME:
            llm_used = True
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

        # 3) 多轮 LLM 决策循环（核心：分析→指令→执行→反馈→更新策略）
        llm_candidates: list = []
        llm_steps = 0
        if (self.planner and hasattr(self.planner, "decide_next_step")
                and self._time_left() > MIN_LLM_TIME):
            llm_used = True
            llm_candidates, llm_steps = self._llm_decision_loop(
                ch, target, llm_hints,
            )

        # 4) 构建检查上下文（含 LLM 提示），规则引擎作为补充
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

        # 5) 专项检查（LLM 优先级 > 指纹优先级），已有 flag 则跳过
        rule_candidates: list = []
        if not any(c.value for c in llm_candidates):
            llm_order = llm_hints.get("priority_checks") or []
            fp_order = self.fp.check_order(tags)
            # 合并：LLM 优先，指纹顺序补充剩余
            seen: set = set(llm_order)
            order = list(llm_order) + [c for c in fp_order if c not in seen]

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
                rule_candidates.extend(found)
                self.db.event("task.info", "challenge", ch["id"],
                              {"msg": f"check {check_name} -> {len(found)} candidate(s)"})
                if any(c.value for c in found):
                    break  # flag 已到手，停止

        # 6) 去重 + Gate + 落库 + 提交
        candidates = llm_candidates + rule_candidates
        n_verified, n_flag = self._persist(ch, task["id"], candidates)
        return {
            "ok": True,
            "outcome": "flag_found" if n_flag else "scanned",
            "fingerprints": tags,
            "llm_used": llm_used,
            "llm_steps": llm_steps,
            "candidates": len(candidates),
            "verified": n_verified,
            "flags": n_flag,
        }

    # ---------- LLM 多轮决策循环 ----------
    def _llm_decision_loop(self, ch: dict, base: str, hints: dict) -> tuple:
        """LLM 驱动的多轮探测：分析历史响应 → 生成下一步 → 执行 → 反馈。

        每轮把最新响应摘要加入历史，LLM 基于全局上下文决定下一步，
        直到命中 flag / LLM 无法继续 / 轮次或时间耗尽。
        """
        candidates: list = []
        history: list = []
        seq = 0
        got_flag = False
        seen_urls: set = set()   # (action, path, params, data) 去重，防 LLM 空转
        for step in range(MAX_LLM_STEPS):
            if self._time_left() <= 0 or got_flag:
                break
            decision = self.planner.decide_next_step(base, history, hints)
            if not decision:
                break
            action = decision.get("next_action", "stop")
            if action == "stop":
                self.db.event("llm.web_step", "challenge", ch["id"],
                              {"step": step, "action": "stop",
                               "reason": str(decision.get("reason", ""))[:120]})
                break
            if action == "flag":
                value = decision.get("flag_candidate")
                if value and extract_flag(value):
                    candidates.append(Candidate(
                        type="llm_flag", url=base,
                        request="LLM 决策循环", response=value,
                        impact="LLM 基于多轮探测确认 flag",
                        confidence=0.9, value=extract_flag(value),
                        confirm={"note": "LLM 决策循环确认"})
                    )
                    got_flag = True
                break
            if action not in ("get", "post"):
                break

            # 执行 LLM 生成的指令
            path = str(decision.get("path") or "/")
            if not path.startswith("/"):
                path = "/" + path
            params = decision.get("params") or {}
            data = decision.get("data") or {}
            headers = decision.get("headers") or {}
            url_key = (action, path, repr(params), repr(data))
            if url_key in seen_urls:
                self.db.event("llm.web_step", "challenge", ch["id"],
                              {"step": step, "action": action, "path": path,
                               "reason": "重复指令，停止防空转"})
                break
            seen_urls.add(url_key)
            url = base.rstrip("/") + path
            seq += 1
            if action == "post":
                resp = post(url, self.http_timeout, data=data or None,
                            headers=headers)
            else:
                resp = get(url, self.http_timeout, params=params or None,
                           headers=headers)
            body = body_of(resp)
            flag = extract_flag(body)
            status = resp.status_code if resp is not None else 0
            history.append({
                "seq": seq, "method": action.upper(), "path": path,
                "status": status,
                "snippet": body[:300],
            })
            self.db.event("llm.web_step", "challenge", ch["id"],
                          {"step": step, "action": action, "path": path,
                           "status": status, "flag": bool(flag),
                           "reason": str(decision.get("reason", ""))[:120]})
            if flag:
                candidates.append(Candidate(
                    type="llm_discovered", url=url,
                    request=f"{action.upper()} {path}",
                    response=body[:400],
                    impact="LLM 决策循环发现的 flag",
                    confidence=0.95, value=flag,
                    confirm={"note": "LLM 多轮决策循环命中"})
                )
                got_flag = True
                break
        return candidates, seq

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
