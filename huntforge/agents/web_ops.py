"""Web 综合挖掘 Agent：指纹 → LLM 多轮决策循环 / 专项检查序列 → 7Q Gate → finding/提交。

LLM（PentestPlanner）接入主决策链：
  - 首轮 analyze_web_target：分析目标响应，发现隐藏路径和非标准端点
  - 多轮 decide_next_step 循环：基于每次探测结果，LLM 生成下一步指令
    （路径/参数/请求头），agent 执行并反馈结果，直到命中 flag 或轮次耗尽
  - WAF/过滤检测，传递提示给专项检查
规则引擎可在 LLM 前或后执行（llm_first 控制）：规则快、LLM 深，
实盘跑分建议规则先行（llm_first=False），时间富余再让 LLM 探索。
"""
from __future__ import annotations

import logging
import re
import time
from typing import Callable, Optional

from ..core.state import StateDB
from ..web import checks
from ..web.common import get, post, body_of, extract_flag, Candidate
from ..web.fingerprint import Fingerprinter
from ..web.gate import evaluate_and_persist

log = logging.getLogger("huntforge.webops")

_LINK_RE = re.compile(r"""(?:href|src|action)=["']([^"'#]{1,200})["']""", re.I)
_FORM_RE = re.compile(r"<form[^>]*>.*?</form>", re.I | re.S)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_INPUT_RE = re.compile(r"""<input[^>]*name=["']([^"']{1,60})["'][^>]*>""", re.I)


def _page_summary(body: str) -> str:
    """把页面压缩成 LLM 友好的摘要：开头正文 + 链接 + 表单 + HTML 注释。

    决策循环每步只回灌这个摘要而非原始 body，信息密度远高于裸截断。
    """
    if not body:
        return ""
    head = body[:400].replace("\n", " ")
    links = _LINK_RE.findall(body[:20000])[:15]
    forms: list[str] = []
    for fm in _FORM_RE.findall(body[:20000])[:3]:
        m = _LINK_RE.search(fm)
        inputs = _INPUT_RE.findall(fm)[:8]
        forms.append(f"form(action={m.group(1) if m else '?'}, inputs={inputs})")
    comments = [c.strip()[:120] for c in _COMMENT_RE.findall(body[:20000])[:3] if c.strip()]
    parts = [head]
    if links:
        parts.append("links=" + ", ".join(links))
    if forms:
        parts.append("forms=" + "; ".join(forms))
    if comments:
        parts.append("comments=" + "; ".join(comments))
    return " | ".join(parts)[:900]


class WebOpsAgent:
    def __init__(self, db: StateDB, http_timeout: float = 8.0,
                 timebox: float = 600.0,
                 submitter: Optional[Callable[[str, str], None]] = None,
                 fingerprint: Optional[Fingerprinter] = None,
                 planner=None, stop_after_flag: bool = True,
                 llm_first: bool = True,
                 max_llm_steps: int = 6,
                 min_llm_time: float = 45.0):
        self.db = db
        self.http_timeout = http_timeout
        self.timebox = timebox
        self.submitter = submitter
        self.fp = fingerprint or Fingerprinter()
        self.planner = planner
        self.stop_after_flag = stop_after_flag
        self.llm_first = llm_first
        self.max_llm_steps = max_llm_steps
        self.min_llm_time = min_llm_time
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

        # 2) LLM 首轮分析（单次调用：理解系统、发现攻击面，提示喂给规则检查）
        llm_hints: dict = {}
        llm_used = False
        if self.planner and main_resp is not None and self._time_left() > self.min_llm_time:
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

        llm_candidates: list = []
        rule_candidates: list = []
        llm_steps = 0

        if self.llm_first:
            # LLM 多轮决策循环优先；未命中再跑规则检查
            llm_candidates, llm_steps, loop_ran = self._maybe_llm_loop(ch, target, llm_hints)
            llm_used = llm_used or loop_ran
            if not any(c.value for c in llm_candidates):
                rule_candidates = self._run_rules(ch, target, tags, llm_hints)
        else:
            # 规则先行（实盘快赢）；规则无 flag 且时间富余再 LLM 探索
            rule_candidates = self._run_rules(ch, target, tags, llm_hints)
            if not any(c.value for c in rule_candidates):
                llm_candidates, llm_steps, loop_ran = self._maybe_llm_loop(ch, target, llm_hints)
                llm_used = llm_used or loop_ran

        # 3) 去重 + Gate + 落库 + 提交
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

    # ---------- 规则检查 ----------
    def _run_rules(self, ch: dict, target: str, tags: list, llm_hints: dict) -> list:
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
        llm_order = llm_hints.get("priority_checks") or []
        fp_order = self.fp.check_order(tags)
        # 合并：LLM 优先，指纹顺序补充剩余
        seen: set = set(llm_order)
        order = list(llm_order) + [c for c in fp_order if c not in seen]

        out: list = []
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
            out.extend(found)
            self.db.event("task.info", "challenge", ch["id"],
                          {"msg": f"check {check_name} -> {len(found)} candidate(s)"})
            if any(c.value for c in found):
                log.info("rules: %s 命中 %d 个候选（含 flag）", check_name, len(found))
                if self.stop_after_flag:
                    break  # 单 flag 题目命中即停（多 flag 继续跑其余检查）
        return out

    # ---------- LLM 多轮决策循环 ----------
    def _maybe_llm_loop(self, ch: dict, base: str, hints: dict) -> tuple:
        """条件满足时启动决策循环。返回 (candidates, steps, ran)。"""
        if not (self.planner and hasattr(self.planner, "decide_next_step")
                and self._time_left() > self.min_llm_time):
            return [], 0, False
        candidates, steps = self._llm_decision_loop(ch, base, hints)
        return candidates, steps, True

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
        for step in range(self.max_llm_steps):
            if self._time_left() <= 0 or got_flag:
                break
            decision = self.planner.decide_next_step(base, history, hints)
            if not decision:
                break
            action = decision.get("next_action", "stop")
            reason = str(decision.get("reason", ""))[:100]
            log.info("llm-step %d: action=%s path=%s reason=%s",
                     step, action, decision.get("path"), reason)
            if action == "stop":
                self.db.event("llm.web_step", "challenge", ch["id"],
                              {"step": step, "action": "stop", "reason": reason})
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
                "snippet": _page_summary(body),   # 链接/表单/注释摘要，而非裸截断
            })
            self.db.event("llm.web_step", "challenge", ch["id"],
                          {"step": step, "action": action, "path": path,
                           "status": status, "flag": bool(flag), "reason": reason})
            log.info("llm-step %d: %s %s -> http %s flag=%s",
                     step, action.upper(), path, status, bool(flag))
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
