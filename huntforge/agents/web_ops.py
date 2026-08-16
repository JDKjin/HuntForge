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
import os
import re
import subprocess
import sys
import time
from typing import Callable, Optional

from ..core.state import StateDB
from ..core.blackboard import Blackboard, record_probe_fact
from ..core.abandon import AbandonGuard, call_signature
from ..core.state_machine import ChallengeFSM
from ..knowledge import cve_engine, skill_store
from ..web import checks
from ..web.common import get, post, body_of, extract_flag, Candidate
from ..web.fingerprint import Fingerprinter
from ..web.gate import evaluate_and_persist
from ..web.sse import emit_event

log = logging.getLogger("huntforge.webops")

_LINK_RE = re.compile(r"""(?:href|src|action)=["']([^"'#]{1,200})["']""", re.I)
_FORM_RE = re.compile(r"<form[^>]*>.*?</form>", re.I | re.S)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_INPUT_RE = re.compile(r"""<input[^>]*name=["']([^"']{1,60})["'][^>]*>""", re.I)

# LLM 生成的脚本执行沙箱：socket 层拦截，只允许访问靶场网段
_SCRIPT_GUARD = (
    "import socket\n"
    "_hf_orig_connect = socket.socket.connect\n"
    "def _hf_guarded(self, addr, *a, **k):\n"
    "    host = addr[0] if isinstance(addr, tuple) else str(addr)\n"
    "    if not (host.startswith(('10.', '127.', '192.168.', '172.'))):\n"
    "        raise OSError('HuntForge sandbox: blocked host ' + host)\n"
    "    return _hf_orig_connect(self, addr, *a, **k)\n"
    "socket.socket.connect = _hf_guarded\n"
)


def _clip_ends(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    head_n = int(limit * 0.6)
    tail_n = limit - head_n - 20
    return text[:head_n] + "\n...[truncated]...\n" + text[-tail_n:]


def _run_script(code: str, base: str, timeout: float = 40.0, brief: str = "") -> str:
    """在受限沙箱执行 LLM 生成的 python 脚本（仅允许访问靶场网段），返回 stdout。

    TARGET 环境变量 = 目标 base URL。脚本把结果 print 出来即可回灌给 LLM。
    脚本内未捕获的异常会被捕获并打印，让 LLM 下一步能自我修复。
    """
    wrapper = (
        "import sys, traceback\n"
        "try:\n"
        "    exec(compile({code!r}, '<llm-script>', 'exec'), globals())\n"
        "except SystemExit:\n"
        "    pass\n"
        "except Exception:\n"
        "    print('[SCRIPT EXCEPTION]', traceback.format_exc(limit=2))\n"
    ).format(code=code)
    try:
        r = subprocess.run(
            [sys.executable, "-c", _SCRIPT_GUARD + wrapper],
            capture_output=True, timeout=timeout,
            env={**os.environ, "TARGET": base, "DESC": brief[:800],
                 "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
        )
        # 注意：不用 text=True——Windows 上默认 GBK 解码子进程 UTF-8 输出会崩掉 reader 线程
        out = (r.stdout or b"").decode("utf-8", "replace")
        if r.stderr:
            out += "\n[stderr] " + r.stderr.decode("utf-8", "replace")[:400]
        if not out.strip():
            out = "[script produced no output]"
        return _clip_ends(out, 4000)
    except subprocess.TimeoutExpired:
        return "[script timeout]"
    except Exception as exc:  # noqa: BLE001
        return f"[script error: {exc}]"


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


def _flag_count(ch: dict) -> int:
    """题目 flag 总数：challenges 表无独立列，flag_count 存于 meta
    （live_runner upsert 时写入；旧数据/测试可能直接放在顶层）。"""
    meta = ch.get("meta") or {}
    return max(1, int(ch.get("flag_count") or meta.get("flag_count") or 1))


def _script_productive(out: str) -> bool:
    """脚本是否真跑出了可用产出（ABANDON 观察用）。

    实盘第 4 轮教训：把「跑成功但没找到 flag」的脚本计为失败，3 个无 flag
    脚本后签名层会禁掉全部 script——而 d-01/d-02 两个 flag 恰恰都来自脚本。
    只有 异常/无输出/超时 才算真失败。
    """
    if not out:
        return False
    for mark in ("[script produced no output]", "[SCRIPT EXCEPTION]",
                 "[script timeout]", "[script error"):
        if mark in out:
            return False
    return len(out.strip()) > 30


class WebOpsAgent:
    def __init__(self, db: StateDB, http_timeout: float = 8.0,
                 timebox: float = 600.0,
                 submitter: Optional[Callable[[str, str], None]] = None,
                 fingerprint: Optional[Fingerprinter] = None,
                 planner=None, stop_after_flag: bool = True,
                 llm_first: bool = True,
                 max_llm_steps: int = 12,
                 min_llm_time: float = 45.0,
                 rules_max_seconds: Optional[float] = None):
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
        # 规则检查的时间上限（None=不限）：实盘规则先跑时防止规则吃光预算饿死 LLM 循环
        self.rules_max_seconds = rules_max_seconds
        self._started = 0.0
        # 架构升级（借用 Cairn / CHYing / D0Pagent）：
        # 黑板（Fact-Intent） + 六态状态机 + ABANDON 三层停损
        self.blackboard = Blackboard(db)
        self.fsm = ChallengeFSM(db)
        self.abandon = AbandonGuard()

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

        # 状态机：终态守卫 + 新一轮尝试重置（多 flag 重攻等场景合法重跑）
        state = self.fsm.state(ch["id"])
        if state == "solved":
            return {"ok": True, "outcome": "already_solved"}
        if state != "idle":
            self.fsm.reset(ch["id"], note="新一轮 agent 尝试")
        # 进入探索态（exploring）；非法流转只记录不阻断主流程
        self.fsm.transition(ch["id"], "exploring", note="web-ops start")

        # 1) 拉主页 + 指纹识别
        tags, main_resp = self._identify(target, ch["id"])
        self.db.put_memory("fingerprint", target[:120], {"tags": tags}, strength=1.0)
        self._seed_board(ch, target, tags, main_resp)

        # 2) LLM 首轮分析（单次调用：理解系统、发现攻击面，提示喂给规则检查）
        llm_hints: dict = {}
        llm_used = False
        lessons = self._load_lessons(ch.get("title") or "")
        if self.planner and main_resp is not None and self._time_left() > self.min_llm_time:
            llm_used = True
            llm_hints = self.planner.analyze_web_target(
                target,
                main_resp.status_code,
                dict(main_resp.headers),
                body_of(main_resp),
                tags,
                brief=ch.get("title") or "",
                lessons=lessons,
            ) or {}
            if llm_hints:
                self.db.event("llm.web_analysis", "challenge", ch["id"],
                              {"hidden_paths": llm_hints.get("hidden_paths", []),
                               "priority": llm_hints.get("priority_checks", []),
                               "waf": llm_hints.get("waf_detected")})
                log.info("LLM analysis: hidden_paths=%s waf=%s",
                         llm_hints.get("hidden_paths"), llm_hints.get("waf_detected"))
            # LLM 提示的隐藏路径 → 黑板 Intent（并行/后续按优先级领取）
            for p in llm_hints.get("hidden_paths", [])[:8]:
                self.blackboard.add_intent(ch["id"], f"GET {p}",
                                           {"path": p, "why": "llm hidden_path",
                                            "fact_keys": ["target"]},
                                           priority=0.9, source="llm_analysis")

        llm_candidates: list = []
        rule_candidates: list = []
        poc_candidates: list = []
        cve_candidates: list = []
        llm_steps = 0
        main_body = body_of(main_resp)

        if self.llm_first:
            # LLM 多轮决策循环优先；未命中再跑规则检查
            self.fsm.transition(ch["id"], "exploiting", note="llm-first 决策循环")
            llm_candidates, llm_steps, loop_ran = self._maybe_llm_loop(ch, target, llm_hints)
            llm_used = llm_used or loop_ran
            multi_flag = _flag_count(ch) > 1
            if not any(c.value for c in llm_candidates) or multi_flag:
                if not any(c.value for c in llm_candidates):
                    self.fsm.transition(ch["id"], "scanning", note="LLM 未命中回退规则")
                rule_candidates = self._run_rules(ch, target, tags, llm_hints)
                if not any(c.value for c in rule_candidates) \
                        and not any(c.value for c in llm_candidates):
                    # 定向 POC → CVE 引擎 → Kali 侦察兜底
                    poc_candidates = self._run_targeted_pocs(ch, target, tags, main_body)
                    if not any(c.value for c in poc_candidates):
                        cve_candidates = self._run_cve_stage(ch, target, main_body)
                        if not any(c.value for c in cve_candidates):
                            self._run_kali_recon(ch, target, llm_hints)
        else:
            # 规则先行（实盘快赢）；规则无 flag → 定向 POC → CVE → Kali → LLM 深攻
            self.fsm.transition(ch["id"], "scanning", note="规则检查先行")
            rule_candidates = self._run_rules(ch, target, tags, llm_hints)
            if not any(c.value for c in rule_candidates):
                poc_candidates = self._run_targeted_pocs(ch, target, tags, main_body)
                if not any(c.value for c in poc_candidates):
                    cve_candidates = self._run_cve_stage(ch, target, main_body)
                    if not any(c.value for c in cve_candidates):
                        self._run_kali_recon(ch, target, llm_hints)
                        self.fsm.transition(ch["id"], "exploiting", note="规则无产出转 LLM 深攻")
                        llm_candidates, llm_steps, loop_ran = self._maybe_llm_loop(ch, target, llm_hints)
                        llm_used = llm_used or loop_ran
            elif _flag_count(ch) > 1 and self._time_left() > self.min_llm_time:
                # 规则已命中 flag：多 flag 题继续 LLM 深挖剩余 flag（b 系列教训）
                self.fsm.transition(ch["id"], "exploiting", note="规则命中，多 flag 继续深挖")
                llm_candidates, llm_steps, loop_ran = self._maybe_llm_loop(ch, target, llm_hints)
                llm_used = llm_used or loop_ran

        # 3) 去重 + Gate + 落库 + 提交
        candidates = llm_candidates + rule_candidates + poc_candidates + cve_candidates
        if candidates:
            self.fsm.transition(ch["id"], "validating", note="候选进入证据门")
        n_verified, n_flag = self._persist(ch, task["id"], candidates)
        if n_flag:
            # 提交 ≠ 平台确认：终态 solved 只由 runner 层在平台 is_completed
            # 校验后标记。这里只转到 exploiting（允许后续轮次继续深挖；
            # 实盘教训：误标 solved 会让再攻循环秒回 already_solved 死循环空转）。
            self.fsm.transition(ch["id"], "exploiting",
                                note=f"flag 已提交({n_flag}/{_flag_count(ch)})")
            # 经验库：成功解题自动归档 skill（下次同类题召回注入）
            try:
                skill_store.archive_challenge(self.db, ch["id"])
            except Exception as exc:  # noqa: BLE001 - 归档失败不影响主流程
                log.warning("skill archive failed: %s", exc)
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

    # ---------- 定向 POC（指纹命中直击） ----------
    def _run_targeted_pocs(self, ch: dict, target: str, tags: list,
                           main_body: str) -> list:
        """指纹命中 → 跑成熟 POC（Shiro/SpringBoot/泛微），产物 flag 直接出库。"""
        if os.environ.get("HUNTFORGE_POC", "1") == "0":
            return []
        if self._time_left() < 45:
            return []
        try:
            from ..tools.targeted import run_targeted
        except ImportError:
            return []
        budget = min(150.0, self._time_left() * 0.5)
        started = time.time()
        cands = run_targeted(self.db, target, tags, main_body,
                             budget=budget, ref_id=ch.get("id", ""))
        ms = (time.time() - started) * 1000
        if cands:
            log.info("targeted POC: %d 个 flag 候选（%dms）", len(cands), int(ms))
            self.db.event("poc.hit", "challenge", ch["id"],
                          {"n": len(cands), "types": [c.type for c in cands]})
        return cands

    # ---------- CVE 识别引擎（规则直击 / LLM 现场写 POC） ----------
    def _run_cve_stage(self, ch: dict, target: str, main_body: str) -> list:
        """指纹匹配内置 CVE 库：有模板直接打，无模板交给 LLM 现场写 POC。"""
        if os.environ.get("HUNTFORGE_CVE", "1") == "0":
            return []
        if self._time_left() < 30:
            return []
        headers_blob = ""
        cands = cve_engine.run_cve_scan(
            self.db, ch["id"], target,
            title=ch.get("title", ""), body=main_body,
            headers_blob=headers_blob, path="",
            budget=min(60.0, self._time_left() * 0.3))
        if not cands:
            # 命中 CVE 但无内置模板 → LLM 现场编写 POC（一次 deep 调用）
            briefs = cve_engine.cve_briefs(title=ch.get("title", ""),
                                           body=main_body, limit=2)
            if briefs and self.planner and hasattr(self.planner, "compose_exploit") \
                    and self._time_left() > 60:
                log.info("cve: %s 命中，LLM 现场编写 POC", briefs[0].get("cve"))
                decision = self.planner.compose_exploit(briefs[0], target, [])
                code = str(decision.get("script") or "")
                if code:
                    started = time.time()
                    out = _run_script(code, target, brief=ch.get("title") or "")
                    ms = (time.time() - started) * 1000
                    emit_event(self.db, "cve.llm_poc", "challenge", ch["id"],
                               tool=f"compose:{briefs[0].get('cve')}",
                               agent_id="cve-engine",
                               result={"out_len": len(out), "flag": bool(extract_flag(out))},
                               duration_ms=ms)
                    flag = extract_flag(out)
                    if flag:
                        cands.append(Candidate(
                            type=f"cve_llm_{briefs[0].get('cve', 'x').lower()}",
                            url=target, request="LLM 现场 POC",
                            response=out[:400],
                            impact=f"LLM 基于 {briefs[0].get('cve')} 编写 POC 命中",
                            confidence=0.95, value=flag,
                            confirm={"note": briefs[0].get("attack", "")[:80]}))
        return cands

    # ---------- Kali 工具链侦察 ----------
    def _run_kali_recon(self, ch: dict, target: str, llm_hints: dict) -> None:
        """WSL Kali 侦察（katana/ffuf/nuclei）：发现喂黑板 + 补进 LLM 提示。"""
        if os.environ.get("HUNTFORGE_KALI", "1") == "0":
            return
        try:
            from ..tools import kali
        except ImportError:
            return
        if not kali.available() or self._time_left() < 30:
            return
        budget = min(90.0, self._time_left() * 0.4)
        started = time.time()
        res = kali.scan_suite(target, budget=budget)
        ms = (time.time() - started) * 1000
        endpoints = res.get("endpoints") or []
        dirs = res.get("dirs") or []
        tech = res.get("tech") or []
        self.db.event("kali.recon", "challenge", ch["id"],
                      {"tools": res.get("tools_ran"), "endpoints": len(endpoints),
                       "dirs": len(dirs), "tech": len(tech)})
        emit_event(self.db, "kali.recon", "challenge", ch["id"],
                   tool="kali", agent_id="web-ops",
                   params={"tools": res.get("tools_ran")},
                   result={"endpoints": len(endpoints), "dirs": len(dirs)},
                   duration_ms=ms)
        # 产出喂黑板：新端点 = Intent；技术栈 = Fact
        if tech:
            self.blackboard.add_fact(ch["id"], "kali:tech",
                                     {"text": "Kali 指纹: " + "; ".join(tech[:8])},
                                     confidence=0.8, source="kali-scan")
        for u in endpoints:
            path = u.split("://", 1)[-1]
            path = "/" + path.split("/", 1)[-1] if "/" in path else "/"
            self.blackboard.add_intent(ch["id"], f"GET {path}",
                                       {"path": path, "why": "kali katana 发现",
                                        "fact_keys": ["kali:tech"] if tech else ["target"]},
                                       priority=0.85, source="kali-scan")
        for d in dirs[:20]:
            p = d if d.startswith("/") else "/" + d
            self.blackboard.add_intent(ch["id"], f"GET {p}",
                                       {"path": p, "why": "kali ffuf 发现",
                                        "fact_keys": ["target"]},
                                       priority=0.8, source="kali-scan")
        # 补进 LLM 提示（bootstrap 与 unauth 都会优先尝试）
        # 实盘教训：katana 输出带 host:port（如 http://10.0.160.192:80/），
        # 不剥离会被 bootstrap 当成伪路径 GET /10.0.160.192:80 浪费 3 步。
        extra = []
        for u in endpoints:
            p = u.split("://", 1)[-1].split("?", 1)[0]
            if "fuzz" in p.lower() or "example." in p.lower():
                continue  # 工具横幅示例文本，非真实端点
            path = ("/" + p.split("/", 1)[-1]) if "/" in p else ""
            if path in ("", "/") or ":" in path:
                continue  # 丢弃根路径与 host:port 残留
            extra.append(path)
        extra += [d for d in dirs[:20]
                  if "fuzz" not in d.lower() and "example." not in d.lower()
                  and ":" not in d]
        llm_hints["hidden_paths"] = list(dict.fromkeys(
            llm_hints.get("hidden_paths", []) + extra))[:12]
        log.info("kali recon: %d endpoints, %d dirs, %d tech (%dms)",
                 len(endpoints), len(dirs), len(tech), int(ms))

    def _seed_board(self, ch: dict, target: str, tags: list,
                    main_resp: Optional[object]) -> None:
        """初始黑板：指纹/首页响应为 Fact，检查序列为 Intent。"""
        bb = self.blackboard
        if main_resp is not None:
            bb.add_fact(ch["id"], "GET /",
                        {"path": "/", "status": main_resp.status_code,
                         "ok": main_resp.status_code in (200, 301, 302),
                         "snippet": body_of(main_resp)[:400]},
                        confidence=1.0, source="explorer")
        if tags:
            bb.add_fact(ch["id"], "fingerprint",
                        {"text": f"技术栈: {', '.join(tags)}", "tags": tags},
                        confidence=0.9, source="explorer")
        bb.add_fact(ch["id"], "target", {"url": target, "title": ch.get("title", "")},
                    confidence=1.0, source="platform")
        for c in self.fp.check_order(tags):
            bb.add_intent(ch["id"], f"scan:{c}",
                          {"check": c,
                           "fact_keys": (["fingerprint", "target"]
                                         if tags else ["target"])},
                          priority=0.7, source="scanner")

    # ---------- 规则检查 ----------
    def _run_rules(self, ch: dict, target: str, tags: list, llm_hints: dict) -> list:
        # 规则阶段独立时间上限：到点即收，把时间留给 LLM 循环
        rules_deadline = (time.time() + self.rules_max_seconds
                          if self.rules_max_seconds else None)
        if rules_deadline:
            time_left = lambda: min(self._time_left(), rules_deadline - time.time())  # noqa: E731
        else:
            time_left = self._time_left
        ctx = {
            "base": target,
            "timeout": self.http_timeout,
            "time_left": time_left,
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

        def _run_check(check_name: str) -> list:
            if time_left() <= 0:
                return []
            fn = checks.CHECKS.get(check_name)
            if not fn:
                return []
            try:
                found = fn(ctx)
            except Exception as exc:  # noqa: BLE001
                log.exception("check %s failed", check_name)
                self.db.event("task.info", "challenge", ch["id"],
                              {"msg": f"check {check_name} error: {exc}"})
                return []
            self.db.event("task.info", "challenge", ch["id"],
                          {"msg": f"check {check_name} -> {len(found)} candidate(s)"})
            if any(c.value for c in found):
                log.info("rules: %s 命中 %d 个候选（含 flag）", check_name, len(found))
            return found

        # 并行执行（提速：五类检查互不依赖，共享 time_left 时间盒）
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="hf-check") as pool:
            futures = {pool.submit(_run_check, cn): cn for cn in order}
            for fut in as_completed(futures):
                out.extend(fut.result())
                if self.stop_after_flag and any(c.value for c in out):
                    break  # 命中即停：其余检查让其自然收尾（time_left 兜底）
        return out

    def _load_lessons(self, title: str = "") -> list:
        """跨题实战教训（自己的经验数据，最多回灌 3 条）。

        同时召回经验库 skills（成功解题自动归档，按题面关键词匹配），
        以摘要形式并入 lessons——已解出同类题的经验直接指导新题。
        预置打法（web/binary playbook）按题类强制注入，保证 100% 命中。
        """
        lessons = [r["value"] for r in self.db.get_memory("lesson")[-2:]]
        for sk in skill_store.match_skills(title or "", limit=2):
            lessons.append({"summary": sk["summary"]})
        lessons = lessons[-2:]          # 动态教训最多 2 条
        # 预置手册：协议/固件特征 → 二进制打法；内网/横向题面 → 多阶段打法；
        # 其余一律 Web 打法（永远第一位）
        from ..knowledge.playbooks import (BINARY_PLAYBOOK_HINT,
                                           MULTI_STAGE_PLAYBOOK_HINT,
                                           WEB_PLAYBOOK_HINT)
        t = (title or "").lower()
        if any(k in t for k in ("协议", "固件", "tcp", "二进制", "内存", "心跳", "mcu")):
            lessons.insert(0, {"summary": BINARY_PLAYBOOK_HINT})
        elif any(k in t for k in ("内网", "横向", "官网", "外网", "渗透", "机密",
                                  "核心数据", "防火墙", "多层", "隔离", "入侵")):
            lessons.insert(0, {"summary": MULTI_STAGE_PLAYBOOK_HINT})
        else:
            lessons.insert(0, {"summary": WEB_PLAYBOOK_HINT})
        return lessons

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
        flags_found = 0
        target_flags = _flag_count(ch)
        lessons = self._load_lessons(ch.get("title") or "")
        seen_urls: set = set()   # (action, path, params, data) 去重，防 LLM 空转
        for step in range(self.max_llm_steps):
            if self._time_left() <= 0 or flags_found >= target_flags:
                break
            facts = self.blackboard.get_facts(ch["id"])
            # Bootstrap 快速路径（借鉴 Cairn）：Fact 已充分时不花 LLM 直接产指令
            decision = None
            if self.planner and hasattr(self.planner, "bootstrap"):
                decision = self.planner.bootstrap(base, facts, hints,
                                                  lessons=lessons)
                if decision:
                    log.info("llm-step %d: bootstrap -> %s %s (免 LLM 调用)",
                             step, decision.get("next_action"), decision.get("path"))
                    self.db.event("llm.web_step", "challenge", ch["id"],
                                  {"step": step, "action": decision.get("next_action"),
                                   "path": decision.get("path"),
                                   "reason": decision.get("reason"), "bootstrap": True})
            if decision is None:
                decision = self.planner.decide_next_step(
                    base, history, hints, brief=ch.get("title") or "",
                    lessons=lessons, facts=facts,
                    state=self.fsm.state(ch["id"]),
                    conv_key=f"{ch['id']}:decide",
                )
            if not decision:
                break
            action = decision.get("next_action", "stop")
            reason = str(decision.get("reason", ""))[:100]
            log.info("llm-step %d: action=%s path=%s reason=%s",
                     step, action, decision.get("path"), reason)
            if action == "stop" and len(history) < 3:
                # 早停硬门：少于 3 次有效探测不许停（题面/robots/首页还没看完）
                action = "get"
                if not decision.get("path"):
                    decision["path"] = "/robots.txt" if len(history) == 1 else "/"
                log.info("llm-step %d: 早停拦截，改为 GET %s", step, decision.get("path"))
            if action == "stop":
                if not history:
                    # 空转保护：历史为空不许停，强制先探测首页再让 LLM 重新决策
                    log.info("llm-step %d: 空历史 stop，强制 GET / 后继续", step)
                    resp = get(base, self.http_timeout)
                    body = body_of(resp)
                    status = resp.status_code if resp is not None else 0
                    seq += 1
                    flag = extract_flag(body)
                    history.append({"seq": seq, "method": "GET", "path": "/",
                                    "status": status, "snippet": _page_summary(body)})
                    self.db.event("llm.web_step", "challenge", ch["id"],
                                  {"step": step, "action": "forced-get",
                                   "path": "/", "status": status,
                                   "flag": bool(flag), "reason": "空历史 stop 兜底"})
                    if flag:
                        candidates.append(Candidate(
                            type="llm_discovered", url=base,
                            request="GET /", response=body[:400],
                            impact="首页直接泄露 flag",
                            confidence=0.95, value=flag,
                            confirm={"note": "兜底探测命中"})
                        )
                        got_flag = True
                        flags_found += 1
                        # 多 flag 题：拿到一个后继续找下一个（下轮 LLM 会看到事实）
                        self.blackboard.add_fact(
                            ch["id"], f"FLAG#{flags_found}",
                            {"text": f"已找到第 {flags_found} 个 flag: {flag}",
                             "snippet": flag}, confidence=0.99,
                            source="llm_loop")
                    continue
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
                    flags_found += 1
                    self.blackboard.add_fact(
                        ch["id"], f"FLAG#{flags_found}",
                        {"text": f"已找到第 {flags_found} 个 flag: {value}",
                         "snippet": value}, confidence=0.9,
                        source="llm_loop")
                    # 多 flag 题：继续深挖剩余 flag
                    continue
                break
            if action == "script":
                # LLM 写的脚本：一次完成多步探测/爆破/利用（受限沙箱）
                code = str(decision.get("script") or "")
                if not code:
                    break
                if ("script", code[:300]) in seen_urls:
                    self.db.event("llm.web_step", "challenge", ch["id"],
                                  {"step": step, "action": "script",
                                   "reason": "重复脚本，标记并让 LLM 换方向"})
                    seq += 1
                    history.append({"seq": seq, "method": "DUP", "path": "(script)",
                                    "status": 0,
                                    "snippet": "[重复脚本已忽略——请换一个策略]"})
                    continue
                seen_urls.add(("script", code[:300]))
                # ABANDON 三层停损（事前拦截）
                abandon_reason = self.abandon.check(
                    ch["id"], "script", "(script)", payload_text=code)
                if abandon_reason:
                    self._abandon_block(ch, step, history, seq, "script",
                                        "(script)", abandon_reason)
                    seq += 1
                    continue
                started = time.time()
                seq += 1
                out = _run_script(code, base, brief=ch.get("title") or "")
                ms = (time.time() - started) * 1000
                flag = extract_flag(out)
                history.append({
                    "seq": seq, "method": "SCRIPT", "path": "(script)",
                    "status": 0, "snippet": _clip_ends(out, 1500),
                })
                self.db.event("llm.web_step", "challenge", ch["id"],
                              {"step": step, "action": "script",
                               "flag": bool(flag), "reason": reason})
                self.blackboard.add_fact(
                    ch["id"], f"SCRIPT#{step}",
                    {"out_len": len(out), "ok": bool(flag),
                     "snippet": _clip_ends(out, 600)},
                    confidence=0.8 if flag else 0.3, source="executor")
                self.abandon.observe(
                    ch["id"], call_signature("script", "(script)"),
                    _script_productive(out),
                    snippet=_clip_ends(out, 400), payload_text=code)
                emit_event(self.db, "llm.script", "challenge", ch["id"],
                           tool="script", params={"code_head": code[:200]},
                           result={"out_len": len(out), "flag": bool(flag)},
                           duration_ms=ms, agent_id="web-ops",
                           extra={"step": step, "reason": reason})
                log.info("llm-step %d: SCRIPT -> %d chars, flag=%s",
                         step, len(out), bool(flag))
                if flag:
                    candidates.append(Candidate(
                        type="llm_script", url=base,
                        request="LLM script", response=out[:400],
                        impact="LLM 脚本探测发现 flag",
                        confidence=0.95, value=flag,
                        confirm={"note": "LLM 脚本执行命中"})
                    )
                    got_flag = True
                    flags_found += 1
                    self.blackboard.add_fact(
                        ch["id"], f"FLAG#{flags_found}",
                        {"text": f"已找到第 {flags_found} 个 flag: {flag}",
                         "snippet": flag}, confidence=0.99,
                        source="llm_loop")
                continue
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
                               "reason": "重复指令，标记并让 LLM 换方向"})
                seq += 1
                history.append({"seq": seq, "method": "DUP", "path": path,
                                "status": 0,
                                "snippet": "[重复指令已忽略——该请求此前已执行过，请换方向]"})
                continue
            seen_urls.add(url_key)
            # ABANDON 三层停损（事前拦截）：命中即跳过执行，强制换方向
            abandon_reason = self.abandon.check(ch["id"], action, path,
                                                params, data)
            if abandon_reason:
                self._abandon_block(ch, step, history, seq, action, path,
                                    abandon_reason)
                seq += 1
                continue
            url = base.rstrip("/") + path
            started = time.time()
            seq += 1
            if action == "post":
                resp = post(url, self.http_timeout, data=data or None,
                            headers=headers)
            else:
                resp = get(url, self.http_timeout, params=params or None,
                           headers=headers)
            ms = (time.time() - started) * 1000
            body = body_of(resp)
            flag = extract_flag(body)
            status = resp.status_code if resp is not None else 0
            history.append({
                "seq": seq, "method": action.upper(), "path": path,
                "status": status,
                "snippet": _page_summary(body),   # 链接/表单/注释摘要，而非裸截断
            })
            # 黑板 Fact + ABANDON 观察 + SSE 事件（一次真实请求 = 一条真实日志）
            ok = bool(flag) or status in (200, 301, 302)
            sig = record_probe_fact(self.blackboard, ch["id"], action.upper(),
                                    path, status, body[:400], ok,
                                    source="llm_loop")
            self.abandon.observe(ch["id"], sig, ok,
                                 snippet=_page_summary(body))
            self.db.event("llm.web_step", "challenge", ch["id"],
                          {"step": step, "action": action, "path": path,
                           "status": status, "flag": bool(flag), "reason": reason})
            emit_event(self.db, "llm.web_step", "challenge", ch["id"],
                       tool=f"{action.upper()} {path}",
                       params=params or data,
                       result={"status": status, "flag": bool(flag),
                               "len": len(body)},
                       duration_ms=ms, agent_id="web-ops",
                       extra={"step": step, "reason": reason})
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
                flags_found += 1
                self.blackboard.add_fact(
                    ch["id"], f"FLAG#{flags_found}",
                    {"text": f"已找到第 {flags_found} 个 flag: {flag}",
                     "snippet": flag}, confidence=0.99,
                    source="llm_loop")
                # 多 flag 题：继续深挖剩余 flag，不再提前收工
        if not got_flag and seq >= 2:
            # 无产出也沉淀教训：下次同类题少走弯路（跨题记忆）
            last = ", ".join(f"{h.get('path')}={h.get('status')}"
                             for h in history[-3:]) or "无"
            self.db.put_memory(
                "lesson", f"web:{str(ch.get('title', ''))[:40]}",
                {"summary": f"{str(ch.get('title', ''))[:60]} 未解：{seq} 步探测无 flag，末态 {last}",
                 "steps": seq},
                strength=0.7,
            )
        return candidates, seq

    # ---------- ABANDON 拦截落账 ----------
    def _abandon_block(self, ch: dict, step: int, history: list, seq: int,
                       action: str, path: str, reason_text: str) -> None:
        """ABANDON 命中：写事件 + 沉淀教训 + 历史标记（强制 planner 换方向）。"""
        self.db.event("abandon.blocked", "challenge", ch["id"],
                      {"step": step, "action": action, "path": path,
                       "reason": reason_text})
        emit_event(self.db, "abandon.blocked", "challenge", ch["id"],
                   tool=f"{action.upper()} {path}", abandoned=reason_text,
                   agent_id="web-ops", extra={"step": step})
        self.db.put_memory("lesson", f"abandon:{ch['id']}:{path}",
                           {"summary": f"{reason_text}（ABANDON 停损强制换方向）"},
                           strength=0.9)
        history.append({"seq": seq + 1, "method": "ABANDON", "path": path,
                        "status": 0,
                        "snippet": f"[停损拦截] {reason_text}——强制换方向"})
        log.info("llm-step %d: ABANDON 拦截 %s %s: %s", step, action, path,
                 reason_text)

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
            result = evaluate_and_persist(self.db, fid, {**cand.evidence(),
                                                        "value": cand.value,
                                                        "source": cand.type})
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
