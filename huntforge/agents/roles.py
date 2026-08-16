"""五角色 Agent（借鉴 ctfSolver 的 Agent 集群：Explorer/Scanner/Solver/Executor/Actioner）。

每个角色是现有能力的角色化封装：统一 RoleResult、真实事件流（每次角色动作都
对应一次真实系统调用/网络请求，emit 进 SSE）、时间盒。

- Explorer：页面探索——路径枚举 + 指纹，产出 Fact 与 Intent。
- Scanner：漏洞扫描——规则检查（unauth/sqli/lfi/ssrf/rce）。
- Solver：解题核心——驱动 planner 产出并执行一步 get/post/flag。
- Executor：命令执行——受限沙箱跑 LLM 生成的脚本。
- Actioner：动作执行——表单提交/登录/会话跟随（漏洞链）。

依赖注入设计：HTTP/脚本/planner 等执行体由调用方（web_ops）经 ctx 传入，
角色层只做编排与记账，避免与执行层循环导入。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..core.blackboard import record_probe_fact
from ..web.common import Candidate, body_of, extract_flag, get, post
from ..web.sse import emit_event


@dataclass
class RoleResult:
    role: str
    ok: bool
    outcome: str = ""
    payload: dict = field(default_factory=dict)
    candidates: list = field(default_factory=list)
    duration_ms: float = 0.0


class BaseRole:
    """统一基类：事件流 + 时间盒 + 结构化结果。"""

    name = "base"
    state = "exploring"   # 该角色对应的 FSM 状态

    def __init__(self, db, http_timeout: float = 8.0,
                 time_left: Optional[Callable[[], float]] = None):
        self.db = db
        self.http_timeout = http_timeout
        self._time_left = time_left or (lambda: 1e9)

    def time_left(self) -> float:
        return self._time_left()

    def _emit(self, challenge_id: str, outcome: str, *, ok: bool = True,
              params=None, result=None, duration_ms: float = 0.0) -> None:
        emit_event(self.db, "role.action", "challenge", challenge_id,
                   agent_id=self.name, tool=self.name, params=params,
                   result=result, duration_ms=duration_ms,
                   extra={"ok": ok, "outcome": outcome})

    def run(self, challenge_id: str, ctx: dict) -> RoleResult:  # pragma: no cover
        raise NotImplementedError


class ExplorerRole(BaseRole):
    """页面探索：枚举 ctx["paths"]，产出 Fact + 未探测路径 Intent。"""

    name = "explorer"
    state = "exploring"

    def run(self, challenge_id: str, ctx: dict) -> RoleResult:
        base = ctx["base"].rstrip("/")
        paths = ctx.get("paths") or ["/"]
        facts: list[dict] = []
        checked = 0
        for path in paths:
            if self.time_left() <= 0:
                break
            started = time.time()
            resp = get(base + path, self.http_timeout)
            body = body_of(resp)
            status = resp.status_code if resp is not None else 0
            checked += 1
            key = record_probe_fact(
                ctx.get("blackboard"), challenge_id, "GET", path, status,
                body[:400], status in (200, 301, 302), source=self.name)
            facts.append({"key": key, "path": path, "status": status})
            self._emit(challenge_id, "probed", ok=(status in (200, 301, 302)),
                       params={"path": path}, result={"status": status,
                                                      "len": len(body)},
                       duration_ms=(time.time() - started) * 1000)
        return RoleResult(self.name, True, "explored",
                          {"checked": checked, "facts": facts})


class ScannerRole(BaseRole):
    """漏洞扫描：执行 ctx["check"] 指定的规则检查。"""

    name = "scanner"
    state = "scanning"

    def run(self, challenge_id: str, ctx: dict) -> RoleResult:
        check_name = ctx["check"]
        from ..web import checks
        fn = checks.CHECKS.get(check_name)
        if not fn:
            return RoleResult(self.name, False, "unknown_check")
        started = time.time()
        found = fn(ctx)
        ms = (time.time() - started) * 1000
        self._emit(challenge_id, f"{check_name} -> {len(found)} candidates",
                   params={"check": check_name},
                   result={"candidates": len(found),
                           "flags": sum(1 for c in found if c.value)},
                   duration_ms=ms)
        return RoleResult(self.name, True, "scanned",
                          {"check": check_name, "n": len(found)}, found)


class SolverRole(BaseRole):
    """解题核心：驱动 planner 产出一轮决策，并执行 get/post/flag 动作。

    ctx 需带 planner 与 execute（执行 get/post 的回调）；script 动作交 Executor。
    """

    name = "solver"
    state = "exploiting"

    def run(self, challenge_id: str, ctx: dict) -> RoleResult:
        planner = ctx.get("planner")
        if not planner:
            return RoleResult(self.name, False, "no_planner")
        decision = planner.decide_next_step(
            ctx["base"], ctx.get("history", []), ctx.get("hints"),
            brief=ctx.get("brief", ""), lessons=ctx.get("lessons"),
            facts=ctx.get("facts"), state=ctx.get("state", ""))
        if not decision:
            return RoleResult(self.name, False, "no_decision")
        action = decision.get("next_action", "stop")
        self._emit(challenge_id, f"decide:{action}",
                   params={"path": decision.get("path"),
                           "reason": str(decision.get("reason", ""))[:100]})
        if action == "flag":
            value = extract_flag(str(decision.get("flag_candidate") or ""))
            if value:
                return RoleResult(self.name, True, "flag_found",
                                  {"value": value}, [])
            return RoleResult(self.name, False, "flag_without_candidate")
        if action in ("get", "post"):
            executor = ctx.get("execute")
            if not executor:
                return RoleResult(self.name, False, "no_executor")
            ok, cand = executor(decision)
            return RoleResult(self.name, True,
                              "flag_found" if cand and cand.value else "executed",
                              {"action": action, "path": decision.get("path")},
                              [cand] if cand else [])
        return RoleResult(self.name, False, f"unhandled:{action}")


class ExecutorRole(BaseRole):
    """命令执行：受限沙箱跑 LLM 脚本（run_script 回调由 web_ops 注入）。"""

    name = "executor"
    state = "exploiting"

    def run(self, challenge_id: str, ctx: dict) -> RoleResult:
        code = ctx.get("script") or ""
        run_script = ctx.get("run_script")
        if not code or not run_script:
            return RoleResult(self.name, False, "no_script")
        started = time.time()
        out = run_script(code, ctx["base"], brief=ctx.get("brief", ""))
        ms = (time.time() - started) * 1000
        flag = extract_flag(out)
        self._emit(challenge_id, "script_executed",
                   params={"script_head": code[:200]},
                   result={"out_len": len(out), "flag": bool(flag)},
                   duration_ms=ms)
        cand = None
        if flag:
            cand = Candidate(type="llm_script", url=ctx["base"],
                             request="LLM script", response=out[:400],
                             impact="Executor 沙箱脚本发现 flag",
                             confidence=0.95, value=flag,
                             confirm={"note": "Executor 脚本执行命中"})
        return RoleResult(self.name, True,
                          "flag_found" if flag else "executed",
                          {"out_len": len(out)}, [cand] if cand else [])


class ActionerRole(BaseRole):
    """动作执行：表单提交 / 登录尝试 / 会话跟随（漏洞链最后一棒）。"""

    name = "actioner"
    state = "exploiting"

    def run(self, challenge_id: str, ctx: dict) -> RoleResult:
        base = ctx["base"].rstrip("/")
        form_path = ctx.get("form_path") or "/login"
        form_data = ctx.get("form_data") or {}
        started = time.time()
        resp = post(base + form_path, self.http_timeout, data=form_data)
        ms = (time.time() - started) * 1000
        if resp is None:
            self._emit(challenge_id, "form_failed",
                       params={"path": form_path}, duration_ms=ms, ok=False)
            return RoleResult(self.name, False, "no_response")
        body = body_of(resp)
        flag = extract_flag(body)
        cand = None
        if flag:
            cand = Candidate(type="actioner_form", url=base + form_path,
                             request=f"POST {form_path}",
                             response=body[:400],
                             impact="表单动作直接泄露 flag",
                             confidence=0.95, value=flag,
                             confirm={"note": "Actioner 表单提交命中"})
        self._emit(challenge_id, "form_submitted",
                   params={"path": form_path, "keys": list(form_data)},
                   result={"status": resp.status_code, "flag": bool(flag)},
                   duration_ms=ms)
        return RoleResult(self.name, True,
                          "flag_found" if flag else "executed",
                          {"status": resp.status_code}, [cand] if cand else [])


class KaliScanRole(BaseRole):
    """Kali 工具链侦察（ctfSolver Scanner 工具化的落地）：
    katana 爬端点 + ffuf 目录爆破 + nuclei 指纹，产出直接喂黑板。"""

    name = "kali-scan"
    state = "scanning"

    def run(self, challenge_id: str, ctx: dict) -> RoleResult:
        from ..tools import kali
        if not kali.available():
            return RoleResult(self.name, False, "kali_unavailable")
        base = ctx["base"]
        budget = min(float(ctx.get("budget", 90)), max(self.time_left(), 5))
        started = time.time()
        res = kali.scan_suite(base, budget=budget)
        ms = (time.time() - started) * 1000
        self._emit(challenge_id, "suite",
                   params={"base": base, "tools": res.get("tools_ran", [])},
                   result={"endpoints": len(res.get("endpoints", [])),
                           "dirs": len(res.get("dirs", [])),
                           "tech": len(res.get("tech", []))},
                   duration_ms=ms)
        return RoleResult(self.name, True, "scanned",
                          {"endpoints": res.get("endpoints", []),
                           "dirs": res.get("dirs", []),
                           "tech": res.get("tech", [])})


ROLE_REGISTRY = {
    "explorer": ExplorerRole,
    "scanner": ScannerRole,
    "solver": SolverRole,
    "executor": ExecutorRole,
    "actioner": ActionerRole,
    "kali-scan": KaliScanRole,
}


def make_role(name: str, db, http_timeout: float = 8.0,
              time_left: Optional[Callable[[], float]] = None) -> Optional[BaseRole]:
    cls = ROLE_REGISTRY.get(name)
    return cls(db, http_timeout=http_timeout, time_left=time_left) if cls else None
