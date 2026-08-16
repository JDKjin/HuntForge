"""TSecBench 实盘跑分编排器。

标准跑分流程（官方 API 文档）：
  列出题目 → 启动容器（≤3 活跃）→ 渗透解题（多 flag 逐个提交）→ 关闭容器 → 下一题
复用 HuntForge 挖掘 Agent（probe/web-ops/ai-ops/binary-ops/chain-ops）与 7Q Gate，
flag 直接提交到真实平台（幂等 duplicate 保护）。
"""
from __future__ import annotations

import logging
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

from ..core.state import StateDB
from ..core.state_machine import ChallengeFSM
from ..llm.gateway import CallBudget
from ..web.sse import emit_event
from .tsec_client import (ChallengeNotFound, DuplicateSubmit, InvalidState,
                          ResourceUnavailable, TaskNotFound, TsecBenchClient,
                          TsecConnectionError, TsecError)

log = logging.getLogger("huntforge.live")

# 可打性先验：题面含未授权/S3/路径的 HTTP 题优先；f1/f2 固件几乎不可打
DIFF_PROB = {"easy": 0.20, "medium": 0.15, "hard": 0.08}

MAX_ATTEMPTS_PER_CHALLENGE = 3
# 尝试计数只看最近 ATTEMPT_WINDOW 秒内（跨任务重启后旧计数自然失效，
# 但同一次任务内的多次重启不再重置计数——run-8928 里 c-07 被开关 6 次的根因）。
ATTEMPT_WINDOW = 8 * 3600
# 同题两次尝试的最小间隔：杜绝"关掉 2 秒后重开同一题"的无效循环
# （run-8928：f1-04 四连 84s 开关循环、b-01 二十分钟内开关 5 次）。
COOLDOWN_S = 720.0
# 拉取平台 hint 前必须先无 hint 攻击这么久（hint 扣分，不能开题 1-2 分钟
# 就拉——run-9202 教训：34 题拉了 22 次提示）。
HINT_MIN_ELAPSED = 240.0


def skip_reason(ch: dict) -> str:
    """能力弃权。

    2026-08-14 实盘修正：f2 固件题不再跳过——容器首页 /download 提供 ELF，
    f2-01/02/03 均以此拿分/解出；f1 心跳/协议题保留（socket 交互打法）。
    无弃权类别时返回空串。
    """
    return ""


def expected_value(ch: dict) -> float:
    if skip_reason(ch):
        return 0.0
    score = ch.get("total_score") or 0
    desc = (ch.get("description") or "").lower()
    code = (ch.get("unique_code") or "").lower()
    bonus = 0.2 if any(k in desc for k in ("未授权", "默认口令", "s3", "path-style",
                                           "路径", "bucket", "actuator", "nacos")) else 0.0
    # 强项优先（实战验证）：e 系列（对抗规避）上轮命中率 50%，是本队得分主力；
    # d 系列（云攻击）上轮 4/6。让它们先于 b/a/c 难题轮转，避免把时间烧在
    # 打不穿的题上（2026-08-14 实战：b/a/c 烧穿 4 次尝试仍零产出）。
    if code.startswith(("e1-", "e2-", "e3-")):
        bonus += 0.25
    elif code.startswith("d-"):
        bonus += 0.15
    return score * (DIFF_PROB.get(ch.get("difficulty", ""), 0.1) + bonus)

# 每类题目的 Agent 尝试链（实盘去掉独立 probe，省 15–40s/题）
AGENT_CHAIN = {
    "web": ["web-ops"],
    "ai": ["ai-ops", "web-ops"],
    "binary": ["binary-ops"],
    "blockchain": ["chain-ops"],
}


def classify_challenge(ch: dict) -> str:
    """按 unique_code/描述判断题目类别 → agent 链。"""
    code = (ch.get("unique_code") or "").lower()
    desc = (ch.get("description") or "").lower()
    if code.startswith("f1-"):
        return "web"    # 协议题：web-ops 的 script 循环用 socket 交互逆向
    if code.startswith("f2-") or any(
            k in desc for k in ("tcp", "固件", "mcu", "嵌入式", "心跳", "内存")):
        return "binary"
    if "区块链" in desc or "合约" in desc or code.startswith(("chain", "bc-")):
        return "blockchain"
    if any(k in desc for k in ("ai", "模型", "智能", "提示词", "prompt")):
        return "ai"
    return "web"


class LiveRunner:
    def __init__(self, base_url: str, token: str, *,
                 per_challenge_timebox: float = 480.0,
                 llm_cfg: Optional[dict] = None,
                 http_timeout: float = 5.0,
                 max_active: int = 3):
        self.client = TsecBenchClient(base_url, token)
        self.per_challenge_timebox = per_challenge_timebox
        self.http_timeout = http_timeout
        self.max_active = max_active
        tmp = tempfile.mkdtemp(prefix="hf-live-")
        # 状态库默认持久化到项目目录：跨重启保留尝试计数/冷却/分数。
        # 设 HUNTFORGE_LIVE_DB 可把状态库固定到指定路径（WebUI 看板跨重启可见）。
        db_env = os.environ.get("HUNTFORGE_LIVE_DB")
        if not db_env:
            proj_db = Path(__file__).resolve().parents[2] / ".huntforge" / "live.db"
            try:
                proj_db.parent.mkdir(parents=True, exist_ok=True)
                db_env = str(proj_db)
            except OSError:
                db_env = str(Path(tmp) / "live.db")
        self.db = StateDB(db_env)
        self._llm_cfg = llm_cfg
        # 全局共享调用预算（跨并行 worker 生效）；上限只认环境变量，避免
        # settings.yaml 的 per_challenge 预算被误当全程上限。
        budget_env = os.environ.get("HUNTFORGE_LLM_CALL_BUDGET")
        self._budget = CallBudget(int(budget_env) if budget_env not in (None, "") else None)
        self.submitted: set[tuple[str, str]] = set()   # (unique_code, flag) 幂等去重
        self.scores: dict[str, int] = {}               # unique_code -> cumulative_score
        self._active: list[str] = []                   # 本 runner 启动且未关闭的题
        self._attempt_ts: dict[str, list[float]] = {}  # 每题尝试时间戳（持久化，窗口内计数）
        self._last_attempt: dict[str, float] = {}      # 每题上次尝试结束时间（冷却用）
        self._solved_locally: set[str] = set()         # 本地已提交且平台接受的题（列表滞后防护）
        self._hinted: set[str] = set()                 # 已拉过 hint 的题（每题只拉一次）
        self._inflight: set[str] = set()               # 正在被 worker 攻击的题
        self._net_fails = 0                             # 连续网络失败计数（防脆死）
        # 跨重启保留每题尝试时间戳（状态库持久化）；只统计 ATTEMPT_WINDOW 内的，
        # 旧任务的历史计数不阻塞新任务（平台每轮任务会重置题目进度）。
        for m in self.db.get_memory("live_attempts"):
            try:
                v = m.get("value") or {}
                tss = [float(t) for t in (v.get("tss") or [])][-10:]
                if tss and any(time.time() - t < ATTEMPT_WINDOW for t in tss):
                    self._attempt_ts[m["key"]] = tss
            except Exception:  # noqa: BLE001
                pass
        for m in self.db.get_memory("live_cooldown"):
            try:
                ts = float((m.get("value") or {}).get("ts") or 0)
                if ts > 0:
                    self._last_attempt[m["key"]] = ts
            except Exception:  # noqa: BLE001
                pass
        for m in self.db.get_memory("live_solved"):
            try:
                if (m.get("value") or {}).get("solved"):
                    self._solved_locally.add(m["key"])
            except Exception:  # noqa: BLE001
                pass
        self._active_lock = threading.Lock()
        self._inflight_lock = threading.Lock()
        self._submit_lock = threading.Lock()
        self._stop = threading.Event()

    def _make_planner(self, code: str):
        """每 agent 独立 planner/gateway：共享全局预算，task_id 按题目稳定归属。"""
        if not self._llm_cfg:
            return None
        try:
            from ..llm.gateway import ModelGateway
            from ..llm.planner import PentestPlanner
            gw = ModelGateway(self._llm_cfg, db=self.db, budget=self._budget,
                              task_id=abs(hash(code)) & 0x7FFFFFFF)
            if gw.supports("fast"):
                return PentestPlanner(gw)
        except Exception as exc:  # noqa: BLE001
            log.info("planner unavailable, rules only: %s", exc)
        return None

    # ---------------- 主循环：3 容器并行 LLM 深攻 ----------------
    # 双轨制（实盘第 3 轮教训）：EV 排序会让尾部 easy 题在时限内排不上队，
    # 而 easy 题（S3/云函数/AI 应用）才是 flash 模型现实的得分区。
    # 2 worker 打最高期望值题，1 worker 专跑 easy 快速通道（时间盒更短，覆盖更多题）。
    EASY_LANE_TIMEOUT = 300.0

    def run(self, max_total_time: Optional[float] = None,
            max_challenges: Optional[int] = None) -> dict:
        deadline = time.time() + max_total_time if max_total_time else None
        limit = max_challenges or 0
        self._stop.clear()
        done = {"n": 0}
        roles = ["top", "top", "easy"]

        def work(role: str) -> None:
            while True:
                if self._stop.is_set():
                    return
                if deadline is not None and time.time() > deadline:
                    return
                if limit and done["n"] >= limit:
                    return
                code: Optional[str] = None
                try:
                    challenges = self.client.list_challenges()
                    ch = self._select(challenges, role=role)
                    if ch is None:
                        return
                    code = ch["unique_code"]
                    with self._inflight_lock:
                        done["n"] += 1
                    timebox = (self.EASY_LANE_TIMEOUT if role == "easy"
                               else self.per_challenge_timebox)
                    self._solve_one(ch, deadline, timebox, True)
                except InvalidState as exc:
                    if exc.max_active:
                        # 名额满：等待别人释放，绝不强关他人正在攻击的容器
                        # （run-8928 教训：强关导致 worker 互相打断 → 开关题刷屏）
                        if self._wait_for_slot(deadline):
                            continue
                        log.info("等待名额超时，稍后重试")
                        continue
                    log.info("任务已结束（invalid_state: %s），停止", exc.message)
                    self._stop.set()
                    return
                except TaskNotFound as exc:
                    log.error("任务不存在，停止: %s", exc)
                    self._stop.set()
                    return
                except TsecConnectionError as exc:
                    # 实盘教训：瞬时网络抖动（代理连接失败/端口耗尽）不该杀死
                    # 整个跑分——指数退避重试，连续 5 次才停。
                    self._net_fails += 1
                    if self._net_fails >= 5:
                        log.error("网络连续失败 %d 次，停止: %s",
                                  self._net_fails, exc)
                        self._stop.set()
                        return
                    wait = min(60, 5 * (2 ** min(self._net_fails, 4)))
                    log.warning("网络错误（第 %d 次），%ds 后重试: %s",
                                self._net_fails, wait, exc)
                    time.sleep(wait)
                    continue
                except TsecError as exc:
                    self._net_fails = 0
                    log.warning("题目 %s 处理出错: %s", code, exc)
                except Exception as exc:  # noqa: BLE001 - 单题异常不杀死整个跑分
                    self._net_fails = 0
                    log.exception("题目 %s 未知异常: %s", code, exc)
                finally:
                    if code is not None:
                        with self._inflight_lock:
                            self._inflight.discard(code)

        workers = max(1, min(3, self.max_active))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="hf-live") as pool:
            futures = [pool.submit(work, roles[i]) for i in range(workers)]
            for f in futures:
                f.result()
        return self._summary(self.client.list_challenges())

    def _select(self, challenges: list[dict], role: str = "top") -> Optional[dict]:
        """在待打题目中挑一道并标记 in-flight（线程安全）。

        role=top：按期望值取最高；role=easy：只打 easy 题（按分值），
        easy 打完后并入 top 池。
        冷却机制：刚打完（含刚失败的）的题 COOLDOWN_S 秒内不再选，
        优先把时间摊到没打过的题上；全部在冷却时才重打最久前的那道。
        """
        now = time.time()
        with self._inflight_lock:
            pending = [c for c in challenges
                       if not c.get("is_completed")
                       and not skip_reason(c)
                       and c["unique_code"] not in self._solved_locally
                       and c["unique_code"] not in self._inflight
                       and self._recent_attempts(c["unique_code"])
                       < MAX_ATTEMPTS_PER_CHALLENGE]
            if not pending:
                return None
            fresh = [c for c in pending
                     if now - self._last_attempt.get(c["unique_code"], 0)
                     >= COOLDOWN_S]
            pool_c = fresh or pending
            if role == "easy":
                easy = [c for c in pool_c if c.get("difficulty") == "easy"]
                pool_c = easy or pool_c
                order = sorted(pool_c, key=lambda c: -(c.get("total_score") or 0))
            else:
                order = sorted(pool_c, key=lambda c: -expected_value(c))
            for c in order:
                code = c["unique_code"]
                if code in self._inflight:
                    continue
                self._inflight.add(code)
                tss = self._attempt_ts.setdefault(code, [])
                tss.append(now)
                self._attempt_ts[code] = tss[-10:]
                self.db.put_memory("live_attempts", code,
                                   {"tss": self._attempt_ts[code]}, strength=1.0)
                return c
            return None

    def _recent_attempts(self, code: str) -> int:
        """最近 ATTEMPT_WINDOW 秒内的尝试次数（跨重启持久化）。"""
        now = time.time()
        return sum(1 for t in self._attempt_ts.get(code, [])
                   if now - t < ATTEMPT_WINDOW)

    def _add_active(self, code: str) -> None:
        with self._active_lock:
            self._active.append(code)

    def _remove_active(self, code: str) -> None:
        with self._active_lock:
            if code in self._active:
                self._active.remove(code)

    def _summary(self, challenges: list[dict]) -> dict:
        """只报事实计数（平台分数为准，本地估算已按需求移除）。"""
        completed = sum(1 for c in challenges if c.get("is_completed"))
        partial = sum(1 for c in challenges if c.get("correct_flag_count", 0) > 0
                      and not c.get("is_completed"))
        return {"total": len(challenges), "completed": completed,
                "partial": partial}

    # ---------------- 单题流程 ----------------
    def _solve_one(self, ch: dict, deadline: Optional[float],
                   per_challenge: float, use_llm: bool) -> bool:
        code = ch["unique_code"]
        why = skip_reason(ch)
        if why:
            log.info("======== 跳过 %s (%s) ========", code, why)
            return False
        log.info("======== 开始 %s (difficulty=%s score=%s flags=%s) ========",
                 code, ch.get("difficulty"), ch.get("total_score"), ch.get("flag_count"))

        # 1) 启动容器（处理 max-active / 资源未就绪）
        started = self._start_with_retry(code)

        try:
            # 2) 等待容器就绪：start 返回地址 ≠ 服务已可访问，
            #    必须等 container_status == available，否则刚启动就被探测误判
            addrs = self._wait_available(code, deadline)
            if not addrs:
                log.warning("%s: 容器未就绪，放弃", code)
                return False
            log.info("%s: container ready at %s", code, addrs)
            emit_event(self.db, "live.container_ready", "challenge", code,
                       tool="platform.start", agent_id="live-runner",
                       result={"addrs": addrs})

            # 3) 解题
            targets = [f"http://{a}" for a in addrs]
            self._attack(code, ch, targets, deadline, per_challenge, use_llm)

            # 4) 校验进度
            for c in self.client.list_challenges():
                if c["unique_code"] == code:
                    self.scores[code] = c.get("cumulative_score") or self.scores.get(code, 0)
                    if bool(c.get("is_completed")):
                        ChallengeFSM(self.db).mark_solved(code,
                                                          note="平台确认通关")
                        self.db.set_challenge_status(code, "solved")
                        # 列表条目没有 cumulative_score 字段：按 total_score
                        # × 正确 flag 占比折算（与 _summary 同口径）。
                        n_ok = int(c.get("correct_flag_count") or 0)
                        n_all = int(c.get("flag_count") or 1) or 1
                        piece = int(round((c.get("total_score") or 0) * n_ok / n_all))
                        self.db.put_memory("platform", f"platform:{code}",
                                           {"score": piece,
                                            "correct": n_ok,
                                            "total": n_all},
                                           strength=1.0)
                    return bool(c.get("is_completed"))
            return False
        finally:
            # 5) 关闭容器释放名额 + 记录冷却（防止同题刚关 2 秒又被重开）
            now = time.time()
            self._last_attempt[code] = now
            self.db.put_memory("live_cooldown", code, {"ts": now}, strength=1.0)
            try:
                self.client.close(code)
                self._remove_active(code)
                emit_event(self.db, "live.container_closed", "challenge", code,
                           tool="platform.close", agent_id="live-runner")
            except TsecError as exc:
                log.warning("%s: close 失败: %s", code, exc)

    def _start_with_retry(self, code: str, attempts: int = 4) -> dict:
        for i in range(attempts):
            try:
                result = self.client.start(code)
                self._add_active(code)
                return result
            except InvalidState as exc:
                if exc.max_active:
                    # 名额满：等别人释放，不杀他人容器
                    if self._wait_for_slot(None, max_wait=90.0):
                        continue
                    raise
                raise
            except ResourceUnavailable:
                log.info("%s: 资源未就绪，%ds 后重试 (%d/%d)", code, 6 * (i + 1), i + 1, attempts)
                time.sleep(6 * (i + 1))
        raise TsecError("resource_unavailable", f"{code} 多次启动失败")

    def _wait_for_slot(self, deadline: Optional[float],
                       max_wait: float = 120.0) -> bool:
        """max_active 撞墙时轮询等待名额释放，绝不强关他人正在攻击的容器。

        run-8928 教训：强关他人容器 → worker 互相打断 → 开关题刷屏
        （9:59:19-25 六连关/开）。现在只等：别人打完自然释放名额。
        """
        t0 = time.time()
        while time.time() - t0 < max_wait:
            if deadline is not None and time.time() > deadline:
                return False
            try:
                active = [c for c in self.client.list_challenges()
                          if c.get("container_status") not in ("stopped", None)]
            except TsecError:
                active = []
            if len(active) < self.max_active:
                return True
            time.sleep(5)
        return False

    def _wait_available(self, code: str, deadline: Optional[float],
                        max_wait: float = 120.0) -> list[str]:
        t0 = time.time()
        while time.time() - t0 < max_wait:
            if deadline is not None and time.time() > deadline:
                return []
            for c in self.client.list_challenges():
                if c["unique_code"] == code and c.get("container_status") == "available":
                    return c.get("container_addr") or []
            time.sleep(3)
        return []

    # ---------------- 攻击执行 ----------------
    KNOWN_WEB_PORTS = {"80", "443", "3000", "5000", "8000", "8080", "8081",
                       "8443", "7860", "8888", "9000", "9001"}

    def _pick_target(self, targets: list[str]) -> Optional[str]:
        """多个 container_addr 里挑第一个讲 HTTP 的（含 https 变体）。

        实盘第 11 轮教训：容器刚 available 时服务可能仍在启动（Gradio 7860 /
        HTTPS 8443 被误判非 HTTP 丢给 TCP 工具，必零分）。现在：
        - 探测升级为 5 轮 + 12s 等待重试一轮
        - 已知 Web 端口兜底：探测失败也按 HTTP 处理（web-ops 自己会等待/重试）
        """
        for addr in targets:
            http = f"http://{addr}" if "://" not in addr else addr
            if self._speaks_http(http, attempts=5):
                return http
            time.sleep(12)   # 服务冷启动等待
            if self._speaks_http(http, attempts=3):
                return http
        # 兜底：已知 Web 端口即使探测失败也走 HTTP 流水线
        for addr in targets:
            port = addr.rsplit(":", 1)[-1]
            if port in self.KNOWN_WEB_PORTS:
                return f"http://{addr}" if "://" not in addr else addr
        return None

    def _attack(self, code: str, ch: dict, targets: list[str],
                deadline: Optional[float], per_challenge: float,
                use_llm: bool) -> None:
        if code.startswith("f1-"):
            # f1 协议题直达 TCP 流：跳过 _speaks_http 探测（每轮白烧 ~60s，
            # run-8928 的 f1-04 四连 84s 开关循环一半时间耗在这），
            # target 用 tcp:// 交给 web-ops 的 script 循环做 socket 交互，
            # 并打满时间盒（老 _attack_non_http 只跑一次 tcp_probe 就关容器）。
            host_port = targets[0].split("://", 1)[-1]
            self._attack_tcp(code, ch, f"tcp://{host_port}", deadline,
                             per_challenge, use_llm)
            return
        if code.startswith("f2-"):
            # f2 固件/RE 题：容器首页挂 /download 下发 ELF（实盘 f2-01/02/03
            # 均走此路拿分/解出），直接交给 binary-ops 下载分析并打满时间盒。
            base = targets[0]
            dl = (f"{base.rstrip('/')}/download" if base.startswith("http")
                  else f"http://{base}/download")
            self._attack_binary_dl(code, ch, dl, deadline, per_challenge, use_llm)
            return
        chain = AGENT_CHAIN.get(classify_challenge(ch), ["probe", "web-ops"])
        target = self._pick_target(targets)
        if target is None:
            host_port = targets[0].split("://", 1)[-1]
            self._attack_tcp(code, ch, f"tcp://{host_port}", deadline,
                             per_challenge, use_llm)
            return
        started_at = time.time()
        budget = per_challenge
        flag_count = ch.get("flag_count") or 1
        # 单 flag 题预留 hint 预算（否则 chain 把时间吃光，hint 轮永远轮不到）
        hint_budget = 90.0 if flag_count <= 1 and budget >= 240 else 0.0
        chain_budget = budget - hint_budget
        for agent_type in chain:
            if deadline is not None and time.time() > deadline:
                break
            if self._is_completed(code):
                break
            remaining = chain_budget - (time.time() - started_at)
            if remaining < 20:
                break
            # ai-ops 找不到对话端点时别耗光预算，最多 40s 然后回退 web-ops
            tb = min(remaining, 40.0) if agent_type == "ai-ops" else remaining
            agent = self._make_agent(agent_type, code, ch, target, tb,
                                     flag_count, use_llm)
            if agent is None:
                continue
            try:
                result = agent.run({"id": 0, "challenge_id": code, "agent_type": agent_type})
                log.info("%s: %s -> outcome=%s", code, agent_type, result.get("outcome"))
            except Exception as exc:  # noqa: BLE001 - 单题失败不影响全局
                log.exception("%s: %s 异常: %s", code, agent_type, exc)

        # 单 flag 题卡住 → 先无 hint 再攻满 HINT_MIN_ELAPSED 秒，真卡住才拉
        # hint 换方向（每题只拉一次；hint 扣分，不能开题 1-2 分钟就拉——
        # run-9202 教训：22 次提示几乎每题都拉，白白扣分）。
        if flag_count <= 1 and not self._is_completed(code):
            if deadline is not None and time.time() > deadline:
                return
            hint = None
            hint_due = False
            while True:
                if deadline is not None and time.time() > deadline:
                    break
                remaining = budget - (time.time() - started_at)
                if remaining < 60 or self._is_completed(code):
                    break
                elapsed = time.time() - started_at
                if not hint_due and elapsed >= HINT_MIN_ELAPSED:
                    hint_due = True
                    with self._inflight_lock:
                        first_time = code not in self._hinted
                        if first_time:
                            self._hinted.add(code)
                    if first_time:
                        try:
                            hint = self.client.hint(code)
                        except TsecError as exc:
                            log.info("%s: hint 获取失败: %s", code, exc)
                        if hint:
                            emit_event(self.db, "live.hint_used", "challenge",
                                       code, tool="platform.hint",
                                       agent_id="live-runner",
                                       result={"hint": str(hint)[:120]})
                tb = min(remaining, deadline - time.time()) if deadline else remaining
                if tb < 30:
                    break
                label = "hint 轮" if hint else "再攻"
                log.info("%s: %s（剩 %ss）", code, label, int(tb))
                agent = self._make_agent("web-ops", code, ch, target, tb,
                                         flag_count, use_llm,
                                         hint_text=(str(hint)[:400] if hint else ""))
                try:
                    result = agent.run({"id": 1, "challenge_id": code,
                                        "agent_type": "web-ops"})
                    log.info("%s: %s -> outcome=%s", code, label, result.get("outcome"))
                    # 防死循环：fsm 误标 solved（提交过但平台未确认）时
                    # agent 会秒回 already_solved，循环将每秒空转刷屏。
                    if result.get("outcome") == "already_solved":
                        break
                except Exception as exc:  # noqa: BLE001
                    log.exception("%s: %s 异常: %s", code, label, exc)
                hint = None   # hint 只注入拉取后的首轮

        # 多 flag 题：链跑完仍未通关 → 循环再攻直到时间盒打满
        # （LLM 循环非确定性，深打多轮比浅试一轮更可能出剩余 flag；
        #   同时避免每 attempt 只打 1-2 分钟就 close 导致面板开/关刷屏）。
        if flag_count > 1 and not self._is_completed(code):
            while True:
                if deadline is not None and time.time() > deadline:
                    return
                remaining = budget - (time.time() - started_at)
                if remaining < 60 or self._is_completed(code):
                    return
                tb = min(remaining, deadline - time.time()) if deadline else remaining
                if tb < 30:
                    return
                log.info("%s: 多 flag 题未通关，剩 %ss，再攻一轮", code, int(tb))
                agent = self._make_agent("web-ops", code, ch, target, tb,
                                         flag_count, use_llm)
                try:
                    result = agent.run({"id": 1, "challenge_id": code,
                                        "agent_type": "web-ops"})
                    log.info("%s: 再攻 -> outcome=%s", code, result.get("outcome"))
                    if result.get("outcome") == "already_solved":
                        return   # 防死循环（fsm 误标 solved 场景）
                except Exception as exc:  # noqa: BLE001
                    log.exception("%s: 再攻异常: %s", code, exc)

    def _speaks_http(self, target: str, attempts: int = 3) -> bool:
        """判定目标是否讲 HTTP。http 不通再试 https（如 8443 的 TLS 服务）。

        容器刚就绪时服务可能仍慢，探测失败会退避重试。
        """
        import requests
        schemes = ["http", "https"] if target.startswith("http://") else ["http", "https"]
        base = target.split("://", 1)[-1]
        for scheme in schemes:
            for attempt in range(max(1, attempts)):
                try:
                    requests.get(f"{scheme}://{base}/", timeout=8,
                                 verify=False, allow_redirects=False)
                    return True   # 收到 HTTP 响应（任意状态码）即算
                except requests.RequestException:
                    if attempt < attempts - 1:
                        time.sleep(4)
        return False

    def _attack_tcp(self, code: str, ch: dict, target: str,
                    deadline: Optional[float], per_challenge: float,
                    use_llm: bool) -> None:
        """TCP 协议靶场：快速工具侦察一次，然后打满时间盒交给
        web-ops 的 script 循环做 socket 协议交互（LLM 现场逆向）。

        run-8928 教训：老实现只跑一次 tcp_probe（~30s）就关容器，
        f1-04 因此四连 84s 无效开关循环。现在容器生命周期用满。
        """
        from ..tools import call_tool
        started_at = time.time()
        budget = per_challenge
        host, _, port = target.replace("tcp://", "").partition(":")
        port = int(port or 23)
        desc = (ch.get("description") or "").lower()
        tool = ("telnet_login" if port == 23 or "telnet" in desc or "远程登录" in desc
                else "tcp_probe")
        try:
            result = call_tool(tool, host=host, port=port, timeout=min(30, budget))
            flags = result.get("flags") or []
            if flags:
                log.info("%s: 工具提取到 %d 个 flag 候选", code, len(flags))
                for flag in flags:
                    self._submit_flag(code, flag)
            else:
                log.info("%s: %s 无 flag（error=%s）→ 转 LLM socket 深攻",
                         code, tool, result.get("error", "无"))
        except Exception as exc:  # noqa: BLE001
            log.warning("%s: %s 失败: %s", code, tool, exc)
        while True:
            if deadline is not None and time.time() > deadline:
                return
            remaining = budget - (time.time() - started_at)
            if remaining < 60 or self._is_completed(code):
                return
            tb = min(remaining, deadline - time.time()) if deadline else remaining
            if tb < 30:
                return
            agent = self._make_agent("web-ops", code, ch, target, tb,
                                     ch.get("flag_count") or 1, use_llm,
                                     tcp=True)
            if agent is None:
                return
            try:
                res = agent.run({"id": 2, "challenge_id": code,
                                 "agent_type": "web-ops"})
                log.info("%s: tcp 轮 -> outcome=%s", code, res.get("outcome"))
                if res.get("outcome") == "already_solved":
                    return
            except Exception as exc:  # noqa: BLE001
                log.exception("%s: tcp 轮异常: %s", code, exc)

    def _attack_binary_dl(self, code: str, ch: dict, target: str,
                          deadline: Optional[float], per_challenge: float,
                          use_llm: bool) -> None:
        """f2 固件题：binary-ops 下载 /download 的 ELF 做静态分析 +
        LLM 审计，打满时间盒（多轮重试，LLM 每轮非确定性）。"""
        started_at = time.time()
        budget = per_challenge
        while True:
            if deadline is not None and time.time() > deadline:
                return
            remaining = budget - (time.time() - started_at)
            if remaining < 60 or self._is_completed(code):
                return
            tb = min(remaining, deadline - time.time()) if deadline else remaining
            if tb < 30:
                return
            agent = self._make_agent("binary-ops", code, ch, target, tb,
                                     ch.get("flag_count") or 1, use_llm)
            if agent is None:
                return
            try:
                res = agent.run({"id": 3, "challenge_id": code,
                                 "agent_type": "binary-ops"})
                log.info("%s: binary 轮 -> outcome=%s", code, res.get("outcome"))
                if res.get("outcome") == "already_solved":
                    return
                # 无产出轮之间稍作间隔，避免同一静态结论空转刷屏
                time.sleep(5)
            except Exception as exc:  # noqa: BLE001
                log.exception("%s: binary 轮异常: %s", code, exc)

    def _is_completed(self, code: str) -> bool:
        for c in self.client.list_challenges():
            if c["unique_code"] == code:
                return bool(c.get("is_completed"))
        return False

    def _make_agent(self, agent_type: str, code: str, ch: dict, target: str,
                    timebox: float, flag_count: int, use_llm: bool = True,
                    hint_text: Optional[str] = None, tcp: bool = False):
        from ..agents.ai_ops import AIOpsAgent
        from ..agents.binary_ops import BinaryOpsAgent
        from ..agents.blockchain_ops import BlockchainOpsAgent
        from ..agents.probe import ProbeAgent
        from ..agents.web_ops import WebOpsAgent

        # 题面是免费情报：description 全文进 title（planner 的 brief），
        # hint 轮把平台提示追加进去。
        title = ch.get("description") or code
        if hint_text:
            title = f"{title}\n[平台提示] {hint_text}"
        self.db.upsert_challenge({
            "id": code, "title": title,
            "category": ch.get("difficulty", "web"), "difficulty": ch.get("difficulty", "medium"),
            "target": target,
            "meta": {"flag_count": int(ch.get("flag_count") or 1),
                     "total_score": ch.get("total_score") or 0},
        })
        submitter = self._make_submitter(code)
        # 每 agent 独立 planner：共享全局预算，task_id 按题目归属
        planner = self._make_planner(code) if use_llm else None
        kwargs = dict(db=self.db, timebox=timebox, submitter=submitter,
                      planner=planner)
        if agent_type == "probe":
            return ProbeAgent(self.db, http_timeout=self.http_timeout,
                              timebox=timebox, submitter=submitter)
        if agent_type == "web-ops":
            return WebOpsAgent(self.db, http_timeout=self.http_timeout,
                               timebox=timebox, submitter=submitter,
                               planner=planner,
                               stop_after_flag=(flag_count <= 1),
                               # HTTP：规则只做 30s recon，LLM 8 步跟进题面线索
                               # TCP（f1 协议题）：规则对 tcp:// 目标无意义，
                               # LLM script 循环直接接管 socket 交互。
                               llm_first=tcp, max_llm_steps=8, min_llm_time=20,
                               rules_max_seconds=(0.0 if tcp else 30.0))
        if agent_type == "ai-ops":
            return AIOpsAgent(**kwargs)
        if agent_type == "binary-ops":
            return BinaryOpsAgent(**kwargs)
        if agent_type == "chain-ops":
            return BlockchainOpsAgent(**kwargs)
        return None

    def _make_submitter(self, code: str):
        def submit(_cid: str, flag: str) -> None:
            self._submit_flag(code, flag)
        return submit

    def _submit_flag(self, code: str, flag: str) -> None:
        flag = (flag or "").strip()
        if not flag:
            return
        key = (code, flag)
        with self._submit_lock:
            if key in self.submitted:
                return
            self.submitted.add(key)
        try:
            res = self.client.submit(code, flag)
        except DuplicateSubmit:
            log.info("%s: flag 已提交过（duplicate），跳过", code)
            return
        except TsecError as exc:
            log.warning("%s: 提交失败 %s", code, exc)
            return
        if res.get("correct"):
            self._solved_locally.add(code)
            self.db.put_memory("live_solved", code, {"solved": True}, strength=1.0)
            if not res.get("duplicate"):
                log.info("FLAG ACCEPTED %s +%s (累计 %s, 进度 %s/%s)",
                         code, res.get("awarded"), res.get("cumulative_score"),
                         res.get("correct_flag_count"), res.get("total_flag_count"))
                emit_event(self.db, "live.flag_accepted", "challenge", code,
                           tool="platform.submit", agent_id="live-runner",
                           result={"awarded": res.get("awarded"),
                                   "cumulative_score": res.get("cumulative_score"),
                                   "progress": f"{res.get('correct_flag_count')}/{res.get('total_flag_count')}"})
            self.scores[code] = res.get("cumulative_score") or self.scores.get(code, 0)
            # 持久化平台进度 → 看板实时总分（key 加前缀，避免与 live_attempts 撞 key）
            self.db.put_memory("platform", f"platform:{code}",
                               {"score": res.get("cumulative_score") or 0,
                                "correct": res.get("correct_flag_count") or 0,
                                "total": res.get("total_flag_count") or 0},
                               strength=1.0)
        else:
            log.info("%s: flag rejected (awarded=0)", code)
            emit_event(self.db, "live.flag_rejected", "challenge", code,
                       tool="platform.submit", agent_id="live-runner",
                       result={"awarded": 0})
            # 大小写回退：平台标准答案大小写不统一（实盘 f2-01 大写 FLAG{，
            # f2-02/03 解出值被判错）。仅翻转前缀，最多一次额外提交。
            variant = _case_variant(flag)
            if variant and (code, variant) not in self.submitted:
                log.info("%s: 前缀大小写变体重试: %s", code, variant)
                self._submit_flag(code, variant)


def _case_variant(flag: str) -> str:
    """flag{ ↔ FLAG{ 前缀翻转（body 保持原样）。"""
    if flag.startswith("flag{"):
        return "FLAG{" + flag[5:]
    if flag.startswith("FLAG{"):
        return "flag{" + flag[5:]
    return ""
