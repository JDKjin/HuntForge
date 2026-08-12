"""TSecBench 实盘跑分编排器。

标准跑分流程（官方 API 文档）：
  列出题目 → 启动容器（≤3 活跃）→ 渗透解题（多 flag 逐个提交）→ 关闭容器 → 下一题
复用 HuntForge 挖掘 Agent（probe/web-ops/ai-ops/binary-ops/chain-ops）与 7Q Gate，
flag 直接提交到真实平台（幂等 duplicate 保护）。
"""
from __future__ import annotations

import logging
import tempfile
import time
from pathlib import Path
from typing import Optional

from ..core.state import StateDB
from .tsec_client import (ChallengeNotFound, DuplicateSubmit, InvalidState,
                          ResourceUnavailable, TaskNotFound, TsecBenchClient,
                          TsecConnectionError, TsecError)

log = logging.getLogger("huntforge.live")

DIFF_RANK = {"easy": 0, "medium": 1, "hard": 2}
# 深攻阶段的解出概率先验（用于期望值排序：分数 × 概率）
DIFF_PROB = {"easy": 0.30, "medium": 0.15, "hard": 0.05}


def expected_value(ch: dict) -> float:
    score = ch.get("total_score") or 0
    return score * DIFF_PROB.get(ch.get("difficulty", ""), 0.1)

# 每类题目的 Agent 尝试链（依次执行，时间盒内全部跑完）
AGENT_CHAIN = {
    "web": ["probe", "web-ops"],
    "ai": ["probe", "ai-ops", "web-ops"],
    "binary": ["probe", "binary-ops"],
    "blockchain": ["probe", "chain-ops"],
}


def classify_challenge(ch: dict) -> str:
    """按 unique_code/描述判断题目类别 → agent 链。"""
    code = (ch.get("unique_code") or "").lower()
    desc = (ch.get("description") or "").lower()
    if code.startswith(("f1-", "f2-")) or any(
            k in desc for k in ("tcp", "固件", "mcu", "嵌入式", "心跳", "内存")):
        return "binary"
    if "区块链" in desc or "合约" in desc or code.startswith(("chain", "bc-")):
        return "blockchain"
    if any(k in desc for k in ("ai", "模型", "智能", "提示词", "prompt")) or code.startswith("c-"):
        # c- 系列多为 AI/安全方向混合，AI 链失败会自动回退 web 规则链
        return "ai" if any(k in desc for k in ("ai", "模型", "智能", "提示", "prompt")) else "web"
    return "web"


class LiveRunner:
    def __init__(self, base_url: str, token: str, *,
                 per_challenge_timebox: float = 300.0,
                 llm_cfg: Optional[dict] = None,
                 http_timeout: float = 5.0,
                 max_active: int = 3):
        self.client = TsecBenchClient(base_url, token)
        self.per_challenge_timebox = per_challenge_timebox
        self.http_timeout = http_timeout
        self.max_active = max_active
        tmp = tempfile.mkdtemp(prefix="hf-live-")
        self.db = StateDB(str(Path(tmp) / "live.db"))
        self.planner = self._build_planner(llm_cfg)
        self.submitted: set[tuple[str, str]] = set()   # (unique_code, flag) 幂等去重
        self.scores: dict[str, int] = {}               # unique_code -> cumulative_score
        self._active: list[str] = []                   # 本 runner 启动且未关闭的题
        self._attempt_counts: dict[str, int] = {}      # 每题跨阶段累计尝试次数

    def _build_planner(self, llm_cfg):
        if not llm_cfg:
            return None
        try:
            from ..llm.gateway import ModelGateway
            from ..llm.planner import PentestPlanner
            gw = ModelGateway(llm_cfg, db=self.db)
            if gw.supports("fast"):
                return PentestPlanner(gw)
        except Exception as exc:  # noqa: BLE001
            log.info("planner unavailable, rules only: %s", exc)
        return None

    # ---------------- 主循环（两阶段：先无 LLM 快扫白拿分，再 LLM 深攻未解题） ----------------
    def run(self, max_total_time: Optional[float] = None,
            max_challenges: Optional[int] = None) -> dict:
        deadline = time.time() + max_total_time if max_total_time else None
        # 阶段 1：纯规则快扫 easy 题（不花 LLM token，限时防止挤占深攻预算）
        self._pass(deadline, per_challenge=75.0, use_llm=False,
                   label="pass1 规则快扫(easy)", only_easy=True,
                   max_pass_time=1200.0, max_attempts=1)
        # 阶段 2：规则 + LLM 深攻剩余未解题（按分值从高到低，每阶段最多攻 2 次）
        self._pass(deadline, per_challenge=self.per_challenge_timebox,
                   use_llm=True, label="pass2 LLM 深攻", max_attempts=2)
        return self._summary(self.client.list_challenges())

    def _pass(self, deadline: Optional[float], *, per_challenge: float,
              use_llm: bool, label: str, only_easy: bool = False,
              max_pass_time: Optional[float] = None, max_attempts: int = 1) -> None:
        log.info("---------- %s 开始（每题 ≤%ss, LLM=%s） ----------",
                 label, per_challenge, use_llm)
        pass_started = time.time()
        while True:
            if deadline is not None and time.time() > deadline:
                log.info("总时间到，%s 收尾", label)
                return
            if max_pass_time and time.time() - pass_started > max_pass_time:
                log.info("%s 阶段时限到，转入下一阶段", label)
                return
            challenges = self.client.list_challenges()   # 可能抛 InvalidState（任务结束）
            pending = [c for c in challenges if not c.get("is_completed")]
            if only_easy:
                pending = [c for c in pending if c.get("difficulty") == "easy"]
            if not pending:
                log.info("%s: 无待处理题目", label)
                return
            if use_llm:
                # 深攻按期望值排序：分数 × 难度先验（b-01/b-03 这类 1200 分题优先于一切 easy）
                order = sorted(pending, key=lambda c: -expected_value(c))
            else:
                order = sorted(pending,
                               key=lambda c: (DIFF_RANK.get(c.get("difficulty", ""), 1),
                                              -(c.get("total_score") or 0)))
            progress = False
            for ch in order:
                if deadline is not None and time.time() > deadline:
                    return
                n = self._attempt_counts.get(ch["unique_code"], 0)
                if n >= max_attempts:
                    continue
                self._attempt_counts[ch["unique_code"]] = n + 1
                try:
                    completed = self._solve_one(ch, deadline, per_challenge, use_llm)
                    progress = True
                    if completed:
                        log.info("%s: 已通关（累计得分 %s）",
                                 ch["unique_code"], self.scores.get(ch["unique_code"]))
                except InvalidState as exc:
                    if exc.max_active:
                        self._release_one_slot()
                        continue
                    log.info("任务已结束（invalid_state: %s），停止", exc.message)
                    return
                except (TaskNotFound, TsecConnectionError) as exc:
                    log.error("致命错误，停止: %s", exc)
                    return
                except TsecError as exc:
                    log.warning("题目 %s 处理出错: %s", ch.get("unique_code"), exc)
                except Exception as exc:  # noqa: BLE001 - 单题任何异常都不应杀死整个跑分
                    log.exception("题目 %s 未知异常: %s", ch.get("unique_code"), exc)
            if not progress:
                return

    def _summary(self, challenges: list[dict]) -> dict:
        total_score = sum(self.scores.values())
        completed = sum(1 for c in challenges if c.get("is_completed"))
        return {"total": len(challenges), "completed": completed,
                "total_score": total_score, "scores": dict(self.scores)}

    # ---------------- 单题流程 ----------------
    def _solve_one(self, ch: dict, deadline: Optional[float],
                   per_challenge: float, use_llm: bool) -> bool:
        code = ch["unique_code"]
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

            # 3) 解题
            targets = [f"http://{a}" for a in addrs]
            self._attack(code, ch, targets, deadline, per_challenge, use_llm)

            # 4) 校验进度
            for c in self.client.list_challenges():
                if c["unique_code"] == code:
                    self.scores[code] = c.get("cumulative_score") or self.scores.get(code, 0)
                    return bool(c.get("is_completed"))
            return False
        finally:
            # 5) 关闭容器释放名额
            try:
                self.client.close(code)
                if code in self._active:
                    self._active.remove(code)
            except TsecError as exc:
                log.warning("%s: close 失败: %s", code, exc)

    def _start_with_retry(self, code: str, attempts: int = 4) -> dict:
        for i in range(attempts):
            try:
                result = self.client.start(code)
                self._active.append(code)
                return result
            except InvalidState as exc:
                if exc.max_active:
                    self._release_one_slot()
                    continue
                raise
            except ResourceUnavailable:
                log.info("%s: 资源未就绪，%ds 后重试 (%d/%d)", code, 6 * (i + 1), i + 1, attempts)
                time.sleep(6 * (i + 1))
        raise TsecError("resource_unavailable", f"{code} 多次启动失败")

    def _release_one_slot(self) -> None:
        for code in list(self._active):
            try:
                self.client.close(code)
                self._active.remove(code)
                log.info("释放名额: closed %s", code)
                return
            except TsecError:
                continue
        log.warning("无本地活跃题目可关闭，等平台释放")

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
    def _pick_target(self, targets: list[str]) -> Optional[str]:
        """多个 container_addr 里挑第一个讲 HTTP 的（含 https 变体）。"""
        for addr in targets:
            http = f"http://{addr}" if "://" not in addr else addr
            if self._speaks_http(http):
                return http
        return None

    def _attack(self, code: str, ch: dict, targets: list[str],
                deadline: Optional[float], per_challenge: float,
                use_llm: bool) -> None:
        chain = AGENT_CHAIN.get(classify_challenge(ch), ["probe", "web-ops"])
        target = self._pick_target(targets)
        if target is None:
            self._attack_non_http(code, ch, targets[0])
            return
        started_at = time.time()
        budget = per_challenge
        flag_count = ch.get("flag_count") or 1
        planner = self.planner if use_llm else None
        for agent_type in chain:
            if deadline is not None and time.time() > deadline:
                break
            if self._is_completed(code):
                break
            remaining = budget - (time.time() - started_at)
            if remaining < 20:
                break
            # probe 只给最多 40s，把时间留给专项检查/LLM
            tb = min(remaining, 40.0) if agent_type == "probe" else remaining
            agent = self._make_agent(agent_type, code, ch, target, tb,
                                     flag_count, planner)
            if agent is None:
                continue
            try:
                result = agent.run({"id": 0, "challenge_id": code, "agent_type": agent_type})
                log.info("%s: %s -> outcome=%s", code, agent_type, result.get("outcome"))
            except Exception as exc:  # noqa: BLE001 - 单题失败不影响全局
                log.exception("%s: %s 异常: %s", code, agent_type, exc)

        # 多 flag 题：链跑完仍未通关且时间富余 → 再攻一轮（LLM 循环非确定性，可能找到新 flag）
        if flag_count > 1 and not self._is_completed(code):
            if deadline is not None and time.time() > deadline:
                return
            remaining = budget - (time.time() - started_at)
            if remaining >= 60:
                log.info("%s: 多 flag 题未通关，剩余 %ss，再攻一轮", code, int(remaining))
                agent = self._make_agent("web-ops", code, ch, target, remaining,
                                         flag_count, planner)
                try:
                    result = agent.run({"id": 1, "challenge_id": code,
                                        "agent_type": "web-ops"})
                    log.info("%s: 再攻 -> outcome=%s", code, result.get("outcome"))
                except Exception as exc:  # noqa: BLE001
                    log.exception("%s: 再攻异常: %s", code, exc)

    def _speaks_http(self, target: str) -> bool:
        """判定目标是否讲 HTTP。http 不通再试 https（如 8443 的 TLS 服务）。

        容器刚就绪时服务可能仍慢，探测失败会退避重试几次。
        """
        import requests
        schemes = ["http", "https"] if target.startswith("http://") else ["http", "https"]
        base = target.split("://", 1)[-1]
        for scheme in schemes:
            for attempt in range(3):
                try:
                    requests.get(f"{scheme}://{base}/", timeout=6,
                                 verify=False, allow_redirects=False)
                    return True   # 收到 HTTP 响应（任意状态码）即算
                except requests.RequestException:
                    if attempt < 2:
                        time.sleep(4)
        return False

    def _attack_non_http(self, code: str, ch: dict, target: str) -> None:
        """非 HTTP 靶场：调用 tools 包（MCP 风格注册表）里的专用工具。"""
        from ..tools import call_tool
        host, _, port = target.replace("http://", "").replace("https://", "").partition(":")
        port = int(port or 23)
        desc = (ch.get("description") or "").lower()
        if port == 23 or "telnet" in desc or "远程登录" in desc:
            log.info("%s: telnet 登录工具 -> %s:%s", code, host, port)
            result = call_tool("telnet_login", host=host, port=port, timeout=45)
        else:
            log.info("%s: TCP 协议探测工具 -> %s:%s", code, host, port)
            result = call_tool("tcp_probe", host=host, port=port, timeout=30)
        flags = result.get("flags") or []
        if flags:
            log.info("%s: 工具提取到 %d 个 flag 候选", code, len(flags))
            for flag in flags:
                self._submit_flag(code, flag)
        else:
            log.info("%s: 工具未找到 flag（error=%s）", code, result.get("error", "无"))

    def _is_completed(self, code: str) -> bool:
        for c in self.client.list_challenges():
            if c["unique_code"] == code:
                return bool(c.get("is_completed"))
        return False

    def _make_agent(self, agent_type: str, code: str, ch: dict, target: str,
                    timebox: float, flag_count: int, planner):
        from ..agents.ai_ops import AIOpsAgent
        from ..agents.binary_ops import BinaryOpsAgent
        from ..agents.blockchain_ops import BlockchainOpsAgent
        from ..agents.probe import ProbeAgent
        from ..agents.web_ops import WebOpsAgent

        self.db.upsert_challenge({
            "id": code, "title": ch.get("description") or code,
            "category": ch.get("difficulty", "web"), "difficulty": ch.get("difficulty", "medium"),
            "target": target,
        })
        submitter = self._make_submitter(code)
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
                               # 实盘：规则快赢优先，LLM 探索殿后；步数收窄省时间
                               llm_first=False, max_llm_steps=4, min_llm_time=20)
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
            if not res.get("duplicate"):
                log.info("FLAG ACCEPTED %s +%s (累计 %s, 进度 %s/%s)",
                         code, res.get("awarded"), res.get("cumulative_score"),
                         res.get("correct_flag_count"), res.get("total_flag_count"))
            self.scores[code] = res.get("cumulative_score") or self.scores.get(code, 0)
        else:
            log.info("%s: flag rejected (awarded=0)", code)
