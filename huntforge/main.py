"""HuntForge 入口：握手 → 拉题 → 派工 → 执行 → 幂等提交 → 统计。

托管模式：平台注入 BENCHMARK_BASE_URL / BENCHMARK_TOKEN，镜像启动即自解。
本地模式：--mock 启动内置 mock 平台+靶场做闭环评测。

用法：
    python -m huntforge.main --mock --rounds 5       # 本地 mock 评测
    python -m huntforge.main --max-time 1800         # 托管模式（环境变量注入）
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Optional

from .agents.ai_ops import AIOpsAgent
from .agents.probe import ProbeAgent
from .agents.web_ops import WebOpsAgent
from .bench.client import BenchClient
from .bench.mock_server import MockBench
from .bench.submission import SubmissionManager
from .core.config import load
from .core.scheduler import Scheduler
from .core.state import StateDB

log = logging.getLogger("huntforge")


def _load_dotenv(path: str | None = None) -> None:
    """加载项目根 .env（KEY=VALUE 行，无依赖实现）。

    只 setdefault：已存在的环境变量（平台注入/手动导出）优先，不会被覆盖。
    仅在 --live / driver 分支调用，保证 mock 评测始终走内置平台。
    HUNTFORGE_NO_DOTENV=1 时完全跳过（测试隔离：防止真实 .env 泄漏进
    测试进程污染 mock 模式）。
    """
    from pathlib import Path
    if os.environ.get("HUNTFORGE_NO_DOTENV") == "1":
        return
    p = Path(path) if path else Path(__file__).resolve().parents[1] / ".env"
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = val.strip()


def _llm_config(cfg) -> dict:
    """合并 settings.yaml 的 llm 段（含 per_challenge_call_budget）与 llm.yaml。"""
    merged = dict(cfg.data.get("llm") or {})
    merged.update(cfg.llm or {})
    return merged


def _make_planner(cfg, db: StateDB, task_id: Optional[int] = None):
    """从配置创建 PentestPlanner，LLM 不可用时返回 None。

    task_id 精确归属 model_usage——并发 worker 共享 gateway 会串号，
    因此每个任务创建独立 planner/gateway（构造开销仅为读环境变量）。
    """
    try:
        from .llm.gateway import ModelGateway
        from .llm.planner import PentestPlanner
        gw = ModelGateway(_llm_config(cfg), db=db, task_id=task_id)
        # 检查是否有可用模型（至少一个 tier 有 key）
        if gw.supports("fast"):
            return PentestPlanner(gw)
    except Exception as exc:  # noqa: BLE001
        log.info("planner unavailable, using rules only: %s", exc)
    return None

# category → agent 阶段序列（依次尝试，直到解出或挂起）
CATEGORY_STAGES = {
    "web": ["probe", "web-ops"],
    "api": ["probe", "web-ops"],
    "ai": ["probe", "ai-ops"],
    "pwn": ["probe", "binary-ops"],
    "binary": ["probe", "binary-ops"],
    "reverse": ["probe", "binary-ops"],
    "blockchain": ["probe", "chain-ops"],
    "crypto": ["probe"],
    "misc": ["probe"],
    "forensics": ["probe"],
}

AGENT_TYPES = {a for stages in CATEGORY_STAGES.values() for a in stages}


def make_handler(db: StateDB, cfg, submissions: SubmissionManager):
    """task.agent_type → 执行体。planner 按任务独立创建（usage 精确归属）。"""
    agent_cfg = cfg.agent
    submitter = lambda cid, v: submissions.queue(cid, v)  # noqa: E731
    planner_available = False
    probe = None
    try:
        probe = _make_planner(cfg, db)
        planner_available = probe is not None
    except Exception as exc:  # noqa: BLE001 - 探测失败不影响规则链路
        log.info("planner probe failed: %s", exc)
    if planner_available:
        log.info("LLM planner enabled (tier=fast available)")

    def handler(task: dict) -> dict:
        # 每任务独立 planner：task_id 精确落到 model_usage（并发 worker 不串号）
        planner = _make_planner(cfg, db, task_id=task.get("id")) if planner_available else None
        agent_type = task["agent_type"]
        timeout = float(agent_cfg.get("timeout_seconds", 600))
        http_t = float(agent_cfg.get("http_timeout", 10))
        if agent_type == "probe":
            return ProbeAgent(
                db, http_timeout=http_t,
                timebox=float(agent_cfg.get("timeout_seconds", 300)),
                submitter=submitter,
            ).run(task)
        if agent_type == "web-ops":
            return WebOpsAgent(
                db, http_timeout=http_t, timebox=timeout,
                submitter=submitter, planner=planner,
                # 实盘教训：规则检查设独立时间上限，防吃光预算饿死 LLM 循环
                rules_max_seconds=timeout * 0.45,
            ).run(task)
        if agent_type == "ai-ops":
            return AIOpsAgent(
                db, http_timeout=http_t, timebox=timeout,
                submitter=submitter, planner=planner,
            ).run(task)
        if agent_type == "binary-ops":
            from .agents.binary_ops import BinaryOpsAgent
            return BinaryOpsAgent(
                db, timebox=timeout, submitter=submitter, planner=planner,
            ).run(task)
        if agent_type == "chain-ops":
            from .agents.blockchain_ops import BlockchainOpsAgent
            return BlockchainOpsAgent(
                db, timebox=timeout, submitter=submitter, planner=planner,
            ).run(task)
        log.warning("unknown agent_type %s, using probe", agent_type)
        return ProbeAgent(db, submitter=submitter).run(task)

    return handler


def dispatch_pending(db: StateDB, sched: Scheduler) -> int:
    """为待办题目排任务（已排未决的跳过）。

    阶段推进：按 CATEGORY_STAGES 依次尝试（probe → web-ops → …），
    某阶段解出则停止；全部阶段试完未解 → idle 等待更高阶段。
    """
    dispatched = 0
    for ch in db.list_challenges():
        if ch["status"] not in ("pending", "solving"):
            continue
        tasks = db.list_tasks(ch["id"])
        if any(t["status"] in ("pending", "claimed", "running") for t in tasks):
            continue
        if all(t["status"] in ("done", "failed") for t in tasks):
            # 有 accepted 或未决提交 → 等（题目已解出或在解出路上）
            subs = db.list_submissions(ch["id"])
            if any(s["status"] == "accepted" for s in subs):
                continue
            if any(s["status"] in ("pending", "unknown", "submitting") for s in subs):
                continue
            # 未解出 → 推进到下一阶段
            stages = CATEGORY_STAGES.get(ch.get("category", "web"), ["probe"])
            used = {t["agent_type"] for t in tasks}
            next_stage = next((a for a in stages if a not in used), None)
            if next_stage is None:
                db.set_challenge_status(ch["id"], "idle")
                continue
            sched.submit(ch["id"], next_stage)
            db.bump_challenge_attempt(ch["id"])
            dispatched += 1
    return dispatched


def run(cfg, *, mock: bool = False, max_rounds: int | None = None,
        max_time: float | None = None, poll_interval: float | None = None) -> dict:
    started = time.time()
    db = StateDB(cfg.db_path)
    recovered = db.recover_interrupted()
    db.event("system.start", payload={"recovered": recovered,
                                      "gateway": bool(cfg.llm.get("gateway", {}).get("enabled"))})

    # ---- BenchClient：环境变量注入 > YAML > mock ----
    bench = BenchClient(
        cfg.bench_base_url, cfg.bench_token,
        list_path=cfg.platform.get("list_challenges_path", "/api/v1/assets"),
        submit_path=cfg.platform.get("submit_path", "/api/v1/flag/collect"),
        value_field=cfg.platform.get("submit_value_field", "flag"),
    )
    mock_bench = None
    if not bench.configured:
        if not mock:
            raise RuntimeError("BENCHMARK_BASE_URL 未配置；托管模式必须显式注入平台环境变量或使用 --mock")
        mock_bench = MockBench()
        mock_bench.start()
        bench = BenchClient(mock_bench.base_url, None)
        log.info("using built-in mock bench: %s", mock_bench.base_url)

    submissions = SubmissionManager(
        db, bench,
        cooldowns=cfg.submission.get("cooldowns", [0, 30, 120, 300, 600]),
        max_attempts=int(cfg.submission.get("max_attempts", 5)),
    )
    sched = Scheduler(db, workers=int(cfg.scheduler.get("workers", 3)),
                      lease_seconds=int(cfg.scheduler.get("lease_seconds", 300)))
    sched.start()
    handler = make_handler(db, cfg, submissions)

    sched_cfg = cfg.scheduler
    poll = poll_interval or float(cfg.platform.get("poll_interval", 5))
    rounds = max_rounds or 0
    round_no = 0

    try:
        while True:
            round_no += 1
            db.event("cycle.started", payload={"round": round_no})
            if max_time and time.time() - started > max_time:
                log.info("max_time reached")
                break
            if rounds and round_no > rounds:
                log.info("max_rounds reached")
                break

            # 1. 拉题（平台最新状态）
            try:
                challenges = bench.list_challenges()
                for c in challenges:
                    db.upsert_challenge(c.to_dict())
                db.event("challenges.fetched", payload={"count": len(challenges)})
            except Exception as exc:  # noqa: BLE001 - 平台抖动容忍
                log.warning("list_challenges failed: %s", exc)
                db.event("challenges.fetch_failed", payload={"error": str(exc)[:120]})

            # 2. 派工 + 执行
            dispatched = dispatch_pending(db, sched)
            if dispatched:
                log.info("dispatched %d new task(s)", dispatched)
            executed = sched.drain(handler, idle_sleep=0.3, max_idle_rounds=1)
            if executed:
                log.info("executed %d task(s) this round", executed)

            # 3. 幂等提交
            flushed = submissions.flush()
            if flushed:
                log.info("flushed %d submission(s)", flushed)

            db.event("cycle.ended", payload={"round": round_no})
            if _all_done(db):
                log.info("all challenges resolved")
                break
            time.sleep(poll)
    finally:
        sched.stop()
        if mock_bench:
            mock_bench.stop()
        summary = _summary(db, started)
        db.event("system.end", payload=summary)
        db.close()
    return summary


def _all_done(db: StateDB) -> bool:
    for ch in db.list_challenges():
        if ch["status"] in ("pending", "solving"):
            return False
    subs = db.list_submissions()
    if any(s["status"] in ("pending", "unknown", "submitting") for s in subs):
        return False
    return True


def _summary(db: StateDB, started: float) -> dict:
    challenges = db.list_challenges()
    subs = db.list_submissions()
    findings = db.list_findings()
    return {
        "duration_sec": round(time.time() - started, 1),
        "challenges": {
            "total": len(challenges),
            "solved": sum(1 for c in challenges if c["status"] == "solved"),
            "failed": sum(1 for c in challenges if c["status"] == "failed"),
            "skipped": sum(1 for c in challenges if c["status"] == "skipped"),
            "pending": sum(1 for c in challenges if c["status"] in ("pending", "solving")),
            "idle": sum(1 for c in challenges if c["status"] == "idle"),
        },
        "findings": len(findings),
        "findings_verified": sum(1 for f in findings if f["status"] == "verified"),
        "submissions": {
            "total": len(subs),
            "accepted": sum(1 for s in subs if s["status"] == "accepted"),
            "rejected": sum(1 for s in subs if s["status"] == "rejected"),
            "pending": sum(1 for s in subs if s["status"] in ("pending", "unknown", "submitting")),
        },
        "llm_usage": db.usage_summary(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="huntforge", description="HuntForge 铸猎 agent")
    parser.add_argument("--mock", action="store_true", help="本地 mock 模式（内置平台+靶场）")
    parser.add_argument("--rounds", type=int, default=0, help="轮数上限（0=不限）")
    parser.add_argument("--max-time", type=float, default=0, help="总时长上限（秒）")
    parser.add_argument("--poll", type=float, default=0, help="拉题间隔覆盖（秒）")
    parser.add_argument("--verbose", action="store_true", help="debug 日志")
    parser.add_argument("--live", action="store_true",
                        help="TSecBench 实盘跑分模式（真实平台 API + 容器生命周期）")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("werkzeug").setLevel(logging.WARNING)  # 靶场访问日志太吵
    cfg = load()
    if os.environ.get("HUNTFORGE_GATEWAY"):
        cfg.llm.setdefault("gateway", {})["enabled"] = True

    if args.live:
        _load_dotenv()   # 实盘配置（.env）：仅在 live 模式加载，mock 不受影响
        # 平台地址/token：环境变量/.env 优先，其次 config/settings.yaml platform 段
        base = (os.environ.get("BENCHMARK_BASE_URL", "") or "").rstrip("/") \
            or (cfg.bench_base_url or "")
        token = os.environ.get("BENCHMARK_TOKEN", "") or cfg.bench_token or ""
        if not base or not token:
            print("--live 模式需要 BENCHMARK_BASE_URL / BENCHMARK_TOKEN"
                  "（环境变量或 config/settings.yaml 的 platform 段）")
            return 1
        from .bench.live_runner import LiveRunner
        runner = LiveRunner(base, token, llm_cfg=_llm_config(cfg))
        summary = runner.run(max_total_time=args.max_time or None)
        print("LIVE_SUMMARY " + json.dumps(summary, ensure_ascii=False))
        return 0

    summary = run(
        cfg, mock=args.mock,
        max_rounds=args.rounds or None,
        max_time=args.max_time or None,
        poll_interval=args.poll or None,
    )
    print("HUNTFORGE_SUMMARY " + json.dumps(summary, ensure_ascii=False))
    return 0 if summary["challenges"]["solved"] == summary["challenges"]["total"] else 2


if __name__ == "__main__":
    sys.exit(main())
