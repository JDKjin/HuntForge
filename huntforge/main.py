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


def _make_planner(cfg, db: StateDB):
    """从配置创建 PentestPlanner，LLM 不可用时返回 None。"""
    try:
        from .llm.gateway import ModelGateway
        from .llm.planner import PentestPlanner
        gw = ModelGateway(cfg.llm, db=db)
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
    """task.agent_type → 执行体。planner 传给所有 agent。"""
    agent_cfg = cfg.agent
    submitter = lambda cid, v: submissions.queue(cid, v)  # noqa: E731
    planner = _make_planner(cfg, db)
    if planner:
        log.info("LLM planner enabled (tier=fast available)")
    else:
        log.info("LLM planner unavailable — rules-only mode")

    def handler(task: dict) -> dict:
        if planner is not None:
            # 任务级 usage 计量（尽力而为：并发 worker 共享 gateway 时可能串号，
            # 精确归属需把 task_id 穿透到每次 planner 调用）
            planner.gw.task_id = task.get("id")
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
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("werkzeug").setLevel(logging.WARNING)  # 靶场访问日志太吵
    cfg = load()
    if os.environ.get("HUNTFORGE_GATEWAY"):
        cfg.llm.setdefault("gateway", {})["enabled"] = True

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
