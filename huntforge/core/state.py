"""SQLite 唯一事实源（借鉴 lingops-agent / CTF-Hunter 的状态库设计）。

表：
  challenges   题目（pending/solving/solved/skipped/failed）
  tasks        任务（pending/claimed/running/done/failed，lease 防重复执行）
  findings     漏洞发现（candidate/verified/killed）
  submissions  提交（pending/submitting/accepted/rejected/unknown，dedup_key 唯一）
  events       事件溯源日志（全程可审计，托管模式即 demo 素材）
  model_usage  模型 token 计量（成本报表数据源）
  memory       跨题经验（P1 启用）

并发约定：WAL + busy_timeout；任务的领取/完成全部 CAS（带 lease_token）。
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'web',
    difficulty TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'pending',
    target TEXT NOT NULL DEFAULT '',
    meta TEXT NOT NULL DEFAULT '{}',
    attempts INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id TEXT NOT NULL,
    agent_type TEXT NOT NULL DEFAULT 'probe',
    status TEXT NOT NULL DEFAULT 'pending',
    lease_token TEXT,
    lease_expires REAL,
    attempt INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 0,
    result TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_pending ON tasks(status, priority, created_at);
CREATE INDEX IF NOT EXISTS idx_tasks_challenge ON tasks(challenge_id);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id TEXT NOT NULL,
    task_id INTEGER,
    vuln_type TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    status TEXT NOT NULL DEFAULT 'candidate',
    evidence TEXT NOT NULL DEFAULT '{}',
    gate TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_challenge ON findings(challenge_id);
CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id TEXT NOT NULL,
    dedup_key TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at REAL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ref_type TEXT NOT NULL DEFAULT '',
    ref_id TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS model_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER,
    tier TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cached_tokens INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    key TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL DEFAULT '{}',
    strength REAL NOT NULL DEFAULT 1.0,
    updated_at REAL NOT NULL
);
"""


def _now() -> float:
    return time.time()


class StateDB:
    """线程安全的状态库（单连接 + 锁，8核预算内够用）。"""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        if self.path.parent != Path("."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._lock = threading.RLock()

    # ---------- 底层 ----------
    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def _row(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        rows = self._query(sql, params)
        return rows[0] if rows else None

    @staticmethod
    def _j(data: dict) -> str:
        return json.dumps(data, ensure_ascii=False)

    @staticmethod
    def _u(text: str) -> dict:
        try:
            return json.loads(text or "{}")
        except json.JSONDecodeError:
            return {}

    # ---------- challenges ----------
    def upsert_challenge(self, ch: dict) -> None:
        now = _now()
        old = self.get_challenge(ch["id"])
        # 仅当平台实际换了题目（target 变化）才复位重测；
        # 否则保持终态（solved/idle），避免每轮拉题造成重派死循环
        target_changed = bool(old and old["target"] != ch.get("target", ""))
        self._execute(
            """INSERT INTO challenges (id,title,category,difficulty,status,target,meta,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 title=excluded.title, category=excluded.category,
                 difficulty=excluded.difficulty, target=excluded.target,
                 meta=excluded.meta,
                 status=CASE WHEN challenges.status='solved' THEN 'solved'
                             WHEN ?=1 THEN 'pending'
                             ELSE challenges.status END,
                 updated_at=excluded.updated_at
               WHERE challenges.status != 'solved'""",
            (ch["id"], ch.get("title", ""), ch.get("category", "web"),
             ch.get("difficulty", "medium"), ch.get("status", "pending"),
             ch.get("target", ""), self._j(ch.get("meta", {})), 1 if target_changed else 0,
             now, now),
        )
        # 换题 → 清旧任务让流水线重跑（提交去重仍由 submissions.dedup_key 保证）
        if target_changed and old["status"] not in ("solved", "pending"):
            self._execute("DELETE FROM tasks WHERE challenge_id=?", (ch["id"],))

    def get_challenge(self, challenge_id: str) -> Optional[dict]:
        row = self._row("SELECT * FROM challenges WHERE id=?", (challenge_id,))
        if row is None:
            return None
        d = dict(row)
        d["meta"] = self._u(d.get("meta", "{}"))
        return d

    def list_challenges(self, status: str | None = None) -> list[dict]:
        if status:
            rows = self._query("SELECT * FROM challenges WHERE status=?", (status,))
        else:
            rows = self._query("SELECT * FROM challenges")
        out = []
        for r in rows:
            d = dict(r)
            d["meta"] = self._u(d.get("meta", "{}"))
            out.append(d)
        return out

    def set_challenge_status(self, challenge_id: str, status: str) -> None:
        self._execute(
            "UPDATE challenges SET status=?, updated_at=? WHERE id=?",
            (status, _now(), challenge_id),
        )

    def bump_challenge_attempt(self, challenge_id: str) -> None:
        self._execute(
            "UPDATE challenges SET attempts=attempts+1, updated_at=? WHERE id=?",
            (_now(), challenge_id),
        )

    # ---------- tasks ----------
    def create_task(self, challenge_id: str, agent_type: str = "probe",
                    priority: int = 0) -> int:
        now = _now()
        cur = self._execute(
            """INSERT INTO tasks (challenge_id, agent_type, status, priority, created_at, updated_at)
               VALUES (?,?, 'pending', ?, ?, ?)""",
            (challenge_id, agent_type, priority, now, now),
        )
        self._execute(
            "UPDATE challenges SET status='solving', updated_at=? WHERE id=? AND status='pending'",
            (now, challenge_id),
        )
        return int(cur.lastrowid)

    def claim_task(self, agent_type: str | None = None) -> Optional[dict]:
        """CAS 原子领取：只认领 lease 过期或 pending 的任务。"""
        now = _now()
        sql = """SELECT id FROM tasks
                 WHERE status='pending' AND (? IS NULL OR agent_type=?)
                 ORDER BY created_at ASC LIMIT 1"""
        rows = self._query(sql, (agent_type, agent_type))
        if not rows:
            # 回收 lease 过期的 claimed/running 任务
            self._execute(
                "UPDATE tasks SET status='pending', lease_token=NULL, updated_at=? "
                "WHERE status IN ('claimed','running') AND lease_expires < ?",
                (now, now),
            )
            rows = self._query(sql, (agent_type, agent_type))
            if not rows:
                return None
        task_id = rows[0]["id"]
        token = uuid.uuid4().hex
        cur = self._execute(
            "UPDATE tasks SET status='claimed', lease_token=?, lease_expires=?, "
            "attempt=attempt+1, updated_at=? WHERE id=? AND status='pending'",
            (token, now + 300, now, task_id),
        )
        if cur.rowcount != 1:
            return None  # 已被其他 worker 抢走
        row = self._row("SELECT * FROM tasks WHERE id=?", (task_id,))
        d = dict(row)
        d["result"] = self._u(d.get("result", "{}"))
        return d

    def start_task(self, task_id: int, lease_token: str, lease_seconds: int) -> bool:
        cur = self._execute(
            "UPDATE tasks SET status='running', updated_at=? WHERE id=? AND lease_token=?",
            (_now(), task_id, lease_token),
        )
        return cur.rowcount == 1

    def renew_lease(self, task_id: int, lease_token: str, lease_seconds: int) -> bool:
        cur = self._execute(
            "UPDATE tasks SET lease_expires=? WHERE id=? AND lease_token=?",
            (_now() + lease_seconds, task_id, lease_token),
        )
        return cur.rowcount == 1

    def complete_task(self, task_id: int, lease_token: str, result: dict) -> bool:
        cur = self._execute(
            "UPDATE tasks SET status='done', result=?, updated_at=? WHERE id=? AND lease_token=?",
            (self._j(result), _now(), task_id, lease_token),
        )
        return cur.rowcount == 1

    def fail_task(self, task_id: int, lease_token: str, result: dict) -> None:
        """失败：可重试则回 pending，否则 failed。"""
        row = self._row("SELECT attempt FROM tasks WHERE id=? AND lease_token=?", (task_id, lease_token))
        if row is None:
            return
        max_attempts = 3
        if row["attempt"] >= max_attempts:
            self._execute(
                "UPDATE tasks SET status='failed', result=?, updated_at=? WHERE id=? AND lease_token=?",
                (self._j(result), _now(), task_id, lease_token),
            )
        else:
            self._execute(
                "UPDATE tasks SET status='pending', lease_token=NULL, updated_at=? WHERE id=? AND lease_token=?",
                (_now(), task_id, lease_token),
            )

    def list_tasks(self, challenge_id: str | None = None) -> list[dict]:
        if challenge_id:
            rows = self._query("SELECT * FROM tasks WHERE challenge_id=?", (challenge_id,))
        else:
            rows = self._query("SELECT * FROM tasks")
        return [dict(r) for r in rows]

    # ---------- findings ----------
    def add_finding(self, challenge_id: str, task_id: Optional[int], vuln_type: str,
                    confidence: float, evidence: dict) -> int:
        now = _now()
        cur = self._execute(
            """INSERT INTO findings (challenge_id, task_id, vuln_type, confidence, evidence, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (challenge_id, task_id, vuln_type, confidence, self._j(evidence), now, now),
        )
        return int(cur.lastrowid)

    def update_finding(self, finding_id: int, status: str, gate: dict | None = None) -> None:
        self._execute(
            "UPDATE findings SET status=?, gate=?, updated_at=? WHERE id=?",
            (status, self._j(gate or {}), _now(), finding_id),
        )

    def list_findings(self, challenge_id: str | None = None) -> list[dict]:
        if challenge_id:
            rows = self._query("SELECT * FROM findings WHERE challenge_id=?", (challenge_id,))
        else:
            rows = self._query("SELECT * FROM findings")
        out = []
        for r in rows:
            d = dict(r)
            d["evidence"] = self._u(d.get("evidence", "{}"))
            d["gate"] = self._u(d.get("gate", "{}"))
            out.append(d)
        return out

    # ---------- submissions ----------
    @staticmethod
    def dedup_key(challenge_id: str, value: str) -> str:
        import hashlib
        norm = value.strip().lower()
        return hashlib.sha256(f"{challenge_id}\x00{norm}".encode()).hexdigest()

    def queue_submission(self, challenge_id: str, value: str) -> bool:
        """入队（去重）。重复的 flag 只产生一个提交项。"""
        key = self.dedup_key(challenge_id, value)
        row = self._row(
            "SELECT id FROM submissions WHERE dedup_key=? AND status NOT IN ('rejected')",
            (key,),
        )
        if row:
            return False
        now = _now()
        self._execute(
            """INSERT OR IGNORE INTO submissions (challenge_id, dedup_key, value, created_at, updated_at)
               VALUES (?,?,?,?,?)""",
            (challenge_id, key, value.strip(), now, now),
        )
        return True

    def peek_submissions(self) -> list[dict]:
        """未决提交列表（不改变状态；冷却判断由调用方基于 attempts 计算）。"""
        rows = self._query(
            "SELECT * FROM submissions WHERE status IN ('pending','unknown') ORDER BY created_at ASC"
        )
        return [dict(r) for r in rows]

    def mark_submitting(self, sub_id: int) -> bool:
        """CAS 置为 submitting 并 attempts+1。返回是否抢到（多线程防重）。"""
        now = _now()
        cur = self._execute(
            "UPDATE submissions SET status='submitting', last_attempt_at=?, "
            "attempts=attempts+1, updated_at=? WHERE id=? AND status IN ('pending','unknown')",
            (now, now, sub_id),
        )
        return cur.rowcount == 1

    def finish_submission(self, sub_id: int, status: str, challenge_id: str) -> None:
        """status: accepted / rejected / unknown"""
        self._execute(
            "UPDATE submissions SET status=?, updated_at=? WHERE id=?",
            (status, _now(), sub_id),
        )
        if status == "accepted":
            self.set_challenge_status(challenge_id, "solved")
        self._execute(
            "UPDATE challenges SET status='solved', updated_at=? WHERE id=?",
            (_now(), challenge_id),
        ) if status == "accepted" else None

    def list_submissions(self, challenge_id: str | None = None) -> list[dict]:
        if challenge_id:
            rows = self._query("SELECT * FROM submissions WHERE challenge_id=?", (challenge_id,))
        else:
            rows = self._query("SELECT * FROM submissions")
        return [dict(r) for r in rows]

    # ---------- events ----------
    def event(self, event_type: str, ref_type: str = "", ref_id: str = "",
              payload: dict | None = None) -> None:
        self._execute(
            "INSERT INTO events (ref_type, ref_id, event_type, payload, ts) VALUES (?,?,?,?,?)",
            (ref_type, ref_id, event_type, self._j(payload or {}), _now()),
        )

    def list_events(self, limit: int = 200, event_type: str | None = None) -> list[dict]:
        if event_type:
            rows = self._query(
                "SELECT * FROM events WHERE event_type=? ORDER BY id DESC LIMIT ?",
                (event_type, limit),
            )
        else:
            rows = self._query("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = self._u(d.get("payload", "{}"))
            out.append(d)
        return out

    # ---------- model usage ----------
    def record_usage(self, task_id: Optional[int], tier: str, model: str,
                     input_tokens: int, output_tokens: int, cached_tokens: int,
                     latency_ms: int) -> None:
        self._execute(
            """INSERT INTO model_usage (task_id, tier, model, input_tokens, output_tokens, cached_tokens, latency_ms, ts)
               VALUES (?,?,?,?,?,?,?,?)""",
            (task_id, tier, model, input_tokens, output_tokens, cached_tokens, latency_ms, _now()),
        )

    def usage_summary(self) -> dict:
        row = self._row(
            "SELECT COUNT(*) AS calls, SUM(input_tokens) AS in_t, SUM(output_tokens) AS out_t, "
            "SUM(cached_tokens) AS cache_t FROM model_usage"
        )
        d = dict(row or {})
        return {k: (int(v) if v else 0) for k, v in d.items()}

    # ---------- memory ----------
    def put_memory(self, kind: str, key: str, value: dict, strength: float = 1.0) -> None:
        self._execute(
            """INSERT INTO memory (kind, key, value, strength, updated_at) VALUES (?,?,?,?,?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value, strength=excluded.strength,
                 updated_at=excluded.updated_at""",
            (kind, key, self._j(value), strength, _now()),
        )

    def get_memory(self, kind: str | None = None) -> list[dict]:
        if kind:
            rows = self._query("SELECT * FROM memory WHERE kind=? ORDER BY strength DESC", (kind,))
        else:
            rows = self._query("SELECT * FROM memory ORDER BY strength DESC")
        out = []
        for r in rows:
            d = dict(r)
            d["value"] = self._u(d.get("value", "{}"))
            out.append(d)
        return out

    # ---------- 恢复 ----------
    def recover_interrupted(self) -> dict:
        """崩溃恢复：claimed/running 任务回 pending；solving 未收尾的题目回 pending。"""
        now = _now()
        self._execute(
            "UPDATE tasks SET status='pending', lease_token=NULL, updated_at=? "
            "WHERE status IN ('claimed','running')",
            (now,),
        )
        # 有未完成任务的 solving 题目回 pending；无任务的保持
        self._execute(
            """UPDATE challenges SET status='pending', updated_at=? WHERE status='solving'
               AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.challenge_id=challenges.id AND t.status='done')""",
            (now,),
        )
        row = self._row("SELECT COUNT(*) AS c FROM tasks WHERE status='pending'")
        return {"recovered_tasks": row["c"] if row else 0}

    def close(self) -> None:
        with self._lock:
            self._conn.close()
