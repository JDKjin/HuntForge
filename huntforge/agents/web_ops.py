"""Web 综合挖掘 Agent：指纹 → 专项检查序列 → 7Q Gate → finding/提交。

规则引擎为主（零 LLM 调用），产出结构化证据；指纹结果写 memory 供跨题复用。
"""
from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from ..core.state import StateDB
from ..web import checks
from ..web.common import get, body_of
from ..web.fingerprint import Fingerprinter
from ..web.gate import evaluate_and_persist

log = logging.getLogger("huntforge.webops")


class WebOpsAgent:
    def __init__(self, db: StateDB, http_timeout: float = 8.0,
                 timebox: float = 600.0,
                 submitter: Optional[Callable[[str, str], None]] = None,
                 fingerprint: Optional[Fingerprinter] = None):
        self.db = db
        self.http_timeout = http_timeout
        self.timebox = timebox
        self.submitter = submitter
        self.fp = fingerprint or Fingerprinter()
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

        # 1) 指纹识别（主页请求）
        tags = self._identify(target, ch["id"])
        self.db.put_memory("fingerprint", target[:120],
                           {"tags": tags}, strength=1.0)

        # 2) 专项检查（指纹驱动排序）
        ctx = {"base": target, "timeout": self.http_timeout,
               "time_left": self._time_left}
        order = self.fp.check_order(tags)
        candidates = []
        for check_name in order:
            if self._time_left() <= 0:
                break
            fn = checks.CHECKS.get(check_name)
            if not fn:
                continue
            try:
                found = fn(ctx)
            except Exception as exc:  # noqa: BLE001 - 单个检查崩溃不拖垮任务
                log.exception("check %s failed", check_name)
                self.db.event("task.info", "challenge", ch["id"],
                              {"msg": f"check {check_name} error: {exc}"})
                continue
            candidates.extend(found)
            self.db.event("task.info", "challenge", ch["id"],
                          {"msg": f"check {check_name} -> {len(found)} candidate(s)"})
            if any(c.value for c in found):
                break  # 已直接命中 flag，停止后续检查

        # 3) 去重 + Gate + 落库 + 提交
        n_verified, n_flag = self._persist(ch, task["id"], candidates)
        return {"ok": True, "outcome": "flag_found" if n_flag else "scanned",
                "fingerprints": tags, "candidates": len(candidates),
                "verified": n_verified, "flags": n_flag}

    # ---------- 指纹 ----------
    def _identify(self, base: str, challenge_id: str) -> list[str]:
        resp = get(base, self.http_timeout)
        if resp is None:
            return []
        path_status: dict[str, int] = {}
        # 少量路径探测辅助指纹
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
        return tags

    # ---------- 落库 ----------
    def _persist(self, ch: dict, task_id: int, candidates) -> tuple[int, int]:
        n_verified = 0
        n_flag = 0
        seen: set[tuple[str, str]] = set()
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
                                   {"url": cand.url, "how": cand.type},
                                   strength=1.0)
            if cand.value and result.passed:
                n_flag += 1
                if self.submitter:
                    self.submitter(ch["id"], cand.value)
        return n_verified, n_flag

    def _time_left(self) -> float:
        return self.timebox - (time.time() - self._started)
