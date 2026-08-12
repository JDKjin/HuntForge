"""P0 探测 Agent：HTTP 探活 + 常见路径枚举 + flag 正则抓取。

这是 Web 流水线的雏形（P1 将扩展为 recon→指纹→专项探测）。
命中 flag 时产出高置信 finding 并排提交任务。
"""
from __future__ import annotations

import logging
import re
import time
import urllib3
from typing import Callable, Optional

import requests

from ..core.state import StateDB

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("huntforge.probe")

# 保守 flag 正则：必须带定界符才计命中（借鉴 lingops：宽松候选会造成误报→永久放弃）
FLAG_RE = re.compile(r"(?:flag|ctf|hf)[\{\(\[]([^\]\}\)]{1,128})[\}\)\]]", re.IGNORECASE)

# 常见敏感路径（P1 将按指纹动态生成）
COMMON_PATHS = [
    "/", "/flag", "/admin", "/api", "/api/admin", "/api/admin/flag", "/api/flag",
    "/robots.txt", "/.env", "/config.json", "/backup.zip", "/flag.txt",
    "/swagger-ui.html", "/api-docs", "/openapi.json", "/health", "/login", "/api/v1/flag",
]

HEADERS = {"User-Agent": "Mozilla/5.0 (HuntForge/0.1)"}


class ProbeAgent:
    """单个任务的执行体。handler 接口：scheduler.run_task(lambda task: ProbeAgent(db, cfg).run(task))"""

    def __init__(self, db: StateDB, http_timeout: float = 10.0,
                 timebox: float = 300.0,
                 submitter: Optional[Callable[[str, str], None]] = None):
        """submitter(challenge_id, value)：命中 flag 时回调（排幂等提交）。"""
        self.db = db
        self.http_timeout = http_timeout
        self.timebox = timebox
        self.submitter = submitter
        self._started = None  # type: ignore[assignment]

    def run(self, task: dict) -> dict:
        ch = self.db.get_challenge(task["challenge_id"])
        if ch is None:
            return {"ok": False, "outcome": "no_challenge"}
        self._started = time.time()
        target = ch.get("target") or ""
        if not target:
            return {"ok": False, "outcome": "no_target"}

        results = {"hits": [], "checked": 0}
        if target.startswith(("http://", "https://")):
            results = self._probe_http(target, task["id"])
        else:
            # 非 HTTP 目标（源码/二进制/APK）：P0 只标记，等待专项 agent
            self.db.event("task.info", "challenge", ch["id"],
                          {"msg": f"non-http target, waiting for specialist: {target[:80]}"})

        # 命中 → finding + 排提交
        for hit in results["hits"]:
            fid = self.db.add_finding(
                ch["id"], task["id"], vuln_type=hit["type"],
                confidence=hit.get("confidence", 0.9),
                evidence={"url": hit["url"], "source": "probe.path",
                          "value": hit["value"]},
            )
            self.db.event("finding.added", "challenge", ch["id"],
                          {"finding_id": fid, "vuln_type": hit["type"]})
            self.db.put_memory("hit", f"{ch.get('category','web')}:{hit['type']}",
                               {"path": hit["path"], "how": "path-scan"})
            if self.submitter:
                self.submitter(ch["id"], hit["value"])

        if results["hits"]:
            return {"ok": True, "outcome": "flag_found", "n_hits": len(results["hits"]),
                    "hits": results["hits"]}
        return {"ok": True, "outcome": "probed_clean", "checked": results["checked"]}

    # ---------- HTTP 探测 ----------
    def _probe_http(self, base: str, task_id: int) -> dict:
        out = {"hits": [], "checked": 0}
        for path in COMMON_PATHS:
            if self._time_left() <= 0:
                break
            url = base.rstrip("/") + path
            try:
                resp = requests.get(url, headers=HEADERS, timeout=self.http_timeout,
                                    allow_redirects=True, verify=False)
            except requests.RequestException:
                continue
            out["checked"] += 1
            body = resp.text or ""
            for m in FLAG_RE.finditer(body):
                out["hits"].append({"type": "flag_leak", "path": path, "url": url,
                                    "value": m.group(0), "confidence": 0.95})
                break  # 一个路径一个 flag 即可
        return out

    def _time_left(self) -> float:
        return self.timebox - (time.time() - self._started)
