"""ABANDON 三层停损（移植 CHYing-agent 的 hooks.py/_matches_dead_end 设计）。

在工具调用**执行前**做三层拦截，命中即返回拦截原因，调用方必须跳过本次
调用并强制 planner 换方向（把原因写入 memory lessons 回灌）。

三层（CHYing 实测设计，其「宁可多拦」原则照搬）：
- 层1 关键词层：a) 最近 N 轮结果中失败特征关键词重复 ≥2 次；b) 新调用输入
  与「已确认失败方向」的关键词交集 ≥2（_extract_keywords 移植）。
- 层2 调用签名层：同一签名（工具名 + URL 路径，**去掉 IP/域名**——CHYing
  作者亲历教训）连续失败 ≥ dup_limit 次。
- 层3 CVE 编号层：同一 CVE 编号已尝试 ≥2 个变体。

突破解锁（CHYing 的 breakthrough-unlock）：某签名出现成功结果时，
清除该签名的失败记录——成功的方向可以继续深挖。

线程安全：并行 worker 共享 guard 时用锁保护状态。
"""
from __future__ import annotations

import json
import re
import threading
from collections import defaultdict, deque
from typing import Optional

FAILURE_KEYWORDS = (
    "access denied", "connection refused", "timed out", "timeout",
    "403 forbidden", "401 unauthorized", "404 not found", "waf",
    "blocked", "rate limit", "too many requests", "connection reset",
)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# _extract_keywords 的停用词（CHYing 同名函数语义）
STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "not",
    "was", "are", "have", "has", "will", "your", "you", "all", "any",
    "can", "get", "post", "http", "https", "www", "com", "org", "net",
}


def _extract_keywords(text: str) -> set[str]:
    """CHYing _extract_keywords 移植：URL 路径（去 host）/ CVE 编号 /
    引号内短语（须含字母数字，过滤纯符号代码碎片）/ 3+ 字符 token（去停用词）。"""
    kws: set[str] = set()
    for m in re.finditer(r"https?://[^/\s]+(/[^\s\"']+)", text):
        kws.add(m.group(1).lower()[:80])
    for m in CVE_RE.finditer(text):
        kws.add(m.group(0).lower())
    for m in re.finditer(r"[\"']([^\"']{4,40})[\"']", text):
        phrase = m.group(1)
        if re.search(r"[a-z0-9]", phrase, re.I):   # 纯符号片段（代码噪音）丢弃
            kws.add(phrase.lower()[:40])
    for tok in re.findall(r"[a-z0-9_./-]{3,}", text.lower()):
        if tok not in STOPWORDS:
            kws.add(tok[:40])
    return kws


def call_signature(tool: str, path: str, params=None, data=None) -> str:
    """调用签名：只保留 工具名 + URL 路径（小写、去尾部斜杠、去 query/参数）。

    CHYing 教训：签名含 IP/域名/参数会导致同一操作被识别成不同操作，
    停损永远不触发；只留路径后不同 IP 下的同一探测才能正确归并。
    """
    p = (path or "").strip() or "/"
    p = p.split("?")[0].split("#")[0].rstrip("/")
    if "://" in p:
        # 防误传绝对 URL：截掉 scheme://host 部分
        parts = p.split("/", 3)
        p = "/" + (parts[-1] if len(parts) > 3 else "")
    p = p.lower() or "/"
    return f"{str(tool).lower()} {p}"


class AbandonGuard:
    """每道题的停损状态按 challenge_id 隔离，互不污染。"""

    def __init__(self, dup_limit: int = 3, fail_rounds: int = 3):
        self.dup_limit = dup_limit
        self.fail_rounds = fail_rounds
        self._lock = threading.Lock()
        self._recent: dict[str, deque] = defaultdict(lambda: deque(maxlen=16))
        self._cve_attempts: dict[str, set] = defaultdict(set)

    # ---------- 观察（每次真实执行后回填结果） ----------
    def observe(self, challenge_id: str, signature: str, ok: bool,
                snippet: str = "", payload_text: str = "") -> None:
        with self._lock:
            hist = self._recent[challenge_id]
            if ok:
                # 突破解锁（CHYing breakthrough-unlock）：成功方向清除失败记录
                keep = [h for h in hist if h["sig"] != signature]
                hist.clear()
                hist.extend(keep)
            hist.append({
                "sig": signature, "ok": ok,
                "snippet": (snippet or "")[:400],
                # 失败方向关键词只取执行结果（snippet）——payload 代码是攻击者
                # 自己写的，代码片段相似 ≠ 方向失败（实盘 b-03 教训）
                "kws": _extract_keywords(snippet or "") if not ok else set(),
            })
            if payload_text:
                for m in CVE_RE.finditer(payload_text):
                    self._cve_attempts[challenge_id].add(m.group(0).upper())

    # ---------- 三层拦截（工具调用执行前） ----------
    def check(self, challenge_id: str, tool: str, path: str,
              params=None, data=None, payload_text: str = "") -> Optional[str]:
        """返回拦截原因；None = 放行。"""
        sig = call_signature(tool, path, params, data)

        with self._lock:
            hist = list(self._recent[challenge_id])
            tried_cves = set(self._cve_attempts[challenge_id])

        # 层2（签名层，先判：最精确）：同签名连续失败 ≥ dup_limit
        same = [h for h in hist if h["sig"] == sig]
        if len(same) >= self.dup_limit and not any(h["ok"] for h in same[-self.dup_limit:]):
            return f"调用签名 {sig!r} 已连续失败 {len(same)} 次，强制换方向"

        # script 是升级路径：get/post 探测失败恰恰是用脚本深挖的原因，
        # 因此关键词两层对 script 一律豁免（实盘第 10 轮教训：连续 3 次误禁）。
        is_script = str(tool).lower() == "script"
        if not is_script:
            # 层1a（关键词计数）：最近 fail_rounds 轮**全部**失败特征才拦
            # （recon 阶段 404/500 是常态，2/3 就拦会禁掉正常探测）
            window = hist[-self.fail_rounds:]
            fail_hits = sum(
                1 for h in window
                if any(k in h["snippet"].lower() for k in FAILURE_KEYWORDS)
            )
            if len(window) >= self.fail_rounds and fail_hits >= self.fail_rounds:
                return f"最近 {self.fail_rounds} 轮全部为失败特征，强制换方向"

            # 层1b（关键词交集，CHYing _matches_dead_end 语义）：
            # 新调用关键词 ∩ 已确认失败方向关键词 ≥ 2
            call_text = f"{path} {json.dumps(params or {}, ensure_ascii=False)} " \
                        f"{json.dumps(data or {}, ensure_ascii=False)}"
            if str(tool).lower() != "script":
                call_text += f" {payload_text}"
            new_kws = _extract_keywords(call_text)
            dead_kws: set = set()
            for h in hist[-8:]:
                if not h["ok"]:
                    dead_kws |= h["kws"]
            inter = new_kws & dead_kws
            if len(inter) >= 2:
                return f"与已确认失败方向重合 {sorted(inter)[:2]}（关键词交集层）"

        # 层3（CVE 编号层）：同一 CVE 反复换变体
        cves = {m.group(0).upper() for m in CVE_RE.finditer(payload_text or "")}
        if cves and cves <= tried_cves:
            cid = sorted(cves)[0]
            return f"CVE {cid} 已尝试多个变体，换 CVE 或换入口"
        return None

    def reset(self, challenge_id: str) -> None:
        with self._lock:
            self._recent.pop(challenge_id, None)
            self._cve_attempts.pop(challenge_id, None)
