"""区块链漏洞挖掘 Agent：Solidity 源码静态规则扫描 → LLM 链上逻辑审查（可选）。

规则库内置（重入/tx.origin/整数溢出/权限/delegatecall），零 LLM 可跑通。
目标形态：.sol 文件路径或 URL。
"""
from __future__ import annotations

import logging
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

from ..core.state import StateDB
from ..web.gate import evaluate_and_persist

log = logging.getLogger("huntforge.chain")

# (模式, 漏洞类型, 影响, 严重度)
RULES: list[tuple[re.Pattern, str, str, float]] = [
    (re.compile(r"\.call\{value:.*?\}", re.S), "reentrancy",
     "外部调用后若先转出资产后更新状态，可重入攻击", 0.9),
    (re.compile(r"\.transfer\(|\.send\(", re.S), "reentrancy",
     "transfer/send 外部调用，若状态更新在调用后存在重入面", 0.6),
    (re.compile(r"tx\.origin", re.I), "tx_origin_auth",
     "tx.origin 鉴权可被中间合约欺骗（钓鱼攻击）", 0.8),
    (re.compile(r"delegatecall", re.I), "delegatecall",
     "delegatecall 执行任意合约代码，存储布局不一致可致状态破坏", 0.85),
    (re.compile(r"selfdestruct|suicide", re.I), "selfdestruct",
     "合约可自毁，资金销毁或逻辑作废", 0.7),
    (re.compile(r"block\.timestamp|block\.number", re.I), "unpredictable_random",
     "基于区块时间/高度的随机数可被矿工操纵", 0.6),
    (re.compile(r"function\s+withdraw", re.I), "logic_withdraw",
     "withdraw 函数需审计余额检查与重入防护", 0.6),
    (re.compile(r"require\(msg\.sender\s*==\s*owner\)", re.I), "centralized_owner",
     "单 owner 权限集中，私钥泄露即全仓风险", 0.4),
]

# 0.8+ 内置溢出检查；低于则无 SafeMath 时提示
SOL_0_8 = re.compile(r"pragma\s+solidity\s*(>=|\^)?\s*0\.8", re.I)
SAFEMATH = re.compile(r"SafeMath|unchecked\s*\{", re.I)
ARITH = re.compile(r"\+\s*=|-\s*=|\*\s*=|/=", re.I)


class BlockchainOpsAgent:
    def __init__(self, db: StateDB, timebox: float = 300.0,
                 submitter: Optional[Callable[[str, str], None]] = None,
                 gateway=None, planner=None):
        self.db = db
        self.timebox = timebox
        self.submitter = submitter
        self.gateway = gateway
        self.planner = planner
        self._started = 0.0

    def run(self, task: dict) -> dict:
        ch = self.db.get_challenge(task["challenge_id"])
        if ch is None:
            return {"ok": False, "outcome": "no_challenge"}
        self._started = time.time()
        target = ch.get("target") or ""

        tmp = tempfile.mkdtemp(prefix="hf-sol-")
        try:
            src = self._acquire(target, tmp)
            if src is None:
                return {"ok": True, "outcome": "acquire_failed"}

            matches = self._scan(src)
            candidates = []
            from ..web.common import extract_flag

            # 1) 源码直接搜索 flag（规则层）
            flag = extract_flag(src)
            if flag:
                candidates.append({
                    "type": "flag_in_source", "confidence": 0.95,
                    "request": "Solidity 源码扫描",
                    "response": flag,
                    "impact": "合约源码直接包含 flag（硬编码泄露）",
                    "value": flag,
                    "confirm": {"note": "源码文本命中"},
                })

            # 2) 规则扫描漏洞
            for pattern, vuln, impact, conf in matches:
                candidates.append({
                    "type": vuln, "confidence": conf,
                    "request": f"Solidity 静态规则扫描 {pattern}",
                    "response": f"命中行: {pattern}",
                    "impact": impact,
                    "confirm": {"note": "规则命中（规则库内置）"},
                })

            # 3) LLM 语义审计（规则找不到 flag 时才调用）
            llm_used = False
            if self.planner and not flag and self._time_left() > 5:
                llm_used = True
                llm_result = self.planner.audit_contract(src)
                if llm_result:
                    self.db.event("llm.contract_audit", "challenge", ch["id"],
                                  {"flag_found": llm_result.get("flag_in_source"),
                                   "vulns": len(llm_result.get("critical_vulns", []))})
                    # LLM 在源码中找到 flag
                    llm_flag = llm_result.get("flag_in_source")
                    flag_value = extract_flag(llm_flag or "")
                    if flag_value:
                        candidates.append({
                            "type": "flag_llm_found", "confidence": 0.90,
                            "request": "LLM 合约语义审计",
                            "response": llm_flag,
                            "impact": "LLM 在合约中识别出 flag",
                            "value": flag_value,
                            "confirm": {"note": "LLM 深度语义分析"},
                        })
                    # LLM 找到漏洞利用路径
                    for vuln in llm_result.get("critical_vulns", [])[:3]:
                        candidates.append({
                            "type": "contract_" + str(vuln.get("type", "vuln"))[:30],
                            "confidence": 0.7,
                            "request": "LLM 合约审计",
                            "response": str(vuln.get("description", ""))[:400],
                            "impact": f"LLM 识别漏洞: {vuln.get('type', '未知')}: {vuln.get('location', '')}",
                            "confirm": {"note": llm_result.get("flag_access_path", "")[:100]},
                        })

            findings = self._persist(ch, task["id"], candidates)
            return {
                "ok": True,
                "outcome": "analyzed",
                "matches": len(matches),
                "llm_used": llm_used,
                **findings,
            }
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _acquire(self, target: str, tmp: str) -> Optional[str]:
        if target.startswith(("http://", "https://")):
            import requests
            try:
                r = requests.get(target, timeout=15, verify=False)
                if r.status_code != 200:
                    return None
                return r.text
            except requests.RequestException:
                return None
        p = Path(target)
        if p.is_file():
            return p.read_text(encoding="utf-8", errors="replace")
        if Path(target).exists():
            return Path(target).read_text(encoding="utf-8", errors="replace")
        return None

    def _scan(self, src: str) -> list[tuple[re.Pattern, str, str, float]]:
        out = []
        seen: set[str] = set()
        for pattern, vuln, impact, conf in RULES:
            if pattern.search(src) and vuln not in seen:
                out.append((pattern, vuln, impact, conf))
                seen.add(vuln)
        # 溢出检查：非 0.8+ 且无 SafeMath 且存在算术赋值
        if not SOL_0_8.search(src) and not SAFEMATH.search(src) and ARITH.search(src):
            out.append((ARITH, "integer_overflow",
                        "未启用 SafeMath 且 pragma <0.8，算术运算存在整数溢出风险", 0.7))
        return out

    def _persist(self, ch: dict, task_id: int, candidates: list[dict]) -> dict:
        n_verified = n_flag = 0
        for c in candidates:
            fid = self.db.add_finding(
                ch["id"], task_id, c["type"], c["confidence"],
                {k: v for k, v in c.items() if k != "value"},
            )
            result = evaluate_and_persist(self.db, fid, {**c, "url": ch.get("target", "")})
            if result.passed:
                n_verified += 1
                self.db.put_memory("hit", f"blockchain:{c['type']}", {"how": "rule"})
            if c.get("value") and result.passed:
                n_flag += 1
                if self.submitter:
                    self.submitter(ch["id"], c["value"])
        return {"verified": n_verified, "flags": n_flag}

    def _time_left(self) -> float:
        return self.timebox - (time.time() - self._started)
