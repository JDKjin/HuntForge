"""区块链 agent 测试：规则扫描 + 源码 flag。"""
import pytest

from huntforge.agents.blockchain_ops import BlockchainOpsAgent


class FakePlanner:
    def audit_contract(self, source):
        return {
            "flag_in_source": "flag{solidity_reentrancy_vulnerability}",
            "critical_vulns": [{"type": "reentrancy", "location": "withdraw", "description": "x"}],
            "flag_access_path": "call secret",
            "required_calls": ["deposit(1)", "secret()"],
        }


def _src():
    from pathlib import Path
    return Path("data/mock/vault.sol").read_text(encoding="utf-8")


def test_rule_scan_finds_reentrancy():
    agent = BlockchainOpsAgent.__new__(BlockchainOpsAgent)
    matches = agent._scan(_src())
    vulns = {v for _, v, _, _ in matches}
    assert "reentrancy" in vulns        # call{value} 先转后更新
    assert "integer_overflow" in vulns  # 0.6.12 无 SafeMath
    assert "logic_withdraw" in vulns    # withdraw 未用防护


def test_rule_scan_detects_tx_origin():
    agent = BlockchainOpsAgent.__new__(BlockchainOpsAgent)
    matches = agent._scan("contract X { function f() { require(tx.origin == owner); } }")
    assert any(v == "tx_origin_auth" for _, v, _, _ in matches)


def test_flag_in_source(db):
    from huntforge.bench.mock_server import FLAGS
    import tempfile, os
    from pathlib import Path
    from huntforge.core.state import StateDB
    db = StateDB(os.path.join(tempfile.mkdtemp(), "t.db"))
    db.upsert_challenge({"id": "chain-demo", "title": "c", "category": "blockchain",
                         "difficulty": "medium",
                         "target": str(Path("data/mock/vault.sol").resolve())})
    submitted = []
    agent = BlockchainOpsAgent(db, timebox=60,
                               submitter=lambda c, v: submitted.append((c, v)),
                               planner=FakePlanner())
    r = agent.run({"id": 1, "challenge_id": "chain-demo", "agent_type": "chain-ops"})
    assert r["flags"] >= 1
    assert submitted[0][1] == FLAGS["chain-demo"]
    assert r["matches"] >= 3
    db.close()
