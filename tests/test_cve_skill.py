"""CVE 引擎 / 经验库 skills / LLM 现场 POC 测试。"""
import pytest

from huntforge.knowledge import cve_engine


def test_cve_db_loads():
    db = cve_engine.load_db()
    assert len(db) >= 70
    cves = {e["cve"] for e in db}
    assert "CVE-2021-44228" in cves and "CVE-2022-22965" in cves
    # 国产 OA 定向条目（离线 CVE 库核心）
    assert "WEAVER-BSHSERVLET-RCE" in cves
    assert "TONGDA-OA-UPLOAD-RCE" in cves
    assert "YONYOU-NC-FILEREAD" in cves


def test_cve_index_and_templates():
    idx = cve_engine.load_index()
    assert len(idx) >= 4000   # nuclei-templates 生成的离线索引
    tpls = cve_engine.cve_templates("CVE-2021-44228")
    assert tpls and all(t.endswith(".yaml") or t.endswith(".yml") for t in tpls)


def test_match_cves():
    hits = cve_engine.match_cves(body="Weaver e-cology login 泛微系统")
    assert hits and hits[0]["severity"] in ("critical", "high")
    assert hits[0]["product"] and "泛微" in hits[0]["product"] or "weaver" in str(hits[0].get("patterns"))
    assert cve_engine.match_cves(body="nothing special here") == []
    # 严重度排序：log4j(critical) 应排在 spring(high) 前
    hits2 = cve_engine.match_cves(headers_blob="x-application-context: log4j")
    assert hits2 and hits2[0]["severity"] == "critical"


def test_run_payload_offline_no_crash(db):
    cand = cve_engine.run_payload(db, "c1", "http://127.0.0.1:9",
                                  {"cve": "CVE-X", "product": "t",
                                   "payloads": [{"method": "GET", "path": "/x"}]})
    assert cand is None  # 死目标：优雅返回无 flag


def test_cve_briefs_shape():
    briefs = cve_engine.cve_briefs(body="apache tomcat server", limit=2)
    assert all("cve" in b and "attack" in b for b in briefs)


def test_skill_archive_and_match(db, tmp_path, monkeypatch):
    from huntforge.knowledge import skill_store
    # 归档现在写运行时目录（去答案化：代码库/镜像不包含题目解法）
    monkeypatch.setenv("HUNTFORGE_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    db.upsert_challenge({"id": "sk-1", "title": "云函数配置泄露", "category": "web",
                         "difficulty": "easy", "target": "http://x", "status": "solved"})
    db.upsert_fact("sk-1", "GET /api/functions",
                   {"status": 200, "snippet": "function list leaked"}, confidence=1.0)
    db.add_finding("sk-1", None, "unauth", 0.9,
                   {"request": "GET /api/functions", "response": "flag{x}"})
    p = skill_store.archive_challenge(db, "sk-1")
    assert p and p.is_file()
    # 归档落在运行时目录，而不是通用手册目录
    assert "artifacts" in str(p) and not str(p).startswith(str(skill_store.SKILLS_DIR))
    hits = skill_store.match_skills("云函数 未授权 api/functions 配置泄露", limit=2)
    assert hits and hits[0]["slug"] == "sk-1"
    # 不相关内容不召回（evm-anvil-attacks 手册已覆盖区块链主题，负面用例
    # 换成与安全完全无关的话题）
    assert skill_store.match_skills("量子通信 轨道卫星 航天器轨道", limit=2) == []


def test_compose_exploit_shape():
    from huntforge.llm.planner import PentestPlanner

    class DGW:
        def chat_json(self, messages, tier="standard"):
            assert messages[0]["role"] == "system" and messages[1]["role"] == "user"
            assert "CVE-X" in messages[1]["content"]
            return {"next_action": "script",
                    "script": 'print("FLAG", "flag{x}")', "reason": "r"}

    out = PentestPlanner(DGW()).compose_exploit(
        {"cve": "CVE-X", "product": "p", "attack": "a", "severity": "high"},
        "http://x", [])
    assert out["next_action"] == "script" and "FLAG" in out["script"]


def test_kali_file_placeholder_rejects_missing(monkeypatch):
    from huntforge.tools import kali
    monkeypatch.setenv("HUNTFORGE_KALI", "1")
    r = kali.run("kali_checksec", "E:\\no\\such\\file.bin", timeout=5)
    assert not r["ok"] and "file not found" in r["error"]
