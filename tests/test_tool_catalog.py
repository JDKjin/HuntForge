"""工具目录 / 定向 POC / quick 生成器 / MCP 目录化测试。"""
import pytest

from huntforge.tools.catalog import CATALOG, ToolCatalog


def test_catalog_loads_and_validates():
    assert CATALOG.get("kali_katana") is not None
    assert CATALOG.get("poc_shiro") is not None
    assert CATALOG.get("gen_deser") is not None
    # 重复 slug 应抛错
    import tempfile
    from pathlib import Path
    bad = Path(tempfile.mkdtemp()) / "bad.yaml"
    bad.write_text("tools:\n- slug: a\n- slug: a\n", encoding="utf-8")
    with pytest.raises(ValueError):
        ToolCatalog(source=bad)


def test_tier_timebox_and_phase_scope():
    rec = CATALOG.get("kali_nmap_top")
    assert rec.tier == "quick" and rec.effective_timeout() == 90.0  # 显式 timeout 优先于 tier 默认
    assert rec.slug in {t.slug for t in CATALOG.for_phase("exploring")}
    assert "poc_shiro" in {t.slug for t in CATALOG.for_phase("exploiting")}
    assert "poc_shiro" not in {t.slug for t in CATALOG.for_phase("exploring")}


def test_side_effect_gate():
    assert CATALOG.authorize("poc_shiro", None) != ""          # exploit 未授权 → 拒绝
    assert CATALOG.authorize("poc_shiro", {"exploit"}) == ""   # 显式授权 → 通过
    assert CATALOG.authorize("kali_katana", None) == ""        # read-only 直接放行


def test_placeholder_check():
    assert CATALOG.check_placeholders("kali_katana", {"target": ""}) == ["target"]
    assert CATALOG.check_placeholders("kali_katana", {"target": "x"}) == []


def test_quick_generators_offline():
    from huntforge.tools import call_tool
    # deser_gen（nodejs IIFE）：纯本地生成，不依赖外部工具
    r = call_tool("gen_deser", format="node", cmd="id")
    assert r.get("ok")
    assert r.get("format") == "nodejs" and "ND_FUNC" in (r.get("payload_raw") or "")
    # pickle_gen 需要 target（本机地址即可，只生成不连）
    r2 = call_tool("gen_pickle", target="127.0.0.1:9", cmd="id")
    assert isinstance(r2, dict) and (r2.get("ok") or "raw" in r2 or "error" in r2)
    # 未授权 exploit 门禁
    r3 = call_tool("poc_shiro", target="http://127.0.0.1:9")
    assert not r3["ok"] and "授权" in r3["error"]


def test_targeted_matchers_no_network():
    from huntforge.tools.targeted import TARGETED_RULES, run_targeted
    for name, slugs, matcher in TARGETED_RULES:
        assert matcher([name], "") or name != "shiro"  # 指纹命中判定可用
    # 无指纹命中 → 不执行任何 POC（离线安全）
    cands = run_targeted(None, "http://127.0.0.1:9", [], "", budget=5)
    assert cands == []


def test_poc_scripts_exist_on_disk():
    """实战教训：YAML script 曾带 pocs/ 前缀导致 _POC_DIR 拼接出
    pocs\pocs\... 而全部 POC 哑火。此处断言每个 poc_* 记录的解析路径
    真实存在于磁盘，杜绝静默回归。"""
    from pathlib import Path
    from huntforge.tools.targeted import _POC_DIR, _resolve_script
    for slug in ("poc_shiro", "poc_springboot", "poc_seeyon", "poc_weaver_sqli"):
        rec = CATALOG.get(slug)
        assert rec is not None, slug
        p = _resolve_script(rec)
        assert p.is_file(), f"{slug}: {p} 不存在（检查 tools.yaml script 是否误带 pocs/ 前缀）"
        assert str(p).count(str(Path("pocs"))) == 1, f"{slug}: 路径拼接异常 {p}"


def test_mcp_lists_catalog_tools():
    from scripts import mcp_server
    r = mcp_server.handle("tools/list", None, 1)
    names = [t["name"] for t in r["result"]["tools"]]
    for slug in ("kali_katana", "poc_shiro", "poc_springboot", "poc_seeyon",
                 "gen_deser", "gen_jwt_forge"):
        assert slug in names, slug
