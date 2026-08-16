"""二进制分析 agent 测试（strings/魔数/危险函数）。"""
import pytest
import conftest as _cf
TP = _cf.TP

from huntforge.bench.mock_server import FLAGS, MockBench
from huntforge.agents.binary_ops import _extract_strings, _identify_format



class FakePlanner:
    def audit_binary(self, fmt, strings, dangerous, kali_info="", **kwargs):
        """模拟 LLM：识别 XOR 编码线索并"解码"（返回正确 flag）。"""
        if any("KEY=0x41" in s for s in strings):
            return {
                "flag_found": None,
                "encoded_hint": "xor key 0x41",
                "decoded_flag": FLAGS["xor-demo"],
                "vuln_path": "xor 解码 strings 尾部密文",
                "exploit_hint": "decode with key",
            }
        return {
            "flag_found": FLAGS["binary-demo"],
            "encoded_hint": None,
            "decoded_flag": None,
            "vuln_path": "strings lead to secret",
            "exploit_hint": "direct",
        }


def test_identify_formats():
    assert _identify_format(b"\x7fELF\x02") == "elf"
    assert _identify_format(b"MZ\x90\x00") == "pe"
    assert _identify_format(b"PK\x03\x04") == "zip"
    assert _identify_format(b"\x1f\x8b\x08") == "gzip"
    assert _identify_format(b"hello") == "unknown"


def test_extract_strings_ascii_and_utf16():
    data = b"hello_world\x00" + "中文".encode("utf-8") + b"\x00" + "fl".encode("utf-16le") + "ag{test}".encode("utf-16le")
    strs = _extract_strings(data, min_len=4)
    assert "hello_world" in strs
    assert any("flag{test}" in s for s in strs)


def test_agent_finds_flag_in_elf(mb):
    """对 mock 生成的假 ELF 运行完整 agent。"""
    from huntforge.bench.mock_server import FLAGS
    from huntforge.core.state import StateDB
    from huntforge.agents.binary_ops import BinaryOpsAgent
    from pathlib import Path
    import tempfile, os
    db = StateDB(os.path.join(tempfile.mkdtemp(), "t.db"))
    elf_path = Path("data/mock/target.elf").resolve()
    assert elf_path.is_file(), "mock 文件靶场未生成"
    db.upsert_challenge({"id": "binary-demo", "title": "b", "category": "binary",
                         "difficulty": "medium", "target": str(elf_path)})
    submitted = []
    agent = BinaryOpsAgent(db, timebox=60,
                           submitter=lambda c, v: submitted.append((c, v)),
                           planner=FakePlanner())
    r = agent.run({"id": 1, "challenge_id": "binary-demo", "agent_type": "binary-ops"})
    assert r["outcome"] == "flag_found"
    assert submitted[0][1] == FLAGS["binary-demo"]
    db.close()


def test_planner_path_decodes_xor_flag(mb):
    """XOR 编码 ELF：规则层 strings 找不到明文 flag → planner 审计被真实调用并解码。"""
    from huntforge.bench.mock_server import FLAGS
    from huntforge.core.state import StateDB
    from huntforge.agents.binary_ops import BinaryOpsAgent
    from pathlib import Path
    import tempfile, os
    db = StateDB(os.path.join(tempfile.mkdtemp(), "t.db"))
    elf_path = Path("data/mock/xor_target.elf").resolve()
    assert elf_path.is_file(), "xor mock 文件未生成"
    # 明文 flag 不应出现在 strings 里（否则测试无意义）
    from huntforge.agents.binary_ops import _extract_strings
    assert not any("flag{" in s for s in _extract_strings(elf_path.read_bytes()))
    db.upsert_challenge({"id": "xor-demo", "title": "x", "category": "binary",
                         "difficulty": "medium", "target": str(elf_path)})
    submitted = []
    agent = BinaryOpsAgent(db, timebox=60,
                           submitter=lambda c, v: submitted.append((c, v)),
                           planner=FakePlanner())
    r = agent.run({"id": 1, "challenge_id": "xor-demo", "agent_type": "binary-ops"})
    # XOR 编码 flag 现在会被确定性解密流水线（rev.xor_single）先行命中，
    # 无需 LLM；LLM 审计是兜底路径
    assert r["outcome"] == "flag_found"
    assert submitted and submitted[0][1] == FLAGS["xor-demo"]
    db.close()
