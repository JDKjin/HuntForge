"""二进制分析 agent 测试（strings/魔数/危险函数）。"""
import pytest

from huntforge.bench.mock_server import MockBench
from huntforge.agents.binary_ops import _extract_strings, _identify_format


@pytest.fixture(scope="module")
def mb():
    m = MockBench()
    m.start()
    yield m
    m.stop()


class FakePlanner:
    def audit_binary(self, fmt, strings, dangerous):
        return {
            "flag_found": None,
            "encoded_hint": "xor",
            "decoded_flag": "flag{binary_strings_reveal_secret}",
            "vuln_path": "strings lead to secret",
            "exploit_hint": "decode",
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
