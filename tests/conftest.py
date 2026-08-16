"""共享测试夹具：session 级 MockBench（偏移端口组）。

历史 flaky 根治：此前 6 个测试模块各自以 module scope 启动同端口组的
MockBench，全量顺序执行时 TIME_WAIT 端口争用导致间歇失败。现在全测试
会话共享一个实例（偏移端口组 191xx），test_e2e 内部 run(mock=True)
使用默认 190xx 组，互不冲突。
"""
import os
import tempfile

import pytest

# LiveRunner 默认把状态库持久化到项目 .huntforge/live.db；测试必须隔离，
# 否则跨测试/跨运行残留的尝试计数与冷却会互相污染（在导入前设置）。
_TMP_ROOT = tempfile.mkdtemp(prefix="hf-tests-")
os.environ.setdefault("HUNTFORGE_LIVE_DB",
                      os.path.join(_TMP_ROOT, "live-test.db"))
# 测试全程禁止加载项目真实 .env（防止真实平台地址/密钥泄漏进 mock 评测，
# test_driver 曾因此把 e2e 的 mock 模式打到真实平台）。
os.environ["HUNTFORGE_NO_DOTENV"] = "1"

from huntforge.bench.mock_server import FLAGS, PLATFORM_PORT, MockBench, TARGET_PORTS

# 偏移端口组（避免与 test_e2e 内部 MockBench 的默认组争用）
TP = {k: v + 100 for k, v in TARGET_PORTS.items()}


@pytest.fixture(scope="session")
def mb():
    m = MockBench(platform_port=PLATFORM_PORT + 100, target_ports=TP)
    m.start()
    yield m
    m.stop()


@pytest.fixture(scope="session")
def mock_ports():
    return TP


@pytest.fixture(scope="session")
def mock_flags():
    return FLAGS


@pytest.fixture()
def db(tmp_path):
    """每个测试独立的临时状态库。"""
    from huntforge.core.state import StateDB
    s = StateDB(tmp_path / "t.db")
    yield s
    s.close()


@pytest.fixture()
def db_path(db):
    return str(db.path)


@pytest.fixture()
def sample_challenge():
    return {
        "id": "test-1", "title": "T1", "category": "web",
        "difficulty": "easy", "status": "pending",
        "target": "http://127.0.0.1:9",
    }
