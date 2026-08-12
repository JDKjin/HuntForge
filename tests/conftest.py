import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("HUNTFORGE_GATEWAY", "0")


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / "test.db"


@pytest.fixture()
def db(db_path):
    from huntforge.core.state import StateDB
    s = StateDB(db_path)
    yield s
    s.close()


@pytest.fixture()
def sample_challenge():
    return {"id": "test-1", "title": "T1", "category": "web",
            "difficulty": "easy", "target": "http://127.0.0.1:9/"}
