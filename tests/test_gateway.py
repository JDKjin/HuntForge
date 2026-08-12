"""模型网关测试：URL 重写、tier 可用性、JSON 提取。"""
import pytest


def _gw(enabled=True, env=None, monkeypatch=None):
    from huntforge.llm.gateway import ModelGateway
    if monkeypatch and env:
        for k, v in env.items():
            monkeypatch.setenv(k, v)
    cfg = {
        "gateway": {"enabled": enabled, "suffix": ".tsecbench.gw", "force_http": True},
        "tiers": {
            "fast": [{"id": "m-fast", "base_url": "https://api.deepseek.com/v1",
                      "api_key_env": "K1"}],
            "deep": [{"id": "m-deep", "base_url": "https://api.xxx.cn/v1",
                      "api_key_env": "K2"}],
        },
        "chat": {"timeout": 5},
    }
    return ModelGateway(cfg)


def test_rewrite_url_enabled():
    gw = _gw(enabled=True)
    assert gw._rewrite_url("https://api.deepseek.com/v1") == \
        "http://api.deepseek.com.tsecbench.gw/v1"
    assert gw._rewrite_url("http://open.bigmodel.cn/api/paas/v4") == \
        "http://open.bigmodel.cn.tsecbench.gw/api/paas/v4"


def test_rewrite_url_disabled():
    gw = _gw(enabled=False)
    assert gw._rewrite_url("https://api.deepseek.com/v1") == "https://api.deepseek.com/v1"


def test_tier_requires_key(monkeypatch):
    gw = _gw(enabled=True, env={"K1": "sk-1"}, monkeypatch=monkeypatch)
    models = gw._tier_models("fast")
    assert len(models) == 1 and models[0]["base_url"] == \
        "http://api.deepseek.com.tsecbench.gw/v1"
    assert gw._tier_models("deep") == []  # K2 未设 → 不可用
    assert gw._available_tier("deep") == "fast"  # 降级到 fast


def test_no_key_raises(monkeypatch):
    gw = _gw(enabled=True, monkeypatch=monkeypatch)
    from huntforge.llm.gateway import NoModelConfigured
    with pytest.raises(NoModelConfigured):
        gw.chat([{"role": "user", "content": "hi"}])


def test_usage_recorded(monkeypatch, db):
    from huntforge.llm.gateway import ModelGateway

    monkeypatch.setenv("K1", "sk-1")
    gw = ModelGateway({
        "gateway": {"enabled": False},
        "tiers": {"fast": [{"id": "m-fast", "base_url": "http://x", "api_key_env": "K1"}]},
        "chat": {"timeout": 1},
    }, db=db, task_id=7)

    class Resp:
        status_code = 200

        def json(self):
            return {
                "choices": [{"message": {"content": "{\"ok\": true}"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 4, "prompt_tokens_details": {"cached_tokens": 1}},
            }

    monkeypatch.setattr("huntforge.llm.gateway.requests.post", lambda *a, **k: Resp())
    out = gw.chat_json([{"role": "user", "content": "hi"}], tier="fast")
    assert out == {"ok": True}
    usage = db.usage_summary()
    assert usage["calls"] == 1
    assert usage["in_t"] == 3
    assert usage["out_t"] == 4
    assert usage["cache_t"] == 1


def test_empty_content_retry(monkeypatch, db):
    """推理模型偶发把 max_tokens 耗在 reasoning 上返回空 content —— 应翻倍重试且都计量。"""
    from huntforge.llm.gateway import ModelGateway

    monkeypatch.setenv("K1", "sk-1")
    gw = ModelGateway({
        "gateway": {"enabled": False},
        "tiers": {"fast": [{"id": "m-fast", "base_url": "http://x", "api_key_env": "K1"}]},
        "chat": {"timeout": 1},
    }, db=db)

    calls = {"n": 0, "max_tokens_seen": []}

    class Resp:
        status_code = 200

        def __init__(self, content):
            self._content = content

        def json(self):
            return {
                "choices": [{"message": {"content": self._content}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }

    def fake_post(url, *a, **k):
        calls["n"] += 1
        calls["max_tokens_seen"].append(k["json"]["max_tokens"])
        return Resp("" if calls["n"] == 1 else '{"ok": true}')

    monkeypatch.setattr("huntforge.llm.gateway.requests.post", fake_post)
    out = gw.chat_json([{"role": "user", "content": "hi"}], tier="fast")
    assert out == {"ok": True}
    assert calls["n"] == 2
    assert calls["max_tokens_seen"] == [2048, 4096]
    assert db.usage_summary()["calls"] == 2  # 重试消耗也入账


def test_call_budget_exhausted(monkeypatch):
    from huntforge.llm.gateway import ModelGateway, LLMError

    monkeypatch.setenv("K1", "sk-1")
    gw = ModelGateway({
        "gateway": {"enabled": False},
        "per_challenge_call_budget": 0,
        "tiers": {"fast": [{"id": "m-fast", "base_url": "http://x", "api_key_env": "K1"}]},
        "chat": {"timeout": 1},
    })
    with pytest.raises(LLMError):
        gw.chat([{"role": "user", "content": "hi"}], tier="fast")


def test_extract_json():
    from huntforge.llm.gateway import _extract_json
    assert _extract_json('{"a": 1}') == {"a": 1}
    assert _extract_json('```json\n{"a": {"b": 2}}\n```') == {"a": {"b": 2}}
    with pytest.raises(Exception):
        _extract_json("no json here")
