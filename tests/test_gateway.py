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


def test_extract_json():
    from huntforge.llm.gateway import _extract_json
    assert _extract_json('{"a": 1}') == {"a": 1}
    assert _extract_json('```json\n{"a": {"b": 2}}\n```') == {"a": {"b": 2}}
    with pytest.raises(Exception):
        _extract_json("no json here")
