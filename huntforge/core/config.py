"""配置加载：YAML + 环境变量覆盖。

约定：
- config/settings.yaml 为运行时配置，config/llm.yaml 为模型网关配置
- 环境变量 HUNTFORGE_* 覆盖 settings.yaml（如 HUNTFORGE_PLATFORM_BASE_URL）
- 平台注入的 BENCHMARK_BASE_URL / BENCHMARK_TOKEN 优先于 YAML
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SETTINGS = PROJECT_ROOT / "config" / "settings.yaml"
DEFAULT_LLM = PROJECT_ROOT / "config" / "llm.yaml"


def _deep_merge(base: dict, override: dict) -> dict:
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def _flatten_env(prefix: str) -> dict:
    """把 HUNTFORGE_A_B_C=1 展开为 {a: {b: {c: 1}}}。"""
    out: dict = {}
    for key, val in os.environ.items():
        if not key.startswith(prefix):
            continue
        parts = key[len(prefix):].lower().split("_")
        node = out
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = val
    return out


class Config:
    def __init__(self, settings_path: Path = DEFAULT_SETTINGS, llm_path: Path = DEFAULT_LLM):
        self.settings_path = Path(settings_path)
        self.llm_path = Path(llm_path)
        self.data: dict = self._load()
        self.llm: dict = self._load_llm()

    # ---------- 加载 ----------
    def _load(self) -> dict:
        cfg: dict = yaml.safe_load(self.settings_path.read_text(encoding="utf-8")) or {}
        cfg = _deep_merge(cfg, _flatten_env("HUNTFORGE_"))
        return cfg

    def _load_llm(self) -> dict:
        cfg: dict = yaml.safe_load(self.llm_path.read_text(encoding="utf-8")) or {}
        gw_env = os.environ.get("HUNTFORGE_GATEWAY")
        if gw_env is not None:
            cfg.setdefault("gateway", {})["enabled"] = gw_env.lower() in ("1", "true", "yes")
        return cfg

    # ---------- 便捷访问 ----------
    def section(self, name: str) -> dict:
        return self.data.get(name, {}) or {}

    @property
    def platform(self) -> dict:
        return self.section("platform")

    @property
    def scheduler(self) -> dict:
        return self.section("scheduler")

    @property
    def submission(self) -> dict:
        return self.section("submission")

    @property
    def agent(self) -> dict:
        return self.section("agent")

    @property
    def db_path(self) -> Path:
        p = self.data.get("paths", {}).get("db")
        if p:
            return Path(p)
        return PROJECT_ROOT / "data" / "huntforge.db"

    @property
    def bench_base_url(self) -> str | None:
        """平台地址：环境变量 > YAML。未配置返回 None（回退 mock）。"""
        env = os.environ.get("BENCHMARK_BASE_URL")
        if env:
            return env.rstrip("/")
        return (self.platform.get("base_url") or "").rstrip("/") or None

    @property
    def bench_token(self) -> str | None:
        return os.environ.get("BENCHMARK_TOKEN") or self.platform.get("token") or None


def load() -> Config:
    return Config()
