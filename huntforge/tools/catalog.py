"""声明式工具目录（借鉴 VulHunter tools/catalog.py + local-tools.yaml）。

- YAML 为唯一配置源（config/tools.yaml），加载时校验重复 slug / 未知 tier /
  未知 side_effect / timeout 上下界 / 必填占位符。
- tier 决定默认时间盒；phase_scope 挂到 FSM 状态（跨态调用由状态机拒绝）。
- stateful/exploit 级工具调用时需显式授权（allow_side_effects）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TOOLS_YAML = PROJECT_ROOT / "config" / "tools.yaml"

TIERS = ("fingerprint", "quick", "scan", "targeted", "utility", "manual")
SIDE_EFFECTS = ("read-only", "local-write", "stateful", "exploit")
INTEGRATIONS = ("local-python", "local-binary", "kali", "poc", "generator")
RESTRICTED_SIDE_EFFECTS = ("stateful", "exploit")

# tier → 默认时间盒（秒）：fingerprint 最快、targeted 给足
TIER_TIMEOUT = {
    "fingerprint": 20.0,
    "quick": 45.0,
    "scan": 90.0,
    "targeted": 120.0,
    "utility": 30.0,
    "manual": 30.0,
}


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


@dataclass
class ToolRecord:
    slug: str
    title: str = ""
    category: str = "utility"
    tier: str = "quick"
    phase_scope: list = field(default_factory=list)
    side_effect: str = "read-only"
    integration: str = "local-python"
    argv: list = field(default_factory=list)
    required_placeholders: list = field(default_factory=list)
    timeout: float = 0.0
    description: str = ""
    module: str = ""      # local-python / generator 用
    fn: str = ""          # local-python / generator 用
    script: str = ""      # poc 用（相对 tools/ 目录）

    def effective_timeout(self) -> float:
        return self.timeout or TIER_TIMEOUT.get(self.tier, 60.0)


class ToolCatalog:
    def __init__(self, source: Optional[Path] = None):
        self.source = Path(source) if source else TOOLS_YAML
        self.tools: list[ToolRecord] = self._load()

    def _load(self) -> list[ToolRecord]:
        if not self.source.is_file():
            raise ValueError(f"tool catalog missing: {self.source}")
        data = yaml.load(self.source.read_text(encoding="utf-8"),
                         Loader=_UniqueKeyLoader) or {}
        entries = data.get("tools") or []
        records: list[ToolRecord] = []
        seen: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("each tool entry must be a mapping")
            slug = str(entry.get("slug") or "").strip()
            if not slug:
                raise ValueError("tool entry requires non-empty slug")
            if slug in seen:
                raise ValueError(f"duplicate tool slug: {slug}")
            seen.add(slug)
            tier = str(entry.get("tier", "quick")).strip()
            if tier not in TIERS:
                raise ValueError(f"{slug}: unknown tier {tier!r}")
            side_effect = str(entry.get("side_effect", "read-only")).strip()
            if side_effect not in SIDE_EFFECTS:
                raise ValueError(f"{slug}: unknown side_effect {side_effect!r}")
            integration = str(entry.get("integration", "local-python")).strip()
            if integration not in INTEGRATIONS:
                raise ValueError(f"{slug}: unknown integration {integration!r}")
            timeout = float(entry.get("timeout") or 0)
            if not 0 <= timeout <= 600:
                raise ValueError(f"{slug}: timeout out of range: {timeout}")
            required = [str(p) for p in entry.get("required_placeholders", [])]
            records.append(ToolRecord(
                slug=slug,
                title=entry.get("title", slug),
                category=entry.get("category", "utility"),
                tier=tier,
                phase_scope=[str(p) for p in entry.get("phase_scope", [])],
                side_effect=side_effect,
                integration=integration,
                argv=[str(a) for a in entry.get("argv", [])],
                required_placeholders=required,
                timeout=timeout,
                description=entry.get("description", ""),
                module=entry.get("module", ""),
                fn=entry.get("fn", ""),
                script=entry.get("script", ""),
            ))
        return records

    # ---------- 查询 ----------
    def get(self, slug: str) -> Optional[ToolRecord]:
        return next((t for t in self.tools if t.slug == slug), None)

    def for_phase(self, state: str) -> list[ToolRecord]:
        return [t for t in self.tools if state in t.phase_scope]

    def for_tier(self, tier: str) -> list[ToolRecord]:
        return [t for t in self.tools if t.tier == tier]

    def by_integration(self, integration: str) -> list[ToolRecord]:
        return [t for t in self.tools if t.integration == integration]

    def check_placeholders(self, slug: str, values: dict[str, str]) -> list[str]:
        """返回缺失的必填占位符。"""
        rec = self.get(slug)
        if not rec:
            return ["unknown tool"]
        return [p for p in rec.required_placeholders
                if not (values.get(p) or "").strip()]

    def authorize(self, slug: str, allowed: set[str] | list[str] | tuple[str] | None) -> str:
        """stateful/exploit 门禁：未授权返回拒绝原因，通过返回 ''。"""
        rec = self.get(slug)
        if not rec:
            return f"unknown tool: {slug}"
        if rec.side_effect in RESTRICTED_SIDE_EFFECTS:
            allowed_set = set(allowed or [])
            if rec.side_effect not in allowed_set:
                return (f"tool {slug} side_effect={rec.side_effect} 需要显式授权"
                        f"（allow_side_effects={{{rec.side_effect}}}）")
        return ""


# 全局单例（进程内共享；加载失败抛异常让启动尽早暴露配置错误）
CATALOG = ToolCatalog()
