"""HuntForge (铸猎) - 参赛 AI 漏洞挖掘 Agent。

架构：规则调度器权威 + LLM 决策分层 + 平台答题 API 适配 + SQLite 唯一事实源。
双模式：自动化实盘 runner（LiveRunner）与 Claude Code 驾驶舱（driver CLI +
MCP 工具链 + 通用方法论知识库）。
"""

__version__ = "0.2.0"
