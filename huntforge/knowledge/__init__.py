"""AI 应用攻击知识库（移植自 lingops-agent，保留原始技术内容）。

210 条攻击技术：提示词注入 59 / RAG投毒 36 / 工具越权 33 / API安全 51 / 逻辑绕过 31。
来源：E:\\traexiangmu\\GX-RGZN-SD2\\lingops-agent（作者自有项目，MIT 风格内部复用）。
"""
from .techniques import (API_SEC_TECHNIQUES, LOGIC_BYPASS_TECHNIQUES,
                         PROMPT_INJECTION_TECHNIQUES, RAG_POISON_TECHNIQUES,
                         TOOL_ABUSE_TECHNIQUES)

ALL_TECHNIQUES: dict[str, list[dict]] = {
    "prompt_injection": PROMPT_INJECTION_TECHNIQUES,
    "rag_poisoning": RAG_POISON_TECHNIQUES,
    "tool_abuse": TOOL_ABUSE_TECHNIQUES,
    "api_security": API_SEC_TECHNIQUES,
    "logic_bypass": LOGIC_BYPASS_TECHNIQUES,
}

CATEGORY_LABELS = {
    "prompt_injection": "提示词注入",
    "rag_poisoning": "RAG投毒",
    "tool_abuse": "工具越权",
    "api_security": "API安全",
    "logic_bypass": "逻辑绕过",
}


def all_techniques() -> list[dict]:
    out = []
    for cat, items in ALL_TECHNIQUES.items():
        for t in items:
            out.append({**t, "category": cat})
    return out
