"""经验库（借鉴 VulHunter skeleton_store 设计）：成功解题 → 自动归档 skill。

- 归档：从 solved 挑战的黑板 Facts + Findings + 提交记录生成 skill.md
  （指纹 → 路径 → payload → flag 链），落在**运行时目录**
  （HUNTFORGE_ARTIFACTS_DIR/artifacts/<code>/skill.md）——绝不写进
  knowledge/skills/：后者只存通用方法论，防止把某场题目的解法预置进
  代码库/镜像（换题即失效且违反去答案化原则）。
- 召回：按题面文本匹配（字母数字 token + CJK 双字组重合打分），
  取 top-2 以摘要形式注入 planner（复用 lessons 管道）。通用手册
  （skills/*.md）+ 运行时归档（artifacts/*/skill.md）都会扫描。
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

SKILLS_DIR = Path(__file__).resolve().parent / "skills"

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_./-]{3,}")


def _cjk_bigrams(text: str) -> set[str]:
    """中文双字组（滑动窗口，覆盖重叠词组）。"""
    s = "".join(ch for ch in text if "\u4e00" <= ch <= "\u9fff")
    return {s[i:i + 2] for i in range(len(s) - 1)}


def _tokens(text: str) -> set[str]:
    toks = {t.lower() for t in _TOKEN_RE.findall(text or "")}
    return toks | _cjk_bigrams(text or "")


def archive_challenge(db, challenge_id: str) -> Optional[Path]:
    """把一道已解出的题目归档为 skill。返回文件路径或 None。"""
    ch = db.get_challenge(challenge_id)
    if not ch or ch.get("status") != "solved":
        return None
    facts = db.list_facts(challenge_id)
    findings = db.list_findings(challenge_id)
    subs = [s for s in db.list_submissions(challenge_id)
            if s.get("status") == "accepted"]
    if not (facts or findings):
        return None
    tags = sorted({str(t) for t in (ch.get("category", "web"),
                                    ch.get("difficulty", "medium"))})
    lines = [
        "---",
        f"slug: {challenge_id}",
        f"tags: [{', '.join(tags)}]",
        f"title: {ch.get('title', '')[:80]}",
        "---",
        f"# {ch.get('title', '')}",
        "",
        "## 攻击链（真实解题记录）",
        "",
        "### 关键事实",
    ]
    for f in facts[:15]:
        p = f.get("payload") or {}
        lines.append(f"- {f['key']}: status={p.get('status')} "
                     f"{(p.get('snippet') or '')[:100]}")
    lines += ["", "### 漏洞发现"]
    for fd in findings[:10]:
        ev = fd.get("evidence") or {}
        lines.append(f"- [{fd['status']}] {fd['vuln_type']} conf={fd['confidence']:.2f}")
        if ev.get("request"):
            lines.append(f"  - request: {str(ev['request'])[:160]}")
    lines += ["", "### 提交结果"]
    for s in subs:
        lines.append(f"- accepted (value 脱敏 {s.get('value', '')[:12]}…)")
    # 运行时归档目录（镜像/代码库不包含——去答案化原则）
    base = Path(os.environ.get("HUNTFORGE_ARTIFACTS_DIR", "artifacts"))
    path = base / f"{challenge_id}" / "skill.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _runtime_skill_files() -> list[Path]:
    """运行时归档的 skill 文件（artifacts/<code>/skill.md）。"""
    base = Path(os.environ.get("HUNTFORGE_ARTIFACTS_DIR", "artifacts"))
    if not base.is_dir():
        return []
    return sorted(base.glob("*/skill.md"))


def match_skills(query: str, limit: int = 2) -> list[dict]:
    """按题面文本召回相关 skills，返回 [{slug, summary, path}]。

    扫描通用手册（skills/*.md）+ 运行时归档（artifacts/*/skill.md）。
    """
    files = list(SKILLS_DIR.glob("*.md")) if SKILLS_DIR.is_dir() else []
    files += _runtime_skill_files()
    q_tokens = _tokens(query or "")
    if not q_tokens:
        return []
    scored = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
        except OSError:
            continue
        body = text.split("---", 2)[-1]
        s_tokens = _tokens(body)
        score = len(q_tokens & s_tokens)
        if score >= 2:
            # 运行时归档（artifacts/<code>/skill.md）以题目代号为 slug，
            # 通用手册（skills/<name>.md）以文件名为 slug
            slug = f.stem if f.parent == SKILLS_DIR else f.parent.name
            is_runtime = 1 if f.parent != SKILLS_DIR else 0
            first = next((ln for ln in body.splitlines() if ln.startswith("# ")), "")
            scored.append({"slug": slug, "score": score,
                           "_runtime": is_runtime,
                           "summary": f"实战经验 skill「{slug}」: "
                                      f"{first.lstrip('# ')[:80]}（关键词重合 {score}）",
                           "path": str(f)})
    # 同分时运行时归档优先（对当前场次题目的特异性高于通用手册）
    scored.sort(key=lambda s: (-s["score"], -s["_runtime"]))
    return [{k: v for k, v in s.items() if k != "_runtime"}
            for s in scored[:limit]]
