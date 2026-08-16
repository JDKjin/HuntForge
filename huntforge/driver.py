"""Claude Code 驱动 CLI：单发命令控制 TSecBench 任务与 HuntForge agent。

供 Claude Code（或人类）在终端调用，输出紧凑 JSON，便于模型直接消费。
复用 LiveRunner 的解题链（冷却/持久化状态/容器纪律全部生效）。

用法：
    python -m huntforge.driver list                  # 题目列表（未解优先）
    python -m huntforge.driver board                 # 面板总览（分数/进度）
    python -m huntforge.driver start <code> [--wait] # 启动容器（--wait 等就绪）
    python -m huntforge.driver close <code>          # 关闭容器
    python -m huntforge.driver submit <code> <flag>  # 提交（自动大小写回退）
    python -m huntforge.driver hint <code>           # 拉提示
    python -m huntforge.driver status <code>         # 单题状态
    python -m huntforge.driver attack <code> [--agent web-ops|binary-ops]
        [--timebox 480] [--no-llm]                   # 单题完整解题（启容器→攻→关）
    python -m huntforge.driver skill <title|query>   # 知识召回（手册+经验库）

配置：BENCHMARK_BASE_URL / BENCHMARK_TOKEN（环境变量或项目 .env，
--live 之外的命令也会读 .env，方便 Claude 直接驱动）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from typing import Optional

# Windows 控制台默认 GBK：Claude Code 终端按 UTF-8 解析输出，
# 不重配会 UnicodeEncodeError 崩溃（⑪ 等字符直接炸）。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from .main import _load_dotenv

_JSON_ERR = {"ok": False, "error": ""}


def _env(cfg=None):
    """平台地址/token：环境变量 > .env > settings.yaml platform 段。"""
    base = os_environ().get("BENCHMARK_BASE_URL", "")
    token = os_environ().get("BENCHMARK_TOKEN", "")
    if not (base and token):
        from .core.config import load
        c = load()
        base = base or (c.bench_base_url or "")
        token = token or (c.bench_token or "")
    return (base or "").rstrip("/"), token or ""


def os_environ():
    import os
    return os.environ


def _client():
    from .bench.tsec_client import TsecBenchClient
    base, token = _env()
    if not base or not token:
        raise SystemExit("需要 BENCHMARK_BASE_URL / BENCHMARK_TOKEN"
                         "（环境变量或项目 .env）")
    return TsecBenchClient(base, token)


def _out(obj) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _compact_ch(c: dict) -> dict:
    return {
        "code": c.get("unique_code"),
        "score": c.get("total_score"),
        "flags": f"{c.get('correct_flag_count') or 0}/{c.get('flag_count') or 1}",
        "done": bool(c.get("is_completed")),
        "status": c.get("container_status"),
        "addr": (c.get("container_addr") or [None])[0],
        "difficulty": c.get("difficulty"),
        "desc": (c.get("description") or "").replace("\n", " ")[:120],
    }


def cmd_list(args) -> int:
    chs = _client().list_challenges()
    rows = [_compact_ch(c) for c in chs]
    rows.sort(key=lambda r: (r["done"], -(r["score"] or 0)))
    for r in rows:
        _out(r)
    return 0


def cmd_board(args) -> int:
    """面板总览。只报事实计数（完成/部分/活跃/未解），不估算总分——
    平台分数为准，本地估算与平台口径（hint 扣分等）对不上，已按需求移除。"""
    chs = _client().list_challenges()
    completed = sum(1 for c in chs if c.get("is_completed"))
    partial = sum(1 for c in chs if c.get("correct_flag_count", 0)
                  and not c.get("is_completed"))
    active = [c["unique_code"] for c in chs
              if c.get("container_status") not in ("stopped", None)]
    unsolved = sorted([c for c in chs if not c.get("is_completed")],
                      key=lambda c: -(c.get("total_score") or 0))
    _out({"total": len(chs), "completed": completed, "partial": partial,
          "active_containers": active,
          "unsolved": [_compact_ch(c) for c in unsolved]})
    return 0


# ---- 纪律硬门控（run-9223 教训：模型把提示词纪律当耳旁风，
# 结尾阶段 20-60 秒开/关洗题 + 开题 9 秒就拉 hint）----
# run-7082 高分选手数据：148 次 hint 仍大胜（hint 成本 10% << 解不出 0 分），
# 所以 hint 门控放宽到 2 分钟；洗题门控保留 3 分钟。
HINT_MIN_ELAPSED = 120.0     # 开题不足 2 分钟禁止拉 hint（禁止秒拉即可）
CLOSE_MIN_ELAPSED = 180.0    # 容器存活不足 3 分钟且未解出禁止关闭（防洗题）
COOLDOWN_DRIVER = 720.0      # driver next 选题：同题 12 分钟冷却
MAX_DRIVER_ATTEMPTS = 4      # 单题主动选题尝试上限（防长耗时题反复回抢通道）

# 长耗时题特征（通用，不依赖任何题号）：hard 难度，或多阶段渗透类题面关键词
# （与 multi-stage 手册/压缩提示词的路由关键词一致）
_LONGHAUL_KEYWORDS = ("内网", "横向", "官网", "渗透", "机密", "核心数据",
                      "防火墙", "多层", "隔离", "入侵", "多阶段", "外网")


def _is_longhaul(ch: dict) -> bool:
    """通用判定：这道题预计单题耗时很长（多阶段/hard）。"""
    if (ch.get("difficulty") or "").lower() == "hard":
        return True
    desc = (ch.get("description") or "").lower()
    return any(k in desc for k in _LONGHAUL_KEYWORDS)


def _state_file(code: str) -> "Path":
    from pathlib import Path
    root = Path(os_environ().get("HUNTFORGE_ARTIFACTS_DIR", "artifacts"))
    return root / code / "state.json"


def _load_state(code: str) -> dict:
    p = _state_file(code)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(code: str, state: dict) -> None:
    p = _state_file(code)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


def _mark_solved(code: str) -> None:
    st = _load_state(code)
    st["solved"] = True
    _save_state(code, st)


def cmd_start(args) -> int:
    code = args.code
    try:
        res = _client().start(code)
    except Exception as exc:  # noqa: BLE001
        _out({"ok": False, "code": code, "error": str(exc)})
        return 1
    st = _load_state(code)
    st["started_at"] = time.time()
    st.setdefault("solved", False)
    _save_state(code, st)
    addrs = res.get("container_addr") or []
    if args.wait:
        t0 = time.time()
        while time.time() - t0 < 90:
            for c in _client().list_challenges():
                if c["unique_code"] == code \
                        and c.get("container_status") == "available":
                    addrs = c.get("container_addr") or addrs
                    break
            else:
                time.sleep(3)
                continue
            break
    _out({"ok": True, "code": code, "addr": addrs})
    return 0


def cmd_close(args) -> int:
    # 洗题门控：容器存活 < CLOSE_MIN_ELAPSED 且未解出 → 拒绝关闭
    st = _load_state(args.code)
    started = float(st.get("started_at") or 0)
    elapsed = time.time() - started if started else 0
    if not st.get("solved") and 0 < elapsed < CLOSE_MIN_ELAPSED \
            and not args.force:
        _out({"ok": False, "code": args.code,
              "error": f"容器仅开启 {int(elapsed)}s 且未解出，禁止关闭（防洗题，"
                       f"纪律：一题至少打 {int(CLOSE_MIN_ELAPSED)}s）。"
                       f"确有把握放弃时用 --force"})
        return 1
    try:
        res = _client().close(args.code)   # TsecBenchClient.close 返回 bool
        _out({"ok": True, "code": args.code, "closed": bool(res)})
        return 0
    except Exception as exc:  # noqa: BLE001
        _out({"ok": False, "code": args.code, "error": str(exc)})
        return 1


def _case_variant(flag: str) -> str:
    """flag{ ↔ FLAG{ 前缀翻转（body 保持原样）。"""
    if flag.startswith("flag{"):
        return "FLAG{" + flag[5:]
    if flag.startswith("FLAG{"):
        return "flag{" + flag[5:]
    return ""


def cmd_submit(args) -> int:
    code, flag = args.code, args.flag
    client = _client()
    tried = [flag]
    variant = _case_variant(flag)
    if variant:
        tried.append(variant)
    for f in tried:
        try:
            res = client.submit(code, f)
        except Exception as exc:  # noqa: BLE001
            _out({"ok": False, "code": code, "flag": f, "error": str(exc)})
            return 1
        if res.get("correct"):
            _mark_solved(code)
            _out({"ok": True, "code": code, "flag": f,
                  "awarded": res.get("awarded"),
                  "cumulative": res.get("cumulative_score"),
                  "progress": f"{res.get('correct_flag_count')}/"
                              f"{res.get('total_flag_count')}"})
            return 0
        if res.get("duplicate"):
            _out({"ok": True, "code": code, "flag": f, "duplicate": True})
            return 0
    _out({"ok": False, "code": code, "tried": tried,
          "error": "flag rejected（含大小写变体）"})
    return 1


def cmd_hint(args) -> int:
    # hint 门控（放宽到 2 分钟：run-7082 高分选手 148 次提示仍大胜——
    # hint 成本 10% 远小于解不出得 0 分；但禁止开题秒拉）
    st = _load_state(args.code)
    started = float(st.get("started_at") or 0)
    elapsed = time.time() - started if started else 0
    if 0 < elapsed < HINT_MIN_ELAPSED and not args.force:
        _out({"ok": False, "code": args.code,
              "error": f"开题仅 {int(elapsed)}s，hint 纪律要求先实际攻击 "
                       f"{int(HINT_MIN_ELAPSED)}s（hint 成本 10%，先自己试）。"
                       f"确有需要时用 --force"})
        return 1
    try:
        hint = _client().hint(args.code)
        _out({"ok": True, "code": args.code, "hint": hint})
        return 0
    except Exception as exc:  # noqa: BLE001
        _out({"ok": False, "code": args.code, "error": str(exc)})
        return 1


def cmd_status(args) -> int:
    for c in _client().list_challenges():
        if c["unique_code"] == args.code:
            _out(_compact_ch(c))
            return 0
    _out({"ok": False, "code": args.code, "error": "not found"})
    return 1


def cmd_skill(args) -> int:
    """知识召回：按题面/查询词输出压缩手册 + 经验库匹配 skill。"""
    from .knowledge import skill_store
    from .knowledge.playbooks import (BINARY_PLAYBOOK_HINT,
                                      MULTI_STAGE_PLAYBOOK_HINT,
                                      WEB_PLAYBOOK_HINT)
    q = args.title or ""
    t = q.lower()
    if any(k in t for k in ("协议", "固件", "tcp", "二进制", "内存", "心跳", "mcu")):
        hint = {"type": "binary", "summary": BINARY_PLAYBOOK_HINT}
    elif any(k in t for k in ("内网", "横向", "官网", "外网", "渗透", "机密",
                              "核心数据", "防火墙", "多层", "隔离", "入侵")):
        hint = {"type": "multi_stage", "summary": MULTI_STAGE_PLAYBOOK_HINT}
    else:
        hint = {"type": "web", "summary": WEB_PLAYBOOK_HINT}
    skills = skill_store.match_skills(q, limit=3)
    _out({"hint": hint,
          "skills": [{"slug": s["slug"], "summary": s["summary"],
                      "path": s["path"]} for s in skills]})
    return 0


def cmd_report(args) -> int:
    """Flag 候选上报（BTFly 式 inbox 协议）：证据落盘，可选自动提交。

    文件：<artifacts>/<code>/flag-candidate-<时间戳>.json
    （artifacts 根目录可用 HUNTFORGE_ARTIFACTS_DIR 覆盖）
    """
    import time as _time
    from pathlib import Path
    root = Path(os_environ().get("HUNTFORGE_ARTIFACTS_DIR", "artifacts"))
    outdir = root / args.code
    outdir.mkdir(parents=True, exist_ok=True)
    ts = _time.strftime("%Y%m%d-%H%M%S")
    path = outdir / f"flag-candidate-{ts}.json"
    payload = {"version": 1, "code": args.code, "value": args.flag,
               "confidence": int(args.confidence),
               "summary": args.summary or "",
               "evidence": list(args.evidence or [])}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                    encoding="utf-8")
    _out({"ok": True, "path": str(path), "value": args.flag})
    if args.submit:
        return cmd_submit(args)
    return 0


def cmd_next(args) -> int:
    """下一道推荐题：期望值排序 + 12 分钟冷却 + 单题尝试封顶 +
    长耗时题排除 / easy 优先（通用特征，不依赖任何题号）。

    供容器入口循环逐题驱动：每道题一个全新小会话（run-7082 高分选手
    「多小会话」模式：1029 条对话逐题推进，避免单巨会话压缩退化）。

    调度公平（run-9661 教训）：多阶段/hard 长耗时题期望值最高但单题吃
    25 分钟且常卡死——入口每批最多 2 道长耗时题（--exclude-longhaul 用于
    第三通道）、始终保留一条 easy 快题通道（--prefer easy），保证快题
    不被饿死；单题尝试 ≥ MAX_DRIVER_ATTEMPTS 次后不再主动选。
    """
    from .bench.live_runner import expected_value, skip_reason
    chs = _client().list_challenges()
    now = time.time()
    cands = []
    for c in chs:
        if c.get("is_completed") or skip_reason(c):
            continue
        if args.exclude_longhaul and _is_longhaul(c):
            continue
        code = c["unique_code"]
        st = _load_state(code)
        last = float(st.get("last_attempt") or 0)
        attempts = int(st.get("attempts") or 0)
        if now - last >= COOLDOWN_DRIVER \
                and attempts < MAX_DRIVER_ATTEMPTS:
            cands.append((expected_value(c), attempts, c))
    if args.prefer == "easy":
        easy = [(ev, at, c) for ev, at, c in cands
                if (c.get("difficulty") or "").lower() == "easy"]
        if easy:
            cands = easy
    if not cands:
        # 全部在冷却/封顶/被排除：只放宽冷却与排除，**不放开尝试上限**
        # （run-10043 教训：旧 fallback 无视上限重打最久前那道 → 同题被
        # 反复攻打 4-5 次，10 道未解题烧掉 10.9 车道小时，11 道题零尝试）
        best, best_last, best_at = None, None, None
        for c in chs:
            if c.get("is_completed") or skip_reason(c):
                continue
            st = _load_state(c["unique_code"])
            attempts = int(st.get("attempts") or 0)
            if attempts >= MAX_DRIVER_ATTEMPTS:
                continue   # 硬上限：不再空烧同一题
            last = float(st.get("last_attempt") or 0)
            if best is None or attempts < best_at \
                    or (attempts == best_at and last < best_last):
                best, best_last, best_at = c, last, attempts
        if best is None:
            _out({"code": None, "error": "all unsolved at attempt cap"})
            return 1
        cands = [(0.0, best_at, best)]
    # 从未打过的题（attempts==0）绝对优先——保证全场每道题至少打一次，
    # 不让高期望值难题永远占住车道（run-10043：11 道题零尝试的实锤教训）
    cands.sort(key=lambda t: (0 if t[1] == 0 else 1, -t[0]))
    code = cands[0][2]["unique_code"]
    # 选中即标记（防同批并发重复选同一题；冷却同时生效）
    st = _load_state(code)
    st["last_attempt"] = time.time()
    st["attempts"] = int(st.get("attempts") or 0) + 1
    _save_state(code, st)
    _out({"code": code, "attempt": st["attempts"],
          "longhaul": _is_longhaul(cands[0][2])})
    return 0


def cmd_brief(args) -> int:
    """生成单题作战 brief：确保容器已开（含等待就绪）+ 题面全文 +
    知识召回（压缩手册 + 经验库）+ 目标地址。输出 JSON 供会话提示词拼接。"""
    code = args.code
    ch = None
    for c in _client().list_challenges():
        if c["unique_code"] == code:
            ch = c
            break
    if ch is None:
        _out({"ok": False, "code": code, "error": "not found"})
        return 1
    addr = (ch.get("container_addr") or [None])[0]
    if ch.get("container_status") != "available":
        try:
            r = _client().start(code)
            addr = (r.get("container_addr") or [addr])[0]
        except Exception as exc:  # noqa: BLE001
            _out({"ok": False, "code": code, "error": str(exc)})
            return 1
        t0 = time.time()
        while time.time() - t0 < 90:
            for c2 in _client().list_challenges():
                if c2["unique_code"] == code \
                        and c2.get("container_status") == "available":
                    addr = (c2.get("container_addr") or [addr])[0]
                    break
            else:
                time.sleep(3)
                continue
            break
    st = _load_state(code)
    st["started_at"] = time.time()
    st["last_attempt"] = time.time()
    st.setdefault("solved", False)
    _save_state(code, st)
    # 目标形态：f1 协议题 tcp://；f2 固件题 /download；其余 http://
    if code.startswith("f1-"):
        target = f"tcp://{addr}" if addr else None
    elif code.startswith("f2-"):
        target = f"http://{addr}/download" if addr else None
    else:
        target = f"http://{addr}" if addr else None
    # 知识召回（与决策循环同一套路由）
    from .knowledge import skill_store
    from .knowledge.playbooks import (BINARY_PLAYBOOK_HINT,
                                      MULTI_STAGE_PLAYBOOK_HINT,
                                      WEB_PLAYBOOK_HINT)
    t = (ch.get("description") or "").lower()
    if any(k in t for k in ("协议", "固件", "tcp", "二进制", "内存", "心跳", "mcu")):
        playbook = BINARY_PLAYBOOK_HINT
    elif any(k in t for k in ("内网", "横向", "官网", "外网", "渗透", "机密",
                              "核心数据", "防火墙", "多层", "隔离", "入侵")):
        playbook = MULTI_STAGE_PLAYBOOK_HINT
    else:
        playbook = WEB_PLAYBOOK_HINT
    skills = skill_store.match_skills(ch.get("description") or "", limit=2)
    # 多目标题（run-10043：bctf-25 双地址只打了第一个，第二个 registry
    # 端口 4873 整个场次没人碰）——全部 container_addr 都进 brief
    addrs = ch.get("container_addr") or []
    extra_targets = []
    for a in addrs[1:] if isinstance(addrs, list) else []:
        a = str(a)
        if not a:
            continue
        extra_targets.append(a if "://" in a else f"http://{a}")
    _out({"ok": True, "code": code,
          "description": ch.get("description") or code,
          "difficulty": ch.get("difficulty"),
          "score": ch.get("total_score"),
          "flags_done": f"{ch.get('correct_flag_count') or 0}/"
                        f"{ch.get('flag_count') or 1}",
          "target": target,
          "additional_targets": extra_targets,
          "prior_notes": _prior_notes(code),
          "playbook": playbook,
          "skill_paths": [s["path"] for s in skills],
          "flag_path": "/challenge/flag.txt（平台常规）"})
    return 0


def _prior_notes(code: str) -> str:
    """往轮会话情报：recon-notes.md + 上次会话日志尾部结论——
    重试会话先读历史换路，不重复烧时间（run-10043 教训）。"""
    from pathlib import Path
    root = Path(os_environ().get("HUNTFORGE_ARTIFACTS_DIR", "artifacts"))
    parts = []
    notes = root / code / "recon-notes.md"
    if notes.is_file():
        try:
            parts.append(notes.read_text(encoding="utf-8", errors="replace")[:1000])
        except OSError:
            pass
    for fname in ("session.prev.log", "session.log"):
        logf = root / code / fname
        if not logf.is_file():
            continue
        try:
            text = logf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = [ln for ln in text.splitlines()
                 if any(k in ln for k in ("FLAG:", "RESULT:", "阻塞",
                                          "CANDIDATES:", "解题", "路径", "端口"))]
        tail = "\n".join(lines[-8:])[:600]
        if tail.strip():
            parts.append(f"上轮会话结论:\n{tail}")
        break
    return "\n".join(parts).strip()[:1400]


_FLAG_RE = re.compile(r"(?:flag|ctf|hf)[{\[\(][^}\]\)\n]{6,128}[\}\)\]]", re.I)


def cmd_harvest(args) -> int:
    """从单题会话日志提取 FLAG/CANDIDATES 并全部提交（答错无成本——
    run-7082 高分选手 388 次失败提交照样大胜），命中后关闭容器并落
    final-result.json。"""
    from pathlib import Path
    code = args.code
    root = Path(os_environ().get("HUNTFORGE_ARTIFACTS_DIR", "artifacts"))
    log = root / code / "session.log"
    text = ""
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    cands: list[str] = []
    for m in re.finditer(r"FLAG:\s*(\S+)", text):
        cands.append(m.group(1).strip().strip("'\"`"))
    for m in re.finditer(r"CANDIDATES:\s*([^\n]+)", text):
        cands += [x.strip() for x in m.group(1).split("|") if x.strip()]
    cands += [m.group(0) for m in _FLAG_RE.finditer(text)]
    seen: list[str] = []
    for c in cands:
        if c and c not in seen:
            seen.append(c)
    accepted: list[str] = []
    client = _client()
    for f in seen[:20]:
        tried = [f]
        v = _case_variant(f)
        if v:
            tried.append(v)
        for t in tried:
            try:
                res = client.submit(code, t)
            except Exception:  # noqa: BLE001 - 单条失败继续下一条
                continue
            if res.get("correct"):
                accepted.append(t)
                _mark_solved(code)
                break
    _out({"ok": True, "code": code, "candidates": len(seen),
          "accepted": accepted})
    # 无论解没解出都关闭容器（run-9530 教训：只关已解出的 → 未解容器泄漏
    # 占满 3 名额 → 后续 brief 全部 start 失败 → 编排器空转死循环）
    try:
        client.close(code)
        _out({"code": code, "closed": True})
    except Exception:  # noqa: BLE001
        _out({"code": code, "closed": False})
    try:
        fr = root / code / "final-result.json"
        fr.write_text(json.dumps(
            {"status": "solved" if accepted else "unsolved",
             "flags": [{"value": a, "verified": True} for a in accepted]},
            ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass
    return 0


def cmd_cve(args) -> int:
    """离线 CVE 情报查询：指纹/关键词 → 内置 CVE 库命中 + nuclei 模板路径。"""
    from .knowledge import cve_engine
    q = args.query or ""
    hits = cve_engine.match_cves(body=q, title=q, headers_blob=q)
    out = []
    for e in hits[:5]:
        item = {"cve": e.get("cve"), "product": e.get("product"),
                "severity": e.get("severity"),
                "attack": (e.get("attack") or "")[:300]}
        tpls = cve_engine.cve_templates(e.get("cve", ""), limit=3)
        if tpls:
            item["nuclei_templates"] = tpls
        out.append(item)
    _out({"ok": True, "query": q, "hits": out,
          "index_cves": len(cve_engine.load_index())})
    return 0


def cmd_audit(args) -> int:
    """自动巡检：核对平台进度与本地产物的一致性（flag↔题目归属）。

    规则：
      1) 本地产物记录过 accepted，但平台该题 correct_flag_count==0
         （归属错题/提交到别的题嫌疑）；
      2) 会话日志存在 flag 形候选但平台未认领（可能漏交/交错题）；
      3) 同一 flag 值出现在多道题产物中（串题污染嫌疑）。
    """
    from pathlib import Path
    chs = _client().list_challenges()
    root = Path(os_environ().get("HUNTFORGE_ARTIFACTS_DIR", "artifacts"))
    per_code: dict = {}
    for c in chs:
        code = c["unique_code"]
        n_ok = int(c.get("correct_flag_count") or 0)
        n_all = int(c.get("flag_count") or 1) or 1
        accepted_local: list[str] = []
        hlog = root / code / "harvest.log"
        if hlog.is_file():
            text = hlog.read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r'"accepted":\s*(\[[^\]]*\])', text):
                try:
                    accepted_local += [str(x) for x in json.loads(m.group(1))]
                except (json.JSONDecodeError, TypeError):
                    pass
        sess_flags: list[str] = []
        slog = root / code / "session.log"
        if slog.is_file():
            text = slog.read_text(encoding="utf-8", errors="replace")
            sess_flags = sorted(set(_FLAG_RE.findall(text)))[:20]
        per_code[code] = {"platform_ok": n_ok, "platform_all": n_all,
                          "accepted_local": sorted(set(accepted_local)),
                          "session_flags": sess_flags}
    issues: list[dict] = []
    for code, info in per_code.items():
        if info["accepted_local"] and info["platform_ok"] == 0:
            issues.append({"code": code,
                           "issue": "local_accepted_but_platform_zero",
                           "detail": info["accepted_local"][:3]})
        if info["session_flags"] and info["platform_ok"] < info["platform_all"]:
            issues.append({"code": code, "issue": "session_flags_unresolved",
                           "detail": info["session_flags"][:3]})
    by_flag: dict[str, set] = {}
    for code, info in per_code.items():
        for f in info["accepted_local"] + info["session_flags"]:
            by_flag.setdefault(f, set()).add(code)
    for f, codes in by_flag.items():
        if len(codes) > 1:
            issues.append({"code": sorted(codes)[0],
                           "issue": "flag_in_multiple_challenges",
                           "detail": f, "codes": sorted(codes)})
    _out({"ok": True, "issues": issues[:20],
          "issue_count": len(issues),
          "challenges_checked": len(per_code)})
    return 0


def cmd_attack(args) -> int:
    """单题完整解题：复用 LiveRunner（含冷却/持久化/容器纪律）。"""
    base, token = _env()
    if not base or not token:
        _out({"ok": False, "error": "需要 BENCHMARK_BASE_URL / BENCHMARK_TOKEN"})
        return 1
    from .bench.live_runner import LiveRunner
    runner = LiveRunner(base, token)
    ch = None
    for c in runner.client.list_challenges():
        if c["unique_code"] == args.code:
            ch = c
            break
    if ch is None:
        _out({"ok": False, "code": args.code, "error": "not found"})
        return 1
    if args.no_llm:
        runner._llm_cfg = None
    t0 = time.time()
    completed = runner._solve_one(ch, None, float(args.timebox), not args.no_llm)
    summary = runner._summary(runner.client.list_challenges())
    _out({"ok": True, "code": args.code, "completed": completed,
          "duration_sec": round(time.time() - t0, 1),
          "board": summary})
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="huntforge.driver",
                                     description="Claude Code 驱动 HuntForge")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="题目列表")
    sub.add_parser("board", help="面板总览")

    p = sub.add_parser("start", help="启动容器")
    p.add_argument("code")
    p.add_argument("--wait", action="store_true", help="等容器就绪")

    p = sub.add_parser("close", help="关闭容器")
    p.add_argument("code")
    p.add_argument("--force", action="store_true",
                   help="跳过洗题门控（确要放弃时）")

    p = sub.add_parser("submit", help="提交 flag（自动大小写回退）")
    p.add_argument("code")
    p.add_argument("flag")

    p = sub.add_parser("hint", help="拉提示")
    p.add_argument("code")
    p.add_argument("--force", action="store_true",
                   help="跳过 2 分钟门控")

    p = sub.add_parser("status", help="单题状态")
    p.add_argument("code")

    p = sub.add_parser("attack", help="单题完整解题")
    p.add_argument("code")
    p.add_argument("--timebox", type=float, default=480.0)
    p.add_argument("--no-llm", action="store_true", help="规则-only（省预算）")

    p = sub.add_parser("next", help="下一道推荐题（期望值+冷却+尝试封顶+公平调度）")
    p.add_argument("--exclude-longhaul", action="store_true",
                   help="排除长耗时题（hard/多阶段特征，通用判定）")
    p.add_argument("--prefer", default="", choices=["easy"],
                   help="easy 快题优先（保留一条快题通道）")

    p = sub.add_parser("brief", help="生成单题作战 brief（开容器+召回）")
    p.add_argument("code")

    p = sub.add_parser("harvest", help="从会话日志提取并提交候选 flag")
    p.add_argument("code")

    p = sub.add_parser("audit", help="自动巡检：flag↔题目归属一致性核对")

    p = sub.add_parser("report", help="Flag 候选上报（证据落盘，可选提交）")
    p.add_argument("code")
    p.add_argument("flag")
    p.add_argument("--confidence", type=int, default=90, help="0-100")
    p.add_argument("--summary", default="")
    p.add_argument("--evidence", nargs="*", default=[],
                   help="证据文件/说明（相对 artifacts 路径）")
    p.add_argument("--submit", action="store_true", help="落盘后立即提交")

    p = sub.add_parser("skill", help="知识召回（手册+经验库）")
    p.add_argument("title", nargs="?", default="")

    p = sub.add_parser("cve", help="离线 CVE 情报查询（内置库+nuclei 模板）")
    p.add_argument("query", nargs="?", default="")

    args = parser.parse_args(argv)
    _load_dotenv()   # 驱动模式下始终读 .env（Claude 终端直调需要）
    try:
        return {
            "list": cmd_list, "board": cmd_board, "start": cmd_start,
            "close": cmd_close, "submit": cmd_submit, "hint": cmd_hint,
            "status": cmd_status, "attack": cmd_attack, "skill": cmd_skill,
            "report": cmd_report, "next": cmd_next, "brief": cmd_brief,
            "harvest": cmd_harvest, "cve": cmd_cve, "audit": cmd_audit,
        }[args.cmd](args)
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception as exc:  # noqa: BLE001 - CLI 层兜底，绝不抛裸 traceback
        _out({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return 1


def main_cli() -> None:
    """setuptools console_scripts 入口（`huntforge` 命令）。"""
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
