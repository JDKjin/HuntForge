#!/bin/bash
# HuntForge 容器入口：Claude Code 无人值守驾驶舱（不用 Python 编排解题，Claude 是大脑）
cd /app

# 诊断旁路：docker run <image> <cmd> 直接执行传入命令（冒烟测试/调试用）
if [ $# -gt 0 ]; then
  exec "$@"
fi

set -u

echo "=== HuntForge 容器启动（Claude Code 驾驶舱）==="
echo "BENCHMARK_BASE_URL=${BENCHMARK_BASE_URL:-<未注入>}"

# 大模型凭据（平台运行时环境变量注入；LLM_API_KEY/DEEPSEEK_API_KEY 为兜底变量名）
export HF_LLM_API_KEY="${HF_LLM_API_KEY:-${DEEPSEEK_API_KEY:-${LLM_API_KEY:-}}}"
if [ -z "$HF_LLM_API_KEY" ]; then
  echo "[entry] 缺少 HF_LLM_API_KEY / DEEPSEEK_API_KEY / LLM_API_KEY，无法驱动模型，退出"
  exit 1
fi
export ANTHROPIC_AUTH_TOKEN="${ANTHROPIC_AUTH_TOKEN:-$HF_LLM_API_KEY}"
# 模型方案（最后一场，用户指定）：全部 deepseek-v4-flash + MAX 推理模式
export ANTHROPIC_MODEL="${ANTHROPIC_MODEL:-deepseek-v4-flash}"
export HF_LLM_MODEL="${HF_LLM_MODEL:-$ANTHROPIC_MODEL}"
export HF_FAST_MODEL="${HF_FAST_MODEL:-deepseek-v4-flash}"
export HF_LLM_FAST_MODEL="$HF_FAST_MODEL"   # 兼容旧变量名
export HF_FAST_BASE_URL="${HF_FAST_BASE_URL:-${HF_LLM_BASE_URL:-http://api.deepseek.com.tsecbench.gw/v1}}"
export HF_FAST_API_KEY="${HF_FAST_API_KEY:-${HF_LLM_API_KEY:-}}"
export HF_FAST_FALLBACK="${HF_FAST_FALLBACK:-deepseek-v4-flash}"
export ANTHROPIC_SMALL_FAST_MODEL="${ANTHROPIC_SMALL_FAST_MODEL:-$HF_FAST_MODEL}"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="$ANTHROPIC_SMALL_FAST_MODEL"
export ANTHROPIC_DEFAULT_SONNET_MODEL="$ANTHROPIC_MODEL"
export ANTHROPIC_DEFAULT_OPUS_MODEL="$ANTHROPIC_MODEL"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT=1

# 平台题面（驱动必需；缺失时仅本地评测可用）
if [ -z "${BENCHMARK_BASE_URL:-}" ] || [ -z "${BENCHMARK_TOKEN:-}" ]; then
  echo "[entry] 警告：未注入 BENCHMARK_BASE_URL/BENCHMARK_TOKEN"
fi

# 项目级 Claude 权限（无人值守：放行 Bash/MCP/文件/子 agent 工具）
mkdir -p .claude
cp docker/claude-settings.json .claude/settings.json

# 自检 0：Anthropic→OpenAI shim（Claude Code 的唯一模型入口）
echo "[entry] 启动协议转换 shim（127.0.0.1:8765 → ${HF_LLM_BASE_URL}）..."
nohup python scripts/anthropic_shim.py 8765 > shim.log 2>&1 &
sleep 2

# 自检 1：MCP 服务握手（initialize/tools/list/tools/call）
echo "[entry] MCP 自检..."
python scripts/mcp_handshake.py \
  && echo "[entry] MCP 握手 OK" \
  || echo "[entry] MCP 自检失败（继续启动，Claude 可感知）"

# 自检 2：知识库召回（driver skill）
python -m huntforge.driver skill "报表导出系统" >/dev/null 2>&1 \
  && echo "[entry] 知识库召回 OK" || echo "[entry] 知识库召回失败"

# 全题解出检查：board 显示 completed >= total 才算完成
all_solved() {
  local out rc
  out=$(python -m huntforge.driver board 2>&1)
  rc=$?
  if [ $rc -eq 0 ]; then
    if echo "$out" | python -c "import sys,json
try:
    d=json.loads(sys.stdin.read().splitlines()[-1] or '{}')
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if int(d.get('completed') or 0) >= int(d.get('total') or 0) and d.get('total') else 1)" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

# 主循环：滚动通道调度（run-7082 高分选手「多小会话」模式 + run-9751
# 教训：批次屏障让快通道等最慢通道 25 分钟空转——改为每通道独立循环，
# 完成一道立即补位下一道，3 通道永不空转）。
# 通道策略（通用特征，不依赖题号）：
#   通道 1：全局期望值最高
#   通道 2：easy 快题优先（保证快题通道永远有分入账）
#   通道 3：排除长耗时题（hard/多阶段特征；每时最多 2 道长耗时在打）
# 单题会话硬时限 + 通道级总超时（任何一步挂起都强制释放）。
WALL_CAP="${HF_MAX_WALL_MINUTES:-720}"
START_TS=$(date +%s)
STOP_FILE=/tmp/hf-stop
rm -f "$STOP_FILE"

pick_code() {
  # $1 = next 附加参数
  # 原子占位防重：冷启动三条通道可能同秒选同一题（state.json 竞态），
  # mkdir 原子占位保证一题同时只有一条通道在打；占位超 10 分钟视为
  # 陈旧（通道被硬杀）自动清理。
  local EXTRA="$1" CODE=""
  local _i
  for _i in 1 2 3; do
    CODE=$(python -m huntforge.driver next $EXTRA 2>/dev/null \
      | python -c "import sys,json
try:
    d=json.loads(sys.stdin.read().splitlines()[-1] or '{}')
except Exception:
    d={}
print(d.get('code') or '')" 2>/dev/null)
    [ -z "$CODE" ] && { echo ""; return 0; }
    mkdir -p "artifacts/$CODE"
    find "artifacts/$CODE" -maxdepth 1 -name '.lane-claim' \
      -mmin +10 -exec rm -rf {} + 2>/dev/null
    if mkdir "artifacts/$CODE/.lane-claim" 2>/dev/null; then
      echo "$CODE"
      return 0
    fi
  done
  echo ""
}

run_lane() {
  local LANE="$1" EXTRA="$2"
  while [ ! -f "$STOP_FILE" ]; do
    CODE=$(pick_code "$EXTRA")
    if [ -z "$CODE" ]; then
      if all_solved; then
        touch "$STOP_FILE"
        break
      fi
      sleep 20
      continue
    fi
    echo "=== 通道 $LANE：单题会话 $CODE ==="
    mkdir -p "artifacts/$CODE"
    # 会话日志按轮次隔离（run-9800 教训：旧轮次 session.log 累积，harvest
    # 把旧 flag 当新候选重复收割，出现"解出题目与提交对不上"）
    [ -f "artifacts/$CODE/session.log" ] \
      && mv "artifacts/$CODE/session.log" "artifacts/$CODE/session.prev.log"
    : > "artifacts/$CODE/session.log"
    [ -f "artifacts/$CODE/harvest.log" ] \
      && mv "artifacts/$CODE/harvest.log" "artifacts/$CODE/harvest.prev.log"
    : > "artifacts/$CODE/harvest.log"
    python -m huntforge.driver brief "$CODE" 2>/dev/null \
      | python -c "
import sys, json
try:
    d = json.loads(sys.stdin.read().splitlines()[-1] or '{}')
except Exception:
    d = {}
extra = d.get('additional_targets') or []
prior = d.get('prior_notes') or ''
print(f'''【题目编号】{d.get('code')}
【难度/分值】{d.get('difficulty')} / {d.get('score')}（已完成 flag {d.get('flags_done')}）
【攻击目标】{d.get('target')}
【其他目标】{\"、\".join(str(x) for x in extra) if extra else '无'}''')
if prior:
    print(f'''【往轮情报】{prior}''')
print(f'''【题面】{d.get('description')}
【通用方法论】{d.get('playbook')}
【可读参考手册】{d.get('skill_paths')}
【flag 路径提示】{d.get('flag_path')}''')" > /tmp/brief_$CODE.txt 2>/dev/null
    # brief 失败（如容器启动失败/名额满）→ 不空跑会话，收割关闭后重试
    if ! grep -q "【攻击目标】http\|【攻击目标】tcp" /tmp/brief_$CODE.txt 2>/dev/null; then
      echo "brief 失败（无法获得攻击目标），跳过会话" >> "artifacts/$CODE/session.log"
      python -m huntforge.driver harvest "$CODE" >/dev/null 2>&1 || true
      rmdir "artifacts/$CODE/.lane-claim" 2>/dev/null || true
      sleep 15
      continue
    fi
    PROMPT="$(cat docker/challenge_prompt.txt)
$(cat /tmp/brief_$CODE.txt)"
    # 单题会话硬时限（run-9530 教训：会话无限循环冻结编排器）。
    # 失速看门狗（run-10043 教训：25 分钟会话零产出满烧）。
    # run-10101 教训：旧实现用「tail -f | tee 后台管道」转写会话日志，
    # 会话结束后后台进程残留握着外层管道写端 → 通道永久卡死不再选题。
    # 新实现：claude 直接追加写 session.log（无中间管道/后台进程），
    # 看门狗只轮询文件大小，任何路径结束都不留后台进程。
    export PROMPT
    timeout --kill-after=30 "$(( ${HF_SESSION_TIMEOUT:-1500} + 300 ))" bash -c '
      set -u
      CODE="$1"
      SLOG="artifacts/$CODE/session.log"
      STALL_KILL="${HF_STALL_KILL:-420}"
      FIRST_GRACE="${HF_FIRST_GRACE:-600}"
      STARTED=$(date +%s)
      timeout --kill-after=30 "${HF_SESSION_TIMEOUT:-1500}" \
        claude -p "$PROMPT" --dangerously-skip-permissions >> "$SLOG" 2>&1 &
      CLAUDE_PID=$!
      LAST_SIZE=$(wc -c < "$SLOG" 2>/dev/null || echo 0)
      LAST_GROW=$STARTED
      HAS_OUT=0
      while kill -0 "$CLAUDE_PID" 2>/dev/null; do
        sleep 10
        SIZE=$(wc -c < "$SLOG" 2>/dev/null || echo 0)
        if [ "$SIZE" -gt "$LAST_SIZE" ]; then
          LAST_SIZE="$SIZE"
          LAST_GROW=$(date +%s)
          HAS_OUT=1
        fi
        # 有产出（FLAG/CANDIDATES/RESULT）→ 不杀（留给它收尾）
        if grep -qE "FLAG:|CANDIDATES:|RESULT:" "$SLOG" 2>/dev/null; then
          continue
        fi
        # 看门狗两段式：pro/max 纯推理阶段无任何输出（推理 token 不落
        # 日志）→ 首输出宽限 FIRST_GRACE；已有输出后停滞 STALL_KILL 秒
        # 才杀（run-10102：单段阈值误杀"正在深度思考"的会话）
        if [ "$HAS_OUT" = "0" ]; then
          KILL_AT=$(( STARTED + FIRST_GRACE ))
        else
          KILL_AT=$(( LAST_GROW + STALL_KILL ))
        fi
        if [ "$(date +%s)" -ge "$KILL_AT" ]; then
          echo "[entry] $CODE 会话$([ "$HAS_OUT" = "0" ] && echo 首响应 || echo 停滞)超时无产出，硬杀换路" \
            | tee -a "$SLOG"
          kill -TERM "$CLAUDE_PID" 2>/dev/null || true
          sleep 5
          kill -KILL "$CLAUDE_PID" 2>/dev/null || true
          break
        fi
      done
      wait "$CLAUDE_PID" 2>/dev/null
      echo "claude exit=$? (killed_by_watchdog=1)" >> "$SLOG" 2>/dev/null || true
      echo "（会话结束/超时，开始收割）" >> "$SLOG"
      python -m huntforge.driver harvest "$CODE" 2>&1 \
        | tee -a "artifacts/$CODE/harvest.log"
    ' _ "$CODE" 2>&1 | tee -a "artifacts/$CODE/lane.log"
    rmdir "artifacts/$CODE/.lane-claim" 2>/dev/null || true
    sleep 3
  done
}

# 三条滚动通道并行（记录 PID：退出时只等通道，不等常驻 shim）
run_lane 1 "" &
LANE1=$!
run_lane 2 "--prefer easy" &
LANE2=$!
run_lane 3 "--exclude-longhaul" &
LANE3=$!

# 监督循环：全部解出或墙钟上限 → 置停止标记，通道自然退出；
# 同时按 HF_AUDIT_INTERVAL（默认 300s）自动巡检 flag↔题目归属一致性。
AUDIT_INTERVAL="${HF_AUDIT_INTERVAL:-300}"
LAST_AUDIT=0
while :; do
  sleep 15
  if all_solved; then
    echo "[entry] 全部题目已解出，容器退出"
    touch "$STOP_FILE"
    break
  fi
  if [ $(( $(date +%s) - START_TS )) -gt $(( WALL_CAP * 60 )) ]; then
    echo "[entry] 墙钟上限 ${WALL_CAP} 分钟到达，容器退出"
    touch "$STOP_FILE"
    break
  fi
  if [ $(( $(date +%s) - LAST_AUDIT )) -ge "$AUDIT_INTERVAL" ]; then
    LAST_AUDIT=$(date +%s)
    python -m huntforge.driver audit 2>/dev/null \
      | tee -a "artifacts/audit.log" | tail -1
  fi
done
# 只等三条解题通道（shim 是常驻服务，不等它——此前 `wait` 无参数把 shim
# 也算进去导致墙钟到达后容器永不退出，run-9802 挂死 15 分钟教训）
wait "$LANE1" "$LANE2" "$LANE3" 2>/dev/null
pkill -f anthropic_shim.py 2>/dev/null || true
echo "[entry] 退出条件达成（全部解出或墙钟上限），容器结束"
