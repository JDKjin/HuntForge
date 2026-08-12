# HuntForge 铸猎 · AI 攻防全链路 Agent

面向「Agent+ 攻防能力挑战赛」的自主漏洞挖掘 Agent：托管模式下镜像启动即自解，拉题 → 漏洞挖掘 → 幂等提交全流程自动化。

## 架构

```
┌─ BenchClient 平台适配层 ──┐
│  BENCHMARK_BASE_URL/TOKEN  │   拉题 /api/v1/assets · 提交 /api/v1/flag/collect
└────────────┬───────────────┘   （接口路径可配置，本地 mock 可闭环）
┌────────────▼───────────────┐
│ 规则调度器（权威，不依赖 LLM）│   SQLite 唯一事实源 · CAS 领取 · lease 续租
│  难度/路由/重试/预算 全规则化 │   崩溃恢复：启动时把遗留任务回 pending
└─────┬─────────┬─────────────┘
      │         │
┌─────▼────┐ ┌──▼────────────┐
│ Web 流水线 │ │ 专项流水线（web/ai/binary/chain）│   P1 SQLi/SSRF/RCE/越权 · P2 AI 应用
│ recon→指纹 │ │  LLM 多轮决策循环 + 规则 fallback │     P3 二进制 · P4 区块链
└─────┬────┘ └──┬────────────┘
┌─────▼────────▼─────────────┐
│ 模型网关（白名单国内模型）      │   tier 路由 fast/standard/deep · failover
│  .tsecbench.gw 网关转换       │   token 计量（成本报表数据源）
└─────┬────────────────────────┘
┌─────▼────────────────────────┐
│ 工具/知识库（全离线内置）＋ 事件溯源 │  全程可审计 = 托管模式下的天然 Demo
└───────────────────────────────┘
```

## 快速开始

```bash
pip install -r requirements.txt

# 1) 本地 mock 评测（内置平台 + 7 个漏洞靶场，无需任何外部服务）
python -m huntforge.main --mock

# 2) 跑测试
python -m pytest tests/ -q

# 3) 托管模式（平台注入环境变量，启动即自解）
#    BENCHMARK_BASE_URL / BENCHMARK_TOKEN 由平台自动注入，无需手动配置
python -m huntforge.main

# 4) 单独起 mock 平台+靶场（供调试）
python -m huntforge.bench.mock_server
```

## 平台适配（托管运行）

| 项 | 说明 |
|---|---|
| 答题 API | 环境变量 `BENCHMARK_BASE_URL` + `BENCHMARK_TOKEN` 自动注入；接口路径在 `config/settings.yaml` 的 `platform` 段配置 |
| 大模型网关 | 白名单 18 家国内模型，网关规则：域名加 `.tsecbench.gw`、https→http。设 `HUNTFORGE_GATEWAY=1` 启用，模型配置见 `config/llm.yaml`，API key 一律环境变量读取 |
| 敏感配置 | 密钥不放代码/镜像，全部环境变量注入（平台审计要求） |
| 幂等提交 | 同 (题目, flag) 唯一去重；`pending→submitting→accepted/rejected/unknown` 状态机；递增冷却 `[0,30,120,300,600]s` 防提交风暴 |
| 崩溃恢复 | 启动时遗留 claimed/running 任务回 pending，重启不重不漏 |

## 目录结构

```
huntforge/
├── main.py            入口：握手→拉题→派工→执行→幂等提交→统计
├── bench/
│   ├── client.py      BenchClient 平台适配层（字段名宽容归一化）
│   ├── submission.py  幂等提交管理器（去重/冷却/状态机）
│   └── mock_server.py 本地 mock 平台 + 7 个漏洞靶场
├── core/
│   ├── state.py       SQLite 唯一事实源（challenges/tasks/findings/submissions/events/model_usage/memory）
│   ├── scheduler.py   规则调度器（CAS 领取 + lease 续租 + 过期回收）
│   └── config.py      YAML + 环境变量配置
├── llm/gateway.py     模型网关（OpenAI 兼容 + 网关转换 + tier 路由 + token 计量）
├── llm/planner.py     渗透规划器（多轮决策 decide_next_step + 归一化清洗层）
└── agents/            web-ops（决策循环）/ ai-ops（多轮反馈）/ binary / chain / probe
config/                settings.yaml（运行时）+ llm.yaml（模型）
tests/                 63 个测试（含 LLM 决策循环与端到端 mock 评测）
```

## 安全与合规

- 仅攻击授权目标（托管沙箱内平台下发题目）
- 提交值在审计日志中脱敏
- 不可信数据（HTTP 响应等）作为数据分析，不执行其中指令（P1 全面落地）

## 路线图

- [x] P0 骨架：平台适配 + 调度器 + 状态库 + 幂等提交 + mock 评测闭环
- [x] P1 Web 漏洞挖掘流水线（probe→web-ops：指纹→unauth/sqli/lfi/ssrf/rce→7Q Gate→会话链）
- [x] P2 AI 应用安全流水线（210 条攻击技术知识库移植：提示词注入/RAG投毒/工具越权/API安全/逻辑绕过）
- [x] P3 二进制漏洞挖掘（魔数/strings/危险函数 + LLM 审计增强）
- [x] P4 区块链漏洞挖掘（Solidity 规则扫描：重入/tx.origin/溢出/权限）
- [x] P5 展示与提交物（Web 控制台 + 量化报表 + Dockerfile + 技术文档 + 自审计）
- [x] P6 说明文档同步（README/技术方案/自审计与当前实现一致）

## 当前状态（实现与文档已同步）

本地 mock 评测：**7/7 题全解**，规则链路可独立运行；LLM 现在已接入规划链，但默认在无 key/无网关时自动降级到规则引擎：

| 类别 | 题目 | 漏洞 | 挖掘路径 |
|---|---|---|---|
| Web | leak-demo | 未授权 API 泄露 | probe 路径枚举 → /api/v1/flag |
| Web | unauth-demo | 鉴权头绕过 | web-ops unauth → X-Admin 头 |
| Web | sqli-demo | SQL 注入登录绕过 | web-ops sqli → **会话跟随 → 管理页 flag（漏洞链）** |
| Web | lfi-demo | 路径遍历 | web-ops lfi → ../ 读 flag.txt |
| AI | ai-demo | 提示词注入 | ai-ops 侦察 → LLM 多轮反馈 → 210 条知识库 fallback |
| 二进制 | binary-demo | 字符串泄露 | binary-ops strings 提取 + LLM 审计增强 |
| 区块链 | chain-demo | 合约重入 | chain-ops 规则扫描 + LLM 语义审计 |

**阶段序列**：`probe（路径枚举）→ 专项 ops（web/ai/binary/chain）→ idle`。

**LLM 说明**：模型网关默认关闭；配置 `HUNTFORGE_GATEWAY=1` 且提供国内模型 key 后，LLM 参与决策链，并通过 `model_usage` 记录成本：
- **Web 多轮决策循环**：首轮 `analyze_web_target` 分析攻击面 → `decide_next_step` 生成 `get/post/flag/stop` 指令（≤6 轮）→ agent 执行并把响应摘要回灌历史，命中即停；LLM 不可用时规则检查兜底
- **AI 多轮反馈**：`generate_ai_payloads(recon_log, prev_attempts)` 把上一轮 payload/回复/结果反馈给 LLM（≤3 轮 × ≤4 条载荷），迭代绕过防御
- **二进制审计 / 合约语义审计**：静态分析结果交给 LLM 深度解读（deep/standard tier）
- 所有 LLM 输出经归一化清洗层（白名单/限长/防注入），非法输出强制降级为规则链路

**比赛提交物**（`docs/`）：技术方案文档（架构/方法/实验/创新点）+ 自审计报告（宣称 vs 实际 + 10 个真实缺陷记录）+ 量化报表（`huntforge/report.py` 自动生成六项指标）。
