# HuntForge 铸猎 · 技术方案文档

**AI 攻防全链路构建与实践落地 · 参赛作品**

---

## 一、项目概述

HuntForge（铸猎）是一个面向 SRC 定向漏洞挖掘与二进制漏洞自动化分析的自主 Agent 系统。系统支持三种运行形态：

1. **托管模式（启动即自解）**：Docker 镜像部署，自动握手平台答题 API → 拉取题目 → 按题目类型路由到对应挖掘流水线 → 证据门禁验证 → 幂等提交答案，全流程无人值守。
2. **TSecBench 实盘模式**：`python -m huntforge.main --live`，LiveRunner 编排 3 worker 并行解题，管理容器生命周期（启动/等待就绪/攻击/关闭）、期望值排序、hint 策略与提交回退。
3. **Claude Code 驾驶舱模式**：参考 VulHunter 的 lead + agent teams 架构——Claude 通过 `huntforge.driver` CLI 与 MCP 工具链直接指挥解题，并行派发子 agent，知识库按题面召回通用方法论。

系统覆盖比赛全部四类题目：
- **Web 漏洞挖掘（67%）**：probe 侦察 + web-ops 综合挖掘（指纹 → 未授权/SQLi/LFI/SSRF/RCE 专项检查 → 漏洞链）
- **二进制漏洞挖掘（20%）**：静态分析（魔数/strings/危险函数）→ 启发规则 → LLM 深度审计（可选增强）；f1 远程协议题走 TCP socket 交互流，f2 固件题自动获取容器 `/download` 的 ELF 静态求解
- **AI 漏洞挖掘（7%）**：内置 210 条 AI 攻击技术（提示词注入 59 / RAG投毒 36 / 工具越权 33 / API安全 51 / 逻辑绕过 31）
- **区块链漏洞挖掘（6%）**：Solidity 静态规则扫描（重入/tx.origin/整数溢出/权限/delegatecall）

## 二、技术架构

```
┌─ 驾驶舱（Claude Code）─────────────┐
│  CLAUDE.md 作战手册 / driver CLI     │   决策 + 子 agent 并行派题 + 手测高价值题
│  .mcp.json（25 工具）/ slash 命令    │
└──────────────┬─────────────────────┘
┌──────────────▼─────────────────────┐
│  BenchClient / TsecBenchClient      │   拉题 /openapi/v1/challenges · 提交 /submit
│  BENCHMARK_BASE_URL/TOKEN           │   启动/关闭容器 · hint（TSecBench API）
└────────────┬───────────────────────┘
┌────────────▼───────────────────────┐
│  LiveRunner 实盘编排（3 worker）     │   期望值排序 + 12min 冷却 + 8h 窗口尝试计数
│  名额等待不杀容器 / 打满时间盒       │   状态库持久化 .huntforge/live.db
└─────┬──────────┬───────────────────┘
┌─────▼─────┐ ┌──▼───────────────────┐
│ Web 流水线 │ │ 专项流水线            │
│ web-ops   │ │ ai/binary/chain-ops   │
└─────┬─────┘ └──┬───────────────────┘
┌─────▼──────────▼───────────────────┐
│ 知识库（通用方法论，禁止背题）        │   playbooks 压缩手册（web/binary/multi-stage）
│  skills/*.md 题面召回 + 经验库归档   │
└─────┬──────────────────────────────┘
┌─────▼──────────────────────────────┐
│ 模型网关（pro=max 大脑 + flash 干活 + glm 备）│   tier 路由 fast/standard/deep · failover
│  429 退避 · 请求去重 · 计量          │   reasoning_effort low（省 token）
└─────┬──────────────────────────────┘
┌─────▼──────────────────────────────┐
│ 工具/知识库（全离线内置）＋ 事件溯源    │   全程可审计 = 全流程自动化证据
└─────────────────────────────────────┘
```

**关键设计原则**：
1. **规则权威、LLM 决策分层**：调度/路由/预算/重试全部规则化；LLM 只在指纹判定、Web 多轮探测决策、AI payload 定制与反馈迭代、漏洞验证、逆向审计五个位置介入。无公网可运行、成本可精确计量、行为可复现。
2. **SQLite 作为协调控制面**：任务领取用 UPDATE-CAS 原子操作 + lease 租约（过期自动回收），崩溃重启后遗留任务自动回 pending，保证"不重不漏"。
3. **幂等提交状态机**：`pending→submitting→accepted/rejected/unknown`，同一 (题目, flag) 由哈希去重唯一约束，递增冷却 `[0,30,120,300,600]s` 防提交风暴。
4. **阶段序列推进**：`probe（路径枚举）→ 专项 ops（漏洞挖掘）→ idle（等待更高阶段）`，某阶段解出即停，避免无限重扫；平台换题（target 变化）自动复位重测。

**架构级能力（四大参考项目源码研习后植入）**：
- **ABANDON 三层停损**（CHYing-agent：关键词计数 + 关键词交集 + 调用签名去 IP/域名 + CVE 变体检测 + 突破解锁），工具调用执行前拦截、强制换方向，拦截原因写入 memory lessons 回灌。
- **Fact-Intent 黑板 + OODA + Bootstrap**（Cairn）：探测结果结构化落 Fact、探索方向落 Intent（open→claimed→done CAS 生命周期），planner 决策前置 Observe/Orient/Decide/Act，事实充分时 Bootstrap 免 LLM 直接产指令。
- **五角色 Agent**（ctfSolver）：Explorer/Scanner/Solver/Executor/Actioner 统一基类 + 真实事件流 + 时间盒。
- **EvidenceStore**（D0Pagent）：证据带 confidence/source，平台提交结果为最终权威自动回校准（accepted→candidate 提 verified；rejected→同值证据证伪 killed）。
- **六态状态机**（D0Pagent）：idle→exploring→scanning→exploiting→validating→solved/failed，禁止零产出跨级跳转，终态守卫防重跑。
- **SSE 实时看板**（ctfSolver/Cairn）：原子操作日志流以 events 表为唯一事实源（零模拟日志），前端时间轴 + Agent 状态卡片 + Fact-Intent 力导向图 + 调用详情抽屉。

## 三、核心方法

### 3.1 Web 挖掘流水线（web-ops）
1. **指纹识别**：内置规则库（30 条头/正文/路径特征）零成本识别 nginx/thinkphp/spring/actuator/shiro 等技术栈，**指纹驱动专项检查排序**（如 actuator → unauth 优先，thinkphp → RCE 优先）。
2. **LLM 多轮决策循环**：首轮 `analyze_web_target` 分析攻击面（隐藏路径/注入参数/WAF 特征/检查优先级）后，进入 `decide_next_step` 驱动的多轮探测——LLM 基于历史响应摘要生成 `get/post/flag/stop` 指令（≤6 轮），agent 执行并把结果回灌历史，命中 flag 即停。LLM 输出经归一化层强制约束（动作白名单、同源路径校验、kv 键白名单、无候选自动降级 stop），不可用或输出非法时自动降级。
3. **专项检查**：LLM 循环未命中时执行，五类检查全部规则化：
   - **unauth**：35 个管理/API 路径枚举 + 6 种鉴权头绕过（X-Admin/X-Forwarded-For/X-Original-URL…）
   - **sqli**：登录表单注入绕过（`' or '1'='1' --`）+ 参数布尔盲注差异探测（恒真/恒假响应对比）
   - **lfi**：8 种遍历载荷 × 12 个文件参数 × 4 种路径形态，passwd 特征与 flag 正则双判定
   - **ssrf**：URL 类参数替换内网地址（回环/元数据/IPv6），内网服务特征判定
   - **rce**：命令注入回显探测（`;id`/`|id`/`$(id)`）+ SSTI 探测（`{{7*7}}`）
4. **漏洞链**：SQLi 登录绕过后自动提取会话凭据，跟随访问管理页抓取 flag（`注入→会话→数据泄露` 链路，结构化记录在 finding 的 confirm 字段）。
5. **7Q Gate 证据门禁**：每个发现必须证据完整（url/request/response/impact）+ 复现确认 + 实质影响，防误报（纯信息泄露默认 kill，防报告灌水）。

### 3.2 二进制流水线（binary-ops）
- 魔数识别（ELF/PE/Mach-O）→ 无依赖 strings 提取（ASCII+UTF-16LE 双通道）→ flag 正则命中即提交
- 危险函数启发（strcpy/gets/system/popen…）→ 漏洞类型候选
- **LLM 深度审计（可选增强）**：配置模型 key 时用 deep tier 对静态分析结果做语义审计（`chat_json` 强制结构化输出），无 key 时规则链路完整可用

### 3.3 AI 应用流水线（ai-ops）
- 四形态交互适配（OpenAI 兼容 / /chat JSON / form / GET 反射）自动发现
- **LLM 多轮反馈**：侦察（中性消息）→ `generate_ai_payloads(recon_log, prev_attempts)` 生成针对性载荷，每轮执行结果（payload/回复/命中与否）回灌给 LLM 迭代优化（≤3 轮 × ≤4 条载荷），命中 flag 立即停止
- **知识库 fallback**：210 条内置攻击技术按价值排序遍历（提示词注入优先），LLM 不可用或未命中时兜底
- 响应分析分层：严格 flag 命中 > 敏感泄露线索（password/api_key/env 特征）> 拒绝识别

### 3.4 区块链流水线（chain-ops）
- 8 类规则（重入/tx.origin/delegatecall/selfdestruct/时间戳随机数/权限集中）+ pragma/SafeMath 溢出启发
- 源码 flag 直接搜索（硬编码泄露）

### 3.5 实盘编排（LiveRunner，TSecBench）
- **调度**：3 worker（2 个 top 期望值 + 1 个 easy 快速通道）；期望值 = 分值 × 难度先验 + 题面特征加成（未授权/S3/路径类 +0.2，e 系列 +0.25，d 系列 +0.15）
- **容器纪律**（run-8928 事件日志复盘产物）：同题 12min 冷却杜绝"关掉即重开"；尝试计数按 8h 窗口持久化（跨重启生效，新任务自然清零）；名额满轮询等待、绝不强关他人正在攻击的容器；解出立即 close 释放名额；单题攻击打满时间盒
- **f1 协议题直达 TCP 流**：跳过 HTTP 探测（旧逻辑每轮白烧 ~60s），`tcp://` 目标交给 web-ops script 循环做 socket 交互并打满时间盒
- **f2 固件题不再弃权**：自动获取容器 `/download` 的 ELF，binary-ops 静态分析 + LLM 审计打满时间盒
- **提交回退**：判错自动 `flag{↔FLAG{` 前缀大小写回退一次；本地已解决集合防平台列表滞后重选

### 3.6 知识库（通用方法论，禁止背题）
- **压缩手册**（`knowledge/playbooks.py`）：WEB / BINARY / MULTI_STAGE 三份，按题面特征（协议/固件/心跳 → 二进制；内网/横向/官网 → 多阶段）强制注入决策上下文
- **专项手册**（`knowledge/skills/*.md`，按题面关键词召回 top-N）：多阶段渗透、SSRF 绕过与内网跳板、导出类命令注入、SSTI、越权/批量赋值、TCP 协议服务、二进制校验器逆向
- **经验库**（`skill_store.py`）：成功解题自动从黑板 Facts/Findings/提交记录归档 skill，下次同类题召回注入
- **原则**：只沉淀可迁移的方法与模式识别（如"SSRF 先按失败类型分诊再选绕过路径"），**禁止预置题目答案/凭据/定向链**——防止模型拿着旧答案对新题生搬硬套产生幻觉

### 3.7 Claude Code 驾驶舱
- **driver CLI**（`huntforge/driver.py`）：`board / list / start --wait / close / submit（大小写回退）/ hint / status / attack（复用 LiveRunner 全链）/ skill（知识召回）`，UTF-8 输出适配 Windows 终端
- **MCP**（`.mcp.json` + `scripts/mcp_server.py`）：28 个工具（tcp_probe/telnet_login + WSL Kali 全家桶 + gen_pickle/gen_deser/shiro/weaver POC + bin_triage/bin_run/bin_angr）以 stdio JSON-RPC 暴露给 Claude Code
- **子 agent 模式**：lead 用 Task/Agent 工具并行派题；子 agent 只攻击（题面全文 + 知识召回内容 + scratch 脚本迭代），开/关容器与提交由 lead 统一执行，避免并行抢容器
- **slash 命令**：`/hf-board` `/hf-attack` `/hf-submit`

## 四、实验结果

### 4.1 本地 mock 评测

评测环境：7 个靶场覆盖四类（Web×4 / AI×1 / 二进制×1 / 区块链×1），本地 mock 模式稳定全解 7/7；在未配置网关或 key 时自动降级为纯规则链路，配置白名单模型后可启用 LLM 规划与审计增强。

**真实模型验证（deepseek-v4-flash 真实 key，本地直连）**：全链路评测 7/7 全解（81.2s），14 次真实 LLM 调用（7184 in / 8977 out / 512 cache tokens）全程写入 `model_usage`。事件溯源可见 LLM 真实参与决策：SQLi 题 LLM 多轮推理式尝试（登录注入 → Cookie 探 /flag → Werkzeug 控制台探测）、unauth 题 LLM 发现 /flag 路径、AI 题多轮反馈后载荷升级为 base64 编码变体。推理模型偶发把 max_tokens 耗尽在 reasoning 上返回空 content（实测约 1/3 概率），网关自动翻倍 max_tokens 重试解决。

### 4.2 TSecBench 实盘

- **成绩**：34/63 题、10400 分。Claude 驾驶阶段新增 7 题（+2800 分）：报表导出命令注入、OA SQLi→后台 SSTI、SSRF 编码绕过→内部配置→管理端点、批量赋值覆写路径→任意文件读取、协议服务负偏移越界写 guard、心脏滴血超长声明越界读、许可证校验器静态求解（构造合法密钥真机验证）。
- **复盘（run-8928-events.csv）**：发现并修复"解题前期不停开关题目"的调度缺陷——同题 84s 无效开关循环、强关他人容器互相打断、重启丢尝试计数导致同题被攻打 5-6 次。修复后全部由 LiveRunner 的冷却/持久化/等待名额机制约束（见 3.5）。
- **短板**：多阶段渗透（b 系列 0/3）为下一轮重点，已配套 multi-stage 手册与入口侦察打法；f2-02/f2-03 凭据已解出，新任务可直接提交验证。

| 指标 | HuntForge | 传统人工（基线估计） |
|---|---|---|
| 漏洞发现率（mock） | 7/7（100%） | 4-5/7 |
| 误报提交 | 0（Gate 拦截 100% 无意义发现） | 常有无效提交 |
| 单题平均时长 | 纯规则 ~1.6s；真实 LLM 全链路 ~11.6s/题 | 10-30 min |
| 大模型成本 | 纯规则 0 次调用；真实 LLM 全链路 14 次调用 / 16.2K tokens，写入 `model_usage` | N/A |
| 人机验证比例 | 0%（全自动） | 60-80% |

事件溯源完整记录全流程：`system.start → challenges.fetched → task.created → finding.added → gate.verified → submission.queued → submission.accepted → system.end`，托管模式全程审计即天然 Demo。

## 五、与题目评分维度的对应

| 评分维度 | 对应设计 |
|---|---|
| Web 漏洞 67% | probe+web-ops 五类专项 + 漏洞链（会话跟随）+ 指纹驱动 |
| 二进制 20% | 静态分析 + 启发规则 + LLM 审计闭环（发现→定位→验证） |
| AI 漏洞 7% | 210 条攻击技术知识库 + 四形态适配 |
| 区块链 6% | Solidity 规则扫描 + 溢出启发 |
| 全流程自动化 | 事件溯源 + 幂等提交 + 崩溃恢复 + 启动自解 |
| 量化指标 | report 模块自动生成六项指标报表 |

## 六、创新点

1. **规则引擎为主 + LLM 决策为辅的分层架构**：主链路默认可脱离 LLM 独立运行，离线可用、成本可复现；LLM 只在高价值节点介入，单题 LLM 成本可精确计量。
2. **SQLite 事务式调度**：CAS 领取 + lease 租约 + 崩溃恢复，用最轻依赖实现多 worker 不重不漏。
3. **阶段序列推进 + 换题复位**：避免死循环重扫，平台换题自动感知。
4. **幂等提交状态机**：错误提交罚分场景的保命设计（去重/冷却/unknown 重试上限 + 大小写前缀回退）。
5. **AI 攻击知识库复用**：移植自自有项目 210 条实战技术，团队在该方向有持续积累。
6. **容器纪律调度（实盘沉淀）**：冷却/持久化窗口计数/名额等待不杀容器——根治"解题前期不停开关题目"的编排反模式，全部由 run-8928 事件日志驱动修复。
7. **去答案化知识库**：只沉淀可迁移方法论（模式识别 + 失败分诊 + 通用链），禁止预置题面答案，防止模型幻觉式套用。
8. **Claude Code 驾驶舱**：driver CLI + MCP 工具面 + 子 agent 派发模板，人工/模型混合指挥实盘解题（参考 VulHunter lead + teams 架构）。

## 七、部署与运行

```bash
# 本地 mock 评测（内置平台+7 靶场）
python -m huntforge.main --mock

# 托管模式（平台注入 BENCHMARK_BASE_URL/BENCHMARK_TOKEN，启动即自解）
docker build -t huntforge:latest .
docker save huntforge:latest | gzip > huntforge.tar.gz

# TSecBench 实盘跑分（.env 提供 BENCHMARK_BASE_URL/BENCHMARK_TOKEN）
python -m huntforge.main --live [--max-time 秒]

# Claude Code 驾驶舱（项目根目录启动 claude 后使用）
python -m huntforge.driver board
python -m huntforge.driver skill "<题面>"
python -m huntforge.driver start a-01 --wait
python -m huntforge.driver attack a-01 --timebox 480
python -m huntforge.driver submit a-01 "<flag>"
python -m huntforge.driver close a-01

# 模型网关：HUNTFORGE_GATEWAY=1 + 白名单模型 key 环境变量（config/llm.yaml）
# 密钥一律环境变量注入，代码内无硬编码（平台审计要求）
```
