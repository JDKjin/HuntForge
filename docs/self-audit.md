# HuntForge 自审计报告（宣称 vs 实际）

> 借鉴 CTF-Hunter 链路审计方法论：README/文档宣称的能力逐条对照代码验证。
> 审计日期：2026-08-14（TSecBench 实盘 + Claude 驾驶舱阶段）

## 一、宣称 vs 实际对照表

| 宣称能力 | 代码位置 | 实际状态 |
|---|---|---|
| 幂等提交（去重/冷却/unknown 重试上限） | `bench/submission.py` + `tests/test_submission.py` | ✅ 通过（3 个专项测试） |
| CAS 任务领取 + lease 过期回收 | `core/state.py:claim_task` + `tests/test_scheduler.py` | ✅ 通过（并发 10 任务无重复） |
| 崩溃恢复（启动回滚遗留任务） | `core/state.py:recover_interrupted` + e2e | ✅ 通过 |
| 平台换题自动复位重测 | `core/state.py:upsert_challenge` | ✅ 通过（target 变化 → 清任务重跑） |
| 7Q Gate 证据门禁 | `web/gate.py` + `tests/test_gate.py` | ✅ 通过（6 个专项测试） |
| Web 五类专项检查 | `web/checks/*.py` + `tests/test_checks.py` | ✅ 通过（4 靶场命中测试） |
| 会话跟随漏洞链 | `web/common.py:follow_session` + sqli 检查 | ✅ 通过（sqli-demo 链式解出） |
| AI 210 条知识库 | `knowledge/`（移植自 lingops） | ✅ 210 条（59+36+33+51+31），每条含 payload |
| 二进制 strings/魔数/危险函数 | `agents/binary_ops.py` + `tests/test_binary_ops.py` | ✅ 通过 |
| 区块链规则扫描 | `agents/blockchain_ops.py` + `tests/test_chain_ops.py` | ✅ 通过 |
| 模型网关 URL 转换/failover/计量 | `llm/gateway.py` + `tests/test_gateway.py` | ✅ 通过（URL 转换、usage 记录、budget） |
| 全程事件溯源 | `core/state.py:event` + e2e 断言 | ✅ 通过（8 类事件全链路） |
| 量化报表 | `report.py` | ✅ 实现（依赖真实运行数据） |
| Web 控制台 | `webui/app.py` | ✅ 实现（本地验证） |
| LLM 规划接入 | `llm/planner.py` + `agents/*` | ✅ 通过（默认降级，启用后参与决策；web 多轮决策循环 ≤6 轮、AI 多轮反馈 ≤3 轮，fake-planner 测试覆盖；真实 deepseek-v4-flash 端到端验证 7/7） |
| TSecBench 实盘 API 客户端 | `bench/tsec_client.py` + `tests/test_driver.py` | ✅ 通过（list/start/close/hint/submit 经本地 stub 平台端到端验证，异常类型化） |
| LiveRunner 容器纪律（12min 冷却 / 8h 窗口计数 / 名额等待不杀容器） | `bench/live_runner.py` + `tests/test_planner.py` | ✅ 通过（冷却过滤与窗口计数逻辑单测覆盖；run-8928 事件日志根因修复） |
| f1 协议题 TCP 直通流 / f2 `/download` 获取 | `bench/live_runner.py:_attack` + `agents/binary_ops.py:_acquire` | ✅ 实现（f1 跳过 HTTP 探测直达 tcp:// 打满时间盒；f2 首页 HTML 自动改拉 /download） |
| 提交大小写前缀回退 | `bench/live_runner.py:_case_variant` + `tests/test_driver.py` | ✅ 通过（stub 平台判错小写→翻转重试命中） |
| Claude 驱动 CLI（board/start/attack/submit/skill…） | `huntforge/driver.py` + `tests/test_driver.py` | ✅ 通过（7 个专项测试；UTF-8 输出修复 GBK 崩溃） |
| MCP stdio 服务（25 工具） | `scripts/mcp_server.py` + `tests/test_kali.py`/`test_tool_catalog.py` | ✅ 通过（initialize/tools/list/tools/call 握手回环 + scratch/mcp_smoke.py 子进程冒烟） |
| 知识库召回（压缩手册 + 经验库 skill） | `knowledge/playbooks.py` + `knowledge/skill_store.py` + `tests/test_driver.py` | ✅ 通过（题面关键词路由 multi-stage/web/binary 手册，经验库 top-N 召回） |
| 知识库去答案化 | `knowledge/playbooks.py` + `knowledge/skills/*.md` | ✅ 完成（全部改写为通用方法论，无题号/凭据/定向链；29 本专项手册） |
| 状态库持久化（跨重启尝试计数/冷却） | `bench/live_runner.py` + `tests/conftest.py` | ✅ 通过（默认 `.huntforge/live.db`；测试经 `HUNTFORGE_LIVE_DB`/`HUNTFORGE_NO_DOTENV` 隔离） |

## 二、开发过程中发现并修复的真实缺陷（记录）

| # | 缺陷 | 触发场景 | 修复 |
|---|---|---|---|
| 1 | tasks 表缺 priority 列导致建表失败 | 首次建库 | 补列 + create_task 传参 |
| 2 | 残留 DB 复用 → 启动即"全部完成" | 二次运行同目录 | upsert 只复位 target 变化的题 |
| 3 | idle 复位 → 每轮重派死循环 | 上一条修复引入 | 终态保持，仅换题复位 |
| 4 | Gate 证据缺 request → 全 killed | ai-ops 落库 | 补全证据（url/request/impact） |
| 5 | SQLi 命中无 flag（缺链） | sqli-demo | 会话提取 + follow_session |
| 6 | AI 命中后 56 次重复提交同 flag | ai-demo | 命中 flag 即停全部探测 |
| 7 | 提交重试上限差 1（attempts 时序） | unknown 重试测试 | mark 后 attempts+1 判断 |
| 8 | LLM usage 不落库 | 真实模型调用 | ModelGateway 持有 db 并记录 usage |
| 9 | hosted 模式缺 BENCHMARK_BASE_URL 静默回退 mock | 托管运行 | 改为 fail-closed，只有 `--mock` 才启动本地 mock |
| 10 | LLM 结果未做边界约束 | planner 输出 | planner 归一化并限制路径/参数/检查项 |
| 11 | 推理模型把 max_tokens 耗在 reasoning 上返回空 content（实测 deepseek-v4-flash 约 1/3 概率） | 真实模型调用 | 网关翻倍 max_tokens 自动重试；每次尝试都计量 |
| 12 | 同题"关掉 2 秒后重开"无效循环（f1-04 四连 84s 开关、b-01 二十分钟开关 5 次） | run-8928 实盘：尝试结束后 `_select` 立即重选同题 | 12min 冷却 + 优先打未尝试过的题 |
| 13 | 重启丢尝试计数 → 同题被攻打 5-6 次（c-07 ×6） | 状态库用临时目录，跨重启清零 | 默认持久化 `.huntforge/live.db` + 8h 时间窗计数 |
| 14 | 名额满时强关他人正在攻击的容器 → worker 互相打断刷屏 | 3 worker 同时 start 撞 max_active | `_wait_for_slot` 轮询等待，绝不杀他人容器 |
| 15 | f1 题每轮白烧 ~60s HTTP 探测 + 只跑一次 tcp_probe 就关容器 | `_pick_target` 对非 HTTP 服务反复探测 | f1 直达 tcp:// 流，web-ops script 循环打满时间盒 |
| 16 | 测试进程加载真实 `.env` 污染 mock 模式（e2e 打到真实平台 404） | `driver` 测试调用 `_load_dotenv` | `HUNTFORGE_NO_DOTENV=1` 测试隔离开关 |
| 17 | driver CLI 在 GBK 控制台 UnicodeEncodeError（⑪ 等字符） | Windows 默认 GBK 输出 | stdout/stderr 强制 UTF-8 重配 |

## 三、已知限制（诚实声明）

1. **真实比赛靶场的 LLM 表现部分验证**：已用真实 deepseek-v4-flash key 在本地 mock 靶场完成端到端验证（7/7 全解、14 次调用、多轮决策循环真实运转）；TSecBench 实盘由 Claude 驾驶模式拿下 34/63 题（10400 分）。但 b 系列多阶段渗透 0/3、漏洞利用维度 1/9，是下一轮重点，已配套 multi-stage 手册与入口侦察打法。
2. **SSRF 检查仅回显型**：盲 SSRF（DNS 回调）需要外部回调服务器，托管沙箱无公网，P1 实现只测回显特征。
3. **二进制动态分析未接入**：gdb/fuzz 逻辑设计了工具探测，但本地 Windows 无 gcc 工具链，动态链路未实测（静态链路已验证；Kali WSL 内 objdump/gdb 已用于 f2 系列实战）。
4. **漏洞链模板有限**：当前只有 SQLi→会话→管理页一种自动化链；13 类链模板（VulHunter 思路）未全部移植。
5. **Claude 驾驶舱依赖人工/模型节奏**：driver CLI 与 MCP 工具面已验收（stub 平台 + stdio 握手 + 152 测试），但真实 Claude Code 会话内的子 agent 编排效果取决于 CLAUDE.md 纪律被执行的程度，需下一轮实盘观察。

## 四、结论

主链路（平台握手 → 调度 → 四类流水线 → 门禁 → 幂等提交 → 报表）全部有代码 + 测试双重验证；LLM 规划链也已接入并可降级运行；TSecBench 实盘通道（容器纪律/冷却/持久化/直通流/大小写回退）与 Claude 驾驶舱（driver CLI/MCP/知识召回）均已落地并通过 152 个测试 + 子进程冒烟验收。剩余风险集中在"多阶段渗透打法"与"真实 Claude Code 会话中的编排纪律"两端。
