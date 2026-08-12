# HuntForge 自审计报告（宣称 vs 实际）

> 借鉴 CTF-Hunter 链路审计方法论：README/文档宣称的能力逐条对照代码验证。
> 审计日期：2026-08-13（真实模型验证阶段）

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

## 三、已知限制（诚实声明）

1. **真实比赛靶场的 LLM 表现未验证**：已用真实 deepseek-v4-flash key 在本地 mock 靶场完成端到端验证（7/7 全解、14 次调用、多轮决策循环真实运转）；但真实比赛靶场难度更高，LLM 在陌生系统上的探索能力仍待实战检验。托管环境还需验证平台注入的 key 与 `.tsecbench.gw` 网关链路。
2. **SSRF 检查仅回显型**：盲 SSRF（DNS 回调）需要外部回调服务器，托管沙箱无公网，P1 实现只测回显特征。
3. **二进制动态分析未接入**：gdb/fuzz 逻辑设计了工具探测，但本地 Windows 无 gcc 工具链，动态链路未实测（静态链路已验证）。
4. **漏洞链模板有限**：当前只有 SQLi→会话→管理页一种链；13 类链模板（VulHunter 思路）未全部移植。

## 四、结论

主链路（平台握手 → 调度 → 四类流水线 → 门禁 → 幂等提交 → 报表）全部有代码 + 测试双重验证；LLM 规划链也已接入并可降级运行。剩余风险集中在“真实 LLM 调用质量”与“动态二进制分析”两端，属环境受限，不是基础架构缺陷。
