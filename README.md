# HuntForge（铸猎）

> AI 攻防全链路构建与实践落地 —— TSecBench 实盘 CTF Agent

HuntForge 是一个面向 CTF 实盘攻防场景的**自主解题 Agent 系统**：以 Claude Code 为驾驶舱大脑，内置离线 CVE 情报库、33 本通用方法论手册、MCP 工具链与容器纪律调度器，支持「驾驶舱交互」与「全自动 runner」双模式，覆盖 Web / 二进制 / 协议 / 多阶段渗透 / 逆向 / 智能合约全类别。

**核心原则**：知识库只沉淀可迁移的通用方法论，不预置任何题目答案；全部密钥经环境变量注入，仓库零硬编码凭据。

---

## 特性

- **双模式一体**
  - 驾驶舱模式：Claude Code 逐题决策、并行派发子 Agent、手测高价值目标
  - runner 模式：3 worker 全自动并行跑分（期望值排序、冷却、幂等提交、证据门）
- **离线知识库**（沙箱无外网，全部本地内置）
  - 88 条精选 CVE 指纹库（国产 OA/CMS + 框架 RCE + 云组件 + 2024-2026 新条目）
  - 4773 个 CVE 的 nuclei 模板索引（内置 1.1 万模板）
  - 33 本通用方法论手册（按题面关键词自动召回，top-2 注入）
  - 成功解题自动归档经验 skill（运行时产物，不入库）
- **工具链全内置**：nuclei/katana/httpx/sqlmap/ffuf/hydra/nmap/binwalk/radare2/jadx/pwntools/angr/z3 等（Docker 镜像），MCP stdio 暴露 28 个工具
- **二进制自动化**：`bin_triage` 勘查 → 确定性解密流水线（XOR/keystream/查表/RC4/LCG）→ `bin_run` 回放验证 → `bin_angr` 符号执行 keygen → LLM 脚本闭环
- **容器纪律调度**：三通道滚动选题（未打过优先）、同题尝试硬上限、失速看门狗、多轮会话日志隔离、解出即关
- **模型网关**：OpenAI 兼容协议 + 平台网关域名重写 + tier 路由 + failover + Anthropic→OpenAI 协议转换 shim（Claude Code 接入）

## 快速开始

### 本地 mock 评测（零依赖、无需密钥）

```bash
pip install -r requirements-dev.txt
python -m huntforge.main --mock        # 内置平台 + 7 个漏洞靶场全链评测
python -m pytest tests/ -q             # 172 个测试用例
python scripts/demo.py                 # 一键 demo（拉题→解题→提交全链路）
```

### Claude Code 驾驶舱模式

```bash
claude                                    # 项目根目录启动（自动挂载 .mcp.json）
python -m huntforge.driver board         # 面板总览
python -m huntforge.driver skill "<题面>" # 知识召回
python -m huntforge.driver cve "<指纹>"  # 离线 CVE 情报
```

### Docker 托管镜像（比赛沙箱部署）

```bash
docker build -t huntforge:latest .
docker save huntforge:latest | gzip > huntforge.tar.gz
```

平台注入环境变量后启动即全自动解题：

| 变量 | 说明 |
|---|---|
| `BENCHMARK_BASE_URL` / `BENCHMARK_TOKEN` | 答题平台地址与令牌（平台自动注入） |
| `DEEPSEEK_API_KEY` | 大模型密钥（支持 `LLM_API_KEY` 兜底变量名） |
| `HF_LLM_BASE_URL` | 模型上游地址（沙箱内默认 `http://api.deepseek.com.tsecbench.gw/v1`） |

> 模型方案：全部模型统一 deepseek-v4-flash + MAX 最大推理模式（`config/llm.yaml`）。

## 架构

```
┌─ 驾驶舱层：Claude Code（决策/子 Agent 编排/手测）────────────┐
│  └─ scripts/anthropic_shim.py（Anthropic→OpenAI 协议转换）    │
├─ 平台控制层：huntforge/driver.py（board/start/submit/hint/...）│
├─ 工具层：MCP stdio（28 工具）+ huntforge/tools/rev.py 逆向链 │
├─ 知识层：playbooks.py 压缩手册 + skills/*.md 方法论库        │
│          + cve_db.yaml 指纹库 + cve_index.json 模板索引       │
├─ 编排层：huntforge/bench/live_runner.py（3 worker 纪律调度） │
│          + docker/entrypoint.sh（滚动通道 + 失速看门狗）     │
└─ 模型层：config/llm.yaml 网关（tier 路由 + failover）        │
```

## 目录结构

```
huntforge/          核心包（driver / bench / agents / knowledge / tools / llm / web）
config/             模型与工具目录配置（llm.yaml / tools.yaml）
docker/             Dockerfile 配套（entrypoint.sh 驾驶循环 / 会话提示词）
scripts/            MCP server / 协议 shim / demo / 离线索引构建
docs/               技术方案 / 自审计 / 案例（≤5000 字参赛文档）
tests/              172 用例（调度 / 网关 / 知识库 / e2e 全链）
CLAUDE.md           作战手册（Claude Code 驾驶舱操作规范）
```

## 文档

- [技术方案](docs/submission-technical.md)（参赛主文档）
- [Demo 与案例](docs/demo-cases.md)
- [自审计](docs/self-audit.md)
- [作战手册](CLAUDE.md)（驾驶舱模式操作规范）

## 许可与声明

- [MIT License](LICENSE)
- 本项目仅用于**授权目标**的安全测试与 CTF 竞赛；请遵守所在平台规则与法律法规。
- 仓库不含任何真实 API 密钥：全部凭据经环境变量注入（`.env` 已 gitignore，示例见 `.env.example` 约定）。
