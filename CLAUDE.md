# HuntForge（铸猎）— TSecBench 实盘 CTF Agent（Claude Code 驱动）

Claude Code 是本项目的**驾驶舱**：你负责决策、编排子 agent、手测高价值题；
HuntForge 提供平台控制 CLI、MCP 工具链、知识库与自动化 runner。参考架构：
VulHunter 的 lead + 持久化 agent teams，但本题场（TSecBench）的核心资源是
**容器名额与任务总时限**，一切决策围绕它们。

## 环境事实

- 平台：`BENCHMARK_BASE_URL` / `BENCHMARK_TOKEN`（项目 `.env` 已配置，
  所有 CLI 自动加载；`.env` 不入库，勿提交）。
- flag 常规路径：容器内 `/challenge/flag.txt`；flag 格式 `flag{...}` 或
  `FLAG{...}`（大小写不定，提交失败要试前缀翻转）。
- 容器上限 **3 个**；**单场任务上限 6 小时**，同分按完成速度排名——速度优先，
  快扫 easy 题先拿分，难题卡点即换，禁止恋战。
- **容器完全离线**：无外网搜索，CVE/知识库/nuclei 模板全部本地内置，
  解题全靠本地方法论 + 本地 CVE 库。
- 容器入口循环：**全部题目解出才退出**（墙钟兜底 12h，`HF_MAX_WALL_MINUTES`
  可调）——每题一个全新小会话（`driver next` 选题 → `brief` 开容器 →
  `claude -p` 单题会话 → `harvest` 收割关容器），单题会话硬时限
  `HF_SESSION_TIMEOUT`（默认 25 分钟）防死循环冻结。

## 运行模式

### 模式 A：Claude 直接驱动（默认，得分效率最高）

用 `python -m huntforge.driver <cmd>` 控制平台，解题用子 agent 并行：

```
board        # 先看面板：总分/未解列表（按分值排序）
skill <题面> # 知识召回：压缩手册 + 经验库 skill（解同类题的通用方法）
start <code> --wait
attack <code> [--timebox 480]   # 单题完整解题（启容器→agent 链→关容器）
submit <code> <flag>            # 提交（自动大小写回退）
close <code>
hint <code>
cve <指纹/关键词>              # 离线 CVE 情报（87 条库 + 4773 nuclei 索引）
```

**解题纪律（run-8928 / run-10043 实盘教训，不可违反）：**

1. **一题一容器，打满时间盒**：`attack` 会打满 480s 再关容器。禁止手动
   开 2 秒关掉重开同一题——那是最严重的浪费（历史上 f1-04 曾四连 84s
   无效开关循环、b-01 二十分钟开关 5 次）。
2. **3 名额管理**：开工前先 `board` 看 `active_containers`；名额满就等，
   绝不为开新题强关别人正在打的容器。同一题失败后 12 分钟内不要重开
   （runner 已内置冷却；手动操作同样遵守）。
3. **解出立即关容器**：submit 成功后马上 `close <code>` 释放名额。
4. **子 agent 并行**：对 2-3 道独立题目用 Claude 的 Task/Agent 工具并行
   派发子 agent，每个子 agent 的 prompt 必须包含：题面全文、容器地址、
   `skill` 召回结果、以及"用 scratch/ 下脚本迭代、拿 flag 后回报，不要
   动容器（开/关/提交由 lead 统一做）"。子 agent 返回 flag 由 lead 统一
   submit + close——避免并行子 agent 互相抢容器。
5. **每题时间盒**：入口 3 分钟无果换攻击面；同题尝试次数硬上限
   （`driver next` 内置 4 次，超限不再选——run-10043 教训：旧 fallback
   无视上限反复重打 10 道未解题，烧掉 10.9 车道小时、11 道题零尝试）。
6. **优先级**：从未打过的题绝对优先（next 内置），每道题至少打一次；
   打过的题按期望值排；多阶段 b 系列（1200-1800 分）用 multi-stage
   手册整链打，但别三题同时深钻到超时。
7. **hint 纪律**：hint 成本 10%——单题未解且已攻击满 2 分钟才允许
   `driver hint`（driver 内置 120s 门控；runner 模式 240s）；高分选手
   148 次 hint 仍大胜，hint 是廉价解题工具，但禁止开题秒拉。

### 模式 B：自动化实盘 runner

`python -m huntforge.main --live [--max-time 秒]` —— 独立跑分（3 worker
并行，内置冷却/持久化状态/容器纪律）。Claude 可在后台启动它
（`run_in_background: true`），期间用 `driver board/list` 观察、必要时
`driver submit` 手动补枪。

## 工具调用（MCP）

`.mcp.json` 已注册 `huntforge` MCP server（stdio），Claude Code 启动后自动
提供 `mcp__huntforge__*` 工具：

- `tcp_probe` / `telnet_login`：TCP 协议题（f1 系列）探测；
- `kali_katana / kali_ffuf_dirs / kali_nuclei / kali_sqlmap / kali_dirsearch
  / kali_nmap / kali_httpx`：WSL Kali 工具链（内部经 wsl 桥接）；
- 目录式工具（gen_pickle / gen_deser / shiro / weaver 等 POC，见
  `config/tools.yaml`）；
- **二进制三件套**（`huntforge/tools/rev.py`，容器原生离线）：`bin_triage`
  静态勘查（file/checksec/r2 导入/函数数/高熵段）→ `bin_run` 本地回放
  候选密钥 → `bin_angr` angr 符号执行 keygen。runner 的 binary-ops 已内置
  确定性解密流水线（单字节 XOR→keystream→查表→RC4→LCG）+ 回放验证 +
  LLM 脚本闭环（≤3 轮"生成脚本→受限执行→输出回灌"），f2 类 license/
  自解密题无需人工全程手推。

**使用规则**：
- 先手测（curl/python 脚本）形成假设，再上 Kali 工具；禁止无脑扫描。
- 工具带 `side_effect` 门禁；拿 flag 后交给 `driver submit`，不要重复提交。
- 每题的 socket 交互脚本写在 `scratch/` 下（一次性，不进库），迭代用
  pwsh 跑 `python scratch/xxx.py`。Windows 控制台 GBK：脚本首行写
  `sys.stdout.reconfigure(encoding="utf-8", errors="replace")`。

## 知识库（解题方法论，禁止背题）

- 决策循环自动注入压缩手册（`huntforge/knowledge/playbooks.py`：
  WEB / BINARY / MULTI_STAGE 三份，按题面特征选一）。
- `huntforge/knowledge/skills/*.md` 是**按题面关键词自动召回**的通用方法论手册
  （33 本，`driver skill <题面>` 取 top-2 注入）：SQLi 深水区、NoSQL/表达式
  注入、LFI/上传/XXE、API/JWT/OAuth/SAML、HTTP 头滥用、认证绕过与账户接管、
  反序列化、JS 客户端攻击、请求走私与缓存投毒、竞态与业务逻辑、二进制 pwn
  进阶、密码学攻击目录、MISC、提权与横向、云原生与 K8s、未授权服务与网络
  协议、侦察与 WAF 绕过、**打包应用密码学逆向（APK/Electron）**、**LLM Agent
  劫持（伪造模型端点）**、**Actuator/Jolokia MBean 利用**、**EVM/Anvil 攻击**，
  以及既有的 SSRF/命令注入/SSTI/越权/协议题/多阶段等。
  **只教方法与模式识别，不含任何题目的答案/凭据/题系代号**——同类新题现场
  分析，禁止生搬硬套历史答案（背答案会产生幻觉，是明确禁止项）。
- 解出新题型后：把**通用方法**（不是答案）沉淀进 skills/ 与 playbooks.py，
  供下一题复用。
- **离线 CVE 库（容器无外网，CVE 情报全本地）**：
  - `huntforge/knowledge/cve_db.yaml`：87 条精选条目（国产 OA/CMS：泛微/
    致远/用友/金蝶/通达/蓝凌/若依/帆软/禅道/齐治/深信服/海康；框架：
    Struts2/Fastjson/Shiro/WebLogic/JBoss/Jenkins/GitLab/Grafana/ThinkPHP/
    Laravel/PHPUnit/Drupal/Solr/ES/Kibana/Log4j/Spring 家族；云组件：
    Redis/MinIO/Harbor/Docker API/Nacos/XXL-Job/ActiveMQ 等；2024-2026
    新条目：Next.js 中间件绕过 CVE-2025-29927、Tomcat PUT RCE
    CVE-2025-24813、ingress-nginx CVE-2025-1974、Vite 任意文件读
    CVE-2025-30208、Ollama RCE CVE-2024-37032、PHP-CGI CVE-2024-4577、
    OFBiz 38856/49070、XWiki 24893、GeoServer OGNL 36401、PostgreSQL
    psql 注入 1094 等），每条含指纹正则 + 攻击路径 + 请求模板；
  - `huntforge/knowledge/cve_index.json`：**4773 个 CVE**（从内置 1.1 万
    nuclei 模板自动生成），命中指纹后直接给出模板路径定向扫描；
  - 查询入口：`python -m huntforge.driver cve "<指纹/关键词>"`；runner 内
    web-ops 的 CVE 引擎在规则未命中时自动匹配并直击。

## 子 agent 治理协议（借鉴 BTFly：受控子 Agent 协作）

1. **先初判后委派**：拿到题先自己完成最小初判（探测首页/读 JS/盘附件/发一次
   探测包），提出 2-3 个可证伪假设，**不要一开始就开子 agent**。
2. **委派条件**：只有出现明确证据表明存在 ≥2 条边界清晰、互不依赖、可并行
   验证的路线（不同接口/参数入口/攻击面/算法分支）时，才把次要路线交给
   子 agent，自己继续主线。
3. **每题最多 3 个子 agent**；子任务必须边界清晰，禁止多个 agent 重复猜
   同一条路线。派发前把必要参数/样本写进 `artifacts/<code>/`，并给每个
   子任务写一份契约 JSON（artifacts/<code>/subtask-01.json）：
   `{"category","question","summary","artifactPaths","expectedOutput"}`。
4. **主线不停**：子 agent 是扩宽搜索面，不是你的替身；派发后立即继续主线
   攻击，不要空等。只有 lead 能判定题目完成——"已枚举/已委派/得到单一猜测"
   都不算完成，除非独立验证了 flag 或记录了可复现的阻塞证据。
5. 子 agent prompt 模板（Task 工具）：

```
Task(description="解题 <code> 子任务 <n>",
     prompt="""
你在解 TSecBench 题目 <code>（<难度> <分值>）的一个子任务。
题面：<description 全文>；容器：<addr>（已开好，禁止 start/close/submit）。
契约：<subtask JSON 内容>
方法参考：<driver skill 召回结果>
规则：假设→脚本→证据→结论 迭代；scratch/<code>_*.py 存脚本（UTF-8 输出）；
flag 常规在 /challenge/flag.txt；拿到 flag 立即以 "FLAG: <原始字符串>" 回报
（不改大小写）；单点 3 分钟无果换路；禁止重复无信息增益的扫描。
""")
```

## Flag 候选上报协议

- 子 agent 回报 `FLAG: xxx` 后，lead 先落证据再提交：
  `python -m huntforge.driver report <code> "<flag>" --confidence 90 --summary "..." --evidence artifacts/<code>/exp.py`
  （写入 `artifacts/<code>/flag-candidate-*.json`；加 `--submit` 立即提交）。
- 提交判错但证据强时，保留候选文件并重试大小写变体；不重复提交同一值。
- runner 自动化模式不经过此协议（自带幂等提交），Claude 驱动模式强制走。

## 假设驱动解题纪律（防无效空转）

1. 每题先写 2-3 个**可证伪假设**（如"登录框存在 SQLi""导出文件名未过滤"），
   对最高优先级假设做一次最小验证再铺开。
2. 迭代闭环：假设 → 命令/脚本 → 证据 → 结论/下一步；失败记录原因并换路。
3. 禁止：重复无信息增益的扫描、爆破、长篇猜测；同一端点 5 轮工具调用无
   新信息立即停止换方向。

## 强制交付物（每道打过的题）

- `artifacts/<code>/`：证据（脚本、关键响应、截图/OCR 文本）。
- `artifacts/<code>/final-result.json`：
  成功 `{"status":"solved","flags":[{"value":"...","verified":true,"evidence":"..."}]}`，
  失败 `{"status":"unsolved","flags":[]}`。
- 结束轮次前输出战果摘要：新解题目、提交结果、总分、未解清单与阻塞原因。

## 验收/调试

- 全量测试：`python -m pytest tests/ -q`（172 用例，2 分钟）。
- MCP 冒烟：`python -c "from scripts.mcp_server import handle; print(handle('tools/list', None, 1))"`。
- driver 冒烟：`python -m huntforge.driver skill 报表导出`。
- 状态库持久化在项目 `.huntforge/live.db`（尝试计数/冷却跨重启保留）。

## 设计约束

1. **禁止幻觉**：没有实际请求/响应支撑的 flag 不得提交（浪费提交额度）。
2. **禁止背题**：知识库只沉淀通用方法；发现自己在引用"上次那道题的答案"
   时立刻停止，按方法论现场重解。
3. **容器纪律**：见上"解题纪律"，run-8928 的开/关刷屏是反面教材。
4. **成本纪律**：LLM 调用走 config/llm.yaml 网关（**最后一场方案：全部
   deepseek-v4-flash + MAX 最大推理模式，fast/standard/deep 三 tier 同模型**）；
   Claude Code 自身经 scripts/anthropic_shim.py 接同一模型
   （ANTHROPIC_MODEL=flash、ANTHROPIC_SMALL_FAST_MODEL=flash，shim 统一
   reasoning_effort=max，快上游故障自动降级主上游重试）。每次决策前检查
   是否真的需要调模型；规则/脚本/本地 CVE 库能做的不用模型。
