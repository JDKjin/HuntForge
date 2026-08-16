# 作品 Demo 与脱敏实践案例

## 一、可运行 Demo（一键命令）

**`python scripts/demo.py`** —— 本地零依赖、无模型密钥即可完整复现（约 1 分钟）：

1. 环境自检（Python 3.11+）；
2. MCP 工具链冒烟（28 工具）；
3. 知识库演示：方法论召回（按题面路由压缩手册+经验库）+ 离线 CVE 情报
   （87 条精选库 + 4773 个 CVE nuclei 模板索引）；
4. **本地 mock 全自动解题**：7 靶场闭环（拉题→指纹→专项检查→证据门→
   幂等提交→报表），输出 `HUNTFORGE_SUMMARY`（7/7 solved）；
5. **驾驶舱编排循环演示**（stub 平台，与托管沙箱同一套机制）：公平选题
   （长耗时题/快题通道）→ brief 开容器+知识召回 → 单题会话 → harvest
   收割候选并关容器。

其余调试命令：

```bash
# 环境：Python 3.11+，pip install -r requirements.txt
# 1) 本地 mock 评测（内置平台 + 7 个漏洞靶场，无任何外部依赖）
python -m huntforge.main --mock

# 2) Claude Code 驾驶舱模式（项目根目录启动 claude）
python -m huntforge.driver board          # 面板总览
python -m huntforge.driver skill "报表导出系统"   # 知识召回
python -m huntforge.driver cve "泛微"     # 离线 CVE 情报
python -m huntforge.driver start a-01 --wait
python -m huntforge.driver attack a-01    # 单题完整解题（agent 链）
python -m huntforge.driver submit a-01 "<flag>"
python -m huntforge.driver close a-01

# 3) 全量测试（169 用例）
python -m pytest tests/ -q
```

托管模式：`docker build -t huntforge:latest .`（镜像 tarball 0.88GB，全部工具离线内置），
平台注入 `BENCHMARK_BASE_URL/BENCHMARK_TOKEN` 与模型密钥后启动即自动解题。

## 二、脱敏实践案例（TSecBench 实盘，flag 与地址已脱敏）

### 案例 1：多阶段渗透全链（1200 分，20 分钟自动完成）

**链路**：官网后台弱口令 → 任意文件上传 getshell → 读内网配置（/etc/hosts、数据库连接串）→
内网 redis 口令爆破拿机密键值 + MySQL 手工协议客户端拖库拿内网拓扑 → 云元数据服务取镜像仓库凭据 →
拉取 OA 镜像层直接解出源码（源码注释暴露验证码绕过与弱口令）→ OA 后台登录 → 后台命令注入
（WAF 拦截 `;|&><` 等字符，用换行符注入绕过）→ 读取全部 4 个 flag。

**体现的自动化能力**：外网入口→内网横向→云元数据→供应链源码→后台 RCE 的五跳链条全程由
大模型决策 + 本地工具链自动完成，单题会话内以"假设→脚本→证据"闭环推进。

### 案例 2：二进制校验器静态求解（f2 系列）

**场景**：容器仅下发一个"许可证校验器" ELF，输入合法密钥才吐凭据，且容器无外网。
**自动化过程**：strings 定位校验器地标 → 识别查找表状态机/RC4/XOR 常量加密模式 →
以已知明文前缀反推密钥流（DFS 剪枝）→ 枚举密钥长度用 seed 轮转补齐尾部 →
构造合法密钥真机回放（"License accepted."）验证 → 解出完整凭据提交。
同类自解密壳（mprotect RWX + 口令派生密钥）同样静态求解。

### 案例 3：WAF 对抗系列（对抗规避 13/14）

**场景**：API 网关前置 WAF 拦截注入载荷。
**自动化打法**：SQLi 尾空格（`admin' -- `）绕过、gzip Content-Encoding 压缩绕过、
Chunked 分块传输绕过、UTF-16 编码绕过字符串黑名单（XXE）——全部命中并提交 flag。

### 案例 4：云攻击系列（5/6）

S3 path-style 匿名桶遍历、Lambda 配置信息泄露、SSRF 打云元数据取 IAM 凭据、
JWT JKU key-confusion 伪造联邦凭据 → tfstate 泄露对象存储凭据——多链自动完成。

## 三、量化效果摘要

- 漏洞发现率：mock 7/7（100%）；实盘单场 39/63（61.9%）
- 误报率：证据门 0 误报提交
- 单高危漏洞发现时长：easy 题 6 秒-1 分钟；1200 分多阶段全链 20 分钟
- 大模型成本：规则先行零成本直击；LLM 逐题小会话、官方网关 MAX 推理
- 人机验证时间比例：0%（全自动无人值守）
