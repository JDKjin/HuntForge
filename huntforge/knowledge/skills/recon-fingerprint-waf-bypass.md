# 侦察指纹与访问控制/WAF 绕过手册

适用题型（命中即召回本手册）：侦察 子域 目录 端口 指纹 JS端点 API文档 源码泄露 .git .svn .DS_Store 备份文件 CVE nuclei 401 403 绕过 路径变体 头部注入 方法篡改 WAF 编码 分块 解析差异 IP伪装

## 1. 识别与分类
- 侦察三阶段：资产面（子域/IP/端口）→ 指纹（组件/框架/版本）→ 攻击面（目录/端点/JS/API 文档/源码泄露），先广后深。
- 指纹判据：响应头 Server/X-Powered-By、Cookie 名（PHPSESSID/JSESSIONID）、404 默认页、静态资源路径带版本、/actuator /version /phpinfo。
- 访问控制判据：401/403 区分——401 无凭据、403 已拒绝；403 目录 + 200 具体文件 = 路由存在可绕；404 才是真不存在。

## 2. 攻击方法论
1. 子域枚举：被动 curl "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value'、subfinder/amass；主动 ffuf -u https://FUZZ.target.com -H "Host: FUZZ.target.com" -mc 200,301,403；vhost 用 Host 头爆。
2. 端口与指纹：nmap -sV -F；httpx -title -tech-detect；curl -sI 看 Server/X-Powered-By/Cookie；whatweb 批量。
3. 目录/端点/JS/API：ffuf -u https://T/FUZZ -w 字典 -mc 200,301,302,403；gau/linkfinder 挖 JS 里的路径；测 /swagger.json /api-docs /openapi.json /v2/api-docs /graphql /actuator；GraphQL 内省 {"query":"{__schema{types{name}}}"}。
4. 源码泄露：/.git/HEAD（返 ref: refs/heads/ 即存在）→ git-dumper/GitHacker 恢复，看 config、logs/HEAD、objects；/.svn/entries 或 wc.db；/.hg/requires；/.DS_Store；备份 /backup.zip /www.zip /db.sql /config.php.bak /index.php.swp /.env.bak。
5. 指纹→漏洞映射（离线）：指纹清单逐条对本地 cve_db.yaml（正则+攻击路径+请求模板）与 cve_index.json（4773 模板索引）；命中即定向 nuclei -u T -t <template> -severity critical,high；版本不确定先触发默认 404/报错页取版本。
6. 401/403 绕过（按顺序）：路径变体（/admin/ /Admin /./admin //admin /admin%20 /admin%00 /admin;x /admin..;/）→ 方法篡改（POST/PUT/HEAD、X-HTTP-Method-Override、_method）→ 头部注入（X-Original-URL /admin、X-Rewrite-URL、X-Forwarded-For 127.0.0.1、X-Real-IP、True-Client-IP）→ 协议（HTTP/1.0）。
7. WAF 识别：wafw00f、看拦截页品牌与 cf-ray/x-sucuri-id 头；行为指纹——发 <script>alert(1)</script> 对比 403/重定向/延迟差异。
8. WAF 绕过（按类别）：编码（%3C、%253C 双重、%u003C、HTML 实体、SQL hex 0x756E696F6E、大小写 SeLeCt、null 字节）→ 分块（Transfer-Encoding: chunked 拆 payload）→ 解析差异（换 Content-Type json/multipart、HPP 重复参数、绝对 URI、路径归一化）→ IP 伪装（XFF/True-Client-IP 白名单）→ 换语法（UNION ALL SELECT、<svg onload>、BENCHMARK 替 SLEEP）。
9. 子域接管：CNAME 指向已删云资源（S3 NoSuchBucket、GitHub Pages "isn't a GitHub Pages site"、Heroku "No such app"）→ 在该服务商注册同名资源接管；NS 指向过期域名 = 整区接管；判据 404 专属文案可接管，403 说明资源仍在不可接管。
10. 参数与隐藏端点：arjun/x8 猜隐藏参数；读 JS/源码里的 ?token= /admin_token= 收参名；robots.txt/sitemap.xml 的 disallow 是路径提示清单；.well-known 与 crossdomain.xml 常泄露端点。

## 3. 变体与绕过
- parser differential：重复键/重复头/大小写头（Transfer-Encoding vs Content-Length）制造 WAF 与应用解析不一致——WAF 看第一个值、应用取最后一个；Unicode 全角字符（／ ． ： ＜）规范化后变路径穿越/XSS。
- **网关路径解析差异（实盘 bctf-16 模式）**：网关对路径 URL 解码后按 `/`
  切分检查关键字段，检查**之后**才把反斜杠归一化成斜杠——用
  `POST /baike\contribute/v1/xxx` 让 `baike\contribute` 整体成一个段逃过
  关键字检查，后端归一化后正常路由。判据：黑名单命中但路径变体（`\`、
  `%2f`、`//`、`;`、大小写）返回差异。
- IP 编码伪装绕过白名单：127.0.0.1 写 2130706433（十进制）/0177.0.0.1（八进制）/0x7f000001（十六进制）/localhost/::1。
- HPP 重复参数：PHP 取末值、ASP.NET 拼接、Flask 取首值——WAF 查首参数、应用取末参数时绕过。
- WAF 绕过验证：不只看 200，要确认 payload 真正生效（回显/延迟），防 WAF 静默剥离。
- 大包绕过：请求体超 WAF 大小上限（>8KB~128KB）可能整体跳过检查；multipart 文件内容常不检。
- 源码泄露 403 目录：403 目录 + 200 具体文件 = 逐个文件抓取，别被目录 403 劝退。
- 无回显绕过：用 HEAD/OPTIONS 观察状态码差异判定绕过是否命中。
- 技术栈差异化绕过：Apache 尾斜杠/点前缀、Nginx X-Original-URL、IIS 分号+后缀(::$DATA)、Tomcat 分号路径参数——按后端选对应变体。

## 战法要点
- 先定指纹再打 CVE，指纹→本地库→nuclei 定向，比盲扫快一个量级。
- 401/403 先路径变体再头部，成功率最高且零成本；最后才上协议/组合。
- WAF 拦截先判拦的是哪一层（关键字/格式/IP），按层选绕过，别乱试编码。
- JS 与源码泄露是免费攻击面，flag 常在 .env/.git/backup 里，优先抓。
- 子域接管看 CNAME 指向已删资源（NoSuchBucket 404 才可接管，403 不可）。
- 每个输入点都看"它服务端干什么"，参数类型直接映射漏洞类（URL→SSRF、文件名→穿越）。
- 报错页/404 默认页/版本接口是免费指纹，先精确化版本再查 CVE，命中率翻倍。
- 无外网时指纹→本地 cve_db.yaml 映射是唯一 CVE 通道，把指纹关键词喂给 driver cve 定向。
- 目录爆破匹配码含 403，403 不等于不存在，是后续绕过/文件抓取的线索。

## 速查清单
```text
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
ffuf -u https://T/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200,301,302,403
nuclei -u T -t cves/ -severity critical,high
arjun -u https://T/api/endpoint
gau T | grep '\.js$'
curl -s https://T/.git/HEAD
curl -s https://T/.env
GET /admin/ /Admin /./admin //admin /admin%20 /admin%00 /admin;x /admin..;/
X-Original-URL: /admin
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
POST /admin  |  X-HTTP-Method-Override: PUT
Transfer-Encoding: chunked
{"role":"user","role":"admin"}
GET /．．/．．/etc/passwd
GET /admin;.css    # IIS
GET /admin..;/    # Tomcat
```
