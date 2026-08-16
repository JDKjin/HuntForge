# 条件竞争与业务逻辑绕过手册

适用题型（命中即召回本手册）：条件竞争 竞态 race-condition TOCTOU 并发
并发下单 多线程 优惠券 积分 库存 barrier 业务逻辑 价格篡改 负数 流程跳跃
重放 越权 审批 二阶注入 二阶SQLi 二阶XSS 存储型 验证码 风控

## 1. 识别与分类
- 竞态判据：一次性/余额/库存类操作"先检查后写入"非原子；同一请求并发 N 次
  出现 N 个成功或余额为负/重复记账/重复领取。
- 业务逻辑判据：价格/数量/状态字段可被客户端改写；多步流程可跳过中间步直达终点。
- 二阶判据：输入被存储后延迟使用(审核/导出/报表/批处理/cron/通知/第三方同步)。
- 分类：TOCTOU 超发 / 多步状态机跳跃 / 价格与字段篡改 / 重放与无限次数 /
  越权审批 / 二阶注入 / 验证码风控缺陷。

## 2. 攻击方法论
1. 找竞态面：redeem / apply_coupon / claim_reward / transfer / purchase / vote /
   verify_token / reset_password 等非幂等状态变更接口。
2. 并发模板：`threading.Barrier(N)` 同步 N 线程 + requests 同发同一请求(或
   aiohttp/grequests 并发)；发 20~100 个副本，记录每个状态码与响应。
3. 判定：预期 0/1 次成功 vs 实际 N 次成功/负余额/重复行 → 确认超发；也对比
   串行(1 次)与并行(N 次)结果差异。
4. 价格篡改：quantity 设负数/小数(0.02)/极大值(2147483648 溢出)、price=0 或负、
   直接改 total=0.01、删掉必需字段骗免费档、多优惠券叠加超 100%。
5. 流程跳跃：直接 POST 最终步 confirm/reset/dashboard，跳过支付/邮箱验证/MFA/
   审批；重复一次性步骤(同一优惠券多次 apply、同 token 多次用)。
6. 越权审批：改 uid/order_id/org_id 枚举相邻值；低权重放高权接口；改 role/status
   字段(self-trigger refund/shipped)；审批后状态未锁可重复提交。
7. 二阶注入：把 payload 存进用户名/资料/文件名，在管理员搜索、报表导出
   (Excel/PDF)、批处理(重命名/压缩/转换)、cron、webhook 处触发。
8. 验证码/风控：验证码在响应体/头/JS 泄漏、空值/固定值通过、删字段、跨账号复用、
   4~6 位无锁定爆破；并发绕过按次计数器(非原子自增)。

## 3. 变体与绕过
- 无回显/盲打：二阶 SQLi 用 `' AND '1'='1` 或 `';WAITFOR DELAY '0:0:5';--`(MSSQL)
  / `';SELECT SLEEP(5);--`(MySQL) 时间盲测确认；用唯一 canary 标记
  (__CANARY_1234__)追踪数据从输入流向输出。
- 过滤/前端绕过：数组参数 couponid[0]/couponid[1] 叠优惠券；删 disabled/readonly；
  字段名大小写/加空格/数组形式绕字段黑名单；前端 JS 校验一律当不存在。
- 对齐强化：HTTP/1.1 last-byte sync(hold 最后 1 字节再同时 flush)；HTTP/2
  single-packet(多流合一段，<100μs 间隔)；多设备并发占住"新人/首单"优惠资格后
  依次支付叠加时长。
- 竞态边界：先看有无 SELECT...FOR UPDATE / UNIQUE 约束 / 幂等键；幂等键缺失或
  可预测(时间戳/自增)即可重放。

## 战法要点
- 竞态先打"一次性/余额"接口，成功率最高；纯扫描器看不到，只能手测。
- 并发判定看服务器端证据(重复成功/负余额/重复行)，不要只看单次 200。
- 价格类先试负数/小数/删除字段/整数溢出，再试改 total 与状态字段。
- 多步流程每一步都问"跳过会怎样、重复会怎样、乱序会怎样"。
- 二阶注入触发点比注入点更关键：审核页/导出/批处理/cron/webhook 最可疑。
- 验证码类先查响应是否泄漏/是否接受空值与固定值，再并发爆破或删字段。
- 越权先换 id 枚举(水平)再低权打高权接口(垂直)，改 X-Forwarded-For 伪装内网。

## 速查清单
```text
并发:  barrier = threading.Barrier(20)
       def f(): barrier.wait(); requests.post(url, json={...})
价格:  quantity=-1 / 0.02 / 2147483648 ; price=0/-99.99 ; total=0.01
流程:  直接 POST /confirm 或 /reset {"payment_status":"paid"} 跳过前步
二阶:  username=test' OR '1'='1 ;  ';WAITFOR DELAY '0:0:5';-- / SELECT SLEEP(5)
验证码: 空值/固定值/删字段/响应泄漏/并发绕过计数器
越权:  改 uid/order_id 枚举; 改 role/status; 数组 couponid[0]
```
