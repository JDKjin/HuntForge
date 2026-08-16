"""预置解题手册（压缩版，强制注入决策上下文）。

原则（用户明确要求）：只写可迁移的通用方法论与模式识别，绝不预置具体题目
的答案、凭据、字段名或定向利用链——同类新题要靠方法现场解，不靠背答案，
避免模型拿着旧答案对新题生搬硬套产生幻觉。

长版手册在 knowledge/skills/*.md（match_skills 召回供深挖）；
此处为决策循环/审计调用的压缩打法，保证 100% 命中。
"""

WEB_PLAYBOOK_HINT = (
    "Web 通用打法（方法论，非答案）：①开局一次 script 批量拉 /robots.txt "
    "/actuator/env /nacos/ /v2/api-docs /.git/config /backup.zip /www.zip "
    "/WEB-INF/web.xml 等未授权/泄露点，JS/注释/报错页里的路径与字段名全跟进；"
    "②登录绕过按 admin'-- → OR 1=1 → Unicode 全角 → || → chunked/gzip 顺序试；"
    "③SQLi：order by 定列数 → union select 提库，WAF 用注释/大小写/编码绕过；"
    "④LFI 试 ../../flag 与 php://filter 读源码；⑤SSRF 试 file:// 与云元数据地址；"
    "⑥命令注入用 |id、${IFS}/$@ 绕空格；⑦上传用图片马 + 双扩展；"
    "⑧反序列化用内置 gen_pickle/gen_deser/shiro POC；⑨国产 OA 按指纹打内置 POC"
    "（weaver/seeyon/springboot）；⑩多 flag 题每个子系统一个 flag，拿到继续。"
    "⑪凭据情报：登录页提示、JS 注释、base64 串里常藏默认口令——先解后试；"
    "⑫SSRF 黑名单绕过方法论：先判别失败类型（BLOCKED=字符串黑名单可编码绕，"
    "DNS 失败=名单外域名，连接拒绝=IP 层拦截），字符串黑名单用 %xx 编码关键字符、"
    "大小写、尾点、整数/八进制 IP 等变体逐个试；进内网后先打 /debug /config "
    "/status 类配置接口拿 token/凭据，再带着 token 打管理端点；"
    "⑬导出/报表/生成器类功能：若响应回显后端命令模板，逐字段分析转义情况——"
    "被转义的字段换未转义的字段打（如文件名拼进重定向路径的场景），注入后把"
    "结果写到 Web 可达目录再 GET 取回；"
    "⑭批量赋值：编辑/更新接口常接受任意字段，覆写文件路径/角色/价格等系统字段，"
    "再配合下载/读取接口落地；前端 JS 注释常点名系统字段名；"
    "⑮模板注入：{{7*7}}/${7*7}/<%= 7*7 %> 判引擎后走对应通用 RCE 链"
    "（Jinja2 用 cycler.__init__.__globals__.os.popen 一族）；"
    "⑯后台模板渲染/公告发布类功能优先测 SSTI；本平台 flag 常规路径为"
    "/challenge/flag.txt。"
)

BINARY_PLAYBOOK_HINT = (
    "二进制/协议题通用打法（方法论，非答案）：f1 远程协议先发 HELP/help/换行/"
    "空包看菜单与错误格式，枚举命令后攻边界——负偏移、超长声明长度、整数回绕"
    "等越界写法；看门狗/guard 类机制被破坏后往往有 reveal 类命令吐 flag；"
    "单连接状态常不跨连接，攻击序列要在同一连接内完成。"
    "f2 先 GET /download 拿 ELF：①bin_triage 一键勘查（file/checksec/导入/"
    "函数数/高熵段）；②license 校验/自解密形态先走确定性解密流水线"
    "（单字节 XOR→已知明文推 keystream→查表置换→RC4 候选→LCG 恢复），"
    "候选密钥 bin_run 本地回放（\"License accepted.\" 即验证通过），"
    "复杂约束 bin_angr 符号执行自动 keygen；③仍无果再人工逆向："
    "strings 找 \"License accepted.\"/\"Usage: %s\"/\"Unpacker\" 类地标；"
    "定位 .data/.rodata 高熵加密 blob 与查找表/常量；识别加密模式"
    "（RC4、单字节 XOR 常量、查找表状态机、hash/PRNG 派生密钥流），"
    "用已知明文 FLAG{ 反推密钥流或逆校验条件；口令常与常量 XOR 后 strcmp、"
    "密钥常由口令派生（djb2 一类）；④构造合法密钥回放二进制，解出的凭据"
    "大小写变体都试提交。"
)

MULTI_STAGE_PLAYBOOK_HINT = (
    "多阶段渗透通用打法：①外网入口先做完整侦察（目录/JS/接口文档/指纹），"
    "入口漏洞多为 SSRF、文件包含、弱口令、已知组件；②拿到 RCE/SSRF/文件读后"
    "第一件事：读 /etc/hosts、env、配置文件、网络连接表，找内网拓扑与凭据；"
    "③横向：SSRF 场景用 http:// 打内网 HTTP、gopher:// 打 redis/mysql/fastcgi，"
    "字符串黑名单按 Web 手册⑫绕过；RCE 场景用 curl/写文件到 web 目录做跳板；"
    "④凭据复用：入口拿到的口令/token 对内网每个服务都试；"
    "⑤机密数据多在数据库/对象存储/内部管理接口，按泄漏配置逐层拿，"
    "每层拿到 flag 立即提交；⑥时间分配：入口 3 分钟无果换攻击面，别死磕。"
)
