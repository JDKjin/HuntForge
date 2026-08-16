# 二进制漏洞挖掘解题手册（HuntForge 预置打法）

二进制题分两类：f1 远程协议服务（交互式）与 f2 固件/文件分析（静态）。

## A. f1 远程协议题（TCP 端口服务，socket 交互打法）
用 script 写 socket 客户端（socket/struct 模块），一次脚本多轮交互，观察响应差异。

1. **握手探测**：先发空包/换行/"help"/"HELP"/"version"/"login"，记录服务欢迎语
   与错误格式；响应里的菜单、命令列表、版本号都是情报。
2. **命令枚举**：常见词表批量试：help flag cat ls dir read get download upload
   admin root login ping echo version whoami secret debug dump print list exec
   shell 123456 admin password，观察哪些返回不同（存在命令 vs 未知命令）。
3. **参数 fuzz**：对已知命令的每个参数位逐字节/逐字 fuzz，找长度字段溢出
   （超长输入导致崩溃=溢出点）、格式串（%x %s %n 回显内存）、整数溢出。
4. **协议结构逆向**：抓响应推断报文格式（magic/长度/类型字段），用 struct
   打包构造报文；长度字段改大改小测越界读写。
5. **隐藏功能**：输入异常（负值、超大值、特殊字符、路径穿越 ../）常触发
   隐藏分支；flag 常藏在某个命令的参数里或溢出后 ret 到读 flag 的函数。
6. **常见弱口令**：root/admin/toor/guest/test/123456/空口令组合试登录。
7. **边界与保护机制**（实战高频）：偏移类写命令试 0/±1/负偏移/整数回绕
   （4294967295 类）；长度类声明命令把声明长度调到远超实际数据（心脏滴血式
   越界回显）；guard/canary 字段被越界写坏后 reveal 类命令吐 flag；
   状态常只在单连接内有效，攻击序列要在同一连接完成。
   详见 skills/protocol-service-pwn.md。

## B. f2 固件/二进制文件题（静态分析）
1. **file 定性**：ELF/PE/固件镜像；固件先用 binwalk -e 解包，再分析文件系统
   （/etc/passwd、配置文件、后门口令、flag 文件）。
2. **strings 抓线索**：全量 strings 后按 flag/口令/key/URL 关键词筛；
   发现 XOR/base64/hex 数组（KEY=0x41 + 字节序列）就逐字节解码试。
3. **r2 分析**（内置 kali_r2_info/r2_flags）：入口点、符号表、字符串引用，
   定位 flag 校验函数 → 逆逻辑或直接 patch；checksec 看防护决定打法
   （无 PIE+CANARY 的栈溢出直接 ret2 已知地址）。
4. **危险函数定位**：system/execve/strcpy/gets/sprintf 交叉引用，找可控输入流。
5. **编码 flag**：flag 常被 hex/base64/XOR/rot13 编码后嵌入——strings 后对
   每个可疑串批量解码（hex → bytes、base64、单字节 XOR 爆破、rot13）。
6. **校验器/自解密壳**（license checker / unpacker 形态）：strings 出现
   "License accepted."/"Unpacker" 类地标时走静态求解——找 .data/.rodata 高熵
   加密 blob 与查找表/常量，识别 RC4/XOR 常量/状态机/hash-PRNG 模式，用已知
   明文 FLAG{ 反推密钥流（每字符 2-4 分支 DFS 剪枝），变长密钥时枚举长度用
   seed 轮转 padding 验尾部，最后构造合法密钥回放二进制验证。
   详见 skills/binary-license-re.md。

## C. 通用原则
- 先静态后动态：strings/r2 能直接找到的（明文 flag、硬编码口令）不要逆向。
- Kali 工具链已挂载（r2/checksec/objdump/gdb/python3），脚本可在沙箱内跑 pwntools。
- 每题限时：静态分析 2 分钟内无果就换 LLM 深挖，不要死磕单点。
