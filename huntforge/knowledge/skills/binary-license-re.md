# 二进制校验器 / 自解密壳逆向手册

适用题型（命中即召回本手册）：授权 许可证 校验 固件 凭证 MCU 门锁 终端
烧录 可执行 逆向 解包 自解密 口令。

f2 类二进制题通用流程（ELF 静态求解，Kali 工具链 objdump/gdb/strings）：

## 1. 获取与定性
- 容器首页一般挂 /download 下发 ELF：先拉首页 HTML，非二进制则改拉 /download；
- strings 全文扫：flag/口令/key/URL 明文直出即走捷径；
- 找校验器地标串："License accepted." / "Invalid license key" /
  "Usage: %s <key>" → 定位 main 与校验函数；"Unpacker"/"Self-Decrypt"
  → 自解密壳形态。

## 2. 识别加密模式（决定求解路径）
- .data/.rodata 里找高熵 blob（密文）与 64/256 字节查找表、单字节常量；
- 口令校验：口令常与常量 XOR 后 strcmp（反解常量即口令）；
- 密钥派生：密钥常由口令/固定串经 hash（djb2 一类 h=h*33^c）或 PRNG 派生；
- 加解密模式：RC4（KSA/PRGA 模板）、单字节 XOR、查找表状态机、
  "字节=(a*t+b*i+state)&0xff，state=(t^const)&0xf" 一类状态机。

## 3. 已知明文求解（静态核心方法）
- 明文几乎总以 FLAG{ 开头：用前缀 5 字节反推密钥流/状态序列（每字符通常
  只有 2-4 个候选分支），加上末尾 } 与中间字符集约束做 DFS 剪枝；
- 变长密钥场景：尾部密钥流常由 seed 串轮转补齐——枚举密钥长度，对每个
  长度计算 padding 解密尾部，出英文词即命中（"…is_the_keystream" 类）；
- 解出候选后构造合法密钥回放二进制，打印 "License accepted." 即验证通过。

## 4. 自解密壳
- 口令 → 派生密钥 → 解密内嵌代码块 → mprotect(RWX) → call 执行：
  静态解密该代码块（Python 复刻派生算法），flag 常在被解密代码的尾部
  数据里（再 XOR 一个常量），或该代码就是打印 flag 的例程；
- gdb 兜底：break mprotect/call 处 dump 解密后的缓冲再 strings。
