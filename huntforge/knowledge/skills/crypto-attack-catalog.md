# 密码学攻击速查手册

适用题型（命中即召回本手册）：RSA 因数分解 低指数 共模 Wiener Coppersmith LLL 格攻击 ECDSA nonce ECB CBC 填充预言机 比特翻转 流密码 keystream 长度扩展 生日攻击 MD5 0e 古典密码 Vigenere 凯撒 频率分析 crypto

## 1. 识别与分类
- 给 n,e,c 三参数→RSA；hex/base64 密文先解码还原字节再定方案；相同明文块产生相同密文块→ECB；填充报错可区分→CBC 填充预言机；改密文使下一块明文翻转→CBC 比特翻转；两密文异或得两明文异或→流密码 keystream 复用；纯字母文本→古典密码。
- RSA 参数判别：n<512bit→sympy 直接分解；e 很小且明文短→开 e 次方；e 很大→d 小走 Wiener/Boneh-Durfee；多组 n→两两 gcd 找共因子；同 n 不同 e→共模；p≈q→Fermat；p-1 光滑→Pollard p-1。
- 古典特征：全大写且频率不均→单表替换；频率平坦（IC≈0.04）→多表 Vigenere；统一移位→凯撒；纯 01/.-/数字对→编码类先解再判。

## 2. 攻击方法论
1. 因数分解：`from sympy import factorint; p,q=list(factorint(n))`；较大 n 用 yafu/msieve（离线本地）；多 n 两两 `gcd` 找共因子；p、q 相近用 Fermat 开方逼近。
2. 低指数开方：`from gmpy2 import iroot; m,e=iroot(c,e)`（m^e<n 无取模时）；广播同 e 多 n 用 `from sympy.ntheory.modular import crt` 合并再开 e 次方。
3. 共模：`g,s1,s2=gcdext(e1,e2); m=pow(c1,s1,n)*pow(c2,s2,n)%n`（负指数先 `invert`）。
4. Wiener 小 d：对 e/n 连分数展开逐收敛子反解 d（判据 d<n^0.25/3）；更宽 d 走 Boneh-Durfee（d<n^0.292，LLL 归约）。
5. Coppersmith 小根：明文高比特已知时 `R.<x>=PolynomialRing(Zmod(n)); f=(known+x)^e-c; f.small_roots(X=2^unkbits)`；部分 p 泄露同法 beta=0.5；Franklin-Reiter 相关消息（m2=a*m1+b）用两多项式 gcd 求公共根。
6. LLL 格判定：ECDSA nonce 复用直接 `k=(h1-h2)*inv(s1-s2,q)%q; x=(s1*k-h1)*inv(r,q)%q`；nonce 偏置/泄露走 HNP 构格 CVP；背包密度<0.94 走 CJLOSS 格；LCG 截断输出走递推格。
7. ECB 剪贴/逐字节：字节翻转 `ct[pos]^=old^new`；byte-at-a-time 用可控前缀构造字典比对目标块，逐字节还原追加的 secret。
8. CBC 填充预言机：末字节猜 0..255 使 padding=0x01 命中，逐字节前移解整块；工具 padbuster 或自写 oracle 脚本。
9. 流密码复用：`c1^c2=m1^m2`，用已知明文 crib 拖动恢复；单字节 XOR 用英文频率打分爆破；重复密钥用汉明距离定长 + 逐列爆破（或 xortool）；LFSR 用 Berlekamp-Massey 恢复反馈多项式。
10. hash：长度扩展 `hashpump -s MAC -d data -k len -a ext`（仅 MD5/SHA1/SHA256/SHA512，SHA3/HMAC 免疫）；生日攻击找 2^(bits/2) 碰撞；弱比较——md5 结果为 `0e`+数字的串在 PHP `==` 松比较下按科学计数法 0 处理，两个 0e 串恒等。
11. 古典破解流：字符集→频率/IC→定类别：凯撒穷举 25 位移打分；单表替换按 ETAOIN 频率映射；Vigenere 用 Kasiski/IC 定键长再逐列凯撒；转置（栅栏/列置换）按行列重排；XOR 用 xortool/crib 拖动。
12. 通用求解流程：①识别方案（参数/密文形态）②找误用（弱参数/密钥复用/可控 IV/无 MAC 完整性校验/弱随机数）③写 exploit——RSA 出私钥解密、分组出明文、流出 keystream、hash 出碰撞或扩展。
13. 编码与爆破：弱口令 hash 用 `hashcat -m 0 hash.txt wordlist.txt`（模式 0=MD5、100=SHA1、1000=NTLM、1800=sha512crypt）；PoW 找 sha256 前导 0 用循环递增 nonce 拼前缀。

## 3. 变体与绕过
- RSA 同明文不同 e 且 e 互素→共模；e 相同明文带线性关系→Franklin-Reiter；有解密 oracle 泄露 LSB→二分区间恢复明文（每轮密文乘 2^e）。
- CBC IV 可控：伪造第一块明文 `P0=IV^D(C0)^want`（配合明文注入）；填充预言机防误报用 0x02 0x02 二次确认。
- CTR/流密码：同 nonce+key 复用即 two-time pad；已知明文直接反推 keystream 解密其余块。
- LCG 恢复：已知若干输出解模方程，截断输出走格；Mersenne Twister 624 个输出可完整恢复状态。
- 双加密（2DES 类）用中间相遇：正向建表 2^n，反向查表匹配。
- hash 0e 绕过仅对 `==` 松比较有效，`===` 免疫；向 md5() 传数组使其返回 NULL，NULL==NULL 亦绕过。
- 古典多层套娃：密文常 base64→hex→凯撒 逐层包装，每层用 file/熵/字符集判断后再解下一层。
- RSA-CRT 故障签名：正确签名与错误签名（或已知明文与签名）之差 gcd 出 p：`p=gcd(pow(sig,e,n)-m,n)`。

## 战法要点
- 先识别方案再找误用：拿到参数先归类（RSA/分组/流/hash/古典），别直接爆破。
- RSA 攻击按参数选：e 小→开方、e 大→Wiener、多 n→gcd、同 n 双 e→共模、已知部分明文→Coppersmith。
- 分组模式看行为：重复块=ECB、填充报错=CBC oracle、可控翻转=CBC bitflip。
- hash 先判构造：Merkle-Damgard（MD5/SHA1/SHA256/SHA512）才可长度扩展。
- 离线无 factordb 等在线工具：用 sympy/gmpy2/yafu/msieve/fpylll 本地算。
- SageMath 本地可用优先（small_roots/LLL 最省事），否则 fpylll + sympy 替代。
- 拿密文先解码还原到字节再分析，base64/hex 只是包装不是方案。
- 分组长度、填充报错、输出长度差异都是 oracle，别只盯明文。

## 速查清单
```text
sympy.factorint(n) ; gmpy2.iroot(c,e) ; gmpy2.invert(e,phi)
sympy.ntheory.modular.crt(ns,cs)         # 广播/CRT
g,s1,s2=gcdext(e1,e2)                    # 共模
hashpump -s MAC -d data -k L -a ext      # 长度扩展
xortool -b file ; xortool -c 20          # XOR 分析
python3 RsaCtfTool.py -n N -e E --uncipher C   # 自动化(若本地已装)
fpylll: IntegerMatrix + LLL.reduction    # 格归约
padbuster URL CT 16 -encoding 0          # 填充预言机
z3: Solver().add(cond); s.check(); s.model()   # 约束求解
python3 -c "from collections import Counter"   # 频率分析
hashcat -m 0 hash.txt wordlist.txt        # 弱口令爆破
john --wordlist=rockyou.txt hashes.txt     # CPU 爆破
openssl enc -d -aes-128-cbc -in c.bin -k key   # 对称解密测试
```
