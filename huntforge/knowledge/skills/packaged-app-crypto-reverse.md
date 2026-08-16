# 打包应用密码学逆向手册（APK / Electron）

适用题型（命中即召回本手册）：apk android 安卓 dex smali jadx 签名证书
signature certificate res/raw assets encrypted xor aes 派生密钥 deriveKey
electron asar node 打包应用 移动端 逆向 flag 加密 校验

## 1. 识别与分类
- 目标只下发一个 APK/ZIP：flag 一定在应用内——「打包应用密码学」形态。
- 判据：题面无 Web 端点；/download 或首页直接给 .apk；Electron 应用是
  zip 壳（内含 app.asar + *.exe）。
- 高分频套路（实盘 5 题同型）：`flag 密文 = 内置 blob XOR 派生密钥`，
  密钥几乎都派生自 **APK 签名证书** 或 dex 内硬编码常量。

## 2. 攻击方法论（步骤即命令）
1. **解包**：jadx（`jadx -d out app.apk`，dex→java 全量）；无 jadx 时
   手写 DEX 解析器兜底（strings 表 + fill-array-data 载荷直接抠）。
   Electron：`unzip app.asar` 失败时手解 asar 头（json 头 → 文件表 →
   偏移拷贝 main.js）。
2. **签名证书提取**（密钥派生的关键原料）：
   - `openssl pkcs7 -inform DER -in META-INF/*.RSA -print_certs -out cert.pem`
   - **v1 JAR 签名证书 = RSA 文件里完整的 846 字节 X.509**；v2 签名块里
     截出的 566 字节子序列是错的——`Signature.toByteArray()` 返回前者。
   - 派生：`key = SHA-256(certDER)` 或 `blob XOR SHA256(cert)`，逐字节循环。
3. **dex 常量挖掘**：字符串表找 FlagManager/deriveKey/decrypt/ENC/base64
   长串；`jadx` 直接读方法体；smali 里 `fill-array-data` 后面就是密文数组。
   **uleb128 陷阱**：字符串表里 blob 前常有 uleb 长度前缀被误读进常量
   （如 "+KlQoy6..." 的 '+' 是长度字节，真实 blob 从下一字节开始）。
4. **解密链复刻**（python 复刻 + 原运行环境双验证）：
   - 逐字节 XOR：`plain[i] = ENC[i] ^ key[i % len(key)]`
   - 右旋/左旋组合：`dec = rotr(ENC[i], i % 7) ^ key[i]`（见题面提示的
     旋转量从常量表找）
   - AES-GCM/ECB：密钥常量 + nonce/IV 从协议或 res 里取
   - 结果必须命中 flag{...} 且可读，否则检查 blob 边界/编码层数
     （base64 一层、uleb 一层、hex 一层）。
5. **Binder/协议校验题**：onTransact code 0 发 nonce → code 1 校验
   `md5(nonce||proto_key)` → 通过后 getFlag()。先按协议喂正确校验值，
   不要硬碰校验。
6. **flag 拼接**：多 seed 多段（label 切分）+ `flag{` + seed 串 + `}`。

## 3. 变体与绕过
- jadx 报反编译错 → 转 smali（`jadx --show-bad-code`）或 baksmali。
- key 不在 dex 而在 res/raw/platform_cfg（32 字节）→ key 与 cfg 都提取。
- 校验通过但 flag 错位 → 换 SHA-1/MD5 派生、试 cert 的 DER 与 PEM 两种。

## 战法要点
- 先找「密文 blob」与「密钥派生函数」，两者齐了直接 python 复刻，别逐行读逻辑。
- 签名证书永远先试 v1 完整证书，再试 v2 块内子串。
- uleb 前缀、base64 解码边界是最常见的两个坑。
- 复刻结果与 jadx 反编译代码或原应用运行输出双验证后再提交。

## 速查清单
```text
jadx -d out app.apk                    # 全量反编译
jadx -j 4 --show-bad-code -d out app.apk
unzip -l app.apk | grep -Ei 'raw|assets|RSA|dex'
openssl pkcs7 -inform DER -in META-INF/CTF.RSA -print_certs -out cert.pem
python - <<'EOF'
import hashlib
cert = open('cert.pem','rb').read()
key = hashlib.sha256(cert).digest()
enc = bytes.fromhex('<hex from fill-array-data>')
flag = bytes(enc[i] ^ key[i % 32] for i in range(len(enc)))
print(flag)
EOF
```
