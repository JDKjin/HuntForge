# 云服务配置泄露与对象存储攻击手册

## 规律
- 云题（S3/Lambda/EC2/Azure）的 flag 几乎都来自"配置泄露"：bucket 公开列、
  函数环境变量、容器凭证文件、管理接口未授权，而不是真实漏洞利用。
- 首页/README/错误页会直接点名 bucket 名、路径、端口：**题面与响应里的
  <bucket>/<key>、company-assets、secret-data 等字样是免费情报**，先列桶、
  读对象，别去猜。
- flag 常在对象列表的文件名或文件内容里，格式可能被 URL 编码/换行包裹，
  抽取时做 url-decode 后再匹配。

## 打法
1. 列 bucket：GET /<bucket>?list-type=2&prefix= 或根路径 XML 列表；解析 Key。
2. 读对象：GET /<bucket>/<key>，逐个读 README/credentials/.env 类文件。
3. Lambda/EC2：尝试实例元数据 169.254.169.254（IAM 凭证 → 后续接口）。
4. 拿到疑似凭证后按题面描述走"换 token / 换接口"流程（多步提交）。
5. 页面 HTML/JS 里的路径、README.txt 内容直接进 hidden_paths 跟进。

## 签名缺陷与越权桶前缀（实盘 bctf-38 模式）
- 上传/注册接口的 `objectKey`（桶前缀）**完全受控** + 签名只验密钥不绑定
  key 本身 → 用最短前缀（如 `v1`）注册后，`GET /bucket/v1/` 携带任意有效
  签名即可**列举整个前缀下的所有对象**，包括其他用户/题目的私密对象。
- 打法：先在上传接口把 objectKey 改成攻击者可控的最短前缀 → 再用列表接口
  枚举该前缀 → 命中 `secret/flag.txt` 类 key 直接读。
- 判据：上传请求里有 objectKey/bucket 前缀参数；列表接口只校验签名
  不校验前缀归属。

## 战法要点
- 拿到签名凭证先试"最短前缀枚举"，越权桶列举比猜 key 快得多。
- 对象列表里的文件名本身就是 flag 线索（secret/flag/private 关键词）。
- 签名参数（policy/expires/signature）原样复用，只改 key/prefix 字段。
