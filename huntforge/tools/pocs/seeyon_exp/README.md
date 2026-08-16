# SeeyonExp

致远 OA 漏洞验证工具。工具仅把脱敏进度摘要写到终端；session、Cookie、
webshell 连接信息等敏感证据只写入调用方显式指定的 JSONL 文件。

## 用法

```powershell
python tools/phases/seeyon_exp/seeyon_exp.py `
  --url https://target.example `
  --output tmp/evidence/seeyon.jsonl

python tools/phases/seeyon_exp/seeyon_exp.py `
  --file targets.txt `
  --output tmp/evidence/seeyon-batch.jsonl
```

需要执行利用验证路径时增加 `--att`。
默认校验 HTTPS 证书。只有在明确接受目标证书风险时才增加 `--insecure`；该选项
只影响本次运行，并且仅在不安全请求的局部上下文中抑制证书警告。

`--output` 是必填参数，并且必须满足：

- 路径位于当前工作目录内；
- 文件及其父目录不能是符号链接、junction 或其他 reparse point；
- 每条发现以一行 JSON 写入；
- 不再使用或隐式创建 `result.txt`。

HTTP 请求统一使用连接/读取超时。异常输出不会包含响应正文、Cookie 或身份标识。
