---
description: 提交 flag 并关闭容器，用法 /hf-submit <code> <flag>
---

解析 $ARGUMENTS 为「题目编码 + flag 字符串」（空格分隔，flag 含花括号原样传递）：

```
python -m huntforge.driver submit <code> <flag>
```

- 返回 correct=true → 再执行 `python -m huntforge.driver close <code>` 释放容器名额。
- 返回 rejected（含大小写变体）→ 不重试同一 flag，回报失败原因。
