---
description: HuntForge 面板总览（分数/进度/活跃容器/未解列表）
---

运行 HuntForge 面板总览并把结果翻译成一段中文战况摘要：

```
python -m huntforge.driver board
python -m huntforge.driver list
```

按输出给 lead 决策建议：活跃容器数（名额是否已满）、未解题按分值排序的
前 5 道（建议下一道打哪个 + 用哪类手册）、已得总分与完成率。
不要在此命令里启动容器。
