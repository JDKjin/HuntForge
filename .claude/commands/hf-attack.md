---
description: 攻击一道题（开容器→知识召回→agent 链→关容器），用法 /hf-attack <code>
---

对题目 $ARGUMENTS 执行完整攻击流程：

1. `python -m huntforge.driver skill $(python -m huntforge.driver status $ARGUMENTS 的题面)` ——
   先做知识召回（读题面关键词选手册 + 经验库 skill），把召回内容加入攻击上下文。
2. `python -m huntforge.driver start $ARGUMENTS --wait`
3. 用 Task/Agent 子代理并行攻击（题面全文 + 容器地址 + 知识召回内容作为
   prompt；子代理只攻击，不开/关容器、不提交）。
4. 拿到 flag 后：`python -m huntforge.driver submit $ARGUMENTS "<flag>"`
   然后 `python -m huntforge.driver close $ARGUMENTS`。
5. 若子代理无果且时间富余：`python -m huntforge.driver attack $ARGUMENTS --timebox 480`
   （复用 runner 的完整 agent 链，内置冷却与容器纪律）。

纪律：同一题失败后 12 分钟内不要重开容器；解出立即 close 释放名额。
