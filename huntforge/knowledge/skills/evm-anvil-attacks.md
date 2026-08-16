# EVM 合约与 Anvil 未授权攻击手册

适用题型（命中即召回本手册）：evm solidity 合约 anvil hardhat foundry rpc
eth ethereum web3 智能合约 casino 抽奖 selfbalance isSolved storage slot
setBalance impersonate 区块链

## 1. 识别与分类
- TCP 菜单题（选项含 "get flag"/"check solved"）+ 下发 RPC 地址与合约
  地址/私钥 → EVM 合约题，flag 由合约 `isSolved()` 判定后经菜单吐出。
- 裸 anvil：`POST rpc {"method":"web3_clientVersion"}` 返回
  `anvil/vX.Y.Z` 且 **dev 命名空间不鉴权** → 直接改写链状态，最短路。

## 2. 攻击方法论
1. **情报收集**：菜单先全点一遍——合约地址、部署者私钥、RPC 地址经常
   直接泄露（送分点）。
2. **判定条件定位**：反汇编合约字节码（菜单常给 bytecode 或地址）：
   - `isSolved()` 常见段 `504715` = selfbalance + iszero（余额为 0 即解）；
   - 或 storage 槽位值比较（slot0 == magic）。
   - 用 `eth_getCode` 拉字节码，r2/evm 反汇编或直接 grep 特征字节。
3. **最短路（anvil dev 命名空间）**：
   - `anvil_setBalance(<合约地址>, 0)` → isSolved 立即 true（余额题）；
   - `anvil_impersonateAccount` + `anvil_setStorageAt(<合约>, slot, value)`
     改写任意状态变量；
   - `anvil_setCode` 整体换码；
   - `evm_snapshot`/`evm_revert` 重放。
4. **正规路（dev 被封时）**：按合约逻辑玩——resolve/commit/claimPrize
   抽奖（部署者私钥在手 = 直接调函数）；伪随机数预言（blockhash/timestamp
   可控）预测结果；`selfdestruct`/`transfer` 把余额清空或转走。
5. **提交**：改完状态回菜单选 get flag，拿原始字符串提交。

## 3. 变体与绕过
- RPC 403 → 只读 eth_call 白盒分析，找内部函数选择子；
- 合约字节码只有地址 → `eth_getCode(addr)` 拉码本地反汇编（evm disasm
  或手写 jumpdest 分析，构造 calldata 调函数）。

## 战法要点
- 先试 dev 命名空间（anvil_*），一行 JSON 顶千行 exploit。
- 余额类判定（selfbalance+iszero）首选 anvil_setBalance。
- 存储类判定用 eth_getStorageAt 读槽 + anvil_setStorageAt 改写。

## 速查清单
```text
curl -s rpc -d '{"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}'
curl -s rpc -d '{"jsonrpc":"2.0","id":1,"method":"anvil_setBalance","params":["0x<合约>","0x0"]}'
curl -s rpc -d '{"jsonrpc":"2.0","id":1,"method":"anvil_setStorageAt","params":["0x<合约>","0x0","0x0000...0001"]}'
curl -s rpc -d '{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["0x<合约>","latest"]}'
curl -s rpc -d '{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":["0x<合约>","0x0","latest"]}'
# isSolved 特征字节（字节码中搜索）: 504715 = selfbalance + iszero
```
