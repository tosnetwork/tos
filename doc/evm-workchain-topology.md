# EVM Workchain — Transaction Lifecycle Topology

从用户提交交易到节点存储和传播的完整数据流。

## 拓扑图

```
用户 / 钱包 (MetaMask / ethers.js / Foundry)
    │
    │  eth_sendRawTransaction (RLP-encoded signed Ethereum tx)
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                    JSON-RPC HTTP Server                      │
│               validator-engine/json-rpc-server.cpp           │
│                                                              │
│  ✅ 34 个 eth_*/net_*/web3_*/debug_* 方法                     │
│  ✅ 数组和对象参数都支持 (MetaMask 兼容)                       │
│  ✅ EIP-1559 fee history / maxPriorityFeePerGas              │
│  ✅ JSON-RPC cache 有容量上限 (max_cache_entries)             │
│  ✅ eth_subscribe / eth_unsubscribe 事件订阅                  │
└──────────────┬──────────────────────────────────────────────┘
               │
               │  evm_workchain::handle_eth_rpc()
               │  crypto/block/evm-workchain/evm-rpc.cpp
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│                  EVM Transaction Decode                       │
│             crypto/block/evm-workchain/evm-transaction.cpp   │
│                                                              │
│  ✅ RLP 解码 (silkworm::rlp::decode_transaction)             │
│  ✅ secp256k1 sender 恢复 (silkworm_recover_address)         │
│  ✅ 支持 Legacy / EIP-2930 / EIP-1559 交易类型               │
└──────────────┬──────────────────────────────────────────────┘
               │
               │  DecodedTransaction { txn, sender }
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│               Transaction Validation                         │
│           crypto/block/evm-workchain/evm-executor.cpp        │
│                                                              │
│  ✅ Nonce 检查 (Yellow Paper §6.2)                           │
│  ✅ 余额检查 (balance >= gas_cost + value)                   │
│  ✅ Intrinsic gas 检查 (21000 + calldata cost)               │
│  ✅ 读写锁保护 (std::unique_lock on EvmState::mutex())       │
└──────────────┬──────────────────────────────────────────────┘
               │
               │  Validated Transaction
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│                    EVM Execution                             │
│           crypto/block/evm-workchain/evm-executor.cpp        │
│           (calls silkworm::EVM → evmone)                     │
│                                                              │
│  ✅ Gas 预扣 (upfront deduction)                             │
│  ✅ Nonce 递增                                               │
│  ✅ EIP-2929 access list 预热                                │
│  ✅ EVM 执行 (evmone baseline interpreter)                   │
│  ✅ 所有 EVM 操作码 (Shanghai 规则)                          │
│  ✅ CALL / CREATE / CREATE2 / DELEGATECALL / STATICCALL      │
│  ✅ SSTORE / SLOAD / LOG0-LOG4 / SELFDESTRUCT               │
│  ✅ BLOCKHASH (256 块滚动历史)                               │
│  ✅ CHAINID = 0x544F53                                       │
│  ✅ 10/10 预编译合约 (ecrecover/sha256/modexp/bn254/blake2f) │
│  ✅ Gas 退款计算 + 剩余退还                                  │
│  ✅ 矿工/beneficiary 手续费支付                              │
│  ✅ EIP-1559 动态 base fee                                   │
└──────────────┬──────────────────────────────────────────────┘
               │
               │  ExecutionResult { success, gas_used, logs,
               │                    return_data, contract_address }
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│                State Commit (IntraBlockState → State)         │
│                                                              │
│  ✅ write_to_db() 提交账户/存储/代码变更                     │
│  ✅ insert_block() 存储区块供 BLOCKHASH 使用                 │
│  ✅ 读写锁保护 (unique_lock 期间独占)                        │
└──────────────┬──────────────────────────────────────────────┘
               │
               ├──────────────────────────────────┐
               │                                  │
               ▼                                  ▼
┌──────────────────────────────┐  ┌──────────────────────────────┐
│     In-Memory Index          │  │     Persistent State         │
│  (bounded, FIFO eviction)    │  │     (RocksDB)                │
│                              │  │                              │
│  ✅ receipts_ (10K cap)      │  │  ✅ Accounts (A+addr→acct)   │
│  ✅ transactions_ (10K cap)  │  │  ✅ Storage (S+addr+slot)    │
│  ✅ blocks_ (256 cap)        │  │  ✅ Code (C+hash→bytes)      │
│  ✅ block_logs_ (256 cap)    │  │  ✅ Receipts (R+hash)        │
│  ✅ hash_to_block_ (256 cap) │  │  ✅ Block number (M+meta)    │
│  ✅ shared_mutex 并发保护    │  │  ✅ thread_local code buf    │
│  ✅ FIFO insertion order     │  │  ✅ {db_root}/evm-state/     │
└──────────────────────────────┘  └──────────────────────────────┘
               │
               │  通知订阅者
               ▼
┌─────────────────────────────────────────────────────────────┐
│               Subscription Notifications                     │
│        crypto/block/evm-workchain/evm-subscriptions.cpp      │
│                                                              │
│  ✅ notify_new_head() → newHeads 订阅者                      │
│  ✅ notify_logs() → logs 订阅者 (address/topic 过滤)         │
│  ✅ notify_new_pending_transaction() → pending 订阅者        │
│  ✅ mutex 保护订阅列表                                       │
│  ✅ 事件队列 + poll() 获取                                   │
└─────────────────────────────────────────────────────────────┘


════════════════════════════════════════════════════════════════
                    交易进入区块 (主链路径)
════════════════════════════════════════════════════════════════

除了 JSON-RPC 直接执行路径，交易还可以通过主链的正常区块流程进入：

┌──────────────────────────┐
│  External Message Pool   │
│  (validator-engine)      │
│                          │
│  ✅ ext_in_msg 格式构建  │
│     (evm-external-       │
│      message.cpp)        │
│  ⬜ 实际提交到消息池     │
│     (需要运行节点验证)   │
└───────────┬──────────────┘
            │
            ▼
┌──────────────────────────┐     ┌──────────────────────────┐
│       Collator           │     │    Validator Consensus    │
│  validator/impl/         │     │                          │
│  collator.cpp            │     │  ⬜ 区块签名             │
│                          │     │  ⬜ 共识投票             │
│  ✅ process_external_    │     │  ⬜ 区块确认             │
│     message() 入口       │     │                          │
│  ✅ EVM dispatch 分支    │     └──────────┬───────────────┘
│     (workchain==2)       │                │
│  ✅ prepare_compute_     │                ▼
│     phase() → EVM        │     ┌──────────────────────────┐
│  ✅ evm-workchain-       │     │   P2P Network Broadcast   │
│     dispatch.h 回调      │     │                          │
└──────────────────────────┘     │  ⬜ 区块广播给其他节点   │
                                 │  ⬜ 其他节点验证并接受   │
                                 │  ⬜ 状态同步             │
                                 └──────────────────────────┘


════════════════════════════════════════════════════════════════
                    协议层配置
════════════════════════════════════════════════════════════════

┌──────────────────────────┐
│  ConfigParam 12          │
│  Workchain Registration  │
│                          │
│  ✅ WorkchainDescr TLB   │
│     构建 + 验证          │
│  ✅ Zerostate 生成       │
│     (root_hash +         │
│      file_hash)          │
│  ✅ workchain_id = 2     │
│  ✅ vm_version = "EVM"   │
│  ✅ chainId = 0x544F53   │
│  ⬜ 提交到测试网         │
│     masterchain          │
└──────────────────────────┘


════════════════════════════════════════════════════════════════
                    跨链桥
════════════════════════════════════════════════════════════════

┌──────────────────────────┐          ┌──────────────────────────┐
│  Basechain (Workchain 0) │          │  EVM Workchain (WC 2)    │
│                          │          │                          │
│  ⬜ 用户发送 deposit tx  │ ──────▶  │  ✅ bridge_deposit()     │
│     到桥合约             │ deposit  │     铸造等额余额         │
│                          │          │                          │
│  ⬜ Relayer 处理         │ ◀──────  │  ✅ record_withdrawal()  │
│     withdrawal           │ withdraw │     记录提现请求         │
│                          │          │  ✅ get_pending_          │
│                          │          │     withdrawals()        │
└──────────────────────────┘          └──────────────────────────┘


════════════════════════════════════════════════════════════════
                    完成度汇总
════════════════════════════════════════════════════════════════

✅ = 已完成并测试
⬜ = 未实现 (需要运行节点或测试网)

用户交易提交 → 节点处理:
  ✅ JSON-RPC 接收         (34 个方法)
  ✅ RLP 解码 + sender 恢复
  ✅ 交易验证 (nonce + balance + intrinsic gas)
  ✅ EVM 执行 (evmone, 全部操作码 + 10 预编译)
  ✅ 状态提交 (IntraBlockState → State)
  ✅ Receipt/TX/Log 存储 (有界缓存 + RocksDB 持久化)
  ✅ 订阅通知 (newHeads + logs + pending)

节点数据库存储:
  ✅ RocksDB 持久化 ({db_root}/evm-state)
  ✅ 内存索引有界 (10K receipts, 10K txns, 256 blocks)
  ✅ shared_mutex 并发保护
  ✅ thread_local code buffer (无共享可变状态)

节点间传播:
  ✅ 区块处理流程 (collator 里的 EVM dispatch 分支)
  ✅ 外部消息构建器 (RLP → ext_in_msg cell)
  ⬜ 实际区块共识 + 签名 (需要运行验证者节点)
  ⬜ P2P 区块广播 (需要多节点测试网)
  ⬜ 状态同步 (需要多节点)

协议层:
  ✅ ConfigParam 12 WorkchainDescr 构建器
  ✅ Zerostate 生成
  ⬜ 提交到 masterchain (需要测试网)
```
