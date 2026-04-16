# EVM Workchain — Transaction Lifecycle Topology

Complete data flow from user transaction submission through node processing,
database storage, and inter-node propagation.

## Topology Diagram

```
User / Wallet (MetaMask / ethers.js / Foundry)
    │
    │  eth_sendRawTransaction (RLP-encoded signed Ethereum tx)
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                    JSON-RPC HTTP Server                      │
│               validator-engine/json-rpc-server.cpp           │
│                                                              │
│  ✅ 34 eth_*/net_*/web3_*/debug_* methods                    │
│  ✅ Array + object params (MetaMask compatible)              │
│  ✅ EIP-1559 feeHistory / maxPriorityFeePerGas              │
│  ✅ JSON-RPC cache with capacity limit (max_cache_entries)   │
│  ✅ eth_subscribe / eth_unsubscribe event subscriptions      │
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
│  ✅ RLP decode (silkworm::rlp::decode_transaction)           │
│  ✅ secp256k1 sender recovery (silkworm_recover_address)     │
│  ✅ Legacy / EIP-2930 / EIP-1559 transaction types           │
└──────────────┬──────────────────────────────────────────────┘
               │
               │  DecodedTransaction { txn, sender }
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│               Transaction Validation                         │
│           crypto/block/evm-workchain/evm-executor.cpp        │
│                                                              │
│  ✅ Nonce check (Yellow Paper §6.2)                          │
│  ✅ Balance check (balance >= gas_cost + value)              │
│  ✅ Intrinsic gas check (21000 + calldata cost)              │
│  ✅ Read-write lock (std::unique_lock on EvmState::mutex())  │
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
│  ✅ Upfront gas deduction                                    │
│  ✅ Nonce increment                                          │
│  ✅ EIP-2929 access list warm-up                             │
│  ✅ EVM execution (evmone baseline interpreter)              │
│  ✅ All EVM opcodes (Shanghai rules)                         │
│  ✅ CALL / CREATE / CREATE2 / DELEGATECALL / STATICCALL      │
│  ✅ SSTORE / SLOAD / LOG0-LOG4 / SELFDESTRUCT               │
│  ✅ BLOCKHASH (256-block rolling history)                    │
│  ✅ CHAINID = 0x544F53                                       │
│  ✅ 10/10 precompiles (ecrecover/sha256/modexp/bn254/blake2) │
│  ✅ Gas refund calculation + remainder return                │
│  ✅ Beneficiary fee payment                                  │
│  ✅ EIP-1559 dynamic base fee                                │
└──────────────┬──────────────────────────────────────────────┘
               │
               │  ExecutionResult { success, gas_used, logs,
               │                    return_data, contract_address }
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│                State Commit (IntraBlockState → State)         │
│                                                              │
│  ✅ write_to_db() commits account/storage/code changes       │
│  ✅ insert_block() stores block for BLOCKHASH                │
│  ✅ Exclusive lock held during commit (unique_lock)          │
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
│  ✅ shared_mutex protection  │  │  ✅ thread_local code buf    │
│  ✅ FIFO insertion order     │  │  ✅ {db_root}/evm-state/     │
└──────────────────────────────┘  └──────────────────────────────┘
               │
               │  Notify subscribers
               ▼
┌─────────────────────────────────────────────────────────────┐
│               Subscription Notifications                     │
│        crypto/block/evm-workchain/evm-subscriptions.cpp      │
│                                                              │
│  ✅ notify_new_head() → newHeads subscribers                 │
│  ✅ notify_logs() → logs subscribers (address/topic filter)  │
│  ✅ notify_new_pending_transaction() → pending subscribers   │
│  ✅ mutex-protected subscription list                        │
│  ✅ Event queue + poll() retrieval                           │
└─────────────────────────────────────────────────────────────┘


════════════════════════════════════════════════════════════════
              Block Production Path (Host Chain)
════════════════════════════════════════════════════════════════

Transactions also enter via the host chain's normal block flow:

┌──────────────────────────┐
│  External Message Pool   │
│  (validator-engine)      │
│                          │
│  ✅ ext_in_msg format    │
│     builder              │
│     (evm-external-       │
│      message.cpp)        │
└───────────┬──────────────┘
            │
            ▼
┌──────────────────────────┐     ┌──────────────────────────┐
│       Collator           │     │    Validator Consensus    │
│  validator/impl/         │     │                          │
│  collator.cpp            │     │  ✅ Block signing         │
│                          │     │     (existing infra)     │
│  ✅ process_external_    │     │  ✅ Consensus voting      │
│     message() entry      │     │     (existing infra)     │
│  ✅ EVM dispatch branch  │     │  ✅ Block confirmation    │
│     (workchain==2)       │     │     (existing infra)     │
│  ✅ prepare_compute_     │     │                          │
│     phase() → EVM        │     │  Workchain-agnostic:     │
│  ✅ evm-workchain-       │     │  operates per-shard,     │
│     dispatch.h callback  │     │  does not distinguish    │
└──────────────────────────┘     │  TVM vs EVM execution    │
                                 └──────────┬───────────────┘
                                            │
                                            ▼
                                 ┌──────────────────────────┐
                                 │   P2P Network Broadcast   │
                                 │                          │
                                 │  ✅ Block broadcast       │
                                 │     (existing infra)     │
                                 │  ✅ Peer validation       │
                                 │     (existing infra)     │
                                 │  ✅ State sync            │
                                 │     (existing infra)     │
                                 │                          │
                                 │  Existing infrastructure │
                                 │  routes by shard.        │
                                 │  Workchain 2 blocks use  │
                                 │  the same network path   │
                                 │  as workchain 0.         │
                                 └──────────────────────────┘


════════════════════════════════════════════════════════════════
                    Protocol Configuration
════════════════════════════════════════════════════════════════

┌──────────────────────────┐
│  ConfigParam 12          │
│  Workchain Registration  │
│                          │
│  ✅ WorkchainDescr TLB   │
│     builder + validation │
│  ✅ Zerostate generation │
│     (root_hash +         │
│      file_hash)          │
│  ✅ workchain_id = 2     │
│  ✅ vm_version = "EVM"   │
│  ✅ chainId = 0x544F53   │
│  ⬜ Submit to testnet    │
│     masterchain          │
└──────────────────────────┘


════════════════════════════════════════════════════════════════
                    Cross-Workchain Bridge
════════════════════════════════════════════════════════════════

┌──────────────────────────┐          ┌──────────────────────────┐
│  Basechain (Workchain 0) │          │  EVM Workchain (WC 2)    │
│                          │          │                          │
│  ⬜ User sends deposit   │ ──────▶  │  ✅ bridge_deposit()     │
│     tx to bridge         │ deposit  │     mints equivalent     │
│     contract             │          │     balance              │
│                          │          │                          │
│  ⬜ Relayer processes    │ ◀──────  │  ✅ record_withdrawal()  │
│     withdrawal           │ withdraw │     records withdraw     │
│                          │          │     request              │
│                          │          │  ✅ get_pending_          │
│                          │          │     withdrawals()        │
└──────────────────────────┘          └──────────────────────────┘


════════════════════════════════════════════════════════════════
                    Completion Summary
════════════════════════════════════════════════════════════════

✅ = Implemented and tested
⬜ = Not yet done (requires running testnet)

User tx submission → node processing:
  ✅ JSON-RPC receive           (34 methods)
  ✅ RLP decode + sender recovery
  ✅ Transaction validation     (nonce + balance + intrinsic gas)
  ✅ EVM execution              (evmone, all opcodes + 10 precompiles)
  ✅ State commit               (IntraBlockState → State)
  ✅ Receipt/TX/Log storage     (bounded cache + RocksDB persistence)
  ✅ Subscription notifications (newHeads + logs + pending)

Node database storage:
  ✅ RocksDB persistence        ({db_root}/evm-state)
  ✅ Bounded in-memory index    (10K receipts, 10K txns, 256 blocks)
  ✅ shared_mutex concurrency   (readers-writer lock)
  ✅ thread_local code buffer   (no shared mutable state)

Node-to-node propagation:
  ✅ Collator EVM dispatch      (our code: workchain==2 branch)
  ✅ External message builder   (our code: RLP → ext_in_msg cell)
  ✅ Consensus / broadcast / sync (existing host chain infrastructure,
     workchain-agnostic, operates per-shard)

Protocol layer:
  ✅ ConfigParam 12 WorkchainDescr builder
  ✅ Zerostate generation
  ⬜ Submit config proposal to masterchain (requires testnet)
```
