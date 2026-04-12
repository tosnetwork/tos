# Actor Model Implementation Plan

## Context

Per the protocol design in `doc/actor.md`, TOS must transition from "one Account = one execution unit" to "one Account contains multiple Actors." Core changes: hybrid balance (per-actor budget + account shared_balance), two-phase execution (Phase 1 parallel + Phase 2 sequential merge), and 7 new TVM instructions. This is a hard-fork-level change.

---

## Module A: TL-B Schema & Account Structure

**Scope:** The foundation of the on-chain data format. All other modules depend on this.

### Files

| File | Changes |
|------|---------|
| `crypto/block/block.tlb:270-292` | Add `ActorDescriptor` type, actor-mode `AccountStorage` variant (tag-distinguished from legacy), add `actor_id:(Maybe bits256)` to Transaction, extend OutMsgQueue from 352 to 608 bits |
| `crypto/block/block-auto.h/cpp` | Auto-generated from block.tlb by `tlbc` |
| `crypto/block/block-parse.h:522-528` + `.cpp` | Branch `AccountStorage` `skip()/validate_skip()` for actor-mode; add `ActorDescriptor` parser |
| `crypto/block/transaction.h:263-345` | Add Account fields: `actor_mode`, `shared_balance`, `actors_dict_root`, `current_actor_id/budget/state/lt` |
| `crypto/block/transaction.h:348-481` | Add Transaction fields: `actor_mode`, `actor_id`, `actor_lt_start/end`, `actor_budget`, `actor_state`, `balance_requests`, `phase2_committed` |
| `crypto/block/transaction.cpp:476-530` | `Account::unpack()` detects actor-mode AccountStorage; add `unpack_actor()` / `commit_actor()` |
| `crypto/block/transaction.cpp:4022-4075` | `Transaction::commit()` actor-mode branch: write only actor-local fields, defer account-global fields to Phase 2 |

### Key TL-B Definitions

```tlb
actor_descriptor$_ state:HashmapE 256 ^Cell
    budget:CurrencyCollection actor_lt:uint64 = ActorDescriptor;

account_storage$_ last_trans_lt:uint64                      // legacy tag=0
    balance:CurrencyCollection state:AccountState
  = AccountStorage;

account_storage_actor$_ last_trans_lt:uint64                // actor tag=1
    shared_balance:CurrencyCollection
    actors:(HashmapE 256 ^ActorDescriptor)
    state:AccountState
  = AccountStorage;
```

**Complexity:** HIGH | **Dependencies:** None | **Estimate:** 3-4 weeks

---

## Module B: TVM Opcodes

**Scope:** 7 new instructions using the 0xFB09-0xFB0F range (currently unoccupied).

### Files

| File | Changes |
|------|---------|
| `crypto/vm/tosops.cpp:2388` | Add `register_tos_actor_ops(OpcodeTable&)` and call it from `register_tos_ops()` |
| `crypto/vm/tosops.h` | Declare `register_tos_actor_ops` |
| `crypto/vm/vm.h:278-315` | Add c6 register for actor state HashmapE root (`get_c6()/set_c6()`) |
| `crypto/vm/continuation.h:39` | Extend `d[]` array to support c6 |
| `crypto/block/block.tlb` | Add OutAction variants: `action_actor_send`, `action_actor_claim`, `action_actor_release` |

### Opcode Map

| Opcode | Name | Implementation Pattern |
|--------|------|----------------------|
| 0xFB09 | STATEGET | `Dictionary(st->get_d(6), 256).lookup(key)` -> push slice |
| 0xFB0A | STATESET | `Dictionary(st->get_d(6), 256).set(key, value)` -> set_d(6) |
| 0xFB0B | STATEDEL | `Dictionary(st->get_d(6), 256).delete_key(key)` -> push bool |
| 0xFB0C | ACTORSEND | Build action cell -> chain to c5 (same pattern as SENDRAWMSG) |
| 0xFB0D | BUDGETGET | `get_param(st, 18)` reads actor budget from c7 tuple |
| 0xFB0E | ACTORCLAIM | Build claim action cell -> chain to c5, push request_id |
| 0xFB0F | ACTORRELEASE | Build release action cell -> chain to c5, push request_id |

All instructions must be gated behind `->require_version(N)` for the hard-fork version.

**Complexity:** MEDIUM | **Dependencies:** Module A | **Estimate:** 1-2 weeks

---

## Module C: Transaction Execution (Two-Phase Model)

**Scope:** Split core transaction execution logic into Phase 1 tentative + Phase 2 commit.

### Files

| File | Changes |
|------|---------|
| `crypto/block/transaction.h` | Add `ActorTransactionResult` and `BalanceRequest` structs |
| `crypto/block/transaction.cpp:~1020` | `prepare_storage_phase()`: in actor-mode, storage fees are NOT deducted from budget; recorded as Phase-2 deferred charge against `shared_balance` |
| `crypto/block/transaction.cpp:~1135` | `prepare_credit_phase()`: targeted actor message value -> actor budget; legacy message -> shared_balance |
| `crypto/block/transaction.cpp:~1960` | `prepare_compute_phase()`: gas deducted from actor budget; set c6 = actor_state; c7[5]=actor_lt, c7[7]=actor_budget, c7[18]=actor_id |
| `crypto/block/transaction.cpp:~2150` | `prepare_action_phase()`: handle `action_actor_send/claim/release`; value deducted from actor budget |
| `crypto/block/transaction.cpp:4022` | Split `commit()` into `commit_phase1()` (returns ActorTransactionResult) + `commit_phase2()` (writes account-global fields) |
| New file `crypto/block/actor-merge.cpp` | Phase 2 merge logic: sort by (actor_id, actor_lt) -> prefix commit rule -> apply balance requests -> assign final lt |

### ActorTransactionResult Struct

```cpp
struct ActorTransactionResult {
  td::BitArray<256> actor_id;
  tos::LogicalTime actor_lt;
  CurrencyCollection tentative_budget;
  Ref<vm::Cell> tentative_state;
  std::vector<BalanceRequest> balance_requests;
  std::vector<Ref<vm::Cell>> tentative_out_msgs;
  Ref<vm::Cell> transaction_root;
  std::unique_ptr<Transaction> trans;
  bool committed{false}, rejected{false};
};
```

### Phase 2 Merge Pseudocode

```
sort by (actor_id ASC, actor_lt ASC)
per_actor_prefix_valid = {}
for each result:
  if !per_actor_prefix_valid[result.actor_id]:
    reject(result); continue
  for each balance_request:
    if !apply(request, shared_balance):
      reject(result)
      per_actor_prefix_valid[result.actor_id] = false
      break
  if committed:
    assign final lt, commit actor snapshot, materialize messages
```

**Complexity:** HIGH | **Dependencies:** Module A + B | **Estimate:** 3-4 weeks

---

## Module D: Collator Restructuring

**Scope:** Transform the block production flow from purely serial to Phase 1 parallel + Phase 2 merge for actor-mode accounts.

### Files

| File | Changes |
|------|---------|
| `validator/impl/collator-impl.h` | Add members: `pending_actor_results_`, `actor_lt_counters_`, `actor_prefix_valid_`; add method declarations |
| `validator/impl/collator.cpp:2379` | `do_collate_inner()`: add Phase 2 merge step after message processing completes |
| `validator/impl/collator.cpp:3349` | `create_ordinary_transaction()`: actor-mode accounts use `execute_actor_transaction()` instead of `impl_create_ordinary_transaction()`; do not immediately commit/register_new_msgs |
| `validator/impl/collator.cpp:4184` | `process_inbound_internal_messages()`: identify actor-mode targets, extract actor_id |
| `validator/impl/collator.cpp:3654` | `process_one_new_message()`: defer actor_send messages to next block |
| `validator/impl/collator.cpp:4945` | `register_new_msgs()`: actor-mode messages only registered after Phase 2 commit |
| `validator/impl/collator.cpp:3061` | `combine_account_transactions()`: actor-mode AccountBlocks include actor_id |

### Core Flow Change

```
Before:  for msg: create_tx -> commit -> register_msgs -> next
After:   for msg:
           if actor_mode:
             Phase1: create tentative result -> stash
           else:
             legacy: create_tx -> commit -> register_msgs
         // after all messages processed
         for each actor_mode account:
           Phase2: merge_actor_results -> commit -> register_msgs
```

**Complexity:** HIGH | **Dependencies:** Module A + B + C | **Estimate:** 3-4 weeks

---

## Module E: Validation Logic

**Scope:** Validators must be able to reproduce the collator's two-phase execution and verify results.

### Files

| File | Changes |
|------|---------|
| `validator/impl/validate-query.cpp:3098` | `precheck_account_updates()`: actor-mode account diffs include actors HashmapE changes |
| `validator/impl/validate-query.cpp:3291` | `precheck_account_transactions()`: verify actor_lt monotonicity per actor_id and prefix commit rule |
| `validator/impl/validate-query.cpp:5574` | `check_one_transaction()`: actor-mode requires replaying Phase 1 + Phase 2 and comparing results |
| `validator/impl/validate-query.cpp:3872` | `check_in_msg()`: handle intra-account actor messages |
| `validator/impl/validate-query.cpp:4437` | `check_out_msg()`: 608-bit queue key validation |
| `validator/impl/validate-query.cpp:6412` | `check_message_processing_order()`: actor-mode message ordering rules |
| `validator/impl/validate-query.hpp` | Add per-actor validation state tracking |

**Complexity:** HIGH | **Dependencies:** Module A + C + D | **Estimate:** 3-4 weeks

---

## Module F: OutMsgQueue Key Extension

**Scope:** Extend queue key from 352 bits to 608 bits (insert 256-bit actor_id).

### Files

| File | Changes |
|------|---------|
| `crypto/block/output-queue-merger.h:30` | `max_key_len` 352->608; `BitArray<352>` -> `BitArray<608>` |
| `crypto/block/output-queue-merger.cpp` | `unpack_node()`, comparison logic, split logic adapted to new key width |
| `crypto/block/block.cpp:2008-2021` | `compute_out_msg_queue_key()`: insert actor_id between shard_prefix and msg_hash |
| `crypto/block/block.h:731` | Update function signature to `BitArray<608>` |
| `validator/impl/collator.cpp` | All call sites of `compute_out_msg_queue_key()` |
| `validator/impl/validate-query.cpp` | Queue key validation width update |
| `crypto/block/block.tlb:243` | `HashmapAugE 352 -> 608` |

### Key Layout

```
Old: workchain(32) | shard_prefix(64) | msg_hash(256)                    = 352 bits
New: workchain(32) | shard_prefix(64) | actor_id(256) | msg_hash(256)    = 608 bits
```

Non-actor messages use zero-filled actor_id to preserve sort order compatibility.

**Complexity:** MEDIUM | **Dependencies:** Module A | **Estimate:** 2 weeks

---

## Module G: Merkle Proofs

**Scope:** Extend proof path with an actor layer.

### Files

| File | Changes |
|------|---------|
| `crypto/block/check-proof.cpp:152-207` | Add `check_actor_proof()`: Block -> Shard -> Account -> **actors(256)** -> ActorDescriptor -> state(256) -> key |
| `crypto/block/check-proof.h` | Declare `check_actor_proof()` |

**Complexity:** MEDIUM | **Dependencies:** Module A | **Estimate:** 2 weeks

---

## Module H: Lite-Client / SDK

**Scope:** Client-side support for actor-level queries.

### Files

| File | Changes |
|------|---------|
| `tl/generate/scheme/lite_api.tl` | Add `getActorState`, `getActorList` queries and response types |
| `lite-client/lite-client.cpp` | Add `get_actor_state()`, `get_actor_list()` commands; modify `got_account_state()` to display actor-mode accounts |
| `tl/generate/scheme/toslib_api.tl` | Add actor-aware SDK types |
| `emulator/transaction-emulator.h` + `emulator-extern.cpp` | Support actor-mode transaction emulation: set actor_id/budget, simulate Phase 2 merge |

**Complexity:** MEDIUM | **Dependencies:** Module A + G | **Estimate:** 2-3 weeks

---

## Implementation Sequencing

```
Week 1-4:   Module A (TL-B & Account)              <- foundation for all modules
Week 3-5:   Module B (TVM Opcodes)                  <- depends on A
Week 3-5:   Module F (OutMsgQueue Key)              <- depends on A, parallel with B
Week 4-6:   Module G (Merkle Proofs)                <- depends on A, parallel
Week 5-8:   Module C (Two-Phase Execution)          <- depends on A+B
Week 7-11:  Module D (Collator Restructuring)       <- depends on A+B+C
Week 9-13:  Module E (Validation Logic)             <- depends on A+C+D
Week 10-13: Module H (Lite-Client / SDK)            <- depends on A+G
```

Parallelizable module group: {B, F, G} can be developed simultaneously.

---

## Verification

Post-completion verification for each module:

| Module | Verification Method |
|--------|-------------------|
| A | Compiles successfully; tlbc generation passes; unpack/pack round-trip tests |
| B | Unit tests: normal/exception paths for each opcode; Fift scripts invoking new instructions |
| C | Unit tests: Phase 1 produces correct tentative results; Phase 2 merge prefix rule and rollback rule |
| D | Integration tests: multi-actor parallel block production; same-block visibility rule; block limit boundaries |
| E | Validator node passes validate-query on blocks produced by D |
| F | Queue merge tests; 608-bit key sort correctness |
| G | lite-client getActorState proof verification passes |
| H | lite-client command-line queries for actor state/list return correct results |

End-to-end test: start local testnet -> deploy actor-mode contract -> multi-actor parallel transactions -> verify block consistency.
