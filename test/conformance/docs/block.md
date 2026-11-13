## block harness

`ref/harness-block.cpp` applies one block offline, the procedure of `emulator/test/epoch-replay.cpp`
(REL-02) on the node's own code: the block's Merkle state update is validated
(`vm::MerkleUpdate::validate`) and applied to the supplied previous state (`vm::MerkleUpdate::apply`),
the configuration is extracted with `block::ConfigInfo::extract_config`, and every transaction of the
block is re-executed in account and logical-time order with `emulator::TransactionEmulator`. Each
result must equal the transaction recorded in the block, the account hash its `HASH_UPDATE` declares
and the `ShardAccount` the applied new state holds (as the collator writes it).

| Context | Meaning |
|---|---|
| `block` | the block BOC |
| `prev_state` | the previous `ShardStateUnsplit`; may be partial, every cell the procedure reads must be present |
| `master_block`, `master_state` | for a shard block: the original bytes of the masterchain block it references (root and file hash are checked) and that block's new state, the source of the configuration |

Effects: `accepted` with `block_root_hash`, `new_state_hash` and the ordered
`transactions` (`transaction_hash`, `account_hash`), or `rejected` with a `reason` class:
`malformed_block`, `split_merge_unsupported`, `state_update_invalid`, `prev_state_mismatch`,
`state_update_not_applicable`, `state_update_mismatch`, `prev_state_malformed`,
`master_context_mismatch`, `config_unavailable`, `account_unavailable`,
`transaction_context_mismatch`, `execution_refused`, `transaction_mismatch`,
`account_hash_mismatch`, `new_state_mismatch`, `pruned_state`. Only the class is compared. Split and
merge blocks need two predecessor states and are refused, as the replay refuses them.

Contexts come from `conformance-block-export` (`migrate/block-export.cpp`), which prepares previous
states the way the replay does: the old side of the block's state update with the corpus's
supplemental cells filled in.

| Family | Fixtures | Context source |
|---|---|---|
| `rel02-negative` | 26 | authored defects of four corpus blocks (first masterchain and basechain blocks with transactions, first key block, busiest masterchain block): another block's previous state, the previous state without supplements, a state update with a foreign or swapped new side, a transaction with altered fees or time, and for the basechain block a wrong or missing masterchain context; `runner/test_block.py` checks each reason class |

Positive cases are not frozen (their states total about 29 MB): `migrate/block_chain.py chain` exports
every one of the 366 corpus blocks and requires `accepted` with the manifest's on-chain block root
hash, new state hash and transaction and account hashes (576 transactions). ctest runs it as
`conformance-block-chain`.

Regenerate the frozen families of both components (block and get_method) from a clean-tree build:

```
python3 test/conformance/migrate/block_families.py create build/test/conformance/conformance-block-export \
    build/test/conformance/conformance-ref-cli test/rel02/corpus test/conformance/vectors
```
