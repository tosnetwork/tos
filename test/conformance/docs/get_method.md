## get_method harness

`ref/harness-get_method.cpp` runs one read-only get-method the way the liteserver answers
`runSmcMethod` (`validator/impl/liteserver.cpp`): the configuration, libraries and previous-block
context come from the masterchain state through `block::ConfigInfo::extract_config`; the account is
decoded as the liteserver decodes it; c7 and the library list come from `block::prepare_get_method_c7`
and `block::get_method_libraries` (the functions the liteserver and the control getter call); the VM
runs with gas limit and maximum both `gas_limit` and the method id pushed on top of the arguments.

The libemulator get-method entry points (`tvm_emulator_run_get_method`,
`tvm_emulator_emulate_run_method`) are not used: they set block and transaction logical time to 0,
the due payment to 0 and the balance to 64 bits, run with an unbounded gas maximum and their own
data-depth and library-load limits, so their answers differ from a node's for the same account.

| Context | Meaning |
|---|---|
| `mc_state`, `mc_block` | masterchain state (may be partial) and the identity of its block (`seqno`, `root_hash`, `file_hash`) |
| `account` | the `Account` cell: code, data, libraries, balance with extra currencies, due payment, address |
| `now`, `lt`, `rand_seed` | the snapshot time and logical time, the seed the liteserver would draw |
| `method_id` | signed 64-bit method id as decimal text |
| `stack`, `gas_limit` | arguments (shared `stack_item` format, bottom first) and the gas limit |

Effects: `executed` with `exit_code`, `gas_used`, the final `stack` (canonical text, as the vm harness
prints it) and `missing_library` (the hash of a library the run needed and did not find, or null);
`no_state` when the account is missing, uninitialized, frozen or undecodable; `context_unavailable`
when the state yields no configuration or getter context. Both mean the liteserver runs nothing.

| Family | Fixtures | Context source |
|---|---|---|
| `rel02-getters` | 589 | elector, config contract and wallet, token and pool getters (the names node tooling calls) on 53 complete account states of 24 corpus accounts, each with the masterchain snapshot its block executed against |
| `rust-get-context` | 748 | rebuilt from the Rust node's `vm/src/tests/test_get_context.rs`: c7 fields by global version, time and seed, precompiled gas, library lookup modes |
| `rust-get-history-context` | 1314 | rebuilt from `test_get_history_context.rs`: previous-block history edits (missing, truncated, renumbered entries, key block), storage prices, precompiled-list variants |
| `rust-get-method-id-context` | 80 | rebuilt from `test_get_method_id.rs`: signed 64-bit method ids |
| `c7-shape` | 9 | the versions of `test/validator/data/getter-c7-shape.tsv`; `runner/test_get_method.py` checks length and c7[18] against that file |

The Rust families freeze only results, so their contexts are rebuilt by `conformance-block-export rust-families`
from the tests' parameters on the corpus's newest masterchain state (its history reduced to the
entries a getter reads, so the history edits can be made); the Rust probe programs are written in
Fift assembler. All effects are filled from the C++ reference. Masterchain snapshots are pruned to the
cells a get-method context reads (for `rel02-getters`, the whole configuration and library
dictionary).
