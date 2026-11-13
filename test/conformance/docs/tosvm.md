# tosctl Rust VM and executor as a conformance target

`tosctl/src/executor/examples/conformance-target.rs` (harness code in
`tosctl/src/executor/examples/conformance_harnesses/`) runs the same vectors against the Rust VM
(`tos_vm`) and executor (`tos_executor`) that check the C++ node. It speaks the line protocol of the
README: `conformance-target --info` and `conformance-target <harness>`, one context JSON per stdin
line, one effects JSON per stdout line.

| Harness | Rust path | Set up as |
|---|---|---|
| `vm` | `Engine::setup_checked` + `execute` | `ref/harness-vm.cpp`: c7 the given tuple or an empty one, c4 the given data or an empty cell, c3 quitting with 11 unless flag bit 0 (then c3 is the code, and flag bit 1 pushes an implicit 0), `Gas::new(limit, credit, max)`, each library collection a 256-bit dictionary, `set_block_version(global_version)`, engine capabilities 0. Out of gas is reported as -14, custom codes as they are. Final stack texts follow `stack_entry_text` in `ref/common.cpp`. |
| `txn` | `OrdinaryTransactionExecutor` / `TickTockTransactionExecutor` | the transaction emulator: `block_lt` is `lt` aligned down to 1 000 000, `last_tr_lt` is `lt`, signatures are checked, the new ShardAccount carries the transaction hash and logical time. A contract that does not accept an external message is `rejected` with its exit code (0 when compute was skipped); every other executor error is `error`. |

Refused (`harness_error`), never approximated:

- anything the reference refuses as well: malformed JSON or BOC, missing or out-of-range fields, a
  code or slice value that is an exotic cell (the reference cannot load it outside the VM), a c7
  that is not a tuple, too deep or too long stack values, more than four library collections,
  previous blocks that are neither a tuple nor null, a configuration the executor cannot read;
- fields the schemas do not define;
- a vm gas limit plus credit past 63 bits (the reference adds them without a check);
- a txn configuration whose global version is not 16: the Rust executor is aligned with the C++
  node at version 16 only.

A panic inside the VM or executor is answered with `{"implementation_panic": true}`, which no harness
accepts, so the runner counts it as a mismatch. `--info` reports the commit the package build script
recorded and always `"dirty": true`: the build script cannot tell whether the tree was clean, so this
target can compare fixtures but never fill them.

## Running

```
# needs cargo; the toolchain is pinned by rust-toolchain.toml
CARGO_TARGET_DIR=tosctl/src/target cargo build --release --locked \
    --manifest-path tosctl/src/Cargo.toml -p tos_executor --example conformance-target
T=tosctl/src/target/release/examples/conformance-target
python3 test/conformance/runner/conformance.py run --target $T test/conformance/vectors
python3 test/conformance/migrate/rel02.py chain build/emulator/test-epoch-replay $T test/rel02/corpus
python3 test/conformance/runner/tosvm_controls.py $T test/conformance/vectors
```

`parts/tosvm.cmake` adds these as ctests labelled `conformance-tosvm` when cargo is found
(`conformance-tosvm-build`, `-vectors`, `-controls`, and `-rel02-chain` when `test-epoch-replay` is a
target); the adapter is built into `build/test/conformance/tosvm-target`:

```
cd build && ctest -L conformance-tosvm --output-on-failure
```

`ctest -L` takes a regular expression, so `ctest -L conformance` selects these tests too; use
`ctest -L '^conformance$'` for the C++ lane alone.

`tosvm_controls.py` shows the comparison can fail: the adapter's output with `gas_used` of the first vm
response corrupted must be exactly one mismatch, and a context the adapter refuses must be counted as
refused. Pointed at the C++ reference the second control fails, since the reference runs that context.

## Current result

| Lane | Result |
|---|---|
| `vm/vm-endstate` (128 fixtures, 127 at version 16, 1 at version 8) | compared 128, equal 128, mismatched 0, refused 0, skipped 0 |
| REL-02 chain (576: 172 ordinary, 202 tick, 202 tock) | 576 checked against the chain, 0 differences |
| REL-02 contexts, full effects against the C++ reference (including the ShardAccount hash) | 576 equal |

There is no frozen `txn` family yet, so the `txn` harness is exercised by the chain lane only.
