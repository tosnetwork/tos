# Deployment state vectors

`deploy-state.json` contains 63 global-version-16 cases: 59 full transaction and
account root comparisons and four explicitly rejected external messages. Inputs
cover nonexistent, uninitialized, frozen and active accounts; successful compute,
accepted failure, explicit commit followed by a throw, configured precompiled
fallback, unaffordable precompiled execution, zero gas, absent code, and fixed-prefix deployment.

The native reference was built at `f2ad5c344d23975407afe228e7959ff393ac7e97`.
Its transaction semantics are those of base `bf31ded4b`; the intervening native
changes add test replay output and optional step tracing. No trace sink is used
by the fixture generator. Expected roots come only from the native emulator.

To regenerate from a reviewed native build:

```sh
EMULATOR_PATH=build/emulator/libemulator.so python3 test/executor-parity/deploy_state.py \
  --output tosctl/src/executor/tests/fixtures/deploy-state.json
cargo test --manifest-path tosctl/src/Cargo.toml -p tos_executor --lib tests_deploy_state
```

Before freezing any effect, the generator asserts success, StateInit use,
activation, exit code, gas, aborted/action shape or the exact rejection class.
The activation/use assertions follow `crypto/block/transaction.cpp`'s compute
phase. Gas assertions use the instruction price in `crypto/vm/opctable.h`
(10 plus one per encoded bit), `crypto/vm/vm.h`'s implicit-return price (5)
and exception price (50), or the explicitly configured precompiled price.
The skipped reason is checked against `crypto/block/block.tlb` (`no_gas$10`).
These assertions are authored independently of the native output.

Initial storage statistics are calculated over the input AccountStorage graph.
Incorrect zero statistics are unsuitable here: an unchanged native account may
retain them while the Rust adapter recomputes them. Frozen inputs use an address
different from their StateInit hash to exercise thawing without equal-address
canonicalization. The fixed-prefix case flips the first address bit and declares
a one-bit prefix; it verifies that retaining a prepared candidate preserves the
address validation already performed by the ordinary executor.

CI regenerates these inputs/effects, requires byte-identical fixtures, and runs
the registered Rust tests. The comparator checks whole roots; it does not copy
native fields into the Rust result. Its only post-execution work mirrors the
emulator adapter: recompute storage statistics and serialize the state update.
