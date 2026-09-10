# Tol stdlib path for default contract generation

Implementation `fd1ea0668`, parent `8fbc30fe5`. One added environment assignment
in root CMakeLists.txt's `slice1_tol_to_boc` supplies the actual source-tree
`crypto/smartcont/tol-stdlib` directory. It serves five current contract commands
in three targets. Tol auto-discovery, environment override support, compiler and
contract sources, Fift execution and verification steps are unchanged.

## Independent default build

New detached source `/tmp/tos-tol-stdlib-source` and new real build directory
`/tmp/tos-tol-stdlib-build`; no source/build shortcut or preexisting cache.
Commands:

```
env -u FUNC_BIN -u FIFT_BIN -u TOL_STDLIB cmake -S /tmp/tos-tol-stdlib-source -B /tmp/tos-tol-stdlib-build -DUNO_CRYPTO_BUILD_JOBS=32
env -u FUNC_BIN -u FIFT_BIN -u TOL_STDLIB cmake --build /tmp/tos-tol-stdlib-build -j32
```

Default feature configuration (Debug, NODE_LINK OFF); the only configure setting
above limits Cargo parallelism. No `--target`: this is full default all, not
all-tests. Configure and build exit **0**, with no caller-supplied tool path
variables. CMake supplies its own per-command paths as intended by this fix.
The five `Compiling Tol contract` events and produced BOCs are positive controls;
zero `Failed to discover Tol stdlib` messages alone would not prove execution.
The three native frozen-contract embed checks also execute without caller FUNC_BIN
or FIFT_BIN. Final restoration default-all result is in manifest.json.

## Isolated removal control

The measurement copy equals the committed/main CMake preimage. Only the newly
added TOL_STDLIB assignment is removed, then the same copy is reconfigured and
all five BOCs are required absent before testing. The three targets independently
fail with `Failed to discover Tol stdlib.`:

- slice1_gas_parity_contracts (three Tol contracts)
- slice5_receive_context_contract
- tos_report_bond_oracle_contract

No `required compiler is unavailable` error is accepted as this evidence. Actual
Tol invocation and generated Make rules are retained; this is compiler discovery
failure, not a contract semantic rejection. Restore is byte-exact, configure is
repeated, all three named targets explicitly rebuilt without environment overrides,
and all five BOC hashes match their pre-mutation baseline. Actual executable
consumers are tol and fift; CMake command generation was mutated, not their code.
No frozen artifact was refreshed or committed. A final default-all rebuild also
refreshes any dependent outputs; it is separate from the initial pristine run.

The first driver attempt is retained and **not credited**: after mutant configure,
the first baseline BOC was already absent, and unconditional unlink raised
FileNotFoundError before any mutant target executed. Its finally block restored
CMake and rebuilt the targets. `control-v2.py` removes files if present and then
asserts all five are absent, preserving the no-stale-output invariant. Only the
v2 completed runs constitute removal evidence. Main source was never mutated.

## Before-fix comparison and separate consumer

The previous complete failed default build from source `f5043d9fc` is copied
losslessly with its original configure/build invocation metadata and compressed
log hash. It has the same Tol discovery error, after all three FUNC/FIFT embedded
targets passed. It is historical comparison, not represented as current-parent
execution; the removal control provides the current-source causal test.

`test-tol` has its own CTest ENVIRONMENT registration. This patch deliberately
does not change it and does not run or claim recovery of that test. The default
contract-generation consumer is now fixed; the test registration remains a
separate known path issue. No complete ordinary CTest regression or final M1
merged-tree verification is claimed by this build-only unit.
