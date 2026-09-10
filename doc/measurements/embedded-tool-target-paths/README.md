# Embedded contract tools use CMake target paths

Implementation commit: `f5043d9fc`; parent `b2fa86273`. Only three custom-command
launchers in crypto/CMakeLists.txt change. CMake passes `FUNC_BIN=$<TARGET_FILE:func>`
and `FIFT_BIN=$<TARGET_FILE:fift>` through `cmake -E env`. Existing tool dependencies,
script logic/environment escape hatches, frozen BOCs, manifests and verification
steps are unchanged.

## Coverage and the five named scripts

The tracked CMake source search is retained in cmake-consumer-search.json, including
the full file search domain. Three current build paths are:
CMake -> embed-tos-service-{native-registry-v1,stablecoin-escrow-v1,stablecoin-escrow-v2}
-> matching test script -> matching build script -> func / fift / hash-code-boc.fif.
The environment passes through every layer. Existing build scripts compile twice,
compare outputs and frozen artifacts, and verify expected hashes/metadata.

No CMake consumer of build-nominator-pool-v1.sh or build-local-stablecoin-fixture.sh
was found in this source tree. The former has shell/Python callers; this patch does
not invent a CMake target for either script. Their manual environment overrides
remain unchanged. This is a bounded source-domain finding, not a claim about future
or external callers. All five script hashes and frozen inputs are recorded.

## Full default build, independent real paths

Source /tmp/uno-embedded-tool-path-source is a new detached checkout, without a
source/build directory or symlink. Build /tmp/uno-embedded-tool-path-build is new,
not either agent's cache. Default feature configuration, Debug, NODE_LINK OFF;
UNO_CRYPTO_BUILD_JOBS=32 changes only parallelism. Build uses `-j32` with no target
selection, i.e. default all, not all-tests. Commands/results are recorded separately:

- First configure/build explicitly unsets FUNC_BIN, FIFT_BIN and TOL_STDLIB.
  All three embedded verification targets complete. The whole default build exits
  **2**, because Tol stdlib discovery fails in slice5_receive_context_contract and
  slice1_gas_parity_contracts. This is not an embedded-tool failure and is not green.
- Resume the same new build with **only TOL_STDLIB supplied**, still unsetting
  FUNC_BIN and FIFT_BIN: default all exits **0**. This proves the tool-path fix
  without caller-supplied compiler/interpreter paths. It is not an independent
  second pristine build or a fully environment-free default-build success.
- After isolated mutations/restoration, default all is explicitly built again;
  its final status/log is recorded in manifest.json. No ordinary CTest or M1 final
  merged-tree verification is claimed here.

Tol remains a separate unresolved consumer-path issue; this patch does not change
its CMake registrations or generation commands. It does not make the fully
unassisted default build green. The operator must preserve that qualification.

## Falsification and restoration

Six controls in the independent checkout separately remove each of the two tool
arguments from each of the three command launchers. Each target is forced to
regenerate, so old generated output cannot mask failure. Each fails with exactly
one `required compiler is unavailable: <source>/build/crypto/{func,fift}` diagnostic
for the removed tool. The other argument remains supplied. This distinguishes
FUNC_BIN coverage from FIFT_BIN coverage; it is not just a generic nonzero result.

After each mutation, CMake source is restored byte-for-byte, reconfigured, and the
actual generation target is explicitly rebuilt with no tool environment overrides.
All three generated C++ output hashes equal the baseline. Targets:
`gen_fif_smartcont_auto_native_registry_code`,
`gen_fif_smartcont_auto_tos_service_stablecoin_escrow_v1`, and
`gen_fif_smartcont_auto_tos_service_stablecoin_escrow_v2`.
The invoked native tools are func and fift (unchanged); no C++ mutant code was
compiled. Main checkout is never mutated. The final default-all rebuild refreshes
any downstream artifacts affected by regenerated-file timestamps.

## Historical failure is not overwritten

The original full failed build from tree `20373d0a...` is copied intact, with its
original source-parent report/configuration and compressed-log hash. It contains
`required compiler is unavailable: /tmp/uno-merged-default-source/build/crypto/func`.
It predates this patch and is not described as a run of the current parent. The six
current-tree removals provide the tighter causal comparison. Earlier failure,
current unassisted Tol failure, successful workaround run and all control outputs
are retained separately and losslessly.
