# D78 consumer/build coverage inventory

Source baseline B 147f9b20b; reviewed structure expectation from A 269fe2e82.
Spec a131b9bb / 187dbc79290d6816. This inventory precedes the next B commit.
It records builders separately from execution evidence. A's configured compile
commands/CTest list were read as build metadata, not treated as a successful
build or a source identity for A's uncommitted work.

## Findings and corrections

1. B had NOT run withdrawal-structure during the 147f9b20b wallet-example check.
   That check ran release m3-scenario points/prove and obsolete-field, overflow,
   insufficient-balance CLI requests. It did not exercise the AST guard.
   B now ran the exact default guard command: exit1 at `statement storage changed`.
   The guard correctly exposes the deliberately changed interface. Reviewed and
   imported A 269fe2e82's deletion of ONLY the retired field expectation; after
   that change the guard and its three structural mutations/comment control pass.
   This is D78 interface review, not a compiler workaround. expected_calls is
   byte-for-byte unchanged. It is a BTreeSet of targets, not a multiset: total's
   two checked additions become one (whole file four become three), but the
   distinct .checked_add and .and_then targets both remain. This AST check does
   not prove arithmetic multiplicity; the checked-overflow behavioral control does.
2. The old D64 .rs is not default-built, but it is NOT orphaned/unrunnable:
   its .py archives 5f628635d, injects that .rs and compiles/tests the old ABI.
   Added an explicit first-line applicability warning. Independently reran that
   old-source route: baseline2/2, witness-index red101, range-object red101,
   restored2/2. It must not be injected into current HEAD. D78 has its own pinned
   .py/.rs at c7a6f62e8, already checked separately. No historical expected number
   was rewritten to match D78.
3. Additional stale manual consumer found: workchain-withdrawal-account-controls.py
   hardcodes schema3 and its diagnostic-string mutation anchor. It is not default
   CTest. On schema4 it fails its anchor-count check BEFORE running a semantic
   mutant. It provides no current D78 capacity-removal evidence. The codec's
   ordinary capacity test remains built, but that is different evidence. This
   inventory labels the old driver pre-D78; it is not silently marked repaired.
4. The live driver checks only whether its wallet executable exists. The default
   epoch behavior runner rebuilds m3-scenario into **epoch-wallet**, while live
   uses **m3-vector-wallet-target**. Thus a green epoch check does not refresh
   live's binary. This explains why an existing release wallet could still demand
   b. A rebuilt its live binary after 147f9b20b. B independently built both Cargo
   examples, not merely --lib. No full Native run is claimed by B here.

## Enumeration method and limits

Tracked source search covered all repository .h/.cpp/.rs/.py/.tlb/.toml files
for WithdrawalAmounts/Statement, V1/V2 ABI symbols, WorkchainWithdrawal and TL-B
Withdrawal names plus encode/decode/check/total helpers. No tosctl/storage
exclusion was used for the tracked symbol search. Exact hits are archived in
measurements/uno-m5-d78-consumers/direct-symbol-hits.txt (26 direct source files).
Support include consumers and build drivers were searched separately; m3-vectors
is listed even though it uses the unchanged generic SEND/COLLECT ABI.

The companion include-consumers-builders.json enumerates all 51 translation units
reached by reverse quoted includes from the changed codec/account/proof-work
headers. Each lists configured compile targets and directly named CTest commands.
Resolution uses including directory, repository root, crypto/; no preprocessor,
macro include, runtime dispatch, alias or linker-reachability completeness claim.
The complete lexical sets are reported, not inferred from a count. A source
included in a TU is compile coverage, not evidence its Withdrawal branch ran.

## Direct consumers and their actual builders

Paths below are repository-relative. 'Default' means CTest registration in the
normal configured suite; conditions are stated. CTest usually runs an existing
C++ executable rather than building it. Explicit cargo-run tests are different:
they compile their Rust carrier during CTest itself.

| Consumer | Builder / carrier | Default-suite status and current evidence |
|---|---|---|
| uno/crypto/src/withdrawal_statement.rs | crypto crate, ffi; real prover tests | Library build through kernel target when enabled; full Rust --lib not itself default CTest. B28/28 library +5/5 prover evidence; AST/effects gates default below. |
| uno/crypto/src/ffi.rs | crypto crate, staticlib | Kernel CMake Cargo build when configured; real ABI backend conditional. V2 real proof test in prover, not all default ABI tests exercise Withdrawal. |
| uno/crypto/include/uno_crypto.h | C backend consumers; Cargo build.rs generated-header comparison | Generated interface guard runs on Cargo build. Conditional linked C backend; B reviewed regenerated diff. |
| uno/crypto/cbindgen.toml | crypto build.rs/cbindgen | Build-time input, not standalone executable or test. |
| uno/prover/src/tests/withdrawal.rs | cargo test --lib via src/tests.rs | Not a CMake-default invocation. B5/5 includes V2 proof/overflow/point checks. |
| uno/prover/examples/m3-scenario.rs | Cargo --example m3-scenario; epoch behavior and manual scenario drivers | Default key-epoch-behavior rebuilds it if kernel target exists; otherwise registered unavailable/failing path. Different output path from live. B release CLI smoke, then fresh --examples build. |
| uno/prover/examples/m3-vectors.rs | Cargo --example m3-vectors; test/uno-m3-vectors.py | Manual vector-generation driver, no default registration found. Uses unchanged generic VerifyRequestV2, NOT WithdrawalAmounts. Fresh --examples build passes; no vector regeneration in this inventory. |
| crypto/block/block.tlb | tlbc generation -> block-auto.cpp/.h -> tos_block | Normal Native build input. New Withdrawal tags generate code; old fixtures rejected by B codec11/11. Generated sources are outputs, not additional handwritten design. |
| crypto/block/workchain-withdrawal-codec.h | test-workchain-withdrawal-codec plus consumers below | Default codec test, native build; B fresh standalone complete TU11/11. Not complete host integration. |
| crypto/block/workchain-withdrawal-account.h | same codec TU, association/host consumers | Default codec and association tests. Key/LT/count and current schema compiled by codec TU; manual removal driver has separate limitation above. |
| crypto/block/workchain-system-origin.h | includes codec protect/pack; codec/origin/Failed users | Default codec/origin tests; no D69 transcript change. Include dependency even without amounts symbol. |
| crypto/block/workchain-withdrawal-association.h | test-workchain-withdrawal-association, Failed | Default association executable. Full D78 association not independently run by B this turn. |
| crypto/block/workchain-failed-funded.h | association TU, live node engine | Default association and conditional live. A-owned D78 wiring; B does not infer green from header inclusion. |
| crypto/block/workchain-proof-work.h | tos_block and many TUs in manifest; test-workchain-proof-work/origin-length | Default test binaries compile interface. The dedicated Withdrawal dispatch still needs linked live/prover evidence. A owns overload update. |
| crypto/block/workchain-proof-backend.cpp | tos_block; conditional test-workchain-proof-backend | Compiled normally, linked ABI branch only with TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED. Real backend test requires target test-uno-crypto-abi-real. Unlinked stub build does not certify V2 call. |
| crypto/test/workchain-m3-node-engine.h | test/test-m3-live.cpp | test-m3-live EXCLUDE_FROM_ALL except TOS_UNO_CRYPTO_NODE_LINK + Ninja; that configuration adds partial Failed CTests. Not general default coverage. |
| crypto/test/workchain-m5-debit.h | node-engine + live-wallet -> test-m3-live | Same conditional live carrier. A-owned fee/authorized reconstruction. |
| crypto/test/workchain-m5-payout.h | node-engine + live-wallet -> test-m3-live | Same conditional live carrier. A-owned record/payout atomicity. |
| test/m3-live-wallet.h | test-m3-live | Conditional live carrier; invokes external wallet whose freshness is not forced by existence check. |
| test/m4-live-deposit.h | test-m3-live | Same; textual Withdrawal references in shared fixture; no ordinary M4 green transferred to D78. |
| test/m5-live-reserve-control.h | test-m3-live | Same; historical name/current A-owned retirement. B tree at inventory baseline still carries prelock code pending A merge. Not independent current green. |
| crypto/test/test-workchain-withdrawal-codec.cpp | test-workchain-withdrawal-codec | Default; B focused full TU11/11. |
| crypto/test/test-workchain-withdrawal-association.cpp | test-workchain-withdrawal-association | Default; A update pending integration in B baseline. No fresh B full-association pass claimed. |
| crypto/test/withdrawal-structure/src/main.rs + api.txt | cargo run, package withdrawal-structure-expiry | DEFAULT test-workchain-withdrawal-statement-expiry, crypto/CMakeLists.txt:810. Fresh red then reviewed green, not previously included in wallet smoke. |
| crypto/test/workchain-withdrawal-effects.rs/.py | Python copies current crypto crate and injects example; cargo run | DEFAULT test-workchain-withdrawal-statement-effects, :818. Now freshly run: baseline, actual callee write detected, restored. Account BOC fixture cut only, not Native state. |
| crypto/test/workchain-d64-independent-review.rs/.py | manual Python archives original5f628635d then cargo test | NOT default. Fresh successful historical replay; top warning added. Old ABI intentionally retained. |
| crypto/test/workchain-d78-independent-review.rs/.py | manual Python archives c7a6f62e8 then cargo test | NOT default. Separate current shape2/2 +two red mutations; old replay never silently retargeted. |
| crypto/test/workchain-withdrawal-account-controls.py | manual Ninja-command shadow compile/link | NOT default; pre-D78 schema3 anchor, not current D78 evidence. Explicit applicability warning; requires a versioned new control before claiming D78 removal evidence. |

## Include-only and driver dispositions

All other quoted-include TUs are listed individually in the JSON, with their
builder targets. Native libraries/validator executables have normal compilation,
but no direct CTest entry should be read as full validator execution. The seven
entries absent from A's compile_commands are accounted for, rather than omitted:

- test-workchain-construction-isolation.cpp: private
  workchain-construction-isolation.cmake target/gates; not ordinary default.
- test-workchain-instance-identity.cpp: opt-in private CMake branch
  crypto/CMakeLists.txt:696; not in this configured build.
- test-workchain-publication-provenance.cpp: explicit private .cmake calibration;
  included construction-isolation source, not an independent default gate.
- test-workchain-publication-recovery.cpp: private .cmake/.py build/gates;
  requires explicit inclusion, not ordinary default.
- workchain-account-connectivity-probe.cpp, workchain-node-link-smoke-types.cpp,
  workchain-registration-deletion-probe.cpp: manual compile-probe artifacts,
  commands/results in doc/measurements/uno-v2-*; no default builder found.
  No new D78 compilation or execution evidence for these artifacts is claimed.

Drivers are also dependencies: test/uno-m3-scenario.py builds m3-scenario into
live's directory; test/uno-m3-vectors.py builds m3-vectors, both manual (no CMake
registration found). test/uno-m3-live.py consumes the prebuilt wallet and is
conditional CTest as above. crypto/test/workchain-key-epoch-behavior.py compiles
its own wallet before execution and is default-registered (kernel-unavailable
fails explicitly). proof-boundary-gates and crypto-abi-boundary inspect files;
they do NOT compile these examples merely because they inventory their names.

Two measurement-source references also appeared: pre-D78
prepare-independent-review/artifact-oracle.cpp belongs to its frozen old state,
not current code; its original log/fixture must stay paired to that revision.
D78-interface/record-control.py is recorded isolated-build procedure with explicit
/tmp build-helper dependencies, not a portable/default CTest. Their location in
measurements and this applicability mapping prevent treating them as live tests.

## Remaining coverage boundaries

B's current proof/codec/example checks do not certify the full host consumer
chain. A must finish/supply its coordinated build and actual branches. Normal
Native default tests, conditional linked tests, manual matrix replay, example
builds and CLI runtime are distinct gates; none subsumes all others. The stale
manual capacity-removal driver and live wallet freshness dependency are recorded
findings, not hidden by the now-green library or structure test. This inventory
is not a claim of exhaustive indirect/runtime dependency discovery.
