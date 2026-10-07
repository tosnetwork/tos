# Security scan remediation: 2026-10-06

Scan run: `wfr_587879028e36a0b20fa2c768bf6bc2d5a88c5b179aea0c45136dd66b204afb60`.
Scan revision: `9960de239fda55dd9888cd23893bd694af130e44`.
Review baseline: `6da705c8ad6e5a1dd118f11de819e0e542416540` (rechecked before publication).

All twelve findings remain present at the baseline: their source paths were unchanged from the scan except for unrelated address parsing additions in nodectl/utils.rs. This is source confirmation, not twelve reproduced production exploits. This branch implements remediation candidates for all twelve. No new Cloud scan, finding closure, production deployment or activation has been performed.

| # | Finding ID | Severity | Finding | Baseline | Remediation and evidence |
|---|---|---|---|---|---|
| 1 | `csf_0e44054d12cb535e11a3d3f2` | high | Source rotation bypasses ADNL decrypt throttling and creates unbounded pre-authentication state | Present | Process and local decrypt work/concurrency budgets; bounded source and statistics tables; IPv6 /64 admission. Native budget/table cardinality and IPv6 tests; two red/green controls. Full actor flood and authenticated-peer service benchmark pending. |
| 2 | `csf_c0cba186c5954d7050a7af3f` | high | Generic multisig authorizations are not bound to the network global ID | Present | Signed int32 GLOBALID in the generic multisig packet and C++/Rust builders; sibling-network transaction replay rejected. 11 multisig transaction tests; cross-network replay red/green. |
| 3 | `csf_80e522ac5cc5420f8641dd26` | high | Node-control configuration writes expose inline keys and credentials through permissive, symlink-following creation | Present | Shared owner-private, random-temp atomic configuration writer; regular-file/owner/link checks and file/directory fsync. Private file mode 0600/update/symlink refusal tests; permission red/green; shared vault library suite. |
| 4 | `csf_d565d7fc0f942dc96e8f05f4` | high | Release and builder pipelines execute downloaded tooling without independent integrity verification | Present | Repository-pinned SHA-256 checks before AppImage execution and NDK/uv extraction; pinned signing key for LLVM apt packages. Two verifier tamper tests covering all pins plus two packaging pipeline tests covering cached AppImage tools on both architectures and cached NDK archives; verifier/call-bypass red/green. Actual NDK archive matches size/upstream SHA-1 and pinned SHA-256. |
| 5 | `csf_c8a7cfb31c272ff0f43fe776` | high | Ambiguous HTTP framing permits request smuggling across proxy boundaries | Present | HTTP token/value/CRLF and decimal length validation; strict single chunked coding; conflicting framing rejected. Native malformed framing tests; coding and raw header-admission red/green. |
| 6 | `csf_eef543a1772e8a986f353a24` | high | TOS Connect trusts an unbound bridge sender as the wallet and permits sender replacement | Present | Trusted out-of-band wallet session key required; encrypted sender pinning, low-order-key refusal and v3 session restoration. 100 Connect tests; encrypted forged connect/RPC/disconnect and replacement cases; sender gate red/green; TypeScript passes. |
| 7 | `csf_762872508293ff63bfe3acca` | medium | JSON vault persistence uses a predictable symlink-following temporary path | Present | Private vault directories; exclusive random temporaries and backups; no-follow regular-file reads and atomic saves. 231 vault tests + 1 CLI import test passed; 1 pre-existing ignored test. Random temp/backup mode and victim-preservation checks. |
| 8 | `csf_7cbc3b2d69ccf923770f6fd9` | medium | RLDP response forwarding emits chunked bodies without a matching HTTP framing header | Present | Canonical chunked headers for persistent EOF bodies; raw EOF plus actual close for nonpersistent/HTTP1.0 responses. Native header/body tests including HTTP/1.0; missing framing-header red/green. Pooled RLDP end-to-end fixture pending. |
| 9 | `csf_ed36e7ef66dea1203e68ef69` | medium | Legacy wallet contracts accept forgeable Ed25519 authority-key encodings | Present | Runtime weak-key checks in twelve legacy wallet families, including restricted-wallet initialization/rotation; regenerated SDK/Rust code. Twelve wallet-family transaction controls; weak-key guard red/green; 10 wallet + 13 highload regression tests; native SDK vectors. |
| 10 | `csf_b8df2f7a85245ada30915d98` | medium | Lite-server error messages are inserted unescaped into explorer HTML | Present | HTML-escaped Status/error/notification/title output; CSP and nosniff on explorer HTML responses. Native HttpAnswer abort/finish escaping checks; actual rendering-call bypass red/green. Browser DOM fixture pending. |
| 11 | `csf_91c17590b773e98f2828c242` | medium | Chain-RPC API keys are accepted in process-visible command-line arguments | Present | Removed literal API-key argv; protected file/descriptor or hidden prompt; installer uses hidden zeroizing input. 2 input-channel tests and argv-admission red/green; command suite has 194 passed / 4 macOS GNU-tar incompatibilities. |
| 12 | `csf_3a15ea0edf9f75b9a8704613` | low | Validator can skip mandatory dispatch-queue priority after cleanup and regrowth | Present | Validated deq/deq_short cleanup count and shared post-cleanup dispatch predicate; excludes later imports/requeues. Native cleanup/regrowth predicate and tag controls; predicate red/green. Full malicious-block validation fixture and activation review pending. |

## Local validation and reproduction

Use the repository's pinned Rust toolchain, freshly built FunC/Fift, and `TOS_ROOT=$PWD` to prevent a sandbox fallback to another checkout.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target func fift emulator test-security-boundaries -j8
build/test-security-boundaries
TOS_ROOT=$PWD cargo test --locked --manifest-path tosctl/src/Cargo.toml -p contracts --test multisig_code_sandbox --test legacy_wallet_key_sandbox --test wallet_sandbox --test highload_wallet_v3_sandbox
cargo test --locked --manifest-path tosctl/src/Cargo.toml -p secrets-vault --lib
cargo test --locked --manifest-path tosctl/src/Cargo.toml -p secrets-vault --features secrets-vault-cli --test cli_import_secret_input
cargo test --locked --manifest-path tosctl/src/Cargo.toml -p commands secret_channel_tests
pnpm --dir sdk/js --filter @tos/connect --filter @tos/wallets typecheck
pnpm --dir sdk/js --filter @tos/connect test
pnpm --dir sdk/js --filter @tos/wallets test
python3 scripts/test-build-tool-pins.py
python3 scripts/test-build-tool-pipelines.py
FUNC_PATH=$PWD/build/crypto/func FIFT_PATH=$PWD/build/crypto/fift python3 scripts/update-auth-contract-code.py --check
FUNC_PATH=$PWD/build/crypto/func FIFT_PATH=$PWD/build/crypto/fift EMULATOR_PATH=$PWD/build/emulator/libemulator.so python3 test/auth-extensions/test_sdk_wallet_vectors.py
```

On macOS use `libemulator.dylib`. The full native build at this baseline fails on Linux-only constants in `metrics/diagnostic-ipc.h`. The local `scripts/run-security-boundaries.py` runner uses CMake's flags and the production HTTP/explorer and registered test sources; it omits only the unused exporter and toslib libraries from the unit link. Four boundary tests passed. All changed native translation units compiled independently. This is unit/source compilation evidence, not a full macOS daemon build.

Local results: 11 multisig tests; one transaction suite covering twelve wallet families; 10 wallet and 13 highload regression tests; 231 vault library tests (one existing ignored); one real vault CLI import test; two API-key input tests; 100 Connect tests; 94 SDK wallet tests; six native SDK deployment/transfer/domain vectors; two tool integrity and two packaging pipeline tests. Rust formatting, TypeScript checking and regenerated-bytecode checks passed.

The complete commands library run passed 194 tests and failed four existing backup tests: this macOS BSD tar does not support `--no-overwrite-dir` and `--transform`. The backup implementation is unchanged. Linux CI is the authority for that suite and the complete native build.

## Sensitivity controls

Run in an isolated checkout without concurrent builds using the mutated sources. The runner removes one control, requires an executed runtime test to fail, restores exact source bytes in `finally`, then requires success. Native controls exited 1 then 0; Rust controls exited 101 then 0; Python/Connect controls exited 1 then 0. File-mode sensitivity is shared by findings 3 and 7. Compiler errors do not count as successful controls.

```sh
python3 scripts/test-security-remediation-mutations.py decrypt sources multisig private-file integrity tool-call http header-names response legacy-key html api-key dispatch connect --logs /tmp/security-remediation-controls
```

These controls do not establish the explicitly pending integration boundaries in the table.

## Compatibility and acceptance

- Generic multisig payload is now `wallet_id:uint32 global_id:int32 query_id:uint64 actions`; both root and co-signatures cover the network. Builders require the identity explicitly and old unbound packets are refused.
- Wallet bytecode and derived deployment addresses change. Existing deployed code is immutable: an SDK update does not upgrade a wallet or migrate its funds. Deployment/migration requires an operator decision.
- Config writes create mode-0600 operator-owned regular files, reject symlink/hardlink targets and fsync atomic replacement. Vault directories must be owner-only (0700), or newly created privately; existing shared directories are refused rather than silently chmodded. Backups use exclusive random names.
- API keys use `--api-key-file`, `--api-key-fd` or `--api-key-prompt`; the old `--api-key` / `-k` form is refused. The setup guide is updated.
- HTTP bridge connections require a trusted paired wallet key; injected connections retain their flow. Old unbound sessions cannot be restored. See `sdk/js/packages/connect/PAIRING.md`.
- Dispatch validation tightens consensus acceptance. A complete malicious-block fixture, historical compatibility/activation review and operator acceptance remain deployment gates. Predicate tests cannot establish production consensus acceptance.
- ADNL budgets bound admission and memory; they do not establish availability under a full network flood. Tool pins authenticate the cited downloaded tools, not every release dependency or reproducible container build.

The PR stays draft for final-head Linux checks and the remaining integration/activation boundaries. Required branch checks remain hard gates; no merge or deployment is requested here.
