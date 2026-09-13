# Production library checks

These drivers link `validator/auth` and the `tos-validator-auth` crate. They do
not compile the old standalone codec fixtures as substitutes for production
libraries. The Python reference is used as an independent public-data oracle.

Build with `TOS_BUILD_P0_IMPLEMENTATION_TESTS=ON`, then build the targets
`test-p0-implementation`, `test-p0-transfer`, `test-p0-transport` and
`test-p0-cells`. Build the Rust `conformance` binary with the workspace manifest
`tosctl/src/Cargo.toml`, package `tos-validator-auth`.

- `check.py`: exact binary bytes, malformed inputs, cryptographic admission and
  signatures, complete certificate verification, native AuthBytes/BOC bounds.
- `check_lifecycle.py`: 104 C++ and Rust per-identity state/selection cases against the frozen reference.
  Authority callbacks are controlled test inputs, not a proof implementation.
- `check_transport.py`: use `--driver` with either the native transport driver or
  the Rust conformance binary. Checks framing, binary shape and correlation.
  Endpoint semantics and authenticated response claims are separate work.
- `mutations.py`: isolated C++ source copies, successful compilation, assertion
  failures and restored baseline. Requires `pkg-config libsodium openssl` and `--rust`.
- `rust_mutations.py`: isolated Rust crate, successful compilation, assertion
  failures and restored baseline. Requires a built native `--cpp` driver and
  dependencies already present in the Cargo cache.
- `cell_mutations.py`: edits only the configured build-tree cell source copy;
  links and executes against the actual native VM. Takes `--build` and `--out`.

Every mutation report records a compiled mutant and an assertion failure.
Abnormal executable exits are harness errors. Never count a compiler failure,
crash, missing dependency or reference-only mutation as production guard proof.

The CI workflow records the actual checked HEAD and uploads evidence. Local
results do not establish Ubuntu or testnet acceptance. The full build remains a
separately authorized manual workflow.

Additional production boundaries:

- `check_api_semantics.py`: all 15 request/result types, full receipt association,
  signer-list equality, proof/cursor binding and bounded referenced attachments;
  runs against C++ `test-p0-api-semantics` and Rust `conformance`.
- `check_service_auth.py`: real C0 service signatures, independent policy history,
  witnessed receipts and retained request-state observations in both languages.
- `test-p0-admin`: durable preparation, staging, retire/cancel intents, real admin
  signatures and PoP, exact receipts, bootstrap and provider rollback. Owner
  execution admission remains a controlled fixture.
- `test-p0-admin-process`: six actual SIGKILL boundaries with separate signer and
  provider/witness processes, preparation reconciliation and uncertain PoP refusal.
- `admin_mutations.py`: eleven compiled administration guard removals with exact
  expected assertion labels.
- `test-p0-object-store`: full principal/anchor isolation and aggregate quotas.
- `test-p0-issuer`: persistent purpose-separated service keys and real signer
  receipts through restart/rotation.
- `test-p0-process`: separate signer/provider process kills, now using the
  production persistent receipt issuer.
- `object_store_mutations.py`, `issuer_mutations.py`, `api_semantic_mutations.py`:
  compiled production removals requiring the exact intended assertion failure.
  The Rust mutation harness also executes API, transfer and service-trust guards.

Native test binaries require `TOS_BUILD_P0_IMPLEMENTATION_TESTS=ON`. Journal,
issuer, signer and process binaries each take a new temporary directory; keep the
Unix socket path short enough for the host OS. Temporary files contain rehearsal
keys and are never release artifacts.

Local API boundaries:

- `test-p0-api-service`: all signer methods, identity/method/chain admission,
  private cached queries, scoped chunks and actual native state proofs. Pass the
  Rust conformance binary as a second argument for cross-language socket calls.
- `check_http.py`: 44 real Unix HTTP cases across C++ and Rust, including bounded
  allocation, peer credentials and immediate peer close with buffered data.
- `check_client.py`: 37 Rust client cases covering all 15 fixture methods, errors,
  response correlation, semantic admission, exact call counts and proof chunks.
- `api_service_mutations.py`: 17 compiled admission/cache guard removals.
- `http_mutations.py`: 14 C++ and 11 Rust compiled framing/credential removals.
  It accepts `--language cpp --build ...` or `--language rust`. The Rust client
  also adds seven guard removals to `rust_mutations.py`.

These are local Unix HTTP/1.1 checks. Remote HTTP/2/mTLS and native node/committee
integration are separate boundaries; the public certificate RPC is not enabled
by the fixture client's ability to parse its response type.

Native Rust checks:

- Build `tos-validator-auth-native` / `native-conformance`. The focused Clippy
  command uses `--no-deps` and explicitly selects both authentication crates;
  the unchanged native block dependency is compiled and exercised by tests.
- Pass a fresh export directory to `test-p0-cells` and `test-p0-proof`, then run
  `check_native.py --rust ... --cpp ... --cells ... --proofs ... --out ...`.
  Exports include completion markers and native positive/negative evidence.
- `rust_native_mutations.py` takes the cell/proof export directories and compiles
  17 guard removals in an isolated crate. The C++ native module harness has 25
  guard removals after adding configuration and proof-metadata binding checks.
- Pass `--native <native-conformance> --proofs <export-directory>` to
  `check_client.py` for 58 HTTP client cases including native proof refusal.
  Add the native Rust binary as the third argument to `test-p0-api-service` for
  actual C++ serving plus Rust verification of inline and referenced proofs.


Native Keyring checks:

- `test-p0-keyring <fresh-directory>` exercises the actual Keyring factory and real
  signing, decryption and secret export before protection, then every protected
  private API. It includes restart, malformed durable records, lost/replaced files,
  permission/link attacks, deterministic asynchronous drain and actual competing
  processes. Test-only keys stay under the fresh directory.
- `keyring_mutations.py --build ... --out ...` compiles 25 removed guards and requires
  the exact assertion failure. No compiler failure, process crash or fixture error
  is accepted as a kill. The unchanged `test-keyring-temp-key` is also run in CI.
- The frozen original production hashes remain authoritative. The insertion
  inventory records additive Keyring guards; the historical checker verifies both
  inserted and original bytes rather than exempting the modified files.

`test-p0-keyring-sanitized` instruments the Keyring, isolation and durable-log
sources with address/undefined-behavior checks and runs the same process scenarios.

Registry replay and native C0 cost:

- `test-p0-state-replay <fresh-directory>` exports 34 native cases. Run Rust
  `state-replay-conformance` from `tos-validator-auth-native` on that directory.
  Each block executes both from a retained state and a decoded checkpoint. C++
  and Rust compare complete native cell content and ordered references, including
  a 501-identity registry, due-slot collisions, cancellation, archived epochs,
  policy boundaries and rejected-block atomicity.
- `registry_replay_mutations.py --fixtures ... --out ...` compiles 18 Rust guard
  removals and requires the intended named replay assertion, then restores and
  reruns the baseline.
- `benchmark-p0-c0 --check` proves full 400-member certificates succeed and corrupt
  P0/native signatures and a native block-ID mismatch fail. Without `--check`, it
  measures 30 paired samples; `--enforce` also enforces the proposed certificate
  median/p95 budget. Run timing only on an idle host.
- `benchmark_mutations.py --build ... --out ...` compiles three removals from the
  actual P0/native verifier paths and requires their exact control assertions.
- `measure_c0.py --build ... --out ... --enforce` records build identity alongside
  the timing. It reports unavailable governor and allocation/propagation evidence
  explicitly rather than representing certificate timing as full P0 acceptance.

Native certificate proofs and client admission:

- `test-p0-certificate-proof <committee-export> <fresh-export>` produces 55 native
  cases. Run `certificate-proof-conformance` and `certificate-client-conformance`
  from the native Rust crate against the export. Both independently verify full
  native committee/policy proofs, expected duties, signatures and computed results.
- `test-p0-certificate-rpc <committee-export> <certificate-export> [rust-client]`
  checks methods 12/13 over 16 native snapshots and public API error semantics.
  Passing `certificate-client-conformance` also exercises actual Unix HTTP, exact
  result bytes and proof-chunk call counts. Its native-history source is a fixture;
  it does not establish live manager/session/archive integration.
- `certificate_proof_mutations.py --language cpp|rust ...` requires 14 compiled
  proof/cryptographic removals per language. `certificate_rpc_mutations.py` adds
  16 source-authority, context, error and resource mutations.
- `certificate_client_mutations.py` adds seven prepared-value/result checks,
  including a compiled change that incorrectly repeats full proof verification.
  Re-fetching a proof must fail the exact single-fetch assertion.

Context and current governance authority:

- `context_fixtures.py --out <fresh-directory>` exports 76 public cases. Run
  `test-p0-context` and the core Rust `context-conformance` against that directory.
  `context_mutations.py --language cpp|rust` compiles 12 C++ or 34 Rust removals;
  malformed descriptors are re-signed so unrelated PoP failures cannot mask guards.
- `test-p0-governance <fresh-export>` and native Rust `governance-conformance`
  independently verify 28 cases, comparing exact certificate IDs, signers, weight
  and refusal codes. A historical roster cannot retain management authority after
  an inclusion-time rotation or expiry. `governance_mutations.py --language cpp|rust`
  compiles 16 C++ or 17 Rust guard removals with exact assertion labels.
- Both native drivers run in the fully instrumented Ubuntu sanitizer build.
  Normal native configuration voting and global registry apply are still separate
  from the read-only governance verifier.

Native owner execution:

- `owner_fixtures.py --build ... --driver <test-p0-owner-proof> --out <fresh-dir>`
  compiles and executes the existing wallet with real signature checks. Run once
  with `--workchain -1` and once with `--workchain 0`. The approval bytes must match
  the machine-readable native owner contract. Each exports six actual transactions
  and checks action rollback and forged-signature refusal.
- `test-p0-owner-proof verify <transactions> <fresh-proof-export>` checks 34 cases
  per workchain. Run native Rust `owner-conformance <proof-export>` to compare exact
  transaction hashes and refusal codes. The surrounding blocks and finality anchors
  are controlled fixtures; these are not node or elector acceptance tests.
- `owner_mutations.py --language cpp --build ... --inputs <mc-transactions>
  --shard-inputs <shard-transactions> --out ...` compiles 25 production mutations.
  The Rust form uses `--language rust --fixtures <mc-proof-export>
  --shard-fixtures <shard-proof-export>` and compiles 27, including the 1024/1025 BOC depth boundary. Both require precise
  assertion labels and restored baselines; setup errors and crashes do not count.
- Full Ubuntu sanitizer builds run both native exports and compare every file.
  The nested-Merkle mutation exercises the dedicated P0 effective-level adapter,
  without modifying historical Rust cell or proof implementation.
