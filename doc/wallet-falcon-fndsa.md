# Falcon wallet authorization and future FN-DSA profiles

This branch implements the original `TOS-FALCON512-PADDED-v1` development
profile described in the 2026-10-03 wallet design. It is experimental. Formal
FN-DSA remains a separately versioned future profile, with its own module code
identity, acceptance vectors and migration. Unknown profiles fail closed.

## Implemented boundaries

- A pinned official reference release, MIT license, archive digest and imported
  file hashes in `third-party/falcon-reference/PROVENANCE.md` and `SHA256SUMS`.
  The node/Rust verifier compiles only integer verification, encoding and SHAKE.
  The complete signer is a separate offline shared library in `tools/falcon`.
- C++ and Rust TVM opcode `PQCHECKSIG_FALCON512_PADDED`, candidate allocation
  `F93101`, candidate activation version 16, proposed base gas 20,000. It takes
  three canonical byte-chain Cells: message, signature, public key. Base gas
  follows stack-depth validation and precedes type/operand decoding. Every byte
  is charged before copying. Length/shape failures throw 9, invalid encodings or
  proofs return 0, valid proofs return -1, backend faults throw 12. Classic
  signature bypass/free-call behavior is not inherited. Version 15 and earlier
  retain historical InvalidOpcode exception metering.
- FunC, Tol, Fift and Rust assembler/disassembler bindings. Both compiled
  language probes execute in both VMs. ML-DSA retains `F93100`, its version-16
  gate, context, wire format and fees. Validator algorithm IDs are unchanged.
- Two immutable AUTH module implementations, separately compiled and addressed.
  Storage is `global_id:int32 profile_version:uint16=1 public_key:^Cell`.
  `submit#46414c31 query_id:uint64 envelope:^Cell signature:^Cell` reconstructs
  the 97-byte domain/root/request message. It accepts only funded internal
  submissions, preserves the exact AUTH envelope, reserves the old balance and
  forwards with mode 64. No owner, withdrawal, SETCODE/SETDATA or classic recovery
  key exists. Non-submit internal messages are deposits; bounces do not relay.
- Wallet V5 and Agent Account SDK codecs plus an offline `AuthProvider` with
  generation, trusted-snapshot preflight, reconstructed signing requests, local
  verification, funded internal submission, recovery checks and multi-hop
  receipt classification. The idempotency key is network/account/epoch/nonce/D.
- OS CSPRNG key generation and signing, encoded-key handles, native scratch
  wiping, redacted handle representation and signing self-verification.
  Portable version-1 encrypted backups authenticate profile, encoding,
  fingerprint, association and KDF/AEAD metadata. Scrypt supports only
  N=32768 or 65536, r=8, p=1; AES-256-GCM authenticates metadata. Duplicate JSON
  keys, unknown formats and excessive resource parameters fail before KDF work.
  Independent Falcon keys are not recoverable from legacy 24-word backups.
- Migration request preparation requires an active destination deployment in the
  same trusted chain snapshot, backup recovery/new-key possession,
  approved module identities and explicit confirmation of category/factor
  changes. The resulting kind=configure request still requires the **current**
  root under its current policy. Real two-hop tests cover ML-DSA to Falcon,
  including the old Ed25519 factor in hybrid mode. Epoch/nonce transitions and
  strict-mode downgrade refusal remain the existing account protocol.

The frozen application profile is [falcon512-profile-v1.json](falcon512-profile-v1.json).
Original Falcon-512 is security category 1; ML-DSA-44 is category 2. Hybrid means
Ed25519 **AND** the selected module. There is no ML-DSA OR Falcon fallback.

## Reproduce the development checks

Use Python 3.14 and the repository's pinned Rust toolchain. Build the tools:

```sh
python -m pip install -r tools/falcon/requirements.txt
scripts/install-rust-toolchain.sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target func fift tol emulator test-pq-falcon512-parity -j2
cmake -S tools/falcon -B build-falcon -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-falcon -j2
cmake -S test/mldsa-auth -B build-old-signer -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-old-signer -j2
cargo build --manifest-path tosctl/src/Cargo.toml --locked --release -p tos_vm --example falcon-parity
cargo build --manifest-path tosctl/src/Cargo.toml --locked --release -p tos_executor --example pq-tx-parity
```

On macOS, pass the selected SDK to native dependency builds. On a fresh build,
OpenSSL headers/libraries must be available before PQ CMake discovery. The CI
workflow selects system OpenSSL for the AArch64 VM checks and bundled OpenSSL
with QUIC for the x86_64 complete-node checks. Follow
[wallet-falcon.yml](../.github/workflows/wallet-falcon.yml) for the full sequence:
fixed KATs, raw and compiled opcode parity, real two-hop transaction parity,
backup/RNG/migration tests, funding boundaries, compiled mutations, injected
backend failures, ASan/UBSan and bounded full-VM calibration. CI runs on both
x86_64 and AArch64 and compares deterministic transcripts and module BOCs.
Artifact retention is 30 days; benchmark timings/compiler binary digests are
host-specific and are not required to be byte-identical across architectures.

Official original Falcon-512 known-answer coverage is separate from the TOS
fixed-profile corpus: `test/pq-falcon512/official/falcon512-KAT.rsp` contains all
100 published Round 3 answers, imported verbatim with source/archive/file
digests. CI verifies the original compressed signatures and key pairs, with
100 altered-message rejection controls, then runs the unmodified official
`test_falcon.c`. Its complete suite regenerates 100 Falcon-512 and 100
Falcon-1024 NIST answers against the upstream expected digests. Skipped KATs
fail CI. Enable `-DFALCON_BUILD_OFFICIAL_TESTS=ON` in the offline signer build,
then run `test/pq-falcon512/official_kat.py --library <offline-library> --suite
<test_falcon-executable> --out <artifact-directory>`. These official answers
are not relabelled as TOS PADDED vectors or independent implementation evidence.

The module compiler manifest records source commit, compiler SHA-256, code hash,
BOC digest and StateInit encoding separately for FunC and Tol. Trust a reviewed
manifest and verify the downloaded BOC digest/code hash before using it.

An opt-in disposable local-chain runner exercises funded deployment, paid bad
proof rejection, successful transfer and actual replay for both module languages
in modes 2 and 3. It treats the operator-controlled test node as its trust anchor;
account/config reads use one masterchain block. It does not provide production
checkpoint discovery or validator authentication. Build the node/lite-client and
generate the SDK API before starting a fresh test directory:

```sh
cmake --build build --target validator-engine dht-server validator-engine-console lite-client create-state generate-random-id tos-pq-consensus-key toslibjson -j2
python test/tostester/generate_tl.py
PYTHONPATH=test/tostester/src TOS_BUILD_DIR=$PWD/build TOS_GLOBAL_VERSION=16 python scripts/localnet-jsonrpc.py --rpc 127.0.0.1:28545 --control 127.0.0.1:28745 --base-port 29000 --workdir work/falcon-devnet
# In another terminal, after the test chain is ready:
python test/falcon-auth/live_relay.py --build build --library build-falcon/libtos_falcon_offline.so --lite-client build/lite-client/lite-client --lite-config work/falcon-devnet/lite-client.json --control 127.0.0.1:28745 --out work/falcon-live-artifacts
```

Stop only the test network process when the run completes. Never point this
runner at a production/shared network or use its ephemeral keys for real assets.

## Offline wallet

```sh
python tools/falcon/wallet.py --library build-falcon/libtos_falcon_offline.so --help
```

Use `.dylib` on macOS. `generate` writes an encrypted backup and public StateInit
without replacing existing files; it rehearses recovery before writing.
`describe` reports the verified account's mode/root/profile. `sign-submit`
reconstructs the request from a locally reviewed chain snapshot and intent,
requires the matching associated backup, verifies the proof, checks an optional
Ed25519 cosignature against D, and writes a funded **internal** message BOC.
It does not transmit a message or claim final delivery.

`migrate` prepares a funded rotation from a current Falcon root. It takes the
current account snapshot/backup, a destination deployment snapshot and the new
associated backup; it rehearses new-key recovery before loading the current
signing key. Mode changes require `--confirm-security-change`, and hybrid still
requires the current Ed25519 cosignature. Destination fields are network,
global_version, now, root, code, data, status; code/data are BOC hex. The two
snapshots must refer to the same chain time. Generic `sign-submit` and manually
constructed provider requests cannot bypass this preflight for kind=configure.
The independent ML-DSA provider remains responsible for authorizing an ML-DSA to
Falcon cutover; `buildMigrationRequest` prepares its D after the same checks.

A trusted chain adapter must validate snapshot/receipt authenticity and
freshness. The CLI's local JSON snapshot is an operator-reviewed offline input,
not a cryptographically verified RPC/lite-client proof. Its required fields are
network, global_version, now, account, account_code, account_data, root,
module_code, module_data, account_status and module_status. Cells are BOC hex;
addresses are raw `workchain:hash`. Intent contains kind, payload (BOC hex),
valid_until. Production adapters and a managed relayer remain to be integrated.
Signing and submission require a request prepared by the same provider from a
reviewed snapshot. The binding covers the serialized request, root, profile,
public keys, account mode and snapshot commitment. Altered or imported request
objects require fresh preflight. The provider retains at most 128 pending
request fingerprints; evicted requests must be prepared again. This client
preflight record does not cache cryptographic verification or affect VM fees.

Receipts distinguish nonce consumption from the requested operation's result.
The old dictionary contract provides progress/failure hints only: phase-success,
nonce and final-state booleans never certify completion or observed funds.
`trackReceipt` requires `TrustedReceiptEvidence` from an authenticated chain
adapter for completion. Its `network` and `module`, `target`, `deliveries` and
`bounce_returns` observations must be inclusion/finality checked by that adapter;
constructing the Python object or decoding RPC BOCs does not authenticate them.
Each `TrustedTransactionObservation` contains the original transaction Cell and
optional full `Account` Cells `before`/`after`. Target completion requires both
Account proofs, with hashes matching that transaction's `HASH_UPDATE`, rather
than an arbitrary genuine later snapshot or StateInit/data alone.

The classifier binds the module submission to the exact signed request and
root, then the target input to the exact emitted relay. It parses real action
counts and the action-list hash, matches requested outgoing destinations,
bodies, StateInit and value semantics, and checks the requested AUTH state.
`+2` ignored sends become `target actions skipped`; a partly emitted batch
becomes `target actions partially completed`, even when action-phase success and
nonce consumption are true. Missing operation evidence remains incomplete.
Every expected send must also have a matching recipient transaction before
`actions completed`; otherwise the receipt says `actions emitted; delivery
pending`. This certifies the requested account actions and recipient acceptance,
not an unspecified downstream business result. Wallet fees/carry-value modes
are bound by the authenticated action list, not guessed from a nominal amount.
Unknown operation matchers remain incomplete.

Configure operations need no outbound message: verify the requested root/mode,
incremented AUTH epoch and reset nonce in the transaction-bound account state.
Agent controller sends/cancellation and owner policy/controller changes also
match their signed operation and resulting state. Recipient rejection and a
later bounce update the delivery outcome without undoing a consumed nonce.
`delivery`, `bounce` and `reserve` are separate observations: an emitted bounce
is still return-pending until its actual return transaction credits the source;
module reserve preservation requires transaction-bound balance proofs and
accounts for collected storage fees. Missing funds evidence stays `not observed`.
Deposits and bounced funds can remain locked in the immutable module; there is
no refund promise. Frozen/deleted snapshots require separate storage recovery.

`test/falcon-auth/receipt_e2e.py` executes 64 native transaction-to-`trackReceipt`
cases across both module languages, Wallet V5 implementations and modes, plus
Agent operations. It covers ignored sends, partial batches, successful delivery,
zero-send configuration/cancellation, policy changes and delayed bounce return.
The Rust executor independently compares all 164 captured transactions.
Configuration-state tampering controls use explicitly synthetic adapter cells;
they are not reported as genuine chain executions. Four compiled client guard
bypasses must reach targeted assertions, then restored baselines must pass.
CI retains these reports and compares deterministic receipt artifacts on both
architectures. The emulator is the local test trust anchor; this regression is
not a production chain adapter or a new live-network qualification claim.

## Acceptance evidence and remaining work

For this delivery, P3 is scoped to MacBook host validation. iOS/Android product
integration and genuine-device release qualification are deferred.

| Design tests | Delivered executable coverage | Remaining qualification |
| --- | --- | --- |
| T01–T06 | Fixed positive/negative vectors, explicit PADDED reference API comparison, lengths/encoding/domain mutations, malformed canonical chains, exotic/library cells, both VMs/bindings, version/gas/type and backend fault injection | Oracle and verifier share reference sources; independent cryptographic implementation/audit still required |
| T07–T11 | Real module action messages delivered unchanged to both account types; cross-VM transaction/state comparison; both workchains; replay, expiry, rotation, hybrid AND, funding/forward/bounce and committed refusal | Disposable distributed devnet/production relayer exercises remain |
| T12–T13 | Legacy staging/cutover, old-policy ML-DSA to Falcon, root review, explicit factor confirmation, possession and encrypted recovery, wrong passwords/metadata/versions/KDF limits | Future formal FN-DSA profile and mobile integration require new releases |
| T14 | Checked OS entropy, RNG failures, matching key handles, self-verification, native scratch wipe and redaction | Python/native stack copies are not a forensic wipe guarantee; phone/release/side-channel qualification remains |
| T15–T16 | ASan/UBSan, 20,000 bounded fuzz inputs, complete-VM valid/invalid/max-message load, compiled verifier/version/gas/canonical/root/profile/network mutations; existing account nonce mutants | Long-running coverage-guided fuzz and complete-node invalid-proof flood/pricing qualification remain |
| T17 | Actual funded PQ-from-genesis deployment from absent accounts; rejection of mismatched legacy StateInit; strict account execution; client refusal of frozen/deleted/unsupported state and undeployed migration roots | Full storage arrears, freeze, deletion/redeployment and durable recovery qualification remains |
| T18 | Existing ML-DSA AUTH, highload/quorum and account nonce regressions; unchanged validator wire/IDs and privacy source | Existing final-head CI remains the validator/privacy regression gate; a broad local Rust VM run passed 74 tests and found 4 unrelated getter tests blocked by missing node fixture zerostate_blank_elections.json |

P0/P1/P2 have executable repository implementations and the above bounded local
checks. This is not 100% completion of all design gates. The TOS branch does not
edit the separate iOS/Android repositories or provide genuine phone/keystore
release evidence. Complete trusted chain/relayer adapters, storage lifecycle
qualification, distributed node load and independent review remain.

The official NIST page checked on 2026-10-03 still lists FIPS 206 as in development:
https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization.
The pinned original Falcon release is not interchangeable with pre-standard
FN-DSA implementations. See https://github.com/pornin/c-fn-dsa for its explicit
compatibility warning. Production requires approved opcode/version/gas,
maintenance/audit ownership, validator coverage, authenticated network ConfigParam
8, reviewed deployment manifests, wallet/relayer/real-device acceptance and
backup/incident exercises. No network configuration or default wallet policy is
changed by this branch.
