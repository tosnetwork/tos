# UNO v1 Audit Scope

> **Shipping scope.** Per the v1 pivot in
> `doc/uno-aggregation-design.md` §-1 (2026-04-21), UNO v1 launches
> with **per-Tx Plonky3 proofs** and `BLOCK_TX_CAP = 4` — no
> block-level recursive aggregation. This document is the **v1
> audit scope**: the code that external reviewers must sign off on
> before mainnet. A parallel document,
> `doc/uno-monolithic-air-invariants.md`, covers the **v2 monolithic
> VerifierAir** (research code, frozen in-tree, explicitly out of
> v1 scope — see §3 below).

---

## 1. Purpose

This document is the scope of the external security audit for the
UNO v1 mainnet launch. It is the vendor handoff material: it
enumerates every component on the v1 consensus-critical path, points
at the exact files the audit should exercise, lists the suggested
pass/fail queries, and flags v2-frozen modules that are deliberately
out of v1 scope. Review cadence: **once pre-mainnet** (full v1
scope), **again on any consensus-binding wire-format change**
(Transfer encoding, public-input byte layout, Poseidon2 tagging,
canonical tx_hash preimage). Items not on the v1 critical path —
notably the monolithic AIR and the block-level aggregator — are
deferred to a later v2 audit, gated by the trigger checklist in
`doc/uno-aggregation-design.md` §-1.

---

## 2. In-scope components (v1 critical path)

Each v1-critical module below lists file path, role, and the
audit angle to prioritise.

### 2.1 Per-Tx Transfer AIR (primary focus)

* **File.** `uno/plonky3-ffi/src/transfer_air.rs` (2 350 LoC).
* **Role.** The single in-circuit artefact on the v1 consensus
  path. Every Transfer carries a Plonky3 STARK proof over this
  AIR; validator §4.3 step-4 verify delegates via
  `MvpVerifier::verify` (see §2.5 for FFI).
* **Shape dispatch.** Parameterised over `(n_spends, n_outputs)`
  with `1 ≤ n_spends, n_outputs ≤ 4` — 16 legal shapes. Width is
  `air_width(n_s, n_o) = GLOBAL_COLS + n_s·per_spend_cols() +
  n_o·per_output_cols()` (defined at `transfer_air.rs:363-365`).
  Shape is derived on the verifier side from the public-input byte
  length (`derive_shape_from_public_inputs_len`), so an attacker
  who ships a 4/4 proof with a 1/2 PI vector is caught at decode.

  | Shape  | Approx AIR width (cols) | PI length (field elems) | PI bytes |
  |--------|-------------------------:|-------------------------:|---------:|
  | 1 / 1  | ~450                    | `8 + 8 + 9 = 25`         | 200      |
  | 2 / 2  | ~1 000                  | `8 + 16 + 18 = 42`       | 336      |
  | 4 / 4  | ~2 600                  | `8 + 32 + 36 = 76`       | 608      |

* **Claims the AIR attests (see module-level docstring at
  `transfer_air.rs:1-113`).** Cross-reference `§4.2` of the
  workchain spec.

  1. **Merkle path (32 levels, §2.3).** For each spend `i`, the
     prover opens `cm_i → anchor` across 32 Poseidon2-Goldilocks-8
     compressions. Row-0 binding: `current_final_i ==
     public_inputs[anchor][0]`.
  2. **Note-commitment opening.** `cm_i = Poseidon2("uno-cm-v1",
     d_i, pk_d_i, ivk_commitment_i, value_i, rcm_i)`. Row-0
     binding: `cm_i == leaf_i`.
  3. **Ownership via ivk-commitment.** `ivk_commitment_i =
     Poseidon2("uno-ivk-cm-v1", ivk_i, d_i)`. Row-0 binding against
     the claim-2 input slot.
  4. **Nullifier.** `nf_i = Poseidon2("uno-nf-v1", nk_i, cm_i,
     pos_i)`. Row-0 binding: `nf_i == public_inputs[nf_i][0]`.
  5. **Value range `value_i < 2^64`** (claim 5 / claim 7). Native
     Goldilocks arithmetic.
  6. **Output commitment** (identical Poseidon2 shape to claim 2,
     over sender-chosen witnesses).
  7. **Output range** (same as claim 5).
  8. **Balance.** `Σ_i value_i = Σ_j value_j + fee`. Single
     degree-1 field-element equality on row 0.
  9. **ivk / ivk_commitment derivation.** Combined with claim 3.

* **Audit angles.**
  - Constraint correctness: every Poseidon2 gate fires on the
    intended row set; shared w=8 / w=16 row-looped Poseidon2
    blocks (`transfer_air.rs:58-91`) cannot leak arithmetic
    between the Merkle, Cm/OutCm, and IvkCm/Nf row regions.
  - Soundness against forged spends: no row-0 binding is
    reachable via a path that bypasses the Poseidon2 chain.
  - Double-spend via rcm reuse: claim 2 + claim 4 together force
    `(cm, pos) → nf` injectivity per `nk` holder.
  - Balance: confirm claim 8's degree-1 equality with no hidden
    carry / wrap. Range: confirm claim 5/7 at the Goldilocks
    boundary `p = 2^64 − 2^32 + 1`.
  - Shape confusion: confirm
    `derive_shape_from_public_inputs_len` rejects every non-legal
    PI length (exercised by `shape_derivation_rejects_bogus_length`
    at `transfer_air.rs:2243`).

* **Test coverage.** 11 `#[test]` in `transfer_air.rs`, plus 13
  in `verifier.rs` — including adversarial tamper tests:
  `verify_rejects_tampered_public_inputs`,
  `verify_rejects_malformed_proof`,
  `verify_rejects_shape_confusion_attack`,
  `verify_rejects_adversarial_{ivk,pos,wrong_anchor}`,
  `prover_rejects_inflation_adversary_4_4`
  (`verifier.rs:127-310`).

### 2.2 Poseidon2-w8 / Goldilocks hash family

* **Files.** No local fork — Poseidon2-w8 round constants and
  linear-layer matrices come from `p3_goldilocks::
  {GOLDILOCKS_POSEIDON2_RC_8_*,
  GenericPoseidon2LinearLayersGoldilocks}`. C++ mirror at
  `uno/crypto/poseidon2.{h,cpp}`; wallet Rust mirror at
  `tosctl/uno/src/poseidon2.rs` (258 LoC; 6 `#[test]`).
* **Upstream pin.** Plonky3 commit
  `6374a36ff50fc641821513852263cc61ca7a1278` (upstream v0.5.1),
  vendored at `third-party/plonky3-uno/` per §16 decision #43
  (`uno/plonky3-ffi/Cargo.toml:11-46`).
  `tosctl/uno/Cargo.toml:92-95` pins the same rev for wallet-
  side p3-goldilocks / p3-poseidon2.
* **Audit angle.** Confirm no local modification relative to
  upstream (round constants, round counts, matrices); vendored
  crates match pinned commit byte-for-byte.
* **Out of internal audit scope.** Algorithm-level analysis
  defers to the upstream Poseidon2 literature; audit posture is
  integration-verify only (equivalent to ML-KEM-768 FIPS-203).

### 2.3 canonical_tx_hash (wire binding)

* **File.** `uno/core/transaction.cpp::canonical_tx_hash` at
  `transaction.cpp:209-274`. Header at `uno/core/transaction.h:1-
  100` documents the wire layout.
* **Function.** BLAKE3 over a canonically-ordered preimage:
  * inline header: `version(1) || scheme_id(1) || chain_id(4, BE)
    || anchor(32) || expiry_block(8, BE) || fee(8, BE) ||
    spend_count(1) || output_count(1)` = 56 bytes
    (`transaction.cpp:244-252`);
  * per spend: `nullifier(32) || rk(32)` — **signatures are
    excluded** (`transaction.cpp:254-258`);
  * per output: `cm(32) || epk(32) || filter_tag(2, BE) ||
    cell_root_hash(enc_ciphertext, 32) ||
    cell_root_hash(mlkem_ct, 32) || out_ciphertext(80)`
    (`transaction.cpp:260-268`).
* **Audit angle.**
  - **Preimage canonicality.** No field omitted, ordering
    unambiguous, inline-vs-cell-root hash choice on the two
    ciphertext fields yields a unique preimage per semantic
    content.
  - **Malleability.** Any wire-level re-ordering of spends /
    outputs yields a distinct `tx_hash`. Signatures excluded so
    re-signing does not change `tx_hash`.
  - **Coupling to §4.3 step 3.** Schnorr verify in
    `parallel-verify.cpp:202-210` signs the value this
    function returns.

### 2.4 Schnorr-on-Ristretto255 (spend auth)

* **Files.** Wallet side: `tosctl/uno/src/schnorr.rs` (229 LoC;
  5 `#[test]`). Validator side:
  `uno/crypto/schnorr-ristretto.{h,cpp}` +
  `uno/crypto/ristretto255.{h,cpp}`. The verifier call site is
  `parallel-verify.cpp:118-127, 202-210`.
* **Scheme (per `tosctl/uno/src/schnorr.rs:1-40`).** Standard
  Schnorr with `c = Scalar::from_bytes_mod_order_wide(
  BLAKE2b-512("uno-schnorr-chal-v1", R, rk, msg))` and
  deterministic nonce `k = BLAKE2b-512("uno-schnorr-nonce-v1",
  rsk, msg)`. Signature is `R(32) || s(32) = 64 B`.
* **Audit angle.**
  - **Ristretto255 point validation.** `rk` / `R` decompress
    with full canonical-encoding checks
    (`parallel-verify.cpp:112-116::ristretto255_is_valid_point`
    + `RistrettoPoint::validate()`) — no weak-curve / low-order
    / non-canonical path slips through.
  - **Hash-to-scalar discipline.** BLAKE2b-512 →
    `from_bytes_mod_order_wide` (no mod-bias); domain-separation
    tags `uno-schnorr-nonce-v1` and `uno-schnorr-chal-v1` never
    confused across call sites.
  - **Hedged vs deterministic signing.** `rsk` drawn from OS
    RNG; deterministic nonces do not leak `rsk` under adversary-
    chosen `msg` (transcript binds both `rsk` and `msg`).
  - **Malleability.** Signatures unique per `(rk, msg)` — no
    trailing-bit / high-bit malleability like Bitcoin pre-BIP62.

### 2.5 Hybrid KEM (ML-KEM-768 + X25519)

* **Files.** Wallet side: `tosctl/uno/src/hybrid_kem.rs` (103 LoC;
  3 `#[test]`). Validator side (for restart-survival scan of owned
  notes): `uno/crypto/hybrid-kem.{h,cpp}`,
  `uno/crypto/mlkem768.{h,cpp}`,
  `uno/crypto/note-encryption.{h,cpp}`.
* **Construction** (see `hybrid_kem.rs:6-19`).
  * `k_aead = BLAKE3("uno-hybrid-kem-v1"(17 B) || compress(s_dh)
    || s_pq || compress(epk) || BLAKE3(mlkem_ct))[0..32]` — 145 B
    fixed-size transcript.
  * `nonce = BLAKE3("uno-nonce-v1" || compress(epk))[0..12]`.
  * AEAD: ChaCha20-Poly1305 over `enc_ciphertext`.
* **Audit angle.**
  - **KDF transcript binding.** BLAKE3 transcript includes every
    byte that determines the shared secret; `mlkem_ct` is hashed
    (not absorbed raw) so flipping one byte changes `k_aead`.
  - **Nonce derivation.** `nonce` bound to `epk`; since `epk` is
    fresh per output, `(k_aead, nonce)` is unique per output.
  - **AEAD mode.** ChaCha20-Poly1305 one-shot — no nonce-reuse
    across outputs.
  - **ML-KEM ciphertext malleability.** Confirm IND-CCA2 of the
    hybrid (standard Shoup argument; BLAKE3 binds both KEM
    outputs).
  - **Point validation.** `compress(s_dh)` / `compress(epk)`
    canonical Ristretto255 encoding only.
  - **Constant-time decap.** No wallet-side timing channel on
    trial-decrypt failure.

### 2.6 Compact filter (§2.8)

* **Files.** Wallet decoder: `tosctl/uno/src/gcs.rs` (239 LoC; 4
  `#[test]`). Validator encoder + per-block filter state:
  `uno/core/block-filter.{h,cpp}`. RPC surface exposes per-block
  filter bytes via `uno_getBlockFilter`.
* **Wire format** (see `gcs.rs:9-19`). Parameters: `P = 15`
  Golomb-Rice quotient bits, `M = 2^16` tag universe (matches the
  16-bit `filter_tag`). Entries encode `Δᵢ = tagᵢ − tagᵢ₋₁ − 1`
  per sorted tag.
* **Audit angle.**
  - **Determinism across validators.** Filter-tag accumulation in
    `compute-phase.cpp:166-167` is declared-order, identical on
    every validator, and matches the wallet-side decoder.
  - **False-positive rate.** Target `2^-16` at `P = 15` — confirm
    observed distribution matches.
  - **Tag secrecy.** `filter_tag` reveals no correlation with the
    spend graph beyond what the tx-list already reveals. Review
    `stealth-address.{h,cpp}::derive_filter_tag`.

### 2.7 Compute-phase ordering (§4.3)

* **Files.** `uno/core/compute-phase.cpp` (383 LoC) drives the
  per-block dispatch; `uno/core/parallel-verify.cpp` (460 LoC)
  owns the consensus step-order inside `verify_transfer_with_
  holder` (at `parallel-verify.cpp:132-234`).
* **Declared step order (§4.3, inside `verify_transfer_with_
  holder`).**
  1. Cheap syntax: `version / scheme_id / chain_id / expiry /
     spend_count / output_count / fee` (L136-153).
  2. Anchor membership: `state.anchor_window_contains(tx.anchor)`
     (L155-157).
  3. Within-tx pairwise distinctness on nullifiers and on output
     commitments (L160-179).
  4. Ristretto point decompression on every `rk` and every `epk`
     (L182-193).
  5. Nullifier not-spent check against on-cell dictionary + LRU
     (L196-200).
  6. Schnorr spend-auth-sig verify over `tx.tx_hash` (L203-210).
  7. Plonky3 STARK verify (L213-231).
  8. Apply (only on success — see `compute-phase.cpp:155-172
     ::apply_transfer`).
* **Audit angles.**
  - **Order correctness.** Every cheaper reject precedes a more
    expensive one — DoS-hardening argument.
  - **No-state-mutation-on-reject.** `compute-phase.cpp:232-261`
    ensures `apply_transfer` is only reached on
    `VerifyResult::Ok`; on any other outcome `cp.new_data` is
    not written and `state` is untouched.
  - **Parallel-verify race-freeness.** The pool only exposes
    `const UnoState&` to workers; `apply` happens in main-thread
    declared order after the pool returns the results vector
    (`run_compute_phase_batch`).
  - **Test-only override.** `compute-phase.cpp:82-90` declares a
    `g_test_proof_override` hook — confirm it is never installed
    in a production binary (scope the audit to the build graph).

### 2.8 Nullifier LRU cache

* **Files.** `uno/core/nullifier-set.{h,cpp}` (406 LoC total).
  Warm-snapshot + LRU front-end over the authoritative on-cell
  `vm::Dictionary`.
* **Authoritative storage.** `vm::Dictionary` with 256-bit keys
  (see `nullifier-set.h:1-50`). The LRU is **advisory only, not
  part of the consensus state root** — a positive LRU hit is
  sufficient to reject a double-spend, but a negative LRU answer
  MUST be confirmed by a dict lookup before declaring the
  nullifier unseen (`nullifier-set.h:7-14`).
* **Default capacity.** 1 M entries (~100 MB RAM), tunable via
  ConfigParam 84 (`nullifier-set.h:40-48`).
* **Audit angle.**
  - **Cache miss / hit correctness.** Two-tier lookup preserves
    the authoritative answer byte-identically (exercised by
    `test-nullifier-warm-lru.cpp`).
  - **Eviction determinism.** Deterministic across validators
    running the same tx stream.
  - **Memory bound.** `kDefaultNullifierWarmSnapshotCap =
    1 048 576` never exceeds the configured limit.
  - **Warm-path (post-restart).** Warm-snapshot repopulation
    matches the persisted dict (`test-restart-survival.cpp`).

### 2.9 BIP-39 / key derivation

* **File.** `tosctl/uno/src/keygen.rs` (372 LoC; 5 `#[test]`).
* **Derivation** (see `keygen.rs:1-22`).
  ```text
  uno_seed    = BLAKE2b-256("uno-seed-v1"   || main_tos_seed)
  nk          = Poseidon2("uno-nk-v1",       uno_seed)
  ivk         = Poseidon2("uno-ivk-v1",      uno_seed, nk)
  ovk         = BLAKE2b-256("uno-ovk-v1"     || uno_seed)
  mlkem_seed  = BLAKE2b-256("uno-mlkem-v1"   || uno_seed)
  (pk_mlkem, sk_mlkem) = ML-KEM-768.KeyGen(mlkem_seed)
  fvk         = (ivk, nk, ovk, sk_mlkem)
  ```
* **Audit angle.**
  - **Derivation rule matches §2.6.** Every domain tag matches
    the spec exactly; no tag re-use across `nk / ivk / ovk /
    mlkem_seed`.
  - **Seed zeroization.** `uno_seed / main_tos_seed / rsk`
    zeroize on drop (`Digest32` derives `Zeroize` at
    `keygen.rs:40-42`; `rsk` via `curve25519-dalek`'s `zeroize`
    feature, `schnorr.rs:75-82`).
  - **fvk / ivk / sk_mlkem separation.** Compromise of any one
    of `ovk`, `sk_mlkem`, `nk`, `ivk` does not imply compromise
    of the others — each derives from `uno_seed` with a distinct
    tag; implication chain needs review.

---

## 3. Out-of-scope components (frozen v2 research)

These modules ship in-tree but are **not on the v1 consensus-
critical path**. Explicitly scoped OUT; deferred to a later v2
audit (gated by triggers in `doc/uno-aggregation-design.md` §-1).

| Component | File(s) | v2-audit doc |
|-----------|---------|-------------|
| Monolithic VerifierAir | `uno/plonky3-ffi/src/monolithic_verifier_air.rs` (5 359 LoC) | `doc/uno-monolithic-air-invariants.md` (15 cross-binding invariants I-1..I-15 + 48 tests catalogued) |
| UnoBlockExtra wire format | `uno/plonky3-ffi/src/block_wire_format.rs` | (field is shipping but unused at v1; lives in `UnoBlockExtra` framing) |
| Block-verifier FFI + RAII (A6-1, A6-1.5, A6-2, A6-3) | `uno/crypto/block-proof-verifier.h` + entry points in `uno/plonky3-ffi/src/lib.rs` | same |
| Aggregator module (`prove_block` / `verify_block`) | `uno/plonky3-ffi/src/aggregator.rs` | same |
| All sub-AIRs supporting monolithic aggregation | `{alpha_reduction_air, challenger_air, compression_path_air, fold_air, leaf_hash_air, merkle_path_air, query_verifier_air, verifier_air}.rs` | same |

Rationale: these modules were built during A1..A6 research
targeting block-level aggregation as a v1 feature. The
2026-04-21 pivot reverted the consensus-binding portion
(A6-4a); the Rust research code stays in-tree for v2. Re-
auditing now costs audit budget against code not on the v1
chain. See `doc/uno-monolithic-air-invariants.md` for the
v2-scoped handoff (~15 cross-binding invariants, 48 tests).

Additional v2-deferred items from `doc/uno-aggregation-design.md`
§-1:
- Block-level monolithic AIR aggregation (the A3-5c path).
- Soft-finality window K (the §2.6 "proof-pending → finalized"
  model).
- `AggregatedProofDelivery` message type.
- `UnoBlockExtra.aggregated_proof` field (framing present; no
  proof content at v1).
- Witness broadcast / prover failover roles.

---

## 4. Known gaps (pre-audit)

The following items are pending and should be resolved before the
audit begins (or, where noted, fed to the audit as a "please
confirm after this lands" addendum):

* **V1-2b fee calibration** — `doc/uno-aggregation-design.md` §-1
  phase table shows V1-2 as **🟡 PARTIAL**. The numeric fee tables
  (`min_fee_nano`, `fee_per_byte_nano`, `fee_per_spend_nano`,
  `fee_per_output_nano`, `filter_tag` bandwidth) have not been
  recalibrated for the post-pivot 4-TPS target and the ~520 KB
  per-Tx proof size. The audit should review `required_fee` in
  `parallel-verify.cpp:82-90` once V1-2b lands.

* **V1-3b tosctl-uno BoC parity with daemon** — `tosctl/uno`
  CAN produce a signed + proven Transfer (the prove path is
  green, `uno_plonky3_ffi::prove_transfer` emits a valid
  `zk_proof`, and 4 integration tests pass), but
  `transfer::encode_transfer_wire` uses a FLAT self-contained
  byte layout that does NOT round-trip through the daemon's
  `uno/core/transaction.cpp::decode_transfer_bytes`, which
  expects a TOS BoC (tree of Cells with refs). Flagged at
  `tosctl/uno/Cargo.toml:15-24`. Until V1-3b lands, the audit
  can only exercise the prove side end-to-end; the wallet →
  daemon submit path is not yet testable.

* **V1-4 testnet burn-in** — 60-day 4-TPS sustained testnet run
  not yet started. The audit report will land BEFORE testnet
  completes; a post-testnet re-review hook is suggested.

* **§13 P.3 activation classification** — the workchain spec
  originally classified parallel Plonky3 verify (§13 P.3) as an
  **activation prerequisite**. Per §16 decision #28, the label
  has been relaxed to "strong recommendation" under v1's 4-TPS
  posture (since 4 × 25 ms = 100 ms serial fits inside the 400 ms
  compute-phase budget). The code path stays at full strength.
  The audit should confirm this re-classification is a bookkeeping
  change only, not a structural re-gate — cross-ref V1-2b when
  the fee table lands.

---

## 5. Test coverage to share with auditor

Test assets shippable as audit collateral. All counts are
`#[test]` / `TEST()` annotations at the time of writing.

### 5.1 Rust unit tests (`uno/plonky3-ffi/src/*.rs`)

22 source files, **325** `#[test]` functions total across the
crate. v1-critical subset:

| File | `#[test]` count |
|------|----------------:|
| `transfer_air.rs` | 11 |
| `verifier.rs` | 13 (incl. 7 adversarial tamper tests) |
| `prover.rs` | 8 |
| `lib.rs` (FFI surface) | 18 |

The remaining files listed in §3 above (monolithic AIR + sub-AIR
modules) contribute the majority of the crate's 325 tests; they
are v2-scoped per §3.

### 5.2 Wallet-side tests (`tosctl/uno/`)

Unit tests inside `tosctl/uno/src/*.rs`:

| File | `#[test]` count |
|------|----------------:|
| `address.rs` | 7 |
| `gcs.rs` | 4 |
| `genesis_build.rs` | 7 |
| `hybrid_kem.rs` | 3 |
| `keygen.rs` | 5 |
| `poseidon2.rs` | 6 |
| `schnorr.rs` | 5 |
| `send.rs` | 6 |
| `transfer.rs` | 6 |
| Others | 3 |

Integration tests at `tosctl/uno/tests/`:
`derive_keys_then_address.rs` (1), `genesis_build_golden.rs` (3),
`send_roundtrip.rs` (4).

### 5.3 C++ integration tests (`uno/test/`)

20 test binaries totalling ~11 500 LoC. v1-critical subset, by
coverage:

| Test file | Area covered |
|-----------|-------------|
| `test-transfer.cpp` | Transfer wire codec round-trip |
| `test-codec-fuzz.cpp` | Fuzz over malformed wire inputs |
| `test-codec-parity.cpp` | C++ ↔ Rust codec parity (golden) |
| `test-codec-shapes.cpp` | All 16 shape permutations |
| `test-mandatory-negatives.cpp` | `VerifyResult` negative paths |
| `test-parallel-verify.cpp` | §13 P.3 pool byte-identical to serial |
| `test-nullifier-warm-lru.cpp` | §2.8 LRU front-end |
| `test-determinism.cpp` | Cross-run byte-identical compute phase |
| `test-state-transition-golden.cpp` | Golden state deltas |
| `test-restart-survival.cpp` | Warm-snapshot restore |
| `test-filter.cpp` / `test-filter-bench.cpp` | GCS compact filter |
| `test-primitive-parity.cpp` | Poseidon2 / Ristretto / Schnorr parity |
| `test-public-input-fixture.cpp` | PI byte-encoding golden |
| `test-uno-end-to-end.cpp` | P.5 two-wallet demo over compute-phase |
| `test-uno-metrics.cpp` | Metrics instrumentation |
| `test-bech32m-envelope.cpp` | Address encoding |
| `test-genesis-loader.cpp` | Genesis distribution parsing |

### 5.4 Golden fixtures (`uno/test/golden/`)

| File | Binds |
|------|-------|
| `codec-parity-v1.hex` | C++ ↔ Rust wire codec |
| `public-inputs-v1.hex` | PI byte encoding §4.3 step 4 |
| `state-transitions-v1.hex` | State-machine deltas |
| `genesis-distribution-v1.json` | Genesis-balance set |

Python KAT: `uno/test/reference/hybrid_kem_kat.py` (cross-
implementation known-answer test for §2.7 hybrid KEM).

---

## 6. Suggested audit queries (checklist)

The following pointed questions are designed as the audit's
pass/fail gate. Each references a concrete file / line / test.

1. **Confirm that** a prover CANNOT produce a valid Transfer AIR
   proof for a double-spend by reusing the same `rcm` across two
   different anchors — i.e. the joint claim-2 + claim-4 chain
   forces `(cm, pos) → nf` to be injective per `(nk)` holder
   (`transfer_air.rs:14-57`).

2. **Confirm that** `canonical_tx_hash`
   (`transaction.cpp:209-274`) binds every consensus-critical
   byte of the Transfer, that `spend_auth_sig` is
   cryptographically tied to it via
   `parallel-verify.cpp:202-210`, and that no permutation /
   re-ordering / zero-filled-cell path produces a collision.

3. **Confirm that** `derive_shape_from_public_inputs_len`
   (transfer_air.rs) rejects every non-legal PI length, so a
   shape-confusion attack (prove 4/4, submit 1/2 PI bytes) is
   trapped before `verify` runs (exercised by
   `verify_rejects_shape_confusion_attack` in verifier.rs:200).

4. **Confirm that** the in-circuit balance constraint (claim 8)
   is exactly `Σ value_i = Σ value_j + fee` over Goldilocks, with
   no hidden carry / wrap, and that it holds for every shape in
   `1..4 × 1..4` (exercised by
   `witness_balance_holds_for_deterministic_valid` at
   `transfer_air.rs:2276`).

5. **Confirm that** the nullifier-LRU cache
   (`nullifier-set.{h,cpp}`) preserves the authoritative on-cell
   dict answer byte-identically under all
   insert-order / eviction scenarios; and that a negative LRU
   answer is never used to accept a Transfer without a dict
   re-check.

6. **Confirm that** the §4.3 compute-phase order in
   `parallel-verify.cpp:132-234` is not re-orderable in a way
   that applies state before a cheaper check could have caught
   the Transfer (`compute-phase.cpp:232-261` is the apply
   gate — confirm it is unreachable on `VerifyResult != Ok`).

7. **Confirm that** the parallel-verify pool
   (`parallel-verify.cpp::ParallelVerifyPool`) has no TOCTOU
   race between `verify` (worker, `const state&`) and `apply`
   (main thread, mutable state) — specifically that no worker
   writes to `UnoState` (exercised by
   `test-parallel-verify.cpp`'s determinism-vs-serial
   invariant).

8. **Confirm that** hybrid-KEM decap
   (`hybrid_kem.rs` + `hybrid-kem.{h,cpp}`) remains IND-CCA2
   under adversarial ML-KEM ciphertext choice, and that the
   BLAKE3 transcript rules out a `mlkem_ct` malleability attack
   (flipping one byte of `mlkem_ct` must change `k_aead` — tested
   at `hybrid_kem.rs:94-102`).

9. **Confirm that** the compact-filter construction
   (§2.6 + `gcs.rs`) reveals no information about the spend
   graph beyond what the tx-list already reveals — specifically,
   that `filter_tag` cannot be inverted to recover `(ivk, cm)`
   without `ivk`.

10. **Confirm that** the Transfer wire format
    (`transaction.{h,cpp}::{encode,decode}_transfer`) is
    unambiguous under all `1..4 × 1..4` shape combinations and
    every out-of-range `spend_count` / `output_count` value is
    rejected at decode (exercised by `test-codec-fuzz.cpp`
    and `test-codec-shapes.cpp`).

11. **Confirm that** an attacker with a compromised block-
    producing validator CANNOT produce a block whose cell-state
    commits to a Transfer set that omits an accepted Transfer
    — i.e. the §4.3 step 5 `apply_transfer` path is the only
    route to a changed nullifier-set root / commitment-tree
    root, and omission is caught at catchain verify (relies on
    TOS's underlying catchain — but UNO-specific invariants
    should be audited).

12. **Confirm that** Schnorr signatures under
    `schnorr.rs` + `schnorr-ristretto.{h,cpp}` are
    non-malleable (no high-bit / trailing-bit variants) and
    deterministic-nonce derivation is safe under adversary-
    chosen `msg` (standard Schnorr-with-domain-separated-hash
    argument).

---

## 7. Deliverables expected from audit

* Formal written report with all findings + CVSS-style severity
  scoring.
* Recommended remediations per finding, prioritised by severity.
* **Re-audit hooks** for any consensus-binding follow-up change:
  SLA spot-check on (a) `canonical_tx_hash` preimage change,
  (b) Transfer AIR constraint change, (c) public-input byte-
  layout change, (d) Poseidon2 domain-tag change, (e) Schnorr or
  hybrid-KEM transcript change.
* Signed-off coverage statement for the v1 scope in §2, with
  §3 out-of-scope items listed as deferred.

---

## 8. Timeline hint

This scope (9 in-scope components, ~12 000 LoC of critical-path
C++/Rust plus the ~2 350 LoC Transfer AIR) is a **4-6 week**
engagement for a competent applied-crypto / zk audit team.

* Weeks 0–2: §2.1 (Transfer AIR), §2.3 (canonical_tx_hash),
  §2.4 (Schnorr), §2.5 (hybrid KEM) — the four soundness-
  dominating items.
* Weeks 2–4: §2.7 (compute phase), §2.8 (nullifier LRU), §2.6
  (compact filter), §2.9 (key derivation), §2.2 (Poseidon2
  integration).
* Weeks 4–6: writeup + finding-triage + re-audit of remediated
  items.

V1-phase alignment: V1-2b fee calibration lands before audit
start (so `required_fee` reflects final parameters). V1-3b BoC
parity lands in parallel; audit schedules the wallet → daemon
submit path as the last item once parity is verified. V1-4
testnet 60-day burn-in runs concurrently; any finding that
invalidates a testnet invariant is promoted to a hard mainnet-
blocker.

Pre-mainnet sign-off gate: no `High` or `Critical` findings
unremediated; `Medium` findings remediated or explicitly
accepted with documented rationale; signed audit-report PDF
at `doc/audits/uno-v1-<vendor>-<date>.pdf`.

---

*Document written against the `uno` branch at the v1 per-Tx
pivot (2026-04-21). Last-commit landmarks: `b2d601a09` (V1-2
doc update), `42fdb46a7` (V1-PRE A6-4a revert + BLOCK_TX_CAP
restore to 4), `0116de520` (V1-pin on aggregation).*
