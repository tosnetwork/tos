# UNO (wc=2) External Crypto Audit — Scope Document (P.7)

Companion to `doc/uno-workchain.md`. Self-contained scope brief for the
external crypto-audit engagement required by §13 P.7. Use this to size
vendor proposals and target reviewer attention.

---

## Executive summary

UNO (wc=2) is an Orchard-family shielded pool with a Plonky3 STARK proof
backend over the Goldilocks field. On top of the Orchard-family
specification, UNO introduces **three novel constructions** — removal of
the value commitment and binding signature in favour of an in-circuit
balance check, fresh per-spend spend-authorization keys with no long-term
`ak`, and an `ivk`-commitment hash-chain ownership proof with no
in-circuit curve operations (§0.2, §16 decisions #29–#31). These are not
backend swaps; they are new protocol-level constructions with no direct
prior deployment, and together with the first-application-of-Plonky3-to-a-shielded-pool
posture they extend the audit surface beyond what a conventional
Orchard-family review would cover. Vendors should budget **6–10 weeks**
for the combined scope described below.

---

## 1. In-scope components

For each component we list the TOS-side source paths, the §N.M claims of
`doc/uno-workchain.md` that fix the construction, and a brief note on
what prior work the auditor can leverage versus what is novel to UNO.

### 1.1 Plonky3 Transfer AIR

- **Source**:
  - `/home/tomi/tos/uno/plonky3-ffi/src/` — Rust AIR + prover + verifier,
    `#[AIR]` trace generation, FRI parameter wiring.
  - `/home/tomi/tos/tosctl/uno/src/` — reference prover CLI and witness
    construction.
  - `/home/tomi/tos/uno/crypto/plonky3-verifier.{h,cpp}` — C++ FFI
    wrapper.
- **Claims to review**: §4.2 claims 1–8; §2.1 pinned FRI parameters
  (`log_blowup=2, num_queries=128, proof_of_work_bits=16`, §16 decision
  #33); §2.2 Poseidon2-over-Goldilocks spec; §2.3 32-level
  note-commitment tree; §2.4 nullifier derivation; §3.3 in-circuit
  balance constraint; §4.3 public-input byte layout (§16 decision #35).
- **Prior art leverage**: the Orchard-family protocol shape
  (note-commitment tree, nullifier set, diversified stealth addresses)
  follows ZIP 224 and is well-studied. Poseidon2 round constants are the
  audited Polygon set (§16 decision #42). FRI soundness analysis follows
  published Plonky3 analyses.
- **Novel to UNO**: the *composition* of claims 1–8 in a single AIR,
  and specifically claims 3, 5+7+8 (ivk-commitment ownership; u64
  range + in-circuit balance conservation). No prior Plonky3 mainnet
  deployment has applied the toolkit to a payment-protocol circuit of
  this shape — all listed precedents (SP1, AggLayer, OP Succinct,
  Valida, Lurk/Sphinx) target zkVMs or cross-chain aggregation.

### 1.2 ivk-commitment hash-chain ownership binding

- **Source**:
  - AIR claim 3 implementation inside `/home/tomi/tos/uno/plonky3-ffi/src/`.
  - `/home/tomi/tos/uno/crypto/stealth-address.{h,cpp}` — off-circuit
    `ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)` and address
    derivation.
  - `/home/tomi/tos/tosctl/uno/src/` — wallet-side witness chain
    `uno_seed → nk → ivk → ivk_commitment`.
- **Claims to review**: §2.6 key hierarchy (hash-native derivation);
  §4.2 claim 3; §16 decision #30.
- **Prior art leverage**: the random-oracle assumption on Poseidon2 is
  standard; BLAKE2b-based seed derivation follows RFC 7693.
- **Novel to UNO**: the construction itself. Orchard proves ownership
  via in-circuit Pallas curve operations on the `ivk`↔`pk_d` relation.
  UNO replaces that with a pure hash chain and deliberately does not
  bind `pk_d` to `ivk` in-circuit (§2.6 "Consistency of `pk_d` and
  `ivk_commitment`"). The adversary-relevant claim — "only the holder
  of `uno_seed` can produce a valid spend proof" — has no prior
  deployment in this form and is the single most important standalone
  review target.

### 1.3 In-circuit balance constraint (value-commitment / binding-sig replacement)

- **Source**:
  - AIR claim 8 implementation inside `/home/tomi/tos/uno/plonky3-ffi/src/`.
  - `/home/tomi/tos/uno/core/transaction.{h,cpp}` — wire layout
    confirms no `cv` field on `SpendDescription`/`OutputDescription`
    and no `binding_sig` field on `Transfer`.
- **Claims to review**: §3.3; §4.2 claims 5, 7, 8; §16 decision #29.
- **Prior art leverage**: Goldilocks u64-native arithmetic is a
  well-studied property of Plonky3; the equality is a single
  field-element check.
- **Novel to UNO**: using this to *replace* the Pedersen `cv` +
  homomorphic Schnorr `binding_sig` construction. Auditors should
  independently confirm that the in-circuit equality is a strictly
  stronger value-conservation argument than the homomorphic trick it
  replaces — i.e. that no adversary degree of freedom has been silently
  introduced by dropping `cv`.

### 1.4 Fresh per-spend `rk` spend authorization (unlinkability argument)

- **Source**:
  - `/home/tomi/tos/uno/crypto/schnorr-ristretto.{h,cpp}` — Schnorr sign
    / verify over Ristretto255.
  - `/home/tomi/tos/uno/crypto/ristretto255.{h,cpp}` — group ops via
    libsodium.
  - `/home/tomi/tos/uno/core/transaction.{h,cpp}` — `SpendDescription`
    wire fields `rk`, `spend_auth_sig`.
  - `/home/tomi/tos/tosctl/uno/src/` — wallet-side fresh `rsk` sampling.
- **Claims to review**: §2.5; §4.2 "No claim for `rk_i` ↔ `ak`
  randomization"; §4.3 step 3; §16 decision #31.
- **Prior art leverage**: Schnorr-on-Ristretto255 signature soundness
  follows RFC 9496 + standard Schnorr security proofs.
- **Novel to UNO**: the *unlinkability argument* — that fresh per-spend
  `rk` with no in-circuit binding to a long-term `ak` gives the same
  unlinkability property Orchard derives from `rk = ak + α·G`
  randomization, while the audit path is redirected to `ovk`-decryption
  of `out_ciphertext` (§2.5 "Why no Orchard-style `rk = ak + α·G`
  randomization?"). Reviewers must confirm that an adversary with
  observation of many `rk` values across spends cannot cluster them by
  holder.

### 1.5 Transcript composition and public-input byte layout

- **Source**:
  - Rust encoder: `/home/tomi/tos/uno/plonky3-ffi/src/`.
  - C++ encoder: `/home/tomi/tos/uno/core/transaction.{h,cpp}` +
    `/home/tomi/tos/uno/crypto/plonky3-verifier.{h,cpp}`.
  - Canonical tx-hash path in `/home/tomi/tos/uno/core/transaction.cpp`.
  - Golden fixture: `/home/tomi/tos/uno/test/golden/public-inputs-v1.hex`.
  - Test binary: `/home/tomi/tos/uno/test/test-public-input-fixture.cpp`.
- **Claims to review**: §4.1 canonical `tx_hash`; §4.3 step 4 (element
  order, byte-level encoding, `mod p_Goldilocks` reduction, total
  length `64 + 64·S + 72·O`); §16 decision #35.
- **Prior art leverage**: the Plonky3 canonical `Goldilocks::from_canonical_u64`
  byte form is upstream-defined.
- **Novel to UNO**: the public-input tuple itself (`scheme_id,
  chain_id, expiry_block, fee, anchor, per-spend (nf, rk), per-output
  (cm, epk, filter_tag)`) and the exact encoding are consensus-binding
  to `scheme_id = 0x01`. Cross-encoder byte-identity is enforced as a
  CI gate, but auditors should independently derive the encoding from
  §4.3 and diff against the fixture.

### 1.6 Hybrid ECDH + ML-KEM-768 note encryption

- **Source**:
  - `/home/tomi/tos/uno/crypto/hybrid-kem.{h,cpp}` — split-KDF combiner.
  - `/home/tomi/tos/uno/crypto/mlkem768.{h,cpp}` — ML-KEM-768 wrapper
    over liboqs.
  - `/home/tomi/tos/uno/crypto/note-encryption.{h,cpp}` — ChaCha20-Poly1305
    AEAD with deterministic nonce.
  - `/home/tomi/tos/uno/crypto/ristretto255.{h,cpp}` — ECDH half.
- **Claims to review**: §2.7; §1.4 success criterion 8 (HNDL closure);
  §16 decision #25.
- **Prior art leverage**: ML-KEM-768 is NIST FIPS 203 (out of scope
  below); Ristretto255 ECDH is RFC 9496; the combiner follows eprint
  2025/1444 verbatim.
- **Novel to UNO**: the exact transcript binding (`compress(s_dh) ||
  s_pq || compress(epk) || BLAKE3(mlkem_ct)`), the deterministic
  nonce derivation `BLAKE3("uno-nonce-v1" || compress(epk))[0..12]`,
  and the `filter_tag` derivation from `k_aead` (§2.8). Auditors should
  confirm the transcript prevents ciphertext-substitution attacks and
  that deterministic-nonce use with fresh per-output `esk` does not
  create key/nonce collision classes.

### 1.7 Deterministic reject ordering + admission-vs-compute split

- **Source**:
  - `/home/tomi/tos/uno/core/compute-phase.{h,cpp}` — full §4.3 verify
    order (`verify_transfer`, `apply_transfer`).
  - `/home/tomi/tos/uno/rpc/handlers.{h,cpp}` + admission hooks — §4.3a
    non-consensus pre-filter.
  - `/home/tomi/tos/uno/core/parallel-verify.{h,cpp}` — parallel pool
    with deterministic output ordering.
  - `/home/tomi/tos/uno/test/test-mandatory-negatives.cpp` — exercises
    every reject path.
- **Claims to review**: §4.3 steps 1–5; §4.3a admission ordering
  (byte-shape envelope first, Plonky3 verify last / compute-only);
  §7.4 parallel-verify constraints; §12 P.5 cross-validator determinism;
  §16 decision #28.
- **Prior art leverage**: reject-order reasoning is standard protocol
  engineering.
- **Novel to UNO**: the explicit split between mempool admission (cheap
  checks) and compute-phase verify (full Plonky3) is load-bearing for
  DoS resistance; auditors should confirm no cheap check in §4.3a
  claims an invariant that the compute phase then assumes, and no
  expensive check slips into admission.

### 1.8 Verifier FFI boundary (Rust ↔ C++ ABI)

- **Source**:
  - Rust side: `/home/tomi/tos/uno/plonky3-ffi/src/`,
    `/home/tomi/tos/uno/plonky3-ffi/include/` (cbindgen-generated C
    header), `/home/tomi/tos/uno/plonky3-ffi/cbindgen.toml`.
  - C++ side: `/home/tomi/tos/uno/crypto/plonky3-verifier.{h,cpp}`.
  - Build glue: `/home/tomi/tos/uno/plonky3-ffi/build.rs` + corrosion-rs
    at `/home/tomi/tos/third-party/corrosion/`.
- **Claims to review**: ABI version check on every call; what invariants
  *cannot* be checked at the boundary (proof-internal soundness, FRI
  query opening correctness — these are by definition delegated to the
  verifier implementation and are why §1.1 of this scope is the single
  largest item); §13 P.3 "activation prerequisite" framing.
- **Prior art leverage**: corrosion-rs is upstream-maintained; cbindgen
  is widely deployed.
- **Novel to UNO**: the specific function surface and what it implies
  for the trusted-code boundary. Auditors should confirm that a
  misbehaving Rust verifier cannot silently return "accept" for a
  proof that does not in fact satisfy claims 1–8, and that ABI version
  mismatches are fail-closed.

---

## 2. Out-of-scope components

These ride independent audit trails and are deliberately excluded from
the UNO engagement; vendors should note them but not rebudget for them.

- **Plonky3 crates** (`/home/tomi/tos/third-party/plonky3-uno/`, pinned
  at upstream commit `6374a36ff50fc641821513852263cc61ca7a1278` per §16
  decision #43). Out of scope: upstream-maintained, production-validated
  via Polygon AggLayer pessimistic proofs and Succinct SP1. We do not
  modify the crates; we pin a commit and hand-cherry-pick upstream
  security fixes.
- **ML-KEM-768 reference implementation**. Out of scope: NIST FIPS 203
  is a published standard; we link liboqs and do not modify the
  primitive. The *use* of ML-KEM-768 inside the hybrid combiner is in
  scope (§1.6 above).
- **Ristretto255 reference implementation** (libsodium). Out of scope:
  RFC 9496 is a published standard; we link libsodium and do not modify
  the primitive. The *use* of Ristretto255 in Schnorr spend-auth (§1.4)
  and in the hybrid KEM ECDH half (§1.6) is in scope.
- **BLAKE3 reference implementation** (avatar SIMD, `/home/tomi/tos/third-party/avatar-crypto/`,
  §16 decision #41). Out of scope: upstream-audited; we select the
  impl and do not modify the primitive.
- **TOS cell-layer invariants**. Out of scope: `CellTraits` limits
  (§17), BoC wire format, TL-B schemas are TOS-ecosystem-wide and
  under separate review. UNO uses them unmodified.

---

## 3. Review priorities (ordered)

1. **Transfer AIR correctness (§4.2 claims 1–8)** — the single largest
   item; covers tree membership, note opening, ivk-commitment ownership,
   nullifier derivation, u64 range, well-formed output commitment,
   range again, value conservation.
2. **ivk-commitment hash-chain binding (§4.2 claim 3)** — the single
   novel construction best captured as a standalone review target; no
   direct prior deployment exists.
3. **In-circuit balance constraint as binding-sig replacement (§4.2
   claim 8)** — confirm value conservation is at least as strong as
   the Pedersen `cv` + homomorphic Schnorr construction it replaces.
4. **Fresh per-spend `rk` unlinkability argument (§2.5)** — confirm the
   fresh-key construction provides the same unlinkability property as
   Orchard's `rk = ak + α·G` randomization without the in-circuit
   curve op.
5. **Transcript composition + public-input byte-layout (§4.3 step 4)**
   — independently derive the serialized public-input vector from §4.3
   and diff against `uno/test/golden/public-inputs-v1.hex`.
6. **Hybrid-KEM combiner (§2.7, eprint 2025/1444)** — confirm split-KDF
   transcript bindings, deterministic-nonce safety, and that per-output
   fresh `esk` eliminates key/nonce collision classes.
7. **Deterministic reject ordering + admission-vs-compute split (§4.3 /
   §4.3a)** — confirm no cheap admission check claims an invariant the
   compute phase then assumes, and no expensive check slips into
   admission.
8. **Verifier FFI boundary (Rust ↔ C++)** — specifically the ABI
   version check, what cannot be checked at the boundary, and
   fail-closed behaviour on mismatch.

---

## 4. Existing self-audit artifacts the vendor can reuse

### 4.1 §12 test matrix (14 binaries, fully green)

Per §13 integration status block (2026-04-20):

| Binary                              | Passed / Failures / Skips |
|-------------------------------------|---------------------------|
| `test-uno-primitive-parity`         | 7 / 0 / 0                 |
| `test-uno-mandatory-negatives`      | 7 / 0 / 0                 |
| `test-uno-end-to-end`               | all / 0 / 0               |
| `test-uno-parallel-verify`          | 27 / 0 / 0                |
| `test-uno-restart-survival`         | 2 / 0 / 0                 |
| `test-uno-determinism`              | 3 / 0 / 0                 |
| `test-uno-state-transition-golden`  | 13 / 0 / 2 (opt-in)       |
| `test-uno-public-input-fixture`     | 2 / 0 / 0                 |
| `test-uno-codec-shapes`             | 5 / 0 / 0                 |
| `test-uno-transfer`                 | all / 0 / 1 (unrelated)   |
| `test-uno-filter`                   | all / 0 / 0               |
| `test-uno-genesis-loader`           | 6 / 0 / 0                 |
| `test-uno-bech32m-envelope`         | 12 / 0 / 0                |
| `test-uno-nullifier-warm-lru`       | 644 / 0 / 0               |

Sources live under `/home/tomi/tos/uno/test/`. The two remaining skips
in `test-uno-state-transition-golden` are behind the `UNO_RUN_PROVE_FIXTURES=1`
opt-in flag and exercise slow prove-heavy records (intentional, not a
gap).

### 4.2 Cross-implementation golden fixtures

- `/home/tomi/tos/uno/test/golden/public-inputs-v1.hex` — §4.3 step 4
  byte-level public-input encoding; A4 Rust encoder vs A5 C++ encoder
  byte-identical, re-checked on every CI run. 272 B + 608 B records.
- `/home/tomi/tos/uno/test/golden/state-transitions-v1.hex` — §12 P.3
  deterministic state-transition fixtures: commitment-tree root,
  nullifier-set root, anchor window post-state.

Any byte-level drift in either fixture is a breaking change to
`scheme_id = 0x01` and triggers a `scheme_id` bump (§16 decision #35).

### 4.3 Decision log §16

45 locked decisions with alternatives considered and rejected. The
decision log pairs with §15 (design choices record) to give a reviewer
the design-space context for each load-bearing choice. Decisions
#29–#31 and #33–#35 are the directly audit-relevant cluster for the
three novel constructions and the pinned FRI / byte-layout parameters;
decisions #42–#45 document engineering-cleanup substitutions executed
during agent-branch merge and are useful context for the test-only
workarounds listed in §5 below.

### 4.4 ivk-commitment hash chain as a standalone review target

The §2.6 + §4.2 claim 3 pair is the single novel construction best
captured as a standalone review target — self-contained, minimal
surface, no coupling to the rest of the AIR except through
`ivk_commitment` as a private witness that is opened against `cm` in
claim 2. Recommend reviewers start here and expand outward.

---

## 5. Known tech debt and test-only workarounds

Nothing here is a protocol bug — all workarounds bypass build-system
quirks and do not appear in any consensus path.

- **`/home/tomi/tos/uno/core/state.h`** — the concrete RPC facade is
  `UnoStateFacade`, not `UnoState`. Originally named `UnoState`,
  renamed to resolve an ODR collision with the pure-virtual abstract
  base defined in `/home/tomi/tos/uno/core/compute-phase.h` (which
  remains the unambiguous `UnoState`). Renamed during the agent-branch
  merge integration (task #14 in the integration batch; see §13
  integration-status block). No consensus consequence; pure code
  hygiene.
- **Weak-symbol stubs in test TUs** — `/home/tomi/tos/uno/test/test-primitive-parity.cpp`
  declares `__attribute__((weak))` Poseidon2 FFI entry points
  (`uno_poseidon2_goldilocks_permute_t8`, `..._t16`) so the test
  binary links in isolation without dragging in the full Rust
  toolchain. When the real crate is linked (full-build CI), these
  weak stubs are overridden by the strong symbols and are never
  called. Similar patterns appear in adjacent test TUs. No consensus
  consequence; pure test-build convenience.

---

## 6. Expected deliverables from the audit

1. **Final audit report** citing CVE-style findings with severity
   (critical / high / medium / low / informational), reproduction
   steps, and a recommended remediation for each.
2. **Clearance letter** — either:
   - "Cleared for mainnet" (no remaining critical or high findings);
     or
   - A **punch-list of required fixes** before mainnet, with each item
     tied back to a finding in the report and a severity justification
     for blocking mainnet activation.
3. Intermediate weekly check-ins during the audit window so findings
   can be triaged as they surface rather than dumped at report time.

---

## 7. Engagement logistics

- **Vendor selection lead time**: 3–6 months before audit start.
  Vendors qualified for the extended scope (first-application-of-Plonky3
  posture + novel constructions) are few and typically booked.
- **Audit window**: 6–10 weeks of review work once engagement starts.
- **Testnet in parallel**: a 60-day 5-validator testnet run executes
  in parallel with (not after) the audit window, so findings that
  motivate testnet-observable checks can be added to the testnet
  telemetry live.
- **v1 mainnet activation gate**: all of P.0–P.7 ✅ **plus** 60 days of
  testnet stability. The audit must clear (or punch-list resolve) and
  the testnet must complete the 60-day run without a stability-class
  incident before mainnet activation.

---

## 8. Cross-references

This document summarizes with back-references; the authoritative spec
is `doc/uno-workchain.md`. Key anchors:

- §0.2 — three novel constructions framing
- §2.1 — pinned FRI parameters
- §2.5 — fresh per-spend `rk` spend authorization
- §2.6 — hash-native key hierarchy + `ivk_commitment` definition
- §2.7 — hybrid ECDH + ML-KEM-768 note encryption
- §3.3 — in-circuit balance constraint
- §4.1 — `Transfer` wire body + canonical `tx_hash`
- §4.2 — the 8 claims attested by the Plonky3 proof
- §4.3 — deterministic verification order + public-input byte layout
- §4.3a — mempool admission non-consensus pre-filter
- §12 — test strategy (P.1–P.7 + mandatory negatives)
- §13 — phased roadmap (P.7 row pins the audit scope)
- §15 — design choices record
- §16 — numbered decisions log (45 locked decisions)
