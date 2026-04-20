# Uno Workchain — Audit Vendor Onboarding

This document is the entry point for an external crypto-audit vendor engaging
with the Uno Workchain (wc=2 PQ-native privacy L1) per §13 P.7 of
`doc/uno-workchain.md`. It is not a contract; it is a technical brief so a
vendor's partner meeting can short-circuit repo exploration.

**Audit target identifier**: Uno Workchain v1, `scheme_id = 0x01` (first
production crypto suite; see §2.0 of the design doc).

---

## Repository map

Paths are relative to the TOS monorepo root. The Uno Workchain is a
TOS shardchain adapter; everything Uno-specific lives under `uno/`.

```
uno/
  CMakeLists.txt              — library build glue (static lib `uno_workchain`)
  core/                       — state, compute-phase, tx codec, dispatch
  crypto/                     — Goldilocks, Poseidon2, Ristretto255, Schnorr,
                                ML-KEM-768, hybrid-KEM, stealth-address,
                                note-encryption, Plonky3 verifier bridge
  rpc/                        — `uno_*` JSON-RPC handlers + filter-service
  plonky3-ffi/                — Rust crate: Plonky3 Transfer AIR verifier
                                (+ reference prover) exposed over C ABI
  test/                       — in-tree test targets (see §12 of design doc)
    test-primitive-parity.cpp         — §12 P.1 primitive KAT
    test-state-transition-golden.cpp  — §12 P.3 golden fixtures
    test-restart-survival.cpp         — §12 P.4 restart/replay
    test-mandatory-negatives.cpp      — §12 mandatory negatives list
    test-public-input-fixture.cpp     — consensus-binding decision #5 fixture
    test-determinism.cpp              — §12 P.5 scaffold
    test-transfer.cpp                 — §4.1 Transfer codec round-trip
    test-filter.cpp                   — §2.8 compact-filter service
    golden/                           — pinned hex fixtures (cross-impl)
    reference/hybrid_kem_kat.py       — BLAKE3 Python reference for §2.7 KAT
    audit/README.md                   — (this file)

doc/uno-workchain.md          — design spec, all section references (§x.y)
                                cited in audit findings should point here.
```

All 45 design decisions in §16 of the design doc are locked on the `uno`
branch. Decision-change proposals produced during audit should be filed as
issues citing `decision #N`.

---

## Audit scope (IN)

The following is **in scope** for the external audit. Line-level code
review and mathematical review are both expected; test coverage is a
secondary concern (the vendor may suggest test gaps; producing tests is
the in-house team's job).

| Scope item | Code | Doc anchor |
|---|---|---|
| Transfer AIR claims 1–8 (once P.2 lands) | `uno/plonky3-ffi/src/transfer_air.rs` | §4.2 |
| In-circuit balance constraint | ` ` (AIR claim 8) | §3.3 |
| Nullifier derivation | `Poseidon2("uno-nf-v1", nk, cm, pos)` | §2.2, §3.2 |
| Note-commitment preimage | `compute_note_commitment` | §3.2, decision #1 |
| Key derivation (seed → fvk, ivk, ovk, ak, nk, pk_mlkem, sk_mlkem) | `uno/crypto/stealth-address.{h,cpp}` | §2.6 |
| Diversified address derivation (d → g_d, pk_d) | `uno/crypto/stealth-address.{h,cpp}` | §2.6 |
| Transcript composition / domain-tag discipline | all `Poseidon2(...)` / BLAKE3 call sites | §2.0 |
| Hybrid-KEM combiner | `uno/crypto/hybrid-kem.{h,cpp}` | §2.7, eprint 2025/1444 |
| Plonky3 verifier FFI boundary | `uno/crypto/plonky3-verifier.{h,cpp}` + C ABI in `uno/plonky3-ffi/include/uno_plonky3_ffi.h` | §4.3, §7.5 |
| Deterministic-reject ordering | `uno/core/compute-phase.cpp :: run_compute_phase` | §4.3 |
| Anchor window and nullifier-set semantics | `uno/core/anchor-window.{h,cpp}`, `uno/core/nullifier-set.{h,cpp}` | §5.3, §5.4 |
| Cell-native state serialization (determinism) | `uno/core/cell-state.{h,cpp}` | §5.1, §5.7 |
| Public-input byte encoding | `build_plonky3_public_inputs` + `plonky3-ffi` parity | decision #5, §4.3 step 4 |
| Fee model and burn accounting | `uno/core/compute-phase.cpp :: apply_transfer` | §4.3, decision #19 |
| Dispatcher integration (wc=2 marker cell) | `crypto/block/uno-workchain-dispatch.{h,cpp}` | §8 |
| Genesis / zerostate construction | `uno/core/genesis.{h,cpp}` | §10.3, decision #17 |

A vendor who finishes this scope early is welcome to peek at the RPC
surface (`uno/rpc/*.cpp`) for observation/log leaks — but the RPC layer
is a consumer of the consensus path, not consensus-binding itself, and
should not consume substantial audit budget.

---

## Audit scope (OUT — consume as given)

The following dependencies are consumed as-given. They are already
independently audited or widely deployed; re-auditing them is not the
best use of this engagement.

| Dep | Source | Why out of scope |
|---|---|---|
| Plonky3 Rust crates (Goldilocks, Poseidon2, FRI, STARK verifier) | `third-party/plonky3-uno/` (pinned `6374a36f`) | Upstream Plonky3 audit covered in separate engagement; any finding here should be filed upstream, not against Uno. |
| libsodium (Ristretto255, ChaCha20-Poly1305, BLAKE2b) | system package | Audited annually; NSA / NIST / open source. |
| liboqs (ML-KEM-768) | system package | Open Quantum Safe; FIPS 203 reference. |
| BLAKE3 (C reference or `at_blake3`) | `third-party/blake3/` or vendored | Well-studied primitive; upstream audit exists. |
| TOS cell / vm primitives (`crypto/vm/`, `vm/cells/`) | TOS core | Chain-wide infrastructure; separate scope. |

Clarification: "out of scope" ≠ "beyond interest." Findings that a given
upstream is mis-configured or mis-used at the Uno-specific call site ARE
in scope (e.g., a mis-formed `libsodium_init()` call, wrong nonce reuse,
missing `oqs_init` handshake). A bug in the upstream primitive itself is
not.

---

## Expected artifacts before audit start

Per §13 P.7, the audit window should not start until the following are
merged on the `uno` branch and the 5-validator testnet has been stable
for 60 days:

1. **Full P.2 Transfer AIR** — claims 1 through 8, matching §4.2, exercised
   by the §4.3 verifier path end-to-end. Prover CLI in `tosctl`.
2. **Golden fixtures populated** — `uno/test/golden/state-transitions-v1.hex`
   and `uno/test/golden/public-inputs-v1.hex` both with real pre-/post-
   state blobs and real proof bytes; no empty fields.
3. **Parallel-verify determinism** — P.3 test harness (see §12 P.5) proves
   byte-identical state roots under N-core parallel verify vs. serial.
   Proof of determinism must be reproducible by the audit vendor on
   commodity hardware.
4. **60-day testnet run log** — 5 validators, sustained ≥ 15 TPS, zero
   state-root divergences, full chain reorg log available.
5. **Decision log frozen** — no changes to `doc/uno-workchain.md` §16
   during the audit window (spec changes invalidate findings). Frozen at
   the commit that kicks off the engagement.
6. **P.1–P.4 + mandatory-negatives tests all green** — these files are
   already landed (see "Repository map" above); the vendor verifies
   `cmake --build build-uno-check --target test-uno-*` all pass before
   beginning code review.

Items 1–3 are the long-pole blockers; items 4–6 are procedural.

---

## Expected timeline

**6–10 weeks** per §13 P.7 rationale. The wider-than-typical window
reflects:

- **First application of Plonky3 to a shielded-pool construction.** No
  prior audit has exercised a Plonky3 AIR at this scale; the vendor
  cannot rely on prior Plonky3-specific findings.
- **Eight claims in the Transfer AIR.** §4.2 enumerates 8 distinct
  in-circuit assertions; each claim warrants 3–5 days of focused
  mathematical review + code walkthrough.
- **Hybrid-KEM combiner (eprint 2025/1444).** Newer construction;
  vendor review of the transcript binding vs. the paper is required.
- **Rust↔C++ FFI boundary.** Memory-safety review of the `extern "C"`
  surface, including proof/public-input ownership conventions, panic
  safety across the FFI line, and deterministic-reject ordering when
  the verifier returns `false`.
- **TOS cell schema for state persistence.** Unusual for a zk audit to
  include a chain-specific storage layer; the cell serialiser is
  consensus-binding (§5.1) so it must be covered.

Suggested phasing inside the 6–10 week window:
- Weeks 1–2: onboarding, spec walk-through, threat modelling.
- Weeks 3–6: Transfer AIR claim-by-claim review + transcript composition.
- Weeks 7–8: FFI boundary, determinism, state schema.
- Weeks 9–10: report authoring, re-verification of fixes delivered within
  window.

---

## Vendor shortlist

These firms have a documented track record on either Plonky3-family proof
systems OR shielded-pool constructions; the ideal vendor has both. Contact
hints are starting points, not endorsements. The in-house team makes the
booking decision.

| Firm | Why them | Contact hint |
|---|---|---|
| **Least Authority** | Original Zcash Sapling / Orchard audits; deep Halo2 + Plonkish experience. Strong on shielded-pool threat modelling. Has published on hybrid PQ + classical schemes. | `https://leastauthority.com/contact` — request "zk-SNARK / Plonky3 engagement scoping." |
| **Trail of Bits** | Broadest in-scope footprint (AIR, FFI, state schema). Extensive Rust + zk FFI audit history. Has Plonky3-adjacent practitioners on staff. | `https://www.trailofbits.com/contact` — ask for the "Cryptography + Privacy" practice. |
| **NCC Group** | Well-known for consensus-layer audits and cell-tree / state-machine work. Less shielded-pool specific, but very strong on determinism / parallel-verifier / restart-survival properties. | `https://www.nccgroup.com/us/contact-us` — reference "blockchain + applied cryptography" group. |
| **0xPARC** | The deepest bench on Plonky3 specifically — several staff have upstream Plonky3 commits. Smaller organisation; best for the AIR-only slice if paired with one of the three above on the rest. | `https://0xparc.org/` — reach out via GitHub or their contact form; engagements are typically grant-structured. |

All four are capable of meeting the 6–10 week window if booked with 3–6
months of lead time (per §13 P.7 rationale: "audit vendor selection needs
3–6 month lead time"). Peak demand windows (Devcon-adjacent, post-major-
zkVM-releases) compress availability.

---

## In-house contacts

For technical questions during scoping:
- **Design spec questions** — file an issue referencing `doc/uno-workchain.md
  §x.y`.
- **Test / fixture questions** — file an issue referencing
  `uno/test/<file>`.
- **Crypto primitive parity / FFI questions** — `uno/plonky3-ffi/` for the
  Rust side; `uno/crypto/` for the C++ side. The A3 / A4 / I-B / I-C commit
  trails explain decision chains.

The 45 design decisions in §16 are the canonical record of "why it is
this way." Any finding that disagrees with a recorded decision should
cite the decision number; the in-house team will respond with either (a)
the decision's underlying rationale, or (b) a decision amendment if the
finding is material.

---

*Document owner: Uno Workchain integration team.
Last updated with §12 test matrix + audit prep (P.7 scaffold).*
