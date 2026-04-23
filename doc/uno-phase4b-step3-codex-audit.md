# Phase 4b-step3 Codex Pre-Audit Report

**Audit type:** P.7-grade pre-audit code review.
**Auditor:** Codex CLI (`codex-cli 0.122.0`), read-only sandbox.
**Scope:** ~28 commits from `42c6550ef` (Phase 4b-step3-step0) through `f547bbe23` (HEAD on `uno`).
**Date:** 2026-04-23.
**Prompt:** 9-item checklist A–I covering underconstrained cols, tag-block parity, padding placement, row-gating one-hotness, conditional-swap soundness, spec-divergence, PI copy-constraint scope, range-check coverage, and public-helper visibility.

Output saved verbatim below; subsequent commits in this repo triage the findings.

---

## Findings

### Finding 1 — `soundness-risk`: spend-side cm is still the legacy u64-proxy single-perm, not the 15-fe iterated sponge

**Locations:** `uno/plonky3-ffi/src/transfer_air.rs:1337`, `transfer_air.rs:2234`, `transfer_air.rs:3225`, `transfer_air.rs:3963`, `transfer_air.rs:4077`; `tosctl/uno/src/send.rs:783`, `send.rs:917`; `doc/uno-workchain.md:828`.

**Description:** Spend-side `cm_i = leaf_i` is still the legacy low-limb/proxy relation, not the real 15-fe tagged sponge claimed by the docs. The AIR spend row binds
```
shared_cm.inputs = (TAG_CM, d_u64, pk_d_u64, ivkcm_u64, value, rcm_u64, 0…)
```
and only checks `shared_cm_out[0] == S_LEAF`. `SpendWitness.d` is still `[u8; 8]`, the spend proxy block is still built from `first_u64_proxy(...)`, and `witness_claim2_leaf_consistent()` still uses `poseidon2_cm()` / `poseidon2_cm_fe()` (the old single-permutation proxy helper), not `poseidon2_cm_full_sponge()`. On the producer side, `TransferWitness::build()` still synthesizes spend witness material from `anchor`-derived proxies and explicitly ignores the selected notes' real `leaf / path / pos` material, then writes the same shared synthetic leaf/path into every spend.

**Impact:** Phase 4b-step3 closes output-side `cm` PI binding, `anchor`, and `nf` over witness `leaf`, but it does **not** close the spend-side note-opening claim the docs now say is closed. The proof still only gives a 64-bit-style spend binding on `leaf[0]`, so the advertised
```
cm[4]_i = Poseidon2-hash_tagged("uno-cm-v1", real …)
```
statement is FALSE on the spend path.

**Context / mitigating factors:** the protocol-layer consensus bindings for a spend are (a) Merkle inclusion of `leaf` under `anchor` (now real 4-fe, step 3a) and (b) nullifier derivation from `(nk, leaf, pos)` (now real 9-fe sponge, step 2b-AIR-v2). Both were closed by Phase 4b-step3. The spend-side claim 2 (leaf = hash(real d, pk_d, …)) is a well-formedness claim rather than a consensus binding — the spender could claim any leaf already in the anchor tree regardless of how it was constructed. BUT the current `doc/uno-workchain.md §2 R9` and `§13 P.2 row` language says "every cryptographic claim now proves over real 32-byte material", which mis-states the actual scope closed. Readers will interpret the claim to include spend-side claim 2.

**Concrete fix (audit-vendor recommendation):** thread real per-spend `(leaf, d, pk_d, ivk_commitment, value, rcm, pos, merkle_path)` from `OwnedNote` into `TransferWitness::build()`; widen `SpendWitness.d` to the real diversifier form; add spend-side bank-1 / bank-2 `cm` sponge rows analogous to the output side; bind `S_LEAF / S_LEAF_FE1..3` to the real sponge output. Then switch `witness_claim2_leaf_consistent()` to the same real sponge helper and add a negative test that flips `leaf[8..32]` while keeping limb 0 fixed.

**Interim mitigation:** update `doc/uno-workchain.md` §2 R9 + §13 P.2 + `doc/uno-p2-phase4b-step3-plan.md` keystone milestone to honestly disclose that spend-side claim 2 remains on the proxy path. Phase 4b-step3 was scoped to the claims whose leakage would be verifier-split-visible (output cm, anchor, nf); the spend-side leaf opening is a well-formedness claim without a direct verifier split.

---

### Finding 2 — `correctness-risk`: output-side diversifier canonical padding never enforced

**Locations:** `uno/plonky3-ffi/src/transfer_air.rs:2285`, `transfer_air.rs:2730`, `transfer_air.rs:3700`, `transfer_air.rs:3784`; `uno/core/transaction.cpp:307`; `tosctl/uno/src/send.rs:944`.

**Description:** Honest `tosctl` zero-pads `d` (`send.rs:944-952`), and C++ `compute_note_commitment()` takes an 11-byte diversifier and zero-pads to 16 bytes before hashing (`transaction.cpp:307-315`). But the Rust witness decoder accepts arbitrary `OutputWitness.d: [u8; 32]`, and `pack_diversifier_as_2fe()` absorbs `d[0..16]` directly. That means `d[11..15]` can change the proven `cm`, and `d[16..31]` are unconstrained garbage.

**Impact:** a direct FFI caller can produce a proof for a `cm` that is consistent with the Rust AIR / helper but not with any valid 11-byte diversifier under the C++ / spec preimage domain. This is not a verifier split (both sides would accept the proof), but it is a spec-domain mismatch on malformed witnesses — a crafted witness could AIR-verify but reference an "impossible" diversifier.

**Concrete fix:** reject non-zero `o.d[11..32]` in `MvpWitness::decode()` or `pre_check_transfer_witness()`. Alternatively, change `OutputWitness.d` to `[u8; 11]` and perform the zero-padding inside the helper / trace-gen only. Add a regression that mutates `d[11]` and expects rejection.

---

## Clean categories (no finding above minor)

**A / D / E:** no underconstrained carry / current / sibling column, no row-selector one-hotness hole. `GS_ROW_SEL` is fixed by first-row boot + shift + booleanity (`transfer_air.rs:1098-1125`), `S_CURRENT_FE[0..3]` is seeded from `leaf` and then advanced/latches explicitly (`transfer_air.rs:1144-1155`, `transfer_air.rs:2073-2086`), and the conditional swap uses path bits that are boolean on row 0 and then held constant by the proxy transition loop (`transfer_air.rs:1159-1166`, `transfer_air.rs:2109-2114`).

**B / C / F / H / I:** no live `TAG_NF` fallback path after `9add1ad0f` (only dead/comment references remain). `uno_nf_v1_tag_block()` delegates directly to `pack_tag_block()` (`transfer_air.rs:3630-3654`), so there is no duplicated nf tag constant to drift. Padding placement is internally consistent for both sponges: `cm` pads at slot 7 in trace/AIR/helper (`transfer_air.rs:1570-1637`, `transfer_air.rs:3214-3221`, `transfer_air.rs:3809-3815`) and `nf` pads at slot 1 (`transfer_air.rs:1811-1829`, `transfer_air.rs:3118-3124`, `transfer_air.rs:4038-4040`). The LogUp receive count matches the implemented decompositions (`transfer_air.rs:903-1022`, `prover.rs:352-444`). The public `poseidon2_cm_full_sponge_bytes` / `poseidon2_nf_full_wide_bytes` helpers match the AIR logic; no helper/AIR byte mismatch.

**G:** no PI slot is still bound via the retired witness-byte copy columns for `cm` / `anchor` / `nf`. `cm` is first-row-bound from `O_CM_SPONGE_OUT` (`transfer_air.rs:1219-1221`, `transfer_air.rs:1276-1285`), `nf` is row-gated from the bank-2 sponge output (`transfer_air.rs:1846-1851`), and `anchor` is last-row-bound from `S_CURRENT_FE` (`transfer_air.rs:2094-2100`). The only caveat is that each `PI[anchor+k]` slot is intentionally bound once per spend on the last row; that strengthens equality across spends rather than reopening a witness-copy hole.

---

## Limits of this review

- Source review only. Codex did not run the Rust test suite in its read-only sandbox.
- Codex did not exercise the C++ validator end-to-end — that's the paid-vendor scope.
- This is a pre-audit dry run, not a substitute for an external crypto vendor's multi-week engagement per `doc/uno-audit-scope.md` Tier 2.

---

## Triage disposition (filled in by downstream commits)

- **Finding 1**: doc scope-honesty update to be landed immediately; spend-side sponge implementation tracked as a follow-up task.
- **Finding 2**: decoder-level rejection of non-zero `d[11..32]` + regression test to be landed immediately.

See follow-up commits for `codex-finding-1-doc-honest-scope` and `codex-finding-2-diversifier-padding-reject`.
