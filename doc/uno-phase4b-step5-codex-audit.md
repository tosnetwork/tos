# Phase 4b-step3-step5 Codex Follow-Up Audit Report

**Audit type:** P.7-grade focused follow-up review of step 5 (spend-side cm sponge closure).
**Auditor:** Codex CLI (`codex-cli 0.122.0`), read-only sandbox.
**Scope:** 4 sub-commits `04ac2365c` → `923dc4d21` that closed Codex finding 1 from the prior audit.
**Date:** 2026-04-23.
**Prompt:** 10-item checklist A–J covering tag-block placement, padding-bit placement, carry-col soundness, bank-2 output binding scope, integration with step 3a Merkle walk, `S_IVK_COMMITMENT_CLAIM` vs `S_IVK_COMMITMENT_FE0` distinction, spend-side `d` decoder-check mirror, tosctl scaffold soundness, lookup formula delta, and legacy-helper delete-check.

Output saved verbatim below; follow-up commits triage the findings.

---

## Findings

### Finding 1 — `soundness-risk`: spend-side `d[11..32]` decoder check has no regression test

**Locations:** `uno/plonky3-ffi/src/transfer_air.rs:3052` (spend-side decoder check), `uno/plonky3-ffi/src/transfer_air.rs:4852` (existing output-side test `witness_decode_rejects_non_canonical_diversifier_padding` at lines 4864–4879, mutates only `output0.d[11..31]`).

**Description:** Step 5a-wire correctly added the spend-side decoder rejection of non-canonical `s.d[11..32] != 0` mirroring the output-side check added in commit `227277104` (step 4c). But the only regression test in-tree is still the output-side mirror — there is no test that flips bytes in `spends[0].d[11..32]` and asserts `MvpWitness::decode()` returns `Err(WitnessInvalid)`.

**Impact:** without a regression, a later refactor can silently weaken or delete the spend-side guard while the current test suite still passes. The guard is what prevents a forged 16-byte-absorbed spend diversifier preimage from getting an accepting proof.

**Fix:** add a spend-side mirror test next to the existing output-side one, derive `spend0.d`'s offset from the encoded layout, iterate all 21 bytes `11..32`, and assert `MvpWitness::decode()` returns `Err(WitnessInvalid)` for each mutation.

---

### Finding 2 — `maintainability`: stale `LookupAir::get_lookups()` doc comment + `Vec::with_capacity()` formula

**Locations:** `uno/plonky3-ffi/src/transfer_air.rs:946` (file header / block comment), `transfer_air.rs:1013` (live receive-registration block), `uno/plonky3-ffi/src/prover.rs:359` (send formula), `transfer_air.rs:4917` (shape-test assertion).

**Description:** The step-5b lookup math is implemented correctly end-to-end (live AIR registrations at lines 1097–1124 + prover send formula at `prover.rs:445` + shape test at `transfer_air.rs:4917` all use `4·(n_s+n_o) + 56·n_o + 88·n_s`). But the reader-side bookkeeping in `LookupAir::get_lookups()` — the block-doc comment and the `Vec::with_capacity(...)` preallocation — still says `36·n_s + 60·n_o`, the pre-step-5b count.

**Impact:** not a soundness bug (live code is right) but an internal-contradiction reachable by an auditor eyeballing the same file for formula parity — the comment claims one number, the test and send formula check a different number.

**Fix:** update the `LookupAir` block-doc comment and `Vec::with_capacity(...)` call to `4·(n_s+n_o) + 56·n_o + 88·n_s` so all four sites (comment, preallocation, prover send formula, shape test) agree.

---

### Finding 3 — `minor`: legacy `poseidon2_cm` wrappers not fully deleted

**Locations:** `uno/plonky3-ffi/src/transfer_air.rs:4496` (`poseidon2_cm()` wrappers), `transfer_air.rs:3877` (`poseidon2_cm_fe` — still live from output-side `O_CM_CLAIM` legacy path in trace-gen), `tosctl/uno/src/send.rs:1151`.

**Description:** Step 5d-close claimed to delete now-unused `poseidon2_cm` / `poseidon2_cm_fe` helpers, but grep shows both `poseidon2_cm()` wrappers are still present (no live callers — pure dead code) and `poseidon2_cm_fe()` is still live from the output-side legacy `O_CM_CLAIM` single-fe trace-population path. The true closure state is "spend-side callers removed, output-side proxy helper still live", not "all old cm helpers gone".

**Impact:** pure cleanup debt; no soundness effect. Makes the step 5 closure harder to reason about ("is the proxy path fully gone?") and may mislead a later auditor.

**Fix:** delete the dead `poseidon2_cm()` wrappers now (no callers); keep `poseidon2_cm_fe()` until `O_CM_CLAIM` is retired in a separate cleanup commit; rename/comment `poseidon2_cm_fe` as "output-side legacy, retire with O_CM_CLAIM" so the remaining dependency is explicit.

---

## Clean categories (no finding above minor)

**A / B — Tag-block + padding placement:** spend-side bank-1 trace population puts `"uno-cm-v1"` tag at capacity slots `state[8..16]` (NOT rate slots) at `transfer_air.rs:3503`; AIR pins `shared_cm.inputs[8+k] == uno_cm_v1_tag_block()[k]` on spend rows at `transfer_air.rs:1492`. Bank-2 trace absorbs `fes[8..14]` into slots `0..6`, adds ONE at slot 7, capacity unchanged at `transfer_air.rs:3523`; AIR mirrors at `transfer_air.rs:1562`. Byte-for-byte identical to the output-side step-1.2f block at `transfer_air.rs:1813`.

**C / D / E — Carry-col soundness + end-to-end chain:** bank-1 row-gate pins `shared_cm_out[0..8]` and `[8..16]` to `S_CM_CARRY_{RATE,CAP}` at `transfer_air.rs:1501`. Bank-2 reads the same cols at `transfer_air.rs:1575`. Transition loop enforces every spend proxy col including the new carry cols as constant across rows at `transfer_air.rs:2412`. No alternate writer can change them between rows `0..3` and `24..27` — they live only in the spend proxy block and trace-gen fills them once per spend at `transfer_air.rs:3842`. Bank-2 output `(S_LEAF, S_LEAF_FE1..3)` binding is row-gated only by `GS_ROW_SEL[24+i]` at `transfer_air.rs:1604`. Other uses of those cols are reads only: row-0 Merkle seeding at `transfer_air.rs:1249` and nf bank-1 absorb at `transfer_air.rs:2007`. End-to-end chain verified: row-24 sponge output pins `S_LEAF_FE`, proxy-invariant carries it to row 0, row 0 seeds `S_CURRENT_FE`, 32-level walk binds last-row digest to `PI[PI_ANCHOR+k]` at `transfer_air.rs:2397`.

**F — `S_IVK_COMMITMENT_CLAIM` vs `S_IVK_COMMITMENT_FE0` distinction:** `S_IVK_COMMITMENT_CLAIM` remains the narrow claim-3 output, used only by the width-8 ivk-commitment block at `transfer_air.rs:1923`. New spend-sponge cols are a separate block starting at `transfer_air.rs:498`, decomposed independently at `transfer_air.rs:2253`. Spend sponge absorbs `S_IVK_COMMITMENT_FE0..3` (NOT the claim col) at `transfer_air.rs:1475` + `1566`. No accidental equality ties the two together.

**H / I — tosctl scaffold + lookup formula delta:** `TransferWitness::build()` derives `shared_leaf_bytes` from `poseidon2_cm_full_sponge_bytes(...)` at `send.rs:917`, threads canonical proxy-shaped `[u8;32]` spend fields at `send.rs:896`. Wallet proof test exercises the full pipeline at `send.rs:1336`. The known wallet gap (OwnedNote lacks per-note pk_d / rseed) is a scaffold limitation; step 5 does not create a new AIR hole there — it IMPROVES the scaffold by making the synthetic spend leaf equal the same sponge the AIR now ratifies. Lookup delta `+56·n_s` matches exactly: spend-side receive loop is `8 + 16 + 16 + 16 = 56` per spend at `transfer_air.rs:1097`; prover-side send matches at `prover.rs:445`; shape test at `transfer_air.rs:4917`. (The stale comment/capacity issue is the finding 2 above, not a count mismatch.)

---

## Limits of this review

- Source review only. Codex did not execute `cargo test` or regenerate proofs in its read-only sandbox.
- Not a substitute for an external paid-vendor engagement per `doc/uno-audit-scope.md` Tier 2.

---

## Triage disposition

All three findings CLOSED by the follow-up commit
`M-P2 Phase 4b-step3-step5e-audit-response`:

- **Finding 1** ✅: added spend-side regression test
  `witness_decode_rejects_non_canonical_spend_diversifier_padding` in
  `uno/plonky3-ffi/src/transfer_air.rs`, mirroring the output-side
  test; iterates all 21 bytes `d[11..32]` and asserts
  `MvpWitness::decode()` returns `Err(WitnessInvalid)` for each flip.
- **Finding 2** ✅: `LookupAir::get_lookups()` block-doc comment +
  `Vec::with_capacity(...)` now both use the post-step-5b formula
  `4·(n_s+n_o) + 56·n_o + 88·n_s`, matching the prover send and the
  shape-test assertion.
- **Finding 3** ✅: deleted the dead `poseidon2_cm()` u64-returning
  wrapper. Kept `poseidon2_cm_fe()` (still live from the output-side
  `O_CM_CLAIM` legacy path in trace-gen) with an explicit
  "output-side legacy only — retire with `O_CM_CLAIM`" doc block.
