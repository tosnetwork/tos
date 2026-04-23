# Phase 4b-step3-step5 — Codex Handoff Prompt

**Purpose.** Self-contained brief for handing the spend-side `cm`
iterated-sponge closure (step 5 of M-P2 Phase 4b-step3, closing Codex
audit finding 1) from Claude Code to Codex CLI. Designed to be pasted
into `codex exec` unmodified.

**Context.** Claude Code delegated step 5 to a background agent. If that
agent is blocked, rate-limited, or token-exhausted mid-way, this
document lets Codex take over without any session state from the
original handoff. It includes explicit references to 8 prior commits
that serve as implementation templates, the 4-sub-commit staging plan,
per-sub-commit test thresholds, and the critical gotchas that caused
`step 2b-AIR-v1` (commit `b92a6bdbb`) to initially diverge from C++ and
require the v2 fix at `9add1ad0f`.

**How to use.**

```bash
codex exec \
  --sandbox workspace-write \
  --output-last-message /tmp/codex-step5.txt \
  "$(sed -n '/^## Prompt (copy-paste below this line)/,$p' doc/uno-phase4b-step5-codex-handoff.md | tail -n +2)"
```

Or: open `codex` interactively, `cd /home/tomi/tos`, and paste the
§ "Prompt (copy-paste below this line)" content below.

---

## Prompt (copy-paste below this line)

You are a cryptography engineer continuing M-P2 Phase 4b-step3 on the Uno
STARK AIR. You are taking over from a Claude Code session mid-way through
implementing step 5 (spend-side cm iterated-sponge closure). Your job is
to land 4 sub-commits that close Codex audit finding 1.

### Orientation

Working tree: `/home/tomi/tos` (Rust workspace).
Branch: `uno` at HEAD `227277104` (may have drifted — run
`git log --oneline origin/uno..uno` first; also check
`git status` for uncommitted work the previous agent may have left;
also check `git branch --list 'worktree-agent-*'` for any in-flight
agent branch).

Full context for the task: `doc/uno-phase4b-step3-codex-audit.md`
Plan status: `doc/uno-p2-phase4b-step3-plan.md` (all of steps 0–4 ✅;
step 5 is what you're implementing).
Spec document: `doc/uno-workchain.md` §2 R9 + §3.2 + §4.2.

### Mission

Close Codex audit finding 1: the spend-side AIR claim

```
leaf_i = Poseidon2-hash_tagged("uno-cm-v1",
                               real d_i, pk_d_i, ivk_commitment_i,
                               value_i, rcm_i)
```

still runs on the legacy u64-proxy single-permutation path (only
output-side cm was migrated in Phase 4b-step3). Mirror step 1.2 (which
closed output-side cm) on the spend side.

### Reference commits (read each — they are the template)

- `50045938f` — step 1.0 (cross-crate sponge byte-parity tests)
- `81d30c246` — step 1.2a (trace-gen fills sponge bank rows)
- `e9a6b8622` — step 1.2b (bank-1 tag-block capacity pin)
- `5bc0a2ba5` — step 1.2c (bank-1 rate slots pinned to fe-limb cols)
- `b187f99fa` — step 1.2d (capacity carry bank-1 → bank-2)
- `9397b2da7` — step 1.2e (bank-2 output → `O_CM_SPONGE_OUT`)
- `5cf965204` — step 1.2f (bank-2 rate absorb, step 1.2 complete)
- `172e079e9` — step 1.3-fields (u16 decomp + LogUp range-check)
- `9add1ad0f` — step 2b-AIR-v2 (nf 9-fe iterated sponge, spec fix —
  CRITICAL to mirror correctly: tag at capacity slots `[8..16]`, NOT
  `[0..8]`; padding bit at slot 7 for 15-fe input, slot 1 for 9-fe)
- `690fa6492` — step 2b-decomp (spend-side nk+leaf fe-limb + u16)
- `227277104` — step 4c (Codex finding 2 fix — diversifier padding
  decoder check; pattern you mirror for spend-side `d[11..32]`)

### Current spend-side state (what you're changing)

In `uno/plonky3-ffi/src/transfer_air.rs`:

- `SpendWitness.d: [u8; 8]` — still 8-byte proxy (needs widening to
  `[u8; 32]`)
- NO `SpendWitness.ivk_commitment: [u8; 32]` field yet — add it
- Spend-row AIR on rows `0..(n_s-1)` uses single-perm:

  ```
  shared_cm.inputs = (TAG_CM, d_u64, pk_d_u64, ivkcm_u64, value,
                       rcm_u64, 0·10)
  shared_cm_out[0] == S_LEAF    // single-fe claim-2 binding
  ```

- Step 2b-decomp already landed: `S_NK_FE1..3`, `S_LEAF_FE1..3`, u16
  decomp.
- Step 3a already landed: `S_CURRENT_FE[0..3]` seeded from `S_LEAF` /
  `S_LEAF_FE1..3`, 4-fe Merkle walk binding `PI[PI_ANCHOR+0..4]`.

Shared wide Poseidon2-16 row assignment (see `generate_trace`):

```
  rows 0..(n_s-1)     : spend cm single-perm    (YOU replace → bank-1)
  rows 4..(4+n_o-1)   : output cm single-perm   (legacy, leave alone)
  rows 8..(8+n_o-1)   : output cm sponge bank-1
  rows 12..(12+n_o-1) : output cm sponge bank-2
  rows 16..(16+n_s-1) : nf sponge bank-1
  rows 20..(20+n_s-1) : nf sponge bank-2
  rows 24..31         : free (YOU use 24..(24+n_s-1) for spend cm bank-2)
```

### Four sub-commits

#### Sub-commit 1 — step 5a-wire (~80 LOC)

1. `SpendWitness.d: [u8; 8] → [u8; 32]` (mirror step 2a-leaf
   `9a5c93861`).
2. Add `SpendWitness.ivk_commitment: [u8; 32]` new field.
3. Wire format: old `PER_SPEND = 1240`. New `PER_SPEND = 1240 + 24`
   (`d` widen) `+ 32` (`ivk_commitment`) `= 1296`. Update
   `encode` / `decode` + the `sizes_at_4_4_worst_case_recorded` test.
   Total wire at 4/4: `10 + 1296·4 + 202·4 + 45 = 5 919 B`.
4. Decoder check: reject `s.d[11..32] != 0` — mirror commit
   `227277104`.
5. `tosctl/uno/src/send.rs`: thread real per-note `(d, ivk_commitment)`
   from `OwnedNote`. If `OwnedNote` lacks these fields, check
   `tosctl/uno/src/scan.rs::OwnedNote` — you may need to add them.
   Wallet should already have them from address derivation or from
   decrypting the note's `enc_ciphertext`.
6. `deterministic_valid` fixture: populate `d[0..11]` from
   `shared_d_word.to_le_bytes()` zero-padded to 32, and
   `shared_ivk_commitment` from a new computation mirroring
   `poseidon2_ivk_commitment(...)`.
7. AIR unchanged — still reads `first_u64_proxy(&s.d)` /
   `first_u64_proxy(&s.ivk_commitment)`.

Commit prefix: `M-P2 Phase 4b-step3-step5a-wire`.

Tests to pass:

```bash
cd uno/plonky3-ffi && cargo test --release -j 128 batch_range_check_round_trip_1_1
cd uno/plonky3-ffi && cargo test --release -j 128 sizes_at_4_4
cd uno/plonky3-ffi && cargo test --release -j 128 witness_decode_rejects
cd tosctl/uno && cargo test --release -j 128 --test send_roundtrip
```

#### Sub-commit 2 — step 5b-decomp (~150 LOC)

Mirror of step 2b-decomp on spend side for cm sponge input fields.

- Add fe-limb cols: `S_D_FE1` (1), `S_PK_D_FE1..3` (3),
  `S_IVK_COMMITMENT_FE0..3` (4), `S_RCM_FE1..3` (3). **11
  cols/spend.** `S_D`, `S_PK_D`, `S_RCM` already hold low fes; value
  already has `S_VALUE_LIMB0..3` from Phase 3b-step2.
- Add u16 limb cols for all 15 input fe-limbs: `15 × 4 = 60` u16 cols.
  But 4 u16 cols for `value` already exist. Net: `14 × 4 = 56` new u16
  cols/spend.
- `SPEND_PROXY_COLS += 11 + 56 = +67`.
- AIR decomp constraints: for each of 15 fe-limbs,
  `fe == Σ u16 · 2^{16k}`. 15 constraints/spend.
- `collect_u16_reads_for_range16` in `prover.rs`: push 56 new u16
  values per spend (mirror step 2b-decomp's existing 32 for
  nk + leaf). Order must match trace-gen.
- Update `lookupair_must_stay_single_tuple_per_limb` formula from
  `4·(n_s+n_o) + 56·n_o + 32·n_s` to
  `4·(n_s+n_o) + 56·n_o + 88·n_s`.
- Trace-gen: populate 11 new fe-limb cols from `pack_32b_as_4fe` /
  `pack_diversifier_as_2fe`.

Commit prefix: `M-P2 Phase 4b-step3-step5b-decomp`.

#### Sub-commit 3 — step 5c-sponge (~250 LOC) — THE CORE

Mirror step 1.2 exactly.

**Bank-1 on rows `0..(n_s-1)`** (REPLACES the existing spend-cm
single-perm):

- `shared_cm.inputs[0..8]` pinned to
  `(d_fes[0..2], pk_d_fes[0..4], ivk_commitment_fes[0..2])`,
  i.e. `(S_D, S_D_FE1, S_PK_D, S_PK_D_FE1..3, S_IVK_COMMITMENT_FE0,
         S_IVK_COMMITMENT_FE1)`.
- `shared_cm.inputs[8..16]` pinned to `uno_cm_v1_tag_block()` (existing
  constant, mirrors step 1.2b).
- `shared_cm_out[0..8]` bound to new per-spend cols
  `S_CM_CARRY_RATE[0..8]`.
- `shared_cm_out[8..16]` bound to new per-spend cols
  `S_CM_CARRY_CAP[0..8]`.

**Bank-2 on rows `24..(24+n_s-1)`**:

Total 15 fes: positions `0..14`. Bank-1 absorbs 8 fes (positions
`0..7`), bank-2 absorbs the remaining 7 fes (`8..14`). Read step 1.2f
(commit `5cf965204`) for the exact absorb pattern:

- `shared_cm.inputs[k] = S_CM_CARRY_RATE[k] + fes[8+k]` for
  `k ∈ 0..7` (absorbs `fes[8..14]`, i.e.
  `ivk_commitment_fes[2..4]`, `value`, `rcm_fes[0..3]`).
  That's 7 absorbs; slot `k=6` absorbs `fes[14] = rcm_fes[3]`.
  Slot `k=7` is NOT an absorb — it's the 10\* padding.
- `shared_cm.inputs[7] = S_CM_CARRY_RATE[7] + 1` (10\* padding bit).
- `shared_cm.inputs[8..16]` pinned to `S_CM_CARRY_CAP[0..8]` (cap
  carry).
- `shared_cm_out[0..4]` bound to `S_LEAF` (k=0) + `S_LEAF_FE1..3`
  (k=1..3). **This is the claim-2 closure**: the sponge output IS the
  Merkle leaf fes that step 3a feeds into `S_CURRENT_FE` for the
  walk.

- Add per-spend `S_CM_CARRY_CAP[0..8]` + `S_CM_CARRY_RATE[0..8]` cols.
  `SPEND_PROXY_COLS += 16`.
- Trace-gen: replace `row0_spend_cm` (single-perm witness) with
  `spend_cm_bank1` + `spend_cm_bank2` vectors + pre-compute
  `spend_cm_out_{cap,rate}` carry values. Row-assembly branch: rows
  `0..(n_s-1)` write bank-1, rows `24..(24+n_s-1)` write bank-2.
- Retire the old spend-row single-perm AIR constraint block.

Commit prefix: `M-P2 Phase 4b-step3-step5c-sponge`.

#### Sub-commit 4 — step 5d-close (~70 LOC)

1. `witness_claim2_leaf_consistent` (pre-check helper in
   `transfer_air.rs`): switch from `poseidon2_cm_fe` (legacy
   single-perm proxy) to `poseidon2_cm_full_sponge` (real 15-fe
   iterated sponge). Compare all 4 fe limbs of `s.leaf` against the
   sponge output.
2. Delete now-unused `poseidon2_cm` / `poseidon2_cm_fe` helpers if
   `grep` confirms no live callers.
3. Cross-crate parity test in
   `tosctl/uno/tests/phase4b_step3_sponge_parity.rs`: verify
   `poseidon2_cm_full_sponge_bytes(spend_inputs) ==
   hash_tagged(b"uno-cm-v1", 15 fes)` for a deterministic test vector.
   (Helper is already `pub` from step 1.0.) This closes the parity gap
   for spend-side cm.
4. Doc updates (scope restoration):
   - `doc/uno-workchain.md §2 R9`: remove the "Out-of-scope" paragraph
     about spend-side claim 2; mark it CLOSED as of this commit.
   - `doc/uno-p2-phase4b-step3-plan.md` keystone-milestone: same
     restoration.
   - `doc/uno-phase4b-step3-codex-audit.md` Finding 1 triage line:
     update from "doc scope-honesty update" to "FIXED by step 5a-d".

Commit prefix: `M-P2 Phase 4b-step3-step5d-close`.

### Tests to run between sub-commits

```bash
cd uno/plonky3-ffi && cargo build -j 128
cd uno/plonky3-ffi && cargo test --release -j 128 batch_range_check_round_trip_1_1
cd uno/plonky3-ffi && cargo test --release -j 128 batch_prove_succeeds_on_valid_1_2
cd uno/plonky3-ffi && cargo test --release -j 128 sizes_at_4_4
cd uno/plonky3-ffi && cargo test --release -j 128 lookupair_must_stay_single_tuple_per_limb
cd tosctl/uno && cargo test --release -j 128 --test send_roundtrip
cd tosctl/uno && cargo test --release -j 128 --test phase4b_step3_sponge_parity
```

After step 5d, also:

```bash
cd uno/plonky3-ffi && cargo test --release -j 128 batch_range_check_round_trip_4_4_worst_case
```

ALL must pass. If the `lookupair` formula test fails, adjust BOTH the
test formula and the LogUp receive count together — they must agree.

### Critical gotchas

1. **Tag-block placement** (mirror step 1.2b, NOT step 2b-AIR-v1):
   `state[8..16] = uno_cm_v1_tag_block()`. The tag goes at capacity
   slots, NOT at `state[0..8]`. Step 2b-AIR-v1 (commit `b92a6bdbb`,
   later superseded by v2 `9add1ad0f`) made this exact mistake and
   diverged from the C++ spec. Follow step 1.2b and step 2b-AIR-v2
   layout.

2. **Padding bit** at bank-2 rate slot 7 for a 15-fe input. Matches
   step 1.2f pattern. (9-fe input would have padding at slot 1 —
   that's the nf layout in step 2b-AIR-v2.)

3. **`S_LEAF` col naming**: `S_LEAF` already exists (single-fe proxy)
   and `S_LEAF_FE1..3` exists from step 2b-decomp. Bank-2 output
   binding: `shared_cm_out[0] == S_LEAF` (not "S_LEAF_FE0" — that
   alias doesn't exist; the low fe IS `S_LEAF`),
   `shared_cm_out[1..4] == S_LEAF_FE1..3`.

4. **Verify with `git log`**: before starting, run
   `git log --oneline origin/uno..uno | head` and
   `git branch --list 'worktree-agent-*'` to check if the previous
   Claude Code agent landed any partial work. If yes, integrate
   cleanly (cherry-pick or skip sub-commits already done).

5. **`OwnedNote` might lack `d` / `ivk_commitment`**: if step 5a-wire's
   tosctl threading can't source these from `OwnedNote` (check
   `scan.rs`), check if they can be derived from the FVK + diversifier
   at wallet scan time. If genuinely blocked, stop step 5a-wire at
   witness-struct + wire-format + fixture (leave tosctl using
   synthetic bytes for these fields), commit, and note the gap for
   follow-up.

### Return format

For each sub-commit landed: commit hash, diff stat, one-line summary,
test pass count. If blocked: exact error + concrete recommendation.
Push to `origin/uno` after all 4 land (user will run `git push`
themselves if they want to verify first).

Work directory: `/home/tomi/tos`. Use `cargo build -j 128` (192-core
host). Do not run the full test suite (takes ~5 min); use the targeted
commands above.
