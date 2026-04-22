# Uno M-P2 Phase 4b-step3 Implementation Plan

**Topic:** Real 32-byte field-material AIR — replacing the u64-proxy
Poseidon2 / Merkle-walk derivations that remain in the AIR after
M-P2 Phase 4b-step2a/b, so the STARK itself proves the real
cryptographic bindings of `cm`, `nf`, `leaf`, and the depth-32
Merkle walk against the real 32-byte recipient / spender material.

**Status:** Plan only. No code landed yet. Tracked as task #131.

**Scope:** strict cryptographic soundness closure. Phase 4b-step3
does NOT improve byte parity (already closed by Phase 4a + 4b-step1
+ 4b-step2a/b) and does NOT change PI layout. It upgrades the AIR
claims themselves from "some self-consistent proxy computation" to
"real 32-byte derivation with 256-bit binding".

---

## 1. Why this work

### 1.1 What the AIR proves today (post-M-P2)

After the M-P2 batch-stark + range-check + byte-parity series, the
shipped Transfer AIR proves:

| # | Claim | Domain | Strength |
|---|---|---|---|
| 1 | `Σ spend.value = Σ output.value + fee`      | u64 arithmetic    | real (128-bit via STARK) |
| 2 | each `value < 2^64` via 4×u16 + LogUp       | u16 limbs         | real (128-bit via STARK + LogUp) |
| 3 | trace-internal `cm_claim = Poseidon2-w=16(TAG_CM, d_proxy, pk_d_proxy, ivk_commitment_proxy, value, rcm_proxy)` | u64 proxies       | **weak** |
| 4 | trace-internal `anchor_proxy = Poseidon2-Merkle-walk(leaf_proxy, [sib_proxies])`, 32 levels | u64 proxies       | **weak** |
| 5 | `PI[cm+k] = witness.cm_bytes[k*8..(k+1)*8]` (k=0..3), copy-constraint | byte copy         | copy-only, not derivation |
| 6 | `PI[anchor+k] = witness.anchor_bytes[k*8..(k+1)*8]` copy-constraint   | byte copy         | copy-only, not derivation |

The "weak" rows are the target of this plan. The u64 proxies
currently used by the AIR are digest-reductions of the real 32-byte
material, not the material itself — tosctl at
`tosctl/uno/src/send.rs` computes `d_proxy = reduce_digest_to_proxy
(b"uno-sw-d", anchor)` et al. at 11 call sites. The AIR therefore
runs Poseidon2 / Merkle constraints over u64 summaries of address
bytes, not over the real bytes.

### 1.2 Concrete soundness impact

Because claim 4 terminates with a single-Goldilocks-element
comparison (`S_CURRENT_last_row == anchor_proxy`, each a single
field element ≈ 64 bits), the Merkle-walk binding has **64-bit
classical preimage resistance** under Poseidon2. The STARK itself
claims 180-bit conjectured / 102-bit proven soundness (FRI Option
B, §2.1), so the AIR's weakest cryptographic binding is below the
STARK soundness floor.

Grover acceleration takes the classical 64-bit figure down to
roughly 32-bit quantum resistance on the Merkle binding. That
directly contradicts the Uno "PQ-native" positioning (§0.1,
§0.2): the surrounding STARK is PQ-safe, but this single AIR
constraint is not.

Protocol-layer signatures (`spend_auth_sig` over Ristretto255) act
as a second gate — they raise the practical attack bar, but are
themselves broken by Shor, so under a full quantum-adversary model
the AIR's 64-bit Poseidon2-preimage surface is load-bearing.

### 1.3 When Phase 4b-step3 is required vs. optional

| Deployment | Step3 required? | Reason |
|---|---|---|
| V1 testnet (60-day stability)                   | optional | no real value; signatures carry the classical-adversary load |
| V1 mainnet, small per-Tx value (~$10K)          | optional, docs must disclose | 2^64 classical work × signature barrier > economic reward at this scale |
| V1 mainnet, large per-Tx value or institutional | **required** | 64-bit AIR binding is an explicit audit blocker; see §4b.1 below |
| Any deployment sold as "post-quantum secure"    | **required** | 32-bit quantum binding contradicts the PQ claim |
| v2 protocol edits that remove or weaken the signature layer | **required** | AIR becomes sole cryptographic gate; 64-bit is not enough |

Current `doc/uno-workchain.md §13` lists this as the remaining
Tier 2 item, post-v1-default, with an explicit launch-policy call
required before activation.

---

## 2. What the vendored Plonky3 tree does and does NOT give us

3 parallel `Explore` sub-agents audited `third-party/plonky3-uno/`
and the relevant upstream surface. Summary:

### 2.1 Directly reusable (no hand-writing needed)

| Component | Location | Usage |
|---|---|---|
| `Poseidon2Air<F, LL, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>` | `third-party/plonky3-uno/poseidon2-air/src/air.rs` | Per-permutation AIR constraints already in use since M-P2 Phase 2 (commit `e3a43b4c6`). No change to the gadget itself; we only change the inputs fed in. |
| `generate_trace_rows::<..Poseidon2Cols..>` | `third-party/plonky3-uno/poseidon2-air/src/generation.rs` | Given a Poseidon2 input array, emits one row of the Poseidon2 witness columns. One call per Merkle level at trace-gen time. |
| `TruncatedPermutation<Poseidon2Goldilocks<8>, 2, 4, 8>` | `third-party/plonky3-uno/symmetric/src/compression.rs` | `[4-fe, 4-fe] → 4-fe` compression primitive. Already used by `MvpCompress` in `uno/plonky3-ffi/src/prover.rs`. Useful **off-circuit** (reference-root derivation in trace-gen); **not directly usable inside the AIR** — the AIR must expand it to the underlying Poseidon2Air round constraints. |
| `p3-lookup` LogUp infrastructure                   | `third-party/plonky3-uno/lookup/` | Already wired by M-P2 Phase 3b for u16 range-check. Phase 4b-step3 does not add new lookups but may reuse the pattern if u8 range-check becomes desirable on per-byte limb views. |
| `p3-batch-stark` prove/verify + `ProverData::from_airs_and_degrees`          | `third-party/plonky3-uno/batch-stark/` | Shipped production path after Phase 5 (commit `df42d6e87`). No change. |

### 2.2 Indirectly useful as reference but not drop-in

| Component | Location | Why not drop-in |
|---|---|---|
| `MerkleTreeMmcs`                     | `third-party/plonky3-uno/merkle-tree/src/mmcs.rs` | Designed for FRI / PCS polynomial commitments. It builds Merkle trees over trace rows to commit them, not an AIR gadget that proves "a specific leaf lies under a specific root via a specific path". The Mmcs `open` / `verify_batch` are Rust helpers run outside any AIR. |
| Upstream Poseidon2 sponge / absorb tests | `third-party/plonky3-uno/poseidon2/tests/` | Good reference for 15-FE absorb layout; not a reusable AIR. |
| `batch-stark/tests/simple.rs` MulAir / FibAir                              | reference | Good working templates for Air<AB> + LookupAir<F> implementation shape, already used as reference for M-P2 Phase 3b-step3. |

### 2.3 What must be hand-written

**There is no ready-made Merkle-path AIR gadget in the Plonky3
ecosystem.** Every production-grade zk-rollup / shielded-payment
codebase the research agents surveyed has its own hand-written
Merkle AIR. This is structural to STARK-as-framework: the primitives
are supplied, the application-specific constraint layout is the
user's responsibility.

The Uno-specific hand-written portions are:

1. The 32-level Merkle-walk AIR with 4-fe state propagation (the
   bulk of the LOC in this phase).
2. The claim-2 / claim-6 wiring changes: `O_CM_CLAIM` is currently 1
   column; step3 expands it to 4 cols and binds all 4 Poseidon2-w=16
   output limbs.
3. Witness wire-format changes + tosctl-side decode path.
4. Pre-check wire-up for the existing-but-unused
   `witness_cm_bytes_consistent` and `witness_anchor_bytes_consistent`
   helpers.

---

## 3. LOC breakdown and time estimate

### 3.1 Per-area LOC estimate (new code, measured against the existing layout)

| Area | Estimated new LOC | Difficulty | Notes |
|---|---:|---|---|
| `SpendWitness` / `OutputWitness` field migration (u64 → [u8; 32] for d / pk_d / ivk / rcm / ivk_commitment); encode/decode updates   | ~80   | mechanical | reuse the existing byte-encode pattern used for rk_bytes / epk_bytes / cm_bytes |
| `tosctl/uno/src/send.rs`: drop 11 `reduce_digest_to_proxy` calls; pass real 32-byte material through to MvpWitness                  | ~120  | mechanical | Agent A of the Phase 4b-step2 turn already audited every call site and confirmed real material is available at witness-build time |
| `cm` 4-fe in-circuit derivation via 15-fe iterated-sponge Poseidon2-w=16 (see §4.1 for the full layout): doubles the shared wide-block rows from 8 to 16, adds input-packing + cross-bank state-carry + padding constraints; matches the tosctl / C++ validator layout exactly                        | **~420**  | cryptographer | revised 2026-04-22 after iterated-sponge audit. Was ~150 LOC under the simpler single-permutation assumption; agents A+B confirmed the production layout is a 15-fe wide sponge with "uno-cm-v1" tag across 2 permutations per cm. Good news: tosctl `output_cms[j]` already uses this layout, so step 1 is Rust-only catch-up. |
| `nf` inputs switched from u64 proxies to real 32-byte material                                                                     | ~40   | cryptographer | `nf` already emits 4 fe from Phase 1; input wiring is the only change |
| **Depth-32 Merkle walk upgraded to 4-fe state: `S_CURRENT` 1 col → 4 cols; `S_SIBLING0..31` 32 cols → 128 cols; per-level Poseidon2-w=8 AIR call rewired**   | **~400** | **cryptographer, bulk of the phase** | this is the hand-written gadget; see §4.3 for the shape |
| PI binding cleanup: delete `G_ANCHOR_LIMB0_REAL`, `G_ANCHOR_PROXY`, `O_CM_LIMB0_REAL` cols and their row-0 copy-constraints; re-bind `PI[anchor+k]` / `PI[cm+k]` to the new 4-fe outputs directly                                                     | ~50   | mechanical | reverses the Phase 4b-step2a/b decoupling in favor of direct derivation-to-PI binding |
| Wire `witness_cm_bytes_consistent` + `witness_anchor_bytes_consistent` into `pre_check_transfer_witness`                             | ~20   | trivial | helpers already exist in `transfer_air.rs`, just unused |
| Regression tests: one per step boundary + one full 4/4 round-trip                                                                    | ~200  | engineer | mirror the style of `batch_range_check_round_trip_4_4_worst_case` |
| Bench + golden re-gen runs                                                                                                           | N/A   | run time only | `cargo bench --bench shape_matrix`; `cargo test --release --test codec_parity_goldens` (Agent B confirmed goldens do not embed proof bytes, so the regen here is only for PI-shape confirmation) |
| **Total new code**                                                                                                                   | **~1 300 LOC** | | revised 2026-04-22 after iterated-sponge audit — was ~1 060 LOC; + ~300 LOC tests |

### 3.2 Time estimate

| Phase of work | Wall time |
|---|---|
| Core coding (steps 0–3 in §4) | 1–2 cryptographer-weeks |
| Regression + bench + goldens  | +2–3 days |
| Audit-ready housekeeping (update `doc/uno-workchain.md §4.2` claim text, `doc/uno-audit-scope.md` Tier 2 block, PR writeup, diff commentary for the vendor auditor) | +1 cryptographer-week |
| **Total audit-ready delivery** | **~1 cryptographer-month** |

The 1–2 week core-coding figure matches the Path (iii)-step-2
estimate recorded in `doc/uno-p2-path-research.md`. The extra 1–2
weeks is for documentation / audit preparation that is required if
this is being shipped into a production deployment, and optional
for a pure testnet-only closure.

---

## 4. Implementation sequence

The work splits into 5 atomic steps. Each step compiles, passes the
existing lib test suite, and can be committed independently. Steps
1–3 each progressively reduce the Poseidon2 / Merkle "proxy surface"
until every derivation runs over real 32-byte material.

### 4.0 Step 0 — witness wire-format refactor (AIR unchanged)

**Goal:** expand `SpendWitness` / `OutputWitness` to carry real
32-byte material for `d`, `pk_d`, `ivk`, `ivk_commitment`, `rcm`;
update `encode` / `decode`; adjust tosctl `send.rs` to stop reducing
to proxies and pass real bytes through.

**AIR changes:** none. The AIR still consumes the same proxy u64
values; it just now computes them inline from `witness.d[0..8]` etc.
instead of reading pre-computed `witness.d` as a u64 field. This
keeps the step fully backward-compatible with the currently-shipped
prove/verify path.

**Tests:** `MvpWitness::encode`/`decode` round-trip on all shapes;
public-input fixture should still be byte-identical (PI format is
unchanged).

**Commit message prefix:** `M-P2 Phase 4b-step3-0: witness wire
format — real 32-byte address material`.

### 4.1 Step 1 — cm derivation in-circuit, real inputs

**Goal:** the Rust AIR proves `cm_bytes` was produced by the SAME
15-fe iterated Poseidon2-w=16 sponge that tosctl
(`tosctl/uno/src/poseidon2.rs::hash_tagged`) and the C++ validator
FFI consume. `PI[pi_cm(j) + k]` is then driven by the AIR's real
Poseidon2 output, reversing Phase 4b-step2a's `O_CM_LIMB0_REAL`
decoupling.

**Scope correction (2026-04-22 agent re-audit).** The original §4.1
text assumed a single Poseidon2-w=16 permutation over 5 real inputs
+ TAG at slot 0 + zeros elsewhere. That was wrong. Two parallel
Explore sub-agents confirmed the actual production layout is a
**15-fe wide-sponge iterated absorb** (rate 8 / capacity 8) with the
"uno-cm-v1" domain tag, TWO permutations per cm:

  Input field elements (15 total, order per
  `uno/core/poseidon2.cpp::compute_note_commitment` +
  `tosctl/uno/src/poseidon2.rs::hash_tagged`):

    fes[0..1]    — d   (11 B diversifier, zero-padded to 16 B,
                        split as 2 × u64 LE mod p)
    fes[2..5]    — pk_d            (32 B → 4 × u64 LE mod p)
    fes[6..9]    — ivk_commitment  (32 B → 4 × u64 LE mod p)
    fes[10]      — value           (u64 mod p)
    fes[11..14]  — rcm             (32 B → 4 × u64 LE mod p)

  Sponge layout (Poseidon2-w=16):

    Perm 1 input:
      state[0..7]  = fes[0..7]
      state[8..15] = "uno-cm-v1" packed as 8 × u64 LE (the capacity
                     slot for domain separation; pinned across the
                     whole absorb)
    Perm 1 output: state' (full 16-fe state carried into perm 2).
    Perm 2 input:
      state[0..6] += fes[8..14]        (rate slots)
      state[7]   += Goldilocks::ONE    (10* padding bit)
      state[8..15] unchanged from perm 1 output
    Perm 2 output: state[0..4] is the 4-fe cm digest.

**AIR structure changes:**

```
// pre-step3 (current)
G_CM_SHARED_P2_16: 1 Poseidon2-w=16 block at rows 0..7,
                   8 instances total (4 spend + 4 output at 4/4).
                   Each instance absorbs (TAG_CM, d, pk_d, ivk_cm,
                   value, rcm, 0..0) and emits state[0] as the
                   cm / leaf proxy.
O_CM_CLAIM      : 1 col, bound to state[0].
O_CM_LIMB0_REAL : 1 col, bound to witness.cm_bytes[0..8],
                  drives PI (Phase 4b-step2a decoupling).
O_CM_LIMB1..3   : 3 cols, bound to witness.cm_bytes[8..32],
                  drive PI (Phase 4b-step1).

// post-step1
G_CM_SHARED_P2_16 doubles: rows 0..15 host two banks of 8 P2-w=16
  instances each. Bank A (rows 0..7) is perm-1 of the sponge; bank
  B (rows 8..15) is perm-2. Cross-bank constraints carry the full
  16-fe state from bank A's output into bank B's input, with the
  fes[8..14] + padding absorbed into state[0..7] between banks.
  Input packing constraints verify d / pk_d / ivk_commitment / rcm
  bytes decompose correctly into their 4-fe (or 2-fe for d) limbs.
O_CM_CLAIM[0..4]: 4 cols, bound to bank B's state[0..4] output.
                  Drives PI[pi_cm(j) + k] for k ∈ 0..4.
O_CM_LIMB0_REAL / O_CM_LIMB1..3: deleted.
```

**Soundness gain:** STARK now proves the C++-identical
`cm_bytes = Poseidon2-w=16-wide-sponge(TAG="uno-cm-v1", [real d,
real pk_d, real ivk_commitment, value, real rcm])`. The
`witness_cm_bytes_consistent` pre-check (already in
`transfer_air.rs`, currently unwired) becomes true for all tosctl-
produced witnesses and gets wired into
`prover::pre_check_transfer_witness`.

**Revised LOC estimate.** The original §3.1 estimate of ~150 LOC for
step 1 was based on the simpler single-permutation assumption. The
true 15-fe iterated-sponge layout requires ~350-450 LOC:

  - Doubled shared-wide-block rows (rows 0..7 → rows 0..15)
    + associated `GS_ROW_SEL` selector expansion: ~80 LOC
  - Input-packing constraints (bytes → 2-fe or 4-fe limbs, mirroring
    `uno/core/poseidon2.cpp::bytes_to_fes_wrapped`): ~70 LOC
  - Cross-bank state carry + per-bank input-absorb addition
    constraints: ~120 LOC
  - Trace-gen for both permutations per instance, correct state
    threading, and padding-bit emission: ~80 LOC
  - Tag-block materialization (`state[8..15]` = "uno-cm-v1" packed):
    ~30 LOC (cached constant)
  - Column-layout cleanup (delete O_CM_LIMB0_REAL / LIMB1..3, rewire
    PI bindings): ~40 LOC

  Total: ~420 LOC new + ~50 LOC deletions. Net complexity closer to
  a **half cryptographer-week in isolation**, vs. the plan-doc
  original ~150 LOC / 1-2 days.

**Good news from the agent audit.** tosctl's `output_cms[j]` is
ALREADY computed via the 15-fe iterated sponge layout (not over u64
proxies). So step 1 is a pure AIR-side change — no tosctl coordination
needed for the cm side. The Rust AIR catches up to what tosctl +
C++ already agree on.

**Tests:** `prove_with_range_check` + `verify_with_range_check`
round-trip at 1/1, 1/2, 4/4; wire
`witness_cm_bytes_consistent`; `codec_parity_goldens` should show
`cm_hex` byte-identical to pre-step1 (the value was already a
valid tosctl cm; step 1 just adds the AIR proof that it's the
correct derivation).

### 4.2 Step 2 — nf derivation in-circuit, real inputs

**Goal:** `nf = Poseidon2-w=8(TAG_NF, real_nk, real_cm[4], pos)` where
the inputs are drawn from the step-1 real 4-fe cm and real 32-byte
nk. `nf_full` trace-gen already returns 4 fe since M-P2 Phase 1; the
change is purely on the input side.

**AIR structure changes:** shared narrow-width block on rows 4+i
switches the nf input from `(nk_proxy, leaf_proxy, pos_proxy)` to
`(nk[0..4], leaf[0..4], pos)` where `leaf = cm` (claim 2 makes them
equal for spends on the tree); drop now-unused nk_proxy / leaf_proxy
cols.

**Soundness gain:** nullifier binding is now a real-material
derivation, matching the protocol-layer definition of nf.

### 4.3 Step 3 — Merkle walk 4-fe state

**Goal:** the depth-32 Merkle walk threads a 4-fe state through all
32 levels. Each level's Poseidon2-w=8 compression is
`(left[4] || right[4]) → output[4]`. The last level's `output[0..4]`
is bound to `witness.anchor_bytes[0..32]` as 4 Goldilocks limbs,
which is directly `PI[PI_ANCHOR + 0..4]`.

**AIR structure changes:**

```
// pre-step3 (current)
S_CURRENT         : 1 col (per spend), single-fe running digest
S_SIBLING0..31    : 32 cols, single-fe siblings per level
G_ANCHOR_PROXY    : 1 col, holds witness.anchor_proxy (Merkle result)
G_ANCHOR_LIMB0_REAL : 1 col, holds anchor_bytes[0..8]
G_ANCHOR_LIMB1..3   : 3 cols, holds anchor_bytes[8..32]

// post-step3
S_CURRENT[0..4]   : 4 cols (per spend), 4-fe running digest
S_SIBLING0_lo[0..4] ... S_SIBLING31_lo[0..4]  : 32 * 4 = 128 cols,
                                                  4-fe siblings per level
                    (levels 0..31, each carrying a full 32-byte sibling)
  G_ANCHOR_PROXY / G_ANCHOR_LIMB*_REAL : all deleted.
```

Per-level constraint (schematic, in the AB::eval):

```
for k in 0..MERKLE_DEPTH {
    let bit = path_bit[k];                      // (pos >> k) & 1, already present
    let cur = S_CURRENT[prev_row, 0..4];
    let sib = S_SIBLING_k[0..4];

    // Conditional swap: bit=0 → (cur, sib), bit=1 → (sib, cur)
    let left  = select(bit, sib, cur);          // 4-fe pair
    let right = select(bit, cur, sib);          // 4-fe pair

    // Plug into the shared Poseidon2-w=8 block on that trace row;
    // its output[0..4] must equal S_CURRENT[next_row, 0..4].
    assert_eq_vec4(p2_w8_block_output[level k], S_CURRENT[next_row]);
}
assert_eq_vec4(S_CURRENT[last_row, 0..4], PI[PI_ANCHOR + 0..4]);
```

`select` is the standard 1-bit-controlled swap: `left[i] =
bit * sib[i] + (1 - bit) * cur[i]`, produces a degree-2 constraint
per lane (4 constraints per level). The per-level Poseidon2-w=8
constraints come directly from the existing `Poseidon2Air` gadget —
no Poseidon2 maths is rewritten.

**Width delta (rough, at 4/4):** +3 cols per spend for the
expanded `S_CURRENT`, +3*32 = +96 cols per spend for the expanded
siblings — total ~+4*99 = +396 cols at the 4-spend worst case, minus
the 5 deleted `G_ANCHOR_*` cols ≈ **+391 net cols** at 4/4. Some
proof-byte growth expected; bench re-run required for precise delta.

**Soundness gain:** the Merkle-walk binding goes from 64-bit
(single fe check) to 256-bit (4 fe check). Wire
`witness_anchor_bytes_consistent` into `pre_check_transfer_witness`.
This is the keystone of the phase — after step 3 commits, the AIR
proves the full protocol-level cryptographic shape.

### 4.4 Step 4 — cleanup, regen, doc

**Goal:** remove the Phase 4b-step2a/b "decoupling" comments from
`transfer_air.rs` (their trade-off is now reversed); re-run
`shape_matrix` bench and record the post-step3 numbers; re-run
`codec_parity_goldens` and confirm zero diff (the PI layout
did not change); update `doc/uno-workchain.md §13` P.2 row to
reflect the strong-soundness closure; update the
`doc/uno-p2-path-research.md` Progress log with a new Phase
4b-step3 block and commit references.

**Audit prep:** amend `doc/uno-audit-scope.md` Tier 2 block with the
specific claims the new AIR makes, and prepare a summary of the
step-by-step diff for vendor reviewers. Call out that the
`Poseidon2Air` gadget itself is upstream-audited (Plonky3 v0.5.1
pinned at `6374a36f`) so the audit surface is the hand-written
Merkle / claim-2/6 binding logic, not the permutation primitive.

---

## 5. Validation plan

Step 3 makes every claim in the AIR correspond to the protocol's
intended cryptographic semantics. The validation levels:

1. **Unit level (must be green before any merge):**
   - All 391 existing lib tests still pass.
   - New test per step: a small 1/1 round-trip asserting the AIR now
     rejects a tampered `cm_bytes[0..8]` (pre-step3 it would accept
     it because cm limb 0 was decoupled; post-step3 it must reject).
   - Similar tamper-rejection test for `anchor_bytes[0..8]`.

2. **Integration level:**
   - `cargo test --release -j 64` across `uno/plonky3-ffi`,
     `tosctl/uno`, plus the 17 C++ test binaries in `uno/test/` — all
     green.
   - BoC parity tests in `tosctl/uno/tests/boc_parity.rs` still
     byte-identical.
   - `public-inputs-v1.hex` golden unchanged (PI layout stable).

3. **Benchmark level:**
   - Re-run `cargo bench --bench shape_matrix`; expect 4/4 verify
     around 25–30 ms (up from post-M-P2's 21 ms due to the wider
     trace), proof bytes around 1.05–1.15 MB.
   - Update `uno-workchain.md §13` P.2 row with the new numbers.
   - If the 4/4 verify goes over ~35 ms or proof > 1.2 MB, stop and
     re-evaluate — the Merkle-walk width expansion may require a
     compensating column-sharing step.

4. **Audit-prep level:**
   - Fresh diff-summary document for the auditor.
   - `doc/uno-workchain.md §4.2` claim text rewritten to reflect the
     real-material semantics.

---

## 6. What step3 does NOT change

- **PI layout.** All 6 of the 256-bit PI fields + filter_tag stay at
  the same slot indices and byte widths. External consumers
  (`build_plonky3_public_inputs` on the C++ side,
  `public-inputs-v1.hex` golden) are unchanged.
- **FRI parameters.** §2.1 Option B pin is untouched.
- **FFI ABI.** `uno_plonky3_verify` / `uno_plonky3_prove` signatures
  are unchanged; proof bytes remain `BatchProof<MvpConfig>` postcard.
- **C++ validator code.** No changes required. Opaque-bytes
  abstraction from `uno/crypto/plonky3-verifier.h` continues to
  hold.
- **Block / BoC wire format.** No changes.

The entire step3 surface is contained to:
- `uno/plonky3-ffi/src/transfer_air.rs` (AIR + witness structs +
  trace-gen + pre-check helpers)
- `tosctl/uno/src/send.rs` (pass real 32-byte material through)

---

## 7. Dependencies and sequencing outside the step itself

- **Phase 5 (#127) must be landed first.** ✅ Already landed in
  commit `df42d6e87`.
- **Phase 4b-step2a/b (#129) must be landed first.** ✅ Already
  landed in commits `b508b3213` and `8d9637d61`.
- **No external blocker** — Plonky3 primitives (`Poseidon2Air`,
  `TruncatedPermutation<Poseidon2Goldilocks<8>, 2, 4, 8>`,
  `p3-batch-stark`, `p3-lookup`) are all already vendored in
  `third-party/plonky3-uno/` at commit `6374a36f`.
- **Golden regen is one-shot at step 4.** No coordination with
  other agents or the C++ side is required.

---

## 8. Cross-references

- `doc/uno-workchain.md §4.2` — original 8 claims (Uno STARK
  semantic target).
- `doc/uno-workchain.md §4.3` R9 audit status — Tier 1 / Tier 2
  split history, updated post-M-P2 to flag step3 as the remaining
  Tier 2 item.
- `doc/uno-workchain.md §13` P.2 row — status table; update after
  step3 lands to flip both "byte-parity" and "strong-soundness"
  columns to ✅.
- `doc/uno-p2-path-research.md` — running M-P2 progress memo, Path
  (iii)-step-2 section has the agent research that drives this
  plan.
- `doc/uno-audit-scope.md` — Tier 2 block to be amended with the
  specific real-material claims once step3 commits.
- `uno/plonky3-ffi/src/transfer_air.rs` — the file that changes the
  most; search for `Phase 4b-step2a` / `Phase 4b-step2b` comments to
  find every site that step3 reverses/upgrades.
- `uno/plonky3-ffi/src/range16_air.rs` — referenced for the
  cross-AIR pattern if step3 ever wants a u8 byte-range-check
  (optional; current plan does not add one).
- `third-party/plonky3-uno/poseidon2-air/src/air.rs` — the
  Poseidon2 AIR gadget already in production use; step3 keeps using
  it unchanged.
- Commit history 2026-04-22: `0e692fb01` → `dadc249ec` → `e83c2cce4`
  → `720481e0e` → `b508b3213` → `8d9637d61` → `df42d6e87` →
  `99fd4db71` → `1274b523c` — the full M-P2 chain that step3 follows.
