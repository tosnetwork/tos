# MineUno Phase 3b Spec: Poseidon2-w16 Sub-AIR Wiring

**Date**: 2026-04-24  
**Author**: Cryptography Investigation  
**Status**: SPEC (no implementation yet)

## Overview

This document specifies the Phase 3b wiring of the shared Poseidon2-w16 sub-AIR for MineUno. Phase 3a established the structural shell: row selectors, witness proxies, and PI bindings. Phase 3b closes the cryptographic gap by constraining two independent iterated-sponge chains on the shared 316-column Poseidon2-w16 block:

- **CM chain** (rows 0–1): `output_cm_fe = Poseidon2Sponge(d, pk_d, ivk_cm, value, rcm, TAG_CM)` — 15-fe absorption, 2 permutations, capacity carry
- **PoW chain** (rows 2–3): `pow_hash_fe = Poseidon2Sponge(epoch, nonce, output_cm, TAG_MINE)` — 9-fe absorption, 2 permutations, capacity carry

Both chains share the same trace block and use row selectors for mutual exclusivity. The pattern mirrors Transfer's output-sponge wiring (transfer_air.rs:1072–1259) except MineUno uses a simpler 4-row trace height instead of row-loop multiplexing.

---

## A. Column Layout Decision

### A.1 Capacity-Carry Proxy Columns

**Required**: 8 witness proxy columns per chain to carry the permutation-1 capacity-state `[8..16]` to permutation-2's input capacity slots.

Since the CM and PoW chains are independent but share the same Poseidon2 block, **a shared proxy block suffices**. The capacity from row 0's perm1 carries to row 1's perm2 (CM chain); the capacity from row 2's perm1 carries to row 3's perm2 (PoW chain). A single 8-cell proxy column array holds whichever capacity is active on the current row (gated by row selectors), so no duplication is needed.

### A.2 Column Offsets

**Current layout** (from `/home/tomi/tos/uno/plonky3-ffi/src/mine_uno_columns.rs`):

```
Offset  Size  Content
------  ----  ----------------------------------------------------------
0–3     4     Row selectors (COL_SEL_CM_P1, CM_P2, POW_P1, POW_P2)
4–319   316   Shared Poseidon2-w16 block (MINE_POSEIDON2_COLS_16)
320–347 28    Witness proxies (witness fields + output/hash proxies)
------  ----
348           Total (MINE_AIR_WIDTH)
```

**Insert new proxy columns after witness proxy block**:

```
Offset  Size  Content
------  ----  ----------------------------------------------------------
0–3     4     Row selectors
4–319   316   Shared Poseidon2-w16 block
320–347 28    Existing witness proxies
348–355 8     NEW: Capacity-carry proxy (COL_CAP_CARRY_BASE)
------  ----
356           Total (MINE_AIR_WIDTH_NEW)
```

**New constants to add to `mine_uno_columns.rs`**:

```rust
/// Base offset for capacity-carry proxy columns (perm1 post[8..16]).
/// Carries the 8-cell capacity from perm1's output to perm2's input
/// capacity slots on the next active row within each chain.
pub const COL_CAP_CARRY_BASE: usize = WITNESS_PROXY_BASE + N_WITNESS_PROXY;

/// Capacity-carry proxy columns span [COL_CAP_CARRY_BASE, COL_CAP_CARRY_BASE + 8).
pub const N_CAP_CARRY_PROXY: usize = 8;

/// Updated total AIR width (adds 8 capacity-carry columns).
pub const MINE_AIR_WIDTH: usize =
    N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16 + N_WITNESS_PROXY + N_CAP_CARRY_PROXY;
```

**Sanity asserts** (add to `mine_uno_columns.rs`):

```rust
const _: () = assert!(
    N_CAP_CARRY_PROXY == 8,
    "capacity carry must hold exactly 8 field elements"
);
const _: () = assert!(
    MINE_AIR_WIDTH == N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16 + N_WITNESS_PROXY + N_CAP_CARRY_PROXY,
    "AIR width must account for all column types"
);
```

---

## B. Per-Row Input Pinning Constraints

The shared P2 block is accessed via `MineP2Cols<T>::inputs[0..16]`. Each row's active permutation has specific rate-slot (inputs[0..8]) and capacity-slot (inputs[8..16]) bindings.

**API signature** (from `p3_poseidon2_air::Poseidon2Cols`):
```rust
pub struct Poseidon2Cols<T, const WIDTH, const SBOX_DEGREE, const SBOX_REGISTERS, const HALF_FULL_ROUNDS, const PARTIAL_ROUNDS> {
    pub inputs: [T; WIDTH],  // [T; POSEIDON2_WIDTH_16] for width-16
    pub beginning_full_rounds: [FullRound<T, WIDTH, ...>; HALF_FULL_ROUNDS],
    pub partial_rounds: [PartialRound<T, WIDTH, ...>; PARTIAL_ROUNDS],
    pub ending_full_rounds: [FullRound<T, WIDTH, ...>; HALF_FULL_ROUNDS],
}

pub struct FullRound<T, const WIDTH, const SBOX_DEGREE, const SBOX_REGISTERS> {
    pub sbox: [SBox<T, SBOX_DEGREE, SBOX_REGISTERS>; WIDTH],
    pub post: [T; WIDTH],  // Output state after full round
}
```

**Row-0 constraint (CM perm-1, gated by COL_SEL_CM_P1)**:
- Inputs[0..2] = diversifier (d_fe0, d_fe1): `shared_p2.inputs[k] = COL_W_D_FE0 + k` for k ∈ [0, 2)
- Inputs[2..6] = pk_d (4 fes): `shared_p2.inputs[k] = COL_W_PK_D_FE0 + (k - 2)` for k ∈ [2, 6)
- Inputs[6..8] = ivk_cm partial (first 2 of 4): `shared_p2.inputs[k] = COL_W_IVK_CM_FE0 + (k - 6)` for k ∈ [6, 8)
- Inputs[8..16] = tag block (capacity): `shared_p2.inputs[k] = uno_cm_v1_tag_block()[k - 8]` for k ∈ [8, 16)

**Row-1 constraint (CM perm-2, gated by COL_SEL_CM_P2)**:
- Inputs[0] = carry[0] + ivk_cm_fe[2]
- Inputs[1] = carry[1] + ivk_cm_fe[3]
- Inputs[2] = carry[2] + value
- Inputs[3] = carry[3] + rcm_fe[0]
- Inputs[4] = carry[4] + rcm_fe[1]
- Inputs[5] = carry[5] + rcm_fe[2]
- Inputs[6] = carry[6] + rcm_fe[3]
- Inputs[7] = carry[7] + ONE (10* padding)
- Inputs[8..16] = carry_cap[0..8] (from row 0 perm1 post-state capacity)

**Row-2 constraint (PoW perm-1, gated by COL_SEL_POW_P1)**:
- Inputs[0] = epoch: `shared_p2.inputs[0] = COL_W_EPOCH`
- Inputs[1..5] = nonce (4 fes): `shared_p2.inputs[k] = COL_W_NONCE_FE0 + (k - 1)` for k ∈ [1, 5)
- Inputs[5..8] = output_cm partial (first 3 of 4): `shared_p2.inputs[k] = COL_W_OUTPUT_CM_FE0 + (k - 5)` for k ∈ [5, 8)
- Inputs[8..16] = tag block (capacity): `shared_p2.inputs[k] = uno_mine_v1_tag_block()[k - 8]` for k ∈ [8, 16)

**Row-3 constraint (PoW perm-2, gated by COL_SEL_POW_P2)**:
- Inputs[0] = carry[0] + output_cm_fe[3]
- Inputs[1] = carry[1] + ONE (10* padding)
- Inputs[2..8] = carry[2..8] + 0 (six zero-pads)
- Inputs[8..16] = carry_cap[0..8] (from row 2 perm1 post-state capacity)

**Pseudocode for constraint block in `mine_uno_air.rs::Air::eval`**:

```rust
// Snapshot the shared P2 block (mutable borrow later).
let shared_p2 = unsafe { &*(local_slice[N_ROW_SELECTORS..].as_ptr() as *const MineP2Cols<_>) };
let shared_p2_mut = unsafe { &mut *(local_slice[N_ROW_SELECTORS..].as_ptr() as *mut MineP2Cols<_>) };

// Row-0 rate-slot pinning: d + pk_d + ivk_cm[0..2]
{
    let sel: AB::Expr = local_slice[COL_SEL_CM_P1].into();
    // inputs[0..2] = d_fe
    for k in 0..2 {
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2.inputs[k]) - 
                          AB::Expr::from(local_slice[COL_W_D_FE0 + k])),
        );
    }
    // inputs[2..6] = pk_d_fe
    for k in 0..4 {
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2.inputs[2 + k]) - 
                          AB::Expr::from(local_slice[COL_W_PK_D_FE0 + k])),
        );
    }
    // inputs[6..8] = ivk_cm_fe[0..2]
    for k in 0..2 {
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2.inputs[6 + k]) - 
                          AB::Expr::from(local_slice[COL_W_IVK_CM_FE0 + k])),
        );
    }
    // inputs[8..16] = uno_cm_v1_tag_block() (capacity)
    let tag = uno_cm_v1_tag_block();
    for k in 0..8 {
        let tag_fe = AB::F::from_u64(tag[k].as_canonical_u64());
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2.inputs[8 + k]) - 
                          AB::Expr::from(tag_fe)),
        );
    }
}

// Row-0 perm1 capacity → carry columns (output binding)
{
    let sel: AB::Expr = local_slice[COL_SEL_CM_P1].into();
    let shared_p2_out = &shared_p2.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
    for k in 0..8 {
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2_out[8 + k]) - 
                          AB::Expr::from(local_slice[COL_CAP_CARRY_BASE + k])),
        );
    }
}

// Row-1 capacity-carry input: inputs[8..16] = carry columns
{
    let sel: AB::Expr = local_slice[COL_SEL_CM_P2].into();
    for k in 0..8 {
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2.inputs[8 + k]) - 
                          AB::Expr::from(local_slice[COL_CAP_CARRY_BASE + k])),
        );
    }
}

// Row-1 rate-slot absorption: ivk_cm[2..4] + value + rcm + ONE pad
{
    let sel: AB::Expr = local_slice[COL_SEL_CM_P2].into();
    let carry_cols = [local_slice[COL_CAP_CARRY_BASE + k] for k in 0..8];
    
    // inputs[0] = carry[0] + ivk_cm_fe[2]
    builder.assert_zero(
        sel.clone() * (AB::Expr::from(shared_p2.inputs[0]) - 
                      (AB::Expr::from(carry_cols[0]) + 
                       AB::Expr::from(local_slice[COL_W_IVK_CM_FE0 + 2]))),
    );
    // inputs[1] = carry[1] + ivk_cm_fe[3]
    builder.assert_zero(
        sel.clone() * (AB::Expr::from(shared_p2.inputs[1]) - 
                      (AB::Expr::from(carry_cols[1]) + 
                       AB::Expr::from(local_slice[COL_W_IVK_CM_FE0 + 3]))),
    );
    // inputs[2] = carry[2] + value
    builder.assert_zero(
        sel.clone() * (AB::Expr::from(shared_p2.inputs[2]) - 
                      (AB::Expr::from(carry_cols[2]) + 
                       AB::Expr::from(local_slice[COL_W_VALUE]))),
    );
    // inputs[3..7] = carry[3..7] + rcm_fe[0..4]
    for k in 0..4 {
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2.inputs[3 + k]) - 
                          (AB::Expr::from(carry_cols[3 + k]) + 
                           AB::Expr::from(local_slice[COL_W_RCM_FE0 + k]))),
        );
    }
    // inputs[7] = carry[7] + ONE (10* padding)
    builder.assert_zero(
        sel.clone() * (AB::Expr::from(shared_p2.inputs[7]) - 
                      (AB::Expr::from(carry_cols[7]) + 
                       AB::Expr::from(AB::F::from_u64(1)))),
    );
}

// Row-2 rate-slot pinning: epoch + nonce + output_cm[0..3]
{
    let sel: AB::Expr = local_slice[COL_SEL_POW_P1].into();
    // inputs[0] = epoch
    builder.assert_zero(
        sel.clone() * (AB::Expr::from(shared_p2.inputs[0]) - 
                      AB::Expr::from(local_slice[COL_W_EPOCH])),
    );
    // inputs[1..5] = nonce_fe[0..4]
    for k in 0..4 {
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2.inputs[1 + k]) - 
                          AB::Expr::from(local_slice[COL_W_NONCE_FE0 + k])),
        );
    }
    // inputs[5..8] = output_cm_fe[0..3]
    for k in 0..3 {
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2.inputs[5 + k]) - 
                          AB::Expr::from(local_slice[COL_W_OUTPUT_CM_FE0 + k])),
        );
    }
    // inputs[8..16] = uno_mine_v1_tag_block() (capacity)
    let tag = uno_mine_v1_tag_block();
    for k in 0..8 {
        let tag_fe = AB::F::from_u64(tag[k].as_canonical_u64());
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2.inputs[8 + k]) - 
                          AB::Expr::from(tag_fe)),
        );
    }
}

// Row-2 perm1 capacity → carry columns (output binding)
{
    let sel: AB::Expr = local_slice[COL_SEL_POW_P1].into();
    let shared_p2_out = &shared_p2.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post;
    for k in 0..8 {
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2_out[8 + k]) - 
                          AB::Expr::from(local_slice[COL_CAP_CARRY_BASE + k])),
        );
    }
}

// Row-3 capacity-carry input: inputs[8..16] = carry columns
{
    let sel: AB::Expr = local_slice[COL_SEL_POW_P2].into();
    for k in 0..8 {
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2.inputs[8 + k]) - 
                          AB::Expr::from(local_slice[COL_CAP_CARRY_BASE + k])),
        );
    }
}

// Row-3 rate-slot absorption: output_cm_fe[3] + ONE pad + 6 zeros
{
    let sel: AB::Expr = local_slice[COL_SEL_POW_P2].into();
    let carry_cols = [local_slice[COL_CAP_CARRY_BASE + k] for k in 0..8];
    
    // inputs[0] = carry[0] + output_cm_fe[3]
    builder.assert_zero(
        sel.clone() * (AB::Expr::from(shared_p2.inputs[0]) - 
                      (AB::Expr::from(carry_cols[0]) + 
                       AB::Expr::from(local_slice[COL_W_OUTPUT_CM_FE0 + 3]))),
    );
    // inputs[1] = carry[1] + ONE (10* padding)
    builder.assert_zero(
        sel.clone() * (AB::Expr::from(shared_p2.inputs[1]) - 
                      (AB::Expr::from(carry_cols[1]) + 
                       AB::Expr::from(AB::F::from_u64(1)))),
    );
    // inputs[2..8] = carry[2..8] + 0 (zero-pads)
    for k in 2..8 {
        builder.assert_zero(
            sel.clone() * (AB::Expr::from(shared_p2.inputs[k]) - 
                          AB::Expr::from(carry_cols[k])),
        );
    }
}
```

**Plonky3 note**: The `shared_p2` reference is unsafe-cast from `&local_slice[N_ROW_SELECTORS..]`. The crate already does this pattern in `transfer_air.rs` (lines 965–980 for `spend_p2_group`); the same technique applies here.

---

## C. Per-Row Output Usage and Cross-Row Bindings

### C.1 CM Chain Output → PoW Chain Input

Row 1 perm2's output digest `state[0..4]` is the final `output_cm_fe`. This is read by Row 2 perm1 as `inputs[5..8]`, which are already constrained in section B above.

**No additional constraint needed** — the rate-slot absorption in Row 2's pinning block (section B) already references `COL_W_OUTPUT_CM_FE0..3`, which the witness trace populates from the computed `output_cm_fes` (mine_uno_witness.rs:292).

### C.2 PoW Chain Output → Public Input Binding

Row 3 perm2's output digest `state[0..4]` is the final `pow_hash_fe`. This must be bound to `PI[PI_POW_HASH_BASE..4]` on row 0 (the first-row public-input binding already in Phase 3a: mine_uno_air.rs:240–243).

**Row-0 binding** (already in Phase 3a, line 240–243):
```rust
first.assert_eq(
    local_slice[COL_W_POW_HASH_FE0 + k],
    pi_pow_hash[k],
);
```

**Witness consistency check** (in mine_uno_witness.rs::generate_trace, after Phase 3b):
Populate `COL_W_OUTPUT_CM_FE0..3` and `COL_W_POW_HASH_FE0..3` from the off-circuit helpers, then ensure the in-circuit permutation's output equals those values. This is validated by the test in section F below.

---

## D. Capacity Carry Constraints

The capacity-carry pattern requires three constraint blocks per chain:

### D.1 Output Binding: Perm1 Capacity → Carry Column

On the active perm1 row (row 0 or row 2), capture the post-permutation capacity slots into the shared carry-column proxy:

```
row0_output_cap[8..16] → COL_CAP_CARRY[0..8]
row2_output_cap[8..16] → COL_CAP_CARRY[0..8]  (overwrites if row 2 is active)
```

**Constraint form** (both rows, via the same selector-gated block):
```
sel_perm1 * (p2_out.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[8 + k] - local[COL_CAP_CARRY_BASE + k]) = 0
```

**Location in AIR eval**: Immediately after row-0 and row-2 rate-slot pinning blocks.

### D.2 Input Binding: Carry Column → Perm2 Capacity

On the active perm2 row (row 1 or row 3), pin the input capacity slots to the carry-column values:

```
COL_CAP_CARRY[0..8] → row1_input_cap[8..16]
COL_CAP_CARRY[0..8] → row3_input_cap[8..16]
```

**Constraint form** (both rows, via selector-gated blocks in section B):
```
sel_perm2 * (p2.inputs[8 + k] - local[COL_CAP_CARRY_BASE + k]) = 0
```

**Location in AIR eval**: Immediately before the rate-slot absorption block for each perm2 row.

### D.3 Transition Invariant: Capacity-Carry Columns are Constant

The carry-column proxy must be identical on every trace row (like all other proxies in Phase 3a, mine_uno_air.rs:175–219):

```
for k in 0..8:
    local[COL_CAP_CARRY_BASE + k] == next[COL_CAP_CARRY_BASE + k]  (transition constraint)
```

This is handled by extending the existing proxy-constancy loop in mine_uno_air.rs to include the new 8 carry columns. Because the carry values are pinned only on perm1 rows (0, 2), and the transition constraint propagates the value to all 8 rows, the perm2 rows (1, 3) trivially read the correct capacity-carry values.

---

## E. Trace Population Code Sketch

**In `mine_uno_witness.rs::MineUnoWitness::generate_trace`** (currently at lines 282–335), Phase 3b will:

1. **Compute the 4 Poseidon2-w16 permutation witnesses** via `p3_poseidon2_air::generate_trace_rows`:

```rust
// Row 0: CM perm-1
let mut state_cm_p1 = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
state_cm_p1[0..2].copy_from_slice(&d_fes);
state_cm_p1[2..6].copy_from_slice(&pk_d_fes);
state_cm_p1[6..8].copy_from_slice(&ivk_cm_fes[0..2]);
state_cm_p1[8..16].copy_from_slice(&uno_cm_v1_tag_block());

let p2_row_0 = generate_trace_rows::<
    Goldilocks,
    GenericPoseidon2LinearLayersGoldilocks,
    POSEIDON2_WIDTH_16,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS_16,
>(vec![state_cm_p1], &constants_16, 0).values;  // Returns Vec<Goldilocks> of length 316

// Row 1: CM perm-2, absorbing from perm-1 post[0..8] and new fes[8..14] + padding
let mut state_cm_p2 = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
// Retrieve post-state capacity from perm-1 (stored in P2Cols structure)
let p2_cols_0: MineP2Cols<Goldilocks> = p2_row_0.borrow();  // Cast Vec to struct
state_cm_p2[0..8].copy_from_slice(&p2_cols_0.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[0..8]);
state_cm_p2[0] += ivk_cm_fes[2];
state_cm_p2[1] += ivk_cm_fes[3];
state_cm_p2[2] += value_fe;
state_cm_p2[3..7].copy_from_slice(&rcm_fes);
state_cm_p2[7] += Goldilocks::ONE;
state_cm_p2[8..16].copy_from_slice(&p2_cols_0.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[8..16]);

let p2_row_1 = generate_trace_rows::<...>(vec![state_cm_p2], &constants_16, 0).values;

// Row 2: PoW perm-1
let mut state_pow_p1 = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
state_pow_p1[0] = Goldilocks::from_u64(u64::from(self.epoch));
state_pow_p1[1..5].copy_from_slice(&nonce_fes);
state_pow_p1[5..8].copy_from_slice(&output_cm_fes[0..3]);
state_pow_p1[8..16].copy_from_slice(&uno_mine_v1_tag_block());

let p2_row_2 = generate_trace_rows::<...>(vec![state_pow_p1], &constants_16, 0).values;

// Row 3: PoW perm-2
let mut state_pow_p2 = [Goldilocks::ZERO; POSEIDON2_WIDTH_16];
let p2_cols_2: MineP2Cols<Goldilocks> = p2_row_2.borrow();
state_pow_p2[0..8].copy_from_slice(&p2_cols_2.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[0..8]);
state_pow_p2[0] += output_cm_fes[3];
state_pow_p2[1] += Goldilocks::ONE;
state_pow_p2[8..16].copy_from_slice(&p2_cols_2.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[8..16]);

let p2_row_3 = generate_trace_rows::<...>(vec![state_pow_p2], &constants_16, 0).values;
```

2. **Copy permutation witnesses into the trace matrix** at rows 0–3:

```rust
for row in 0..MINE_TRACE_HEIGHT {
    let row_base = row * MINE_AIR_WIDTH;
    
    if row == 0 {
        values[row_base + N_ROW_SELECTORS..row_base + N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16]
            .copy_from_slice(&p2_row_0);
    } else if row == 1 {
        values[row_base + N_ROW_SELECTORS..row_base + N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16]
            .copy_from_slice(&p2_row_1);
    } else if row == 2 {
        values[row_base + N_ROW_SELECTORS..row_base + N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16]
            .copy_from_slice(&p2_row_2);
    } else if row == 3 {
        values[row_base + N_ROW_SELECTORS..row_base + N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16]
            .copy_from_slice(&p2_row_3);
    } else {
        // Padding rows 4–7: zero-input permutation
        let padding = generate_trace_rows::<...>(vec![[Goldilocks::ZERO; POSEIDON2_WIDTH_16]], &constants_16, 0).values;
        values[row_base + N_ROW_SELECTORS..row_base + N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16]
            .copy_from_slice(&padding);
    }
}
```

3. **Populate capacity-carry proxy columns** after the witness proxies are set (lines 320–331):

```rust
// Extract capacity from CM chain perm-1 and store in proxy (same for all rows via constancy).
let p2_cols_0: MineP2Cols<Goldilocks> = p2_row_0.borrow();
let cm_p1_cap = &p2_cols_0.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[8..16];

for row in 0..MINE_TRACE_HEIGHT {
    let row_base = row * MINE_AIR_WIDTH;
    for k in 0..8 {
        values[row_base + COL_CAP_CARRY_BASE + k] = cm_p1_cap[k];
    }
}
```

(Note: The PoW chain's capacity is captured from row 2; both chains' capacities happen to be identical *on the witness they construct*, but the AIR doesn't assume this — the carry columns just hold whichever capacity was active perm1's output, propagated by the transition constraint.)

---

## F. Off-Circuit Consistency Check

The witness-side computation must be bit-identical to the in-circuit permutation. Two helpers are already in place (mine_uno_witness.rs):

- **`poseidon2_cm_full_sponge`** (lines 210–253): Computes CM sponge via reference Poseidon2.
- **`poseidon2_mine_pow_hash`** (lines 423–447): Computes PoW sponge via reference Poseidon2.

**Unit test strategy** (add to `mine_uno_witness.rs::tests`):

```rust
#[test]
fn poseidon2_cm_sponge_matches_in_circuit_parity() {
    let w = MineUnoWitness::deterministic_valid(42, 0xDEAD_BEEF);
    let perm16 = default_goldilocks_poseidon2_16();
    
    // Off-circuit computation
    let output_cm_off_circuit = poseidon2_cm_full_sponge(
        &perm16,
        &w.d,
        &w.pk_d,
        &w.ivk_commitment,
        w.value_nano,
        &w.compute_rcm(),
    );
    
    // Trace generation populates this
    let trace = w.generate_trace();
    let trace_vals = &trace.values;
    
    // Extract the CM perm-2 output (state[0..4]) from row 1
    let row_1_base = 1 * MINE_AIR_WIDTH;
    let p2_cells = &trace_vals[row_1_base + N_ROW_SELECTORS..
                                row_1_base + N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16];
    let p2_cols: &MineP2Cols<Goldilocks> = unsafe {
        &*(p2_cells.as_ptr() as *const MineP2Cols<Goldilocks>)
    };
    
    let output_cm_in_circuit = [
        p2_cols.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[0],
        p2_cols.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[1],
        p2_cols.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[2],
        p2_cols.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[3],
    ];
    
    // Verify byte-parity
    assert_eq!(output_cm_off_circuit, output_cm_in_circuit,
        "CM sponge output mismatch between off-circuit and trace");
}

#[test]
fn poseidon2_pow_hash_matches_in_circuit_parity() {
    let w = MineUnoWitness::deterministic_valid(7, 0x1234_5678);
    let perm16 = default_goldilocks_poseidon2_16();
    
    // Off-circuit
    let output_cm = w.compute_output_cm_fes();
    let pow_hash_off_circuit = poseidon2_mine_pow_hash(
        &perm16,
        w.epoch,
        &w.nonce,
        &{
            let mut tmp = [0u8; 32];
            for i in 0..4 {
                tmp[i * 8..(i + 1) * 8]
                    .copy_from_slice(&output_cm[i].as_canonical_u64().to_le_bytes());
            }
            tmp
        },
    );
    
    // In-circuit (row 3, perm2 output)
    let trace = w.generate_trace();
    let trace_vals = &trace.values;
    let row_3_base = 3 * MINE_AIR_WIDTH;
    let p2_cells = &trace_vals[row_3_base + N_ROW_SELECTORS..
                                row_3_base + N_ROW_SELECTORS + MINE_POSEIDON2_COLS_16];
    let p2_cols: &MineP2Cols<Goldilocks> = unsafe {
        &*(p2_cells.as_ptr() as *const MineP2Cols<Goldilocks>)
    };
    
    let pow_hash_in_circuit = [
        p2_cols.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[0],
        p2_cols.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[1],
        p2_cols.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[2],
        p2_cols.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[3],
    ];
    
    assert_eq!(pow_hash_off_circuit, pow_hash_in_circuit,
        "PoW hash output mismatch between off-circuit and trace");
}
```

**Cross-crate test** (tosctl integration, if applicable):
Add a golden fixture test in tosctl that calls `poseidon2_cm_full_sponge_bytes` / `poseidon2_mine_pow_hash_bytes` and compares against tosctl's own PoW/CM derivation on the same witness. See `tosctl/uno/tests/phase4b_step3_sponge_parity.rs` for the pattern (transfer already has this).

---

## G. Risk Callouts and Common Mistakes

### G.1 Capacity-Slot Pinning Forgetting

**Risk**: Omitting the capacity-slot pinning blocks (sections D.1–D.2 or section B's `inputs[8..16]` bindings) leaves the capacity slots unconstrained. A malicious prover can then substitute arbitrary capacity values, breaking domain separation (the tag block loses its enforcing power) and allowing a fake sponge output.

**Mitigation**: 
- Section B enumerates *every* input slot pinning for all 4 rows.
- Section D.3 ensures carry columns are constant across rows.
- Transfer AIR does this correctly at lines 1042–1149 (tag pinning on rows 8+j, 12+j) and lines 1123–1149 (capacity carry).
- **Verification**: In the unit test (section F), assert that swapping a capacity byte in the witness fails the AIR verifier.

### G.2 Padding Byte Position Error

**Risk**: The 10* padding symbol is absorbed at `inputs[7]` (the last rate slot). Putting it elsewhere (e.g., `inputs[8]`) violates the sponge spec and produces a different hash.

**Mitigation**:
- Row 1 perm2: `inputs[7] = carry[7] + ONE` (not `inputs[6]`, not `inputs[8]`).
- Row 3 perm2: `inputs[1] = carry[1] + ONE` (all other inputs[2..8] are zero).
- Transfer AIR confirms this: line 1167 `inputs[7] = carry_rate[7] + ONE`.
- **Test**: `pow_hash_matches_in_circuit_parity` will fail if padding is off.

### G.3 Rate-Slot Absorption Order

**Risk**: Absorbing `[d, pk_d, ivk_cm_partial]` in the wrong order (e.g., pk_d before d) changes the sponge output, breaking the commitment proof.

**Mitigation**:
- Section B lists inputs[0..8] in order: d[0..2], pk_d[0..4], ivk_cm[0..2].
- Matches the `poseidon2_cm_full_sponge` helper: lines 226–231 pack in order `d, pk_d, ivk_cm, value, rcm`.
- **Test**: `poseidon2_cm_sponge_matches_in_circuit_parity` verifies the exact FE sequence.

### G.4 Cross-Row Capacity Carry Off-by-One

**Risk**: Pinning row 0 perm1 capacity to row 1 perm2 inputs, but accidentally reading row 0's rate slots (post[0..8]) or row 1's input rate instead of the explicit carry proxy. Misalignment breaks the iterated-sponge property.

**Mitigation**:
- The carry proxy (COL_CAP_CARRY_BASE[0..8]) is the *sole* vehicle for cross-row capacity passing.
- Output binding (D.1): `perm1.post[8..16] → carry_cols` on the active perm1 row.
- Input binding (D.2): `carry_cols → perm2.inputs[8..16]` on the active perm2 row.
- Capacity carry (D.3): transition constraint ensures carry_cols are constant across all 8 rows.
- Transfer AIR does this correctly: lines 1096–1121 (output/input binding), lines 1750–1770 (proxy constancy).
- **Test**: Verify carry value is written on row 0, read correctly on row 1 by checking constraint equations.

### G.5 Confusing `.post` (Full Round output) with Permutation Output

**Risk**: The Plonky3 `Poseidon2Cols` structure has many layers: `beginning_full_rounds[i].post`, `partial_rounds[i].post_sbox`, `ending_full_rounds[i].post`. The final permutation output is at `ending_full_rounds[HALF_FULL_ROUNDS - 1].post[0..4]`, not some other intermediate.

**Mitigation**:
- Sections C and E explicitly cite `ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[0..4]` for the output digest.
- Transfer AIR confirms this: line 1728, `merkle.ending_full_rounds[POSEIDON2_HALF_FULL_ROUNDS - 1].post[m]`.
- **Datasheet**: For width-16 with Transfer's params (HALF_FULL_FULL_ROUNDS=8, PARTIAL_ROUNDS=22), the ending_full_rounds array has 8 elements; index 7 is the final one.

### G.6 Tag-Block Byte Order

**Risk**: The tag blocks `uno_cm_v1_tag_block()` and `uno_mine_v1_tag_block()` are little-endian u64s packed into Goldilocks elements. Using big-endian or ASCII directly breaks domain separation.

**Mitigation**:
- Section B uses the helper functions directly: `uno_cm_v1_tag_block()` and `uno_mine_v1_tag_block()`.
- These are defined in `transfer_sponge.rs:130–160` and `mine_uno_witness.rs:393–404`.
- Transfer AIR uses them: line 1058, `let tag = uno_cm_v1_tag_block()`.
- **Parity**: The bytes `b"uno-cm-v1"` (9 bytes) fit in `[0]` (8 bytes) + `[1]` (1 byte); remaining `[2..7]` are zero. See `uno_cm_v1_tag_block()` implementation for exact layout.

### G.7 Witness Proxy Population Before P2 Permutation

**Risk**: The witness proxies (d_fes, pk_d_fes, etc.) must be populated before or simultaneously with the Poseidon2 trace generation. If they're left zero, the permutation will compute the wrong output, and the parity test in section F will fail.

**Mitigation**:
- Section E (trace population) shows that witness proxies are already filled (lines 320–331 in current mine_uno_witness.rs).
- The P2 permutation witnesses are computed from the same witness values (e.g., `d_fes` feeds both `state_cm_p1` and the proxy columns).
- **Test**: The unit test reads the proxy columns and compares them against the witness values.

### G.8 Carry-Column Constancy Not Enforced

**Risk**: If the carry proxy columns are not added to the transition-constraint proxy-constancy loop (mine_uno_air.rs line 182), the verifier can change them per row, breaking capacity passing.

**Mitigation**:
- Section D.3 requires extending the existing proxy array to include COL_CAP_CARRY_BASE[0..8].
- The updated `proxy_cols` array in the `Constraint 3` block must list all 28 + 8 = 36 proxy columns.
- Transfer AIR confirms this pattern: lines 1750–1770 (proxies are constant-across-rows).
- **Sanity check**: If N_CAP_CARRY_PROXY is not included in proxy-constancy loop, FRI-verification detects a row-transition inconsistency.

---

## H. Implementation Checklist

- [ ] Add `COL_CAP_CARRY_BASE`, `N_CAP_CARRY_PROXY` to `mine_uno_columns.rs`.
- [ ] Update `MINE_AIR_WIDTH` calculation in `mine_uno_columns.rs` to include 8 new columns.
- [ ] Add sanity asserts for capacity-carry column count.
- [ ] Extend witness-proxy constancy loop in `mine_uno_air.rs::Air::eval` to include 8 carry columns (Constraint 3 block).
- [ ] Add 8 constraint blocks in `mine_uno_air.rs::Air::eval` (Phase 3b TODO location at line 264):
  - Row-0 rate-slot pinning (d, pk_d, ivk_cm[0..2])
  - Row-0 capacity-output binding → carry columns
  - Row-1 capacity-input binding (from carry)
  - Row-1 rate-slot absorption (ivk_cm[2..4], value, rcm, ONE pad)
  - Row-2 rate-slot pinning (epoch, nonce, output_cm[0..3])
  - Row-2 capacity-output binding → carry columns
  - Row-3 capacity-input binding (from carry)
  - Row-3 rate-slot absorption (output_cm[3], ONE pad, zeros)
- [ ] Call `eval_poseidon2_16` delegation in `transfer_sponge.rs` (or inline the call if the crate re-exports it) for the shared block on every row.
- [ ] Implement `generate_trace_rows` calls in `mine_uno_witness.rs::MineUnoWitness::generate_trace` for rows 0–3 permutation witnesses.
- [ ] Populate capacity-carry proxy columns in `generate_trace` from row-0 and row-2 perm1 outputs.
- [ ] Add unit tests for `poseidon2_cm_sponge_matches_in_circuit_parity` and `poseidon2_pow_hash_matches_in_circuit_parity` in `mine_uno_witness.rs::tests`.
- [ ] Verify off-circuit helpers (`poseidon2_cm_full_sponge`, `poseidon2_mine_pow_hash`) match the witness trace via parity tests.

---

## References

- **transfer_air.rs** lines 1042–1259: Iterated-sponge wiring for output CM (the template for MineUno).
- **transfer_air.rs** lines 1289–1400: Nullifier iterated-sponge (secondary reference).
- **transfer_witness.rs** lines 844–872: `generate_trace_rows` API usage (applies directly to MineUno).
- **transfer_sponge.rs** lines 130–160: Tag-block helpers.
- **transfer_sponge.rs** lines 210–253: Reference implementation of 15-fe iterated sponge (poseidon2_cm_full_sponge).
- **mine_uno_columns.rs** lines 16–70: Trace layout and sponge structure.
- **mine_uno_air.rs** lines 146–156: Row-selector constraints (context for gating).
- **mine_uno_air.rs** lines 175–219: Witness-proxy constancy (to be extended).
- **mine_uno_witness.rs** lines 210–253: Off-circuit CM sponge helper.
- **mine_uno_witness.rs** lines 423–447: Off-circuit PoW sponge helper.
- **p3_poseidon2_air/src/columns.rs** lines 11–39: Poseidon2Cols and FullRound structure definitions.
- **Plonky3 docs**: See `p3_poseidon2_air::Poseidon2Cols`, `generate_trace_rows`, and `eval` delegation pattern.

