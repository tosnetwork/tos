# UNO MineUno AIR Constraints Specification

**Status**: Phase 1 — Design locked. Implementation pending (Phase 2).

**Task**: #12 — UNO MineUno AIR extension (wc=2 STARK)

**Source of truth**: `doc/Mining-Design.md` §"UNO Mining (wc=2 STARK / Privacy)"

**Data structures**: `uno/core/mine_uno.h`, `uno/core/mine_constants.h`,
`tosctl/uno/src/mine_uno.rs`, `tosctl/uno/src/mine_constants.rs`

---

## Overview

A `MineUno` transaction proves three things simultaneously inside a single
Plonky3 STARK:

1. The miner found a valid Poseidon2-over-Goldilocks nonce (PoW).
2. The minted note commitment is well-formed and binds the recipient address.
3. The minted amount matches the deterministic halving schedule and does not
   exceed the remaining supply cap.

The proof is ~200 KB (Plonky3 + FRI). Verify time is sub-second; prove time
is ~30–60 s on a modern CPU. The AIR is a sibling of the existing `Transfer`
AIR in `uno/plonky3-ffi/src/transfer_air.rs`.

### Notation

| Symbol | Meaning |
|---|---|
| `P` | Goldilocks prime: 2^64 − 2^32 + 1 |
| `PI[x]` | Public input field `x` (from `MineUnoPublicInputs`) |
| `W[x]` | Private witness field `x` (from `MineUnoWitness`) |
| `P2(tag, ...)` | Poseidon2 hash with domain-separation tag over Goldilocks |
| `fe(b)` | Pack byte array `b` into Goldilocks field elements (LE u64 limbs mod P) |
| `<<` | Right-shift for the halving table (integer arithmetic) |

---

## Constraint 1 — Proof of Work (PoW)

**Name**: `pow_hash_below_target`

### Plain English

The miner must produce a nonce `W[nonce]` such that the Poseidon2 hash of the
mining tag, the current epoch, the nonce, and the minted note commitment is
strictly less than the current difficulty target.

This is the CPU-only work function. The hash output is compared numerically
as a big-endian 256-bit integer against `PI[target]`.

### Mathematical formulation

```
h = P2("uno-mine-v1", fe(epoch), fe(W[nonce]), fe(PI[output_cm]))

Interpret h and PI[target] as big-endian 256-bit integers:
  h_int    = 4 Goldilocks elements packed LE → 32 bytes BE
  tgt_int  = PI[target] (32 bytes, big-endian)

Constraint: h_int < tgt_int   (numeric comparison, 256-bit unsigned)
```

The Plonky3 AIR encodes the numeric comparison as a range-check:
`tgt_int - h_int - 1 ≥ 0`, i.e., `tgt_int - h_int ∈ [1, 2^256 - 1]`.
This requires a 256-bit subtraction gadget (4 × 64-bit limbs with borrow
propagation) plus a 256-bit non-zero check.

### Witness vs public input dependencies

| Field | Source | Role |
|---|---|---|
| `W[nonce]` | Witness (private) | Hash preimage |
| `PI[epoch]` | Public input | Hash preimage |
| `PI[output_cm]` | Public input | Hash preimage |
| `PI[target]` | Public input | Threshold |
| `h` | Derived in-circuit | Hash output (constrained ≤ target) |

### Edge cases

- **Epoch = 0**: allowed; the hash still uses `fe(0)` as the epoch element.
- **Target = 0**: not permitted (no valid nonce could satisfy `h < 0`). The
  genesis initial target is 2^219 ≠ 0; retargeting must never produce 0.
  Phase 2 retargeting code must clamp to min target = 1.
- **All-zero nonce**: not special; the miner is free to use any 32-byte nonce.
  The hash domain-separation tag (`"uno-mine-v1"`) prevents trivial preimage
  reuse across epochs.

### Implementation file pointer (Phase 2)

`uno/plonky3-ffi/src/mine_uno_air.rs` — function `constrain_pow_hash_below_target`.
Uses Poseidon2 sponge from `uno/plonky3-ffi/src/permute.rs` (same primitives
as `transfer_air.rs`). 256-bit limb comparison gadget is new.

---

## Constraint 2 — Commitment Well-formedness

**Name**: `output_cm_well_formed`

### Plain English

The minted note commitment `PI[output_cm]` must be the canonical Poseidon2
hash of the recipient's address fields plus the minted value and a randomness
trapdoor derived from `W[rseed]`. This proves the miner generated a spendable
note for a valid recipient rather than an unspendable commitment.

### Mathematical formulation

```
rcm = P2("uno-rcm-v1", fe(W[rseed]))                              // §3.1

cm  = P2("uno-cm-v1",
         fe(W[recipient.d]),          // 11 B → 2 Goldilocks fes
         fe(W[recipient.pk_d]),       // 32 B → 4 fes
         fe(W[recipient.ivk_commitment]), // 32 B → 4 fes
         fe(W[value_nano]),           // u64 → 1 fe
         fe(rcm))                     // 32 B → 4 fes
                                      // Total: 15 fes → 1 width-16 permutation

Constraint: cm == PI[output_cm]
```

Packing convention is byte-identical to `transfer_air.rs` claim-6 / claim-2
(same `compute_note_commitment` formula, §3.2). The prover re-uses the same
Poseidon2 sub-circuit already proven in Transfer.

### Witness vs public input dependencies

| Field | Source | Role |
|---|---|---|
| `W[recipient.d]` | Witness | Address diversifier (11 B) |
| `W[recipient.pk_d]` | Witness | Compressed Ristretto pk_d (32 B) |
| `W[recipient.ivk_commitment]` | Witness | IVK binding (32 B) |
| `W[rseed]` | Witness | Randomness seed (32 B) |
| `W[value_nano]` | Witness | Mint amount |
| `PI[output_cm]` | Public input | Expected commitment |
| `rcm` | Derived in-circuit | Trapdoor from rseed |

### Edge cases

- **rseed = 0^32**: valid (zero is a legal Goldilocks field element packed
  vector); produces a deterministic `rcm`. Mining clients SHOULD use a fresh
  random `rseed` per solve to avoid note-commitment collisions if the same
  epoch is solved twice (which cannot happen on-chain, but could happen in
  local testing).
- **ivk_commitment = 0^32**: technically valid for the arithmetic but indicates
  a degenerate address. Constraint 6 independently validates address well-form.
- **value_nano = 0**: rejected by Constraint 3 (halving table gives non-zero
  value for every era where `mine_remaining > 0`; era ≥ 36 gives 0 value which
  means mining is economically worthless but not forbidden by the circuit).

### Implementation file pointer (Phase 2)

`uno/plonky3-ffi/src/mine_uno_air.rs` — function `constrain_output_cm`.
Re-uses `transfer_sponge.rs` `poseidon2_compress_15_to_4` sub-circuit.

---

## Constraint 3 — Halving Table

**Name**: `value_matches_halving_schedule`

### Plain English

The minted value must exactly match the deterministic Bitcoin-clone halving
schedule for the current epoch. This prevents a miner from claiming more (or
less) UNO than the schedule allows.

The schedule is baked into the AIR as constants derived from
`mine_constants::mine_reward_for_epoch` — it is NOT read from chain state.
This is safe because the halving schedule is a pure function of epoch
(no governance can change it without a scheme_id bump / hard fork).

### Mathematical formulation

```
era          = PI[epoch] / kEraSize             // integer quotient
reward(era)  = kInitMineReward >> era           // right-shift
               = 0  when era ≥ 64              // saturates to zero

Constraint: W[value_nano] == reward(PI[epoch])
```

In-circuit, the shift is implemented as a look-up table over a small range:
the AIR uses a preprocessed column indexed by `era mod 64` containing the 64
non-zero rewards (era 0..35 yield non-zero values; era 36..63 yield 0). Since
`era < 2^32 / 210000 ≈ 20000`, a full 64-row table is affordable.

### Witness vs public input dependencies

| Field | Source | Role |
|---|---|---|
| `PI[epoch]` | Public input | Era derivation |
| `W[value_nano]` | Witness (= `PI[value_nano]`) | Claimed mint amount |
| `kEraSize`, `kInitMineReward` | AIR constants | Halving schedule |

`value_nano` appears in both the witness and the public inputs — they are
the same value; the circuit enforces `W[value_nano] == PI[value_nano]`.

### Edge cases

- **Exact era boundary (epoch = k × 210,000)**: Constraint 3 uses integer
  division `era = epoch / 210000`. At epoch 210,000, `era = 1` and the
  reward drops from 50 UNO to 25 UNO. This is correct by design (Bitcoin-clone).
  The retargeting at this boundary is handled separately in chain state
  (Phase 2 `apply_mine_uno`).
- **Era ≥ 36 (reward = 0)**: The circuit accepts `value_nano = 0` for these
  eras. The chain apply step (Phase 2) may additionally require
  `mine_remaining > 0` to even accept a MineUno tx; zero-reward mining
  produces a note commitment with no economic value, which is valid but useless.

### Implementation file pointer (Phase 2)

`uno/plonky3-ffi/src/mine_uno_air.rs` — function `constrain_halving_table`.
Preprocessed table in `mine_uno_witness.rs::build_halving_table_column`.

---

## Constraint 4 — Conservation

**Name**: `remaining_conservation`

### Plain English

The total minted supply counter must decrease by exactly the minted value.
In other words, `remaining_pre - value_nano = remaining_post` with no rounding
or truncation.

### Mathematical formulation

```
Constraint: PI[remaining_pre] - PI[value_nano] == PI[remaining_post]

Equivalently: PI[remaining_pre] == PI[remaining_post] + PI[value_nano]
```

This is a single field-element equality on row 0 of the AIR (degree 1). All
three values are 64-bit unsigned integers; the subtraction must be checked for
underflow (Constraint 5). Because `value_nano < 2^64` and
`remaining_pre < 2^64`, the equality fits within a single Goldilocks element
(Goldilocks p ≈ 2^64 − 2^32 + 1 > 2^63; the difference could wrap, so the
underflow check is essential).

### Witness vs public input dependencies

All three fields are public inputs; no private witness dependency.

| Field | Source | Role |
|---|---|---|
| `PI[remaining_pre]` | Public input | Supply before tx |
| `PI[value_nano]` | Public input | Mint amount |
| `PI[remaining_post]` | Public input | Supply after tx |

### Edge cases

- **remaining_pre = value_nano**: `remaining_post = 0`. Valid — means the very
  last UNO was just minted. After this tx, no further MineUno txs can succeed
  because remaining_post = 0 and value_nano > 0 for any era with a reward.
- **remaining_pre = 0**: rejected by Constraint 5 (underflow check ensures
  `remaining_pre >= value_nano`, i.e., 0 >= value_nano only if value_nano = 0,
  which requires era ≥ 36).

### Implementation file pointer (Phase 2)

`uno/plonky3-ffi/src/mine_uno_air.rs` — single row-0 equality gate
`constrain_remaining_conservation`. Trivial: one column sum constraint.

---

## Constraint 5 — Cap (No Over-Mint)

**Name**: `remaining_no_underflow`

### Plain English

The minted value must not exceed the remaining supply. Equivalently,
`remaining_post` must be non-negative (no underflow in unsigned arithmetic).
This prevents a miner from forging supply beyond the 21 M UNO cap.

### Mathematical formulation

```
Constraint: PI[remaining_pre] >= PI[value_nano]
```

In a 64-bit unsigned context this is equivalent to:
```
PI[remaining_pre] - PI[value_nano] does NOT wrap (no borrow in subtraction)
```

Implementation: a 64-bit range check on the difference
`PI[remaining_pre] - PI[value_nano]`. Since both operands are `< 2^64`, the
difference fits in 64 bits iff `remaining_pre >= value_nano`. The AIR uses
the same u16-limb range decomposition as the Transfer AIR's value range check
(Claim 5 / Claim 7 in `transfer_air.rs`).

### Witness vs public input dependencies

| Field | Source | Role |
|---|---|---|
| `PI[remaining_pre]` | Public input | Must be ≥ value_nano |
| `PI[value_nano]` | Public input | Must be ≤ remaining_pre |

### Edge cases

- **remaining_pre < value_nano**: the tx is invalid. The chain apply step
  (Phase 2 `apply_mine_uno`) performs the off-circuit check
  `check_conservation(pi)` before calling the verifier. If the
  fast-fail passes but the AIR check fails, the proof is rejected as
  soundness-failing (should not happen if the prover is honest).
- **remaining_pre = 0, value_nano = 0 (era ≥ 36)**: subtraction is 0 − 0 = 0,
  range check passes. The tx is economically worthless but not invalid.

### Implementation file pointer (Phase 2)

`uno/plonky3-ffi/src/mine_uno_air.rs` — function `constrain_remaining_no_underflow`.
Shares `Range16Air` cross-AIR LogUp table with Transfer (already in
`range16_air.rs`).

---

## Constraint 6 — Address Well-formedness

**Name**: `recipient_address_valid`

### Plain English

The recipient address fields must have the correct byte lengths. This prevents
degenerate note commitments whose address cannot be decoded by any wallet.

The three checked fields are:
- `d` (diversifier): exactly 11 bytes.
- `pk_d` (Ristretto255 point): exactly 32 bytes.
- `ivk_commitment`: exactly 32 bytes.
- `pk_mlkem` (ML-KEM-768 public key): exactly 1184 bytes.

### Mathematical formulation

The length constraints are enforced structurally by the witness encoding:
the AIR allocates exactly the right number of field elements for each field
(fixed column widths), so an honest prover cannot fit a malformed-length
field into the trace. The constraint is implicit in the column layout rather
than an explicit polynomial equality.

The only field that requires explicit range-checking is `pk_mlkem` — it is
the largest field (1184 bytes = 148 × u64 field elements). The AIR encodes
`pk_mlkem` as 148 Goldilocks elements, each in canonical range `[0, P)`.
The Constraint 2 commitment hash absorbs the first portion of `pk_mlkem` via
the `ivk_commitment` field (which is 32 bytes derived from the full key
off-circuit); the full `pk_mlkem` is not absorbed in-circuit because it would
require 148 field elements in the sponge and dominate trace size.

**In-circuit check (simplified)**:
```
For each of the packed field elements of d, pk_d, ivk_commitment:
  fe_i ∈ [0, P)   // canonical Goldilocks range
// pk_mlkem: validated off-circuit by the chain (Phase 2 apply step)
//           checking pk_mlkem.len() == 1184
```

The full ML-KEM-768 key validity (i.e., that `pk_mlkem` encodes a valid
lattice key) is NOT checked in-circuit — checking this would require a
full ML-KEM key-expansion in a STARK, which is prohibitively expensive.
The constraint only checks field size; a note minted with an invalid `pk_mlkem`
simply cannot be decrypted by any wallet (economic incentive is sufficient
for miners to use valid keys since they want to spend the minted note).

### Witness vs public input dependencies

| Field | Source | Role |
|---|---|---|
| `W[recipient.d]` | Witness | Must be 11-byte canonical |
| `W[recipient.pk_d]` | Witness | Must be 32-byte canonical |
| `W[recipient.ivk_commitment]` | Witness | Must be 32-byte canonical |
| `W[recipient.pk_mlkem]` | Witness | Off-circuit size check only |

### Edge cases

- **pk_d not on curve**: not checked in-circuit. A miner who uses an invalid
  Ristretto255 point gets an unspendable note (the wallet cannot decode it).
- **pk_mlkem with wrong length**: caught by the off-circuit apply step checking
  `recipient.pk_mlkem.len() == 1184` before calling the verifier.
- **All-zero diversifier d**: valid (zero is a legal diversifier for genesis
  addresses and test vectors); Constraint 2 still produces a well-defined cm.

### Implementation file pointer (Phase 2)

`uno/plonky3-ffi/src/mine_uno_air.rs` — implicit via column layout in
`mine_uno_witness.rs`. Explicit range checks piggyback on `Range16Air`.

---

## Race Protection (Non-constraint, Chain-level)

**Not an AIR constraint** — enforced by the chain's apply step.

### Description

Multiple miners may solve the same epoch concurrently. The MineUno tx includes
`PI[remaining_pre]` as a public input. The chain's `apply_mine_uno` function
(Phase 2, `uno/core/compute-phase.cpp`) checks:

```
assert chain_state.mine_remaining == PI[remaining_pre]
```

If two miners solve the same epoch, one will be included first in a block.
After the first tx is applied, `mine_remaining` decreases by `value_nano`.
The second miner's tx will then fail the `remaining_pre` check because
`chain_state.mine_remaining ≠ PI[remaining_pre]` (the first solve already
decremented it).

The second miner must re-compute a new proof for the new epoch (epoch + 1)
and the new remaining value. This race-protection mechanism does NOT require
any AIR constraint — it is a purely chain-side check before the verifier is
invoked.

### Properties

- **Monotone decrease**: `mine_remaining` only decreases. No tx can increase it.
- **Epoch advance**: each successful MineUno increments `mine_epoch` by 1.
  The epoch is therefore a strictly increasing counter that also serves as
  the race-resolution nonce.
- **Latency**: miners with ~30–60 s prove time will see ~5–10% of solves
  lose the race during peak periods. This is acceptable (comparable to
  orphan rates in Bitcoin during early high-variance mining).

---

## Implementation Phase 2 Plan

Files to create in `uno/plonky3-ffi/src/`:

| File | Contents |
|---|---|
| `mine_uno_air.rs` | AIR struct + `Air` trait impl; 6 constraints encoded as polynomial identity rows |
| `mine_uno_witness.rs` | `MineUnoWitness` trace-generation; `build_mine_uno_trace()` |
| `mine_uno_prover.rs` | Entry point `prove_mine_uno(witness) -> Vec<u8>` (FFI exposed) |
| `mine_uno_verifier.rs` | Entry point `verify_mine_uno(proof, pi) -> bool` (FFI exposed) |

Files to modify:

| File | Change |
|---|---|
| `uno/plonky3-ffi/src/lib.rs` | Register `mod mine_uno_air`, `mod mine_uno_witness`, etc.; expose C ABI symbols |
| `uno/plonky3-ffi/include/uno_plonky3_ffi.h` | Add `uno_mine_uno_prove()` and `uno_mine_uno_verify()` C declarations |
| `uno/core/compute-phase.cpp` | Add `apply_mine_uno()`: off-circuit checks + FFI verify call + state update |
| `uno/core/mine_uno.cpp` | Implement `decode_mine_uno()`, `encode_mine_uno()`, `canonical_mine_uno_hash()` |
| `uno/core/cell-state.cpp` | Extend shard-state serializer to persist `mine_remaining`, `mine_epoch`, `mine_target`, `halving_era` |
| `uno/core/genesis.cpp` | Initialize mining state fields in `build_zerostate_state()` |
| `uno/core/state.h` | Uncomment the TODO block and add the four mining fields to `UnoShardState` |
| `tosctl/uno/src/mine_uno.rs` | Replace `encode_mine_uno_wire` / `decode_mine_uno_wire` stubs with real BoC codec |
| `tosctl/uno/src/main.rs` | Add `tosctl-uno mine` subcommand (CPU-threaded nonce search + prove + submit) |

### Estimated effort (from `doc/Mining-Design.md` Phase C)

- AIR columns + constraints: 2–3 weeks
- Prover/verifier FFI wiring: 1 week
- Chain-side apply + state: 3 days
- `tosctl uno mine` client: 1 week
- Zerostate wiring + end-to-end testnet test: 1 week

**Total Phase 2: ~4–6 weeks** (single developer, not parallelized).

---

## Cross-reference

- `doc/Mining-Design.md` §"UNO Mining" — parameter source of truth, halving math, race protection narrative
- `uno/core/mine_constants.h` — C++ constants: `kEraSize`, `kInitMineReward`, `kMineHashTag`, `mine_reward_for_era()`
- `uno/core/mine_uno.h` — C++ structs: `MineUnoWitness`, `MineUnoPublicInputs`, `MineUno`
- `tosctl/uno/src/mine_constants.rs` — Rust mirror of `mine_constants.h`
- `tosctl/uno/src/mine_uno.rs` — Rust mirror of `mine_uno.h`
- `uno/plonky3-ffi/src/transfer_air.rs` — reference implementation for Transfer AIR structure (MineUno AIR follows same pattern)
