# UNO MineUno C++ Integration Specification (Phase 2)

**Date**: 2026-04-24  
**Phase**: Phase 2 — C++ `uno/core/` implementation & compute-phase wiring  
**Status**: SPEC (not yet implemented)

---

## §1. Wire Format for `decode_mine_uno` / `encode_mine_uno`

### 1.1 Byte-Level Layout

The MineUno transaction envelope occupies a root cell with inline header and references per the layout in `mine_uno.h` (lines 179–191):

```
Inline header (99 bytes total):
  [0]    uint8_t     tx_kind = 0x02             (1 byte)
  [1]    uint8_t     version = 1                (1 byte)
  [2]    uint8_t     scheme_id = 0x01           (1 byte)
  [3..7] uint32_t    chain_id                   (4 bytes, big-endian)
  [8..12] uint32_t   epoch (public_inputs)      (4 bytes)
  [13..45] bytes[32] target (public_inputs)     (32 bytes, big-endian)
  [46..54] uint64_t  value_nano (public_inputs) (8 bytes)
  [55..87] bytes[32] output_cm (public_inputs)  (32 bytes)
  [88..96] uint64_t  remaining_pre              (8 bytes)
  [97..105] uint64_t remaining_post             (8 bytes)

Total inline: 106 bytes (note: 105 per spec comment, verify alignment).

Cell references:
  ref[0] → zk_proof (Plonky3 STARK proof; chunk-tree layout per §4.1a)
```

### 1.2 Discriminator Byte

The first byte (`tx_kind`) serves as the dispatch lever:
- **0x01**: Existing Transfer (implied; Transfer wire v1 has no explicit discriminator)
- **0x02**: MineUno (new; explicitly present at offset 0)
- **Other**: Reject (unknown tx kind)

### 1.3 Public Inputs Block (MineUnoPublicInputs wire format)

The 9 public-input fields (96 bytes when serialized for Plonky3 verifier):
- `epoch` (u32): 4 bytes
- `target` (32 bytes): big-endian 256-bit threshold
- `value_nano` (u64): 8 bytes
- `output_cm` (32 bytes): the commitment being minted
- `remaining_pre` (u64): chain's `mine_remaining` *before* this tx
- `remaining_post` (u64): chain's `mine_remaining` *after* this tx

All multi-byte fields use **big-endian** byte order on the wire (matching Transfer's anchor, fee, and similar fields). The Plonky3 verifier receives these 96 bytes as a serialized `Plonky3PublicInputs` struct (see `uno_plonky3_ffi.h` lines 880–911).

### 1.4 Proof Blob Layout

The `zk_proof` cell reference points to a **postcard-encoded** Plonky3 STARK proof blob. The proof encoding format is:

```
[variable-length STARK proof bytes]
```

This is a binary encoding managed by the Rust Plonky3 FFI layer (`uno_mine_uno_prove` / `uno_mine_uno_verify` in `uno_plonky3_ffi.h` lines 1204–1216). The C++ side:
1. Extracts the cell reference
2. Traverses chunk-tree if needed to collect all bytes
3. Passes the byte range to `uno_mine_uno_verify` as a `Plonky3ProofBytes` struct (ptr, len)

### 1.5 Cross-Reference to Rust `mine_uno.rs`

All field names, byte widths, and ordering in `MineUno` struct **must match byte-for-byte** with the Rust mirror in `tosctl/uno/src/mine_uno.rs`. Any divergence is a consensus fault. Key invariants:
- `version = 1` (future versions bump this)
- `scheme_id = 0x01` (Plonky3 / Goldilocks / Poseidon2)
- `tx_kind = 0x02` (distinguishes MineUno from Transfer)
- All 256-bit fields in big-endian byte order
- All 64-bit integer fields in big-endian byte order

---

## §2. Canonical MineUno Hash (`canonical_mine_uno_hash`)

### 2.1 Purpose

The canonical hash is used for:
- **Mempool deduplication**: prevent the same tx from appearing twice in the mempool/pending pool
- **Anti-replay**: miners cannot resubmit an old tx that already landed in-block
- **Transaction identification**: logs, RPC results, and subscription channels

### 2.2 Hash Computation

Per `mine_uno.h` lines 208–210:

```
canonical_mine_uno_hash(tx) = BLAKE3(
  tx_kind ‖ version ‖ scheme_id ‖ chain_id ‖ 
  epoch ‖ target ‖ value_nano ‖ output_cm ‖ 
  remaining_pre ‖ remaining_post
)
```

**Byte order**: All multi-byte fields use **big-endian** serialization, matching Transfer's `canonical_tx_hash()` pattern in `transaction.cpp`.

### 2.3 Implementation Pattern (Mirrored from Transfer)

The Transfer implementation in `transaction.cpp` (around line 400–450) shows the pattern:

1. **Reserve a buffer** for the preimage (total: 1 + 1 + 1 + 4 + 4 + 32 + 8 + 32 + 8 + 8 = 99 bytes)
2. **Append each field** using helper lambdas:
   - `append_byte()` for single bytes
   - `append_be_u32()` for 32-bit integers
   - `append_be_u64()` for 64-bit integers
   - `append_bytes()` for 32-byte arrays (target, output_cm)
3. **Hash the buffer** using TOS's BLAKE3 wrapper (e.g., `td::Bits256` from util/UInt.h)

**Signature**:
```cpp
td::Bits256 canonical_mine_uno_hash(const MineUno& tx) noexcept;
```

Return type matches Transfer's `canonical_tx_hash()` return type.

---

## §3. `apply_mine_uno(UnoState& state, const MineUno& tx)` Semantics

### 3.1 Sequential Verification & Application Order

Apply a MineUno tx in this exact order. **All checks run before any state mutation** (verify-before-mutate invariant). Each failure returns immediately with the corresponding `VerifyResult` enum value.

#### Step 1: Epoch Race Protection
**Check**: `tx.public_inputs.epoch == state.mine_epoch`

If mismatch, another miner solved first (race condition). Reject with `VerifyResult::EpochRaceDetected` (new enum value, TBD error code).

**Rationale**: The proof is tied to a specific epoch via the AIR public inputs. If chain state has already advanced to epoch+1, this proof is stale.

#### Step 2: Remaining Balance Race Protection
**Check**: `tx.public_inputs.remaining_pre == state.mine_remaining`

If mismatch, another tx was applied first, draining the available supply. Reject.

**Rationale**: Conservation in the AIR ensures `remaining_post = remaining_pre - value_nano`. If state has already accepted a tx, `remaining_pre` no longer matches.

#### Step 3: FFI Verify Call
**Call**: `uno_mine_uno_verify(proof_bytes, public_inputs_bytes)`

This invokes the Rust Plonky3 verifier (async safe, may be parallel across multiple CPU cores). On non-zero return, reject with `VerifyResult::BadPlonky3Proof`.

**Input construction**:
- `proof_bytes`: a `Plonky3ProofBytes` struct wrapping the postcard-encoded STARK proof
- `public_inputs_bytes`: a `Plonky3PublicInputs` struct wrapping 96 bytes of serialized PI:
  - 4 bytes: epoch (BE)
  - 32 bytes: target (BE)
  - 8 bytes: value_nano (BE)
  - 32 bytes: output_cm
  - 8 bytes: remaining_pre (BE)
  - 8 bytes: remaining_post (BE)

**Signature** (from `uno_plonky3_ffi.h` line 1216):
```cpp
int32_t uno_mine_uno_verify(Plonky3ProofBytes proof, 
                            Plonky3PublicInputs public_inputs);
```

Returns 0 on success, non-zero on verify failure.

#### Step 4: Target Check (PoW Hash Threshold)
**Parse**: Extract the PoW hash result from the proof public inputs

The AIR constraint 1 computes:
```
pow_hash_fe = Poseidon2("uno-mine-v1" ‖ epoch ‖ nonce ‖ output_cm)
```

This hash is 4 field elements (Goldilocks, 64-bit each). The verifier constraint ensures the hash is less than the target:
```
pow_hash_fe (as 4 × u64) < target (as 4 × u64, big-endian)
```

**C++ check** (redundant with AIR, but good for robustness):
- Parse `pow_hash_fe[0..4]` from the Goldilocks limbs in the proof witness
- Reassemble as big-endian 256-bit integer
- Compare numerically against `state.mine_target` (also 256-bit BE)
- If pow_hash >= target, reject with `VerifyResult::BadPoWHash` (new error, TBD code)

**Note**: The AIR already enforces this. This check is a defensive layer for off-circuit validation.

#### Step 5: Conservation Check (Redundant with AIR)
**Check**: `remaining_post + value_nano == remaining_pre` and `remaining_pre >= value_nano` (no underflow)

Use the inline helper `check_conservation(tx.public_inputs)` from `mine_uno.h` line 247.

**Rationale**: AIR constraint 4–5 already enforces this. The redundant off-circuit check is defensive and cheap.

#### Step 6: Halving Table Lookup & Value Validation
**Check**: `value_nano == mine_reward_for_epoch(epoch)`

Use the constexpr function from `mine_constants.h` line 143:
```cpp
constexpr uint64_t mine_reward_for_epoch(uint32_t epoch) noexcept
```

Compute the expected reward for `epoch`, compare against `tx.public_inputs.value_nano`. If mismatch, reject with `VerifyResult::InvalidHalvingReward`.

**Rationale**: AIR constraint 3 (Halving Table in `uno-mine-air-constraints.md`) also enforces this. The off-circuit check is cheap and catches obvious tampering.

**Halving boundaries**: Epoch 0–209999 → era 0 → 50 UNO. At epoch 210000, era flips to 1 → 25 UNO. Use `era_from_epoch()` from `mine_constants.h` line 138.

#### Step 7: Output Commitment Uniqueness (Collision Check)
**Check**: `output_cm` must not already exist in the commitment tree

Query the state's commitment tree (via `UnoState::*` interface) to ensure the new output commitment does not duplicate an existing commitment. If collision detected, reject with `VerifyResult::DuplicateCommitment`.

**Implementation**: Call `state.commitment_tree->contains(output_cm)` or similar API (details TBD by Agent 2). If found, reject. If not found, proceed to apply.

#### Step 8: State Update — Mutations
On all checks passing, apply these state mutations **in order**:

1. **Advance epoch**: `state.mine_epoch += 1`
2. **Update remaining**: `state.mine_remaining = tx.public_inputs.remaining_post`
3. **Append commitment**: `state.append_commitment(tx.public_inputs.output_cm)`
4. **LT advance**: Increment the ledger-timestamp / logical-time counter (if applicable; see §5.7 of `uno-workchain.md`)
5. **(Optional) Retarget**: See §6 below

#### Step 9: Block-Filter Accumulation & Stats (Mirrored from Transfer)
Per `compute-phase.cpp` line 165–172:
```cpp
state.accumulate_filter_tag(output_filter_tag);  // TBD: filter tag for MineUno
state.bump_stats(fee, 1);  // MineUno emits 1 output (the minted note)
```

**Fee**: MineUno has no explicit fee field (miners implicitly pay zero; they're compensated by the minting itself). Set `fee = 0` in stats.

### 3.2 Error Handling

All verification steps must return a deterministic error code. Extend `VerifyResult` enum (from `compute-phase.h` lines 91–114) with new MineUno-specific values:

```cpp
enum class VerifyResult : int {
    Ok = 0,
    // ... existing Transfer errors (1–40) ...
    // New MineUno errors (41–60 reserved):
    EpochRaceDetected      = 41,
    RemainingRaceDetected  = 42,
    BadPoWHash             = 43,
    InvalidHalvingReward   = 44,
    DuplicateCommitment    = 45,
    // ... room for future (46–60) ...
};
```

Each error maps to a distinct `cp.exit_code` in the host-chain `ComputePhase` record.

---

## §4. Compute-Phase Dispatch Integration

### 4.1 Where to Add the Dispatch Branch

File: `/home/tomi/tos/uno/core/compute-phase.cpp`

Function: `run_compute_phase()` (line 207–315)

**Current flow** (lines 219–239):
```cpp
// Decode Transfer
auto decoded = decode_transfer(in_msg_body);
if (auto* err_ptr = std::get_if<TransferDecodeError>(&decoded)) {
    // handle error
}
Transfer tx = std::move(std::get<Transfer>(decoded));
```

**New flow**:
```cpp
// --- Step 0: Peek at discriminator byte to dispatch ---
auto discriminator = peek_byte_at_offset_0(in_msg_body);

if (discriminator == 0x01) {
    // Existing Transfer path
    auto decoded = decode_transfer(in_msg_body);
    if (auto* err_ptr = std::get_if<TransferDecodeError>(&decoded)) {
        // handle error
    }
    Transfer tx = std::move(std::get<Transfer>(decoded));
    // ... rest of Transfer apply ...
} else if (discriminator == 0x02) {
    // New MineUno path
    auto decoded = decode_mine_uno(in_msg_body);
    if (auto* err_ptr = std::get_if<MineUnoDecodeError>(&decoded)) {
        // handle error
    }
    MineUno tx = std::move(std::get<MineUno>(decoded));
    uint64_t gas_used = compute_gas_used_mine_uno(tx);
    VerifyResult vr = apply_mine_uno(state, tx);
    // ... handle result ...
} else {
    // Reject unknown tx kind
}
```

### 4.2 Function Signatures

**Decoder**:
```cpp
MineUnoDecodeResult decode_mine_uno(vm::CellSlice body) noexcept;
```

Returns a variant `std::variant<MineUno, MineUnoDecodeError>`.

**Apply** (combines verify + apply into one):
```cpp
VerifyResult apply_mine_uno(UnoState& state, const MineUno& tx) noexcept;
```

Returns a `VerifyResult` enum. On `Ok`, state is mutated; on any error, state is unchanged (verify-before-mutate).

**Gas costing**:
```cpp
uint64_t compute_gas_used_mine_uno(const MineUno& tx) noexcept;
```

Suggest: `kFixedMineVerifyCost (40k) + kPerByteCostMine (1) * wire_size_bytes`. MineUno has no spends/outputs vector, so per-spend/per-output costs don't apply. Adjust constants per benchmarking.

### 4.3 Batch Collator-Facing Function Extension

File: `/home/tomi/tos/uno/core/compute-phase.cpp`

Function: `run_compute_phase_batch()` (line 334–380)

**Current pattern**: Dispatches all N transfers through parallel verify, then applies accepted ones serially.

**Extension for MineUno**: The same logic applies:
1. **Parallel verify**: Each tx (Transfer or MineUno) runs through its verifier
2. **Serial apply**: Accepted txs are applied in declared order, with live race-condition re-checks

The dispatcher needs to route each tx to the correct verifier:
```cpp
for (size_t i = 0; i < n_txs; ++i) {
    uint8_t discriminator = peek_discriminator(txs[i]);
    if (discriminator == 0x02) {
        results[i] = verify_mine_uno(state, txs[i]);
    } else {
        results[i] = verify_transfer(state, txs[i]);
    }
}
```

Then the serial apply path:
```cpp
for (size_t i = 0; i < n_txs; ++i) {
    if (results[i] == VerifyResult::Ok) {
        // Re-check live race conditions (e.g., epoch/remaining)
        if (txs[i].is_mine_uno()) {
            if (txs[i].public_inputs.epoch != state.mine_epoch ||
                txs[i].public_inputs.remaining_pre != state.mine_remaining) {
                results[i] = VerifyResult::EpochRaceDetected;  // or Remaining...
                continue;
            }
        }
        // Apply
        if (txs[i].is_mine_uno()) {
            apply_mine_uno(state, txs[i]);
        } else {
            apply_transfer(state, txs[i]);
        }
    }
}
```

---

## §5. C++ FFI Binding for `uno_mine_uno_verify`

### 5.1 Plonky3 Verifier Handle & Initialization

File: `/home/tomi/tos/uno/crypto/plonky3-verifier.h` (already exists for Transfer)

The `Plonky3Verifier` class wraps the Rust FFI. For MineUno, extend it:

```cpp
class Plonky3Verifier {
public:
    Plonky3Verifier();
    ~Plonky3Verifier();
    
    // Existing Transfer verifier
    bool verify(td::Slice proof, const Plonky3PublicInputs& pi) const noexcept;
    
    // NEW: MineUno verifier
    bool verify_mine_uno(td::Slice proof, const Plonky3PublicInputs& pi) const noexcept;
};
```

### 5.2 Plonky3PublicInputs & Plonky3ProofBytes Structs

**From** `uno_plonky3_ffi.h` lines 873–911:

```cpp
typedef struct {
    const uint8_t *ptr;   // Pointer to proof bytes
    uintptr_t len;        // Length in bytes
} Plonky3ProofBytes;

typedef struct {
    const uint8_t *ptr;   // Pointer to PI bytes
    uintptr_t len;        // Length in bytes (should be 96 for MineUno)
} Plonky3PublicInputs;
```

These are **borrowed** slices; the Rust side reads but does not retain.

**C++ wrapper construction**:
```cpp
auto build_mine_uno_pi_bytes(const MineUno& tx) noexcept 
    -> std::vector<uint8_t> 
{
    std::vector<uint8_t> buf;
    buf.reserve(96);
    
    // epoch (u32, BE)
    append_be_u32(buf, tx.public_inputs.epoch);
    
    // target (32 bytes, BE)
    buf.insert(buf.end(), tx.public_inputs.target.begin(), 
               tx.public_inputs.target.end());
    
    // value_nano (u64, BE)
    append_be_u64(buf, tx.public_inputs.value_nano);
    
    // output_cm (32 bytes)
    buf.insert(buf.end(), tx.public_inputs.output_cm.begin(),
               tx.public_inputs.output_cm.end());
    
    // remaining_pre (u64, BE)
    append_be_u64(buf, tx.public_inputs.remaining_pre);
    
    // remaining_post (u64, BE)
    append_be_u64(buf, tx.public_inputs.remaining_post);
    
    assert(buf.size() == 96);
    return buf;
}
```

### 5.3 FFI Entry Point

**From** `uno_plonky3_ffi.h` line 1216:

```c
int32_t uno_mine_uno_verify(Plonky3ProofBytes proof, 
                            Plonky3PublicInputs public_inputs);
```

**Return codes**:
- `0` (kOk): Proof valid
- `1` (kProofDecodeFailed): Postcard decode failed
- `2` (kVerifyFailed): STARK verify returned error
- Non-zero: Other errors

**C++ wrapper**:
```cpp
bool verify_mine_uno_ffi(const uint8_t* proof_ptr, size_t proof_len,
                         const uint8_t* pi_ptr, size_t pi_len) noexcept {
    Plonky3ProofBytes proof{proof_ptr, proof_len};
    Plonky3PublicInputs pi{pi_ptr, pi_len};
    int32_t result = uno_mine_uno_verify(proof, pi);
    return result == 0;
}
```

**Error translation**:
```cpp
// In apply_mine_uno():
int32_t ffi_result = uno_mine_uno_verify(proof_bytes, pi_bytes);
if (ffi_result != 0) {
    // Map to VerifyResult
    if (ffi_result == 1) {
        return VerifyResult::BadPoWHash;  // or ProofDecodeFailed
    } else if (ffi_result == 2) {
        return VerifyResult::BadPlonky3Proof;
    } else {
        return VerifyResult::BadPlonky3Proof;  // catch-all
    }
}
```

---

## §6. Retarget Policy

### 6.1 UNO Retargeting Design

**From** `Mining-Design.md` §"UNO" (lines 667–702):

| Parameter | Value | Source |
|-----------|-------|--------|
| Target solve interval | 600 seconds (10 minutes) | Bitcoin block time |
| Retarget cadence | Every solve (or every N solves; TBD) | Unlike Bitcoin's every-2016-blocks |
| Retarget factor bounds | [3/4, 4/3] | More aggressive than TOS/eTOS [7/8, 9/8] |
| Initial target | 2^219 | Calibrated for ~150 M/s CPU hashrate |

**Formula** (TBD; to be implemented in Phase 2):
```
new_target = old_target × (actual_time / target_time)
clamped_to [old_target × 3/4, old_target × 4/3]
```

Where `actual_time` is the elapsed time since the last solve, and `target_time = 600s`.

### 6.2 C++ Implementation Notes

1. **State fields** (from `state.h` lines 90–94):
   ```cpp
   uint64_t mine_remaining{0};             // Total supply left to mine
   uint32_t mine_epoch{0};                 // Cumulative solve count
   std::array<uint8_t, 32> mine_target{};  // Current PoW target (BE)
   uint32_t halving_era{0};                // = mine_epoch / kEraSize (cached)
   ```

2. **Retarget check** (in `apply_mine_uno`):
   ```cpp
   // Pseudocode: retarget every solve
   if (should_retarget(state.mine_epoch)) {
       uint64_t elapsed_seconds = compute_elapsed_time(last_solve_time);
       state.mine_target = adjust_target(state.mine_target, 
                                          elapsed_seconds, 
                                          kTargetSolveSeconds);
   }
   ```

3. **If retargeting is deferred** (e.g., retarget every 10 solves):
   Store `last_retarget_epoch` in state and check modulo arithmetic.

### 6.3 Static vs. Dynamic Target

**Current spec assumption**: Target is updated on every solve (or every N solves), following the Bitcoin model but more frequently. The target is **not** in the `MineUnoPublicInputs` — it is read from chain state at proof-generation time, then verified by constraint 1 (PoW hash < target) in the AIR.

If the design shifts to a **static target** per era (no retargeting), state that explicitly in this spec and simplify step 8 above (remove retarget logic).

---

## §7. Risk & Correctness Pitfalls

### 7.1 Same-Height Tx Race (Two Miners Solve Simultaneously)

**Scenario**: Miner A and Miner B both solve at epoch N in the same block.

**Expected behavior**:
- Collator includes both txs in the block
- Both pass AIR verify (both have epoch=N in PI)
- Batch apply runs serially:
  - Miner A's tx: checks epoch==N ✓, remaining==current ✓ → apply → epoch becomes N+1, remaining decreases
  - Miner B's tx: checks epoch==N ✗ (state is now N+1) → reject with EpochRaceDetected

**Implementation**: The race check in step 1 (`tx.public_inputs.epoch == state.mine_epoch`) catches this exactly. The second tx fails gracefully; no consensus fault.

### 7.2 Epoch Wraparound After 2^32 Solves

**Scenario**: After 2^32 successful solves, `mine_epoch` wraps to 0.

**Risk**: If era arithmetic is not careful, epoch 0 and epoch 2^32 may collide in reward lookup.

**Mitigation**:
- The halving table in `mine_constants.h` uses `era_from_epoch()` which does integer division by `kEraSize = 210,000`.
- After 2^32 solves (~4.6 × 10^9 years at 600s/solve), the network will have undergone 2^32 / 210,000 ≈ 20,000 halvings. By era ~100, rewards are already 0 (kMaxNonZeroEra = 35).
- For maximum safety, use 64-bit epoch tracking if feasible, or add an explicit saturation check.

### 7.3 Halving Boundary: Reward Validation

**Scenario**: Epoch 209,999 → era 0 (50 UNO reward). Epoch 210,000 → era 1 (25 UNO reward).

**Risk**: If the compare-against-expected-value check (step 6) doesn't handle the boundary correctly, a miner solving at the boundary could claim the wrong reward.

**Mitigation**:
- Always compute `mine_reward_for_epoch(tx.public_inputs.epoch)` using the constexpr function, which internally calls `era_from_epoch()`.
- The AIR constraint 3 (Halving Table) also enforces this, so the off-circuit check is defensive.
- No special boundary handling needed; the division in `era_from_epoch()` is exact.

### 7.4 PoW Hash Field Element Reduction

**Scenario**: The Poseidon2 hash produces 4 field elements (Goldilocks, p = 2^64 - 2^32 + 1). These must be compared against the 256-bit target numerically.

**Risk**: Limb byte order confusion. Goldilocks FE serialization and big-endian target must align.

**Mitigation**:
- The AIR constraint 1 enforces `pow_hash_fe[0..4] < target` in the Goldilocks field arithmetic.
- The C++ off-circuit check (step 4) must parse the limbs in the same order (little-endian field limbs → big-endian reassembly).
- Cross-reference the Rust implementation (`tosctl/uno/src/mine_uno.rs`) for the exact limb layout.

### 7.5 Remaining Balance Underflow

**Scenario**: `value_nano > remaining_pre`, violating conservation.

**Risk**: Integer underflow if not checked.

**Mitigation**:
- Step 5 uses the inline `check_conservation()` helper, which explicitly checks `remaining_pre >= value_nano`.
- The AIR constraint 5 also enforces this, so the check is redundant but cheap and defensive.

### 7.6 Output Commitment Collision

**Scenario**: Two miners independently solve and produce the same `output_cm` (collision in Poseidon2 or reuse of randomness).

**Risk**: Two notes with the same commitment confuse spent-note tracking.

**Mitigation**:
- Step 7 checks for commitment uniqueness via the commitment tree.
- The probability of collision is negligible (Poseidon2 is a secure hash), but the check is a hard requirement for correctness.

---

## §8. Summary of Functions to Implement

| Function | File | Signature | Purpose |
|----------|------|-----------|---------|
| `decode_mine_uno` | `mine_uno.cpp` | `MineUnoDecodeResult decode_mine_uno(vm::CellSlice)` | Decode wire envelope → MineUno struct |
| `encode_mine_uno` | `mine_uno.cpp` | `td::Result<td::Ref<vm::Cell>> encode_mine_uno(const MineUno&)` | Encode MineUno struct → cell |
| `canonical_mine_uno_hash` | `mine_uno.cpp` | `td::Bits256 canonical_mine_uno_hash(const MineUno&)` | Compute dedup/anti-replay hash |
| `apply_mine_uno` | `mine_uno.cpp` | `VerifyResult apply_mine_uno(UnoState&, const MineUno&)` | Verify & apply tx; mutate state on Ok |
| `compute_gas_used_mine_uno` | `compute-phase.cpp` | `uint64_t compute_gas_used_mine_uno(const MineUno&)` | Gas cost estimation |
| Dispatch branch | `compute-phase.cpp` | (inline in `run_compute_phase`) | Route tx_kind 0x02 to MineUno path |
| Batch dispatch | `compute-phase.cpp` | (extend `run_compute_phase_batch`) | Route each tx to correct verifier |
| FFI wrapper | `crypto/plonky3-verifier.cpp` | (extend `Plonky3Verifier`) | Call `uno_mine_uno_verify` FFI |

---

## §9. Related Documentation

- **AIR constraint spec**: `doc/uno-mine-air-constraints.md` — full constraint system
- **Mining design**: `doc/Mining-Design.md` — difficulty calibration, retarget policy, rewards
- **Rust mirror**: `tosctl/uno/src/mine_uno.rs` — wire format reference
- **Transfer pattern**: `uno/core/transaction.cpp` → `canonical_tx_hash()`, `decode_transfer()` — architectural template
- **State & serialization**: `uno/core/state.h`, `cell-state.cpp` → persistence layer
- **FFI binding**: `uno/plonky3_ffi/include/uno_plonky3_ffi.h` — C↔Rust boundary

---

## §10. Testing & Validation

### 10.1 Unit Tests

- **`test-uno-mine-loader.cpp` Test 7**: Placeholder for AIR proof verification. Enable when `uno_mine_uno_verify` is live.
- **New tests** (Phase 2):
  - Decode/encode round-trip
  - Canonical hash determinism
  - Halving table boundary conditions
  - Race condition semantics (same-height collision)
  - Retarget convergence (if static, skip)

### 10.2 Golden Fixtures

- Produce a valid (epoch=0, nonce=..., recipient=...) MineUno tx with a real Plonky3 proof
- Verify C++ decoder matches Rust encoder byte-for-byte
- Test canonical hash stability across process restarts

### 10.3 Integration Tests

- Block-level: collator feeds N MineUno txs, verifies correct serial apply & race handling
- Parallel verify: verify batch processing matches serial path (same invariant as Transfer)

---

**End of specification.**
