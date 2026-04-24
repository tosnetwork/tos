/*
    Uno Workchain — workchain identification and compile-time constants.

    wc=2 is TOS's PQ-native privacy workchain. See doc/uno-workchain.md.

    This file is deliberately dependency-light (constants + a handful of
    inline helpers) so that every file in core/, crypto/, rpc/ can include
    it without dragging transitive headers. Struct / cell / proof logic
    lives in state.h, cell-state.h, transaction.h, compute-phase.h.

    Layout origin: uno-workchain.md §2.0, §5.1, §5.6, §10.1, §10.2, §10.4.
*/
#pragma once
#ifndef UNO_WORKCHAIN_H_
#define UNO_WORKCHAIN_H_
// NOTE: guard-macro is paired with `#pragma once` so transaction.h can
// detect whether this header is in scope (it hosts an optional copy of
// `kTransferVersion` / `kSchemeIdV1` for TUs that include transaction.h
// without workchain.h; see transaction.h §"Fixed wire constants").
#endif

#include <cstdint>
#include <cstddef>

#include "tos/tos-types.h"  // tos::WorkchainId — host-chain type

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Workchain identity (§10.1, §10.4)
// ---------------------------------------------------------------------------

/// Workchain id registered in ConfigParam 12. wc=2 is the next slot after
/// masterchain (-1), basechain (0), and EVM (1).
constexpr tos::WorkchainId kWorkchainId = 2;

/// vm_version value baked into the WorkchainDescr (§10.1). ASCII "UNO1".
/// 0x55 'U' | 0x4E 'N' | 0x4F 'O' | 0x31 '1' = 0x554E4F31.
constexpr int32_t kVmVersion = 0x554E4F31;

/// vm_mode — Uno has no VM (§8.4). Reserved to 0 on the wc descriptor.
constexpr uint32_t kVmMode = 0;

// Decision #8 (doc/uno-workchain.md §16): no UNO_FLAG. The WorkchainDescr
// TLB enforces `flags = 0`; workchain identity is carried by `vm_version`
// ("UNO1") only. No `kUnoFlag` constant exists. Do not reintroduce.

// ---------------------------------------------------------------------------
// Chain ids (§10.4)
// ---------------------------------------------------------------------------

/// Default chain_id baked into ConfigParam 84 for the testnet image.
/// ASCII "UNOT" = 0x554E4F54. Overridable at runtime via ConfigParam load.
constexpr uint32_t kDefaultTestnetChainId = 0x554E4F54;

/// Alias of `kDefaultTestnetChainId`, kept for symmetry with
/// `kChainIdMainnet` below. Decision #9 (§16) pins both values.
constexpr uint32_t kChainIdTestnet = kDefaultTestnetChainId;

/// Mainnet chain_id per decision #9 (§16) / §10.4.
/// ASCII "UNOM" = 0x554E4F4D. Bound into every Uno tx transcript (§2.0).
/// Independent from TOS `global_id` (ConfigParam 19): that is masterchain-
/// level; `chain_id` here is wc=2-level, carried inside `UnoConfig`.
constexpr uint32_t kChainIdMainnet = 0x554E4F4D;

/// Returns the currently configured chain id. Boot flow: set once from
/// ConfigParam 84 at node startup, otherwise falls back to testnet.
///
/// Mirrors `evm_workchain::current_evm_chain_id()` — kept as a free function
/// so the runtime override has one canonical accessor.
uint32_t current_uno_chain_id() noexcept;

/// Override the runtime chain id. Called exactly once at startup, from
/// `init_uno_workchain()` after loading ConfigParam 84. Calling this after
/// a block has been produced is undefined — Fiat-Shamir transcripts (§2.0)
/// absorb chain_id and every signed tx binds to it.
void set_uno_chain_id(uint32_t chain_id) noexcept;

// ---------------------------------------------------------------------------
// Cryptographic scheme identity (§2.0)
// ---------------------------------------------------------------------------

/// v1-plonky3-goldilocks — the only scheme_id accepted on mainnet at v1 ship.
constexpr uint8_t kSchemeIdV1 = 0x01;

/// scheme_id reserved for Phase 1 ML-DSA hybrid spend-auth (§2.0).
/// Declared here so that future upgrade code knows not to reuse the slot.
constexpr uint8_t kSchemeIdV2 = 0x02;

/// scheme_id reserved for Phase 3 Tachyon-like PCD recursion (§2.0).
constexpr uint8_t kSchemeIdV3 = 0x03;

/// Test-only scheme_id; never accepted on mainnet (§2.0).
constexpr uint8_t kSchemeIdTest = 0xFF;

/// Schema version of the wire `Transfer` body (§4.1).
constexpr uint8_t kTransferVersion = 1;

/// Schema version of the on-cell `UnoShardState` root cell (§5.1).
constexpr uint8_t kShardStateVersion = 1;

/// Schema version of ConfigParam 84 `UnoConfig` (§10.2). Slot is pinned by
/// decision #4 (§16): UnoConfig lives in ConfigParam 84, not 26.
constexpr uint8_t kConfigParamVersion = 1;

/// Masterchain ConfigParam slot reserved for `UnoConfig` (§10.2, decision #4).
/// Callers that load / install ConfigParam should use this constant rather
/// than hardcoding the literal.
constexpr int kUnoConfigParamIdx = 84;

// ---------------------------------------------------------------------------
// Cell / state layout constants (§5.1, §5.2, §5.4)
// ---------------------------------------------------------------------------

// Decision #14 (A1↔A2 alignment): the tree/nullifier/anchor subsystems own
// their own size constants in their headers — `kTreeDepth` in
// commitment-tree.h, `kNullifierBytes` / `kDefaultNullifierLruCapacity` in
// nullifier-set.h, `kDefaultAnchorWindowSize` in anchor-window.h. Keep only
// the consensus-observable constants here (hash width in bits/bytes) so
// non-A2 call sites can size buffers without pulling in A2 headers.

/// Width of Poseidon2 output consumed for a node / leaf hash (bits).
/// Each node is 4 Goldilocks field elements = 256 bits.
constexpr unsigned kHashBits = 256;

/// Size, in bytes, of a serialised 256-bit hash (cm, nf, anchor, root…).
constexpr unsigned kHashBytes = kHashBits / 8;

/// Reference slot indices in the `UnoShardState` root cell (§5.1).
/// The root cell uses refs {0=commitment_tree, 1=nullifier_set, 2=meta}; ref 3
/// is reserved to keep one slot open for v1.1 / Phase 1 extensions without a
/// cell-schema migration. Names are 0-indexed to match vm::CellBuilder APIs.
constexpr unsigned kStateRefCommitmentTree = 0;
constexpr unsigned kStateRefNullifierSet   = 1;
constexpr unsigned kStateRefMeta           = 2;
constexpr unsigned kStateRefReserved       = 3;
constexpr unsigned kStateRefCount          = 4;

/// Ref slot indices inside the MetaCell (§5.1).
constexpr unsigned kMetaRefAnchorWindow = 0;
constexpr unsigned kMetaRefStats        = 1;
constexpr unsigned kMetaRefMiningState  = 2;  // added per uno-mine-v1 Phase 2
constexpr unsigned kMetaRefCount        = 3;  // bumped from 2 → 3 for mining state

/// Dictionary key width for the nullifier set (§5.3): 256-bit.
constexpr unsigned kNullifierKeyBits = kHashBits;

// ---------------------------------------------------------------------------
// Default config values (§10.2). Overridable by ConfigParam 84 at runtime.
// ---------------------------------------------------------------------------
//
// Values below are pinned by decision #7 (§16) / §10.2 launch schedule:
//
//   min_fee_nano           = 100_000        (0.0001 UNO baseline)
//   fee_per_byte_nano      = 10
//   fee_per_spend_nano     = 50_000
//   fee_per_output_nano    = 50_000
//   max_spends_per_tx      = 4
//   max_outputs_per_tx     = 4
//   expiry_window_blocks   = 64             (~64 s at 1 s block rate)
//   anchor_window_size     = 100            (kDefaultAnchorWindowSize, decision #15)
//   tree_depth             = 32             (kTreeDepth, §2.3)
//   nullifier_lru_capacity = 1_000_000      (kDefaultNullifierLruCapacity, advisory)
//
// The four fee fields are governance-upgradable via ConfigParam 11 voting
// (§10.2). `max_spends_per_tx`, `max_outputs_per_tx`, and `tree_depth` are
// consensus-binding (they pin AIR public-input shape) and must be treated
// as frozen after genesis.

constexpr uint64_t kDefaultMinFeeNano        = 100'000ULL;            // 0.0001 UNO baseline
constexpr uint64_t kDefaultFeePerByteNano    = 10ULL;
constexpr uint64_t kDefaultFeePerSpendNano   = 50'000ULL;
constexpr uint64_t kDefaultFeePerOutputNano  = 50'000ULL;
constexpr uint8_t  kDefaultMaxSpendsPerTx    = 4;   // §10.2 hard cap
constexpr uint8_t  kDefaultMaxOutputsPerTx   = 4;   // §10.2 hard cap
constexpr uint32_t kDefaultExpiryWindowBlocks = 64; // §10.2, ~64 s at 1 s blocks
// `kDefaultNullifierLruCapacity` lives in nullifier-set.h (decision #14).

// ---------------------------------------------------------------------------
// Domain-separation strings used across the module
// ---------------------------------------------------------------------------
//
// The ASCII strings below are referenced by off-circuit code
// (seed derivation, filter tagging, cell-state sanity hashing) AND must
// match the strings used inside the Plonky3 AIR (Agent 4).  If a constant
// is renamed here, the AIR must be updated in the same change.  See §2.0,
// §2.4, §2.6, §2.8.

/// Transcript root tag absorbed as the first Poseidon2 input of every
/// Fiat-Shamir transcript in the protocol (§2.0). ASCII, 16 bytes,
/// zero-padded to one Poseidon2-over-Goldilocks absorb.
constexpr const char kTranscriptRootTag[] = "uno-workchain-v1";

/// Domain separator for the nullifier hash (§2.4, §3.4).
constexpr const char kNullifierTag[] = "uno-nf-v1";

/// Domain separator for the note commitment hash (§3.2).
///
/// Note-commitment formula per decision #1 (§3.2 updated):
///
///     cm = Poseidon2("uno-cm-v1", d, pk_d.bytes, ivk_commitment, value, rcm)
///
/// The five-argument form (with `ivk_commitment`) is the v1 wire contract;
/// the older four-argument form (without `ivk_commitment`) is retracted.
/// Both sides — the off-circuit C++ sender and the Plonky3 AIR — MUST use
/// the five-arg preimage, or prover/verifier disagree silently.
constexpr const char kNoteCommitmentTag[] = "uno-cm-v1";
/// Explicit alias so callers can reference the domain separator by its
/// decision-#1 name. Identical bytes to `kNoteCommitmentTag`.
constexpr const char kDomainSepCmV1[] = "uno-cm-v1";

/// Domain separator for the ivk-commitment hash-chain binding (decision #1,
/// §2.6 Addresses, §4.2 claim 3):
///
///     ivk_commitment = Poseidon2("uno-ivk-cm-v1", ivk, d)
///
/// A 256-bit public field published in every Address; bound into `cm` via
/// `kDomainSepCmV1`; recomputed inside the Transfer AIR from the private
/// witness `(ivk, d)` to prove ownership without any in-circuit curve op.
constexpr const char kIvkCommitmentTag[] = "uno-ivk-cm-v1";
constexpr const char kDomainSepIvkCmV1[] = "uno-ivk-cm-v1";

/// Domain separator for rcm (note-commitment trapdoor) (§3.1).
constexpr const char kRcmTag[] = "uno-rcm-v1";
constexpr const char kDomainSepRcmV1[] = "uno-rcm-v1";

/// Domain separators for the key hierarchy (§2.6).
constexpr const char kSeedTag[]     = "uno-seed-v1";
constexpr const char kAskTag[]      = "uno-ask-v1";
constexpr const char kEskSeedTag[]  = "uno-esk-v1";
constexpr const char kMlkemSeedTag[]= "uno-mlkem-v1";
constexpr const char kOvkTag[]      = "uno-ovk-v1";
constexpr const char kNkTag[]       = "uno-nk-v1";
constexpr const char kIvkTag[]      = "uno-ivk-v1";

/// Hybrid-KEM transcript tag (§2.7).
constexpr const char kHybridKemTag[] = "uno-hybrid-kem-v1";

/// AEAD nonce tag (§2.7).
constexpr const char kAeadNonceTag[] = "uno-nonce-v1";

/// Compact-filter tag (§2.8).
constexpr const char kFilterTag[] = "uno-filter-v1";

/// Diversifier-hash-to-curve tag (§2.6 Addresses).
constexpr const char kDiversifierTag[] = "uno-diversifier-v1";

/// Sanity-hash tag over live ConfigParam 84 bytes, mixed into
/// `UnoShardState.config_hash` (§5.1). This is consensus-independent but
/// consensus-observable: nodes with mismatched configs diverge on the
/// first block and fail replay immediately.
constexpr const char kConfigHashTag[] = "uno-config-hash-v1";

// ---------------------------------------------------------------------------
// Single-executor account (§5.6)
// ---------------------------------------------------------------------------

/// Fixed wc=2 outer account that carries the entire UnoShardState.
/// 256-bit address = all zeros except the low bit set to 1:
///   0x00…01 (mirrors the EVM convention).
constexpr unsigned char kUnoExecutorAddressBytes[32] = {
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 1,
};

/// Canonical code-marker byte embedded in StateInit.code of the wc=2
/// executor account. 0x55 == ASCII 'U'. Declared here so core/ code can
/// spot-check the marker without pulling in the dispatcher header
/// (crypto/block/uno-workchain-dispatch.{h,cpp}, owned by Agent 5).
constexpr unsigned char kUnoCodeMarkerByte = 0x55;  // 'U'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns true when \p wc matches the Uno workchain id.
inline bool is_uno_workchain(tos::WorkchainId wc) noexcept {
    return wc == kWorkchainId;
}

/// Returns true when \p scheme_id is a value the v1 verifier can accept.
/// v1 installs exactly one entry; every other value is a deterministic
/// reject (§2.0). Test scheme_id is only accepted in non-mainnet builds;
/// mainnet predicate is owned by the dispatcher, not this header.
inline bool is_accepted_scheme_id_v1(uint8_t scheme_id) noexcept {
    return scheme_id == kSchemeIdV1;
}

}  // namespace uno_workchain
