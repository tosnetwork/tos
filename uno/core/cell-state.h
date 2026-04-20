/*
    Uno Workchain — cell-native serializer for UnoShardState.

    Ownership split:
      - In-memory mutation — `uno/core/state.{h,cpp}` (this agent).
      - Per-sub-object serialisation (frontier chain, nullifier dict,
        anchor ring, stats) — `uno/core/{commitment-tree,nullifier-set,
        anchor-window,block-filter}.{h,cpp}` owned by Agent 2.
      - Root-cell assembly + disassembly — this file. We call into Agent 2's
        per-sub-object codecs for the refs and inline the header fields.

    The root cell layout reproduced from doc/uno-workchain.md §5.1:

        uno_shard_state#554E4F53
          version              : uint8   (= kShardStateVersion)
          scheme_id            : uint8
          next_position        : uint64
          config_hash          : bits256
          commitment_tree_root : bits256
          ^commitment_tree_cell  (ref 0)
          ^nullifier_set_cell    (ref 1)
          ^meta_cell             (ref 2)
          // ref 3 = RESERVED (intentionally absent)
        = UnoShardStateCell;

        meta#_
          ^anchor_window_cell  (ref 0)
          ^stats_cell          (ref 1)
        = UnoMetaCell;

        stats#_ burned_fees:uint64 tx_count:uint64 note_count:uint64 = UnoStatsCell;

    The inline bit budget:
        8 + 8 + 64 + 256 + 256 = 592 bits    ≤ 1023
        3 refs used, 1 reserved              ≤ 4

    Source: TOS-specific adapter; see doc/uno-workchain.md §5, §10.3.
*/
#pragma once

#include <cstdint>

#include "vm/cells.h"
#include "uno/core/state.h"

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Cell-schema magic values
// ---------------------------------------------------------------------------

/// shard-state magic for UnoShardStateCell. ASCII "UNOS" = 0x554E4F53.
/// Prefix byte distinguishes a wc=2 executor StateInit.data cell from wc=1
/// (EVM's `0x45564D`) and any future non-TVM workchain.
constexpr uint32_t kUnoShardStateMagic = 0x554E4F53;
constexpr unsigned kUnoShardStateMagicBits = 32;

// ---------------------------------------------------------------------------
// Serialise / deserialise
// ---------------------------------------------------------------------------

/// Serialise an `UnoShardState` into a single root cell suitable for
/// writing into the wc=2 executor account's `StateInit.data`. The cell
/// tree returned references three child cells (commitment-tree frontier,
/// nullifier dict, MetaCell) and leaves ref 3 unused.
///
/// The cell is deterministic: identical input state → identical cell hash
/// on every validator (P.5 requirement in doc §12).
///
/// Returns a null cell and logs ERROR if any sub-object fails to
/// serialise or the TL-B validator rejects the result.
td::Ref<vm::Cell> serialize_state(const UnoShardState& state);

/// Parse an UnoShardStateCell back into a fresh `UnoShardState`.
/// `out` is overwritten on success; on failure `out` is left in a
/// default-constructed state and `false` is returned.
///
/// Called at process start from `init_uno_workchain()` (§8.3) with the
/// cell loaded from CellDb, and by tests that round-trip state cells.
bool deserialize_state(td::Ref<vm::Cell> root, UnoShardState& out);

/// Convenience wrapper mirroring `evm_workchain::CellEvmState::serialize_to_cell`.
/// Returns a null cell when the state is empty (is_empty() == true).
inline td::Ref<vm::Cell> serialize_state_or_null(const UnoShardState& state) {
    if (state.is_empty()) return {};
    return serialize_state(state);
}

// ---------------------------------------------------------------------------
// config_hash sanity-computation
// ---------------------------------------------------------------------------

/// Recompute the `config_hash` field of UnoShardState from a canonicalised
/// byte view of the live ConfigParam 84 cell. The hash is BLAKE3 with the
/// `kConfigHashTag` domain separator (§5.1 "BLAKE3 over live wc=2 config
/// params; sanity").
///
/// This is consensus-observable: two validators with mismatched configs
/// will diverge on the first block that writes the state root. Boot-time
/// mismatch surfaces as a replay failure against the genesis state.
std::array<uint8_t, kHashBytes> compute_config_hash(td::Slice config_cell_bytes);

/// Helper that builds the MetaCell (anchor_window + stats) independently,
/// useful for tests and for the genesis path that wants to assemble the
/// meta cell before pushing an anchor. Returns a null cell if either
/// sub-cell is null.
// TODO(uno-integration): Agent 2's AnchorWindow and the inline StatsCell
// serialisers must expose matching names; adjust once Agent 2 lands.
td::Ref<vm::Cell> build_meta_cell(td::Ref<vm::Cell> anchor_window_cell,
                                  td::Ref<vm::Cell> stats_cell);

/// Encode a UnoStats struct inline into a single cell: 192 bits, no refs.
td::Ref<vm::Cell> encode_stats_cell(const UnoStats& stats);

/// Decode a StatsCell back into UnoStats. Returns false on schema mismatch.
bool decode_stats_cell(td::Ref<vm::Cell> cell, UnoStats& out);

}  // namespace uno_workchain
