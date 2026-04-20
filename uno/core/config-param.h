/*
    Uno Workchain — ConfigParam 12 (wc=2 workchain descriptor) +
                    ConfigParam 26 (UnoConfig) builders.

    ConfigParam 12 (workchain registry) is a masterchain-global dictionary
    of `WorkchainDescr` values keyed by workchain id. wc=2 ships as a
    slot in the genesis value — no hardfork machinery (§10).

    ConfigParam 26 is a new parameter reserved for Uno: a single cell
    encoding the wc=2 chain config (fees, tx limits, anchor window size,
    tree depth, expiry window). The schema is pinned in §10.2 of the
    design doc; this file provides the builder + parser.

    Source: TOS-specific adapter; see doc/uno-workchain.md §10.1, §10.2.
*/
#pragma once

#include <cstdint>

#include "vm/cells.h"
#include "tos/tos-types.h"

#include "uno/core/workchain.h"
#include "uno/core/commitment-tree.h"  // kTreeDepth (decision #14)
#include "uno/core/anchor-window.h"    // kDefaultAnchorWindowSize (decision #14)

namespace uno_workchain {

// ---------------------------------------------------------------------------
// UnoConfig (ConfigParam 26)
// ---------------------------------------------------------------------------

/// In-memory view of ConfigParam 26. Matches §10.2 field-for-field.
struct UnoConfig {
    uint8_t  version              {kConfigParamVersion};
    uint32_t chain_id             {kDefaultTestnetChainId};
    uint64_t min_fee_nano         {kDefaultMinFeeNano};
    uint64_t fee_per_byte_nano    {kDefaultFeePerByteNano};
    uint64_t fee_per_spend_nano   {kDefaultFeePerSpendNano};
    uint64_t fee_per_output_nano  {kDefaultFeePerOutputNano};
    uint8_t  max_spends_per_tx    {kDefaultMaxSpendsPerTx};
    uint8_t  max_outputs_per_tx   {kDefaultMaxOutputsPerTx};
    uint16_t anchor_window_size   {static_cast<uint16_t>(kDefaultAnchorWindowSize)};
    uint8_t  tree_depth           {static_cast<uint8_t>(kTreeDepth)};
    uint32_t expiry_window_blocks {kDefaultExpiryWindowBlocks};

    /// Factory for the canonical v1 testnet config. Production mainnet
    /// configs are populated by network ops — see `build_uno_config_cell`.
    static UnoConfig default_testnet() noexcept { return UnoConfig{}; }

    bool operator==(const UnoConfig& other) const noexcept {
        return version == other.version && chain_id == other.chain_id &&
               min_fee_nano == other.min_fee_nano &&
               fee_per_byte_nano == other.fee_per_byte_nano &&
               fee_per_spend_nano == other.fee_per_spend_nano &&
               fee_per_output_nano == other.fee_per_output_nano &&
               max_spends_per_tx == other.max_spends_per_tx &&
               max_outputs_per_tx == other.max_outputs_per_tx &&
               anchor_window_size == other.anchor_window_size &&
               tree_depth == other.tree_depth &&
               expiry_window_blocks == other.expiry_window_blocks;
    }
};

/// Serialise `UnoConfig` into a single cell suitable for insertion into
/// ConfigParam 26. Deterministic; identical input → identical cell hash.
///
/// The layout:
///     uno_config#26554E4F
///       version               : uint8
///       chain_id              : uint32
///       min_fee_nano          : uint64
///       fee_per_byte_nano     : uint64
///       fee_per_spend_nano    : uint64
///       fee_per_output_nano   : uint64
///       max_spends_per_tx     : uint8
///       max_outputs_per_tx    : uint8
///       anchor_window_size    : uint16
///       tree_depth            : uint8
///       expiry_window_blocks  : uint32
///     = UnoConfigParam;
///
/// Total inline bits: 32 + 8 + 32 + 4·64 + 8 + 8 + 16 + 8 + 32
///                  = 32 + 8 + 32 + 256 + 40 + 16 + 8 + 32 = 424 bits.
/// One cell, no refs.
td::Ref<vm::Cell> build_uno_config_cell(const UnoConfig& cfg);

/// Magic prefix for the UnoConfig cell. ASCII "26UN" reworked so the first
/// 8 bits distinguish it inside ConfigParam 26 from any accidental neighbour.
/// Value 0x26554E4F packs cleanly into 32 bits.
constexpr uint32_t kUnoConfigMagic = 0x26554E4F;
constexpr unsigned kUnoConfigMagicBits = 32;

/// Parse a ConfigParam 26 cell back into a UnoConfig.
/// Returns false on magic / version mismatch or short read.
bool parse_uno_config_cell(td::Ref<vm::Cell> cell, UnoConfig& out);

// ---------------------------------------------------------------------------
// ConfigParam 12 — wc=2 workchain descriptor (§10.1)
// ---------------------------------------------------------------------------

/// Build the `WorkchainDescr` cell for the Uno workchain.  Identical in
/// shape to `evm_workchain::build_evm_workchain_descr` but with wc=2
/// identity (kVmVersion="UNO1", flags=0 per decision #8).
///
/// Per §10.1 + decision #8:
///   - min_split = 0, max_split = 0 (single shard; global commitment tree)
///   - basic     = true (first-class workchain; bit is not "is-TVM")
///   - active    = true, accept_msgs = true
///   - flags     = 0 (TLB enforces zero; identity carried by vm_version only)
///   - vm_version = kVmVersion, vm_mode = kVmMode
///
/// @param zerostate_root_hash  Root hash of the wc=2 zerostate (from
///                             `build_zerostate()` in genesis.h).
/// @param zerostate_file_hash  BoC file hash of the wc=2 zerostate.
/// @param enabled_since        Unix ts when the workchain becomes active
///                             (0 = genesis).
/// @return                     Cell containing the serialised WorkchainDescr,
///                             or a null Ref on error.
td::Ref<vm::Cell> build_uno_workchain_descr(
    const tos::RootHash& zerostate_root_hash,
    const tos::FileHash& zerostate_file_hash,
    uint32_t enabled_since = 0);

// ---------------------------------------------------------------------------
// Runtime config accessor
// ---------------------------------------------------------------------------

/// Returns the currently-loaded UnoConfig. Populated by
/// `install_uno_config(cfg)` at node startup (called from `init_uno_workchain`
/// once the masterchain ConfigParam 26 is read). Until then, returns a
/// default-constructed UnoConfig with testnet defaults.
const UnoConfig& current_uno_config() noexcept;

/// Install a new UnoConfig at process scope. Called exactly once at startup
/// (masterchain ConfigParam 26 load). Re-installing after block production
/// has started is undefined — fee floors would change mid-flight and tx
/// validation would desync across validators.
void install_uno_config(UnoConfig cfg) noexcept;

}  // namespace uno_workchain
