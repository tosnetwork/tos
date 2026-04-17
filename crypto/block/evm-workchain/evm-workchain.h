/*
    EVM Workchain — workchain identification and constants.

    This file defines the EVM workchain as an execution domain within the host
    chain. The EVM workchain is not a second independent chain; it is an
    alternative compute path registered under a dedicated workchain id.
*/
#pragma once

#include <cstdint>
#include "tos/tos-types.h"  // tos::WorkchainId — existing chain type, unavoidable

namespace evm_workchain {

// ---------------------------------------------------------------------------
// Workchain identity
// ---------------------------------------------------------------------------

/// Workchain id registered in ConfigParam 12.
/// Value 1 is the next available slot after masterchain (-1) and basechain (0).
constexpr tos::WorkchainId kWorkchainId = 1;

/// EVM chainId exposed to wallets and JSON-RPC (eth_chainId).
/// This is the Ethereum-style network identifier, not the internal workchain id.
constexpr uint64_t kEvmChainId = 0x544F53;  // "TOS" in ASCII — placeholder, freeze before mainnet

// ---------------------------------------------------------------------------
// VM descriptor fields (written into the workchain descriptor)
// ---------------------------------------------------------------------------

/// vm_version value that marks an account as running on the EVM executor.
constexpr int32_t kVmVersion = 0x45564D;  // "EVM" in ASCII

/// vm_mode — reserved, 0 for now.
constexpr uint32_t kVmMode = 0;

// ---------------------------------------------------------------------------
// Address model
// ---------------------------------------------------------------------------

/// EVM accounts use 256-bit address slots inside the workchain, but the
/// externally visible address is the lower 160 bits (20 bytes), consistent
/// with standard Ethereum 0x addresses.
constexpr unsigned kEvmAddressBytes = 20;

/// The host chain uses 256-bit internal address representation.  For EVM
/// accounts the upper 96 bits are zero-padded.
constexpr unsigned kInternalAddressBits = 256;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns true when \p wc matches the EVM workchain id.
inline bool is_evm_workchain(tos::WorkchainId wc) noexcept {
    return wc == kWorkchainId;
}

// ---------------------------------------------------------------------------
// Single-executor account (see doc/evm-workchain-transaction-admission-and-single-executor.md)
// ---------------------------------------------------------------------------

/// Fixed wc=1 TOS outer account that carries the entire EVM world state.
///
/// Every EVM external message is routed to this address. Its `StateInit.data`
/// is a cell in `cp.new_data` format (magic 0x45564D + Maybe ^CellEvmState
/// root + bits256 eth_state_root). On every block the compute phase
/// updates this cell to reflect the post-execution world state.
///
/// 256-bit address = all zeros except the low bit set to 1:
///   0x0000000000000000000000000000000000000000000000000000000000000001
constexpr unsigned char kEvmExecutorAddressBytes[32] = {
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 1,
};

}  // namespace evm_workchain
