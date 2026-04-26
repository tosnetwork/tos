/*
    EVM Workchain — workchain identification and constants.

    This file defines the EVM workchain as an execution domain within the host
    chain. The EVM workchain is not a second independent chain; it is an
    alternative compute path registered under a dedicated workchain id.
*/
#pragma once

#include <cstddef>
#include <cstdint>
#include "tos/tos-types.h"  // tos::WorkchainId — existing chain type, unavoidable

namespace evm_workchain {

// ---------------------------------------------------------------------------
// Workchain identity
// ---------------------------------------------------------------------------

/// Workchain id registered in ConfigParam 12.
/// Value 1 is the next available slot after masterchain (-1) and basechain (0).
constexpr tos::WorkchainId kWorkchainId = 1;

/// Default EVM chainId baked into the binary.
///
/// Exposed to wallets and JSON-RPC via `eth_chainId`. This is the
/// Ethereum-style network identifier, not the internal workchain id.
///
/// At runtime tests/devnet tooling may override this via
/// `set_evm_chain_id()` before any EVM config is materialised. Production
/// validators must not source this value from process-local environment; it
/// is consensus-critical and must be bound by chain configuration.
///
/// Kept as a `constexpr` so existing callers (unit tests, fixtures, etc.)
/// that hard-coded the default continue to compile. Production code paths
/// that read the chain id at runtime MUST use `current_evm_chain_id()`.
constexpr uint64_t kEvmChainId = 0x544F53;  // "TOS" in ASCII — historical default

/// Safety budget for the full Ethereum MPT state-root pass. Until wc=1
/// persists a true incremental trie witness, accepted EVM transactions are
/// rejected once state size exceeds this small synchronous rebuild envelope.
/// This keeps validator host work bounded instead of tying one low-value EVM
/// tx to consensus-sized account/storage dictionaries.
constexpr std::size_t kMaxFullRootAccounts = 16'384;
constexpr std::size_t kMaxFullRootStorageSlots = 65'536;

/// Returns the chain id to use at runtime. Defaults to `kEvmChainId` until
/// `set_evm_chain_id` is called by explicit test/devnet bootstrap code.
///
/// Header-defined inline so the lookup is cheap and there is no extra
/// translation unit dependency for callers.
uint64_t current_evm_chain_id() noexcept;

/// Override the runtime chain id. Intended only for tests/devnet bootstrap,
/// and only before any block is processed or any RPC is served.
/// Calling this after the validator has accepted a block is undefined —
/// EIP-155 v-recovery and stored receipts assume a stable chain id.
void set_evm_chain_id(uint64_t chain_id) noexcept;

// ---------------------------------------------------------------------------
// VM descriptor fields (written into the workchain descriptor)
// ---------------------------------------------------------------------------

/// vm_version value that marks an account as running on the EVM executor.
constexpr int32_t kVmVersion = 0x45564D;  // "EVM" in ASCII

/// Legacy placeholder used before chain_id was bound into ConfigParam 12.
///
/// Current wc=1 WorkchainDescr values MUST store `current_evm_chain_id()` in
/// `WorkchainFormat::wfmt_basic.vm_mode`; a zero vm_mode is rejected for the
/// EVM workchain because TOS has not launched and has no legacy descriptor to
/// preserve.
constexpr uint32_t kLegacyVmMode = 0;

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
/// is a cell in `cp.new_data` format (magic 0x45564D + schema_version=4
/// + Maybe ^CellEvmState
/// root + bits256 eth_state_root + Maybe ^block_hash_history
/// + reserved accumulator bit set to nothing). On every block the compute phase
/// updates this cell to reflect the post-execution world state, the EVM
/// BLOCKHASH lookback window, and the single-transaction Ethereum block root.
///
/// 256-bit address = all zeros except the low bit set to 1:
///   0x0000000000000000000000000000000000000000000000000000000000000001
constexpr unsigned char kEvmExecutorAddressBytes[32] = {
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 1,
};

}  // namespace evm_workchain
