/*
    EVM Workchain — ConfigParam 12 workchain descriptor.

    Provides helpers to create the TLB-encoded WorkchainDescr cell for
    registering the EVM workchain in the masterchain configuration.

    The descriptor follows the workchain#a6 format (v1):
      workchain#a6 enabled_since:uint32 monitor_min_split:(## 8)
        min_split:(## 8) max_split:(## 8)
        basic:(## 1) active:Bool accept_msgs:Bool flags:(## 13)
        zerostate_root_hash:bits256 zerostate_file_hash:bits256
        version:uint32 format:(WorkchainFormat basic)
      = WorkchainDescr;

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <optional>

#include "vm/cells.h"
#include "tos/tos-types.h"

namespace evm_workchain {

/// Build the WorkchainDescr cell for the EVM workchain.
///
/// @param zerostate_root_hash  Root hash of the EVM workchain zerostate.
/// @param zerostate_file_hash  File hash (BoC hash) of the EVM workchain zerostate.
/// @param enabled_since        Unix timestamp when the workchain becomes active (0 = genesis).
/// @return                     A cell containing the serialised WorkchainDescr, or null on error.
td::Ref<vm::Cell> build_evm_workchain_descr(
    const tos::RootHash& zerostate_root_hash,
    const tos::FileHash& zerostate_file_hash,
    uint32_t enabled_since = 0);

/// Build a minimal zerostate cell for the EVM workchain.
///
/// The zerostate is an empty ShardState that serves as the starting point
/// for the EVM workchain.  It contains no accounts and no transactions.
///
/// @param root_hash  [out] Receives the root hash of the zerostate cell.
/// @param file_hash  [out] Receives the file hash (BoC hash) of the zerostate cell.
/// @return           The zerostate cell, or null on error.
td::Ref<vm::Cell> build_evm_zerostate(
    tos::RootHash& root_hash,
    tos::FileHash& file_hash);

/// Extract the EVM chain id bound into an EVM WorkchainDescr.
///
/// TOS binds the Ethereum-style EVM chain id to ConfigParam 12 by storing it
/// in `WorkchainFormat::wfmt_basic.vm_mode`. Returns std::nullopt if `cell`
/// is not a valid EVM WorkchainDescr.
std::optional<uint64_t> extract_evm_chain_id_from_workchain_descr(
    td::Ref<vm::Cell> cell) noexcept;

}  // namespace evm_workchain
