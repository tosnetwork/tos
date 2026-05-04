/*
    EVM Workchain dispatch — canonical account marker cell.

    This header lives in crypto/block/ (part of tos_crypto) so that
    callers in the crypto layer can obtain the EVM singleton executor
    code-marker cell without pulling in EVM/silkworm headers.

    Source: TOS-specific integration point.
*/
#pragma once

#include "vm/cells/Cell.h"

namespace evm_workchain_dispatch {

/// Canonical "EVM activated account" code marker cell.
///
/// A single-byte cell containing 0x45 ('E'). Used as the StateInit.code cell
/// for descriptor-selected EVM singleton executor accounts. Bytecode itself
/// lives in EvmAccountData.code_hash, so the outer code cell only needs to
/// satisfy the "account_active" requirement.
///
/// Returns the same Ref<vm::Cell> on every call (cached singleton). All
/// validators produce the same cell hash, which CellDb will deduplicate
/// across every EVM account.
td::Ref<vm::Cell> get_evm_code_marker_cell();

}  // namespace evm_workchain_dispatch
