/*
    JVM Workchain — genesis account builder.

    build_jvm_zerostate_accounts_cell() produces the ShardAccounts dict cell
    for the wc=3 genesis shard block.  The result contains exactly one entry:
    the singleton executor account at 0x0000…0001, seeded as acc_uninit (no
    StateInit) with zero balance.  The first inbound external message activates
    it via the normal AccountExecutionPolicy activation_code path, which
    installs the 0x4a ('J') code-marker cell.

    This mirrors build_uno_zerostate_accounts_cell() (uno/core/init.h) for
    wc=2 and build_evm_zerostate_accounts_cell() (evm/core/init.h) for wc=1.
    It is called from the Fift word `jvm-zerostate` in create-state.cpp and
    from genesis tooling that constructs the initial wc=3 block state.

    Source: TOS-specific integration point.
*/
#pragma once

#include "vm/cells.h"

namespace jvm_workchain {

/// Build the ShardAccounts cell for the wc=3 genesis shard.
///
/// Contains exactly one account:
///   addr    = MsgAddressInt{wc=3, account_id = 0x0000…0001}
///   state   = account_uninit$00
///   balance = 0
///
/// The activation code marker (0x4a 'J') is not embedded here; it is
/// installed during the first transaction by the AccountExecutionPolicy
/// machinery.  Returns null on internal cell-builder failure (should never
/// happen with valid TLB constants).
td::Ref<vm::Cell> build_jvm_zerostate_accounts_cell();

}  // namespace jvm_workchain
