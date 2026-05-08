/*
    JVM Workchain — genesis ShardAccounts builder.

    Under v2 account-native topology there is NO genesis JVM account: each
    contract becomes its own wc=3 account at a deterministic address derived
    by `derive_jvm_contract_address`, materialized later via the host
    `action_create_account` (or a normal inbound message carrying StateInit).

    `build_jvm_zerostate_accounts_cell()` therefore produces an empty
    ShardAccounts dict cell (`hme_empty$0`) for the wc=3 genesis shard
    block.  This is called from the Fift word `jvm-zerostate-accounts-cell`
    in create-state.cpp and from genesis tooling that constructs the
    initial wc=3 block state.

    The legacy v1 SingletonExecutor at 0x0000…0001 is no longer seeded.

    Source: TOS-specific integration point.
*/
#pragma once

#include "vm/cells.h"

namespace jvm_workchain {

/// Build the (empty) ShardAccounts cell for the wc=3 genesis shard.
///
/// Always returns a non-null cell shaped as `hme_empty$0` (HashmapAugE 256
/// SimpleAccount).  Returns null only on internal cell-builder failure
/// (should never happen at runtime).
td::Ref<vm::Cell> build_jvm_zerostate_accounts_cell();

}  // namespace jvm_workchain
