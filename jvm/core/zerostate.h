/*
    JVM Workchain — genesis ShardAccounts builder.

    Two shapes:

      * `build_jvm_zerostate_accounts_cell()` — empty dict, the default
        for a chain that bootstraps every wc=3 contract through inbound
        `action_create_account` from existing wc=3 senders.  The chain
        has no wc=3 senders at block 0 in this configuration, which
        creates a chicken-and-egg for the very first contract; use the
        parameterized form below to break it.

      * `build_jvm_zerostate_accounts_cell(wallets, stdlib_hash, class_bytes)`
        — pre-seeds N Ed25519 wallets (java.lang.Wallet) at deterministic
        wc=3 addresses.  Each wallet's storage matches what `Wallet.init`
        would have written, so the chain has working wc=3 senders from
        block 0 and any subsequent contract can be deployed through the
        normal `action_create_account` path.

    Source: TOS-specific integration point.  Called from the Fift word
    `jvm-zerostate-accounts-cell` / `jvm-zerostate-from-alloc` in
    `crypto/block/create-state.cpp`.
*/
#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "jvm/core/genesis-wallet.h"
#include "td/utils/Slice.h"
#include "vm/cells.h"

namespace jvm_workchain {

/// Build the (empty) ShardAccounts cell for the wc=3 genesis shard.
///
/// Always returns a non-null cell shaped as `hme_empty$0`
/// (HashmapAugE 256 ShardAccount).
td::Ref<vm::Cell> build_jvm_zerostate_accounts_cell();

/// Build the ShardAccounts cell with N pre-seeded Ed25519 wallets.
///
/// Each wallet entry materializes a real wc=3 Account cell with
/// `account_active$1 + StateInit{code=^0x4a, data=^JVAC}`, balance
/// from `wallet.initial_balance`, and a storage_root pre-populated as
/// if `Wallet.init(wallet.owner_pubkey)` had already run.
///
/// Returns null only if any wallet's encoding fails; callers should
/// treat that as a fatal genesis build error (it means the network is
/// trying to launch with malformed wallet declarations).
td::Ref<vm::Cell> build_jvm_zerostate_accounts_cell(
    const std::vector<JvmGenesisWallet>& wallets,
    const std::array<std::uint8_t, 32>& stdlib_hash,
    td::Slice wallet_class_bytes);

}  // namespace jvm_workchain
