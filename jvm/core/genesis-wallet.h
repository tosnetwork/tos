/*
    JVM Workchain — wc=3 genesis wallet seeder.

    Network operators declare a list of pre-deployed Ed25519 wallet
    accounts in the zerostate (typically through the Fift word
    `jvm-zerostate-from-alloc`).  This module materializes each
    declaration into the cells the wc=3 ShardAccounts dict expects:

      ShardAccount {
        account:^Account = account$1
                            addr_std$10(wc=3, addr=derived)
                            storage_stat:StorageInfo (computed)
                            storage:AccountStorage = (
                                last_trans_lt:0
                                balance:initial
                                state:account_active$1
                                      + StateInit { code=^marker(0x4a)
                                                    data=^JVAC } )
        last_trans_hash:0
        last_trans_lt:0
      }

    The derived address satisfies `dispatch-engine.cpp`'s address-binding
    gate because all five inputs (deployer / address_commit / class_hash /
    manifest_root_hash, then sha256 with the `"TOS-JVM-CONTRACT-v2"`
    domain tag) are computed here using the same helpers consensus uses.

    The wallet storage is pre-populated with the three slots
    `Wallet.ownerPubKey`, `Wallet.nonce`, `Wallet.initFlag` exactly as
    `java.lang.Wallet.init()` would write them on first activation, so
    a genesis wallet is functionally indistinguishable from one deployed
    later through `action_create_account` + an inbound init message.
*/
#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "jvm/core/cell-codec.h"
#include "jvm/core/deploy-abi.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "td/utils/int_types.h"
#include "vm/cells.h"

namespace jvm_workchain {

// A single genesis wallet declaration. `salt` lets a single owner
// hold multiple distinct wallets at distinct addresses; pick any
// 32 bytes (sha256 of a human-readable name works well).
struct JvmGenesisWallet {
    std::array<std::uint8_t, 32> owner_pubkey{};
    std::array<std::uint8_t, 32> salt{};
    td::RefInt256 initial_balance;
};

// Everything a caller needs to insert one genesis wallet into the
// wc=3 ShardAccounts dict.  `address` is the wc=3 32-byte account
// address; `shard_account_cell` is the entry value (Account ref +
// last_trans_hash + last_trans_lt) ready for `set_builder`/
// `set_ref`-style insertion.
struct JvmGenesisWalletBuild {
    JvmContractId address{};
    td::Ref<vm::Cell> shard_account_cell;
    td::Ref<vm::Cell> account_cell;
    td::Ref<vm::Cell> contract_account_state_cell;
};

// Sentinel deployer for genesis wallets.  Uses all-zero bytes to
// signal "this account was seeded at network zerostate, not deployed
// by any wc=3 sender".  Genesis accounts are `acc_active` from block 0,
// so they never traverse the first-activation gate that would have
// rejected an all-zero deployer.
constexpr JvmContractId kJvmGenesisDeployer{};

// Build the per-wallet bits.  `wallet_class_bytes` is the canonical
// rt.jar Wallet.class bytecode; `stdlib_hash` mirrors ConfigParam 85's
// stdlib_hash at the chosen launch ConfigParam.
//
// Returns an error on any cell-encoding failure (oversize class blob,
// malformed pubkey, etc.).  The caller should fail the genesis build
// loudly — a malformed genesis wallet is a network-launch bug, not a
// runtime fault.
td::Result<JvmGenesisWalletBuild> build_jvm_genesis_wallet(
    const JvmGenesisWallet& wallet,
    const std::array<std::uint8_t, 32>& stdlib_hash,
    td::Slice wallet_class_bytes);

}  // namespace jvm_workchain
