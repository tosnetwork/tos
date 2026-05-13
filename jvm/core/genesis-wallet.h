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

// Genesis Deployer declaration.  Structurally mirrors `JvmGenesisWallet`
// but lands the account at a `java.lang.Deployer`-shaped address: the
// derived address binds the Deployer manifest (init/deploy/getNonce)
// and the Deployer slot-name prefix.
//
// Why this is distinct from JvmGenesisWallet: the address binding gate
// at `dispatch-engine.cpp` checks `manifest_root_hash`, so a Deployer
// at the same (owner_pubkey, salt) as a Wallet derives to a different
// wc=3 address.  Mixing them in one genesis dict therefore cannot
// collide.  The Deployer is the only contract on a fresh wc=3 chain
// that can emit `action_create_account` — without at least one
// genesis Deployer, no further wc=3 contracts can ever be deployed.
struct JvmGenesisDeployer {
    std::array<std::uint8_t, 32> owner_pubkey{};
    std::array<std::uint8_t, 32> salt{};
    td::RefInt256 initial_balance;
};

// Result of `build_jvm_genesis_deployer`.  Same shape as the wallet
// build — distinct type only to keep call sites self-documenting.
struct JvmGenesisDeployerBuild {
    JvmContractId address{};
    td::Ref<vm::Cell> shard_account_cell;
    td::Ref<vm::Cell> account_cell;
    td::Ref<vm::Cell> contract_account_state_cell;
};

// Build the per-Deployer bits.  `deployer_class_bytes` is the canonical
// rt.jar Deployer.class bytecode (NOT the Wallet bytecode — they must
// be admitted separately by the contract-profile header).
td::Result<JvmGenesisDeployerBuild> build_jvm_genesis_deployer(
    const JvmGenesisDeployer& deployer,
    const std::array<std::uint8_t, 32>& stdlib_hash,
    td::Slice deployer_class_bytes);

// Build the canonical `java.lang.Wallet` method manifest cell.  The
// returned cell's `repr_hash` is hashed into every Wallet address —
// it is consensus-stable and MUST equal the cell hash produced by the
// Rust port (`contracts::jvm_wallet::build_wallet_manifest_cell`).
// The codec parity test (`JvmCodecParityVectors`) pins this property.
td::Ref<vm::Cell> build_wallet_manifest_cell();

// Build the canonical `java.lang.Deployer` method manifest cell.
// Same parity guarantee as `build_wallet_manifest_cell`: the cell's
// `repr_hash` is hashed into every Deployer address and MUST equal
// the Rust port's output.
td::Ref<vm::Cell> build_deployer_manifest_cell();

}  // namespace jvm_workchain
