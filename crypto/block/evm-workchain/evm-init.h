/*
    EVM Workchain — module initialisation.

    Call init_evm_workchain() once at node startup to register the EVM
    compute phase handler with the host-chain transaction pipeline.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <string>

#include "td/utils/Slice.h"
#include "vm/cells/Cell.h"

namespace vm {
class Dictionary;
}

namespace evm_workchain {

class EvmState;
class IncrementalTrieCalculator;

/// Register the EVM compute phase handler with the host chain.
void init_evm_workchain(const std::string& db_root = "");

/// Access the global EVM workchain state singleton.
EvmState& global_evm_state();

/// Access the global incremental trie calculator.
IncrementalTrieCalculator& global_trie_calculator();

/// Populate `target` with one entry per pre-funded test account.
///
/// Each entry has key = padded 256-bit EVM address and value = a single ref
/// to a freshly-encoded `EvmAccountData` cell (nonce=0, balance=10000 TOS,
/// empty code/storage). The encoding is identical to what the silkworm-side
/// `seed_test_accounts` produces — so the host-chain ShardAccounts mirror
/// and the EVM in-RAM state stay in sync at first-block bootstrap time.
///
/// Used by collator and validate-query on the very first wc=1 block. The
/// iteration order is the source-order of `kTestAccounts`, identical across
/// all validator binaries → consensus-deterministic.
void copy_test_accounts_into_dict(vm::Dictionary& target);

/// Build the inner Account cell for a wc=1 EVM account.
///
/// The returned cell is a TLB-valid `Account` whose `StateInit.data` references
/// the supplied `evm_account_data_cell` (an `EvmAccountData` cell produced by
/// `encode_evm_account_data`). Outer balance is zero; code is the canonical
/// `0x45` marker (see `evm_workchain_dispatch::get_evm_code_marker_cell`).
///
/// The dict-value layout for ShardAccounts is:
///   `^Account + last_trans_hash:bits256 + last_trans_lt:uint64`
/// — the caller is responsible for adding the 320 trailing bits.
///
/// Deterministic and side-effect-free: identical inputs produce identical
/// cell hashes on every validator. The declaration lives in this header
/// (not evm-cell-state.h) so callers in tos_validator can use it without
/// pulling in silkworm headers.
td::Ref<vm::Cell> build_evm_shard_account_cell(
    const td::Bits256& addr_bits,
    const td::Ref<vm::Cell>& evm_account_data_cell);

}  // namespace evm_workchain
