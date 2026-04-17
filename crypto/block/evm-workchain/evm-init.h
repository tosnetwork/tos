/*
    EVM Workchain — module initialisation.

    Call init_evm_workchain() once at node startup to register the EVM
    compute phase handler with the host-chain transaction pipeline.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstddef>
#include <string>

#include "td/utils/Slice.h"
#include "vm/cells/Cell.h"

namespace vm {
class Dictionary;
class AugmentedDictionary;
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
    const td::Ref<vm::Cell>& evm_account_data_cell,
    const td::Ref<vm::Cell>& code_cell = {});

/// Walk an `AugmentedDictionary` of `ShardAccount` entries (i.e. the wc=1
/// `account_dict` loaded from a previously-committed `ShardState`), and
/// for each entry whose `StateInit.data` decodes as `EvmAccountData`, push
/// the account (nonce + balance + code_hash) and its storage slots into
/// `target`'s in-RAM CellEvmState.
///
/// Used at the start of every wc=1 block by the collator and validate-query
/// to rehydrate `g_evm_state` from canonical state when the process is
/// fresh (`EvmState::is_empty() == true`). Replaces the obsolete
/// `evm-state.boc` sidecar load path.
///
/// Idempotent and side-effect-free on the input dict. Returns the number
/// of accounts hydrated (zero if `shard_accounts` is empty or contains no
/// EVM-shaped entries).
size_t populate_state_from_shard_accounts(
    EvmState& target,
    vm::AugmentedDictionary& shard_accounts);

/// Convenience wrapper used from `tos_validator` (collator + validate-query).
///
/// If the process-global `g_evm_state` is empty AND `shard_accounts` is
/// non-empty, calls `populate_state_from_shard_accounts(global_evm_state(),
/// shard_accounts)` and returns the count. Otherwise returns 0.
///
/// Provided so call sites in collator.cpp / validate-query.cpp don't have to
/// `#include "evm-state.h"` (which would pull silkworm headers into the
/// validator library's include surface).
size_t hydrate_global_state_if_empty(vm::AugmentedDictionary& shard_accounts);

/// Build a ShardAccounts dict cell containing the 10 pre-funded test EOAs.
///
/// Used at zerostate generation (Phase C): the wc=1 zerostate's
/// `accounts:^ShardAccounts` field is set to this cell, so every chain
/// generated from this commit has the test accounts present from genesis.
/// Returns a cell suitable to be stored as the `^ShardAccounts` ref of a
/// ShardState whose accounts dict contains 10 EVM EOAs each holding 10000 TOS.
///
/// Deterministic: same inputs (the constexpr kTestAccounts list and the
/// EvmAccountData encoder) → byte-identical cell hash on every binary.
td::Ref<vm::Cell> build_evm_zerostate_accounts_cell();

}  // namespace evm_workchain
