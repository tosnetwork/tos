/*
    EVM Workchain — module initialisation.

    Call init_evm_workchain() once at node startup to register the EVM
    compute phase handler with the host-chain transaction pipeline.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <vector>

#include "td/utils/Slice.h"
#include "vm/cells/Cell.h"

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace vm {
class Dictionary;
class AugmentedDictionary;
}

namespace evm_workchain {

class EvmState;

/// Register the EVM compute phase handler with the host chain.
void init_evm_workchain(const std::string& db_root = "");

/// Access the global EVM workchain state singleton.
EvmState& global_evm_state();

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
/// `#include "evm/core/state.h"` (which would pull silkworm headers into the
/// validator library's include surface).
size_t hydrate_global_state_if_empty(vm::AugmentedDictionary& shard_accounts);

/// Cancun pre-fork prep — see Category E in
/// `doc/evm-workchain-known-divergences.md`. The two helpers below are
/// invoked from `init_evm_workchain` on every node startup. They are
/// idempotent and safe to call against a Shanghai-revision config; they
/// only become load-bearing once `cancun_time = 0` is flipped in
/// `evm_chain_config()`.

/// Deploy the EIP-4788 beacon-roots system contract at the magic address
/// `0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02`. Sets nonce=1, balance=0,
/// and writes the canonical 200-byte runtime bytecode from the EIP. No-op
/// when the contract is already in state with the correct code_hash, so
/// it's safe to call on every node startup. Exposed publicly so the
/// state-test runner and unit tests can re-invoke it on a fresh EvmState.
void seed_eip4788_predeploy(EvmState& state);
void seed_eip2935_predeploy(EvmState& state);  // EIP-2935 (Pectra)

/// Run the EIP-4844 spec test vector through the KZG point-evaluation
/// precompile (silkworm `precompile::point_evaluation_run`). Logs WARNING
/// on success, ERROR if the precompile fails (which would be a build-time
/// issue — the trusted setup is bundled as a constexpr in evmone, so
/// failure here means the precompile is missing/unlinked). Does not
/// terminate the process; serves as a startup-time canary.
void verify_kzg_setup_loaded();

/// Devnet-only default ShardAccounts builder. Production builds return a null
/// cell here; use the parameterised `build_evm_zerostate_accounts_cell(allocs)`
/// / Fift `evm-zerostate-from-alloc` path for every real network.
td::Ref<vm::Cell> build_evm_zerostate_accounts_cell();

// =============================================================================
// Phase D — parameterised genesis allocations
// =============================================================================
//
// Allows zerostate to be built from arbitrary Ethereum-style allocs (the
// `alloc` field of a Hive `genesis.json`, the EELS / execution-apis fixture
// pre-state, an EIP-4788 predeploy seed, etc.) instead of the hard-coded
// public tutorial EOAs.
//
// The data shape mirrors Ethereum's GenesisAccount JSON:
//   address  → evmc::address
//   balance  → intx::uint256 (wei)
//   nonce    → uint64_t
//   code     → silkworm::Bytes (raw EVM bytecode; empty = EOA)
//   storage  → ordered map<bytes32, bytes32> (slot → value pairs)
//
// All fields are optional except `addr`. An entry with empty `code` and empty
// `storage` is functionally equivalent to a `seed_account()` call.

struct GenesisAccount {
    evmc::address addr{};
    intx::uint256 balance{0};
    uint64_t nonce{0};
    silkworm::Bytes code{};
    std::map<evmc::bytes32, evmc::bytes32> storage{};
};

/// Parameterised version of build_evm_zerostate_accounts_cell. Builds a
/// CellEvmState seeded with the supplied allocations, wraps it the same
/// way the zero-arg version does (single executor ShardAccount whose
/// StateInit.data is a cp.new_data v5 cell), and returns the
/// ShardAccounts cell.
///
/// Deterministic: same `accounts` vector → byte-identical cell hash.
/// The zero-arg overload is disabled in production and only exists for
/// devnet/test builds that explicitly opt into public tutorial accounts.
td::Ref<vm::Cell> build_evm_zerostate_accounts_cell(
    const std::vector<GenesisAccount>& accounts);

}  // namespace evm_workchain
