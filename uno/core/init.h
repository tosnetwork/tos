/*
    Uno Workchain — module initialisation.

    Call `init_uno_workchain(db_root)` once at node startup — §8.3.

    Responsibilities:
      1. Register the UnoNativeEngine with the global WorkchainExecutionRegistry
         via `uno_workchain::register_uno_workchain_engine`.
      2. Load (or zero-init from genesis) the wc=2 executor account's
         UnoShardState from CellDb at `db_root`.
      3. Install the end-of-block hook that:
           - pushes commitment_tree_root into the anchor window
           - compiles the block's compact filter from accumulated filter_tags
      4. Pre-load the Plonky3 verifier state (FRI params, Poseidon2 consts,
         public-input schema, AIR precomputations).
      5. Warm the nullifier LRU by scanning the last K blocks of inserts.

    Source: TOS-specific adapter.
*/
#pragma once

#include <cstdint>
#include <string>

#include "block/transaction.h"  // block::ComputePhase
#include "vm/cells/Cell.h"
#include "vm/cells/CellSlice.h"

namespace uno_workchain {

class UnoState;

/// Register the native Uno workchain engine with the host chain. Called from
/// validator-engine.cpp, immediately after `evm_workchain::init_evm_workchain`.
void init_uno_workchain(const std::string& db_root = "");

/// Run the Uno compute phase using the live global state singleton.
///
/// This is the direct-call entry point used by `UnoNativeEngine::run_compute()`
/// (uno/core/dispatch-engine.cpp). It contains the compute path that previously
/// lived behind the Phase 1-2 callback bridge:
///   1. Hydrate g_live from `state_data` if needed; on failure set cp fields
///      for sk_bad_state and return true.
///   2. Set the current block seqno on g_live.
///   3. Delegate to `run_compute_phase(cp, in_msg_body, ...)`.
///
/// Returns true if the phase completed (even on reject), false on infra error.
bool uno_run_compute_phase(
    block::ComputePhase& cp,
    td::Ref<vm::Cell> state_data,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]);

/// Access the global Uno state singleton. Created inside
/// `init_uno_workchain`; owns the in-memory `UnoShardState` for this process.
UnoState& global_uno_state();

/// Builds the wc=2 zerostate ShardAccounts cell with the single UNO executor
/// account at address 0x00…01 pre-registered as `acc_uninit`. Mirrors
/// `build_evm_zerostate_accounts_cell()` for wc=1. Called from the Fift word
/// `uno-zerostate-accounts-cell` in create-state.cpp.
///
/// The seeded account carries:
///   - addr = MsgAddressInt{wc=2, account_id = kUnoExecutorAddressBytes}
///   - balance = 0
///   - state = account_uninit$00
/// The first MineUno ext_in_msg delivered to this address activates the
/// account via the wc=2 dispatch path in transaction.cpp (acc_uninit →
/// acc_active with the canonical 0x55 'U' code marker and the serialised
/// UnoShardState as data). No pre-seeded commitment tree / nullifier set
/// / anchor window — those are materialised lazily by the first tx.
///
/// Deterministic and side-effect-free: same output on every validator.
td::Ref<vm::Cell> build_uno_zerostate_accounts_cell();

}  // namespace uno_workchain
