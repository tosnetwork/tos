/*
    Uno Workchain — native engine implementation.

    Phase 4 refactoring: `UnoNativeEngine` lives here in uno/core/ so it can
    call `uno_run_compute_phase()` directly, eliminating the function-pointer
    indirection that the old `uno_workchain_dispatch` callback bridge required.

    Source: TOS-specific integration point.
*/
#include "uno/core/dispatch-engine.h"
#include "uno/core/config-param.h"
#include "uno/core/init.h"
#include "uno/core/workchain.h"

#include "block/mc-config.h"
#include "block/transaction.h"
#include "block/workchain-execution-dispatch.h"
#include "td/utils/Status.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cellslice.h"

namespace uno_workchain {

namespace {

tos::StdSmcAddress singleton_executor_address() {
    tos::StdSmcAddress addr;
    addr.set_zero();
    addr.data()[31] = 1;
    return addr;
}

/// Canonical "Uno activated account" code marker cell.
///
/// A single-byte cell containing 0x55 ('U'). Used as StateInit.code for the
/// descriptor-selected Uno singleton executor account. The UnoShardState
/// itself lives in StateInit.data; the outer code cell only needs to satisfy
/// the "account_active" requirement.
///
/// Returns the same Ref<vm::Cell> on every call (cached singleton). All
/// validators produce the same cell hash, which CellDb will deduplicate.
td::Ref<vm::Cell> get_uno_code_marker_cell() {
    static const td::Ref<vm::Cell> kMarker = []() {
        vm::CellBuilder cb;
        cb.store_long(0x55, 8);  // 'U' — Uno activated account marker
        return cb.finalize();
    }();
    return kMarker;
}

struct UnoEngineConfig final : public block::WorkchainEngineConfig {
};

block::WorkchainComputeOutput output_from_compute_phase(
    const block::ComputePhase& cp,
    bool committed) {
    block::WorkchainComputeOutput out;
    out.skip_reason = cp.skip_reason;
    out.completed = true;
    out.accepted = cp.accepted;
    out.committed = committed;
    out.engine_success = cp.success;
    out.msg_state_used = cp.msg_state_used;
    out.account_activated = cp.account_activated;
    out.out_of_gas = cp.out_of_gas;
    out.mode = cp.mode;
    out.exit_code = cp.exit_code;
    out.exit_arg = cp.exit_arg;
    out.vm_steps = cp.vm_steps;
    out.vm_init_state_hash = cp.vm_init_state_hash;
    out.vm_final_state_hash = cp.vm_final_state_hash;
    out.gas_used = cp.gas_used;
    out.gas_fees = cp.gas_fees.not_null() ? cp.gas_fees : td::zero_refint();
    out.new_data = cp.new_data;
    out.action_list = cp.actions;
    out.vm_log = cp.vm_log;
    return out;
}

class UnoNativeEngine final : public block::WorkchainEngine {
 public:
    block::WorkchainEngineKey engine_key() const override {
        return block::uno_workchain_engine_key();
    }

    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>> validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor& descriptor,
        const block::Config& block_transition_config) const override {
        if (!block::workchain_engine_key_is_uno(
                block::workchain_engine_key_from_descriptor(descriptor))) {
            return td::Status::Error("Uno engine received non-Uno descriptor");
        }
        if (descriptor.vm_mode != 0) {
            return td::Status::Error("Uno v1 descriptor requires vm_mode=0");
        }
        // Round 128 + 129 fix: install ConfigParam 84 from the
        // masterchain config on every descriptor validation so a
        // governance update propagates to all subsequent dispatches
        // (round 129 dropped the one-shot install guard for this).
        // Pre-fix init_uno_workchain never read ConfigParam 84,
        // so the process-global g_uno_config stayed at the static
        // testnet default — chain-id checks (parallel-verify.cpp,
        // mine_uno.cpp) compared against that default while the
        // configured (e.g. mainnet) chain-id was rejected as
        // BadChainId; tx fields tied to fee_per_byte_nano /
        // anchor_window_size / etc. used testnet values regardless
        // of governance.
        //
        // Round 129 MEDIUM fix: malformed-but-present ConfigParam
        // 84 must error here, not fall through to default.  Pre-fix
        // a misconfigured chain (wrong magic, version mismatch,
        // invalid tree_depth) silently used the testnet default,
        // letting the validator accept txs valid under defaults
        // while the rest of the network rejected them.  Absence of
        // the param still falls through to the default to preserve
        // existing dev/test workflows.
        auto config_cell =
            block_transition_config.get_config_param(kUnoConfigParamIdx);
        if (config_cell.not_null()) {
            UnoConfig parsed{};
            if (!parse_uno_config_cell(config_cell, parsed)) {
                return td::Status::Error(
                    "Uno engine: ConfigParam 84 cell is present but "
                    "malformed (refusing to fall through to testnet "
                    "default)");
            }
            install_uno_config(parsed);
        }
        // Uno v1 reads chain_id from the process-global g_uno_config set by
        // install_uno_config at startup or via the round-128 path above.
        // vm_mode=0 is reserved for Uno v1, so a future Uno v2 descriptor
        // should encode chain_id in vm_mode and route it through
        // UnoEngineConfig here, matching EvmNativeEngine.
        std::shared_ptr<const block::WorkchainEngineConfig> result =
            std::make_shared<UnoEngineConfig>();
        return result;
    }

    block::AccountExecutionPolicy account_policy(
        const block::WorkchainExecutionDescriptor& /*descriptor*/,
        const block::WorkchainEngineConfig& /*engine_config*/) const override {
        block::AccountExecutionPolicy policy;
        policy.kind = block::AccountExecutionPolicyKind::SingletonExecutor;
        policy.singleton_address = singleton_executor_address();
        policy.accepts_external_inbound = true;
        policy.accepts_internal_inbound = true;
        policy.may_activate_uninitialized_account = true;
        policy.activation_code = get_uno_code_marker_cell();
        return policy;
    }

    td::Result<block::WorkchainComputeOutput> run_compute(
        const block::WorkchainComputeInput& input,
        const block::WorkchainComputeContext& context) const override {
        if (input.inbound_body.is_null()) {
            block::WorkchainComputeOutput out;
            out.completed = true;
            out.skip_reason = block::ComputePhase::sk_bad_state;
            out.gas_fees = td::zero_refint();
            return out;
        }
        // Round 64 CRITICAL fix: Uno has no canonical first-
        // activation gate.  Pre-fix the host's custom-engine branch
        // unpacked any inbound `StateInit.data` into
        // `input.current_data` before this engine ran, so the very
        // first caller to the wc=2 singleton executor (`acc_uninit`
        // in the documented zerostate) could supply an arbitrary
        // attacker-chosen `UnoShardState` and the engine would
        // commit it as the initial state — an attacker-controlled
        // state-init front-run that bypasses the genesis empty
        // shard state.  Reject any compute where the host supplied
        // `StateInit.data` (`msg_state_used == true`).  Subsequent
        // calls (msg_state_used == false) continue to thread
        // `current_data` from the prior tx's persisted account
        // state as before; first-activation must come from the
        // canonical zerostate, not from inbound StateInit.
        if (input.msg_state_used) {
            block::WorkchainComputeOutput out;
            out.completed = true;
            out.skip_reason = block::ComputePhase::sk_bad_state;
            out.gas_fees = td::zero_refint();
            return out;
        }
        // Round 64 CRITICAL fix: also reject any inbound that
        // carries a non-canonical `StateInit.code` or
        // `StateInit.library`.  Uno has no library semantics and
        // its activation marker is the singleton-executor cell
        // (`get_uno_code_marker_cell()`).  Pre-fix the host
        // copied attacker-supplied code/library into Account state
        // verbatim (same class as Round 58/59 for JVM).
        if (input.current_code.not_null()
            && input.current_code->get_hash() !=
                   get_uno_code_marker_cell()->get_hash()) {
            block::WorkchainComputeOutput out;
            out.completed = true;
            out.skip_reason = block::ComputePhase::sk_bad_state;
            out.gas_fees = td::zero_refint();
            return out;
        }
        if (input.current_library.not_null()) {
            block::WorkchainComputeOutput out;
            out.completed = true;
            out.skip_reason = block::ComputePhase::sk_bad_state;
            out.gas_fees = td::zero_refint();
            return out;
        }
        block::ComputePhase cp{};
        vm::CellSlice body_cs{*input.inbound_body};
        // Round 76 HIGH fix: forward the singleton-account balance into
        // the compute phase so it can pre-reject txs whose Round-75
        // gas_fees the singleton cannot afford.  Pre-fix, the compute
        // phase happily applied a full Transfer + fired
        // `on_included_tx_from_compute` side effects; the host then
        // reset the cp to sk_no_gas because balance < cp.gas_fees,
        // leaving in-memory g_live and the per-block outputs/tx-status
        // index out of sync with canonical state until the next tx
        // forced a `hydrate_from_cell_if_needed` resync.
        const td::RefInt256 balance =
            input.account_balance.tomis.not_null()
                ? input.account_balance.tomis
                : td::zero_refint();
        bool ok = uno_workchain::uno_run_compute_phase(
            cp,
            input.current_data,
            body_cs,
            input.gas_limit,
            context.block_seqno,
            context.now,
            context.rand_seed.data(),
            balance);
        if (!ok) {
            return td::Status::Error("Uno compute phase failed");
        }
        return output_from_compute_phase(cp, cp.success && cp.new_data.not_null());
    }
};

}  // namespace

void register_uno_workchain_engine(block::WorkchainExecutionRegistry& registry) {
    registry.register_engine_if_absent(std::make_unique<UnoNativeEngine>());
}

}  // namespace uno_workchain
