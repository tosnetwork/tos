/*
    JVM Workchain — native engine implementation.

    JvmNativeEngine implements WorkchainEngine following the same pattern as
    EvmNativeEngine (evm/core/dispatch-engine.cpp) and UnoNativeEngine.

    run_compute decodes the canonical per-account JvmContractAccountState
    from `input.current_data` and delegates actual contract invocation to
    an installed JvmComputeRuntime.  A production binary without that
    runtime fails closed if wc=3 is active.

    Source: TOS-specific integration point.
*/
#include "jvm/core/dispatch-engine.h"

#include "block/block-auto.h"
#include "block/transaction.h"
#include "block/workchain-execution-dispatch.h"
#include "jvm/core/cell-codec.h"
#include "jvm/core/config-param.h"
#include "jvm/core/deploy-abi.h"
#include "jvm/core/message-abi.h"
#include "td/utils/Status.h"
#include "td/utils/logging.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cellslice.h"

#include <cstring>
#include <limits>

#include <memory>
#include <string>

namespace jvm_workchain {

namespace {

// JVM activation code cell: single byte 0x4a ('J').
td::Ref<vm::Cell> jvm_activation_code_cell() {
    vm::CellBuilder cb;
    cb.store_long(kJvmActivationCode, 8);
    return cb.finalize();
}

struct JvmEngineConfig final : public block::WorkchainEngineConfig {
    JvmConfig config;
};

block::WorkchainComputeOutput skipped_output(int skip_reason,
                                             std::string vm_log,
                                             bool out_of_gas = false) {
    block::WorkchainComputeOutput out;
    out.completed = true;
    out.skip_reason = skip_reason;
    out.out_of_gas = out_of_gas;
    out.gas_fees = td::zero_refint();
    out.vm_log = std::move(vm_log);
    return out;
}

block::WorkchainEngineKey jvm_engine_key() {
    // vm_version = 0x4a564d31 ("JVM1"), sign-extended to int64_t via int32_t.
    return block::WorkchainEngineKey{
        block::WorkchainFormat::Basic,
        static_cast<std::int64_t>(static_cast<std::int32_t>(kJvmVmVersion))};
}

class JvmNativeEngine final : public block::WorkchainEngine {
 public:
    explicit JvmNativeEngine(std::shared_ptr<const JvmComputeRuntime> runtime)
        : runtime_(std::move(runtime)) {
    }

    block::WorkchainEngineKey engine_key() const override {
        return jvm_engine_key();
    }

    td::Result<std::shared_ptr<const block::WorkchainEngineConfig>>
    validate_and_resolve_config(
        const block::WorkchainExecutionDescriptor& descriptor,
        const block::Config& block_transition_config) const override {
        if (descriptor.format != block::WorkchainFormat::Basic ||
            static_cast<std::int32_t>(descriptor.vm_version) != kJvmVmVersion) {
            return td::Status::Error("JVM engine received non-JVM descriptor");
        }
        if (descriptor.vm_mode != 0) {
            return td::Status::Error("JVM v1 descriptor requires vm_mode=0");
        }
        TRY_RESULT(parsed_config,
                   parse_jvm_config_cell(
                       block_transition_config.get_config_param(kJvmConfigParam)));
        auto cfg = std::make_shared<JvmEngineConfig>();
        cfg->config = parsed_config;
        std::shared_ptr<const block::WorkchainEngineConfig> result = cfg;
        return result;
    }

    block::AccountExecutionPolicy account_policy(
        const block::WorkchainExecutionDescriptor& /*descriptor*/,
        const block::WorkchainEngineConfig& /*engine_config*/) const override {
        // Account-native topology: each JVM contract is its own wc=3
        // account at a deterministic address derived by
        // `derive_jvm_contract_address`.  The host accepts any address in
        // wc=3 and lets the engine emit `action_create_account` to
        // materialize new contract accounts (host plumbing in
        // crypto/block/transaction.cpp Transaction::try_action_create_account).
        block::AccountExecutionPolicy policy;
        policy.kind = block::AccountExecutionPolicyKind::EngineDefined;
        policy.singleton_address.reset();
        policy.accepts_external_inbound = true;
        policy.accepts_internal_inbound = true;
        policy.may_activate_uninitialized_account = true;
        policy.admits_engine_create_account_actions = true;
        policy.activation_code = jvm_activation_code_cell();
        return policy;
    }

    td::Result<block::WorkchainComputeOutput> run_compute(
        const block::WorkchainComputeInput& input,
        const block::WorkchainComputeContext& context) const override {
        auto* cfg = dynamic_cast<const JvmEngineConfig*>(context.engine_config.get());
        if (cfg == nullptr || cfg->config.chain_id == 0) {
            return td::Status::Error("JVM engine missing resolved ConfigParam 85");
        }
        if (input.inbound_body.is_null()) {
            return skipped_output(block::ComputePhase::sk_bad_state,
                                  "JVM inbound body is missing");
        }
        if (input.gas_limit == 0 || input.gas_limit > cfg->config.max_gas_per_tx) {
            return skipped_output(block::ComputePhase::sk_no_gas,
                                  "JVM gas limit is outside ConfigParam 85 bounds",
                                  true);
        }
        if (runtime_ == nullptr) {
            return skipped_output(block::ComputePhase::sk_bad_state,
                                  "JVM Avata interpreter runtime is not installed");
        }
        // Round-31 fix: cap the engine's gas budget by what the
        // account can actually pay at the JVM's gas price.  Round 30
        // turned the post-hoc balance check into a graceful -701
        // rejection, but the engine still ran with the full host gas
        // budget, letting a zero/low-balance account force validators
        // to execute up to `max_gas_per_tx` work that the host then
        // discards.  Compute `affordable = balance / gas_price` and
        // pass `min(input.gas_limit, affordable)` to the runtime.
        // gas_price is u64 from ConfigParam 85; balance.tomis is a
        // RefInt256 from the host.  affordable=0 (balance can't even
        // pay one gas unit) routes through the host's round-30
        // sk_no_gas reject path.
        std::uint64_t effective_gas_limit = input.gas_limit;
        if (cfg->config.gas_price > 0
            && input.account_balance.tomis.not_null()) {
            auto affordable_int =
                input.account_balance.tomis
                / td::make_refint(cfg->config.gas_price);
            if (affordable_int.not_null()) {
                std::uint64_t affordable = 0;
                if (affordable_int->fits_bits(64, /*sign=*/false)) {
                    affordable = affordable_int->to_long();
                } else {
                    // balance/gas_price > UINT64_MAX → not constraining.
                    affordable = std::numeric_limits<std::uint64_t>::max();
                }
                if (affordable < effective_gas_limit) {
                    effective_gas_limit = affordable;
                }
            }
        }
        // After capping, gas_limit may be 0; the host's round-30
        // charging block will then see gas_used=0, gas_fees=0, the
        // engine returns no useful work, and the call ends up
        // sk_no_gas via the normal "engine returned 0 useful gas"
        // path.
        if (parse_jvm_call_descriptor(input.inbound_body).is_error()) {
            return skipped_output(
                block::ComputePhase::sk_bad_state,
                "JVM inbound body is not a valid call descriptor");
        }

        JvmContractAccountState state;
        if (!decode_jvm_contract_account_state(input.current_data, state)) {
            return skipped_output(
                block::ComputePhase::sk_bad_state,
                "JVM contract account state cell is malformed");
        }
        if (state.stdlib_hash != cfg->config.stdlib_hash) {
            return skipped_output(
                block::ComputePhase::sk_bad_state,
                "JVM contract account stdlib hash does not match ConfigParam 85");
        }
        // Round 17 fix: bind the loaded rt.jar to ConfigParam 85.
        // Without this, two validators with identical on-chain
        // ConfigParam 85 + state both pass the
        // `state.stdlib_hash == cfg.stdlib_hash` gate above and then
        // execute against possibly-different local rt.jar contents
        // (silent consensus divergence).  `runtime_->rt_jar_hash()` is
        // computed at runtime startup over the actual loaded boot
        // classpath bytes; if it does not match the on-chain
        // `stdlib_hash`, the validator's runtime is incompatible with
        // consensus and we fail closed for every wc=3 transaction.
        const auto runtime_jar_hash = runtime_->rt_jar_hash();
        std::array<std::uint8_t, 32> cfg_stdlib_hash_array{};
        std::memcpy(cfg_stdlib_hash_array.data(),
                    cfg->config.stdlib_hash.data(),
                    cfg_stdlib_hash_array.size());
        if (runtime_jar_hash != cfg_stdlib_hash_array) {
            return skipped_output(
                block::ComputePhase::sk_bad_state,
                "JVM Avata runtime rt.jar does not match ConfigParam 85 "
                "stdlib_hash; refusing to run wc=3 transactions");
        }
        // ConfigParam 85's `max_class_bytes` cap must be enforced at
        // consensus, not just at the JSON-RPC admission layer.
        // Pre-round-9 the consensus path skipped this check, which let
        // a class up to `kJvmStorageValueMaxBytes` (1 MiB) bypass the
        // governance limit and inflate per-call sha256 / class-load
        // cost.  `decoded_class_bytes_size` is populated by
        // `decode_jvm_contract_account_state`, so this is O(1) here.
        if (cfg->config.max_class_bytes > 0 &&
            state.decoded_class_bytes_size >
                cfg->config.max_class_bytes) {
            return skipped_output(
                block::ComputePhase::sk_bad_state,
                "JVM contract class_bytes exceeds ConfigParam 85 max_class_bytes");
        }
        // Address-binding gate: the wc=3 account address must equal
        //   sha256("TOS-JVM-CONTRACT-v2"
        //          || state.address_commit
        //          || state.class_hash
        //          || sha256-cell-hash(state.manifest_root))
        //
        // Without this check an attacker could deliver any well-formed
        // StateInit to a victim's deterministic but not-yet-active
        // address (the host-side custom-engine branch unpacks
        // `StateInit.data` for every acc_uninit wc=3 transaction and
        // skips `check_in_msg_state_hash` because v2 addresses are
        // derived from the deploy descriptor, not from `hash(StateInit)`).
        // Since the address is the sha256 of the four bound fields, the
        // only way to land at a chosen victim address is a sha256
        // pre-image; rejecting any state whose `(address_commit,
        // class_hash, manifest_root_hash)` does not produce
        // `account_addr` therefore prevents both the bytecode-squat and
        // the manifest-swap (method_id redirect) attacks.
        //
        // Manifest is immutable post-deploy (build_jvm_workchain_output
        // forwards previous_state.manifest_root unchanged), so this
        // binding holds on every subsequent call.
        const auto manifest_hash = compute_jvm_manifest_root_hash(
            state.manifest_root);
        const auto expected_addr = derive_jvm_contract_address_from_state(
            state.deployer, state.address_commit, state.class_hash,
            manifest_hash);
        if (std::memcmp(input.account_addr.data(), expected_addr.data(),
                        expected_addr.size()) != 0) {
            return skipped_output(
                block::ComputePhase::sk_bad_state,
                "JVM contract account state does not bind to account address");
        }
        // First-activation invariants (msg_state_used == true): the
        // host has just unpacked a StateInit-bearing message into
        // `current_data`.  Two checks here, plus the address-binding
        // gate above:
        //   * `storage_root` must be empty/null — otherwise an attacker
        //     who knows the victim's deploy tuple could pre-load
        //     attacker-favorable storage (e.g. `owner = attacker`).
        //   * The inbound message MUST be int_msg_info with src.addr
        //     equal to `state.deployer` — otherwise an attacker who
        //     saw the victim's pending deploy could copy the StateInit
        //     and run their own first-call body on the same address
        //     (round-14 front-run finding).
        if (input.msg_state_used) {
            if (state.storage_root.not_null()) {
                return skipped_output(
                    block::ComputePhase::sk_bad_state,
                    "JVM contract account state has non-empty storage_root at "
                    "first activation");
            }
            if (input.inbound_message.is_null()) {
                return skipped_output(
                    block::ComputePhase::sk_bad_state,
                    "JVM first activation requires an inbound message");
            }
            try {
                bool special = false;
                auto msg_cs = vm::load_cell_slice_special(
                    input.inbound_message, special);
                if (special) {
                    return skipped_output(
                        block::ComputePhase::sk_bad_state,
                        "JVM first activation: inbound_message is special");
                }
                int tag = block::gen::t_CommonMsgInfo.get_tag(msg_cs);
                if (tag != block::gen::CommonMsgInfo::int_msg_info) {
                    return skipped_output(
                        block::ComputePhase::sk_bad_state,
                        "JVM first activation requires an internal message "
                        "(external first activation cannot authenticate "
                        "the deployer)");
                }
                block::gen::CommonMsgInfo::Record_int_msg_info info;
                if (!tlb::unpack(msg_cs, info)) {
                    return skipped_output(
                        block::ComputePhase::sk_bad_state,
                        "JVM first activation: inbound int_msg_info "
                        "is malformed");
                }
                block::gen::MsgAddressInt::Record_addr_std src;
                if (!block::gen::csr_unpack(info.src, src)) {
                    return skipped_output(
                        block::ComputePhase::sk_bad_state,
                        "JVM first activation: inbound src is not addr_std");
                }
                // Round 15 + 16 fix: also verify src.workchain_id ==
                // context.workchain_id (the wc this engine instance
                // serves) and that src.anycast is Nothing.  Without
                // this, an attacker in a different workchain whose
                // 32-byte address happened to match (or could be
                // coerced to match via an anycast-shaped addr_std)
                // the victim's deployer.addr would satisfy the
                // round-14 32-byte auth even though the address
                // derivation only commits to the deployer's 32-byte
                // id.  Restricting the deployer's workchain to the
                // executing workchain makes the binding
                // cryptographically tight: forging a matching src
                // requires a sha256 pre-image on the 32-byte
                // deployer field of the address derivation.
                //
                // Round 16 swapped the hard-coded `3` for
                // `context.workchain_id` so the same engine binary
                // wired to a non-wc=3 testnet workchain would still
                // require src in that workchain (the registry
                // routes by descriptor engine key, not by wc id, so
                // wc-hardcoding here was a future-proofing hole).
                if (src.workchain_id != context.workchain_id) {
                    return skipped_output(
                        block::ComputePhase::sk_bad_state,
                        "JVM first activation: inbound src.workchain "
                        "does not match the executing workchain");
                }
                // anycast is Maybe Anycast.  size() == 1 means Nothing
                // (the prefix bit is 0 with no payload); larger means
                // a Just-Anycast prefix follows.
                if (src.anycast.is_null() || src.anycast->size() != 1) {
                    return skipped_output(
                        block::ComputePhase::sk_bad_state,
                        "JVM first activation: inbound src.anycast must "
                        "be Nothing");
                }
                std::array<std::uint8_t, 32> src_bytes{};
                std::memcpy(src_bytes.data(), src.address.data(), 32);
                if (src_bytes != state.deployer) {
                    return skipped_output(
                        block::ComputePhase::sk_bad_state,
                        "JVM first activation: inbound src.addr does not "
                        "match state.deployer");
                }
            } catch (vm::VmError&) {
                return skipped_output(
                    block::ComputePhase::sk_bad_state,
                    "JVM first activation: inbound_message decode hit VmError");
            } catch (vm::VmVirtError&) {
                return skipped_output(
                    block::ComputePhase::sk_bad_state,
                    "JVM first activation: inbound_message decode hit "
                    "VmVirtError");
            } catch (...) {
                return skipped_output(
                    block::ComputePhase::sk_bad_state,
                    "JVM first activation: inbound_message decode failed");
            }
        }

        // Pass the affordability-capped gas limit through to the
        // runtime so it never runs more gas than the account can pay.
        block::WorkchainComputeInput effective_input = input;
        effective_input.gas_limit = effective_gas_limit;
        TRY_RESULT(invocation,
                   runtime_->run_contract(effective_input, context,
                                          cfg->config, state));
        return build_jvm_workchain_output(
            cfg->config, state, effective_gas_limit, invocation);
    }


 private:
    std::shared_ptr<const JvmComputeRuntime> runtime_;
};

}  // namespace

void register_jvm_workchain_engine(
    block::WorkchainExecutionRegistry& registry,
    std::shared_ptr<const JvmComputeRuntime> runtime) {
    registry.register_engine_if_absent(
        std::make_unique<JvmNativeEngine>(std::move(runtime)));
}

}  // namespace jvm_workchain
