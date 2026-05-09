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
#include "vm/boc.h"
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

// Round-37 fix: skipped output that bills the admission floor.
// Used when the engine reaches `sk_bad_state` AFTER the runtime
// (or output builder) has already done resolver / class-load /
// execution work — the admission floor (round-34) covers that
// work even though no useful contract logic ran.  Pre-runtime
// rejects (sk_no_gas / sk_bad_state from decode/binding gates)
// continue to use `skipped_output` with zero fees because no
// resolver work happened there.
block::WorkchainComputeOutput skipped_output_billed(
    int skip_reason,
    std::string vm_log,
    const JvmConfig& config,
    std::uint64_t gas_used = kJvmAdmissionGasFloor,
    bool out_of_gas = false) {
    block::WorkchainComputeOutput out;
    out.completed = true;
    // accepted=true is required for the host's round-30 charging
    // block to actually debit the admission floor.  The compute is
    // semantically "the message was accepted by the contract layer
    // (resolver / runtime ran), but the result is rejected
    // (engine_success=false, committed=false) and no state
    // transitions apply".  Mirrors TVM's treatment of compute-
    // failed-but-gas-used.
    out.accepted = true;
    out.skip_reason = skip_reason;
    out.out_of_gas = out_of_gas;
    // Round-38 fix: bill `max(invocation.gas_used, floor)` on
    // output-builder rejects, not just the floor.  The runtime
    // executed real work; under-billing lets a contract near
    // max_storage_cells burn most of max_gas_per_tx then trigger an
    // output rejection (e.g., one slot over cap) and pay only the
    // floor.
    out.gas_used = std::max<std::uint64_t>(gas_used,
                                            kJvmAdmissionGasFloor);
    out.gas_fees = td::make_refint(config.gas_price) * out.gas_used;
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
        if (input.gas_limit == 0) {
            return skipped_output(block::ComputePhase::sk_no_gas,
                                  "JVM gas limit is zero",
                                  true);
        }
        // Round-36 fix: the host's `compute_gas_limits` for custom
        // engines passes Param 21's gas_limit (typically 30M for
        // non-masterchain workchains) without consulting JVM's
        // `max_gas_per_tx` (typically 1M).  Pre-fix the engine
        // rejected any `input.gas_limit > max_gas_per_tx`, which
        // means under the canonical activation config (Param 21 = 30M,
        // ConfigParam 85 max_gas_per_tx = 1M) every JVM transaction
        // is rejected before runtime.  Cap to JVM's max instead of
        // rejecting; the host already takes `gas_used <= effective
        // gas limit` and bills accordingly.
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
        std::uint64_t effective_gas_limit =
            std::min<std::uint64_t>(input.gas_limit,
                                     cfg->config.max_gas_per_tx);
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
        // After capping, gas_limit may be 0 (balance < gas_price, so
        // the account can't even pay one gas unit).  Short-circuit
        // before invoking the runtime — execute_jvm_avata_transaction
        // rejects gas_limit==0 with a td::Status::Error, which would
        // propagate back through `run_compute` as a fatal collator
        // error -669 (round-32 finding).  Return a skipped output
        // with sk_no_gas so the host's round-30 charging block sees a
        // clean reject and external messages map to graceful -701.
        if (effective_gas_limit == 0) {
            return skipped_output(
                block::ComputePhase::sk_no_gas,
                "JVM account balance cannot afford a single gas unit",
                /*out_of_gas=*/true);
        }
        // Round-35 fix: enforce the admission floor BEFORE any
        // resolver / runtime work.  Round 34 added the floor in
        // `build_jvm_workchain_output`'s success path, but a balance
        // below `floor * gas_price` could still enter descriptor
        // parsing, state decode, manifest lookup, args decode, VM
        // cache/class loading, and method resolution — the host's
        // post-execution charging block then discards the result
        // with sk_no_gas zero-fee.  All that resolver work was
        // unbilled.  Rejecting at the engine boundary closes that
        // window: low-balance accounts pay the forward fee on the
        // inbound message but never reach the resolver.
        if (effective_gas_limit < kJvmAdmissionGasFloor) {
            return skipped_output(
                block::ComputePhase::sk_no_gas,
                "JVM account balance cannot afford the admission gas floor",
                /*out_of_gas=*/true);
        }
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
        // Round-32 fix: convert user-controlled runtime errors into
        // skipped compute outputs.  Pre-fix any `td::Status::Error`
        // from `run_contract` (e.g., unknown method_id, typed ABI
        // mismatch, malformed args, manifest resolution failure)
        // propagated up through TRY_RESULT, then `prepare_compute_phase`
        // returned false, then the collator mapped that to fatal
        // error -669.  User-controlled inputs reaching that path is a
        // liveness/DoS surface — the collator stops producing blocks
        // on conditions a sender can trigger.  Treat all runtime
        // errors as sk_bad_state.  `td::Status::Error` propagation is
        // reserved for node-local invariant/config failures (e.g.,
        // missing engine config), which we already handle explicitly
        // earlier in this function.
        auto invocation_res = runtime_->run_contract(
            effective_input, context, cfg->config, state);
        if (invocation_res.is_error()) {
            LOG(DEBUG)
                << "JVM runtime returned error (treated as sk_bad_state): "
                << invocation_res.error().message();
            // Round-37 fix: bill the admission floor here.  Resolver
            // work (manifest parse, args decode, class load, method
            // resolve) ran before the runtime returned an error, so
            // the account must pay for it even though the call did
            // not commit.  Without this billing, a malicious caller
            // could repeatedly trigger malformed args / bad manifest
            // resolution and consume validator CPU for free.  The
            // runtime never produced a JvmAvataInvocationResult, so
            // we bill the floor only.
            return skipped_output_billed(
                block::ComputePhase::sk_bad_state,
                "JVM runtime invocation failed",
                cfg->config);
        }
        auto invocation = invocation_res.move_as_ok();
        // Round-39 fix: bill the contract for the unique-cell walk
        // the host performs to enforce ConfigParam-85's
        // max_storage_cells.  Pre-fix the walk happened inside
        // `build_jvm_workchain_output` and consumed validator CPU
        // proportional to total committed storage (up to the cap)
        // without metering — a contract near max_storage_cells could
        // do one cheap `Storage.store` to push over the cap, the
        // validator walked ~65k cells to detect it, then
        // build_output rejected and the contract paid only its tiny
        // runtime gas.  Charge `cells_walked * 1` gas here so the
        // attack pays for the validator CPU it consumed.  We do the
        // walk in the engine instead of inside build_output because
        // build_output takes invocation by const ref and we need to
        // read the walked-cell count back to dispatch-engine for
        // billing on either success or error.
        constexpr std::uint64_t kJvmStorageWalkGasPerCell = 1;
        if (cfg->config.max_storage_cells > 0
            && invocation.success
            && invocation.storage_root.not_null()) {
            const bool storage_changed =
                state.storage_root.is_null()
                || invocation.storage_root->get_hash()
                       != state.storage_root->get_hash();
            if (storage_changed) {
                vm::CellStorageStat stat(static_cast<unsigned long long>(
                    cfg->config.max_storage_cells));
                auto stat_result =
                    stat.add_used_storage(invocation.storage_root, true);
                const std::uint64_t walk_gas =
                    stat.cells * kJvmStorageWalkGasPerCell;
                // Saturating add to avoid wraparound on absurd
                // walk counts.
                if (invocation.gas_used >
                    std::numeric_limits<std::uint64_t>::max() - walk_gas) {
                    invocation.gas_used =
                        std::numeric_limits<std::uint64_t>::max();
                } else {
                    invocation.gas_used += walk_gas;
                }
                if (stat_result.is_error()) {
                    LOG(DEBUG) << "JVM storage walk hit max_storage_cells "
                                  "(treated as sk_bad_state, billing "
                               << invocation.gas_used << " gas)";
                    return skipped_output_billed(
                        block::ComputePhase::sk_bad_state,
                        "JVM committed storage_root exceeds max_storage_cells",
                        cfg->config, invocation.gas_used);
                }
            }
        }
        // Round-33 fix: build_jvm_workchain_output can also return
        // td::Status::Error — most notably when the committed
        // storage_root exceeds ConfigParam-85's max_storage_cells
        // (round-12).  That's a user-controlled condition (a contract
        // can write distinct slots until the cap), so the error must
        // not propagate up to prepare_compute_phase as fatal -669.
        // Convert to sk_bad_state and bill the actual gas the
        // runtime used (round-38) — pre-fix this billed only the
        // admission floor, letting a contract near max_storage_cells
        // burn most of max_gas_per_tx, write one extra slot to
        // trigger output-builder rejection, and pay only the floor.
        const std::uint64_t invocation_gas_used = invocation.gas_used;
        auto output_res = build_jvm_workchain_output(
            cfg->config, state, effective_gas_limit, std::move(invocation));
        if (output_res.is_error()) {
            LOG(DEBUG)
                << "JVM output builder returned error "
                   "(treated as sk_bad_state): "
                << output_res.error().message();
            return skipped_output_billed(
                block::ComputePhase::sk_bad_state,
                "JVM output builder failed",
                cfg->config,
                invocation_gas_used);
        }
        return output_res.move_as_ok();
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
