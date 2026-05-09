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

// Round-37 fix: billed compute-failure output.  Used when the engine
// reaches a rejection AFTER the runtime (or output builder) has
// already done resolver / class-load / execution work — the
// admission floor (round-34) covers that work even though no useful
// contract logic ran.  Pre-runtime rejects (sk_no_gas / sk_bad_state
// from decode / binding gates) continue to use `skipped_output` with
// zero fees because no resolver work happened there.
//
// Round 49 MEDIUM fix: emit this as an executed-but-failed compute
// (`tr_phase_compute_vm$1`) rather than a "skipped" compute
// (`tr_compute_phase_skipped`).  The wire format
// (crypto/block/transaction.cpp serialize_compute_phase, line
// ~4385) only carries `gas_used` / `gas_fees` on the executed
// branch; the skipped branch is just a 2-bit reason code.  Pre-fix
// `skipped_output_billed` set `skip_reason != sk_none`, which made
// the host charge the fees but the on-chain transaction record
// (and any block-explorer / light-client / audit tool replaying
// the BOC) reported "compute skipped" with no gas — an externally
// visible accounting divergence between balance debits and the
// transaction's compute phase.
//
// The fix encodes the original skip reason via `exit_code`:
//   sk_no_gas    → -100  (out-of-gas-class rejection, e.g. round-40
//                          walk-gas cap or round-30 host insufficient
//                          balance — though the host's reject path
//                          still uses skipped_output with
//                          accepted=false; this billed shape is for
//                          the engine-side cap firing *before* the
//                          host gets to charge)
//   sk_bad_state → -101  (state / output-builder rejection, e.g.
//                          round-12 max_storage_cells, round-32
//                          runtime resolver error, round-37 admission
//                          floor on engine-side malformed args)
//   anything else → -200 (catch-all; not currently produced)
// Negative codes keep these clearly separate from any positive
// TVM-style exit code a future evolution might use.
block::WorkchainComputeOutput skipped_output_billed(
    int skip_reason,
    std::string vm_log,
    const JvmConfig& config,
    std::uint64_t gas_used = kJvmAdmissionGasFloor,
    bool out_of_gas = false,
    bool msg_state_used = false) {
    block::WorkchainComputeOutput out;
    out.completed = true;
    // Round 51 LOW fix: forward the host's first-activation signal
    // even on the billed reject path.  Pre-Round-51 only the
    // build_jvm_workchain_output success path set
    // `output.msg_state_used`; failed first-activation rejects
    // (e.g. unknown method_id under msg_state_used=true) returned
    // here with the default `false`, so the wire-format
    // tr_phase_compute_vm$1.msg_state_used lied about whether the
    // transaction consumed StateInit.  account_activated stays
    // `false` because activation requires a committed compute output.
    out.msg_state_used = msg_state_used;
    // accepted=true is required for the host's round-30 charging
    // block to actually debit the admission floor.  The compute is
    // semantically "the message was accepted by the contract layer
    // (resolver / runtime ran), but the result is rejected
    // (engine_success=false, committed=false) and no state
    // transitions apply".  Mirrors TVM's treatment of compute-
    // failed-but-gas-used.
    out.accepted = true;
    // Round 49 fix: emit on the executed branch (skip_reason ==
    // sk_none) so wire serialization carries the gas fields.
    out.skip_reason = block::ComputePhase::sk_none;
    out.engine_success = false;
    out.out_of_gas = out_of_gas;
    switch (skip_reason) {
        case block::ComputePhase::sk_no_gas:
            out.exit_code = -100;
            break;
        case block::ComputePhase::sk_bad_state:
            out.exit_code = -101;
            break;
        default:
            out.exit_code = -200;
            break;
    }
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
        // Round 54 MEDIUM fix: pass `cfg->config.max_class_bytes` so
        // the decoder bails out as soon as the running class_bytes
        // total exceeds the cap.  Pre-fix the decoder fully copied +
        // sha256-hashed up to 1 MiB before this engine then rejected
        // with `skipped_output(sk_bad_state)` — zero-billed
        // validator-CPU work per submission.  Decode-failure here
        // still hits the existing zero-billed reject; the win is
        // that an attacker-controlled chunk chain larger than the
        // cap no longer forces full-blob work.
        if (!decode_jvm_contract_account_state(
                input.current_data, state,
                cfg->config.max_class_bytes)) {
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
            // Round 58 LOW fix: the inbound `StateInit.code` is
            // caller-controlled and the host's custom-engine branch
            // (`Transaction::prepare_compute_phase`) preserves it on a
            // committed activation.  JVM execution is dispatched by
            // workchain id, not by code, so attacker-supplied code is
            // never executed — but it persists on-chain in
            // `account.code`, breaking the invariant that all wc=3
            // JVM accounts carry the canonical activation marker
            // (single byte 0x4a).  Reject any non-marker first-
            // activation inbound here; the host will fall back to
            // its policy `activation_code` (i.e. the marker) since
            // the engine emits no `new_code`.
            if (input.current_code.not_null()
                && input.current_code->get_hash() !=
                       jvm_activation_code_cell()->get_hash()) {
                return skipped_output(
                    block::ComputePhase::sk_bad_state,
                    "JVM first activation: StateInit.code is not the "
                    "canonical activation marker");
            }
            // Round 59 LOW fix: same threat for `StateInit.library`.
            // Pre-fix the host copied `si.library` into
            // `new_library` and committed it verbatim into
            // `account.library`.  Canonical JVM accounts have no
            // library (TVM precompile semantics don't apply), so
            // any non-null inbound library is non-canonical bytes
            // that pollute the on-chain state record.  Reject here.
            // `current_library` was plumbed through
            // `WorkchainComputeInput` in this round.
            if (input.current_library.not_null()) {
                return skipped_output(
                    block::ComputePhase::sk_bad_state,
                    "JVM first activation: StateInit.library must "
                    "be empty");
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
        // Round 66 MEDIUM fix: pre-compute total argument bytes so
        // the resolver-error path can bill them.  Pre-fix the
        // round-61 arg-bytes charge happened INSIDE the runtime
        // AFTER `execute_jvm_avata_transaction` returned, so a
        // resolver failure (e.g. method not in class) short-
        // circuited before the charge — `parse_jvm_args` had
        // already memcpy'd the full payload (up to ~1 MiB), but
        // dispatch billed only `kJvmAdmissionGasFloor`.
        // `peek_jvm_args_total_bytes` walks the chunk chain
        // summing byte counts WITHOUT memcpy, returning the same
        // total the runtime's round-61 post-charge would compute.
        // For the success path the runtime's round-61 charge
        // already added these bytes to `invocation.gas_used`, so
        // we don't re-add here.  Only the error path uses this.
        std::uint64_t error_path_arg_bytes = 0;
        {
            auto call_descriptor_res =
                parse_jvm_call_descriptor(input.inbound_body);
            if (call_descriptor_res.is_ok() &&
                call_descriptor_res.ok().args.not_null()) {
                auto bytes_res = peek_jvm_args_total_bytes(
                    call_descriptor_res.ok().args);
                if (bytes_res.is_ok()) {
                    error_path_arg_bytes = bytes_res.ok();
                }
            }
        }
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
            //
            // Round 66 MEDIUM fix: bill `max(floor, arg_bytes)` to
            // cover the byte-decode work that already happened in
            // `parse_jvm_args` before the resolver returned an
            // error.  Mirrors the runtime's round-61 success-path
            // post-charge of arg bytes.
            const std::uint64_t error_billed =
                std::max<std::uint64_t>(kJvmAdmissionGasFloor,
                                        error_path_arg_bytes);
            return skipped_output_billed(
                block::ComputePhase::sk_bad_state,
                "JVM runtime invocation failed",
                cfg->config,
                /*gas_used=*/error_billed,
                /*out_of_gas=*/false,
                /*msg_state_used=*/input.msg_state_used);
        }
        auto invocation = invocation_res.move_as_ok();
        // Round 62 MEDIUM fix: cap the runtime-reported gas at
        // `effective_gas_limit` BEFORE the storage-walk branch.  The
        // runtime now post-charges argument bytes (round-61) directly
        // into `invocation.gas_used`, so a no-storage-mutate call
        // with large typed `Bytes` arguments could push gas_used past
        // the cap before this engine even reaches the round-40
        // walk-gas cap (which sits inside the storage-walk branch and
        // therefore did not fire for non-mutating calls).  Without
        // this gate, `build_jvm_workchain_output` rejected the result
        // with "gas_used > gas_limit", dispatch converted to
        // sk_bad_state with the over-cap amount, and the host's
        // round-30 charging block zeroed the fee when balance fell
        // short — a free-CPU loop for attacker payloads.  Bill the
        // cap here and reject with sk_no_gas to mirror round-40's
        // post-walk cap.
        if (invocation.gas_used > effective_gas_limit) {
            LOG(DEBUG) << "JVM runtime gas_used (incl. arg bytes) exceeded "
                          "the affordable cap; billing the cap and rejecting "
                          "(sk_no_gas)";
            return skipped_output_billed(
                block::ComputePhase::sk_no_gas,
                "JVM runtime gas exceeded affordable cap",
                cfg->config, effective_gas_limit,
                /*out_of_gas=*/true,
                /*msg_state_used=*/input.msg_state_used);
        }
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
        // kJvmStorageWalkGasPerCell now lives in avata-execution.h so
        // rpc.cpp's local-simulation can mirror this billing identically.
        // Round 43 LOW: track whether dispatch performed the walk
        // successfully, so build_jvm_workchain_output can skip the
        // duplicate walk it used to do (validator-CPU was 2x what
        // the contract paid for).
        bool storage_walk_performed = false;
        if (cfg->config.max_storage_cells > 0
            && invocation.success
            && invocation.storage_root.not_null()) {
            const bool storage_changed =
                state.storage_root.is_null()
                || invocation.storage_root->get_hash()
                       != state.storage_root->get_hash();
            if (storage_changed) {
                storage_walk_performed = true;
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
                // Round-40 fix: cap the post-walk gas at
                // `effective_gas_limit`.  Without this, a contract
                // can fund itself for exactly `runtime_gas * gas_price`,
                // execute that much, then mutate storage so the
                // round-39 walk pushes `invocation.gas_used` above
                // the limit.  The engine reports `gas_fees` exceeding
                // balance, the host's round-30 charging block converts
                // the call to sk_no_gas with `gas_fees = 0`, and no
                // state commits — the contract repeats the work for
                // free.  We cap to `effective_gas_limit` and treat
                // the overflow as `sk_no_gas` with the cap as gas_used,
                // so the host bills exactly the affordable amount.
                if (invocation.gas_used > effective_gas_limit) {
                    LOG(DEBUG) << "JVM storage walk pushed gas_used past "
                                  "the affordable cap; billing the cap "
                                  "and rejecting (sk_no_gas)";
                    return skipped_output_billed(
                        block::ComputePhase::sk_no_gas,
                        "JVM storage walk gas exceeded affordable cap",
                        cfg->config, effective_gas_limit,
                        /*out_of_gas=*/true,
                        /*msg_state_used=*/input.msg_state_used);
                }
                if (stat_result.is_error()) {
                    LOG(DEBUG) << "JVM storage walk hit max_storage_cells "
                                  "(treated as sk_bad_state, billing "
                               << invocation.gas_used << " gas)";
                    return skipped_output_billed(
                        block::ComputePhase::sk_bad_state,
                        "JVM committed storage_root exceeds max_storage_cells",
                        cfg->config, invocation.gas_used,
                        /*out_of_gas=*/false,
                        /*msg_state_used=*/input.msg_state_used);
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
        const bool invocation_committed = invocation.success;
        auto output_res = build_jvm_workchain_output(
            cfg->config, state, effective_gas_limit, std::move(invocation),
            /*storage_walk_already_billed=*/storage_walk_performed);
        if (output_res.is_error()) {
            LOG(DEBUG)
                << "JVM output builder returned error "
                   "(treated as sk_bad_state): "
                << output_res.error().message();
            return skipped_output_billed(
                block::ComputePhase::sk_bad_state,
                "JVM output builder failed",
                cfg->config,
                invocation_gas_used,
                /*out_of_gas=*/false,
                /*msg_state_used=*/input.msg_state_used);
        }
        auto output = output_res.move_as_ok();
        // Round 50 LOW fix: forward the host's first-activation
        // signal into the serialized compute phase.  The host sets
        // `input.msg_state_used = true` when it unpacked
        // `StateInit.data` from the inbound message to activate an
        // `acc_uninit` account (transaction.cpp prepare_compute_phase
        // round-14 plumbing); without copying it here the output's
        // default `false` is what the wire records, so block
        // explorers / light clients / audit replays cannot tell that
        // a JVM contract activation happened on this transaction.
        // `account_activated` mirrors the same signal: a successful
        // first-activation compute genuinely transitions
        // acc_uninit→acc_active.  For subsequent calls
        // (`msg_state_used = false`) the defaults stay correct.
        output.msg_state_used = input.msg_state_used;
        output.account_activated =
            input.msg_state_used && invocation_committed;
        return output;
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
