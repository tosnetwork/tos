#pragma once
// TEST-SCOPE registered engine. Shape NOT frozen. No deployment parser/hook.
// The production business-config codec is a separate undecided unit; this
// layout must not become its precedent. Authorizations come only from input.

#include "workchain-m3-business-config.h"
#include "block/workchain-confidential-execution.h"
#include "block/workchain-confidential-native.h"
#include "block/workchain-registration-payment.h"
#include "td/utils/filesystem.h"

namespace block::m3_test {
class M3NodeEngine final : public RegisteredWorkchainAccountEngine {
  const WorkchainEngineKey key_;
  const std::string observation_path_;
  mutable unsigned configurations_ = 0, executions_ = 0;
  void observe() const {
    // Synchronous test observation: a missing write is a failed instrument,
    // never evidence of zero execution.
    td::write_file(observation_path_, "config=" + std::to_string(configurations_) +
        "\nexecute=" + std::to_string(executions_) + "\n").ensure();
  }
  struct Configuration final : WorkchainEngineConfig {
    WorkchainExecutionDescriptor descriptor;
    WorkchainNativeIngressPolicy ingress;
    WorkchainEngineParameters parameters;
    M3TestBusinessParameters business;
    WorkchainSet workchains;
    td::Bits256 configuration_hash;
    Configuration(WorkchainExecutionDescriptor d, WorkchainNativeIngressPolicy i, WorkchainEngineParameters p,
                  M3TestBusinessParameters b, WorkchainSet w, td::Bits256 hash)
        : descriptor(std::move(d)), ingress(std::move(i)), parameters(std::move(p)),
          business(std::move(b)), workchains(std::move(w)), configuration_hash(hash) {}
  };
  static td::Status local(td::Slice reason) { return td::Status::Error(-7201, reason); }
  static td::Status invalid(td::Slice reason) { return td::Status::Error(-7200, reason); }
  static td::Result<WorkchainReplayInput> decode_candidate(const td::Ref<vm::Cell>& candidate) {
    // Only the already materialized candidate component is reachable here, not
    // an authenticated account/configuration read. Allocation failures retain
    // the enclosing local-failure handling instead of becoming candidate faults.
    try {
      return decode_workchain_replay_input(candidate);
    } catch (const vm::VmError&) {
      return invalid("malformed M3 candidate authorization");
    } catch (const vm::VmVirtError&) {
      return invalid("incomplete M3 candidate authorization");
    }
  }
  struct NativeAccount {
    td::Ref<vm::Cell> data;
    CurrencyCollection balance;
  };
  static td::Result<NativeAccount> read(WorkchainAccountReadView& view, const td::Bits256& key,
                                       std::uint32_t now, bool confidential) {
    TRY_RESULT(root, view.read(key));
    if (root.is_null()) return invalid("required M3 account absent");
    // The admitted read view carries Account, not ShardAccount. These synthetic
    // wrapper history fields are never used: only data/balance are extracted.
    auto wrapper = vm::CellBuilder().store_ref(root).store_zeroes(320).finalize();
    Account account(2, key.bits());
    if (!account.unpack(vm::load_cell_slice_ref(wrapper), now, false))
      return local("authenticated M3 Native account unavailable");
    if (confidential && !is_workchain_confidential_native_wrapper(account.code, account.tick, account.tock))
      return local("authenticated confidential Native wrapper mismatch");
    return NativeAccount{account.data, account.balance};
  }

 public:
  M3NodeEngine(WorkchainEngineKey key, std::string observation_path)
      : key_(key), observation_path_(std::move(observation_path)) { observe(); }
  WorkchainEngineKey engine_key() const override { return key_; }
  td::Result<std::shared_ptr<const WorkchainEngineConfig>> validate_and_resolve_config(
      const WorkchainExecutionDescriptor& descriptor, const Config& config,
      const td::Ref<vm::Cell>& payload) const override {
    CHECK(configurations_ != UINT_MAX);
    ++configurations_;
    observe();
    TRY_RESULT(table, load_workchain_native_ingress_table(config));
    auto found = table.find(descriptor.workchain_id);
    if (payload.is_null() || config.get_root_cell().is_null() || found == table.end() || !found->second.custody_address ||
        found->second.engine_configuration.is_null() ||
        found->second.engine_configuration->get_hash() != payload->get_hash())
      return local("M3 test engine lacks bound coordinator/custody configuration");
    TRY_RESULT(parameters, decode_workchain_engine_parameters(payload));
    TRY_RESULT(business, decode_m3_test_business_parameters(parameters.parameters));
    if (descriptor.workchain_id != 2 || business.rules.custody != *found->second.custody_address ||
        parameters.resources.admission_version != 4)
      return local("M3 test engine configuration incompatible with metered execution");
    return std::shared_ptr<const WorkchainEngineConfig>(std::make_shared<Configuration>(
        descriptor, found->second, std::move(parameters), std::move(business), config.get_workchain_list(),
        // Same full authenticated configuration cut as resolve_account_binding;
        // the Param84 payload alone is not the host policy identity.
        td::Bits256(config.get_root_cell()->get_hash().bits())));
  }
  td::Result<std::uint64_t> proof_work(const td::Ref<vm::Cell>& candidate, const InputPolicyIdentity& identity,
                                      const WorkchainEngineConfig& configuration) const override {
    const auto* cfg = dynamic_cast<const Configuration*>(&configuration);
    if (!cfg || td::Bits256(identity.configuration_hash.bits()) != cfg->configuration_hash)
      return local("M3 proof inspection configuration mismatch");
    TRY_RESULT(wire, decode_candidate(candidate));
    if (std::holds_alternative<WorkchainRegistrationReplayInput>(wire))
      return workchain_registration_operations_v4().total();
    if (std::holds_alternative<WorkchainClosureReplayInput>(wire))
      return workchain_closure_operations_v4().total();
    const auto& transfer = std::get<WorkchainTransferInput>(wire);
    TRY_RESULT(shape, confidential_input_detail::shape(transfer.data));
    UnoCryptoVerifyRequestV2 request{};
    request.abi_version = UNO_BALANCE_ABI_VERSION;
    request.relation = workchain_transfer_kind(transfer.data);
    request.limits = cfg->business.limits;
    request.context_bytes = 427;  // Existing fixed transfer-context v1 encoding.
    request.receipt_count = request.relation == UNO_RELATION_COLLECT
        ? std::get<WorkchainCollectData>(transfer.data).selected.size() : 0;
    request.point_count = request.relation == UNO_RELATION_SEND ? 10 : 6 + 3 * request.receipt_count;
    request.commitment_count = shape.commitments;
    request.response_count = shape.responses;
    request.proof_bytes = shape.range;
    if (request.receipt_count > cfg->business.limits.max_collect ||
        request.proof_bytes > cfg->business.limits.max_proof_bytes)
      return invalid("candidate exceeds authenticated proof shape limits");
    TRY_RESULT(operations, workchain_proof_operations_v4(request));
    return operations.total();
  }
  td::Result<WorkchainAccountEffects> execute_accounts(const td::Ref<vm::Cell>&,
      WorkchainAccountReadView&, const WorkchainEngineConfig&) const override {
    return local("M3 test engine requires admitted operation verifier");
  }
  td::Result<WorkchainAccountEffects> execute_metered_accounts(const td::Ref<vm::Cell>& input,
      WorkchainAccountReadView& accounts, const WorkchainEngineConfig& configuration,
      WorkchainProofVerifier& verifier) const override {
    CHECK(executions_ != UINT_MAX);
    ++executions_;
    observe();
    const auto* cfg = dynamic_cast<const Configuration*>(&configuration);
    if (!cfg) return local("M3 test engine configuration type mismatch");
    gen::UnoV2HostInput::Record host;
    gen::UnoV2HostIdentity::Record identity;
    gen::UnoV2HostDomain::Record domain;
    gen::UnoV2HostPolicy::Record policy;
    gen::UnoV2HostContext::Record clock;
    if (!tlb::unpack_cell(input, host) || !tlb::unpack_cell(host.identity, identity) ||
        !tlb::unpack_cell(identity.domain, domain) || !tlb::unpack_cell(identity.policy, policy) ||
        !tlb::unpack_cell(identity.context, clock) || domain.workchain_id != 2 ||
        domain.instance_id != cfg->parameters.instance_id ||
        policy.configuration_hash != cfg->configuration_hash)
      return local("M3 admitted host/configuration identity mismatch");
    const auto& b = cfg->business;
    // These protocol versions describe this TEST engine, not production defaults.
    gen::UnoV2ReplayProtocolV1::Record protocol{2, 1, 1, 2, domain.global_id, 2,
                                               domain.genesis_hash, domain.instance_id};
    gen::UnoV2TransferProfilesV1::Record profiles{policy.configuration_hash,
                                                b.generator_profile, b.range_profile};
    WorkchainPossessionPolicy possession{protocol, b.rules, profiles, b.fee_profile, b.fee_effective_height};
    TRY_RESULT(coordinator, read(accounts, cfg->ingress.executor_address, clock.gen_utime, false));
    auto system_result = decode_workchain_coordinator_state(coordinator.data);
    if (system_result.is_error()) return local("authenticated coordinator record unavailable");
    auto system = system_result.move_as_ok();
    TRY_RESULT(wire, decode_candidate(host.candidate));
    WorkchainAccountEffects result;
    if (const auto* registration = std::get_if<WorkchainRegistrationReplayInput>(&wire)) {
      const auto key = registration->context.subject.account;
      TRY_RESULT(existing, accounts.read(key));
      WorkchainRegistrationPolicy registration_policy{domain.global_id, domain.genesis_hash, domain.instance_id,
          {b.rules.asset, b.rules.custody, b.rules.policy}, b.account_schema, b.relation_profile, b.proof_profile,
          cfg->parameters.registration_deposit, possession, cfg->workchains};
      auto inbox_root = host.inbox->prefetch_ulong(1) ? host.inbox->prefetch_ref() : td::Ref<vm::Cell>{};
      TRY_RESULT(inbox, plan_workchain_native_inbox(inbox_root, 2, {cfg->ingress.executor_address},
          clock.host_after_lt, cfg->parameters.resources.input.max_inbound));
      if (inbox.envelopes.size() != 1) return invalid("registration requires one authenticated payment");
      tlb::MsgEnvelope::Record_std envelope;
      if (!tlb::unpack_cell(inbox.envelopes.front(), envelope)) return local("admitted payment unavailable");
      TRY_RESULT(payment, replay_workchain_registration_payment(registration_policy, cfg->ingress, cfg->descriptor,
          inbox, td::Bits256(envelope.msg->get_hash().bits()), system, coordinator.balance, existing,
          host.candidate, verifier));
      result.updates = {{key, payment.registration.account_data},
                        {cfg->ingress.executor_address, payment.registration.coordinator_data}};
      result.registration = std::make_shared<WorkchainRegistrationPaymentResult>(std::move(payment));
    } else if (const auto* closure = std::get_if<WorkchainClosureReplayInput>(&wire)) {
      const auto key = closure->context.subject.account;
      TRY_RESULT(native, read(accounts, key, clock.gen_utime, true));
      auto decoded_account = decode_workchain_confidential_account(native.data);
      if (decoded_account.is_error()) return local("authenticated closure account record unavailable");
      auto account = decoded_account.move_as_ok();
      TRY_RESULT(transition, replay_workchain_account_closure(account, system, possession, b.domain,
                                                             host.candidate, verifier));
      result.updates = {{key, transition.account_data},
                        {cfg->ingress.executor_address, transition.coordinator_data}};
      result.closure = std::make_shared<WorkchainAccountClosureExecution>(WorkchainAccountClosureExecution{
          key, td::Bits256(native.data->get_hash().bits()), td::Bits256(coordinator.data->get_hash().bits()),
          std::move(transition)});
    } else {
      const auto& transfer = std::get<WorkchainTransferInput>(wire);
      const auto& claims = workchain_transfer_claims(transfer.data);
      const unsigned kind = workchain_transfer_kind(transfer.data);
      TRY_RESULT(native, read(accounts, claims.source.account, clock.gen_utime, true));
      auto decoded_source = decode_workchain_confidential_account(native.data);
      if (decoded_source.is_error()) return local("authenticated source record unavailable");
      auto source = decoded_source.move_as_ok();
      std::optional<WorkchainConfidentialAccount> destination;
      td::Bits256 target = claims.source.account;
      if (const auto* send = std::get_if<WorkchainSendData>(&transfer.data)) {
        target = send->destination.account;
        TRY_RESULT(target_native, read(accounts, target, clock.gen_utime, true));
        auto decoded = decode_workchain_confidential_account(target_native.data);
        if (decoded.is_error()) return local("authenticated destination record unavailable");
        destination = decoded.move_as_ok();
      }
      WorkchainTransferEnvironment env{b.limits, b.domain,
          {2, 1, 1, 2, kind, domain.global_id, 2, domain.genesis_hash, domain.instance_id},
          b.rules, profiles, b.fee_profile, b.fee_effective_height, clock.height,
          kind == 1 ? b.send_fee : b.collect_fee, 16, b.account_schema, b.relation_profile, b.proof_profile};
      TRY_RESULT(applied, execute_workchain_confidential_transfer(env, transfer, std::optional{source},
                                                                 destination, verifier));
      result.updates = {{claims.source.account, applied.source_data},
                        {cfg->ingress.executor_address, coordinator.data}};
      if (applied.destination_data.not_null()) result.updates.push_back({target, applied.destination_data});
    }
    std::sort(result.updates.begin(), result.updates.end(), [](const auto& a, const auto& b) {
      return a.account < b.account;
    });
    return result;
  }
};
}  // namespace block::m3_test
