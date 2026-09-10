#pragma once

#include "block/workchain-account-effects.h"
#include "block/workchain-allocation-overlay.h"
#include "block/workchain-registration-payment.h"

namespace block {

// Post-admission materialization of a locally executed registration payment,
// NEVER a result decoded from the candidate. Queue authentication and possession
// verification precede this call. The validator must derive its own payment
// transition. This is not a substitute for either authentication or replay.
//
// Two participants, one private root transition: the coordinator entry imports
// the deposit and records the counter/sub-bucket; the registration participant
// changes account_none to active. No action_create_account message, delayed
// activation, Native phases or CellDb writes occur. On any failure no root is
// returned and the authenticated old root is unchanged.
namespace registration_settlement_detail {
inline td::Result<WorkchainInboundAllocationOverlay> build(
    td::Ref<vm::Cell> old_accounts, const WorkchainHostIdentity& identity, td::Ref<vm::Cell> input,
    const WorkchainRegistrationPaymentResult& payment, const td::Bits256& coordinator, const td::Bits256& custody,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound, int extra_validation_cells,
    const SerializeConfig& cfg) {
  TRY_RESULT(created, decode_workchain_confidential_account(payment.registration.account_data));
  const auto& key = created.address.account;
  if (identity.workchain_id != 2 || created.address.workchain_id != 2 ||
      created.address.instance != identity.instance_id || created.global_id != identity.global_id ||
      created.genesis_hash != identity.genesis_hash || key == coordinator || key == custody ||
      coordinator == custody || payment.coordinator_flow.account != coordinator ||
      payment.registration.payer_balance != 0 || !payment.coordinator_flow.fees.is_zero()) {
    return td::Status::Error("registration settlement differs from locally derived payment roles");
  }
  gen::UnoV2HostInput::Record decoded;
  if (!tlb::unpack_cell(input, decoded))
    return td::Status::Error("invalid registration host input");
  TRY_RESULT(access, decode_workchain_account_declarations(decoded.access, max_reads, max_writes));
  std::vector<td::Bits256> keys{coordinator, key};
  std::sort(keys.begin(), keys.end());
  if (access.writes != keys)
    return td::Status::Error("registration requires exactly coordinator and new account");
  vm::AugmentedDictionary old(vm::load_cell_slice_ref(old_accounts), 256, tlb::aug_ShardAccounts);
  // Existence is determined by authenticated state, not local availability.
  // A repeated registration is invalid even if an earlier transition cache
  // still claims absence. Dictionary Add below independently prevents overwrite.
  if (old.lookup(key).not_null())
    return td::Status::Error(-7200, "registration ShardAccount already exists");
  Account prior(2, coordinator.bits());
  if (!prior.unpack(old.lookup(coordinator), identity.gen_utime, false) || prior.data.is_null()) {
    return td::Status::Error(-7201, "registration coordinator state unavailable");
  }
  if (payment.old_coordinator_data_hash != prior.data->get_hash().bits() ||
      prior.balance != payment.coordinator_flow.old_balance) {
    return td::Status::Error(-7201, "registration payment belongs to another state snapshot");
  }
  // Bind the imported message to this same batch, not another successful payment.
  auto inbox_root = decoded.inbox->prefetch_ulong(1) ? decoded.inbox->prefetch_ref() : td::Ref<vm::Cell>{};
  TRY_RESULT(inbox, plan_workchain_native_inbox(inbox_root, 2, {coordinator}, identity.host_after_lt, max_inbound));
  if (inbox.envelopes.size() != 1)
    return td::Status::Error("registration requires its single admitted payment");
  tlb::MsgEnvelope::Record_std envelope;
  if (!tlb::unpack_cell(inbox.envelopes[0], envelope) || payment.imported_message != envelope.msg->get_hash().bits()) {
    return td::Status::Error("registration payment does not belong to this input");
  }
  WorkchainAccountEffects effects;
  effects.updates = {{coordinator, payment.registration.coordinator_data}, {key, payment.registration.account_data}};
  std::sort(effects.updates.begin(), effects.updates.end(),
            [](const auto& a, const auto& b) { return a.account < b.account; });
  TRY_RESULT(encoded, encode_workchain_account_effects(effects, max_writes, 0, extra_validation_cells));
  return allocation_overlay_detail::build(std::move(old_accounts), identity, std::move(input), encoded, coordinator,
                                          custody, max_reads, max_writes, 0, max_inbound, extra_validation_cells, cfg,
                                          nullptr, &key);
}
}  // namespace registration_settlement_detail

// All inputs here are authenticated old views or locally rebuilt artifacts.
// Failures loading/constructing them are local; registration authorization has
// already classified candidate bytes in execute_workchain_registration_payment.
// Do not use this boundary to parse unadmitted candidate data.
inline td::Result<WorkchainInboundAllocationOverlay> settle_workchain_registration(
    td::Ref<vm::Cell> old_accounts, const WorkchainHostIdentity& identity, td::Ref<vm::Cell> input,
    const WorkchainRegistrationPaymentResult& payment, const td::Bits256& coordinator, const td::Bits256& custody,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound, int extra_validation_cells,
    const SerializeConfig& cfg) {
  auto local = [](td::Slice message) { return td::Status::Error(-7201, message); };
  if (old_accounts.is_null() || input.is_null() || payment.registration.account_data.is_null() ||
      payment.registration.coordinator_data.is_null())
    return local("registration settlement artifacts unavailable");
  try {
    auto result =
        registration_settlement_detail::build(std::move(old_accounts), identity, std::move(input), payment, coordinator,
                                              custody, max_reads, max_writes, max_inbound, extra_validation_cells, cfg);
    if (result.is_error() && result.error().code() != -7200)
      return local(result.error().message());
    return result;
  } catch (const vm::VmVirtError&) {
    return local("registration settlement view incomplete");
  } catch (const vm::VmError&) {
    return local("registration settlement authenticated view unavailable");
  } catch (const vm::CellBuilder::CellCreateError&) {
    return local("registration settlement cell allocation failed");
  } catch (const vm::CellBuilder::CellWriteError&) {
    return local("registration settlement cell construction failed");
  } catch (const std::bad_alloc&) {
    return local("registration settlement allocation failed");
  }
}

}  // namespace block
