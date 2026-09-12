#pragma once

#include "block/workchain-withdrawal-association.h"
#include "block/workchain-withdrawal-account.h"
#include "block/workchain-coordinator-state.h"
#include "block/workchain-native-inbox.h"
#include "block/workchain-operation-fees.h"
#include "block/workchain-unexpected-bucket.h"
#include "block/workchain-value-flow.h"
#include "block/workchain-proof-work.h"
#include <array>

namespace block {
enum class WorkchainReturnRoute { Window, Late };
// Required resolved policy, not protocol defaults. Billing units are D70
// configuration, independent of the seven D72 proof-work units.
struct WorkchainFailedFundedPolicy {
  std::uint32_t withdrawal_limit, system_slots;
  std::uint64_t slot_fee, base_compute, issuance_billing_units;
};
struct WorkchainFailedFundedResult {
  td::Ref<vm::Cell> owner_data, coordinator_data;
  WorkchainSystemReceipt receipt;
  WorkchainFeeSettlement fees;
  td::Bits256 inbound_message, attempt_id;
  std::uint64_t recovered, released_p, released_w;
  WorkchainReturnRoute route{WorkchainReturnRoute::Window};
  std::vector<WorkchainInternalTransfer> transfers;
  bool issued{true};
};

// This is an executed admission branch, not a label reconstructed by an oracle.
// A late return's body attributes actual imported funds; it cannot release W/P.
inline td::Result<WorkchainSystemOrigin> admit_workchain_late_return(
    const WorkchainWithdrawalAssociation& value, const td::Bits256& owner, std::uint64_t sequence) {
  auto body = vm::load_cell_slice(value.original_body);
  if (body.size_ext() != 256 || td::Bits256(body.data_bits()) != owner)
    return td::Status::Error("late return attribution differs from owner");
  LOG(INFO) << "WORKCHAIN_RETURN_CALLEE admit_workchain_late_return inbound=" << value.inbound_message.to_hex();
  return WorkchainSystemOrigin{WorkchainDepositOrigin{value.inbound_message, sequence}};
}

// Narrow immutable transition. The enclosing host must authenticate final-import
// inbox membership, predecessor roots and configuration, then install both roots,
// the actual custody import and Native fee effects atomically. No partial roots
// or counters are published. Errors remain neutral for a source-aware caller;
// this helper is not a registered engine or proof of Native publication.
// Unsupported branches are errors, NOT successful Failed/Paid/disposal outcomes.
inline td::Result<WorkchainFailedFundedResult> prepare_workchain_failed_funded(
    const WorkchainNativeInboxPlan& inbox, const td::Ref<vm::Cell>& owner_root,
    const td::Ref<vm::Cell>& coordinator_root, const WorkchainFailedFundedPolicy& policy,
    const std::array<unsigned char, 80>& domain,
    const gen::UnoV2OperationNetworkV1::Record& network, const td::Bits256& custody,
    const td::Bits256& coordinator_address, std::uint32_t arrival_height,
    WorkchainProofVerifier& verifier) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<WorkchainFailedFundedResult> {
    auto error = [](td::Slice s) { return td::Status::Error(s); };
    if (!policy.withdrawal_limit || !policy.system_slots || policy.system_slots > 4 ||
        custody == coordinator_address || inbox.envelopes.size() != 1)
      return error("funded Failed requires explicit policy and one Native input");
    TRY_RESULT(owner, decode_workchain_withdrawal_account(owner_root, policy.withdrawal_limit));
    TRY_RESULT(coordinator, decode_workchain_coordinator_state(coordinator_root));
    if (coordinator.layout_version != 3 || !coordinator.deposit_sequence ||
        owner.account.address.workchain_id != 2 || owner.account.bindings.custody != custody)
      return error("funded Failed predecessor binding mismatch");
    tlb::MsgEnvelope::Record_std envelope;
    if (!tlb::unpack_cell(inbox.envelopes.front(), envelope))
      return error("malformed funded Failed Native envelope");
    TRY_RESULT(association, associate_workchain_withdrawal_return(envelope.msg, 2, custody, network, owner.control));
    const bool matched = association.has_value();
    if (!association) {
      TRY_RESULT(late, describe_workchain_late_return(envelope.msg, 2, custody));
      association = std::move(late);
    }
    auto found = std::find_if(owner.control.withdrawals.begin(), owner.control.withdrawals.end(),
        [&](const auto& record) { return record.attempt_id == association->attempt_id; });
    if (matched && found == owner.control.withdrawals.end()) return error("funded Failed associated record missing");
    bool late = !matched;
    // D77: a strongly matched bounce is positive delivery evidence. Phase 0
    // has no running window; its zero removed-height is NOT a deadline origin.
    // Phase 1 still uses the authenticated height window, not record presence.
    if (matched && found->timing.phase != 0) {
      std::uint32_t deadline;
      if (found->timing.phase != 1 ||
          __builtin_add_overflow(found->timing.queue_removed_height, found->timing.settlement_blocks, &deadline) ||
          arrival_height < found->timing.queue_removed_height)
        return error("invalid authenticated return window");
      late = arrival_height > deadline;
    }
    if (association->received.extra.not_null() || association->received.tomis.is_null() ||
        !association->received.tomis->unsigned_fits_bits(64))
      return error("funded Failed requires a uint64 native recovery");
    const auto recovered = association->received.tomis->to_long();
    // Do not narrow a value with its top bit set through a signed conversion.
    if (recovered < 0) return error("funded Failed recovery outside supported signed range");
    const auto y = static_cast<std::uint64_t>(recovered);
    std::uint64_t compute, fee, amount;
    // D78 has one positive-issuance rule: y must strictly exceed slot+g.
    // The checked subtraction enforces that bound without an unsigned wrap.
    // Arithmetic failure is distinct from a well-formed value below service
    // cost. The latter must publish attributed bucket value, not refuse it.
    if (__builtin_mul_overflow(policy.base_compute, policy.issuance_billing_units, &compute) ||
        __builtin_add_overflow(policy.slot_fee, compute, &fee))
      return error("return service fee arithmetic overflow");
    const bool no_slot = owner.account.system_pending.size() + owner.origin_pending.size() >= policy.system_slots;
    const bool closed = !std::holds_alternative<WorkchainAccountActive>(owner.account.lifecycle);
    if (y <= fee || no_slot || closed) {
      // Resolve attribution before touching the bucket. For a matched return
      // the authenticated record supplies it; otherwise the complete body does.
      if (!matched) {
        auto body = vm::load_cell_slice(association->original_body);
        if (body.size_ext() != 256 || td::Bits256(body.data_bits()) != owner.account.address.account)
          return error("bucket return attribution differs from owner");
      }
      gen::Message::Record message;
      gen::CommonMsgInfo::Record_int_msg_info info;
      tos::WorkchainId source_wc; td::Bits256 source;
      if (!tlb::type_unpack_cell(envelope.msg, gen::t_Message_Any, message) ||
          !tlb::csr_unpack(message.info, info) ||
          !tlb::t_MsgAddressInt.extract_std_address(info.src, source_wc, source))
        return error("bucket return source unavailable");
      TRY_RESULT(bucket, decode_workchain_unexpected_bucket(coordinator.unexpected, {256, 256}, 4096));
      const auto previous_count = bucket.entries.size();
      TRY_RESULT(credited, credit_workchain_unexpected(bucket, {256, 256},
          {source_wc, source}, association->received, 4096));
      if (credited.bucket.entries.size() != previous_count) {
        credited.bucket.account_attribution = true;
        credited.bucket.entries.back().account_id = owner.account.address.account;
      }
      if (credited.sender_attribution_lost || credited.extra_attribution_lost)
        LOG(WARNING) << "WORKCHAIN_RETURN_BUCKET attribution overflow inbound=" << association->inbound_message.to_hex();
      TRY_RESULT(bucket_root, encode_workchain_unexpected_bucket(credited.bucket, {256, 256}, 4096));
      coordinator.unexpected = std::move(bucket_root);
      const auto released = matched ? found->principal : std::uint64_t{0};
      if (matched) owner.control.withdrawals.erase(found);
      TRY_RESULT(owner_data, encode_workchain_withdrawal_account(owner, policy.withdrawal_limit));
      TRY_RESULT(coordinator_data, encode_workchain_coordinator_state(coordinator));
      LOG(INFO) << "WORKCHAIN_RETURN_CALLEE type2_bucket_disposition inbound=" << association->inbound_message.to_hex();
      WorkchainFailedFundedResult result{owner_data, coordinator_data, {}, {},
          association->inbound_message, association->attempt_id, y, released, released,
          late ? WorkchainReturnRoute::Late : WorkchainReturnRoute::Window};
      result.issued = false;
      if (y) result.transfers.push_back({custody, coordinator_address, association->received});
      return result;
    }
    if (__builtin_sub_overflow(y, fee, &amount) || !amount)
      return error("return amount underflow");
    TRY_RESULT(sequence, next_workchain_deposit_sequence(*coordinator.deposit_sequence));
    WorkchainSystemOrigin origin;
    if (late) {
      TRY_RESULT(attributed, admit_workchain_late_return(*association, owner.account.address.account, sequence));
      origin = std::move(attributed);
    } else {
      LOG(INFO) << "WORKCHAIN_RETURN_CALLEE window_return inbound=" << association->inbound_message.to_hex();
      origin = WorkchainSettlementOrigin{found->attempt_id, sequence};
    }
    TRY_RESULT(id, derive_workchain_system_receipt_id(origin));
    for (const auto& entry : owner.account.pending)
      if (entry.receipt_id == id) return error("funded Failed duplicate receipt id");
    for (const auto& entry : owner.account.system_pending)
      if (entry.receipt_id == id) return error("funded Failed duplicate receipt id");
    for (const auto& entry : owner.origin_pending)
      if (entry.receipt_id == id) return error("funded Failed duplicate receipt id");
    TRY_RESULT(bytes, encode_workchain_system_origin_transcript(origin));
    UnoCryptoSystemEncryptionRequestV2 request{};
    request.abi_version = 2; request.amount = amount;
    request.origin_bytes = static_cast<std::uint32_t>(bytes.size());
    if (bytes.size() > sizeof(request.origin)) return error("funded Failed origin exceeds ABI buffer");
    std::copy(bytes.begin(), bytes.end(), request.origin);
    std::copy(domain.begin(), domain.end(), request.domain);
    std::copy(id.as_slice().begin(), id.as_slice().end(), request.receipt_id);
    std::copy(owner.account.public_key.as_slice().begin(), owner.account.public_key.as_slice().end(), request.recipient);
    TRY_RESULT(ciphertext, verifier.system_encrypt(request));
    WorkchainCiphertext encoded;
    encoded.commitment.as_slice().copy_from(td::Slice(ciphertext.commitment, 32));
    encoded.handle.as_slice().copy_from(td::Slice(ciphertext.handle, 32));
    WorkchainSystemReceipt receipt{id, amount,
        {owner.account.address.instance, owner.account.key_epoch, owner.account.bindings.asset}, encoded, origin};
    owner.origin_pending.push_back(receipt);
    const auto released = matched ? found->principal : std::uint64_t{0};
    const auto attempt = association->attempt_id;
    if (matched) owner.control.withdrawals.erase(found);
    coordinator.deposit_sequence = sequence;
    TRY_RESULT(owner_data, encode_workchain_withdrawal_account(owner, policy.withdrawal_limit));
    TRY_RESULT(coordinator_data, encode_workchain_coordinator_state(coordinator));
    auto fees = materialize_workchain_operation_fees({policy.slot_fee, compute, 0, fee}, custody, coordinator_address);
    return WorkchainFailedFundedResult{owner_data, coordinator_data, receipt, fees,
        td::Bits256(envelope.msg->get_hash().bits()), attempt, y, released, released,
        late ? WorkchainReturnRoute::Late : WorkchainReturnRoute::Window};
  });
}
}  // namespace block
