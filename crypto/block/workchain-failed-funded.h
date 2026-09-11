#pragma once

#include "block/workchain-withdrawal-association.h"
#include "block/workchain-withdrawal-account.h"
#include "block/workchain-coordinator-state.h"
#include "block/workchain-native-inbox.h"
#include "block/workchain-operation-fees.h"
#include "block/workchain-proof-work.h"
#include <array>

namespace block {
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
};

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
    if (!association) return error("funded Failed requires strong pending payout association");
    auto found = std::find_if(owner.control.withdrawals.begin(), owner.control.withdrawals.end(),
        [&](const auto& record) { return record.attempt_id == association->attempt_id; });
    if (found == owner.control.withdrawals.end()) return error("funded Failed associated record missing");
    const auto record = *found;
    std::uint32_t deadline;
    if (record.timing.phase != 1 ||
        __builtin_add_overflow(record.timing.queue_removed_height, record.timing.settlement_blocks, &deadline) ||
        arrival_height < record.timing.queue_removed_height || arrival_height > deadline)
      return error("funded Failed requires an open height window");
    if (!std::holds_alternative<WorkchainAccountActive>(owner.account.lifecycle) ||
        owner.account.system_pending.size() + owner.origin_pending.size() >= policy.system_slots)
      return error("funded Failed receipt admission unsupported");
    if (association->received.extra.not_null() || association->received.tomis.is_null() ||
        !association->received.tomis->unsigned_fits_bits(64))
      return error("funded Failed requires a uint64 native recovery");
    const auto recovered = association->received.tomis->to_long();
    // Do not narrow a value with its top bit set through a signed conversion.
    if (recovered < 0) return error("funded Failed recovery outside supported signed range");
    const auto y = static_cast<std::uint64_t>(recovered);
    std::uint64_t loss, compute, fee, cost, gross, amount, released_w;
    if (__builtin_sub_overflow(record.principal, y, &loss) ||
        __builtin_mul_overflow(policy.base_compute, policy.issuance_billing_units, &compute) ||
        __builtin_add_overflow(policy.slot_fee, compute, &fee) ||
        __builtin_add_overflow(loss, fee, &cost) || cost > record.costs.original_reserve ||
        record.costs.consumed_return_cost != 0 ||
        __builtin_add_overflow(y, record.costs.original_reserve, &gross) ||
        __builtin_sub_overflow(gross, fee, &amount) || !amount ||
        __builtin_add_overflow(record.principal, record.costs.original_reserve, &released_w))
      return error("funded Failed shortfall or arithmetic branch unsupported");
    TRY_RESULT(sequence, next_workchain_deposit_sequence(*coordinator.deposit_sequence));
    WorkchainSystemOrigin origin = WorkchainSettlementOrigin{record.attempt_id, sequence};
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
    owner.control.withdrawals.erase(found);
    coordinator.deposit_sequence = sequence;
    TRY_RESULT(owner_data, encode_workchain_withdrawal_account(owner, policy.withdrawal_limit));
    TRY_RESULT(coordinator_data, encode_workchain_coordinator_state(coordinator));
    auto fees = materialize_workchain_operation_fees({policy.slot_fee, compute, 0, fee}, custody, coordinator_address);
    return WorkchainFailedFundedResult{owner_data, coordinator_data, receipt, fees,
        td::Bits256(envelope.msg->get_hash().bits()), record.attempt_id, y, record.principal, released_w};
  });
}
}  // namespace block
