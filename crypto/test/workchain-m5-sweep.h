#pragma once
#include "workchain-m3-business-config.h"
#include "block/workchain-unexpected-bucket.h"
#include "block/workchain-withdrawal-account.h"
#include "block/workchain-coordinator-state.h"
#include "block/workchain-proof-work.h"

namespace block::m3_test {
// Verification is read-only. A round has no authorization-time entry set and
// does not expire; unrelated credits preserve its dedicated sequence.
inline td::Status verify_m5_sweep_authorization(const M5TestSweepParameters& authorization,
    const WorkchainUnexpectedBucket& bucket, std::uint32_t height) {
  if (!bucket.sweep_sequence)
    return td::Status::Error(-7201, "authenticated sweep sequence absent; explicit initialization required");
  if (!authorization.count || authorization.count > authorization.limit || height < authorization.earliest_height ||
      authorization.sequence != *bucket.sweep_sequence)
    return td::Status::Error(-7200, "sweep round authorization mismatch");
  return td::Status::OK();
}

// Successful type-2 credit only. Other destinations belong to the independent
// bucket-sweep runner, not this completion slot. No state is published here.
struct M5SweepCredit {
  td::Ref<vm::Cell> owner, coordinator;
  td::Bits256 target;
  std::uint64_t gross, net, slot, compute;
};
inline td::Result<M5SweepCredit> apply_m5_sweep_credit(const M3TestBusinessParameters& policy,
    const td::Ref<vm::Cell>& owner_root, const td::Ref<vm::Cell>& coordinator_root,
    std::uint32_t height, int validation_cells, WorkchainProofVerifier& verifier) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<M5SweepCredit> {
    auto unsupported = [](td::Slice text) { return td::Status::Error(-7201, text); };
    if (!policy.sweep || !policy.sweep->bucket_limits || !policy.prepare || !policy.deposit || !policy.operation_tariff || validation_cells <= 0)
      return unsupported("ConfigInvalid: explicit sweep policy absent");
    auto system_result = decode_workchain_coordinator_state(coordinator_root);
    if (system_result.is_error()) return unsupported("authenticated sweep coordinator unavailable");
    auto system = system_result.move_as_ok();
    auto bucket_result = decode_workchain_unexpected_bucket(system.unexpected, *policy.sweep->bucket_limits, validation_cells);
    if (bucket_result.is_error()) return unsupported("authenticated sweep bucket unavailable");
    auto bucket = bucket_result.move_as_ok();
    TRY_STATUS(verify_m5_sweep_authorization(*policy.sweep, bucket, height));
    // This test entry currently supports one successful credit, not arbitrary
    // rounds or fallback returns. Never silently truncate an authorized round.
    if (policy.sweep->count != 1 || bucket.entries.empty())
      return unsupported("test sweep requires one existing type2 entry");
    const auto& entry = bucket.entries.front();
    if (!entry.account_id || entry.return_failed || entry.tomis.is_null() ||
        !entry.tomis->unsigned_fits_bits(63))
      return unsupported("test sweep entry is not eligible type2 credit");
    auto owner_result = decode_workchain_withdrawal_account(owner_root, policy.prepare->withdrawal_limit);
    if (owner_result.is_error()) return unsupported("authenticated sweep account unavailable");
    auto owner = owner_result.move_as_ok();
    if (owner.account.address.workchain_id != 2 || owner.account.address.account != *entry.account_id ||
        owner.account.bindings.custody != policy.rules.custody ||
        !std::holds_alternative<WorkchainAccountActive>(owner.account.lifecycle) ||
        owner.account.system_pending.size() + owner.origin_pending.size() >= policy.deposit->system_slots)
      return unsupported("test sweep credit destination unavailable");
    const auto y = static_cast<std::uint64_t>(entry.tomis->to_long());
    std::uint64_t compute, fee, amount, next_round;
    if (__builtin_mul_overflow(policy.operation_tariff->base, policy.sweep->issuance_billing_units, &compute) ||
        __builtin_add_overflow(policy.deposit->slot_fee, compute, &fee) ||
        __builtin_sub_overflow(y, fee, &amount) || !amount ||
        __builtin_add_overflow(*bucket.sweep_sequence, std::uint64_t{1}, &next_round))
      return unsupported("test sweep arithmetic or positive-issuance precondition failed");
    if (!system.deposit_sequence) return unsupported("authenticated issuance sequence absent");
    TRY_RESULT(sequence, next_workchain_deposit_sequence(*system.deposit_sequence));
    WorkchainSystemOrigin origin = WorkchainSweepOrigin{sequence,
        {2, entry.sender.workchain, entry.sender.account, *entry.account_id, entry.tomis, entry.return_failed}};
    TRY_RESULT(id, derive_workchain_system_receipt_id(origin));
    for (const auto& receipt : owner.account.pending)
      if (receipt.receipt_id == id) return unsupported("sweep duplicate receipt id");
    for (const auto& receipt : owner.account.system_pending)
      if (receipt.receipt_id == id) return unsupported("sweep duplicate receipt id");
    for (const auto& receipt : owner.origin_pending)
      if (receipt.receipt_id == id) return unsupported("sweep duplicate receipt id");
    TRY_RESULT(bytes, encode_workchain_system_origin_transcript(origin));
    UnoCryptoSystemEncryptionRequestV2 request{};
    request.abi_version = 2; request.amount = amount;
    if (bytes.size() != 115 || bytes.size() > sizeof(request.origin))
      return unsupported("constructed sweep origin shape mismatch");
    request.origin_bytes = static_cast<std::uint32_t>(bytes.size());
    std::copy(bytes.begin(), bytes.end(), request.origin);
    std::copy(policy.domain.begin(), policy.domain.end(), request.domain);
    std::copy(id.as_slice().begin(), id.as_slice().end(), request.receipt_id);
    std::copy(owner.account.public_key.as_slice().begin(), owner.account.public_key.as_slice().end(), request.recipient);
    TRY_RESULT(ciphertext, verifier.system_encrypt(request));
    WorkchainCiphertext encoded;
    encoded.commitment.as_slice().copy_from(td::Slice(ciphertext.commitment,32));
    encoded.handle.as_slice().copy_from(td::Slice(ciphertext.handle,32));
    owner.origin_pending.push_back({id, amount,
        {owner.account.address.instance, owner.account.key_epoch, owner.account.bindings.asset}, encoded, origin});
    // Only the private successor changes. Failure anywhere below or in Native
    // publication leaves BOTH authenticated counters and the old bucket intact.
    bucket.entries.erase(bucket.entries.begin());
    bucket.sweep_sequence = next_round;
    system.deposit_sequence = sequence;
    TRY_RESULT(bucket_root, encode_workchain_unexpected_bucket(bucket, *policy.sweep->bucket_limits, validation_cells));
    system.unexpected = std::move(bucket_root);
    TRY_RESULT(owner_data, encode_workchain_withdrawal_account(owner, policy.prepare->withdrawal_limit));
    TRY_RESULT(system_data, encode_workchain_coordinator_state(system));
    return M5SweepCredit{owner_data, system_data, owner.account.address.account, y, amount,
        policy.deposit->slot_fee, compute};
  });
}
}  // namespace block::m3_test
