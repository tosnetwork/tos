#pragma once
// TEST-ONLY debit checkpoint, not a complete Withdrawal prepare. The enclosing
// registered engine is reachable only with its existing D59 instance permit.
#include "workchain-m3-business-config.h"
#include "block/workchain-withdrawal-codec.h"
#include "block/workchain-confidential-execution.h"

namespace block::m3_test {
inline bool is_m5_test_debit(const td::Ref<vm::Cell>& root) {
  if (root.is_null()) return false;
  bool special = false;
  auto s = vm::load_cell_slice_special(root, special);
  return !special && s.size() == 32 && s.size_refs() == 1 && s.prefetch_ulong(32) == 0x54574431;
}
inline td::Ref<vm::Cell> wrap_m5_test_debit(td::Ref<vm::Cell> input) {
  return vm::CellBuilder().store_long(0x54574431, 32).store_ref(input).finalize();
}
inline td::Result<WorkchainWithdrawalInput> decode_m5_test_debit(const td::Ref<vm::Cell>& root) {
  if (!is_m5_test_debit(root)) return td::Status::Error(-7200, "invalid test debit selector");
  return decode_workchain_withdrawal_input(vm::load_cell_slice(root).prefetch_ref());
}
inline td::Result<std::string> m5_debit_context(const WorkchainTransferEnvironment& env,
    const M5TestPrepareParameters& policy, const WorkchainConfidentialAccount& old,
    const WorkchainWithdrawalInput& input) {
  using namespace confidential_execution_detail;
  const auto& c = input.data.claims;
  if (!matches_policy(old, env) || !same_address(old.address, c.source) || old.key_epoch != c.key_epoch ||
      !std::holds_alternative<WorkchainAccountActive>(old.lifecycle) || env.height > c.expiry_height)
    return invalid("Withdrawal source identity, lifecycle or expiry mismatch");
  TRY_RESULT(next, next_workchain_confidential_counters(old, c.auth_nonce, c.available_revision));
  (void)next;
  TRY_RESULT(total, workchain_withdrawal_total(input.data.amounts)); (void)total;
  TRY_RESULT(id, derive_workchain_withdrawal_id(network(env), old.address, old.auth_nonce));
  TRY_RESULT(attempt, derive_workchain_attempt_id(id));
  if (input.claimed_operation_id != id || input.claimed_attempt_id != attempt)
    return invalid("Withdrawal identity mismatch");
  TRY_RESULT(data, encode_workchain_withdrawal_data(input.data));
  TRY_RESULT(previous, encode_workchain_confidential_account(old));
  const auto& p = env.protocol;
  WorkchainWithdrawalContext context{
      {{p.engine_version, p.relation_version, p.wire_version, p.proof_version,
        p.global_id, p.workchain_id, p.genesis_hash, p.workchain_instance},
       env.rules, env.profiles, env.fee_profile, env.fee_effective_height,
       old.address, old.auth_nonce, old.available_revision, old.key_epoch},
      {id, data->get_hash().bits(), previous->get_hash().bits()}, attempt,
      policy.settlement_blocks, policy.withdrawal_limit};
  return encode_workchain_withdrawal_context(context);
}
inline td::Result<td::Ref<vm::Cell>> execute_m5_test_debit(const WorkchainTransferEnvironment& env,
    const M5TestPrepareParameters& policy, const WorkchainConfidentialAccount& old,
    const WorkchainWithdrawalInput& input, WorkchainProofVerifier& verifier) {
  TRY_RESULT(context, m5_debit_context(env, policy, old, input));
  const auto& a = input.authorization;
  UnoCryptoWithdrawalVerifyRequestV1 request{};
  request.abi_version = 1; request.limits = env.limits;
  std::copy(env.domain.begin(), env.domain.end(), request.domain);
  auto copy = [](unsigned char* dst, const td::Bits256& word) {
    std::memcpy(dst, word.as_slice().data(), 32);
  };
  copy(request.withdrawal_id, input.claimed_operation_id); copy(request.attempt_id, input.claimed_attempt_id);
  request.principal = input.data.amounts.principal; request.outward_fee = input.data.amounts.outward_fee;
  request.return_reserve = input.data.amounts.return_reserve; request.operation_fee = input.data.amounts.operation_fee;
  unsigned i = 0;
  for (const auto& point : {old.public_key, old.available.commitment, old.available.handle,
       input.data.available.commitment, input.data.available.handle, input.data.auxiliary}) copy(request.balance_points[i++], point);
  request.context = reinterpret_cast<const unsigned char*>(context.data()); request.context_bytes = context.size();
  request.commitments = reinterpret_cast<const unsigned char (*)[32]>(a.commitments.data());
  request.commitment_count = a.commitments.size();
  request.responses = reinterpret_cast<const unsigned char (*)[32]>(a.responses.data());
  request.response_count = a.responses.size();
  request.proof = reinterpret_cast<const unsigned char*>(a.range_proof.data()); request.proof_bytes = a.range_proof.size();
  TRY_STATUS(verifier.verify(request));
  auto updated = old;
  TRY_RESULT(next, next_workchain_confidential_counters(old, old.auth_nonce, old.available_revision));
  updated.auth_nonce = next.auth_nonce; updated.available_revision = next.available_revision;
  updated.available = input.data.available;
  if (updated.auth_nonce == UINT64_MAX) updated.lifecycle = WorkchainAccountReadOnly{};
  // Both pending collections are copied unchanged. No W or payout is claimed
  // by this deliberately incomplete checkpoint.
  return encode_workchain_confidential_account(updated);
}
}  // namespace block::m3_test
