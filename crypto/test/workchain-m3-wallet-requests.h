#pragma once
// TEST ONLY. Explicit authenticated inputs and wallet-produced points.
// No proof generation, curve arithmetic, account acquisition or state transition.
#include "block/workchain-confidential-execution.h"
#include <map>

namespace block::m3_test {
using M3WalletFields = std::map<std::string,std::string>;
struct M3PreparedWalletTransfer {
  WorkchainTransferInput input; // Authorization is supplied separately by uno/prover.
  WorkchainPreparedTransferStatement statement;
  M3WalletFields prover_fields; // Merge with explicit wallet witness fields at the caller.
};
namespace wallet_request_detail {
inline td::Status bad() { return td::Status::Error("invalid M3 test wallet request shape"); }
inline std::string words(const std::vector<std::array<unsigned char,32>>& values) {
  std::string result;
  for (const auto& v:values)
    result+=td::hex_encode(td::Slice(reinterpret_cast<const char*>(v.data()),v.size()));
  return result;
}
inline td::Result<M3PreparedWalletTransfer> prepare(
    const WorkchainTransferEnvironment& env, const WorkchainConfidentialAccount& source,
    const std::optional<WorkchainConfidentialAccount>& destination, WorkchainTransferData data) {
  const auto kind=workchain_transfer_kind(data);
  // These are the existing test CLI's explicit supported limits, not defaults.
  if (env.protocol.kind!=kind || env.limits.max_collect!=8 ||
      env.limits.max_context_bytes!=1024 || env.limits.max_proof_bytes!=4096) return bad();
  TRY_RESULT(id,derive_workchain_operation_id(
      {env.protocol.global_id,env.protocol.genesis_hash,env.protocol.workchain_instance},
      source.address,kind,source.auth_nonce));
  WorkchainTransferInput input{id,std::move(data),{}};
  WorkchainHistoricalConfidentialAccount old_source{std::optional<WorkchainConfidentialAccount>{source}};
  WorkchainHistoricalConfidentialAccount old_destination{destination};
  TRY_RESULT(statement,prepare_workchain_transfer_statement(env,input,old_source,old_destination));
  M3WalletFields fields{{"kind",std::to_string(kind)}, {"fee",std::to_string(env.execution_fee)},
      {"max_balance",std::to_string(env.limits.max_balance)}, {"max_value",std::to_string(env.limits.max_value)},
      {"domain",td::hex_encode(td::Slice(reinterpret_cast<const char*>(env.domain.data()),env.domain.size()))},
      {"context",td::hex_encode(statement.context)}, {"points",words(statement.points)},
      {"receipt_ids",words(statement.receipt_ids)}};
  return M3PreparedWalletTransfer{std::move(input),std::move(statement),std::move(fields)};
}
} // namespace wallet_request_detail

// points is the existing uno/prover `points` result; no public old state is
// trusted from it. The formal host builder reconstructs old state from records.
inline td::Result<M3PreparedWalletTransfer> prepare_m3_test_send(
    const WorkchainTransferEnvironment& env, const WorkchainConfidentialAccount& source,
    const WorkchainConfidentialAccount& destination, std::uint32_t expiry_height,
    const std::vector<td::Bits256>& points) {
  if (points.size()!=10) return wallet_request_detail::bad();
  WorkchainTransferClaims claims{source.address,source.auth_nonce,source.available_revision,
      source.key_epoch,expiry_height,env.execution_fee};
  return wallet_request_detail::prepare(env,source,destination,WorkchainSendData{
      claims,destination.address,destination.key_epoch,{points[4],points[5]},
      {points[6],points[7],points[8]},points[9]});
}
inline td::Result<M3PreparedWalletTransfer> prepare_m3_test_collect(
    const WorkchainTransferEnvironment& env, const WorkchainConfidentialAccount& owner,
    std::uint32_t expiry_height, const std::vector<td::Bits256>& selected_receipts,
    const std::vector<td::Bits256>& points) {
  // Bound before multiplication; preserve caller selection order exactly.
  if (selected_receipts.empty() || selected_receipts.size()>8 ||
      points.size()!=6+3*selected_receipts.size()) return wallet_request_detail::bad();
  WorkchainTransferClaims claims{owner.address,owner.auth_nonce,owner.available_revision,
      owner.key_epoch,expiry_height,env.execution_fee};
  WorkchainCollectData data{claims,{points[3],points[4]},points[5],{}};
  for (std::size_t i=0;i<selected_receipts.size();++i)
    data.selected.push_back({selected_receipts[i],points[8+3*i]});
  return wallet_request_detail::prepare(env,owner,std::nullopt,std::move(data));
}
inline td::Result<td::Ref<vm::Cell>> finish_m3_test_transfer(
    const M3PreparedWalletTransfer& prepared, WorkchainTransferAuthorization authorization) {
  auto input=prepared.input;
  input.authorization=std::move(authorization);
  return encode_workchain_transfer_input(input);
}
} // namespace block::m3_test
