#pragma once
// TEST WALLET INPUT ONLY. No proof generation, curve arithmetic or state update.
#include "workchain-m3-registration-wallet.h"

namespace block::m3_test {
struct M3TestClosureWalletInput {
  td::Bits256 operation_id;
  WorkchainReplayContext context;
  std::string context_bytes, prefix_bytes;
};
// The caller supplies its authenticated possession policy/domain and actual old
// account. The prefix is the existing test CLI format: domain, registration
// fields, then consumed nonce and old revision. P/C/D are separate CLI fields.
template <class PossessionPolicy>
inline td::Result<M3TestClosureWalletInput> make_m3_test_closure_wallet_input(
    const PossessionPolicy& possession, const std::array<unsigned char,80>& domain,
    const WorkchainConfidentialAccount& account) {
  const auto& protocol=possession.protocol;
  TRY_RESULT(id,derive_workchain_closure_operation_id(
      {protocol.global_id,protocol.genesis_hash,protocol.workchain_instance},account.address,account.auth_nonce));
  auto context=rebuild_workchain_possession_context(possession,account);
  TRY_RESULT(bytes,encode_workchain_replay_context(context,WorkchainReplayOperation::Closure));
  std::string prefix(reinterpret_cast<const char*>(domain.data()),domain.size());
  prefix+=m3_test_registration_prefix(account);
  for (auto value:{account.auth_nonce,account.available_revision})
    for (unsigned i=8;i>0;--i) prefix.push_back(static_cast<char>(value>>(8*(i-1))));
  if (bytes.size()!=426 || prefix.size()!=306) return td::Status::Error("M3 closure wallet context size mismatch");
  return M3TestClosureWalletInput{id,context,bytes,prefix};
}
} // namespace block::m3_test
