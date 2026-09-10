#pragma once
// TEST WALLET INPUT ONLY. No proof generation, curve arithmetic or admission.
#include "block/workchain-registration.h"
#include "block/workchain-confidential-input.h"

namespace block::m3_test {
struct M3TestRegistrationWalletInput {
  WorkchainConfidentialAccount account;
  td::Ref<vm::Cell> account_data;
  td::Bits256 operation_id;
  WorkchainReplayContext context;
  std::string context_bytes, prefix_bytes;
};

inline std::string m3_test_registration_prefix(const WorkchainConfidentialAccount& a) {
  std::string prefix;
  auto be=[&](std::uint64_t n,unsigned width) {
    for (unsigned i=width;i>0;--i) prefix.push_back(static_cast<char>(n>>(8*(i-1))));
  };
  be(static_cast<std::uint32_t>(a.global_id),4);
  prefix+=a.genesis_hash.as_slice().str();
  be(static_cast<std::uint32_t>(a.address.workchain_id),4);
  for (const auto& v:{a.address.account,a.address.instance,a.bindings.asset,a.bindings.custody,a.bindings.policy})
    prefix+=v.as_slice().str();
  be(a.schema_version,2); be(a.relation_profile,2); be(a.proof_profile,2); be(a.key_epoch,4);
  return prefix;
}

// Policy is the host's actual registration policy, including mandatory possession
// configuration (v2 host API). It is a template only to keep this test header
// usable on the encoding branch before that host API is integrated. No fallback
// exists for a policy lacking possession. Native payer identity is explicit;
// validating its admission/refund eligibility remains the host's responsibility.
template <class Policy>
inline td::Result<M3TestRegistrationWalletInput> make_m3_test_registration_wallet_input(
    const Policy& policy, std::int32_t payer_workchain, const td::Bits256& payer_account,
    const td::Bits256& public_key, const td::Bits256& account_key) {
  WorkchainConfidentialAccount a{};
  a.global_id=policy.global_id; a.genesis_hash=policy.genesis_hash;
  a.address={policy.possession.protocol.workchain_id,account_key,td::Bits256::zero()};
  a.bindings=policy.bindings;
  a.schema_version=policy.schema_version; a.relation_profile=policy.relation_profile;
  a.proof_profile=policy.proof_profile; a.public_key=public_key;
  a.funding={policy.deposit,payer_workchain,payer_account};
  // Explicit initial registration state, not defaults for an existing account.
  a.key_epoch=0; a.auth_nonce=0; a.available_revision=0;
  a.available={td::Bits256::zero(),td::Bits256::zero()}; a.pending.clear();
  a.lifecycle=WorkchainAccountActive{};
  TRY_RESULT(id,derive_workchain_registration_operation_id(policy,a));
  a.address.instance=id;
  TRY_RESULT(data,encode_workchain_confidential_account(a));
  auto context=rebuild_workchain_possession_context(policy.possession,a);
  TRY_RESULT(bytes,encode_workchain_replay_context(context,WorkchainReplayOperation::Registration));
  // Existing test-wallet register prefix, matching key_possession.rs numeric
  // BE fields after context and before P/R. Domain tag/context/P/R are NOT here.
  auto prefix=m3_test_registration_prefix(a);
  if (prefix.size()!=210 || bytes.size()!=426) return td::Status::Error("M3 test wallet context size mismatch");
  return M3TestRegistrationWalletInput{a,data,id,context,bytes,prefix};
}
} // namespace block::m3_test
