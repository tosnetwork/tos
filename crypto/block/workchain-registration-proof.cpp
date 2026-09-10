#include "block/workchain-registration-proof.h"
#include <algorithm>

namespace block {
td::Status verify_workchain_registration_possession(
    const WorkchainConfidentialAccount& a, const std::array<unsigned char, 64>& proof) {
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  UnoCryptoKeyPossessionRequestV1 r{};
  r.abi_version = 1;
  r.global_id = a.global_id;
  r.workchain_id = a.address.workchain_id;
  auto copy = [](const td::Bits256& source, auto& target) {
    std::copy(source.as_slice().begin(), source.as_slice().end(), target);
  };
  copy(a.genesis_hash, r.genesis_hash);
  copy(a.address.account, r.account);
  copy(a.address.instance, r.incarnation);
  copy(a.bindings.asset, r.asset);
  copy(a.bindings.custody, r.custody);
  copy(a.bindings.policy, r.policy);
  copy(a.public_key, r.public_key);
  r.schema_version = a.schema_version;
  r.relation_profile = a.relation_profile;
  r.proof_profile = a.proof_profile;
  r.key_epoch = a.key_epoch;
  std::copy(proof.begin(), proof.end(), r.proof);
  switch (uno_crypto_verify_key_possession_v1(&r)) {
    case UNO_CRYPTO_OK: return td::Status::OK();
    case UNO_CRYPTO_DECODE:
    case UNO_CRYPTO_VERIFY:
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                              "invalid registration key possession proof");
    default:
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                              "registration verification kernel contract failure");
  }
#else
  return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                          "registration verification kernel unavailable");
#endif
}
}
