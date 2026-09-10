#include "block/workchain-registration-proof.h"
#include <algorithm>

namespace block {
td::Status verify_workchain_closure_possession(
    const WorkchainConfidentialAccount& a, const WorkchainPossessionPolicy& policy,
    const std::array<unsigned char, 80>& domain,
    const std::array<unsigned char, 96>& proof) {
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  UnoCryptoClosurePossessionRequestV2 r{};
  r.abi_version = 2;
  auto encoded = encode_workchain_replay_context(rebuild_workchain_possession_context(policy, a),
                                                WorkchainReplayOperation::Closure);
  if (encoded.is_error()) return td::Status::Error(-7201, "authenticated closure context unavailable");
  auto context = encoded.move_as_ok();
  if (context.size() != sizeof(r.context)) return td::Status::Error(-7201, "closure context ABI mismatch");
  std::copy(context.begin(), context.end(), r.context);
  std::copy(domain.begin(), domain.end(), r.domain);
  r.global_id = a.global_id;
  r.workchain_id = a.address.workchain_id;
  auto copy = [](const td::Bits256& source, auto& target) {
    std::copy(source.as_slice().begin(), source.as_slice().end(), target);
  };
  copy(a.genesis_hash, r.genesis_hash); copy(a.address.account, r.account);
  copy(a.address.instance, r.incarnation); copy(a.bindings.asset, r.asset);
  copy(a.bindings.custody, r.custody); copy(a.bindings.policy, r.policy);
  copy(a.public_key, r.public_key); copy(a.available.commitment, r.commitment);
  copy(a.available.handle, r.handle);
  r.schema_version = a.schema_version; r.relation_profile = a.relation_profile;
  r.proof_profile = a.proof_profile; r.key_epoch = a.key_epoch;
  r.auth_nonce = a.auth_nonce; r.available_revision = a.available_revision;
  std::copy(proof.begin(), proof.end(), r.proof);
  switch (uno_crypto_verify_closure_possession_v2(&r)) {
    case UNO_CRYPTO_OK: return td::Status::OK();
    case UNO_CRYPTO_DECODE:
    case UNO_CRYPTO_VERIFY:
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                              "invalid closure zero-balance possession proof");
    default:
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                              "closure verification kernel contract failure");
  }
#else
  return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                          "closure verification kernel unavailable");
#endif
}

td::Status verify_workchain_registration_possession(
    const WorkchainConfidentialAccount& a, const WorkchainPossessionPolicy& policy,
    const std::array<unsigned char, 64>& proof) {
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  UnoCryptoKeyPossessionRequestV2 r{};
  r.abi_version = 2;
  auto encoded = encode_workchain_replay_context(rebuild_workchain_possession_context(policy, a),
                                                WorkchainReplayOperation::Registration);
  if (encoded.is_error()) return td::Status::Error(-7201, "authenticated registration context unavailable");
  auto context = encoded.move_as_ok();
  if (context.size() != sizeof(r.context)) return td::Status::Error(-7201, "registration context ABI mismatch");
  std::copy(context.begin(), context.end(), r.context);
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
  switch (uno_crypto_verify_key_possession_v2(&r)) {
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
