#include "native-rpc.h"
namespace tos::auth {
Result<Bytes> NativeClientRpc::call(std::uint8_t method, const Bytes& request, const Hash& principal, std::uint64_t now,
                                    ObjectReader& reader) {
  if (request.size() > 2000000)
    return Error{"api-binary-bound"};
  Result<Anchor> anchor(Error{"unsupported-native-method"});
  if (method == 8) {
    auto q = decode<GetProfileRequest>(request);
    if (!q.ok())
      return q.error();
    anchor = q.value().anchor_;
  } else if (method == 9) {
    auto q = decode<GetPolicyRequest>(request);
    if (!q.ok())
      return q.error();
    anchor = q.value().anchor_;
  } else if (method == 10) {
    auto q = decode<GetRegistryRequest>(request);
    if (!q.ok())
      return q.error();
    anchor = q.value().anchor_;
  } else if (method == 11) {
    auto q = decode<GetKeyRequest>(request);
    if (!q.ok())
      return q.error();
    anchor = q.value().anchor_;
  } else if (method == 12) {
    auto q = decode<GetCertificateRequest>(request);
    if (!q.ok())
      return q.error();
    anchor = q.value().anchor_;
  } else if (method == 13) {
    auto q = decode<VerifyCertificateRequest>(request);
    if (!q.ok())
      return q.error();
    anchor = q.value().anchor_;
  }
  if (!anchor.ok())
    return anchor.error();
  auto state = source_.state(anchor.value());
  if (!state.ok())
    return state.error();
  auto publish = [&](const ObjectRef& manifest, std::span<const std::uint8_t> bytes) {
    return objects_.publish(principal, anchor.value(), manifest, bytes, now);
  };
  if (method == 12 || method == 13) {
    if (state.value().is_null())
      return Error{"native-source-anchor"};
    auto hash = state.value()->get_hash();
    if (!std::equal(anchor.value().state_.begin(), anchor.value().state_.end(), hash.as_slice().ubegin()))
      return Error{"native-source-anchor"};
    auto chain = source_.chain_context();
    if (!chain.ok())
      return chain.error();
    if (chain.value().network != network_)
      return Error{"certificate-chain-context"};
    std::optional<Error> source_failure;
    NativeDutyResolver expected = [&](const Duty& claim) {
      auto resolved = source_.expected_duty(anchor.value(), claim);
      if (!resolved.ok())
        source_failure = resolved.error();
      return resolved;
    };
    if (method == 13) {
      auto q = decode<VerifyCertificateRequest>(request);
      if (!q.ok())
        return q.error();
      auto verified = verify_native_certificate(q.value(), anchor.value(), chain.value(), expected, reader);
      if (!verified.ok()) {
        if (source_failure)
          return *source_failure;
        if (reader.source_error())
          return *reader.source_error();
        const auto& error = verified.error().code;
        if (error == "backend-error" || error == "unsupported-profile")
          return verified.error();
        if (error == "certificate-anchor" || error == "expected-context" || error == "certificate-chain-context")
          return Error{"api-context-mismatch"};
        return Error{"api-bad-request"};
      }
      auto result = verified.value().result();
      if (!result.ok())
        return result.error();
      return encode(result.value());
    }
    auto q = decode<GetCertificateRequest>(request);
    if (!q.ok())
      return q.error();
    auto cert = source_.certificate(anchor.value(), q.value().certificate_id_);
    if (!cert.ok())
      return cert.error();
    auto id = object_id("certificate", cert.value());
    if (!id.ok())
      return id.error();
    if (id.value() != q.value().certificate_id_)
      return Error{"certificate-id"};
    auto duty = expected(cert.value().duty_);
    if (!duty.ok())
      return duty.error();
    if (duty.value() != cert.value().duty_)
      return Error{"expected-context"};
    if (duty.value().network_ != chain.value().network || duty.value().genesis_root_ != chain.value().genesis_root ||
        duty.value().genesis_file_ != chain.value().genesis_file || duty.value().anchor_mc_ != anchor.value().seqno_)
      return Error{"certificate-chain-context"};
    auto committee = NativeCommittee::derive(state.value(), anchor.value(), chain.value(),
                                             {duty.value().workchain_, duty.value().shard_}, duty.value().catchain_);
    if (!committee.ok())
      return committee.error();
    auto verified = committee.value().snapshot().verify(cert.value(), duty.value());
    if (!verified.ok())
      return verified.error();
    auto proof = make_committee_proof(state.value(), anchor.value(), chain.value(),
                                      {duty.value().workchain_, duty.value().shard_}, duty.value().catchain_, publish);
    if (!proof.ok())
      return proof.error();
    auto policy_query = encode(GetPolicyRequest{anchor.value(), duty.value().policy_});
    if (!policy_query.ok())
      return policy_query.error();
    auto policy_response =
        make_native_response(state.value(), anchor.value(), network_, 9, policy_query.value(), publish);
    if (!policy_response.ok())
      return policy_response.error();
    auto policy = decode<PolicyResult>(policy_response.value());
    if (!policy.ok())
      return policy.error();
    auto raw = encode(cert.value());
    if (!raw.ok())
      return raw.error();
    auto carrier = object_value(4, raw.value());
    if (!carrier.ok())
      return carrier.error();
    if (!carrier.value().reference_.empty()) {
      auto stored = publish(carrier.value().reference_[0], raw.value());
      if (!stored.ok())
        return stored.error();
      if (!stored.value())
        return Error{"proof-publication"};
    }
    return encode(CertificateResult{anchor.value(), 1, interface_fingerprint, carrier.value(), proof.value(),
                                    policy.value().proof_});
  }
  return make_native_response(state.value(), anchor.value(), network_, method, request, publish);
}
}  // namespace tos::auth
