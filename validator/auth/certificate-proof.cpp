#include "certificate-proof.h"
namespace tos::auth {
Result<VerifyResult> VerifiedNativeCertificate::result() const {
  const auto& duty = certificate_.duty();
  auto id = object_id("duty", duty);
  if (!id.ok())
    return id.error();
  return VerifyResult{anchor_,    certificate_.certificate_id(), duty.policy_,         duty.committee_,
                      id.value(), certificate_.signers(),        certificate_.weight()};
}
Result<VerifiedNativeCertificate> verify_native_certificate(const VerifyCertificateRequest& request,
                                                            const Anchor& anchor, const ChainContext& chain,
                                                            const Duty& expected, ObjectReader& reader) {
  return verify_native_certificate(request, anchor, chain,
                                   NativeDutyResolver([&](const Duty&) -> Result<Duty> { return expected; }), reader);
}
Result<VerifiedNativeCertificate> verify_native_certificate(const VerifyCertificateRequest& request,
                                                            const Anchor& anchor, const ChainContext& chain,
                                                            const NativeDutyResolver& resolve, ObjectReader& reader) {
  if (request.anchor_ != anchor)
    return Error{"certificate-anchor"};
  auto raw = reader.resolve(request.certificate_, 4);
  if (!raw.ok())
    return raw.error();
  auto cert = decode<Certificate>(raw.value());
  if (!cert.ok())
    return cert.error();
  if (!resolve)
    return Error{"native-duty-source"};
  auto resolved = resolve(cert.value().duty_);
  if (!resolved.ok())
    return resolved.error();
  const auto& expected = resolved.value();
  if (expected.network_ != chain.network || expected.genesis_root_ != chain.genesis_root ||
      expected.genesis_file_ != chain.genesis_file || expected.anchor_mc_ != anchor.seqno_)
    return Error{"certificate-chain-context"};
  if (cert.value().duty_ != expected)
    return Error{"expected-context"};
  auto committee = verify_committee_proof(request.committee_, anchor, chain, {expected.workchain_, expected.shard_},
                                          expected.catchain_, reader);
  if (!committee.ok())
    return committee.error();
  const auto& snapshot = committee.value().snapshot();
  auto query = encode(GetPolicyRequest{anchor, expected.policy_});
  if (!query.ok())
    return query.error();
  auto response = encode(PolicyResult{anchor, snapshot.policy(), request.policy_});
  if (!response.ok())
    return response.error();
  auto policy = verify_native_response(9, query.value(), response.value(), anchor, chain.network, reader);
  if (!policy.ok())
    return policy.error();
  auto verified = snapshot.verify(cert.value(), expected);
  if (!verified.ok())
    return verified.error();
  return VerifiedNativeCertificate(anchor, std::move(verified.value()));
}
Result<VerifiedNativeCertificate> verify_native_certificate_response(std::uint8_t method,
                                                                     std::span<const std::uint8_t> request,
                                                                     std::span<const std::uint8_t> response,
                                                                     const Anchor& anchor, const ChainContext& chain,
                                                                     const Duty& expected, ObjectReader& reader) {
  if (request.size() > 2000000 || response.size() > 2000000)
    return Error{"api-binary-bound"};
  if (method == 12) {
    auto q = decode<GetCertificateRequest>(request);
    if (!q.ok())
      return q.error();
    auto r = decode<CertificateResult>(response);
    if (!r.ok())
      return r.error();
    if (q.value().anchor_ != anchor || r.value().anchor_ != anchor)
      return Error{"certificate-anchor"};
    if (r.value().era_ != 1 || r.value().interface_digest_ != interface_fingerprint)
      return Error{"certificate-era"};
    auto verified = verify_native_certificate({anchor, r.value().certificate_, r.value().committee_, r.value().policy_},
                                              anchor, chain, expected, reader);
    if (!verified.ok())
      return verified.error();
    if (verified.value().certificate().certificate_id() != q.value().certificate_id_)
      return Error{"certificate-id"};
    return verified;
  }
  if (method == 13) {
    auto q = decode<VerifyCertificateRequest>(request);
    if (!q.ok())
      return q.error();
    auto r = decode<VerifyResult>(response);
    if (!r.ok())
      return r.error();
    auto verified = verify_native_certificate(q.value(), anchor, chain, expected, reader);
    if (!verified.ok())
      return verified.error();
    auto actual = verified.value().result();
    if (!actual.ok())
      return actual.error();
    if (r.value() != actual.value())
      return Error{"verified-result"};
    return verified;
  }
  return Error{"unsupported-native-method"};
}
}  // namespace tos::auth
