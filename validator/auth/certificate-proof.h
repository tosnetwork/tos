#pragma once
#include "committee-proof.h"
namespace tos::auth {
using NativeDutyResolver = std::function<Result<Duty>(const Duty&)>;
class VerifiedNativeCertificate {
  Anchor anchor_;
  VerifiedCertificate certificate_;
  VerifiedNativeCertificate(Anchor anchor, VerifiedCertificate certificate)
      : anchor_(anchor), certificate_(std::move(certificate)) {
  }
  friend Result<VerifiedNativeCertificate> verify_native_certificate(const VerifyCertificateRequest&, const Anchor&,
                                                                     const ChainContext&, const NativeDutyResolver&,
                                                                     ObjectReader&);

 public:
  const Anchor& anchor() const {
    return anchor_;
  }
  const VerifiedCertificate& certificate() const {
    return certificate_;
  }
  Result<VerifyResult> result() const;
};
// The caller independently pins finality and derives the exact native duty,
// including its session birth context. Neither input is inferred from the peer's
// certificate or proof. One reader charges all three attachments together.
Result<VerifiedNativeCertificate> verify_native_certificate(const VerifyCertificateRequest&, const Anchor&,
                                                            const ChainContext&, const Duty& independently_expected,
                                                            ObjectReader&);
// Resolve a claimed duty only as a lookup coordinate into independently trusted
// native history. The resolver must not approve the claim by returning it as-is.
Result<VerifiedNativeCertificate> verify_native_certificate(const VerifyCertificateRequest&, const Anchor&,
                                                            const ChainContext&, const NativeDutyResolver&,
                                                            ObjectReader&);
// Authenticate a received getCertificate/verifyCertificate response locally;
// remote success and claimed weight never create a verified result.
Result<VerifiedNativeCertificate> verify_native_certificate_response(std::uint8_t method,
                                                                     std::span<const std::uint8_t> request,
                                                                     std::span<const std::uint8_t> response,
                                                                     const Anchor&, const ChainContext&,
                                                                     const Duty& independently_expected, ObjectReader&);
}  // namespace tos::auth
