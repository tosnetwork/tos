#pragma once
#include "signer-service.h"
namespace tos::auth {
enum class ServicePurpose : std::uint8_t { permit = 1, receipt = 2 };
struct ServiceIdentity {
  ServicePolicy policy;
  ServiceKey key;
};
// Provisioning and rotation are local administrative operations. Exporting the
// public history does not install it into a verifier's independent trust store.
// There is no raw signing or private-key export entry point.
class ServiceIssuer final : public ReceiptIssuer {
  ServicePurpose purpose_;
  Hash issuer_, audience_, seed_{};
  std::unique_ptr<DurableLog> log_;
  std::vector<ServiceIdentity> history_;
  Hash policy_id_{};
  bool stopped_ = false;
  ServiceIssuer(ServicePurpose purpose, Hash issuer, Hash audience)
      : purpose_(purpose), issuer_(issuer), audience_(audience) {
  }
  Result<bool> replay(std::span<const std::uint8_t>);
  Result<ServiceComponent> signature(std::span<const std::uint8_t>) const;

 public:
  ~ServiceIssuer();
  static Result<std::unique_ptr<ServiceIssuer>> open(const std::string&, bool create, ServicePurpose, Hash issuer,
                                                     Hash audience);
  Result<ServiceIdentity> rotate();
  const std::vector<ServiceIdentity>& public_history() const {
    return history_;
  }
  ReceiptBody base() const override;
  Result<Receipt> issue(const ReceiptBody&) override;
  // Only the independently validated local adapter constructs this expectation.
  // No RPC forwards a peer-supplied body to this operation.
  Result<Permit> issue_permit(const PermitExpectation&);
};
}  // namespace tos::auth
