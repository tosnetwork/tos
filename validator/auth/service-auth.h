#pragma once
#include "context.h"
namespace tos::auth {
struct ServiceKey {
  Hash id{};
  Bytes public_key;
};
class ServiceTrust {
  struct Installed {
    ServicePolicy policy;
    Hash policy_id{};
    ServiceKey key;
    AdmittedKey admitted;
  };
  std::map<Hash, Installed> history_;
  std::map<Hash, Hash> current_;

 public:
  // Only independently authenticated local service configuration may call this.
  Result<bool> install_trusted(const ServicePolicy&, const ServiceKey&);
  Result<bool> verify(const Permit&) const;
  Result<bool> verify(const Receipt&) const;

 private:
  Result<bool> verify_body(const Hash& issuer, const Hash& policy, std::span<const std::uint8_t> body,
                           const std::vector<ServiceComponent>&) const;
};
class ReceiptWitness {
 public:
  virtual ~ReceiptWitness() = default;
  virtual Result<bool> contains(std::uint64_t sequence, const Hash& receipt_body_id) const = 0;
};
Result<bool> verify_permit(const Permit&, const PermitBody& independently_expected, const ServiceTrust&,
                           std::uint32_t current_coordinate, std::uint64_t current_fence, bool live_permission);
Result<bool> validate_permit_context(const PermitBody&, std::uint32_t current_coordinate, std::uint64_t current_fence,
                                     bool live_permission);
Result<bool> verify_receipt(const Receipt&, const ReceiptBody& independently_expected, const ServiceTrust&,
                            const ReceiptWitness&);
Result<bool> validate_request_state(const RequestState&, const Hash& expected_id);
Result<bool> observe_request_state(const RequestState* previously_verified, const RequestState& next,
                                   const Hash& expected_id);
}  // namespace tos::auth
