#pragma once
#include "c0-provider.h"
namespace tos::auth {
struct PermitExpectation {
  PermitBody body;
  std::uint32_t current_coordinate = 0;
  std::uint64_t fence = 0;
  bool live_permission = false;
};
// Implemented by the trusted native consensus/admin adapter. It must derive
// permission from validated local state, never echo request.permit as authority.
class SignContext {
 public:
  virtual ~SignContext() = default;
  virtual Result<PermitExpectation> authorize(const SignPlan&) const = 0;
};
class ReceiptIssuer {
 public:
  virtual ~ReceiptIssuer() = default;
  virtual ReceiptBody base() const = 0;
  virtual Result<Receipt> issue(const ReceiptBody&) = 0;
};
class SignerService {
  SafetyLedger& ledger_;
  C0SigningProvider& provider_;
  const ServiceTrust& permits_;
  const SignContext& context_;
  ReceiptIssuer& receipts_;
  Result<Receipt> receipt(const SignRequest&, const SignPlan&, std::uint8_t state, Hash result);

 public:
  SignerService(SafetyLedger& ledger, C0SigningProvider& provider, const ServiceTrust& permits,
                const SignContext& context, ReceiptIssuer& receipts)
      : ledger_(ledger), provider_(provider), permits_(permits), context_(context), receipts_(receipts) {
  }
  Result<SignResult> sign(const SignRequest&);
  Result<RequestState> get_result(const Hash& request) const;
};
}  // namespace tos::auth
