#pragma once
#include "lifecycle.h"
#include "signer-service.h"
namespace tos::auth {
// All inputs are independently authenticated local state, pinned for one
// inclusion coordinate. Peer permits never populate this view.
class AdminContext {
  ChainContext chain_;
  Identity identity_;
  const KeyHistory& history_;
  const LifecycleAuthority& authority_;
  PermitExpectation permission_;
  Result<PermitExpectation> permission(const Update&, std::uint8_t method) const;

 public:
  AdminContext(ChainContext chain, Identity identity, const KeyHistory& history, const LifecycleAuthority& authority,
               PermitExpectation permission)
      : chain_(chain)
      , identity_(std::move(identity))
      , history_(history)
      , authority_(authority)
      , permission_(permission) {
  }
  const ChainContext& chain() const {
    return chain_;
  }
  Result<PermitExpectation> authorize(const StageRequest&) const;
  Result<PermitExpectation> authorize(const RetireRequest&) const;
};
class AdminSignerService {
  SafetyLedger& ledger_;
  C0SigningProvider& provider_;
  const ServiceTrust& permits_;
  const AdminContext& context_;
  ReceiptIssuer& receipts_;
  Result<Receipt> receipt(const OperationPlan&, const Bytes& result_body);

 public:
  AdminSignerService(SafetyLedger& ledger, C0SigningProvider& provider, const ServiceTrust& permits,
                     const AdminContext& context, ReceiptIssuer& receipts)
      : ledger_(ledger), provider_(provider), permits_(permits), context_(context), receipts_(receipts) {
  }
  Result<PrepareResult> prepare(const PrepareRequest&);
  Result<StageResult> stage(const StageRequest&);
  Result<RetireResult> retire(const RetireRequest&);
};
}  // namespace tos::auth
