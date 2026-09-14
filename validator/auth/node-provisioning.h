#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "c0-provider.h"
#include "service-issuer.h"
#include "state.h"

namespace tos::auth {

struct ReconciledProviderRoute {
  Keyref key;
  Hash handle{};
};

// Admission token for one node identity at one authenticated registry
// coordinate. Construction is possible only after exact two-way reconciliation
// between the registry's active keys and the provider's own inventory.
class ProviderSessionAdmission {
 public:
  static Result<ProviderSessionAdmission> reconcile(
      const CurrentRegistry&, C0SigningProvider&, const Hash& identity);

  Result<Hash> route(const Keyref&) const;
  const Hash& identity() const {
    return identity_;
  }
  std::uint32_t coordinate() const {
    return coordinate_;
  }
  const std::vector<ReconciledProviderRoute>& routes() const {
    return routes_;
  }

 private:
  ProviderSessionAdmission(
      Hash identity, std::uint32_t coordinate,
      std::vector<ReconciledProviderRoute> routes)
      : identity_(identity),
        coordinate_(coordinate),
        routes_(std::move(routes)) {
  }

  Hash identity_{};
  std::uint32_t coordinate_ = 0;
  std::vector<ReconciledProviderRoute> routes_;
};

// Implementations of this seam are privileged local configuration adapters.
// They must authenticate operator-selected service history independently of
// peers, requests, permits or receipts.
class AuthenticatedLocalServiceConfig {
 public:
  virtual ~AuthenticatedLocalServiceConfig() = default;
  virtual Result<std::vector<ServiceIdentity>> load() const = 0;
};

// Non-empty installed trust token. Node-side permit verification accepts this
// type rather than a raw ServiceTrust so an empty/default trust store cannot
// accidentally become the production provisioning path.
class InstalledServiceTrust {
 public:
  static Result<std::unique_ptr<InstalledServiceTrust>> load(
      const AuthenticatedLocalServiceConfig&);

  const ServiceTrust& trust() const {
    return trust_;
  }
  const std::vector<ServiceIdentity>& history() const {
    return history_;
  }

 private:
  InstalledServiceTrust() {
  }

  ServiceTrust trust_;
  std::vector<ServiceIdentity> history_;
};

class NodePermitSource {
 public:
  virtual ~NodePermitSource() = default;
  virtual Result<Permit> obtain(const PermitExpectation&) = 0;
};

// Local issuer adapter. The caller may substitute another source later, but the
// node verifier below treats every source result as untrusted until verified.
class ServiceIssuerPermitSource final : public NodePermitSource {
 public:
  explicit ServiceIssuerPermitSource(ServiceIssuer& issuer)
      : issuer_(issuer) {
  }

  Result<Permit> obtain(const PermitExpectation&) override;

 private:
  ServiceIssuer& issuer_;
};

class VerifiedNodePermit {
 public:
  const Permit& permit() const {
    return permit_;
  }
  const PermitExpectation& expectation() const {
    return expectation_;
  }

 private:
  friend class NodePermitAdapter;
  VerifiedNodePermit(Permit permit, PermitExpectation expectation)
      : permit_(std::move(permit)),
        expectation_(std::move(expectation)) {
  }

  Permit permit_;
  PermitExpectation expectation_;
};

// Obtains exactly one permit attempt and binds it to an independently derived
// expectation. Missing, stale, expired, context-mismatched or untrusted permits
// are refusals. This adapter never renews or edits a permit in place.
class NodePermitAdapter {
 public:
  NodePermitAdapter(
      const InstalledServiceTrust& trust, NodePermitSource& source)
      : trust_(trust), source_(source) {
  }

  Result<VerifiedNodePermit> obtain(
      const PermitExpectation&) const;

 private:
  const InstalledServiceTrust& trust_;
  NodePermitSource& source_;
};

}  // namespace tos::auth
