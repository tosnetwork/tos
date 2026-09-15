#include "node-provisioning.h"

#include <set>
#include <utility>

namespace tos::auth {
namespace {

Result<Keyref> active_reference(
    const CurrentRegistry& registry, const Hash& identity,
    const Roleref& active) {
  auto key = registry.find(active.key_.key_id_);
  if (!key.ok())
    return key.error();

  const auto& descriptor = key.value();
  if (descriptor.identity_ != identity ||
      descriptor.role_ != active.role_ ||
      descriptor.valid_from_ > registry.coordinate() ||
      descriptor.valid_until_ <= registry.coordinate())
    return Error{"provider-registry-active-key"};

  auto reference = key_reference(descriptor);
  if (!reference.ok())
    return reference.error();
  if (reference.value() != active.key_)
    return Error{"provider-registry-active-key"};
  return reference.value();
}

Result<bool> canonical_service_identity(
    const ServiceIdentity& identity) {
  auto raw = encode(identity.policy);
  if (!raw.ok())
    return raw.error();
  auto decoded = decode<ServicePolicy>(raw.value());
  if (!decoded.ok())
    return decoded.error();
  auto roundtrip = encode(decoded.value());
  if (!roundtrip.ok())
    return roundtrip.error();
  if (decoded.value() != identity.policy ||
      roundtrip.value() != raw.value() ||
      identity.key.id == Hash{} ||
      identity.key.public_key.empty())
    return Error{"service-trust-config-record"};
  return true;
}

}  // namespace

Result<ProviderSessionAdmission>
ProviderSessionAdmission::reconcile(
    const CurrentRegistry& registry, C0SigningProvider& provider,
    const Hash& identity) {
  if (identity == Hash{})
    return Error{"provider-inventory-identity"};

  auto current = registry.lookup_identity(identity);
  if (!current.ok())
    return current.error();
  if (!current.value() || current.value()->active_.empty())
    return Error{"provider-inventory-identity"};

  const auto& active = current.value()->active_;
  if (active.size() > 10)
    return Error{"provider-inventory-bound"};

  std::vector<Keyref> expected;
  expected.reserve(active.size());
  std::set<Hash> expected_ids;
  for (const auto& role : active) {
    auto reference = active_reference(registry, identity, role);
    if (!reference.ok())
      return reference.error();
    if (!expected_ids.insert(reference.value().key_id_).second)
      return Error{"provider-registry-active-key"};
    expected.push_back(reference.value());
  }

  auto inventory = provider.inventory();
  if (!inventory.ok())
    return inventory.error();
  if (inventory.value().empty())
    return Error{"provider-inventory-missing"};
  if (inventory.value().size() > 4096)
    return Error{"provider-inventory-bound"};

  std::set<Hash> handles;
  std::set<Hash> seen;
  std::vector<ReconciledProviderRoute> routes;
  routes.reserve(expected.size());

  for (const auto& local : inventory.value()) {
    if (local.handle == Hash{} ||
        !handles.insert(local.handle).second)
      return Error{"provider-inventory-extra"};

    auto resolved = provider.descriptor(local.handle);
    if (!resolved.ok())
      return resolved.error();
    if (resolved.value() != local.descriptor)
      return Error{"provider-inventory-descriptor"};

    auto reference = key_reference(local.descriptor);
    if (!reference.ok())
      return reference.error();

    if (local.descriptor.identity_ != identity ||
        !expected_ids.contains(reference.value().key_id_))
      return Error{"provider-inventory-extra"};

    bool exact = false;
    for (const auto& wanted : expected)
      if (wanted == reference.value())
        exact = true;
    if (!exact)
      return Error{"provider-inventory-extra"};

    if (!seen.insert(reference.value().key_id_).second)
      return Error{"provider-inventory-extra"};

    routes.push_back(
        {reference.value(), local.handle});
  }

  for (const auto& wanted : expected)
    if (!seen.contains(wanted.key_id_))
      return Error{"provider-inventory-missing"};

  return ProviderSessionAdmission(
      identity, registry.coordinate(), std::move(routes));
}

Result<Hash> ProviderSessionAdmission::route(
    const Keyref& key) const {
  for (const auto& route : routes_)
    if (route.key == key)
      return route.handle;
  return Error{"provider-route-unreconciled"};
}

Result<std::unique_ptr<InstalledServiceTrust>>
InstalledServiceTrust::load(
    const AuthenticatedLocalServiceConfig& source) {
  auto records = source.load();
  if (!records.ok())
    return records.error();
  if (records.value().empty())
    return Error{"service-trust-unavailable"};
  if (records.value().size() > 4096)
    return Error{"service-trust-capacity"};

  auto result =
      std::unique_ptr<InstalledServiceTrust>(
          new InstalledServiceTrust());

  auto selected = records.value();
  for (const auto& record : selected) {
    auto canonical = canonical_service_identity(record);
    if (!canonical.ok())
      return canonical.error();

    auto installed =
        result->trust_.install_trusted(record.policy, record.key);
    if (!installed.ok())
      return installed.error();

    result->history_.push_back(record);
  }

  return result;
}

Result<Permit> ServiceIssuerPermitSource::obtain(
    const PermitExpectation& expectation) {
  return issuer_.issue_permit(expectation);
}

Result<VerifiedNodePermit> NodePermitAdapter::obtain(
    const PermitExpectation& expectation) const {
  auto permit = source_.obtain(expectation);
  if (!permit.ok())
    return permit.error();

  if (permit.value().body_ != expectation.body)
    return Error{"permit-context"};

  auto context = validate_permit_context(
      permit.value().body_,
      expectation.current_coordinate,
      expectation.fence,
      expectation.live_permission);
  if (!context.ok())
    return context.error();

  auto trusted = trust_.trust().verify(permit.value());
  if (!trusted.ok())
    return trusted.error();
  if (!trusted.value())
    return Error{"unauthorized"};

  return VerifiedNodePermit(
      std::move(permit.value()), expectation);
}

}  // namespace tos::auth
