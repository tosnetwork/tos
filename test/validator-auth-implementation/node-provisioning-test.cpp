#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "validator/auth/node-provisioning.h"

#include "native-fixture.h"

namespace {
namespace auth = tos::auth;
namespace fixture = auth_fixture;

struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
}

template <class T>
T require_value(auth::Result<T> result, const std::string& assertion) {
  require(result.ok(), assertion);
  return std::move(result.value());
}

template <class T>
T canonical(const T& value, const std::string& assertion) {
  auto raw = require_value(auth::encode(value), assertion);
  auto decoded = require_value(auth::decode<T>(raw), assertion);
  auto roundtrip = require_value(auth::encode(decoded), assertion);
  require(roundtrip == raw, assertion);
  return decoded;
}

class InventoryProvider final : public auth::C0SigningProvider {
 public:
  std::vector<auth::OpaqueKey> keys;
  std::map<auth::Hash, auth::Key> descriptors;

  auth::Result<std::vector<auth::OpaqueKey>> inventory() const override {
    return keys;
  }

  auth::Result<auth::Key> descriptor(
      const auth::Hash& handle) const override {
    auto found = descriptors.find(handle);
    if (found == descriptors.end())
      return auth::Error{"unknown-key"};
    return found->second;
  }

  auth::Result<auth::Record> sign(
      const auth::SignRequest&) override {
    return auth::Error{"fixture-sign-unused"};
  }
};

struct ProviderFixture {
  auth::RegistryState registry;
  auth::Hash identity{};
  std::vector<auth::OpaqueKey> inventory;
  std::vector<auth::Keyref> references;
};

ProviderFixture provider_fixture() {
  auto registry = fixture::state(1);
  require(
      registry.identities().size() == 1,
      "provider-fixture-identity");

  const auto& identity =
      registry.identities().begin()->second;
  const auto identity_id = identity.identity_;
  std::vector<auth::OpaqueKey> inventory;
  std::vector<auth::Keyref> references;

  std::uint32_t marker = 2000;
  for (const auto& active : identity.active_) {
    auto key = require_value(
        registry.find(active.key_.key_id_),
        "provider-fixture-key");
    key = canonical(key, "provider-fixture-key-canonical");
    auto reference = require_value(
        auth::key_reference(key),
        "provider-fixture-reference");
    require(
        reference == active.key_,
        "provider-fixture-active-reference");
    inventory.push_back(
        {key, fixture::h(marker++)});
    references.push_back(reference);
  }

  return {
      std::move(registry),
      identity_id,
      std::move(inventory),
      std::move(references)};
}

InventoryProvider provider_from(
    const ProviderFixture& source) {
  InventoryProvider provider;
  provider.keys = source.inventory;
  for (const auto& key : provider.keys)
    provider.descriptors.emplace(
        key.handle, key.descriptor);
  return provider;
}

class LocalConfig final
    : public auth::AuthenticatedLocalServiceConfig {
 public:
  std::vector<auth::ServiceIdentity> records;
  std::optional<std::string> failure;

  auth::Result<std::vector<auth::ServiceIdentity>>
  load() const override {
    if (failure)
      return auth::Error{*failure};
    return records;
  }
};

class StaticPermitSource final : public auth::NodePermitSource {
 public:
  std::optional<auth::Permit> permit;
  std::optional<std::string> failure;
  unsigned calls = 0;

  auth::Result<auth::Permit> obtain(
      const auth::PermitExpectation&) override {
    ++calls;
    if (failure)
      return auth::Error{*failure};
    if (!permit)
      return auth::Error{"permit-unavailable"};
    return *permit;
  }
};

struct TempDirectory {
  std::filesystem::path path;

  TempDirectory() {
    std::string value =
        (std::filesystem::temp_directory_path() /
         "p0-node-provisioning-XXXXXX")
            .string();
    require(
        ::mkdtemp(value.data()) != nullptr,
        "temp-directory");
    path = value;
    require(
        ::chmod(path.c_str(), 0700) == 0,
        "temp-directory-mode");
  }

  ~TempDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};

auth::ServiceIdentity canonical_identity(
    const auth::ServiceIdentity& identity) {
  return {
      canonical(identity.policy, "service-policy-canonical"),
      identity.key};
}

LocalConfig local_config(
    const std::vector<auth::ServiceIdentity>& history) {
  LocalConfig config;
  for (const auto& identity : history)
    config.records.push_back(canonical_identity(identity));
  return config;
}

auth::Receipt issue_receipt(
    auth::ServiceIssuer& issuer, std::uint64_t sequence,
    std::uint32_t marker) {
  auto body = issuer.base();
  body.request_id_ = fixture::h(marker);
  body.method_ = 5;
  body.subject_ = fixture::h(marker + 1);
  body.result_hash_ = fixture::h(marker + 2);
  body.journal_sequence_ = sequence;
  body.fence_ = 9;
  body.state_ = 2;
  body.context_id_ = fixture::h(marker + 3);
  body = canonical(body, "receipt-body-canonical");

  auto receipt = require_value(
      issuer.issue(body), "receipt-issue");
  return canonical(receipt, "receipt-canonical");
}

auth::PermitExpectation permit_expectation(
    const auth::ServiceIssuer& issuer,
    std::uint32_t current = 100) {
  require(
      !issuer.public_history().empty(),
      "permit-history");
  const auto& identity = issuer.public_history().back();
  auto policy_id = require_value(
      auth::object_id("service_policy", identity.policy),
      "permit-policy-id");

  auth::PermitBody body{
      identity.policy.issuer_,
      policy_id,
      fixture::h(801),
      -239,
      fixture::h(11),
      fixture::h(12),
      {100, fixture::h(900), fixture::h(901), fixture::h(902)},
      fixture::h(903),
      fixture::h(904),
      fixture::h(905),
      fixture::h(906),
      fixture::h(907),
      5,
      fixture::h(908),
      120,
      9};

  body = canonical(body, "permit-body-canonical");
  return {body, current, 9, true};
}

std::unique_ptr<auth::InstalledServiceTrust> installed_trust(
    const std::vector<auth::ServiceIdentity>& history,
    const std::string& assertion) {
  auto config = local_config(history);
  return require_value(
      auth::InstalledServiceTrust::load(config),
      assertion);
}

using Test = std::pair<std::string, std::function<void()>>;

std::vector<Test> tests() {
  std::vector<Test> result;
  auto add = [&](std::string name, std::function<void()> fn) {
    result.emplace_back(std::move(name), std::move(fn));
  };

  add("provider_missing_active_refused", [] {
    auto data = provider_fixture();
    auto provider = provider_from(data);
    require(
        !provider.keys.empty(),
        "provider_missing_active_refused");
    provider.descriptors.erase(provider.keys.back().handle);
    provider.keys.pop_back();

    auto admitted = auth::ProviderSessionAdmission::reconcile(
        data.registry, provider, data.identity);
    require(
        !admitted.ok() &&
            admitted.error().code == "provider-inventory-missing",
        "provider_missing_active_refused");
  });

  add("provider_extra_handle_refused", [] {
    auto data = provider_fixture();
    auto provider = provider_from(data);
    require(
        !provider.keys.empty(),
        "provider_extra_handle_refused");

    auto extra = provider.keys.front();
    extra.handle = fixture::h(2999);
    provider.keys.push_back(extra);
    provider.descriptors.emplace(
        extra.handle, extra.descriptor);

    auto admitted = auth::ProviderSessionAdmission::reconcile(
        data.registry, provider, data.identity);
    require(
        !admitted.ok() &&
            admitted.error().code == "provider-inventory-extra",
        "provider_extra_handle_refused");
  });

  add("provider_descriptor_binding", [] {
    auto data = provider_fixture();
    auto provider = provider_from(data);
    require(
        provider.keys.size() >= 2,
        "provider_descriptor_binding");

    provider.descriptors[
        provider.keys.front().handle] =
        provider.keys[1].descriptor;

    auto admitted = auth::ProviderSessionAdmission::reconcile(
        data.registry, provider, data.identity);
    require(
        !admitted.ok() &&
            admitted.error().code ==
                "provider-inventory-descriptor",
        "provider_descriptor_binding");
  });

  add("provider_routing_reconciled_only", [] {
    auto data = provider_fixture();
    auto provider = provider_from(data);
    auto admitted = require_value(
        auth::ProviderSessionAdmission::reconcile(
            data.registry, provider, data.identity),
        "provider_routing_reconciled_only");

    require(
        admitted.routes().size() == data.inventory.size(),
        "provider_routing_reconciled_only");

    for (std::size_t i = 0; i < data.references.size(); ++i) {
      auto handle = admitted.route(data.references[i]);
      require(
          handle.ok() &&
              handle.value() == data.inventory[i].handle,
          "provider_routing_reconciled_only");
    }

    auth::Keyref unknown{
        1, 1, 1, fixture::h(3999)};
    unknown = canonical(
        unknown, "provider-route-canonical");

    auto refused = admitted.route(unknown);
    require(
        !refused.ok() &&
            refused.error().code ==
                "provider-route-unreconciled",
        "provider_routing_reconciled_only");
  });

  add("local_trust_required", [] {
    LocalConfig empty;
    auto missing =
        auth::InstalledServiceTrust::load(empty);
    require(
        !missing.ok() &&
            missing.error().code ==
                "service-trust-unavailable",
        "local_trust_required");

    TempDirectory directory;
    auto issuer = require_value(
        auth::ServiceIssuer::open(
            (directory.path / "receipt").string(),
            true, auth::ServicePurpose::receipt,
            fixture::h(800), fixture::h(801)),
        "local_trust_required");

    auto receipt = issue_receipt(*issuer, 1, 4100);

    auth::ServiceTrust raw_default;
    auto refused = raw_default.verify(receipt);
    require(
        !refused.ok(),
        "local_trust_required");
  });

  add("local_trust_rotation_history", [] {
    TempDirectory directory;
    auto issuer = require_value(
        auth::ServiceIssuer::open(
            (directory.path / "receipt").string(),
            true, auth::ServicePurpose::receipt,
            fixture::h(800), fixture::h(801)),
        "local_trust_rotation_history");

    auto old_receipt = issue_receipt(*issuer, 1, 4200);
    auto rotated = issuer->rotate();
    require(
        rotated.ok(),
        "local_trust_rotation_history");
    auto current_receipt =
        issue_receipt(*issuer, 2, 4300);

    auto trust = installed_trust(
        issuer->public_history(),
        "local_trust_rotation_history");
    require(
        trust->history().size() == 2,
        "local_trust_rotation_history");

    auto old_valid = trust->trust().verify(old_receipt);
    auto current_valid =
        trust->trust().verify(current_receipt);
    require(
        old_valid.ok() && old_valid.value() &&
            current_valid.ok() && current_valid.value(),
        "local_trust_rotation_history");
  });

  add("permit_missing_refused", [] {
    TempDirectory directory;
    auto issuer = require_value(
        auth::ServiceIssuer::open(
            (directory.path / "permit").string(),
            true, auth::ServicePurpose::permit,
            fixture::h(800), fixture::h(801)),
        "permit_missing_refused");

    auto trust = installed_trust(
        issuer->public_history(),
        "permit_missing_refused");
    StaticPermitSource source;
    source.failure = "permit-unavailable";
    auth::NodePermitAdapter adapter(*trust, source);

    auto result =
        adapter.obtain(permit_expectation(*issuer));
    require(
        !result.ok() &&
            result.error().code == "permit-unavailable" &&
            source.calls == 1,
        "permit_missing_refused");
  });

  add("permit_signature_refused", [] {
    TempDirectory directory;
    auto issuer = require_value(
        auth::ServiceIssuer::open(
            (directory.path / "permit").string(),
            true, auth::ServicePurpose::permit,
            fixture::h(800), fixture::h(801)),
        "permit_signature_refused");

    auto expectation = permit_expectation(*issuer);
    auto permit = require_value(
        issuer->issue_permit(expectation),
        "permit_signature_refused");
    permit = canonical(
        permit, "permit-signature-canonical");
    require(
        permit.components_.size() == 1 &&
            !permit.components_[0].signature_.empty(),
        "permit_signature_refused");
    permit.components_[0].signature_[0] ^= 1;
    permit = canonical(
        permit, "permit-signature-mutated-canonical");

    auto trust = installed_trust(
        issuer->public_history(),
        "permit_signature_refused");
    StaticPermitSource source;
    source.permit = permit;
    auth::NodePermitAdapter adapter(*trust, source);

    auto result = adapter.obtain(expectation);
    require(
        !result.ok() &&
            result.error().code == "service-signature" &&
            source.calls == 1,
        "permit_signature_refused");
  });

  add("permit_context_refused", [] {
    TempDirectory directory;
    auto issuer = require_value(
        auth::ServiceIssuer::open(
            (directory.path / "permit").string(),
            true, auth::ServicePurpose::permit,
            fixture::h(800), fixture::h(801)),
        "permit_context_refused");

    auto trust = installed_trust(
        issuer->public_history(),
        "permit_context_refused");

    auto valid_expectation = permit_expectation(*issuer);
    auth::ServiceIssuerPermitSource issuer_source(*issuer);
    auth::NodePermitAdapter issuer_adapter(
        *trust, issuer_source);
    auto valid =
        issuer_adapter.obtain(valid_expectation);
    require(
        valid.ok() &&
            valid.value().permit().body_ ==
                valid_expectation.body,
        "permit_context_refused");

    auto permit = canonical(
        valid.value().permit(),
        "permit-context-permit-canonical");
    StaticPermitSource source;
    source.permit = permit;
    auth::NodePermitAdapter adapter(*trust, source);

    auto changed = valid_expectation;
    changed.body.network_ += 1;
    changed.body = canonical(
        changed.body, "permit-context-body-canonical");

    auto refused = adapter.obtain(changed);
    require(
        !refused.ok() &&
            refused.error().code == "permit-context" &&
            source.calls == 1,
        "permit_context_refused");
  });

  add("expired_permit_not_renewed", [] {
    TempDirectory directory;
    auto issuer = require_value(
        auth::ServiceIssuer::open(
            (directory.path / "permit").string(),
            true, auth::ServicePurpose::permit,
            fixture::h(800), fixture::h(801)),
        "expired_permit_not_renewed");

    auto issued_at = permit_expectation(*issuer, 100);
    auto permit = require_value(
        issuer->issue_permit(issued_at),
        "expired_permit_not_renewed");
    permit = canonical(
        permit, "expired-permit-canonical");

    auto trust = installed_trust(
        issuer->public_history(),
        "expired_permit_not_renewed");
    StaticPermitSource source;
    source.permit = permit;
    auth::NodePermitAdapter adapter(*trust, source);

    auto later = issued_at;
    later.current_coordinate =
        later.body.expires_mc_ + 1;

    auto result = adapter.obtain(later);
    require(
        !result.ok() &&
            result.error().code ==
                "permit-current-coordinate" &&
            source.calls == 1,
        "expired_permit_not_renewed");
  });

  return result;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc > 2) {
    std::cerr
        << "USAGE: test-p0-node-provisioning "
           "[case-name|--list|--exclude=case]\n";
    return 2;
  }

  const auto all = tests();

  if (argc == 2 && std::string_view(argv[1]) == "--list") {
    for (const auto& test : all)
      std::cout << test.first << '\n';
    return 0;
  }

  std::string selected;
  std::string excluded;
  if (argc == 2) {
    std::string argument(argv[1]);
    constexpr std::string_view prefix = "--exclude=";
    if (argument.starts_with(prefix))
      excluded = argument.substr(prefix.size());
    else
      selected = std::move(argument);
  }

  std::size_t ran = 0;
  for (const auto& [name, fn] : all) {
    if (!selected.empty() && name != selected)
      continue;
    if (!excluded.empty() && name == excluded)
      continue;

    try {
      std::cout << "SETUP_OK " << name << '\n';
      fn();
      std::cout << "CASE_PASS " << name << '\n';
      ++ran;
    } catch (const AssertionFailure& error) {
      std::cerr << "ASSERTION_FAILED "
                << error.what() << '\n';
      return 1;
    } catch (const std::exception& error) {
      std::cerr << "UNEXPECTED_EXCEPTION "
                << name << ": " << error.what() << '\n';
      return 2;
    }
  }

  if (ran == 0) {
    std::cerr << "UNKNOWN_CASE\n";
    return 2;
  }

  std::cout << "SUMMARY cases=" << ran
            << " passed=" << ran << '\n';
  return 0;
}
