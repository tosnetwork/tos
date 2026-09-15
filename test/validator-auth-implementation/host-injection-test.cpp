// When is the registry authority offered to a running contract?
//
// The instructions that reach the registry refuse unless a host is present, so
// the decision to inject one is the whole of their reachability. That decision
// used to be spelled out at the single call site inside transaction execution,
// where checking it would have meant running a whole transaction; it is now a
// named predicate, and this exercises every condition it depends on.
//
// The other half -- that a present host makes the instructions work -- is
// already covered by the native host VM cases and is not restated here.
#include <iostream>
#include <stdexcept>

#include "block/transaction.h"
#include "vm/authops.h"

namespace {
unsigned passed = 0;

void check(bool condition, const char* name) {
  if (!condition)
    throw std::runtime_error(name);
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

struct Host final : vm::ValidatorAuthHost {
  td::Ref<vm::Cell> checkpoint(const Charge&) override {
    return {};
  }
  td::Ref<vm::Cell> apply(td::Ref<vm::Cell>, td::Ref<vm::Cell>, const Charge&) override {
    return {};
  }
  td::Ref<vm::Cell> bind(td::Ref<vm::Cell>, td::Ref<vm::Cell>, const Charge&) override {
    return {};
  }
};

td::Bits256 address(unsigned value) {
  td::Bits256 result;
  result.set_zero();
  result.bits().store_uint(value, 32);
  return result;
}

// A configuration that satisfies every condition, so each case can remove
// exactly one and observe the refusal that removal causes.
block::ComputePhaseConfig admitting(const std::shared_ptr<vm::ValidatorAuthHost>& host) {
  block::ComputePhaseConfig config;
  config.validator_auth_host = host;
  config.validator_auth_account = address(46);
  config.global_version = vm::validator_auth_min_version;
  config.global_capabilities = vm::validator_auth_capability;
  return config;
}
}  // namespace

int main() {
  try {
    auto host = std::make_shared<Host>();
    const auto named = address(46);

    check(admitting(host).offers_validator_auth_host(true, named), "complete-configuration-offers");

    auto without_host = admitting(host);
    without_host.validator_auth_host.reset();
    check(!without_host.offers_validator_auth_host(true, named), "absent-host-offers-nothing");

    auto without_account = admitting(host);
    without_account.validator_auth_account.reset();
    check(!without_account.offers_validator_auth_host(true, named), "unnamed-account-offers-nothing");

    check(!admitting(host).offers_validator_auth_host(false, named), "non-masterchain-refused");
    check(!admitting(host).offers_validator_auth_host(true, address(47)), "other-address-refused");

    auto old_version = admitting(host);
    old_version.global_version = vm::validator_auth_min_version - 1;
    check(!old_version.offers_validator_auth_host(true, named), "unactivated-version-refused");

    auto no_capability = admitting(host);
    no_capability.global_capabilities = 0;
    check(!no_capability.offers_validator_auth_host(true, named), "absent-capability-refused");

    // A later version still requires the capability, so a chain that advanced
    // its version without enabling the feature is not accidentally admitted.
    auto later_version = admitting(host);
    later_version.global_version = vm::validator_auth_min_version + 1;
    later_version.global_capabilities = 0;
    check(!later_version.offers_validator_auth_host(true, named), "later-version-still-needs-capability");

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
