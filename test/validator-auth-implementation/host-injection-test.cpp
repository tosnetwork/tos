// When is the registry authority offered to a running contract?
//
// The instructions that reach the registry refuse unless a host is present, so
// the decision to inject one is the whole of their reachability. That decision
// used to be spelled out at the single call site inside transaction execution,
// where checking it would have meant running a whole transaction; it is now a
// named predicate, and this exercises every condition it depends on.
//
// The authority belongs to one transaction, not to the block's compute
// configuration. That is not a tidiness preference: validation re-executes
// different accounts in concurrent actors against one shared configuration, so
// an authority installed there by one account would be read by all of them, and
// whether a block validated would depend on scheduling. The last case below is
// the one the previous design could not express without mutating the shared
// configuration, which is exactly what made it unsafe.
//
// Which account may receive an authority is not decided here any more. It is
// decided where the authority is assembled, by refusing any message not
// addressed to the configuration account -- so the authority reaches a
// transaction only because that transaction is processing that message.
//
// The other half -- that a present host makes the instructions work -- is
// already covered by the native host VM cases and is not restated here.
#include <iostream>
#include <stdexcept>

#include "block/transaction.h"
#include "vm/authops.h"

namespace {
unsigned passed = 0, failed = 0;

// Every case runs, including the ones after a failure. Stopping at the first
// makes a case that was never reached indistinguishable from one that passed,
// which is precisely the question a mutation asks: did removing this condition
// break anything other than the case that names it.
void check(bool condition, const char* name) {
  if (condition) {
    ++passed;
    std::cout << "CASE_PASS " << name << '\n';
  } else {
    ++failed;
    std::cout << "CASE_FAIL " << name << '\n';
  }
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

block::Account account_on(tos::WorkchainId workchain) {
  auto addr = address(46);
  return block::Account(workchain, addr.bits());
}

// A configuration on a chain that has activated the feature, so each case can
// remove exactly one condition and observe the refusal that removal causes.
block::ComputePhaseConfig activated() {
  block::ComputePhaseConfig config;
  config.global_version = vm::validator_auth_min_version;
  config.global_capabilities = vm::validator_auth_capability;
  return config;
}

block::transaction::Transaction transaction_on(const block::Account& account,
                                               const std::shared_ptr<vm::ValidatorAuthHost>& host) {
  block::transaction::Transaction result(account, block::transaction::Transaction::tr_ord, 1, 1);
  result.validator_auth_host = host;
  return result;
}
}  // namespace

int main() {
  try {
    auto host = std::make_shared<Host>();
    const auto masterchain = account_on(tos::masterchainId);
    const auto basechain = account_on(0);

    check(transaction_on(masterchain, host).offers_validator_auth_compute_phase(activated()),
          "transaction-authority-offers");
    check(!transaction_on(masterchain, nullptr).offers_validator_auth_compute_phase(activated()),
          "transaction-without-authority-offers-nothing");
    check(!transaction_on(basechain, host).offers_validator_auth_compute_phase(activated()),
          "non-masterchain-transaction-offers-nothing");

    auto old_version = activated();
    old_version.global_version = vm::validator_auth_min_version - 1;
    check(!transaction_on(masterchain, host).offers_validator_auth_compute_phase(old_version),
          "unactivated-version-refused");

    auto no_capability = activated();
    no_capability.global_capabilities = 0;
    check(!transaction_on(masterchain, host).offers_validator_auth_compute_phase(no_capability),
          "absent-capability-refused");

    // A later version still requires the capability, so a chain that advanced
    // its version without enabling the feature is not accidentally admitted.
    auto later_version = activated();
    later_version.global_version = vm::validator_auth_min_version + 1;
    later_version.global_capabilities = 0;
    check(!transaction_on(masterchain, host).offers_validator_auth_compute_phase(later_version),
          "later-version-still-needs-capability");

    // The property the previous design could not hold. One configuration, two
    // transactions on the same masterchain account, and only the one that was
    // handed an authority has one. When the authority lived on the
    // configuration, making this true for one transaction made it true for
    // every transaction any concurrent checker was running.
    {
      const auto shared = activated();
      auto admitted = transaction_on(masterchain, host);
      auto ordinary = transaction_on(masterchain, nullptr);
      check(admitted.offers_validator_auth_compute_phase(shared) &&
                !ordinary.offers_validator_auth_compute_phase(shared),
            "two-transactions-sharing-one-compute-config-do-not-share-authority");
    }

    std::cout << "SUMMARY cases=" << passed + failed << " passed=" << passed << '\n';
    return failed ? 1 : 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
