// What a signature verification costs a native transaction, and what stops one
// that cannot pay.
//
// The privileged host does not price signatures. It reports each verification
// just before performing it, and the machine charges at the tariff it already
// publishes for that primitive -- the classical suite through the schedule and
// counter CHKSIGNU uses, the post-quantum suite at its instruction's price.
// Nothing in the registry names a number, so nothing there can drift from the
// machine's.
//
// The reason the report comes first rather than last is the whole point. A
// certificate this profile admits carries four hundred signatures. A host that
// verified all four hundred and only then asked to be charged would have done
// the work whether or not the transaction could pay for it, and a sender with
// ten gas would get four hundred verifications for ten gas' worth. So the last
// case here is not about a price at all: it is that an exhausted allowance
// stops the next verification from happening.
#include <iostream>
#include <stdexcept>
#include <string>

#include "vm/authops.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cp0.h"
#include "vm/vm.h"

namespace {
unsigned passed = 0;

// A failed case stops the run and names itself, so a price removed from the
// machine is answered by the case meant to catch that removal.
void report(bool condition, const std::string& name) {
  if (!condition)
    throw std::runtime_error(name);
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

// Reports the verifications it was asked to report and counts how many it got
// through. It performs none: what is being measured is the charge, and a host
// that actually verified would add the cost of the verification to the cost of
// being charged for it.
struct Host final : vm::ValidatorAuthHost {
  std::uint64_t requested = 0, reported = 0;
  std::uint16_t suite = 1;
  td::Ref<vm::Cell> checkpoint(const Charge& charge) override {
    for (std::uint64_t i = 0; i < requested; ++i) {
      charge.signature_check(suite);
      ++reported;
    }
    return vm::CellBuilder().finalize();
  }
  td::Ref<vm::Cell> apply(td::Ref<vm::Cell>, td::Ref<vm::Cell>, const Charge&) override {
    return {};
  }
  td::Ref<vm::Cell> bind(td::Ref<vm::Cell>, td::Ref<vm::Cell>, const Charge&) override {
    return {};
  }
};

struct Outcome {
  // What the machine returned. A handled exception comes back complemented; an
  // unhandled out-of-gas comes back as the bare code, deliberately, so that a
  // program cannot fake one.
  int raw = 0;
  int exit = 0;
  long long gas = 0;
  std::uint64_t reported = 0;
};

// One VAUTH_STATE against a host that reports `checks` verifications.
Outcome run(std::uint64_t checks, std::uint16_t suite, long long budget) {
  auto host = std::make_shared<Host>();
  host->requested = checks;
  host->suite = suite;
  auto code = vm::CellBuilder().store_long(vm::validator_auth_state_opcode, 16).finalize();
  vm::VmState state{vm::load_cell_slice_ref(code),
                    vm::validator_auth_min_version,
                    td::Ref<vm::Stack>{true},
                    vm::GasLimits{budget, budget},
                    0,
                    {},
                    {},
                    {},
                    {},
                    vm::validator_auth_capability};
  state.set_validator_auth_host(host);
  Outcome out;
  out.raw = state.run();
  out.exit = ~out.raw;
  out.gas = state.gas_consumed();
  out.reported = host->reported;
  return out;
}

// What the verifications cost, with the instruction's own overhead removed by
// measuring against the same program reporting none.
long long tariff(std::uint64_t checks, std::uint16_t suite = 1) {
  const auto none = run(0, suite, 100000000), some = run(checks, suite, 100000000);
  if (none.exit != 0 || some.exit != 0)
    throw std::runtime_error("tariff-run");
  return some.gas - none.gas;
}
}  // namespace

int main() {
  try {
    vm::init_vm().ensure();
    SET_VERBOSITY_LEVEL(0);
    static const char* const manifest[] = {
        "verification-within-the-free-allowance-is-not-charged",
        "verification-past-the-free-allowance-pays-the-machine-tariff",
        "the-largest-admissible-certificate-pays-for-every-verification-past-it",
        "a-post-quantum-verification-pays-the-post-quantum-tariff",
        "a-suite-the-machine-has-no-tariff-for-is-refused-not-charged",
        "an-exhausted-allowance-stops-the-verifications-that-would-follow",
    };
    for (const auto* name : manifest)
      std::cout << "MANIFEST " << name << '\n';

    // The allowance a transaction already has for signature checks is the one
    // the host draws on; it does not receive a second one of its own.
    report(tariff(0) == 0 && tariff(10) == 0, "verification-within-the-free-allowance-is-not-charged");
    report(tariff(11) == 4000, "verification-past-the-free-allowance-pays-the-machine-tariff");

    // Two ceilings. The masterchain committee is `max_main_validators`, which
    // the zerostate installs as one hundred, so that is the crypto bill a
    // running chain presents. Four hundred is what the profile admits and what
    // the configuration parameter could be raised to without a new one, so it
    // is what the code has to survive.
    const auto installed = tariff(100), ceiling = tariff(400);
    std::cerr << "MEASURE checks=100 crypto_gas=" << installed << '\n';
    std::cerr << "MEASURE checks=400 crypto_gas=" << ceiling << '\n';
    report(installed == (100 - 10) * 4000 && ceiling == (400 - 10) * 4000,
           "the-largest-admissible-certificate-pays-for-every-verification-past-it");

    // The registry admits no post-quantum key today, but the price of one is
    // not invented on the day it does: the tariff its own instruction pays is
    // the tariff a host reporting it pays, and no allowance applies.
    report(tariff(1, 2) == 50000 && tariff(2, 2) == 100000, "a-post-quantum-verification-pays-the-post-quantum-tariff");

    // A suite with no published tariff is refused. Charging it at another
    // suite's price would be a guess, and charging it nothing would make
    // verification free, which is the thing this whole charge exists to stop.
    {
      const auto unpriced = run(1, 3, 100000000);
      report(unpriced.exit == static_cast<int>(vm::Excno::cell_und) && unpriced.reported == 0,
             "a-suite-the-machine-has-no-tariff-for-is-refused-not-charged");
    }

    // And the case the ordering exists for. Given an allowance that covers a
    // few verifications and a host that wants four hundred, the transaction
    // stops partway rather than performing all four hundred and discovering
    // afterwards that it could not pay.
    {
      const auto floor = run(0, 1, 100000000).gas;
      const auto starved = run(400, 1, floor + 20 * 4000);
      std::cerr << "MEASURE budget=" << floor + 20 * 4000 << " reported=" << starved.reported
                << " gas=" << starved.gas << '\n';
      // Ten free and twenty paid is what this allowance buys, and thirty is
      // where it stopped. The remaining three hundred and seventy verifications
      // did not happen.
      report(starved.raw == static_cast<int>(vm::Excno::out_of_gas) && starved.reported == 30,
             "an-exhausted-allowance-stops-the-verifications-that-would-follow");
    }

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
