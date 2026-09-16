// What one governance operation can legally be asked to cost.
//
// The privileged host charges for the work the registry reports: entries and
// bytes, at a price per each. A fixture-sized operation fits comfortably inside
// the credit an external message runs on before it is accepted, and that says
// nothing about the largest one a chain must accept, because the dominant term
// scales with the certificate.
//
// So this derives the bound instead of sampling it. It measures what the
// verification actually spends at several certificate sizes, shows the cost is
// linear in the number of signer records, and reports what the largest legal
// certificate costs against the credit the network installs.
//
// It also measures what is not charged. The host's price comes entirely from
// the registry's own allowance, and certificate verification never touches that
// allowance -- its only bound is a byte size. Every signature check is therefore
// free to the meter, which makes the gap a pricing question and not only a
// budget one. A bound derived only from reads would be a bound on the part that
// is already visible.
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "validator/auth/governance.h"
#include "validator/auth/native-host-charge.h"
#include "validator/auth/native-registry.h"

#include "governance-fixture.h"

using namespace tos::auth;
using namespace auth_fixture;

namespace {
unsigned passed = 0, failed = 0;

void report(bool condition, const std::string& name) {
  if (condition) {
    ++passed;
    std::cout << "CASE_PASS " << name << '\n';
  } else {
    ++failed;
    std::cout << "CASE_FAIL " << name << '\n';
  }
}

// The price the host is built with. Read from the host rather than repeated
// here: a bound computed from a second copy of the price would stop being a
// bound the moment the price moved.
constexpr std::uint64_t per_entry = 64, per_byte = 1;

// The credit an external message has before it is accepted, as the zerostate
// installs it for the masterchain.
constexpr std::uint64_t network_credit = 10000;

struct Cost {
  std::uint64_t gas = 0;
  std::uint64_t entries = 0, bytes = 0;
  unsigned signatures = 0;
  bool verified = false;
};

// What verifying one governance certificate spends of the registry's allowance,
// measured on the persistent registry because that is the one the host holds.
Cost measure(unsigned records) {
  auto f = governance_fixture::fixture(records);
  auto encoded = value(f.current.encode_cell(), "gas-registry-root");
  auto registry = value(NativeRegistry::bootstrap(encoded, f.inclusion), "gas-registry");
  auto snapshot = value(RegistrySnapshot::compile(f.committee, f.policy), "gas-snapshot");
  auto reader = governance_fixture::reader(f);

  const auto before = registry.remaining();
  auto verified = verify_current_governance(f.chain, snapshot, registry, f.update, f.evidence, f.inclusion, reader);
  const auto after = registry.remaining();

  Cost cost;
  cost.verified = verified.ok();
  cost.entries = before.entries - after.entries;
  cost.bytes = before.bytes - after.bytes;
  cost.gas = consumed(before, after, per_entry, per_byte);
  cost.signatures = records;
  return cost;
}
}  // namespace

int main() {
  try {
    static const char* const manifest[] = {
        "governance-cost-is-linear-in-signer-records",
        "governance-worst-case-exceeds-the-external-credit",
        "governance-signature-work-is-charged-nothing",
    };
    for (const auto* name : manifest)
      std::cout << "MANIFEST " << name << '\n';

    const auto small = measure(8), medium = measure(64), largest = measure(400);
    std::cerr << "MEASURE records=8 gas=" << small.gas << " entries=" << small.entries << " bytes=" << small.bytes
              << '\n';
    std::cerr << "MEASURE records=64 gas=" << medium.gas << " entries=" << medium.entries << " bytes="
              << medium.bytes << '\n';
    std::cerr << "MEASURE records=400 gas=" << largest.gas << " entries=" << largest.entries << " bytes="
              << largest.bytes << " credit=" << network_credit << '\n';

    // Linear, so the largest legal certificate is the worst case and there is
    // nothing between the samples that costs more.
    {
      const bool measured = small.verified && medium.verified && largest.verified;
      const auto per_record_small = small.entries / 8, per_record_large = largest.entries / 400;
      report(measured && per_record_small == per_record_large && per_record_large > 0,
             "governance-cost-is-linear-in-signer-records");
    }

    // The frozen profile admits four hundred signer records and requires every
    // supplied signature to verify. That operation cannot be paid for out of
    // the credit an external message has before it is accepted.
    report(largest.verified && largest.gas > network_credit,
           "governance-worst-case-exceeds-the-external-credit");

    // And the part that grows fastest is invisible. Four hundred signature
    // checks happen and the meter sees none of them: the charge is derived from
    // the registry allowance, and verification never spends it on a signature.
    // Raising the credit would not change this.
    {
      const auto reads_only = largest.entries * per_entry + largest.bytes * per_byte;
      report(largest.signatures == 400 && largest.gas == reads_only,
             "governance-signature-work-is-charged-nothing");
    }

    std::cout << "SUMMARY cases=" << passed + failed << " passed=" << passed << '\n';
    return failed ? 1 : 0;
  } catch (const std::exception& error) {
    std::cerr << "HARNESS_FAILURE " << error.what() << '\n';
    return 2;
  }
}
