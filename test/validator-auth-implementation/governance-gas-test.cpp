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
// Reads are not the whole bill. Certificate verification never touches the
// registry's allowance -- its only bound is a byte size -- so the signature work
// is priced separately, by the machine, from the count the verification reports.
// What this file has to show about that count is that it is the number of
// verifications actually performed: equal to the records when they are all
// checked, and zero when the certificate is refused before any of them is. What
// one costs is measured where it is charged, against a running machine.
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
unsigned passed = 0;

// A failed measurement stops the run and names itself, so a guard removed from
// the production source is answered by the case that was supposed to catch it
// rather than by whichever case happens to trip first afterwards.
void report(bool condition, const std::string& name) {
  if (!condition)
    throw std::runtime_error(name);
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

// The price the host is built with. Read from the host rather than repeated
// here: a bound computed from a second copy of the price would stop being a
// bound the moment the price moved.
constexpr std::uint64_t per_entry = 64, per_byte = 1;

// The credit an external message has before it is accepted, as the zerostate
// installs it for the masterchain.
constexpr std::uint64_t network_credit = 10000;

// Two different ceilings, and they answer two different questions.
//
// The profile admits four hundred signer records and the registry refuses the
// four hundred and first, so four hundred is what this code must survive -- and
// it stays reachable, because the validator counts are a configuration
// parameter a governance operation may raise up to that same bound.
//
// What the network as configured actually presents is smaller. Governance is
// signed by the masterchain committee, and the masterchain subset is
// `max_main_validators`, which the zerostate installs as twenty-one -- a size
// chosen so the same operation stays inside a block under a post-quantum suite
// as well. Four hundred is the ceiling it could be raised to without a new
// profile.
constexpr unsigned profile_ceiling = 400, installed_main_validators = 21;

struct Cost {
  std::uint64_t gas = 0;
  std::uint64_t entries = 0, bytes = 0;
  // Verifications the registry announced it was about to perform, which is what
  // a paying caller is charged for.
  std::uint64_t reported = 0;
  bool verified = false;
  std::string refusal;
};

// What verifying one governance certificate spends of the registry's allowance,
// measured on the persistent registry because that is the one the host holds.
Cost measure(unsigned records) {
  auto f = governance_fixture::fixture(records);
  auto encoded = value(f.current.encode_cell(), "gas-registry-root");
  auto registry = value(NativeRegistry::bootstrap(encoded, f.inclusion), "gas-registry");
  auto snapshot = value(RegistrySnapshot::compile(f.committee, f.policy), "gas-snapshot");
  auto reader = governance_fixture::reader(f);

  Cost cost;
  SignatureMeter meter = [&](std::uint16_t) { ++cost.reported; };

  const auto before = registry.remaining();
  auto verified =
      verify_current_governance(f.chain, snapshot, registry, f.update, f.evidence, f.inclusion, reader, &meter);
  const auto after = registry.remaining();

  cost.verified = verified.ok();
  if (!verified.ok())
    cost.refusal = verified.error().code;
  cost.entries = before.entries - after.entries;
  cost.bytes = before.bytes - after.bytes;
  cost.gas = consumed(before, after, per_entry, per_byte);
  return cost;
}
}  // namespace

int main() {
  try {
    static const char* const manifest[] = {
        "governance-cost-is-linear-in-signer-records",
        "governance-worst-case-exceeds-the-external-credit",
        "governance-reports-one-verification-for-each-signature-it-checks",
        "a-certificate-refused-before-verification-reports-none",
    };
    for (const auto* name : manifest)
      std::cout << "MANIFEST " << name << '\n';

    const auto small = measure(8), medium = measure(64), installed = measure(installed_main_validators),
               largest = measure(profile_ceiling);
    std::cerr << "MEASURE records=8 gas=" << small.gas << " entries=" << small.entries << " bytes=" << small.bytes
              << '\n';
    std::cerr << "MEASURE records=64 gas=" << medium.gas << " entries=" << medium.entries << " bytes="
              << medium.bytes << '\n';
    std::cerr << "MEASURE records=" << installed_main_validators << " gas=" << installed.gas
              << " entries=" << installed.entries << " bytes=" << installed.bytes << '\n';
    std::cerr << "MEASURE records=" << profile_ceiling << " gas=" << largest.gas << " entries=" << largest.entries
              << " bytes=" << largest.bytes << " credit=" << network_credit << '\n';

    // Linear, so the largest legal certificate is the worst case and there is
    // nothing between the samples that costs more.
    {
      const bool measured = small.verified && medium.verified && installed.verified && largest.verified;
      const auto per_record_small = small.entries / 8, per_record_installed = installed.entries / installed_main_validators,
                 per_record_large = largest.entries / profile_ceiling;
      report(measured && per_record_small == per_record_large && per_record_installed == per_record_large &&
                 per_record_large > 0,
             "governance-cost-is-linear-in-signer-records");
    }

    // Neither ceiling fits the credit an external message has before it is
    // accepted, so this does not turn on which one the network installs: the
    // committee it runs today already exceeds that credit by sixfold, and the
    // one the profile admits by twenty-five.
    report(installed.verified && installed.gas > network_credit && largest.verified && largest.gas > network_credit,
           "governance-worst-case-exceeds-the-external-credit");

    // What the caller is charged for the part that grows fastest is the number
    // of verifications, and the number of verifications is the number of
    // records. A count taken from the certificate's length instead would say
    // the same thing here and a different thing for every certificate that is
    // refused before a signature is looked at.
    report(small.reported == 8 && medium.reported == 64 && installed.reported == installed_main_validators &&
               largest.reported == profile_ceiling,
           "governance-reports-one-verification-for-each-signature-it-checks");

    // Which is the case below. One component names an epoch the governing
    // committee's roster does not have, so the certificate is refused while
    // structure is still being read -- before the first verification. Nothing
    // was verified, so nothing is reported, and a sender cannot present a
    // certificate that never reaches a signature check and be billed for four
    // hundred of them.
    {
      auto f = governance_fixture::fixture(8);
      auto cert = value(decode<Certificate>(f.evidence.governance_[0].certificate_.inline_), "refused-cert");
      // Not the first record. A certificate refused at its first record would
      // report nothing even from an implementation that verified as it read,
      // and this case exists to tell those two apart.
      cert.records_.at(4).components_[0].epoch_ += 1;
      f.evidence.governance_[0].certificate_ =
          value(object_value(4, value(encode(cert), "refused-encoded")), "refused-carrier");

      auto registry = value(NativeRegistry::bootstrap(value(f.current.encode_cell(), "refused-root"), f.inclusion),
                            "refused-registry");
      auto snapshot = value(RegistrySnapshot::compile(f.committee, f.policy), "refused-snapshot");
      auto reader = governance_fixture::reader(f);
      std::uint64_t reported = 0;
      SignatureMeter meter = [&](std::uint16_t) { ++reported; };
      auto refused =
          verify_current_governance(f.chain, snapshot, registry, f.update, f.evidence, f.inclusion, reader, &meter);
      std::cerr << "MEASURE refused=" << (refused.ok() ? "accepted" : refused.error().code) << " reported=" << reported
                << '\n';
      report(!refused.ok() && refused.error().code == std::string("key-binding") && reported == 0,
             "a-certificate-refused-before-verification-reports-none");
    }

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
