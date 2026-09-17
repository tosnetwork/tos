// What one authenticated governance transaction actually costs, end to end.
//
// Every earlier measurement here took a piece. The gas closure measured the
// registry reads a certificate causes and the tariff its signatures pay, both
// against the verification path alone. The contract suite measured the
// contract, but against a host that hands back a prepared registry and never
// verifies anything -- so the number it produced was the cost of everything
// except the part that scales.
//
// This runs the whole thing: a real committee of N validators, a real
// certificate every one of them signed, the real registry, the real privileged
// host, the real compiled configuration contract, and the account's own
// tick-tock after it. What it reports is the transaction's gas, not a sum of
// parts, because the parts were measured under different assumptions and a sum
// of those is not a measurement of anything.
//
// Two committee sizes, and they answer two different questions. The masterchain
// subset of an elected set is `max_main_validators`, which the zerostate
// installs as one hundred: that is what a running chain presents. Four hundred
// is what the frozen profile admits and what configuration parameter 16 may be
// raised to without a new profile: that is what the code has to survive.
//
// The ceiling it is measured against is the masterchain block gas limit the
// zerostate installs, two and a half million -- and only the transaction is
// measured against it, because a tick-tock's gas is deliberately left out of
// block accounting. The credit an external message runs on before it is
// accepted is ten thousand, and the registry action is unsigned and accepts
// only after the update has applied -- so the whole verification has to fit in
// that credit, and this reports where it stops when it does not.
#include <iostream>
#include <stdexcept>
#include <string>

#include "validator/auth/native-config-host.h"
#include "validator/auth/native-config-state-host.h"
#include "validator/auth/native-evidence.h"
#include "validator/auth/native-registry.h"

#include "pq/mldsa44.h"

#include "config-contract-fixture.h"
#include "governance-fixture.h"

namespace {
namespace cc = config_contract_fixture;
namespace gf = governance_fixture;
using tos::auth::Anchor;
using tos::auth::Hash;

unsigned passed = 0;

void report(bool condition, const std::string& name) {
  if (!condition)
    throw std::runtime_error(name);
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

// The masterchain block gas limits the zerostate installs as configuration
// parameter 22 -- underload, soft, hard -- which is the parameter the collator
// actually reads. The same hard figure appears again as `block_gas_limit` in
// the masterchain gas prices; the two agree today, and this uses the one the
// collator bounds a block with.
//
// Soft is where a collator stops adding transactions to a block; hard is what a
// block may not exceed. A transaction below hard but above soft is one that can
// be included and then leaves the block closed behind it.
//
// What counts toward those limits is not all execution. A tick-tock is entered
// with `update_limits(status, with_gas = false)`, which adds zero gas however
// much it actually used, while still counting its logical time and its size.
// So the account's own tick-tock below is real work and is measured, and it is
// not part of what the block's gas budget sees -- and neither is the elector's,
// which is far larger. The governance message is an ordinary transaction and is
// not one of the mint/recover special transactions the gas exclusion is for, so
// its gas does count, all of it.
constexpr long long block_gas_soft_limit = 1000000, block_gas_hard_limit = 2500000;
// The credit an external message runs on before it is accepted.
constexpr long long external_gas_credit = 10000;

// The committee this network installs, and the one the profile admits.
constexpr unsigned installed_main_validators = 100, profile_ceiling = 400;

// Two smaller committees, measured because a post-quantum suite makes each
// signature cost more than a hundred of them do today, and the question of what
// size it could be run at is decided by measurement rather than by argument.
constexpr unsigned smaller_committees[] = {20, 40};

// What one verification costs under each suite, from the machine's own
// schedule: the classical one after its ten-check allowance, and the
// post-quantum one, which has no allowance.
constexpr long long classical_signature_gas = 4000, classical_free_checks = 10;
constexpr long long post_quantum_signature_gas = 50000;

// What one signer record weighs under each suite. A classical component carries
// a sixty-four byte signature beside its identity, key reference and epoch; a
// post-quantum one carries two thousand four hundred and twenty.
constexpr long long classical_record_bytes = 32 + 12 + 64;
constexpr long long post_quantum_record_bytes = 32 + 12 + tos::pq::mldsa44_signature_bytes;

// An allowance large enough that the transaction always runs to the end, so
// that what is reported is what the work costs rather than where the meter ran
// out. It is not a claim that such an allowance exists.
constexpr long long uncapped = 100000000;

class FixedHistory final : public tos::auth::FinalizedAnchorSource {
 public:
  tos::auth::Result<Anchor> finalized_anchor(std::uint32_t coordinate) const override {
    return Anchor{coordinate, auth_fixture::h(7001), auth_fixture::h(7101), auth_fixture::h(7201)};
  }
};

struct Measured {
  long long transaction_gas = 0, ticktock_gas = 0;
  int exit = -1000;
  bool committed = false, accepted = false;
  std::uint64_t verifications = 0;
  unsigned applies = 0;
};

// One governance operation of `records` signers, carried by the real contract.
//
// The operation is a policy activation rather than a configuration
// finalization, because the registry half of a configuration operation is
// deliberately not implemented -- `apply_global` refuses operation 6 with
// `global-configuration-unimplemented`, since nothing yet carries its
// authorization to the block where the configuration vote completes. Both
// operations present the same certificate to the same verification path, so the
// cost that scales with the committee is the same one; what operation 6 adds is
// the contract-side acceptance of a proposal, which the contract suite measures
// against its own fixture.
Measured measure(const td::Ref<vm::Cell>& contract, unsigned records, long long limit, long long credit) {
  auto f = gf::fixture(records);

  // A zero-identity policy activation, authorized by the same quorum and signed
  // by every member of it.
  auto policy = auth_fixture::value(f.current.policy_at(0), "capacity-current-policy");
  policy.revision_ += 1;
  policy.previous_ = f.current.current_policy();
  policy.effective_from_ = 64;
  f.update = {};
  f.update.operation_ = 4;
  f.update.identity_ = Hash{};
  f.update.nonce_ = 1;
  f.update.previous_ = f.current.current_policy();
  f.update.effective_from_ = policy.effective_from_;
  f.update.new_policy_ = auth_fixture::value(tos::auth::encode(policy), "capacity-policy-bytes");
  gf::sign(f);

  // The block this transaction is in is the one after the registry's own
  // coordinate; a prefix cannot be opened on the block the parent already is.
  const std::uint32_t inclusion = f.inclusion + 1;
  auto registry_cell = auth_fixture::value(f.current.encode_cell(), "capacity-registry-cell");
  auto persistent =
      auth_fixture::value(tos::auth::NativeRegistry::bootstrap(registry_cell, f.inclusion), "capacity-bootstrap");
  auto prefix = auth_fixture::value(tos::auth::NativeRegistryBlock::begin(persistent, inclusion), "capacity-begin");
  auto snapshot =
      auth_fixture::value(tos::auth::RegistrySnapshot::compile(f.committee, f.policy), "capacity-snapshot");

  FixedHistory history;
  tos::auth::NativeIdentityContext context{
      f.chain, snapshot, history,
      Anchor{inclusion, auth_fixture::h(7001), auth_fixture::h(7101), auth_fixture::h(7201)}};
  auto reader = gf::reader(f);

  // The evidence container the message carries, which is also what the host is
  // admitted with: the instruction receives the same reference the contract
  // was given, so the host recognises it rather than reading it again.
  auto packed = auth_fixture::value(
      tos::auth::pack_bytes(auth_fixture::value(tos::auth::encode(f.evidence), "capacity-evidence-bytes")),
      "capacity-evidence-packed");
  vm::CellBuilder carried;
  carried.store_long(tos::auth::native_evidence_tag, 32).store_long(1, 16).store_long(0, 1);
  carried.store_ref(packed).store_ref(vm::CellBuilder().finalize());
  auto evidence_cell = carried.finalize();

  auto update_cell = auth_fixture::value(
      tos::auth::pack_bytes(auth_fixture::value(tos::auth::encode(f.update), "capacity-update-bytes")),
      "capacity-update-packed");

  tos::auth::NativeConfigHost host(std::move(prefix), context, reader, inclusion, evidence_cell, f.evidence);

  cc::RegistryCells cells{registry_cell, registry_cell, update_cell, evidence_cell};
  auto run = cc::run_contract(contract, cc::registry_body(cells), 0, 1000, &host, vm::validator_auth_capability,
                              vm::validator_auth_min_version, true, registry_cell, limit, false, {}, nullptr, {},
                              credit);

  Measured out;
  out.transaction_gas = run.gas;
  out.exit = run.exit;
  out.committed = run.committed;
  out.accepted = run.accepted;
  out.verifications = host.signature_checks();
  out.applies = host.updates();

  // The account's own tick-tock, which every masterchain block runs whether or
  // not a registry message arrived in it. Its host is the state-only one, so
  // this is the tick-tock as it actually occurs and not the update path again.
  tos::auth::NativeConfigStateHost state_host(
      auth_fixture::value(tos::auth::NativeRegistryBlock::begin(persistent, inclusion), "capacity-ticktock-begin"));
  auto tick = cc::run_ticktock(contract, &state_host, vm::validator_auth_capability, vm::validator_auth_min_version,
                               true, registry_cell);
  out.ticktock_gas = tick.gas;
  return out;
}
}  // namespace

int main(int argc, char** argv) {
  try {
    cc::expect(argc == 2, "arguments");
    auto initialized = vm::init_vm();
    cc::expect(initialized.is_ok(), "vm-initialized");
    SET_VERBOSITY_LEVEL(VERBOSITY_NAME(FATAL));
    auto contract = cc::read_boc(argv[1]);

    static const char* const manifest[] = {
        "the-whole-transaction-verifies-every-signature-the-committee-supplied",
        "the-installed-committee-fits-the-masterchain-block",
        "the-profile-ceiling-fits-the-masterchain-block",
        "only-the-installed-committee-leaves-the-block-open",
        "the-account-tick-tock-is-work-the-block-gas-budget-does-not-see",
        "a-post-quantum-committee-of-twenty-fits-the-masterchain-block",
        "a-post-quantum-committee-of-forty-does-not-fit-with-its-certificate",
        "no-committee-size-fits-the-unaccepted-external-credit",
    };
    for (const auto* name : manifest)
      std::cout << "MANIFEST " << name << '\n';

    const auto installed = measure(contract, installed_main_validators, uncapped, 0);
    const auto ceiling = measure(contract, profile_ceiling, uncapped, 0);

    // The same transaction at committee sizes small enough to be worth asking
    // about under a post-quantum suite. What is reported for that suite is a
    // floor, not a cost: the classical verification is removed and the
    // post-quantum tariff put in its place, while everything else -- the reads,
    // the contract, the instruction -- is left at what it measured here. A
    // post-quantum certificate is roughly eighteen times the size of this one,
    // so the part left unchanged can only grow. Nothing below claims to have
    // run one; the registry admits no such key.

    for (const auto* line : {"installed", "ceiling"}) {
      const auto& m = line[0] == 'i' ? installed : ceiling;
      const auto n = line[0] == 'i' ? installed_main_validators : profile_ceiling;
      std::cerr << "MEASURE signers=" << n << " block_gas=" << m.transaction_gas
                << " ticktock_gas_excluded=" << m.ticktock_gas << " soft=" << block_gas_soft_limit
                << " hard=" << block_gas_hard_limit << " verifications=" << m.verifications << " exit=" << m.exit
                << " committed=" << m.committed << '\n';
    }

    // The transaction ran the verification it was given, rather than stopping
    // somewhere earlier for a reason that would make the number meaningless.
    report(installed.exit == 0 && installed.committed && installed.applies == 1 &&
               installed.verifications == installed_main_validators && ceiling.exit == 0 && ceiling.committed &&
               ceiling.applies == 1 && ceiling.verifications == profile_ceiling,
           "the-whole-transaction-verifies-every-signature-the-committee-supplied");

    report(installed.transaction_gas < block_gas_hard_limit,
           "the-installed-committee-fits-the-masterchain-block");

    // The one that could have gone either way. Parameter 16 may be raised to
    // this without a new profile, so a configuration a governance operation is
    // allowed to install must not produce a governance operation the
    // masterchain can no longer execute.
    report(ceiling.transaction_gas < block_gas_hard_limit, "the-profile-ceiling-fits-the-masterchain-block");

    // What fitting does not say. At the profile ceiling the transaction alone
    // passes the point where a collator stops adding to a block, so it is a
    // transaction that closes the block it is in rather than one that shares
    // it.
    report(installed.transaction_gas < block_gas_soft_limit && ceiling.transaction_gas > block_gas_soft_limit,
           "only-the-installed-committee-leaves-the-block-open");

    // And the tick-tock beside it is work the block's gas budget never sees.
    // Measuring it is still worth doing -- it is execution a validator performs
    // -- but adding it to the figures above would be comparing it against a
    // limit it is deliberately excluded from.
    report(installed.ticktock_gas > 0 && installed.ticktock_gas == ceiling.ticktock_gas,
           "the-account-tick-tock-is-work-the-block-gas-budget-does-not-see");

    // And the separate question, which fitting the block does not answer. The
    // registry action is unsigned and accepts only after the update has
    // applied, so the entire verification happens on the credit an external
    // message has before acceptance. Neither committee size fits it, so neither
    // can be admitted through this ingress at all.
    {
      const auto starved = measure(contract, installed_main_validators, uncapped, external_gas_credit);
      std::cerr << "MEASURE credit=" << external_gas_credit << " signers=" << installed_main_validators
                << " gas=" << starved.transaction_gas << " accepted=" << starved.accepted
                << " committed=" << starved.committed << " verifications=" << starved.verifications << '\n';
      report(!starved.accepted && !starved.committed, "no-committee-size-fits-the-unaccepted-external-credit");
    }

    // Everything the largest measured transaction spent that was not signature
    // verification: the reads, the contract, the instruction, and the cost of
    // carrying a certificate of four hundred records. It stands in below for
    // the same costs under a post-quantum suite, and it is a conservative
    // stand-in rather than an estimate: a forty-record ML-DSA certificate
    // carries about a hundred thousand bytes against that one's fifty-six
    // thousand, so whatever those costs are, they are not smaller.
    const auto largest_non_crypto =
        ceiling.transaction_gas - (profile_ceiling - classical_free_checks) * classical_signature_gas;

    long long post_quantum_floor[2] = {0, 0};
    for (unsigned index = 0; index < 2; ++index) {
      const auto records = smaller_committees[index];
      const auto small = measure(contract, records, uncapped, 0);
      const auto classical = (records > classical_free_checks ? records - classical_free_checks : 0) *
                             classical_signature_gas;
      // The classical verification taken out and the post-quantum tariff put in
      // its place. Nothing here has run an ML-DSA certificate; the registry
      // admits no such key. What is asserted is arithmetic on measured gas.
      post_quantum_floor[index] = small.transaction_gas - classical + records * post_quantum_signature_gas;
      std::cerr << "MEASURE signers=" << records << " block_gas=" << small.transaction_gas
                << " classical_crypto=" << classical << " post_quantum_floor=" << post_quantum_floor[index]
                << " certificate_bytes_post_quantum=" << records * post_quantum_record_bytes
                << " soft=" << block_gas_soft_limit << " hard=" << block_gas_hard_limit
                << " verifications=" << small.verifications << '\n';
    }
    std::cerr << "MEASURE largest_non_crypto=" << largest_non_crypto
              << " certificate_bytes_classical=" << profile_ceiling * classical_record_bytes << '\n';

    // Twenty fits with room left over even after the largest non-verification
    // cost this suite has ever measured is added on top of it.
    report(post_quantum_floor[0] + largest_non_crypto < block_gas_hard_limit,
           "a-post-quantum-committee-of-twenty-fits-the-masterchain-block");

    // Forty does not. Its verification alone is four fifths of the block, and
    // what is left is less than the non-verification cost of a certificate
    // carrying fewer bytes than its own.
    report(post_quantum_floor[1] < block_gas_hard_limit &&
               post_quantum_floor[1] + largest_non_crypto > block_gas_hard_limit,
           "a-post-quantum-committee-of-forty-does-not-fit-with-its-certificate");

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
