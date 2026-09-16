// The configuration account's prefix is what the account committed, not what a
// host staged.
//
// Every other suite here proves one half of that sentence in isolation: the
// host suites prove a host accepts or refuses, the contract suites prove the
// contract writes what it was handed, the registry suites prove a successor is
// computed correctly. Each is green on its own, and the failure this file
// exists for lives only where they join -- a host that accepted A while the
// account committed B, a parameter that moved with no host behind it, a
// candidate promoted by a transaction that never committed at all.
//
// So the cases here are deliberately not "the sequence returns the right
// value". They are "the value the sequence carries forward is the one the
// account actually holds", which is a statement about two subsystems agreeing
// and cannot be made inside either one.
//
// Every case reports its name whether it passes or fails, and the harness
// prints the manifest it intended to run. A case that vanishes under a mutation
// is a harness defect, not a survivor: that has happened twice in this tree,
// and the mutation driver compares the reported set against this manifest for
// exactly that reason.
#include <iostream>
#include <stdexcept>
#include <string>

#include "validator/auth/native-config-sequence.h"
#include "validator/auth/native-election-binding-transaction.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

#include "committee-fixture.h"
#include "native-config-context-fixture.h"

using namespace tos::auth;
using namespace p0_fixture;
namespace context_fixture = p0_config_context_fixture;

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

// The configuration account's persistent data, in the layout the contract
// stores and the context reads: the parameter dictionary, the sequence number
// and public key, no vote dictionary, and the registry checkpoint last.
td::Ref<vm::Cell> account_data(const td::Ref<vm::Cell>& configuration, const td::Ref<vm::Cell>& checkpoint) {
  vm::CellBuilder d;
  d.store_ref(configuration).store_zeroes(32 + 256).store_long(0, 1).store_ref(checkpoint);
  return d.finalize();
}

// The same dictionary with parameter 46 replaced, which is the only way the
// account's registry ever moves.
td::Ref<vm::Cell> with_registry(const td::Ref<vm::Cell>& configuration, const td::Ref<vm::Cell>& registry) {
  vm::Dictionary parameters{configuration, 32};
  check(parameters.set_ref(td::BitArray<32>{46}, registry), "fixture-parameter-46");
  return parameters.get_root_cell();
}

// A refusal, and the reason for it.
//
// The reason is part of what is being tested, not decoration. Each guard below
// is shadowed by the ones after it for most inputs -- a claim-less commit also
// names a registry nothing accepted -- so a case that only asked "was this
// refused" would stay green with the guard it names deleted, and would be
// measuring the guard after it instead.
bool refused(const Result<bool>& result, const char* reason) {
  return !result.ok() && result.error().code == reason;
}

// A prefix built from a registry the sequence did not start from, so a claim
// naming it is a claim about something the account never held.
NativeRegistryBlock foreign_prefix() {
  auto encoded = value(p0_fixture::state(6).encode_cell(), "fixture-foreign-root");
  auto registry = value(NativeRegistry::bootstrap(encoded, 0), "fixture-foreign-registry");
  return value(NativeRegistryBlock::begin(registry, 1), "fixture-foreign-block");
}
}  // namespace

int main() {
  try {
    SET_VERBOSITY_LEVEL(0);
    // Printed before any case runs, so a run that dies partway is still
    // distinguishable from a run whose cases quietly stopped existing.
    static const char* const manifest[] = {
        "joined-sequence-begins-at-the-block-being-built",
        "joined-sequence-refuses-a-gathered-coordinate",
        "joined-contract-c4-is-the-installed-root",
        "joined-param46-change-without-host-refused",
        "joined-host-root-mismatch-refused",
        "joined-checkpoint-mismatch-refused",
        "joined-accepted-host-the-contract-ignored-refused",
        "joined-refusal-does-not-move-the-prefix",
        "joined-unchanged-parameter-does-not-promote",
        "joined-later-transaction-opens-on-the-committed-prefix",
    };
    for (const auto* name : manifest)
      std::cout << "MANIFEST " << name << '\n';

    // A state with a real elected set and catchain selector, because opening
    // the context derives a committee from it and a bare registry state has
    // neither.
    auto base = p0_fixture::chain_state(p0_fixture::state(4));
    auto fixture = context_fixture::make(base);
    auto context = value(NativeConfigContext::open(fixture.root, fixture.head, fixture.chain), "fixture-context");
    const std::uint32_t inclusion = fixture.head.seqno_ + 1;

    // The prefix every transaction in this block opens from: the parent
    // registry advanced to the coordinate being built, so a transition that
    // falls due here is already part of what the first transaction reads.
    {
      auto sequence = context_fixture::begin_sequence(fixture, inclusion);
      auto expected = value(NativeRegistryBlock::begin(context.parent(), inclusion), "fixture-expected-prefix");
      report(sequence.ok() && value(sequence.value().accepted().state().encode_cell(), "accepted-root")->get_hash() ==
                                  value(expected.state().encode_cell(), "expected-root")->get_hash(),
             "joined-sequence-begins-at-the-block-being-built");
    }

    // A gathered coordinate would materialize transitions due for a block that
    // is not being built, which every transaction already refuses on its own.
    report(!context_fixture::begin_sequence(fixture, inclusion + 1).ok(),
           "joined-sequence-refuses-a-gathered-coordinate");

    auto configuration = value(read_configuration_account(context.data()), "fixture-account-data").configuration;

    // What the account holds after a transaction that installed the prefix its
    // host accepted. The parameter the sequence compares against is read out of
    // this cell, not out of the host, which is the whole point.
    {
      auto sequence = value(context_fixture::begin_sequence(fixture, inclusion), "fixture-sequence");
      auto candidate = foreign_prefix();
      auto claim = value(NativeCommitClaim::staged(candidate), "fixture-claim");
      auto installed = account_data(
          with_registry(configuration, value(candidate.state().encode_cell(), "candidate-root")),
          value(candidate.state().checkpoint(), "candidate-checkpoint"));
      auto promoted = sequence.promote(claim, installed);
      const bool advanced =
          promoted.ok() && promoted.value() && sequence.promoted() == 1 &&
          value(sequence.accepted().state().encode_cell(), "promoted-root")->get_hash() ==
              value(candidate.state().encode_cell(), "candidate-root")->get_hash();
      report(advanced, "joined-contract-c4-is-the-installed-root");
    }

    // A parameter that moved with nothing behind it. The shape is legal and the
    // revision is whatever the registry itself says, so the transition sanity
    // gate has no complaint -- it never sees a host, which is precisely why it
    // is not the guard this is.
    {
      auto sequence = value(context_fixture::begin_sequence(fixture, inclusion), "fixture-sequence");
      auto candidate = foreign_prefix();
      auto installed = account_data(
          with_registry(configuration, value(candidate.state().encode_cell(), "candidate-root")),
          value(candidate.state().checkpoint(), "candidate-checkpoint"));
      auto promoted = sequence.promote(NativeCommitClaim{}, installed);
      report(refused(promoted, "config-sequence-unauthorized") && sequence.promoted() == 0,
             "joined-param46-change-without-host-refused");
    }

    // The host accepted one prefix and the contract wrote another. Both halves
    // are individually well formed, which is why neither suite alone sees it.
    {
      auto sequence = value(context_fixture::begin_sequence(fixture, inclusion), "fixture-sequence");
      auto accepted = foreign_prefix();
      auto claim = value(NativeCommitClaim::staged(accepted), "fixture-claim");
      auto written = value(NativeRegistryBlock::begin(
                               value(NativeRegistry::bootstrap(value(p0_fixture::state(7).encode_cell(), "written-root"),
                                                               0),
                                     "written-registry"),
                               1),
                           "written-block");
      auto installed =
          account_data(with_registry(configuration, value(written.state().encode_cell(), "written-parameter")),
                       value(written.state().checkpoint(), "written-checkpoint"));
      auto promoted = sequence.promote(claim, installed);
      report(refused(promoted, "config-sequence-registry") && sequence.promoted() == 0,
             "joined-host-root-mismatch-refused");
    }

    // The parameter agrees and the checkpoint does not. These are the two homes
    // of one fact, and a commit that moved only one of them is the shape that
    // made the registry unreadable one block after the first update.
    {
      auto sequence = value(context_fixture::begin_sequence(fixture, inclusion), "fixture-sequence");
      auto candidate = foreign_prefix();
      auto claim = value(NativeCommitClaim::staged(candidate), "fixture-claim");
      auto installed =
          account_data(with_registry(configuration, value(candidate.state().encode_cell(), "candidate-root")),
                       fixture.checkpoint);
      auto promoted = sequence.promote(claim, installed);
      report(refused(promoted, "config-sequence-checkpoint") && sequence.promoted() == 0,
             "joined-checkpoint-mismatch-refused");
    }

    // The host accepted an update and the contract wrote nothing at all. The
    // account is unchanged, so there is no bad parameter to find; the only
    // evidence is that a host said yes and the account does not show it.
    {
      auto sequence = value(context_fixture::begin_sequence(fixture, inclusion), "fixture-sequence");
      auto claim = value(NativeCommitClaim::staged(foreign_prefix()), "fixture-claim");
      auto promoted = sequence.promote(claim, context.data());
      report(refused(promoted, "config-sequence-uninstalled") && sequence.promoted() == 0,
             "joined-accepted-host-the-contract-ignored-refused");
    }

    // After a refusal the next transaction must still open from where the last
    // committed one left off, not from whatever the refused one proposed.
    {
      auto sequence = value(context_fixture::begin_sequence(fixture, inclusion), "fixture-sequence");
      const auto before = value(sequence.accepted().state().encode_cell(), "before-root")->get_hash();
      auto candidate = foreign_prefix();
      auto installed =
          account_data(with_registry(configuration, value(candidate.state().encode_cell(), "candidate-root")),
                       value(candidate.state().checkpoint(), "candidate-checkpoint"));
      auto refused = sequence.promote(NativeCommitClaim{}, installed);
      const auto after = value(sequence.accepted().state().encode_cell(), "after-root")->get_hash();
      report(!refused.ok() && before == after && sequence.promoted() == 0,
             "joined-refusal-does-not-move-the-prefix");
    }

    // A transaction that committed without touching the registry. The account
    // moved and the prefix did not, and the sequence has to be able to say so
    // without calling it a promotion -- otherwise "the prefix did not move"
    // and "nothing committed" would be the same observation.
    {
      auto sequence = value(context_fixture::begin_sequence(fixture, inclusion), "fixture-sequence");
      auto promoted = sequence.promote(NativeCommitClaim{}, context.data());
      report(promoted.ok() && !promoted.value() && sequence.promoted() == 0 &&
                 sequence.accepted_data().not_null(),
             "joined-unchanged-parameter-does-not-promote");
    }

    // The property the sequence exists for, stated where it can fail: a
    // transaction opened after a commit must see what that commit installed.
    //
    // Both halves are individually fine either way -- the sequence really did
    // promote, and the transaction really did open -- so this is only visible
    // by asking the opened transaction which prefix it is holding. Re-deriving
    // the registry from the parent state, which is what every transaction did
    // before, produces a host that works perfectly and binds against a registry
    // the block has already replaced.
    {
      auto sequence = value(context_fixture::begin_sequence(fixture, inclusion), "fixture-sequence");
      const auto parent_root = value(sequence.accepted().state().encode_cell(), "parent-root")->get_hash();
      auto candidate = foreign_prefix();
      auto claim = value(NativeCommitClaim::staged(candidate), "fixture-claim");
      auto installed =
          account_data(with_registry(configuration, value(candidate.state().encode_cell(), "candidate-root")),
                       value(candidate.state().checkpoint(), "candidate-checkpoint"));
      const bool promoted = sequence.promote(claim, installed).ok();

      auto opened = NativeElectionBindingTransaction::open(
          {fixture.root, fixture.head, fixture.chain, inclusion}, sequence);
      const auto candidate_root = value(candidate.state().encode_cell(), "candidate-root")->get_hash();
      const bool carried =
          promoted && opened.ok() &&
          value(opened.value()->host_state().staged().state().encode_cell(), "opened-root")->get_hash() ==
              candidate_root &&
          candidate_root != parent_root;
      report(carried, "joined-later-transaction-opens-on-the-committed-prefix");
    }

    std::cout << "SUMMARY cases=" << passed + failed << " passed=" << passed << '\n';
    return failed ? 1 : 0;
  } catch (const std::exception& error) {
    std::cerr << "HARNESS_FAILURE " << error.what() << '\n';
    return 2;
  }
}
