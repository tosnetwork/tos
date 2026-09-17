// What authority does a native configuration transaction execute under?
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "validator/auth/cells.h"
#include "validator/auth/native-config-transaction.h"

#include "committee-fixture.h"
#include "native-config-context-fixture.h"
#include "owner-fixture.h"

using namespace owner_fixture;

namespace {
struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool condition, const char* name) {
  if (!condition)
    throw AssertionFailure(name);
}

template <class T>
void refuses(const Result<T>& result, const char* code, const char* name) {
  if (result.ok() || result.error().code != code)
    throw AssertionFailure(name);
}

struct History final : FinalizedAnchorSource {
  Anchor anchor;
  Result<Anchor> finalized_anchor(std::uint32_t at) const override {
    if (at != anchor.seqno_)
      return Error{"finalized-anchor-unavailable"};
    return anchor;
  }
};

td::Ref<vm::Cell> evidence_cell() {
  Authorizations none;
  auto encoded = value(encode(none), "evidence-authorizations");
  auto packed = value(pack_bytes(encoded), "evidence-packed");
  vm::CellBuilder b;
  b.store_long(native_evidence_tag, 32);
  b.store_long(1, 16);
  b.store_long(0, 1);
  b.store_ref(std::move(packed));
  b.store_ref(vm::CellBuilder().finalize());
  return b.finalize();
}

using Test = std::pair<std::string, std::function<void()>>;
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 3 || argc > 4) {
      std::cerr << "USAGE: test-p0-config-transaction verify OWNER_INPUTS [case-name|--list|--exclude=case]\n";
      return 2;
    }

    std::filesystem::path input(argv[2]);
    auto f = fixture(input, 5);

    // Keep the original refusal fixture exactly as it was. Its parent is at 99,
    // so the coordinate regression cases exercise 98/99/101 rather than relying
    // on unsigned wraparound at genesis. It intentionally has no elected set;
    // none of those cases is meant to reach committee derivation.
    auto state = mcstate(f);
    auto history = std::make_shared<History>();
    history->anchor = Anchor{99, hash(state), h(6001), hash(state)};

    NativeConfigTransactionInputs inputs;
    inputs.masterchain_state = state;
    inputs.parent = Anchor{99, hash(state), h(6001), hash(state)};
    inputs.chain = f.chain;
    inputs.shard = {tos::masterchainId, tos::shardIdAll};
    inputs.catchain = 3;
    inputs.inclusion = 100;
    auto charge = [](std::size_t) -> Result<bool> { return true; };
    // The block's prefix, opened once. Every refusal case opens a transaction
    // onto it rather than having the transaction derive its own from the parent.
    const auto sequence =
        config_context_fixture::sequence_for(state, inputs.parent, f.chain, inputs.inclusion);

    // The clone case is the first positive NativeConfigTransaction::open() in
    // this file, so it needs a state that can actually derive a committee. Use
    // the shared committee fixture rather than inventing another validator-set
    // encoder here. One elected member matches this owner fixture's one
    // identity/stake pair; make() adds the real configuration account while
    // preserving Config34 and the catchain selector.
    auto positive_context =
        config_context_fixture::make(auth_fixture::chain_state(f.registry, 0, false, 1));
    auto positive_history = std::make_shared<History>();
    positive_history->anchor = positive_context.head;
    NativeConfigTransactionInputs positive_inputs;
    positive_inputs.masterchain_state = positive_context.root;
    positive_inputs.parent = positive_context.head;
    positive_inputs.chain = positive_context.chain;
    positive_inputs.shard = {tos::masterchainId, tos::shardIdAll};
    positive_inputs.catchain = 3;
    positive_inputs.inclusion = positive_context.head.seqno_ + 1;
    const auto positive_sequence = config_context_fixture::sequence_for(
        positive_context.root, positive_inputs.parent, positive_inputs.chain, positive_inputs.inclusion);

    std::vector<Test> tests;
    auto add = [&](std::string name, std::function<void()> fn) { tests.emplace_back(std::move(name), std::move(fn)); };

    add("coordinate-must-advance", [=] {
      auto same = inputs;
      same.inclusion = inputs.parent.seqno_;
      refuses(NativeConfigTransaction::open(same, sequence, evidence_cell(), {}, history, charge),
              "native-config-transaction-coordinate", "coordinate-must-advance");
    });
    add("coordinate-cannot-regress", [=] {
      auto earlier = inputs;
      earlier.inclusion = inputs.parent.seqno_ - 1;
      refuses(NativeConfigTransaction::open(earlier, sequence, evidence_cell(), {}, history, charge),
              "native-config-transaction-coordinate", "coordinate-cannot-regress");
    });
    add("coordinate-must-be-immediate-successor", [=] {
      auto skipped = inputs;
      skipped.inclusion = inputs.parent.seqno_ + 2;
      refuses(NativeConfigTransaction::open(skipped, sequence, evidence_cell(), {}, history, charge),
              "native-config-transaction-coordinate", "coordinate-must-be-immediate-successor");
    });
    add("unestablished-chain-refused", [=] {
      auto unnamed = inputs;
      unnamed.chain.chain_domain = Hash{};
      refuses(NativeConfigTransaction::open(unnamed, sequence, evidence_cell(), {}, history, charge),
              "native-config-transaction-chain", "unestablished-chain-refused");
    });
    add("absent-network-refused", [=] {
      auto no_network = inputs;
      no_network.chain.network = 0;
      refuses(NativeConfigTransaction::open(no_network, sequence, evidence_cell(), {}, history, charge),
              "native-config-transaction-chain", "absent-network-refused");
    });
    add("absent-evidence-refused", [=] {
      refuses(NativeConfigTransaction::open(inputs, sequence, {}, {}, history, charge), "native-config-transaction-input",
              "absent-evidence-refused");
    });
    add("absent-state-refused", [=] {
      auto absent_state = inputs;
      absent_state.masterchain_state = {};
      refuses(NativeConfigTransaction::open(absent_state, sequence, evidence_cell(), {}, history, charge),
              "native-config-transaction-input", "absent-state-refused");
    });
    add("absent-history-refused", [=] {
      refuses(NativeConfigTransaction::open(inputs, sequence, evidence_cell(), {}, {}, charge), "native-config-transaction-input",
              "absent-history-refused");
    });
    add("execution-clone-reuses-admitted-material-with-a-fresh-host", [&] {
      unsigned expansion_charges = 0;
      auto counting_charge = [&](std::size_t) -> Result<bool> {
        ++expansion_charges;
        return true;
      };
      auto primary = NativeConfigTransaction::open(positive_inputs, positive_sequence, evidence_cell(), {},
                                                   positive_history, counting_charge);
      require(primary.ok() && primary.value() != nullptr && expansion_charges != 0,
              "execution-clone-reuses-admitted-material-with-a-fresh-host");
      const auto charges_after_admission = expansion_charges;

      // Model the real retry order: the first execution has already touched its
      // host before the logging run asks for another one. The clone must start
      // clean despite that mutation, and creating it must not charge/open the
      // evidence a second time.
      vm::ValidatorAuthHost::Charge no_charge{[](long long) {}, [](std::uint16_t) {}};
      primary.value()->host().checkpoint(no_charge);
      require(primary.value()->host().checkpoints() == 1,
              "execution-clone-reuses-admitted-material-with-a-fresh-host");

      auto retry = primary.value()->clone_for_execution();
      require(retry != nullptr && expansion_charges == charges_after_admission,
              "execution-clone-reuses-admitted-material-with-a-fresh-host");
      require(&retry->host() != &primary.value()->host() && retry->host().checkpoints() == 0,
              "execution-clone-reuses-admitted-material-with-a-fresh-host");

      retry->host().checkpoint(no_charge);
      require(primary.value()->host().checkpoints() == 1 && retry->host().checkpoints() == 1 &&
                  expansion_charges == charges_after_admission,
              "execution-clone-reuses-admitted-material-with-a-fresh-host");
    });

    if (argc == 4 && std::string_view(argv[3]) == "--list") {
      for (const auto& [name, _] : tests)
        std::cout << name << '\n';
      return 0;
    }

    std::string selected;
    std::string excluded;
    if (argc == 4) {
      std::string argument(argv[3]);
      constexpr std::string_view prefix = "--exclude=";
      if (argument.starts_with(prefix))
        excluded = argument.substr(prefix.size());
      else
        selected = std::move(argument);
    }

    std::size_t ran = 0;
    for (const auto& [name, fn] : tests) {
      if (!selected.empty() && name != selected)
        continue;
      if (!excluded.empty() && name == excluded)
        continue;
      std::cout << "SETUP_OK " << name << '\n';
      try {
        fn();
      } catch (const AssertionFailure&) {
        std::cerr << "ASSERTION_FAILED " << name << '\n';
        return 1;
      }
      std::cout << "CASE_PASS " << name << '\n';
      ++ran;
    }
    if (ran == 0) {
      std::cerr << "UNKNOWN_CASE\n";
      return 2;
    }
    std::cout << "SUMMARY cases=" << ran << " passed=" << ran << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "UNEXPECTED_EXCEPTION " << error.what() << '\n';
    return 2;
  }
}
