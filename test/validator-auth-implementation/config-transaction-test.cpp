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

#include "owner-fixture.h"

using namespace p0_owner_fixture;

namespace {
struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

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

    std::vector<Test> tests;
    auto add = [&](std::string name, std::function<void()> fn) { tests.emplace_back(std::move(name), std::move(fn)); };

    add("coordinate-must-advance", [=] {
      auto same = inputs;
      same.inclusion = inputs.parent.seqno_;
      refuses(NativeConfigTransaction::open(same, evidence_cell(), history, charge),
              "native-config-transaction-coordinate", "coordinate-must-advance");
    });
    add("coordinate-cannot-regress", [=] {
      auto earlier = inputs;
      earlier.inclusion = inputs.parent.seqno_ - 1;
      refuses(NativeConfigTransaction::open(earlier, evidence_cell(), history, charge),
              "native-config-transaction-coordinate", "coordinate-cannot-regress");
    });
    add("coordinate-must-be-immediate-successor", [=] {
      auto skipped = inputs;
      skipped.inclusion = inputs.parent.seqno_ + 2;
      refuses(NativeConfigTransaction::open(skipped, evidence_cell(), history, charge),
              "native-config-transaction-coordinate", "coordinate-must-be-immediate-successor");
    });
    add("unestablished-chain-refused", [=] {
      auto unnamed = inputs;
      unnamed.chain.chain_domain = Hash{};
      refuses(NativeConfigTransaction::open(unnamed, evidence_cell(), history, charge),
              "native-config-transaction-chain", "unestablished-chain-refused");
    });
    add("absent-network-refused", [=] {
      auto no_network = inputs;
      no_network.chain.network = 0;
      refuses(NativeConfigTransaction::open(no_network, evidence_cell(), history, charge),
              "native-config-transaction-chain", "absent-network-refused");
    });
    add("absent-evidence-refused", [=] {
      refuses(NativeConfigTransaction::open(inputs, {}, history, charge), "native-config-transaction-input",
              "absent-evidence-refused");
    });
    add("absent-state-refused", [=] {
      auto absent_state = inputs;
      absent_state.masterchain_state = {};
      refuses(NativeConfigTransaction::open(absent_state, evidence_cell(), history, charge),
              "native-config-transaction-input", "absent-state-refused");
    });
    add("absent-history-refused", [=] {
      refuses(NativeConfigTransaction::open(inputs, evidence_cell(), {}, charge), "native-config-transaction-input",
              "absent-history-refused");
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
