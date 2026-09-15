// What authority does a native configuration transaction execute under?
//
// Assembling it wrongly is not a crash; it is a block governed by a committee it
// is itself introducing, or an update authorised by state the block has not
// finished producing. Both would pass every existing check, so they are what
// these cases construct.
#include <iostream>
#include <memory>
#include <stdexcept>

#include "validator/auth/cells.h"
#include "validator/auth/native-config-transaction.h"

#include "owner-fixture.h"

using namespace p0_owner_fixture;

namespace {
unsigned passed = 0;

void ok(const char* name) {
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

void refuses(const Result<std::unique_ptr<NativeConfigTransaction>>& result, const char* code, const char* name) {
  if (result.ok() || result.error().code != code) {
    std::cerr << "DETAIL " << name << " expected=" << code
              << " actual=" << (result.ok() ? "accepted" : result.error().code) << '\n';
    throw std::runtime_error(name);
  }
  ok(name);
}

struct History final : FinalizedAnchorSource {
  Anchor anchor;
  bool* destroyed = nullptr;
  ~History() override {
    if (destroyed)
      *destroyed = true;
  }
  Result<Anchor> finalized_anchor(std::uint32_t at) const override {
    if (at != anchor.seqno_)
      return Error{"finalized-anchor-unavailable"};
    return anchor;
  }
};

td::Ref<vm::Cell> evidence_cell() {
  // A transaction that carries no attachments still carries a complete,
  // canonical evidence cell. A tag-only stand-in would make a positive case
  // fail at the decoder before it exercised transaction assembly.
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
}  // namespace

int main(int argc, char** argv) {
  try {
    check(argc == 3, "arguments");
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

    // The registry may only be advanced past the state it was read from. A
    // block that claims a coordinate at or below its parent would apply an
    // update to a state that already contains it.
    auto same = inputs;
    same.inclusion = inputs.parent.seqno_;
    refuses(NativeConfigTransaction::open(same, evidence_cell(), history, charge),
            "native-config-transaction-coordinate", "coordinate-must-advance");

    auto earlier = inputs;
    earlier.inclusion = inputs.parent.seqno_ - 1;
    refuses(NativeConfigTransaction::open(earlier, evidence_cell(), history, charge),
            "native-config-transaction-coordinate", "coordinate-cannot-regress");

    // A context the node never established is not a context.
    auto unnamed = inputs;
    unnamed.chain.chain_domain = Hash{};
    refuses(NativeConfigTransaction::open(unnamed, evidence_cell(), history, charge),
            "native-config-transaction-chain", "unestablished-chain-refused");

    auto no_network = inputs;
    no_network.chain.network = 0;
    refuses(NativeConfigTransaction::open(no_network, evidence_cell(), history, charge),
            "native-config-transaction-chain", "absent-network-refused");

    refuses(NativeConfigTransaction::open(inputs, {}, history, charge), "native-config-transaction-input",
            "absent-evidence-refused");

    auto absent_state = inputs;
    absent_state.masterchain_state = {};
    refuses(NativeConfigTransaction::open(absent_state, evidence_cell(), history, charge),
            "native-config-transaction-input", "absent-state-refused");

    refuses(NativeConfigTransaction::open(inputs, evidence_cell(), {}, charge), "native-config-transaction-input",
            "absent-history-refused");

    // The finalized-history source is used by owner verification after
    // admission has returned. The transaction therefore has to own it rather
    // than retain a reference to a caller-local prefetched source.
    bool destroyed = false;
    history->destroyed = &destroyed;
    std::weak_ptr<const FinalizedAnchorSource> weak = history;
    auto authority = NativeConfigTransaction::open(inputs, evidence_cell(), history, charge);
    check(authority.ok(), "history-owned-for-authority-lifetime");
    history.reset();
    check(!destroyed && !weak.expired(), "history-owned-for-authority-lifetime");
    authority.value().reset();
    check(destroyed && weak.expired(), "history-owned-for-authority-lifetime");
    ok("history-owned-for-authority-lifetime");

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
