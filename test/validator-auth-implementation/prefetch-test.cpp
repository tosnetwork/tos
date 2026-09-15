// Everything a transaction will read, known before it runs.
//
// The library resolves anchors synchronously and a node's archive is not
// synchronous. The resolution is to declare the requirement up front rather
// than to block or to go asynchronous, which only works if a miss during
// execution is a refusal. If a miss could still reach storage, the declaration
// would be advisory and an execution could read more than it declared.
#include <iostream>
#include <stdexcept>

#include "validator/auth/native-prefetch.h"

#include "native-fixture.h"

using namespace tos::auth;
using namespace p0_fixture;

namespace {
unsigned passed = 0;

void ok(const char* name) {
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

void expect(bool condition, const char* name) {
  if (!condition)
    throw std::runtime_error(name);
}

OwnerAuth owner_at(std::uint32_t seqno) {
  OwnerAuth auth;
  auth.proof_.anchor_ = Anchor{seqno, h(100 + seqno), h(200 + seqno), h(300 + seqno)};
  return auth;
}

Anchor anchor_at(std::uint32_t seqno) {
  return Anchor{seqno, h(100 + seqno), h(200 + seqno), h(300 + seqno)};
}
}  // namespace

int main() {
  try {
    Authorizations none;
    auto empty = required_finalized_coordinates(none, 100);
    expect(empty.ok() && empty.value().empty(), "no-owner-proof-requires-nothing");
    ok("no-owner-proof-requires-nothing");

    Authorizations two;
    two.owner_ = {owner_at(90), owner_at(80), owner_at(90)};
    auto listed = required_finalized_coordinates(two, 100);
    expect(listed.ok(), "duplicates-collapse-and-sort");
    expect(listed.value() == std::vector<std::uint32_t>{80, 90}, "duplicates-collapse-and-sort");
    ok("duplicates-collapse-and-sort");

    // The rule execution applies is applied here too, so a caller is never asked
    // to fetch a block whose proof could not be accepted anyway.
    Authorizations future;
    future.owner_ = {owner_at(100)};
    auto refused = required_finalized_coordinates(future, 100);
    expect(!refused.ok() && refused.error().code == "owner-finality-coordinate", "same-block-anchor-refused");
    ok("same-block-anchor-refused");

    Authorizations many;
    for (std::uint32_t i = 0; i < 65; ++i)
      many.owner_.push_back(owner_at(i + 1));
    auto wide = required_finalized_coordinates(many, 100);
    expect(!wide.ok() && wide.error().code == "owner-finality-breadth", "unbounded-history-refused");
    ok("unbounded-history-refused");

    PrefetchedAnchorSource source({{80, anchor_at(80)}, {90, anchor_at(90)}});
    auto found = source.finalized_anchor(90);
    expect(found.ok() && found.value() == anchor_at(90), "prefetched-anchor-answers");
    ok("prefetched-anchor-answers");

    // The property the whole arrangement rests on.
    auto missed = source.finalized_anchor(85);
    expect(!missed.ok() && missed.error().code == "finalized-anchor-unavailable", "unfetched-coordinate-refused");
    ok("unfetched-coordinate-refused");

    // A prefetched map is still a place a substitution could hide, so an entry
    // filed under the wrong coordinate is refused rather than returned.
    PrefetchedAnchorSource misfiled({{80, anchor_at(81)}});
    auto wrong = misfiled.finalized_anchor(80);
    expect(!wrong.ok() && wrong.error().code == "finalized-anchor-binding", "misfiled-anchor-refused");
    ok("misfiled-anchor-refused");

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
