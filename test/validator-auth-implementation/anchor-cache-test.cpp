// History a node resolved once and keeps across blocks.
//
// This is node-lifetime state, so the question that matters is not whether it
// answers, but whether it stops growing and whether it can be made to answer
// with something it was never given.
#include <iostream>
#include <stdexcept>

#include "validator/auth/native-anchor-cache.h"

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

Anchor at(std::uint32_t seqno, unsigned salt = 0) {
  return Anchor{seqno, h(1000 + seqno + salt), h(2000 + seqno + salt), h(3000 + seqno + salt)};
}
}  // namespace

int main() {
  try {
    NativeAnchorCache cache(4);

    std::vector<std::uint32_t> want{80, 90};
    expect(cache.missing(want) == want, "empty-cache-is-entirely-missing");
    expect(!cache.source(want).ok(), "empty-cache-is-entirely-missing");
    ok("empty-cache-is-entirely-missing");

    expect(cache.admit(80, at(80)).ok(), "resolved-anchor-is-kept");
    expect(cache.missing(want) == std::vector<std::uint32_t>{90}, "resolved-anchor-is-kept");
    ok("resolved-anchor-is-kept");

    // A partial set must not produce a source: executing against one would use
    // history that was never resolved.
    auto partial = cache.source(want);
    expect(!partial.ok() && partial.error().code == "anchor-cache-incomplete-set", "partial-set-produces-no-source");
    ok("partial-set-produces-no-source");

    expect(cache.admit(90, at(90)).ok(), "complete-set-produces-a-source");
    auto source = cache.source(want);
    expect(source.ok(), "complete-set-produces-a-source");
    auto served = source.value().finalized_anchor(90);
    expect(served.ok() && served.value() == at(90), "complete-set-produces-a-source");
    ok("complete-set-produces-a-source");

    // The cache is consulted instead of the archive, so an anchor filed under a
    // coordinate it does not carry would never be checked again.
    auto misfiled = cache.admit(70, at(71));
    expect(!misfiled.ok() && misfiled.error().code == "anchor-cache-binding", "misfiled-anchor-refused");
    ok("misfiled-anchor-refused");

    auto incomplete = cache.admit(60, Anchor{60, {}, {}, {}});
    expect(!incomplete.ok() && incomplete.error().code == "anchor-cache-incomplete", "incomplete-anchor-refused");
    ok("incomplete-anchor-refused");

    // Two different answers for one coordinate is a disagreement about
    // finalized history, not a refresh.
    auto conflict = cache.admit(80, at(80, 1));
    expect(!conflict.ok() && conflict.error().code == "anchor-cache-conflict", "conflicting-answer-refused");
    expect(cache.source({want.data(), 1}).ok(), "conflicting-answer-refused");
    ok("conflicting-answer-refused");

    expect(cache.admit(80, at(80)).ok(), "identical-answer-is-not-a-conflict");
    ok("identical-answer-is-not-a-conflict");

    // Node-lifetime state that does not stop growing is the failure this bound
    // exists for. The oldest coordinates go first, because an approval names
    // recent history.
    for (std::uint32_t i = 100; i < 120; ++i)
      expect(cache.admit(i, at(i)).ok(), "cache-stays-bounded");
    expect(cache.size() == 4, "cache-stays-bounded");
    expect(cache.missing({want.data(), 2}).size() == 2, "cache-stays-bounded");
    expect(cache.source(std::vector<std::uint32_t>{119}).ok(), "cache-stays-bounded");
    ok("cache-stays-bounded");

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
