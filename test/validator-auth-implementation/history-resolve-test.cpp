// Filling the resolved-history cache from the archive.
//
// An update that names history this node has not fetched is deferred, and
// nothing ever admits it unless something resolves what it named. This is that
// step, and the question it has to answer is not whether it can fill the cache
// but whether it can be made to fill it with the wrong thing: the cache is
// consulted instead of the archive afterwards, so a block accepted here under a
// coordinate it does not commit would never be looked at again.
#include <filesystem>
#include <iostream>
#include <stdexcept>

#include "validator/auth/native-anchor-cache.h"

#include "native-history-fixture.h"
#include "owner-fixture.h"

using namespace p0_owner_fixture;

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

void refuses(const Result<Resolution>& result, const char* code, const char* name) {
  if (result.ok() || result.error().code != code) {
    std::cerr << "DETAIL " << name << " expected=" << code
              << " actual=" << (result.ok() ? "resolved" : result.error().code) << '\n';
    throw std::runtime_error(name);
  }
  ok(name);
}
}  // namespace

int main(int argc, char** argv) {
  try {
    check(argc == 2, "arguments");
    std::filesystem::path input(argv[1]);

    // A real masterchain block, built the way the header fixture builds one, so
    // the anchor under test is the anchor that block actually commits.
    auto f = fixture(input);
    auto zero = history_state(mcstate(f), 0, {});
    f.chain.genesis_root = hash(zero);
    f.chain.genesis_file = file_hash(boc(zero));
    Entry z{0, 0, f.chain.genesis_root, f.chain.genesis_file};
    auto state = history_state(mcstate(f), 99, {z});
    auto previous = history_state(mcstate(f), 98, {z});
    auto block = block_for(cell(read(input / "accept.boc")), state, f);
    block = replace_ref(block, 2, vm::CellBuilder::create_merkle_update(previous, state));
    const auto raw = boc(block);
    const Anchor committed{99, hash(block), file_hash(raw), hash(state)};

    // The archive this node has: one block, at the coordinate it commits.
    auto archive = [&](std::uint32_t at, std::size_t limit) -> Result<Bytes> {
      if (at != 99)
        return Error{"archive-miss"};
      if (raw.size() > limit)
        return Error{"archive-size"};
      return raw;
    };

    {
      NativeAnchorCache cache;
      std::vector<std::uint32_t> want{99};
      auto resolved = resolve_declared_history(want, f.chain.network, archive, cache);
      expect(resolved.ok(), "declared-history-becomes-a-source");
      expect(resolved.value().admitted == 1, "declared-history-becomes-a-source");
      expect(resolved.value().unavailable.empty(), "declared-history-becomes-a-source");
      expect(cache.missing(want).empty(), "declared-history-becomes-a-source");
      // The point of resolving: what was deferred can now be served.
      auto source = cache.source(want);
      expect(source.ok(), "declared-history-becomes-a-source");
      auto served = source.value().finalized_anchor(99);
      expect(served.ok() && served.value() == committed, "declared-history-becomes-a-source");
      ok("declared-history-becomes-a-source");
    }

    {
      // A block served under a coordinate it does not commit is the
      // substitution this whole arrangement has to refuse.
      NativeAnchorCache cache;
      auto misfiling = [&](std::uint32_t, std::size_t) -> Result<Bytes> { return raw; };
      std::vector<std::uint32_t> want{50};
      refuses(resolve_declared_history(want, f.chain.network, misfiling, cache), "anchor-cache-binding",
              "block-under-another-coordinate-is-refused");
      expect(cache.size() == 0, "block-under-another-coordinate-is-refused");
    }

    {
      // Bytes that are not a block do not become an anchor.
      NativeAnchorCache cache;
      auto rubbish = [&](std::uint32_t, std::size_t) -> Result<Bytes> { return Bytes{1, 2, 3, 4}; };
      std::vector<std::uint32_t> want{99};
      auto broken = resolve_declared_history(want, f.chain.network, rubbish, cache);
      expect(!broken.ok(), "unparsable-bytes-are-refused");
      expect(cache.size() == 0, "unparsable-bytes-are-refused");
      ok("unparsable-bytes-are-refused");
    }

    {
      // The same parse guard, reached with a different input: a block that
      // belongs to another chain. It shares the guard above rather than having
      // one of its own, which is why no mutation names this case.
      NativeAnchorCache cache;
      std::vector<std::uint32_t> want{99};
      auto other = resolve_declared_history(want, f.chain.network + 1, archive, cache);
      expect(!other.ok(), "another-network-is-refused");
      expect(cache.size() == 0, "another-network-is-refused");
      ok("another-network-is-refused");
    }

    {
      // The ordinary case for a freshly deferred update: the archive does not
      // have it yet. That is not a refusal, it is a reason to try again.
      NativeAnchorCache cache;
      std::vector<std::uint32_t> want{99, 120};
      auto resolved = resolve_declared_history(want, f.chain.network, archive, cache);
      expect(resolved.ok(), "missing-block-is-reported-not-refused");
      expect(resolved.value().admitted == 1, "missing-block-is-reported-not-refused");
      expect(resolved.value().unavailable == std::vector<std::uint32_t>{120}, "missing-block-is-reported-not-refused");
      expect(!cache.source(want).ok(), "missing-block-is-reported-not-refused");
      ok("missing-block-is-reported-not-refused");
    }

    {
      // More coordinates than a declaration may carry is refused before a
      // single read, so an oversized demand costs no archive work.
      NativeAnchorCache cache;
      unsigned reads = 0;
      auto counted = [&](std::uint32_t at, std::size_t limit) -> Result<Bytes> {
        ++reads;
        return archive(at, limit);
      };
      std::vector<std::uint32_t> want(65, 99);
      refuses(resolve_declared_history(want, f.chain.network, counted, cache), "anchor-resolve-budget",
              "oversized-declaration-is-refused");
      expect(reads == 0, "oversized-declaration-is-refused");
    }

    {
      NativeAnchorCache cache;
      std::vector<std::uint32_t> want{99};
      refuses(resolve_declared_history(want, f.chain.network, {}, cache), "anchor-resolve-reader",
              "absent-reader-is-refused");
    }

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
