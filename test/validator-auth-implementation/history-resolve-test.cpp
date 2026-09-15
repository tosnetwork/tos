// Filling the resolved-history cache from the archive.
//
// An update that names history this node has not fetched is deferred, and
// nothing ever admits it unless something resolves what it named. This is that
// step, and the question it has to answer is not whether it can fill the cache
// but whether it can be made to fill it with the wrong thing: the cache is
// consulted instead of the archive afterwards, so a block accepted here would
// never be looked at again.
//
// Which block belongs at a coordinate is decided by the parent state's own
// record of previous blocks, through the one implementation that reads it. What
// these cases have to show is that resolution really does go through it, and
// that it refuses rather than waits when a block is served and does not match.
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

    // A real masterchain block at coordinate 99, and a head state at 100 whose
    // record of previous blocks names it. This is the arrangement the header
    // fixture builds, and it is the only thing that makes a coordinate mean
    // anything.
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

    auto recorded = history_state(mcstate(f), 100, {z, {99, 99, committed.root_, committed.file_}});
    const tos::BlockIdExt head_id{{tos::masterchainId, tos::shardIdAll, 100},
                                  td::Bits256(td::ConstBitPtr(h(800).data())),
                                  td::Bits256(td::ConstBitPtr(h(801).data()))};
    const Anchor head = anchor_of(head_id, recorded);
    check(head == (Anchor{100, h(800), h(801), hash(recorded)}), "fixture-head-anchor");

    // Another real block, which is not the one the record names.
    auto elsewhere = block_for(cell(read(input / "accept.boc")), previous, f);
    elsewhere = replace_ref(elsewhere, 2, vm::CellBuilder::create_merkle_update(state, previous));
    const auto other_raw = boc(elsewhere);
    check(other_raw != raw, "fixture-distinct-blocks");

    auto archive = [&](const tos::BlockIdExt& id, std::size_t limit) -> Result<Bytes> {
      if (id.seqno() != 99)
        return Error{"archive-miss"};
      if (raw.size() > limit)
        return Error{"archive-size"};
      return raw;
    };

    {
      NativeAnchorCache cache;
      std::vector<std::uint32_t> want{99};
      auto resolved = resolve_declared_history(want, recorded, head, f.chain, archive, cache);
      expect(resolved.ok(), "declared-history-becomes-a-source");
      expect(resolved.value().admitted == 1, "declared-history-becomes-a-source");
      expect(resolved.value().unavailable.empty(), "declared-history-becomes-a-source");
      expect(cache.missing(want).empty(), "declared-history-becomes-a-source");
      // The point of resolving: what was deferred can now be served, and what
      // is served is the anchor that block commits.
      auto source = cache.source(want);
      expect(source.ok(), "declared-history-becomes-a-source");
      auto served = source.value().finalized_anchor(99);
      expect(served.ok() && served.value() == committed, "declared-history-becomes-a-source");
      ok("declared-history-becomes-a-source");
    }

    {
      // A real block that is not the one the record names. Serving it is not a
      // reason to wait; it is a reason to refuse.
      NativeAnchorCache cache;
      auto substitution = [&](const tos::BlockIdExt&, std::size_t) -> Result<Bytes> { return other_raw; };
      std::vector<std::uint32_t> want{99};
      auto refused = resolve_declared_history(want, recorded, head, f.chain, substitution, cache);
      expect(!refused.ok(), "substituted-block-is-refused");
      expect(cache.size() == 0, "substituted-block-is-refused");
      ok("substituted-block-is-refused");
    }

    {
      // The ordinary case for a freshly deferred update: this node does not
      // have the block yet. That is not a refusal, it is a reason to try again.
      NativeAnchorCache cache;
      auto empty_archive = [&](const tos::BlockIdExt&, std::size_t) -> Result<Bytes> { return Error{"archive-miss"}; };
      std::vector<std::uint32_t> want{99};
      auto resolved = resolve_declared_history(want, recorded, head, f.chain, empty_archive, cache);
      expect(resolved.ok(), "unfetched-block-is-reported-not-refused");
      expect(resolved.value().admitted == 0, "unfetched-block-is-reported-not-refused");
      expect(resolved.value().unavailable == std::vector<std::uint32_t>{99}, "unfetched-block-is-reported-not-refused");
      expect(!cache.source(want).ok(), "unfetched-block-is-reported-not-refused");
      ok("unfetched-block-is-reported-not-refused");
    }

    {
      // A coordinate the record does not name is not history this chain has,
      // and no archive read can make it so.
      NativeAnchorCache cache;
      unsigned reads = 0;
      auto counted = [&](const tos::BlockIdExt& id, std::size_t limit) -> Result<Bytes> {
        ++reads;
        return archive(id, limit);
      };
      std::vector<std::uint32_t> want{50};
      auto refused = resolve_declared_history(want, recorded, head, f.chain, counted, cache);
      expect(!refused.ok(), "coordinate-outside-the-record-is-refused");
      expect(reads == 0, "coordinate-outside-the-record-is-refused");
      expect(cache.size() == 0, "coordinate-outside-the-record-is-refused");
      ok("coordinate-outside-the-record-is-refused");
    }

    {
      // The head needs no read at all, and what is kept for it is the head
      // this resolution was opened against.
      NativeAnchorCache cache;
      unsigned reads = 0;
      auto counted = [&](const tos::BlockIdExt& id, std::size_t limit) -> Result<Bytes> {
        ++reads;
        return archive(id, limit);
      };
      std::vector<std::uint32_t> want{100};
      auto resolved = resolve_declared_history(want, recorded, head, f.chain, counted, cache);
      expect(resolved.ok() && resolved.value().admitted == 1, "head-is-served-without-a-read");
      expect(reads == 0, "head-is-served-without-a-read");
      auto source = cache.source(want);
      expect(source.ok(), "head-is-served-without-a-read");
      auto served = source.value().finalized_anchor(100);
      expect(served.ok() && served.value() == head, "head-is-served-without-a-read");
      ok("head-is-served-without-a-read");
    }

    {
      // What a node has to fetch before it can resolve. It is the block the
      // record names, not merely a block at that coordinate.
      NativeAnchorCache empty;
      auto wanted = required_finalized_blocks({std::vector<std::uint32_t>{99, 100}}, recorded, head, f.chain, empty);
      expect(wanted.ok(), "reads-are-enumerable-before-fetching");
      expect(wanted.value().size() == 1, "reads-are-enumerable-before-fetching");
      expect(wanted.value()[0].seqno() == 99, "reads-are-enumerable-before-fetching");
      expect(wanted.value()[0].root_hash == td::Bits256(td::ConstBitPtr(committed.root_.data())),
             "reads-are-enumerable-before-fetching");
      expect(wanted.value()[0].file_hash == td::Bits256(td::ConstBitPtr(committed.file_.data())),
             "reads-are-enumerable-before-fetching");
      // Nothing the node already holds is named again.
      NativeAnchorCache holding;
      expect(holding.admit(99, committed).ok(), "reads-are-enumerable-before-fetching");
      auto none = required_finalized_blocks({std::vector<std::uint32_t>{99}}, recorded, head, f.chain, holding);
      expect(none.ok() && none.value().empty(), "reads-are-enumerable-before-fetching");
      ok("reads-are-enumerable-before-fetching");
    }

    {
      // A resolution that disagrees with what is already held is a
      // disagreement about finalized history, not a refresh.
      NativeAnchorCache cache;
      expect(cache.admit(99, Anchor{99, h(11), h(12), h(13)}).ok(), "disagreement-with-what-is-held-is-refused");
      std::vector<std::uint32_t> want{99};
      auto refused = resolve_declared_history(want, recorded, head, f.chain, archive, cache);
      expect(!refused.ok() && refused.error().code == "anchor-cache-conflict",
             "disagreement-with-what-is-held-is-refused");
      ok("disagreement-with-what-is-held-is-refused");
    }

    {
      // One coordinate this node cannot serve must not turn the next one into
      // a wait: a coordinate the record does not name is still a refusal.
      NativeAnchorCache cache;
      auto empty_archive = [&](const tos::BlockIdExt&, std::size_t) -> Result<Bytes> { return Error{"archive-miss"}; };
      std::vector<std::uint32_t> want{99, 50};
      auto mixed = resolve_declared_history(want, recorded, head, f.chain, empty_archive, cache);
      expect(!mixed.ok(), "a-wait-does-not-excuse-a-later-refusal");
      ok("a-wait-does-not-excuse-a-later-refusal");
    }

    {
      // More coordinates than a declaration may carry is refused before a
      // single read, so an oversized demand costs no archive work.
      NativeAnchorCache cache;
      unsigned reads = 0;
      auto counted = [&](const tos::BlockIdExt& id, std::size_t limit) -> Result<Bytes> {
        ++reads;
        return archive(id, limit);
      };
      std::vector<std::uint32_t> want(65, 99);
      refuses(resolve_declared_history(want, recorded, head, f.chain, counted, cache), "anchor-resolve-budget",
              "oversized-declaration-is-refused");
      expect(reads == 0, "oversized-declaration-is-refused");
    }

    {
      NativeAnchorCache cache;
      std::vector<std::uint32_t> want{99};
      refuses(resolve_declared_history(want, recorded, head, f.chain, {}, cache), "anchor-resolve-reader",
              "absent-reader-is-refused");
    }

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
