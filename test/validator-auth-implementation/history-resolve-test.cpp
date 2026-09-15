// Filling the resolved-history cache from the archive.
#include <filesystem>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "validator/auth/native-anchor-cache.h"

#include "native-history-fixture.h"
#include "owner-fixture.h"

using namespace p0_owner_fixture;

namespace {
struct AssertionFailure : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void require(bool condition, const std::string& assertion) {
  if (!condition)
    throw AssertionFailure(assertion);
}

void refuses(const Result<Resolution>& result, const char* code, const char* name) {
  if (result.ok() || result.error().code != code) {
    std::cerr << "DETAIL " << name << " expected=" << code
              << " actual=" << (result.ok() ? "resolved" : result.error().code) << '\n';
    throw AssertionFailure(name);
  }
}

using Test = std::pair<std::string, std::function<void()>>;
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2 || argc > 3) {
      std::cerr << "USAGE: test-p0-history-resolve INPUTS [case-name|--list|--exclude=case]\n";
      return 2;
    }
    std::filesystem::path input(argv[1]);

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
    const auto head_root = h(800);
    const auto head_file = h(801);
    const tos::BlockIdExt head_id{{tos::masterchainId, tos::shardIdAll, 100},
                                  td::Bits256(td::ConstBitPtr(head_root.data())),
                                  td::Bits256(td::ConstBitPtr(head_file.data()))};
    const Anchor head = anchor_of(head_id, recorded);
    check(head == (Anchor{100, head_root, head_file, hash(recorded)}), "fixture-head-anchor");

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

    std::vector<Test> tests;
    auto add = [&](std::string name, std::function<void()> fn) {
      tests.emplace_back(std::move(name), std::move(fn));
    };

    add("declared-history-becomes-a-source", [&] {
      NativeAnchorCache cache;
      std::vector<std::uint32_t> want{99};
      auto resolved = resolve_declared_history(want, recorded, head, f.chain, archive, cache);
      require(resolved.ok() && resolved.value().admitted == 1 && resolved.value().unavailable.empty(),
              "declared-history-becomes-a-source");
      require(cache.missing(want).empty(), "declared-history-becomes-a-source");
      auto source = cache.source(want);
      require(source.ok(), "declared-history-becomes-a-source");
      auto served = source.value().finalized_anchor(99);
      require(served.ok() && served.value() == committed, "declared-history-becomes-a-source");
    });
    add("substituted-block-is-refused", [&] {
      NativeAnchorCache cache;
      auto substitution = [&](const tos::BlockIdExt&, std::size_t) -> Result<Bytes> { return other_raw; };
      std::vector<std::uint32_t> want{99};
      auto refused = resolve_declared_history(want, recorded, head, f.chain, substitution, cache);
      require(!refused.ok() && cache.size() == 0, "substituted-block-is-refused");
    });
    add("unfetched-block-is-reported-not-refused", [&] {
      NativeAnchorCache cache;
      auto empty_archive = [&](const tos::BlockIdExt&, std::size_t) -> Result<Bytes> { return Error{"archive-miss"}; };
      std::vector<std::uint32_t> want{99};
      auto resolved = resolve_declared_history(want, recorded, head, f.chain, empty_archive, cache);
      require(resolved.ok() && resolved.value().admitted == 0 &&
                  resolved.value().unavailable == std::vector<std::uint32_t>{99} && !cache.source(want).ok(),
              "unfetched-block-is-reported-not-refused");
    });
    add("coordinate-outside-the-record-is-refused", [&] {
      NativeAnchorCache cache;
      unsigned reads = 0;
      auto counted = [&](const tos::BlockIdExt& id, std::size_t limit) -> Result<Bytes> {
        ++reads;
        return archive(id, limit);
      };
      std::vector<std::uint32_t> want{50};
      auto refused = resolve_declared_history(want, recorded, head, f.chain, counted, cache);
      require(!refused.ok() && reads == 0 && cache.size() == 0, "coordinate-outside-the-record-is-refused");
    });
    add("head-is-served-without-a-read", [&] {
      NativeAnchorCache cache;
      unsigned reads = 0;
      auto counted = [&](const tos::BlockIdExt& id, std::size_t limit) -> Result<Bytes> {
        ++reads;
        return archive(id, limit);
      };
      std::vector<std::uint32_t> want{100};
      auto resolved = resolve_declared_history(want, recorded, head, f.chain, counted, cache);
      require(resolved.ok() && resolved.value().admitted == 1 && reads == 0, "head-is-served-without-a-read");
      auto source = cache.source(want);
      require(source.ok(), "head-is-served-without-a-read");
      auto served = source.value().finalized_anchor(100);
      require(served.ok() && served.value() == head, "head-is-served-without-a-read");
    });
    add("reads-are-enumerable-before-fetching", [&] {
      NativeAnchorCache empty;
      const std::vector<std::uint32_t> both{99, 100};
      auto wanted = required_finalized_blocks(both, recorded, head, f.chain, empty);
      require(wanted.ok() && wanted.value().size() == 1 && wanted.value()[0].seqno() == 99,
              "reads-are-enumerable-before-fetching");
      require(wanted.value()[0].root_hash == td::Bits256(td::ConstBitPtr(committed.root_.data())) &&
                  wanted.value()[0].file_hash == td::Bits256(td::ConstBitPtr(committed.file_.data())),
              "reads-are-enumerable-before-fetching");
      NativeAnchorCache holding;
      require(holding.admit(99, committed).ok(), "reads-are-enumerable-before-fetching");
      const std::vector<std::uint32_t> one{99};
      auto none = required_finalized_blocks(one, recorded, head, f.chain, holding);
      require(none.ok() && none.value().empty(), "reads-are-enumerable-before-fetching");
    });
    add("disagreement-with-what-is-held-is-refused", [&] {
      NativeAnchorCache cache;
      require(cache.admit(99, Anchor{99, h(11), h(12), h(13)}).ok(),
              "disagreement-with-what-is-held-is-refused");
      std::vector<std::uint32_t> want{99};
      auto refused = resolve_declared_history(want, recorded, head, f.chain, archive, cache);
      require(!refused.ok() && refused.error().code == "anchor-cache-conflict",
              "disagreement-with-what-is-held-is-refused");
    });
    add("a-wait-does-not-excuse-a-later-refusal", [&] {
      NativeAnchorCache cache;
      auto empty_archive = [&](const tos::BlockIdExt&, std::size_t) -> Result<Bytes> { return Error{"archive-miss"}; };
      std::vector<std::uint32_t> want{99, 50};
      auto mixed = resolve_declared_history(want, recorded, head, f.chain, empty_archive, cache);
      require(!mixed.ok(), "a-wait-does-not-excuse-a-later-refusal");
    });
    add("oversized-declaration-is-refused", [&] {
      NativeAnchorCache cache;
      unsigned reads = 0;
      auto counted = [&](const tos::BlockIdExt& id, std::size_t limit) -> Result<Bytes> {
        ++reads;
        return archive(id, limit);
      };
      std::vector<std::uint32_t> want(65, 99);
      refuses(resolve_declared_history(want, recorded, head, f.chain, counted, cache), "anchor-resolve-budget",
              "oversized-declaration-is-refused");
      require(reads == 0, "oversized-declaration-is-refused");
    });
    add("absent-reader-is-refused", [&] {
      NativeAnchorCache cache;
      std::vector<std::uint32_t> want{99};
      refuses(resolve_declared_history(want, recorded, head, f.chain, {}, cache), "anchor-resolve-reader",
              "absent-reader-is-refused");
    });

    if (argc == 3 && std::string_view(argv[2]) == "--list") {
      for (const auto& [name, _] : tests)
        std::cout << name << '\n';
      return 0;
    }
    std::string selected;
    std::string excluded;
    if (argc == 3) {
      std::string argument(argv[2]);
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
