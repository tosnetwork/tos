/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
// Archive LRU decisions: the default policy validators use must decide exactly
// as before, and a sequential reader's retention must stop thrashing an
// oversized slice without letting descriptors grow past its budget.
#include <map>
#include <random>
#include <vector>

#include "services/source-admission.h"
#include "td/utils/tests.h"
#include "validator/db/archive-lru-policy.h"

namespace {
using tos::validator::ArchiveLruPolicy;
using Key = ArchiveLruPolicy::Key;

Key slice(std::uint32_t id) {
  return Key{id, false, false};
}

// The eviction rule validators ran before the policy was extracted, kept
// verbatim as the reference the default policy must reproduce.
class LegacyLru {
 public:
  explicit LegacyLru(std::size_t max_total_files) : max_total_files_(max_total_files) {
  }
  std::vector<Key> on_query(Key id, std::size_t files_count) {
    SliceInfo &info = slices_[id];
    if (info.opened_idx != 0) {
      total_files_ -= info.files_count;
      lru_.erase(info.opened_idx);
    }
    total_files_ += (info.files_count = files_count);
    info.opened_idx = current_idx_++;
    if (!info.is_permanent) {
      lru_.emplace(info.opened_idx, id);
    }
    return enforce_limit();
  }
  std::vector<Key> set_permanent_slices(std::vector<Key> ids) {
    for (auto id : permanent_slices_) {
      SliceInfo &info = slices_[id];
      if (!info.is_permanent) {
        continue;
      }
      info.is_permanent = false;
      if (info.opened_idx) {
        lru_.emplace(info.opened_idx, id);
      }
    }
    permanent_slices_ = std::move(ids);
    for (auto id : permanent_slices_) {
      SliceInfo &info = slices_[id];
      if (info.is_permanent) {
        continue;
      }
      info.is_permanent = true;
      if (info.opened_idx) {
        lru_.erase(info.opened_idx);
      }
    }
    return enforce_limit();
  }

 private:
  struct SliceInfo {
    std::size_t files_count = 0;
    std::size_t opened_idx = 0;
    bool is_permanent = false;
  };
  std::vector<Key> enforce_limit() {
    std::vector<Key> closed;
    while (total_files_ > max_total_files_ && !lru_.empty()) {
      auto it = lru_.begin();
      auto it2 = slices_.find(it->second);
      lru_.erase(it);
      total_files_ -= it2->second.files_count;
      closed.push_back(it2->first);
      it2->second.opened_idx = 0;
    }
    return closed;
  }
  std::size_t current_idx_ = 1;
  std::map<Key, SliceInfo> slices_;
  std::map<std::size_t, Key> lru_;
  std::size_t total_files_ = 0;
  std::size_t max_total_files_ = 0;
  std::vector<Key> permanent_slices_;
};

ArchiveLruPolicy reader(std::size_t max_total_files, std::size_t keep, std::size_t budget = 0,
                        std::size_t reserve = 512) {
  return ArchiveLruPolicy{ArchiveLruPolicy::Options{max_total_files, keep, budget, reserve}};
}
}  // namespace

TEST(ArchiveLru, DefaultPolicyDecidesExactlyAsBefore) {
  for (std::size_t max_files : {1u, 16u, 128u, 512u}) {
    std::mt19937 random(static_cast<unsigned>(max_files));
    LegacyLru legacy(max_files);
    ArchiveLruPolicy policy(ArchiveLruPolicy::Options{max_files, 0, 0});
    for (int step = 0; step < 20000; ++step) {
      std::vector<Key> expected, actual;
      if (random() % 50 == 0) {
        std::vector<Key> permanent;
        for (unsigned i = 0, n = random() % 4; i < n; ++i) {
          permanent.push_back(Key{static_cast<std::uint32_t>(random() % 40), random() % 2 == 0, random() % 3 == 0});
        }
        expected = legacy.set_permanent_slices(permanent);
        actual = policy.set_permanent(permanent, static_cast<std::int64_t>(random() % 5000));
      } else {
        Key key{static_cast<std::uint32_t>(random() % 40), random() % 2 == 0, random() % 3 == 0};
        auto files = static_cast<std::size_t>(1 + random() % 600);
        expected = legacy.on_query(key, files);
        // A descriptor count changes nothing without a budget.
        actual = policy.on_query(key, files, static_cast<std::int64_t>(random() % 5000));
      }
      ASSERT_TRUE(expected == actual);
    }
    ASSERT_EQ(policy.retention_withdrawn(), 0u);
    ASSERT_TRUE(!policy.over_budget());
  }
}

TEST(ArchiveLru, DefaultPolicyClosesAnOversizedSliceAfterEveryRead) {
  auto policy = reader(128, 0);
  std::size_t closes = 0;
  for (int i = 0; i < 100; ++i) {
    closes += policy.on_query(slice(200000), 405).size();
  }
  ASSERT_EQ(closes, 100u);
}

TEST(ArchiveLru, ReaderKeepsAnOversizedSliceOpenAcrossReads) {
  auto policy = reader(128, 2);
  std::size_t closes = 0;
  for (int i = 0; i < 100; ++i) {
    closes += policy.on_query(slice(200000), 405).size();
  }
  ASSERT_EQ(closes, 0u);
  ASSERT_EQ(policy.evictable_count(), 1u);
  ASSERT_EQ(policy.total_files(), 405u);
}

// Reads alternate between two slices at a slice boundary (a masterchain block
// in one slice, its shard blocks or parents in the previous one).
TEST(ArchiveLru, ReaderCrossesASliceBoundaryWithoutReopening) {
  auto keep_two = reader(128, 2);
  auto keep_one = reader(128, 1);
  std::size_t closes_two = 0, closes_one = 0;
  for (int i = 0; i < 100; ++i) {
    auto key = slice(i % 2 == 0 ? 200000 : 220000);
    auto files = i % 2 == 0 ? 405u : 169u;
    closes_two += keep_two.on_query(key, files).size();
    closes_one += keep_one.on_query(key, files).size();
  }
  ASSERT_EQ(closes_two, 0u);
  ASSERT_EQ(closes_one, 99u);
  // Moving on to a third slice closes only the least recently used one.
  auto closed = keep_two.on_query(slice(228172), 51);
  ASSERT_EQ(closed.size(), 1u);
  ASSERT_TRUE(closed[0] == slice(200000));
  ASSERT_EQ(keep_two.evictable_count(), 2u);
}

TEST(ArchiveLru, AGrowingSliceIsCountedOnceAtItsCurrentWeight) {
  auto policy = reader(128, 2);
  policy.set_permanent({slice(600000)});
  for (std::size_t files = 5; files <= 5005; files += 100) {
    // The newest slice grows as packages are added; it is never closed.
    for (const auto &key : policy.on_query(slice(600000), files)) {
      ASSERT_TRUE(!(key == slice(600000)));
    }
    policy.on_query(slice(220000), 169);
    ASSERT_EQ(policy.total_files(), files + 169);
  }
  // A non-permanent slice that grows is re-weighed, not added again.
  auto growing = reader(128, 1);
  for (std::size_t files = 10; files <= 1000; files += 10) {
    ASSERT_TRUE(growing.on_query(slice(1), files).empty());
    ASSERT_EQ(growing.total_files(), files);
  }
}

TEST(ArchiveLru, ReaderHoldsAtMostTheTargetPlusItsRetainedSlices) {
  const std::size_t target = 128, keep = 2;
  auto policy = reader(target, keep);
  std::mt19937 random(7);
  std::size_t largest = 0;
  for (std::uint32_t i = 0; i < 5000; ++i) {
    auto files = static_cast<std::size_t>(1 + random() % 405);
    largest = std::max(largest, files);
    policy.on_query(slice(i % 300), files);
    ASSERT_TRUE(policy.evictable_files() <= target + keep * largest);
    ASSERT_TRUE(policy.evictable_count() <= keep + target);
  }
}

TEST(ArchiveLru, ABudgetWithdrawsRetentionAndKeepsRoomForOneSlice) {
  auto policy = reader(128, 2, 1000, 100);
  ASSERT_TRUE(policy.on_query(slice(200000), 405, 300).empty());
  ASSERT_TRUE(policy.on_query(slice(220000), 169, 480).empty());
  // 600 held + room for the largest slice (405) exceeds 1000: the oldest
  // retained slice is closed, which frees enough.
  auto closed = policy.on_query(slice(220000), 169, 600);
  ASSERT_EQ(closed.size(), 1u);
  ASSERT_TRUE(closed[0] == slice(200000));
  ASSERT_EQ(policy.retention_withdrawn(), 1u);
  ASSERT_TRUE(!policy.over_budget());
  // Descriptors held elsewhere (a growing permanent slice, sockets): every
  // non-permanent slice is closed and the policy reports it is over budget.
  policy.set_permanent({slice(600000)});
  policy.on_query(slice(600000), 3000, 3200);
  ASSERT_EQ(policy.evictable_count(), 0u);
  ASSERT_TRUE(policy.over_budget());
  ASSERT_EQ(policy.retention_withdrawn(), 2u);
}

TEST(ArchiveLru, RebalanceClosesWhatAnOverstatedWeightLeftOpen) {
  auto policy = reader(128, 2, 1000, 100);
  policy.on_query(slice(1), 300, 200);
  policy.on_query(slice(2), 300, 400);
  // The estimate after closing slice 1 fits, but the slice held fewer
  // descriptors than its weight: the actual count stays high.
  ASSERT_EQ(policy.on_query(slice(2), 300, 750).size(), 1u);
  ASSERT_TRUE(!policy.over_budget());
  auto closed = policy.rebalance(720);
  ASSERT_EQ(closed.size(), 1u);
  ASSERT_TRUE(closed[0] == slice(2));
  // Within the budget again, rebalancing changes nothing.
  ASSERT_TRUE(policy.rebalance(100).empty());
}

TEST(ArchiveLru, SourceReadsAreAdmittedOnlyWithRoomForASlice) {
  using tos::services::admit_source_request;
  using tos::services::SourceAdmission;
  ASSERT_TRUE(admit_source_request(SourceAdmission{0, 512}, -1, 0).is_ok());
  SourceAdmission admission{4000, 512};
  ASSERT_TRUE(admit_source_request(admission, -1, 0).is_error());
  ASSERT_TRUE(admit_source_request(admission, 3488, 0).is_ok());
  ASSERT_TRUE(admit_source_request(admission, 3489, 0).is_error());
  // The largest slice seen raises the reserve.
  ASSERT_TRUE(admit_source_request(admission, 3000, 1000).is_ok());
  ASSERT_TRUE(admit_source_request(admission, 3001, 1000).is_error());
  ASSERT_TRUE(admit_source_request(admission, 5000, 0).is_error());
}
