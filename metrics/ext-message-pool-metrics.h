#pragma once

#include <array>
#include <algorithm>
#include <cstdio>
#include <string_view>

#include "metrics-collectors.h"

namespace tos::metrics {

enum class ExtMessageState { eligible, postponed };

// Maintained by ExtMessagePool at the mutation sites. In particular, collecting a snapshot must
// only copy this object: it must not walk the pool or advance lazy expiry/reactivation state.
class ExtMessageStateCounts {
 public:
  void insert(ExtMessageState state = ExtMessageState::eligible, td::uint64 count = 1) {
    values_[index(state)] += count;
  }

  void erase(ExtMessageState state, td::uint64 count = 1) {
    auto &value = values_[index(state)];
    CHECK(value >= count);
    value -= count;
  }

  void transition(ExtMessageState from, ExtMessageState to, td::uint64 count = 1) {
    if (from == to) {
      return;
    }
    erase(from, count);
    insert(to, count);
  }

  td::uint64 value(ExtMessageState state) const {
    return values_[index(state)];
  }

  td::uint64 total() const {
    td::uint64 result = 0;
    for (auto value : values_) {
      result += value;
    }
    return result;
  }

 private:
  static constexpr size_t state_count = 2;

  static constexpr size_t index(ExtMessageState state) {
    return static_cast<size_t>(state);
  }

  std::array<td::uint64, state_count> values_{};
};

enum class ExtMessageAdmissionOutcome : size_t {
  accepted,
  validated_only,
  not_ready,
  too_large,
  backpressure,
  invalid,
  state_unavailable,
  vm_rejected,
  rate_limited,
  pool_full,
  address_full,
  duplicate,
  internal_error,
  reprioritized,
  count
};

enum class ExtMessageRemovalReason : size_t { applied, expired, rejected_final, filtered, pool_pressure, count };

// How long an entry sat in the pool before this node saw it applied. An idle chain includes within
// one block, so the low end has to stay sub-second; an entry can never be stored longer than the
// 600 s TTL, which is therefore the natural last bound.
inline constexpr std::array<double, 12> kExtInclusionBuckets = {0.25, 0.5, 1, 2, 4, 8, 15, 30, 60, 120, 300, 600};

class ExtMessageInclusionHistogram {
 public:
  void observe(double value) {
    ++buckets_[std::lower_bound(kExtInclusionBuckets.begin(), kExtInclusionBuckets.end(), value) - kExtInclusionBuckets.begin()];
    sum_ += value;
    ++count_;
  }
  td::uint64 count() const { return count_; }
  double sum() const { return sum_; }
  MetricFamily collect() const {
    MetricFamily result{.name = "mempool_ext_inclusion_seconds", .type = "histogram", .help = std::nullopt, .metrics = {}};
    td::uint64 cumulative = 0;
    for (size_t i = 0; i <= kExtInclusionBuckets.size(); ++i) {
      cumulative += buckets_[i];
      char bound[32];
      if (i < kExtInclusionBuckets.size()) {
        std::snprintf(bound, sizeof(bound), "%.17g", kExtInclusionBuckets[i]);
      } else {
        std::snprintf(bound, sizeof(bound), "+Inf");
      }
      result.metrics.push_back(Metric{.suffix = "bucket", .label_set = {{{"le", bound}}},
          .samples = {{.label_set = {}, .value = static_cast<double>(cumulative)}}});
    }
    result.metrics.push_back(Metric{.suffix = "sum", .label_set = {}, .samples = {{.label_set = {}, .value = sum_}}});
    result.metrics.push_back(Metric{.suffix = "count", .label_set = {}, .samples = {{.label_set = {}, .value = static_cast<double>(count_)}}});
    return result;
  }
 private:
  std::array<td::uint64, kExtInclusionBuckets.size() + 1> buckets_{};
  double sum_ = 0;
  td::uint64 count_ = 0;
};

struct ExtMessagePoolSnapshot {
  ExtMessageStateCounts ext_messages;
  double oldest_ext_message_age_seconds{0.0};
  td::uint64 check_ok{0};
  td::uint64 check_error{0};
  std::array<td::uint64, static_cast<size_t>(ExtMessageAdmissionOutcome::count)> admission{};
  std::array<td::uint64, static_cast<size_t>(ExtMessageRemovalReason::count)> removed{};
  ExtMessageInclusionHistogram ext_inclusion_seconds;
  td::uint64 applied_master{0};
  td::uint64 applied_shard{0};

  MetricSet collect() const {
    MetricSet result;
    auto pending = MetricFamily{.name = "mempool_ext_messages", .type = "gauge", .help = std::nullopt, .metrics = {}};
    for (const auto &[name, state] : {std::pair{"eligible", ExtMessageState::eligible}, std::pair{"postponed", ExtMessageState::postponed}}) {
      pending.metrics.push_back(Metric{.suffix = "", .label_set = {{{"state", name}}},
          .samples = {{.label_set = {}, .value = static_cast<double>(ext_messages.value(state))}}});
    }
    result.families.push_back(std::move(pending));
    result.families.push_back(MetricFamily::make_scalar("mempool_oldest_ext_message_age_seconds", "gauge", oldest_ext_message_age_seconds));
    auto add_counter = [&](std::string name, std::string label, auto values, auto names) {
      auto family = MetricFamily{.name = std::move(name), .type = "counter", .help = std::nullopt, .metrics = {}};
      for (size_t i = 0; i < values.size(); ++i) {
        family.metrics.push_back(Metric{.suffix = "total", .label_set = {{{label, std::string(names[i])}}},
            .samples = {{.label_set = {}, .value = static_cast<double>(values[i])}}});
      }
      result.families.push_back(std::move(family));
    };
    add_counter("mempool_ext_check", "result", std::array{check_ok, check_error}, std::array{"ok", "error"});
    add_counter("mempool_ext_admission", "outcome", admission, admission_outcome_names_);
    add_counter("mempool_ext_removed", "reason", removed, removal_reason_names_);
    add_counter("applied_ext_messages", "chain", std::array{applied_master, applied_shard}, std::array{"master", "shard"});
    result.families.push_back(ext_inclusion_seconds.collect());
    return result;
  }

 private:
  static constexpr auto admission_outcome_names_ = std::to_array<std::string_view>({
      "accepted",
      "validated_only",
      "not_ready",
      "too_large",
      "backpressure",
      "invalid",
      "state_unavailable",
      "vm_rejected",
      "rate_limited",
      "pool_full",
      "address_full",
      "duplicate",
      "internal_error",
      "reprioritized",
  });
  static_assert(admission_outcome_names_.size() == static_cast<size_t>(ExtMessageAdmissionOutcome::count));

  static constexpr auto removal_reason_names_ = std::to_array<std::string_view>({
      "applied",
      "expired",
      "rejected_final",
      "filtered",
      "pool_pressure",
  });
  static_assert(removal_reason_names_.size() == static_cast<size_t>(ExtMessageRemovalReason::count));
};

}  // namespace tos::metrics
