#pragma once

#include <array>
#include <string_view>

#include "metrics-collectors.h"

namespace tos::metrics {

enum class ExtMessageAdmissionOutcome : size_t {
  accepted,
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

struct ExtMessagePoolSnapshot {
  td::uint64 pending_ext_messages{0};
  double oldest_ext_message_age_seconds{0.0};
  td::uint64 check_ok{0};
  td::uint64 check_error{0};
  std::array<td::uint64, static_cast<size_t>(ExtMessageAdmissionOutcome::count)> admission{};
  std::array<td::uint64, static_cast<size_t>(ExtMessageRemovalReason::count)> removed{};
  td::uint64 applied_master{0};
  td::uint64 applied_shard{0};

  MetricSet collect() const {
    MetricSet result;
    result.families.push_back(MetricFamily::make_scalar("mempool_ext_messages", "gauge", pending_ext_messages));
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
    return result;
  }

 private:
  static constexpr auto admission_outcome_names_ = std::to_array<std::string_view>({
      "accepted",
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
