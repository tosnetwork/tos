#include <algorithm>
#include <functional>

#include "td/utils/ScopeGuard.h"

#include "core-health.h"
#include "metrics-collectors.h"

namespace tos::metrics {

namespace {
td::Result<MetricSet> join_with_budget(MetricSet whole, MetricSet child, const CollectionBudget &budget) {
  if (budget.bounded) {
    if (budget.expired()) return td::Status::Error("Native collection total deadline expired");
    auto remaining = budget.max_resident_bytes;
    for (const auto resident : {whole.resident_bytes(), child.resident_bytes()}) {
      if (resident > remaining) return td::Status::Error("Native collection resident budget exceeded");
      remaining -= resident;
    }
    if (whole.families.size() > budget.max_families || child.families.size() > budget.max_families - whole.families.size())
      return td::Status::Error("Native collection family capacity exceeded");
  }
  auto result = std::move(whole).join(std::move(child));
  if (budget.bounded && result.resident_bytes() > budget.max_resident_bytes)
    return td::Status::Error("Native joined resident budget exceeded");
  return result;
}

struct TimedMetricResult {
  double callback_completed_at = 0;
  td::Result<MetricSet> result;
};
}  // namespace

MetricSet shed_families(const std::vector<CollectionShed> &sheds) {
  auto shed = MetricFamily{.name = kShedFamily,
                           .type = "gauge",
                           .help = "One per collector refused before it ran in this bounded collection; the result is partial.",
                           .metrics = {}};
  for (const auto &item : sheds) {
    auto scalar = MetricFamily::make_scalar("unused", "gauge", 1)
                      .label(LabelSet{{{"source", item.source}, {"reason", item.reason}}});
    shed.metrics.push_back(std::move(scalar.metrics.front()));
  }
  MetricSet set{};
  if (!sheds.empty()) {
    set.families.push_back(std::move(shed));
  }
  return set;
}

void CollectorWrapper::collect(MetricsPromise P) { collect_with_budget(std::move(P), {}); }

void CollectorWrapper::collect_with_budget(MetricsPromise P, CollectionBudget budget) {
  if (registration_overflow_) {
    P.set_error(td::Status::Error("Metrics collector registry capacity exceeded"));
    return;
  }
  if (collection_inflight_) {
    P.set_error(td::Status::Error("Metrics collection is busy"));
    return;
  }
  collection_inflight_ = true;
  connect(std::move(P), collect_coro(budget));
}

td::actor::Task<MetricSet> CollectorWrapper::collect_coro(CollectionBudget budget) {
  SCOPE_EXIT {
    collection_inflight_ = false;
  };
  MetricSet whole_set = {};
  td::Status error;
  std::vector<CollectionShed> sheds;
  const bool publish_source_metadata = health::enabled.load(std::memory_order_relaxed);
  // Freeze the count, not iterators: registration may grow the vector while suspended.
  const auto count = source_collectors_.size();
  const size_t batch = budget.bounded ? 1 : 8;
  for (size_t base = 0; base < count; base += batch) {
    if (budget.expired()) co_return td::Status::Error("Native collection total deadline expired before child start");
    std::vector<td::actor::StartedTask<TimedMetricResult>> futures;
    futures.reserve(8);
    for (size_t i = base; i < std::min(base + batch, count); ++i) {
      auto child_budget = budget;
      if (budget.bounded) {
        const auto parent = whole_set.resident_bytes();
        if (parent >= child_budget.max_resident_bytes || whole_set.families.size() >= child_budget.max_families)
          co_return td::Status::Error("Native remaining child budget exhausted before start");
        child_budget.max_resident_bytes -= parent;
        child_budget.max_families -= whole_set.families.size();
      }
      auto [future, promise] = td::actor::StartedTask<TimedMetricResult>::make_bridge();
      source_collectors_[i].collect(td::PromiseCreator::lambda(
          [promise = std::move(promise), publish_source_metadata](td::Result<MetricSet> result) mutable {
            promise.set_value(
                TimedMetricResult{.callback_completed_at = publish_source_metadata ? td::Timestamp::now().at_unix() : 0,
                                  .result = std::move(result)});
          }), child_budget);
      futures.push_back(std::move(future));
    }
    // Drain the entire started batch, including on error. Dropping siblings would
    // report completion while their actor work still owns the source lease.
    for (size_t offset = 0; offset < futures.size(); ++offset) {
      auto timed = co_await std::move(futures[offset]);
      auto &source = source_collectors_[base + offset];
      if (publish_source_metadata) {
        source.last_completed_at = timed.callback_completed_at;
      }
      auto result = std::move(timed.result);
      if (result.is_error()) {
        if (publish_source_metadata) {
          ++source.failures;
          source.last_result_ok = false;
        }
        // A shed is a child refused before it ran, not a failed child: the
        // collection goes on and the refusal is published with its reason.
        if (const auto reason = shed_reason_of(result.error())) {
          sheds.push_back({source.source_id, *reason});
        } else if (error.is_ok()) {
          error = result.move_as_error();
        }
      } else {
        if (publish_source_metadata) {
          source.last_success_at = timed.callback_completed_at;
          source.last_result_ok = true;
        }
        auto joined = join_with_budget(std::move(whole_set), result.move_as_ok(), budget);
        if (joined.is_error()) {
          if (error.is_ok()) error = joined.move_as_error();
          if (publish_source_metadata) { ++source.failures; source.last_result_ok = false; }
        } else { whole_set = joined.move_as_ok(); }
      }
    }
    if (error.is_error()) {
      co_return std::move(error);
    }
    co_await td::actor::yield_on_current();
  }
  if (publish_source_metadata) {
    auto completed = MetricFamily{.name = "health_source_collection_completed_timestamp_seconds",
                                  .type = "gauge",
                                  .help = "Publisher callback completion time; not underlying observation time.",
                                  .metrics = {}};
    auto succeeded = MetricFamily{.name = "health_source_last_success_timestamp_seconds",
                                  .type = "gauge",
                                  .help = "Publisher callback success time; not underlying observation time.",
                                  .metrics = {}};
    auto usable = MetricFamily{.name = "health_source_usable",
                               .type = "gauge",
                               .help = "One means collector callback succeeded; not verified observation freshness.",
                               .metrics = {}};
    auto failures =
        MetricFamily{.name = "health_source_failures_total", .type = "counter", .help = std::nullopt, .metrics = {}};
    auto observed = MetricFamily{.name = "health_source_observed_timestamp_available",
                                 .type = "gauge",
                                 .help = "Zero: the collector callback does not expose source observation time.",
                                 .metrics = {}};
    for (const auto &source : source_collectors_) {
      const auto labels = LabelSet{{{"source", source.source_id}}};
      auto add = [&](MetricFamily &family, double value) {
        auto scalar = MetricFamily::make_scalar("unused", family.type.value(), value).label(labels);
        family.metrics.push_back(std::move(scalar.metrics.front()));
      };
      add(completed, source.last_completed_at);
      add(succeeded, source.last_success_at);
      add(usable, source.last_result_ok ? 1 : 0);
      add(failures, static_cast<double>(source.failures));
      add(observed, 0);
    }
    MetricSet metadata{.families = {std::move(completed), std::move(succeeded), std::move(usable), std::move(failures),
                                    std::move(observed)}};
    auto joined = join_with_budget(std::move(whole_set), std::move(metadata), budget);
    if (joined.is_error()) co_return joined.move_as_error();
    whole_set = joined.move_as_ok();
  }
  if (!sheds.empty()) {
    auto joined = join_with_budget(std::move(whole_set), shed_families(sheds), budget);
    if (joined.is_error()) co_return joined.move_as_error();
    whole_set = joined.move_as_ok();
  }
  co_return whole_set;
}

LambdaGauge::LambdaGauge(std::string metric_name, SamplerLambda lambda, std::optional<std::string> help,
        std::optional<CollectionReservation> reservation)
    : metric_name_(std::move(metric_name)), lambda_(std::move(lambda)), help_(std::move(help)), reservation_(reservation) {
}

MetricSet LambdaGauge::collect() {
  auto metric = Metric{.suffix = "", .label_set = {}, .samples = lambda_()};
  auto family = MetricFamily{.name = metric_name_, .type = "gauge", .help = help_, .metrics = {std::move(metric)}};
  return MetricSet{.families = {std::move(family)}};
}

LambdaCounter::LambdaCounter(std::string metric_name, SamplerLambda lambda, std::optional<std::string> help,
        std::optional<CollectionReservation> reservation)
    : metric_name_(std::move(metric_name)), lambda_(std::move(lambda)), help_(std::move(help)), reservation_(reservation) {
}

MetricSet LambdaCounter::collect() {
  // TODO(avevad): check monotonic increase (as required for a counter)
  auto metric = Metric{.suffix = "", .label_set = {}, .samples = lambda_()};
  auto family = MetricFamily{.name = metric_name_, .type = "counter", .help = help_, .metrics = {std::move(metric)}};
  return MetricSet{.families = {std::move(family)}};
}

LambdaCollector::LambdaCollector(CollectorLambda lambda, std::optional<CollectionReservation> reservation)
    : lambda_(std::move(lambda)), reservation_(reservation) {
}

MetricSet LambdaCollector::collect() {
  return {.families = lambda_()};
}

MultiCollector::MultiCollector(std::string prefix) : prefix_(std::move(prefix)) {
}

void MultiCollector::collect(MetricsPromise P) { collect_with_budget(std::move(P), {}); }

void MultiCollector::collect_with_budget(MetricsPromise P, CollectionBudget budget) {
  if (collection_inflight_ || registration_overflow_) {
    P.set_error(td::Status::Error("Metrics collection busy or registry incomplete"));
    return;
  }
  collection_inflight_ = true;
  MetricSet whole_set = {};
  std::vector<CollectionShed> sheds;
  for (std::size_t index = 0; index < sync_collectors_.size(); ++index) {
    auto &c = sync_collectors_[index];
    if (budget.expired()) { collection_inflight_ = false; P.set_error(td::Status::Error("Native total deadline expired before sync child")); return; }
    if (budget.bounded) {
      // Budget before allocation: the child declares what it will build and
      // is refused, not run, when it cannot or when it does not fit what
      // remains. The join below still measures what it actually built.
      const auto declared = c->reservation();
      const char *reason = nullptr;
      if (!declared) {
        reason = kShedUnbudgeted;
      } else {
        auto remaining = budget;
        const auto parent = whole_set.resident_bytes();
        remaining.max_resident_bytes = parent >= remaining.max_resident_bytes ? 0 : remaining.max_resident_bytes - parent;
        remaining.max_families = whole_set.families.size() >= remaining.max_families ? 0 : remaining.max_families - whole_set.families.size();
        if (!remaining.admits(*declared)) reason = kShedOverBudget;
      }
      if (reason != nullptr) {
        sheds.push_back({PSTRING() << "sync_collector_" << index, reason});
        continue;
      }
    }
    auto metric_set = c->collect();
    auto joined = join_with_budget(std::move(whole_set), std::move(metric_set), budget);
    if (joined.is_error()) { collection_inflight_ = false; P.set_error(joined.move_as_error()); return; }
    whole_set = joined.move_as_ok();
  }
  auto child_budget = budget;
  if (budget.bounded) {
    const auto parent = whole_set.resident_bytes();
    if (parent > child_budget.max_resident_bytes || whole_set.families.size() > child_budget.max_families) {
      collection_inflight_ = false; P.set_error(td::Status::Error("Native parent resident budget exceeded")); return;
    }
    child_budget.max_resident_bytes -= parent;
    child_budget.max_families -= whole_set.families.size();
  }
  async_collector_->collect_with_budget(
      [self = actor_id(this), whole_set = std::move(whole_set), P = std::move(P), budget,
       sheds = std::move(sheds)](td::Result<MetricSet> R) mutable {
        td::actor::send_closure(self, &MultiCollector::collection_completed, std::move(whole_set), std::move(P),
                                std::move(R), budget, std::move(sheds));
      }, child_budget);
}

void MultiCollector::collection_completed(MetricSet whole_set, MetricsPromise promise, td::Result<MetricSet> result,
                                          CollectionBudget budget, std::vector<CollectionShed> sheds) {
  collection_inflight_ = false;
  if (result.is_error()) {
    promise.set_error(result.move_as_error());
    return;
  }
  auto joined = join_with_budget(std::move(whole_set), result.move_as_ok(), budget);
  if (joined.is_error()) { promise.set_error(joined.move_as_error()); return; }
  if (budget.bounded) {
    // Publish the sync-side sheds and one completeness gauge: the result is
    // complete only when neither this level nor any child level shed a
    // collector (a child's sheds arrive as its own shed family).
    auto set = joined.move_as_ok();
    const bool child_shed = std::any_of(set.families.begin(), set.families.end(),
                                        [](const MetricFamily &family) { return family.name == kShedFamily; });
    auto marker = shed_families(sheds);
    marker.families.push_back(MetricFamily::make_scalar(
        kCompleteFamily, "gauge", sheds.empty() && !child_shed ? 1 : 0,
        "One when every collector of this bounded collection ran; zero when any was refused."));
    joined = join_with_budget(std::move(set), std::move(marker), budget);
    if (joined.is_error()) { promise.set_error(joined.move_as_error()); return; }
  }
  auto wrapped = std::move(joined.move_as_ok()).wrap(prefix_);
  if (budget.bounded && wrapped.resident_bytes() > budget.max_resident_bytes) {
    promise.set_error(td::Status::Error("Native wrapped resident budget exceeded")); return;
  }
  promise.set_value(std::move(wrapped));
}

void MultiCollector::add_sync_collector(std::shared_ptr<Collector> collector) {
  if (sync_collectors_.size() >= 256) {
    registration_overflow_ = true;
    return;
  }
  sync_collectors_.push_back(std::move(collector));
}

td::actor::ActorOwn<MultiCollector> MultiCollector::create(std::string prefix) {
  return td::actor::create_actor<MultiCollector>(PSTRING() << "MultiCollector:" << prefix, std::move(prefix));
}

}  // namespace tos::metrics
