#include <functional>

#include "td/utils/ScopeGuard.h"

#include "core-health.h"
#include "metrics-collectors.h"

namespace tos::metrics {

namespace {
struct TimedMetricResult {
  double callback_completed_at = 0;
  td::Result<MetricSet> result;
};
}  // namespace

void CollectorWrapper::collect(MetricsPromise P) {
  if (registration_overflow_) {
    P.set_error(td::Status::Error("Metrics collector registry capacity exceeded"));
    return;
  }
  if (collection_inflight_) {
    P.set_error(td::Status::Error("Metrics collection is busy"));
    return;
  }
  collection_inflight_ = true;
  connect(std::move(P), collect_coro());
}

td::actor::Task<MetricSet> CollectorWrapper::collect_coro() {
  SCOPE_EXIT {
    collection_inflight_ = false;
  };
  MetricSet whole_set = {};
  td::Status error;
  const bool publish_source_metadata = health::enabled.load(std::memory_order_relaxed);
  // Freeze the count, not iterators: registration may grow the vector while suspended.
  const auto count = source_collectors_.size();
  for (size_t base = 0; base < count; base += 8) {
    std::vector<td::actor::StartedTask<TimedMetricResult>> futures;
    futures.reserve(8);
    for (size_t i = base; i < std::min(base + 8, count); ++i) {
      auto [future, promise] = td::actor::StartedTask<TimedMetricResult>::make_bridge();
      source_collectors_[i].collect(td::PromiseCreator::lambda(
          [promise = std::move(promise), publish_source_metadata](td::Result<MetricSet> result) mutable {
            promise.set_value(
                TimedMetricResult{.callback_completed_at = publish_source_metadata ? td::Timestamp::now().at_unix() : 0,
                                  .result = std::move(result)});
          }));
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
        if (error.is_ok()) {
          error = result.move_as_error();
        }
      } else {
        if (publish_source_metadata) {
          source.last_success_at = timed.callback_completed_at;
          source.last_result_ok = true;
        }
        whole_set = std::move(whole_set).join(result.move_as_ok());
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
    whole_set = std::move(whole_set).join(std::move(metadata));
  }
  co_return whole_set;
}

LambdaGauge::LambdaGauge(std::string metric_name, SamplerLambda lambda, std::optional<std::string> help)
    : metric_name_(std::move(metric_name)), lambda_(std::move(lambda)), help_(std::move(help)) {
}

MetricSet LambdaGauge::collect() {
  auto metric = Metric{.suffix = "", .label_set = {}, .samples = lambda_()};
  auto family = MetricFamily{.name = metric_name_, .type = "gauge", .help = help_, .metrics = {std::move(metric)}};
  return MetricSet{.families = {std::move(family)}};
}

LambdaCounter::LambdaCounter(std::string metric_name, SamplerLambda lambda, std::optional<std::string> help)
    : metric_name_(std::move(metric_name)), lambda_(std::move(lambda)), help_(std::move(help)) {
}

MetricSet LambdaCounter::collect() {
  // TODO(avevad): check monotonic increase (as required for a counter)
  auto metric = Metric{.suffix = "", .label_set = {}, .samples = lambda_()};
  auto family = MetricFamily{.name = metric_name_, .type = "counter", .help = help_, .metrics = {std::move(metric)}};
  return MetricSet{.families = {std::move(family)}};
}

LambdaCollector::LambdaCollector(CollectorLambda lambda) : lambda_(std::move(lambda)) {
}

MetricSet LambdaCollector::collect() {
  return {.families = lambda_()};
}

MultiCollector::MultiCollector(std::string prefix) : prefix_(std::move(prefix)) {
}

void MultiCollector::collect(MetricsPromise P) {
  if (collection_inflight_ || registration_overflow_) {
    P.set_error(td::Status::Error("Metrics collection busy or registry incomplete"));
    return;
  }
  collection_inflight_ = true;
  MetricSet whole_set = {};
  for (auto &c : sync_collectors_) {
    auto metric_set = c->collect();
    whole_set = std::move(whole_set).join(std::move(metric_set));
  }
  async_collector_->collect(
      [self = actor_id(this), whole_set = std::move(whole_set), P = std::move(P)](td::Result<MetricSet> R) mutable {
        td::actor::send_closure(self, &MultiCollector::collection_completed, std::move(whole_set), std::move(P),
                                std::move(R));
      });
}

void MultiCollector::collection_completed(MetricSet whole_set, MetricsPromise promise, td::Result<MetricSet> result) {
  collection_inflight_ = false;
  if (result.is_error()) {
    promise.set_error(result.move_as_error());
    return;
  }
  promise.set_value(std::move(whole_set).join(result.move_as_ok()).wrap(prefix_));
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
