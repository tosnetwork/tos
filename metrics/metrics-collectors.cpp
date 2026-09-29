#include <functional>

#include "td/utils/ScopeGuard.h"

#include "metrics-collectors.h"

namespace tos::metrics {

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
  // Freeze the count, not iterators: registration may grow the vector while suspended.
  const auto count = collector_closures_.size();
  for (size_t base = 0; base < count; base += 8) {
    std::vector<td::actor::StartedTask<MetricSet>> futures;
    futures.reserve(8);
    for (size_t i = base; i < std::min(base + 8, count); ++i) {
      auto [future, promise] = td::actor::StartedTask<MetricSet>::make_bridge();
      collector_closures_[i](std::move(promise));
      futures.push_back(std::move(future));
    }
    // Drain the entire started batch, including on error. Dropping siblings would
    // report completion while their actor work still owns the source lease.
    for (auto &future : futures) {
      auto result = co_await std::move(future).wrap();
      if (result.is_error()) {
        if (error.is_ok()) {
          error = result.move_as_error();
        }
      } else {
        whole_set = std::move(whole_set).join(result.move_as_ok());
      }
    }
    if (error.is_error()) {
      co_return std::move(error);
    }
    co_await td::actor::yield_on_current();
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
