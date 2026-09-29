#include <atomic>
#include <iostream>
#include <string>

#include "metrics/core-health.h"
#include "metrics/metrics-collectors.h"
#include "td/actor/actor.h"
#include "td/utils/check.h"

namespace {
struct Peak {
  std::atomic<unsigned> active{0};
  std::atomic<unsigned> peak{0};
  void enter() {
    const auto now = active.fetch_add(1) + 1;
    auto old = peak.load();
    while (old < now && !peak.compare_exchange_weak(old, now)) {
    }
  }
  void leave() {
    active.fetch_sub(1);
  }
};
class Child final : public td::actor::Actor, public tos::metrics::AsyncCollector {
 public:
  Child(double delay, Peak *peak) : delay_(delay), peak_(peak) {
  }
  void collect(tos::metrics::MetricsPromise promise) override {
    peak_->enter();
    promise_ = std::move(promise);
    alarm_timestamp() = td::Timestamp::in(delay_);
  }

 private:
  void alarm() override {
    peak_->leave();
    promise_.set_value({});
  }
  double delay_;
  Peak *peak_;
  tos::metrics::MetricsPromise promise_;
};
class Wrapper final : public td::actor::Actor, public tos::metrics::CollectorWrapper {
 public:
  Wrapper(td::actor::ActorId<Child> slow, td::actor::ActorId<Child> fast) {
    add_collector("slow", slow);
    add_collector("fast", fast);
  }
  void run(tos::metrics::MetricsPromise promise) {
    collect(std::move(promise));
  }
};
double sample(const std::string &body, const std::string &source) {
  const auto key = "health_source_collection_completed_timestamp_seconds{source=\"" + source + "\"} ";
  const auto start = body.find(key);
  CHECK(start != std::string::npos);
  return std::stod(body.substr(start + key.size()));
}
class Driver final : public td::actor::Actor {
 public:
  Driver(bool enabled, bool *passed) : enabled_(enabled), passed_(passed) {
  }

 private:
  void finish(td::Result<tos::metrics::MetricSet> result) {
    CHECK(result.is_ok());
    auto body = result.move_as_ok().render();
    if (enabled_) {
      CHECK(sample(body, "fast") < sample(body, "slow"));
      CHECK(body.find("health_source_observed_timestamp_available{source=\"fast\"} 0.000000\n") != std::string::npos);
    } else {
      CHECK(body.find("health_source_") == std::string::npos);
    }
    CHECK(peak_.peak.load() == 2);
    CHECK(peak_.active.load() == 0);
    std::cout << "collector_children_peak=" << peak_.peak.load() << " gate=" << (enabled_ ? "enabled" : "disabled")
              << std::endl;
    *passed_ = true;
    td::actor::SchedulerContext::get().stop();
  }
  void start_up() override {
    slow_ = td::actor::create_actor<Child>("slow", 0.1, &peak_);
    fast_ = td::actor::create_actor<Child>("fast", 0.0, &peak_);
    wrapper_ = td::actor::create_actor<Wrapper>("wrapper", slow_.get(), fast_.get());
    td::actor::send_closure(
        wrapper_.get(), &Wrapper::run,
        td::make_promise([self = actor_id(this)](td::Result<tos::metrics::MetricSet> result) mutable {
          td::actor::send_closure(self, &Driver::finish, std::move(result));
        }));
  }
  bool enabled_;
  bool *passed_;
  Peak peak_;
  td::actor::ActorOwn<Child> slow_, fast_;
  td::actor::ActorOwn<Wrapper> wrapper_;
};
void run(bool enabled) {
  tos::health::enabled.store(enabled, std::memory_order_relaxed);
  bool passed = false;
  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] { driver = td::actor::create_actor<Driver>("driver", enabled, &passed); });
  scheduler.run();
  CHECK(passed);
}
}  // namespace

int main() {
  run(false);
  run(true);
}
