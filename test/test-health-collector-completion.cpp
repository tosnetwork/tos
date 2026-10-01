#include "metrics/metrics-collectors.h"
#include "td/actor/actor.h"
#include "td/utils/check.h"

namespace {
struct State {
  bool slow_entered = false;
  bool slow_completed = false;
  bool first_completed = false;
  bool busy_completed = false;
};
class Child final : public td::actor::Actor, public tos::metrics::AsyncCollector {
 public:
  Child(bool fail, State *state) : fail_(fail), state_(state) {
  }
  void collect(tos::metrics::MetricsPromise promise) override {
    if (fail_) {
      promise.set_error(td::Status::Error("expected child failure"));
      return;
    }
    CHECK(!state_->slow_entered);
    state_->slow_entered = true;
    pending_ = std::move(promise);
  }
  void finish() {
    state_->slow_completed = true;
    pending_.set_value(tos::metrics::MetricSet{});
  }

 private:
  bool fail_;
  State *state_;
  tos::metrics::MetricsPromise pending_;
};
class Wrapper final : public td::actor::Actor, public tos::metrics::CollectorWrapper {
 public:
  Wrapper(td::actor::ActorId<Child> a, td::actor::ActorId<Child> b) {
    add_collector("failure", a);
    add_collector("slow", b);
  }
  void request(tos::metrics::MetricsPromise promise) {
    collect(std::move(promise));
  }
};
class Driver final : public td::actor::Actor {
 public:
  explicit Driver(bool *passed) : passed_(passed) {
  }
  void first(td::Result<tos::metrics::MetricSet> result) {
    CHECK(result.is_error());
    CHECK(result.error().message() == "expected child failure");
    CHECK(state_.slow_completed && state_.busy_completed);
    state_.first_completed = true;
    *passed_ = true;
    td::actor::SchedulerContext::get().stop();
  }
  void busy(td::Result<tos::metrics::MetricSet> result) {
    CHECK(result.is_error());
    CHECK(result.error().message() == "Metrics collection is busy");
    CHECK(!state_.first_completed && !state_.slow_completed);
    state_.busy_completed = true;
    td::actor::send_closure(slow_.get(), &Child::finish);
  }

 private:
  void start_up() override {
    failure_ = td::actor::create_actor<Child>("failure", true, &state_);
    slow_ = td::actor::create_actor<Child>("slow", false, &state_);
    wrapper_ = td::actor::create_actor<Wrapper>("wrapper", failure_.get(), slow_.get());
    td::actor::send_closure(wrapper_.get(), &Wrapper::request,
                            td::make_promise([self = actor_id(this)](td::Result<tos::metrics::MetricSet> result) {
                              td::actor::send_closure(self, &Driver::first, std::move(result));
                            }));
    alarm_timestamp() = td::Timestamp::in(0.05);
  }
  void alarm() override {
    CHECK(!alarm_sent_);
    CHECK(state_.slow_entered && !state_.slow_completed && !state_.first_completed);
    alarm_sent_ = true;
    td::actor::send_closure(wrapper_.get(), &Wrapper::request,
                            td::make_promise([self = actor_id(this)](td::Result<tos::metrics::MetricSet> result) {
                              td::actor::send_closure(self, &Driver::busy, std::move(result));
                            }));
    alarm_timestamp() = td::Timestamp::in(3);  // fail instead of silently hanging
  }
  State state_;
  bool *passed_;
  bool alarm_sent_ = false;
  td::actor::ActorOwn<Child> failure_, slow_;
  td::actor::ActorOwn<Wrapper> wrapper_;
};
}  // namespace
int main() {
  bool passed = false;
  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] { driver = td::actor::create_actor<Driver>("driver", &passed); });
  scheduler.run();
  CHECK(passed);
}
