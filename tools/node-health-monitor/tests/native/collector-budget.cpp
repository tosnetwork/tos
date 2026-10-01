// Budget before allocation: under a bounded collection a child declares what
// it will build and is refused, not run, when it cannot or when it does not
// fit; the refusal is published as a shed with its reason and the result is
// marked incomplete. Unbounded collections are unchanged.
#include <atomic>
#include <optional>
#include <string>

#include "metrics/metrics-collectors.h"
#include "metrics/tl-traffic-bucket.h"
#include "auto/tl/tos_api.h"
#include "auto/tl/lite_api.h"
#include "quic/health-metrics-policy.h"
#include "td/utils/logging.h"
#include "td/actor/actor.h"
#include "td/utils/check.h"

namespace {
using tos::metrics::CollectionBudget;
using tos::metrics::CollectionReservation;
using tos::metrics::MetricFamily;
using tos::metrics::MetricSet;

struct Counts {
  int declared_sync = 0;
  int undeclared_sync = 0;
  int legacy_async = 0;
  int declared_async = 0;
};

// Allocation hook: `collect` is where the families are built, so a call count
// of zero means nothing was allocated.
class SyncChild final : public tos::metrics::Collector {
 public:
  SyncChild(std::size_t families, bool declare, int *count) : families_(families), declare_(declare), count_(count) {
  }
  std::optional<CollectionReservation> reservation() const override {
    if (!declare_) {
      return std::nullopt;
    }
    return CollectionReservation{families_ * 256, families_};
  }
  MetricSet collect() override {
    ++*count_;
    MetricSet set{};
    for (std::size_t i = 0; i < families_; ++i) {
      set.families.push_back(
          MetricFamily::make_scalar(PSTRING() << (declare_ ? "sync_declared_" : "sync_undeclared_") << i, "gauge", 1));
    }
    return set;
  }

 private:
  std::size_t families_;
  bool declare_;
  int *count_;
};

// A child written before budgets existed: `collect` only.
class LegacyAsync final : public td::actor::Actor, public tos::metrics::AsyncCollector {
 public:
  explicit LegacyAsync(int *count) : count_(count) {
  }
  void collect(tos::metrics::MetricsPromise promise) override {
    ++*count_;
    promise.set_value(MetricSet{{MetricFamily::make_scalar("legacy_async", "gauge", 1)}});
  }

 private:
  int *count_;
};

// A child that declares its reservation and otherwise only implements collect.
class DeclaringAsync final : public td::actor::Actor, public tos::metrics::AsyncCollector {
 public:
  explicit DeclaringAsync(int *count) : count_(count) {
  }
  std::optional<CollectionReservation> reservation() const override {
    return CollectionReservation{512, 1};
  }
  void collect(tos::metrics::MetricsPromise promise) override {
    ++*count_;
    promise.set_value(MetricSet{{MetricFamily::make_scalar("declared_async", "gauge", 1)}});
  }

 private:
  int *count_;
};

// Stand-ins for the production children of the health exporter, declaring
// their reservations with the same helper calls and arguments as the real
// classes (quic/quic-sender.cpp, overlay/overlay-manager.cpp,
// validator-engine/json-rpc-server.cpp), and building what those classes
// build, so a declared bound that understates the real size is caught here.
class QuicStandIn final : public td::actor::Actor, public tos::metrics::AsyncCollector {
 public:
  std::optional<CollectionReservation> reservation() const override {
    if (tos::quic::health_metrics_policy::build_per_path) {
      return std::nullopt;
    }
    return tos::metrics::scalar_families_reservation(8, 32, 0);
  }
  void collect(tos::metrics::MetricsPromise promise) override {
    MetricSet summary{};
    for (const char *name : {"conns", "rx_bytes_total", "tx_bytes_total", "lost_bytes_total", "unacked_bytes",
                             "unsent_bytes", "open_sids", "mean_rtt"}) {
      summary.families.push_back(MetricFamily::make_scalar(name, "gauge", 1));
    }
    promise.set_value(std::move(summary).wrap("summary").wrap("quic"));
  }
};

class OverlayStandIn final : public td::actor::Actor, public tos::metrics::AsyncCollector {
 public:
  OverlayStandIn() {
    // A realistic spread of cells: a handful of named schemas plus the
    // shared unknown cell, in both directions.
    for (td::int32 magic : {tos::tos_api::overlay_broadcast::ID, tos::tos_api::overlay_message::ID,
                           tos::tos_api::overlay_query::ID, tos::lite_api::liteServer_query::ID}) {
      in_.account(magic, 100);
      out_.account(magic, 100);
    }
  }
  std::optional<CollectionReservation> reservation() const override {
    const auto metrics = 2 * (in_.cells() + out_.cells());
    return tos::metrics::traffic_collection_reservation(metrics / 2, 0);
  }
  void collect(tos::metrics::MetricsPromise promise) override {
    promise.set_value(std::move(in_.collect("in")).join(out_.collect("out")));
  }

 private:
  tos::metrics::TlTrafficBucket in_, out_;
};

class JsonRpcStandIn final : public td::actor::Actor, public tos::metrics::AsyncCollector {
 public:
  JsonRpcStandIn() {
    for (const char *method : {"getBlock", "sendMessage", "getAccountState", "runGetMethod"}) {
      requests_->label(method)->add(3);
      errors_->label(method)->add(1);
    }
  }
  std::optional<CollectionReservation> reservation() const override {
    const auto requests = requests_->reservation();
    const auto errors = errors_->reservation();
    if (!requests || !errors) {
      return std::nullopt;
    }
    auto total = tos::metrics::scalar_families_reservation(7, 32, 64);
    total.resident_bytes += requests->resident_bytes + errors->resident_bytes;
    total.families += requests->families + errors->families;
    return total;
  }
  void collect(tos::metrics::MetricsPromise promise) override {
    MetricSet set{};
    for (const char *name : {"jsonrpc_requests_total", "jsonrpc_errors_total", "jsonrpc_active_requests",
                             "jsonrpc_cache_hits_total", "jsonrpc_cache_misses_total", "jsonrpc_cache_entries",
                             "jsonrpc_uptime_seconds"}) {
      set.families.push_back(MetricFamily::make_scalar(name, "counter", 1, "JSON-RPC requests that resulted in errors"));
    }
    set = std::move(set).join(requests_->collect());
    set = std::move(set).join(errors_->collect());
    promise.set_value(std::move(set));
  }

 private:
  tos::metrics::Labeled<std::string, tos::metrics::AtomicCounter<td::uint64>>::Ptr requests_ =
      tos::metrics::Labeled<std::string, tos::metrics::AtomicCounter<td::uint64>>::make(
          "method", "jsonrpc_method_requests_total", std::optional<std::string>("JSON-RPC requests by method"));
  tos::metrics::Labeled<std::string, tos::metrics::AtomicCounter<td::uint64>>::Ptr errors_ =
      tos::metrics::Labeled<std::string, tos::metrics::AtomicCounter<td::uint64>>::make(
          "method", "jsonrpc_method_errors_total", std::optional<std::string>("JSON-RPC errors by method"));
};

// The declared bound must cover what the child actually builds.
template <typename StandIn>
void check_declaration_covers_result(const char *what) {
  StandIn stand_in;
  const auto declared = stand_in.reservation();
  CHECK(declared.has_value());
  MetricSet built;
  stand_in.collect(td::make_promise([&](td::Result<MetricSet> result) { built = result.move_as_ok(); }));
  LOG(INFO) << what << " declared " << declared->resident_bytes << " bytes/" << declared->families
            << " families, built " << built.resident_bytes() << "/" << built.families.size();
  CHECK(declared->families >= built.families.size());
  CHECK(declared->resident_bytes >= built.resident_bytes());
}

const MetricFamily *find(const MetricSet &set, const char *suffix) {
  const std::string want = suffix;
  for (const auto &family : set.families) {
    if (family.name.size() >= want.size() && family.name.compare(family.name.size() - want.size(), want.size(), want) == 0) {
      return &family;
    }
  }
  return nullptr;
}

bool has_shed(const MetricFamily &shed, const char *source, const char *reason) {
  for (const auto &metric : shed.metrics) {
    bool source_ok = false, reason_ok = false;
    for (const auto &label : metric.label_set.labels) {
      source_ok |= label.key == "source" && label.val == source;
      reason_ok |= label.key == "reason" && label.val == reason;
    }
    if (source_ok && reason_ok) {
      return true;
    }
  }
  return false;
}

class Driver final : public td::actor::Actor {
 public:
  explicit Driver(bool *passed) : passed_(passed) {
  }

 private:
  void start_up() override {
    legacy_ = td::actor::create_actor<LegacyAsync>("legacy", &counts_.legacy_async);
    declared_ = td::actor::create_actor<DeclaringAsync>("declared", &counts_.declared_async);
    root_ = tos::metrics::MultiCollector::create("t");
    td::actor::send_closure(root_.get(), &tos::metrics::MultiCollector::add_sync_collector,
                            std::make_shared<SyncChild>(8, true, &counts_.declared_sync));
    td::actor::send_closure(root_.get(), &tos::metrics::MultiCollector::add_sync_collector,
                            std::make_shared<SyncChild>(1, false, &counts_.undeclared_sync));
    td::actor::send_closure(root_.get(), &tos::metrics::MultiCollector::add_async_collector<LegacyAsync>, "legacy",
                            legacy_.get());
    td::actor::send_closure(root_.get(), &tos::metrics::MultiCollector::add_async_collector<DeclaringAsync>,
                            "declared", declared_.get());
    // Bounded, with room for four families: the eight-family sync child does
    // not fit, the undeclared sync child and the legacy async child cannot be
    // bounded, only the declaring async child may run.
    CollectionBudget bounded{.bounded = true,
                             .deadline = td::Timestamp::now().at() + 5,
                             .max_resident_bytes = 1 << 20,
                             .max_families = 4};
    td::actor::send_closure(root_.get(), &tos::metrics::MultiCollector::collect_with_budget,
                            td::make_promise([self = actor_id(this)](td::Result<MetricSet> result) {
                              td::actor::send_closure(self, &Driver::bounded_done, std::move(result));
                            }),
                            bounded);
    alarm_timestamp() = td::Timestamp::in(5);  // fail instead of hanging
  }
  void bounded_done(td::Result<MetricSet> result) {
    CHECK(result.is_ok());
    const auto set = result.move_as_ok();
    // Nothing a refused child would have built was built.
    CHECK(counts_.declared_sync == 0);
    CHECK(counts_.undeclared_sync == 0);
    CHECK(counts_.legacy_async == 0);
    CHECK(counts_.declared_async == 1);
    CHECK(find(set, "declared_async") != nullptr);
    CHECK(find(set, "legacy_async") == nullptr);
    CHECK(find(set, "sync_declared_0") == nullptr);
    CHECK(find(set, "sync_undeclared_0") == nullptr);
    // The refusals are published with their reasons, and the result says it
    // is incomplete.
    const auto *sync_shed = find(set, "health_collection_shed");
    CHECK(sync_shed != nullptr);
    CHECK(has_shed(*sync_shed, "sync_collector_0", tos::metrics::kShedOverBudget));
    CHECK(has_shed(*sync_shed, "sync_collector_1", tos::metrics::kShedUnbudgeted));
    bool legacy_shed = false;
    for (const auto &family : set.families) {
      if (family.name.size() >= 22 && family.name.find("health_collection_shed") != std::string::npos) {
        legacy_shed |= has_shed(family, "legacy", tos::metrics::kShedUnbudgeted);
      }
    }
    CHECK(legacy_shed);
    const auto *complete = find(set, "health_collection_complete");
    CHECK(complete != nullptr && complete->metrics.size() == 1 && complete->metrics[0].samples.size() == 1);
    CHECK(complete->metrics[0].samples[0].value == 0);
    // Unbounded: everything runs exactly as before, and no shed or
    // completeness family is added.
    td::actor::send_closure(root_.get(), &tos::metrics::MultiCollector::collect_with_budget,
                            td::make_promise([self = actor_id(this)](td::Result<MetricSet> result) {
                              td::actor::send_closure(self, &Driver::unbounded_done, std::move(result));
                            }),
                            CollectionBudget{});
  }
  void unbounded_done(td::Result<MetricSet> result) {
    CHECK(result.is_ok());
    const auto set = result.move_as_ok();
    CHECK(counts_.declared_sync == 1);
    CHECK(counts_.undeclared_sync == 1);
    CHECK(counts_.legacy_async == 1);
    CHECK(counts_.declared_async == 2);
    CHECK(find(set, "legacy_async") != nullptr);
    CHECK(find(set, "sync_declared_7") != nullptr);
    CHECK(find(set, "sync_undeclared_0") != nullptr);
    CHECK(find(set, "health_collection_shed") == nullptr);
    CHECK(find(set, "health_collection_complete") == nullptr);
    // Bounded with room for everything that can declare itself: the two
    // declared children run and the two that cannot are still refused, so the
    // result is honest about being partial.
    CollectionBudget roomy{.bounded = true,
                           .deadline = td::Timestamp::now().at() + 5,
                           .max_resident_bytes = 1 << 20,
                           .max_families = 64};
    td::actor::send_closure(root_.get(), &tos::metrics::MultiCollector::collect_with_budget,
                            td::make_promise([self = actor_id(this)](td::Result<MetricSet> result) {
                              td::actor::send_closure(self, &Driver::roomy_done, std::move(result));
                            }),
                            roomy);
  }
  void roomy_done(td::Result<MetricSet> result) {
    CHECK(result.is_ok());
    const auto set = result.move_as_ok();
    CHECK(counts_.declared_sync == 2);
    CHECK(counts_.undeclared_sync == 1);
    CHECK(counts_.legacy_async == 1);
    CHECK(find(set, "sync_declared_7") != nullptr);
    CHECK(find(set, "sync_undeclared_0") == nullptr);
    const auto *complete = find(set, "health_collection_complete");
    CHECK(complete != nullptr && complete->metrics[0].samples[0].value == 0);
    // The production children of the health exporter, as stand-ins with the
    // same declared reservations, under the exporter's own bounded budget
    // (default family cap, the scratch allowance the exporter reserves):
    // every one runs and the collection is complete.
    production_ = tos::metrics::MultiCollector::create("tos");
    quic_ = td::actor::create_actor<QuicStandIn>("quic");
    overlays_ = td::actor::create_actor<OverlayStandIn>("overlays");
    jsonrpc_ = td::actor::create_actor<JsonRpcStandIn>("jsonrpc");
    td::actor::send_closure(production_.get(), &tos::metrics::MultiCollector::add_async_collector<QuicStandIn>, "quic",
                            quic_.get());
    td::actor::send_closure(production_.get(), &tos::metrics::MultiCollector::add_async_collector<OverlayStandIn>,
                            "overlays", overlays_.get());
    td::actor::send_closure(production_.get(), &tos::metrics::MultiCollector::add_async_collector<JsonRpcStandIn>,
                            "jsonrpc", jsonrpc_.get());
    CollectionBudget exporter_like{.bounded = true,
                                   .deadline = td::Timestamp::now().at() + 5,
                                   .max_resident_bytes = 320 * 1024};
    td::actor::send_closure(production_.get(), &tos::metrics::MultiCollector::collect_with_budget,
                            td::make_promise([self = actor_id(this)](td::Result<MetricSet> result) {
                              td::actor::send_closure(self, &Driver::production_done, std::move(result));
                            }),
                            exporter_like);
  }
  void production_done(td::Result<MetricSet> result) {
    CHECK(result.is_ok());
    const auto set = result.move_as_ok();
    CHECK(find(set, "health_collection_shed") == nullptr);
    const auto *complete = find(set, "health_collection_complete");
    CHECK(complete != nullptr && complete->metrics[0].samples[0].value == 1);
    CHECK(find(set, "quic_summary_conns") != nullptr);
    CHECK(find(set, "overlay_broadcast_bytes_total") != nullptr);
    CHECK(find(set, "jsonrpc_method_requests_total") != nullptr);
    *passed_ = true;
    td::actor::SchedulerContext::get().stop();
  }
  void alarm() override {
    CHECK(false && "collection did not complete");
  }
  Counts counts_;
  bool *passed_;
  td::actor::ActorOwn<LegacyAsync> legacy_;
  td::actor::ActorOwn<DeclaringAsync> declared_;
  td::actor::ActorOwn<tos::metrics::MultiCollector> root_;
  td::actor::ActorOwn<tos::metrics::MultiCollector> production_;
  td::actor::ActorOwn<QuicStandIn> quic_;
  td::actor::ActorOwn<OverlayStandIn> overlays_;
  td::actor::ActorOwn<JsonRpcStandIn> jsonrpc_;
};
}  // namespace

void check_traffic_growth_before_render() {
  tos::metrics::TlTrafficBucket in, out;
  const auto initial = tos::metrics::traffic_collection_reservation(in.cells() + out.cells(), 0);
  CHECK(initial.has_value());
  CollectionBudget budget{.bounded = true, .deadline = td::Timestamp::now().at() + 5,
                         .max_resident_bytes = initial->resident_bytes, .max_families = 4};
  CHECK(tos::metrics::collect_traffic_with_budget(in, out, 0, budget).is_ok());
  for (const auto magic : {tos::tos_api::overlay_broadcast::ID, tos::tos_api::overlay_broadcastFec::ID,
                           tos::tos_api::overlay_message::ID, tos::tos_api::overlay_query::ID,
                           tos::tos_api::overlay_certificate::ID, tos::lite_api::liteServer_query::ID}) {
    in.account(magic, 100); out.account(magic, 100);
  }
  auto refused = tos::metrics::collect_traffic_with_budget(in, out, 0, budget);
  CHECK(refused.is_error());
  CHECK(tos::metrics::shed_reason_of(refused.error()) == tos::metrics::kShedOverBudget);
  budget.max_resident_bytes = 1024 * 1024;
  auto result = tos::metrics::collect_traffic_with_budget(in, out, 0, budget);
  CHECK(result.is_ok());
  CHECK(result.ok().resident_bytes() > initial->resident_bytes);
  auto fanout = tos::metrics::collect_traffic_with_budget(in, out, tos::metrics::kTrafficDrainLimit + 1, budget);
  CHECK(fanout.is_error());
  budget.bounded = false;
  CHECK(tos::metrics::collect_traffic_with_budget(in, out, tos::metrics::kTrafficDrainLimit + 1, budget).is_ok());
}

int main() {
  check_traffic_growth_before_render();
  check_declaration_covers_result<QuicStandIn>("quic");
  check_declaration_covers_result<OverlayStandIn>("overlays");
  check_declaration_covers_result<JsonRpcStandIn>("jsonrpc");
  bool passed = false;
  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] { driver = td::actor::create_actor<Driver>("driver", &passed); });
  scheduler.run();
  CHECK(passed);
  return 0;
}
