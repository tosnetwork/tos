/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "bus.h"
#include "stats.h"

namespace tos::validator::consensus::simplex {

namespace {

class FakeCatchainStatsTag : public tos::stats::Tag {
 public:
  std::string_view name() const override {
    return "fake-catchain";
  }
};

FakeCatchainStatsTag fake_catchain_stats;

class MetricCollectorImpl : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  static bool should_be_spawned(const Bus& bus) {
    return bus.is_validator();
  }

  void start_up() override {
    auto& bus = *owning_bus();
    collector.emplace(stats::MetricCollector{
        bus.session_id,
        bus.local_id->short_id,
        tos::stats::recorder_for(fake_catchain_stats),
    });
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const TraceEvent> event) {
    auto ev = event->event.get();
    using consensus::stats::CollectibleEvent;
    if (auto collectible = dynamic_cast<const CollectibleEvent<consensus::stats::MetricCollector>*>(ev)) {
      collectible->collect_to(*collector);
    } else if (auto collectible = dynamic_cast<const CollectibleEvent<stats::MetricCollector>*>(ev)) {
      collectible->collect_to(*collector);
    }
  }

 private:
  std::optional<stats::MetricCollector> collector;
};

}  // namespace

void MetricCollector::register_in(td::actor::Runtime& runtime) {
  runtime.register_actor<MetricCollectorImpl>("MetricCollector");
}

}  // namespace tos::validator::consensus::simplex
