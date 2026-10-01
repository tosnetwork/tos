#include <cstdio>
#include <cstdlib>
#include <limits>

#include "metrics/native-core-snapshot.h"
#include "metrics/metrics-collectors.h"
#include "td/actor/coro_utils.h"

using namespace tos;
using namespace tos::health;
namespace {
void require(bool condition, const char *message) {
  if (!condition) { std::fprintf(stderr, "C04_PUBLISHER_ASSERTION: %s\n", message); std::exit(1); }
}
std::string mode;
std::array<unsigned, 3> calls{}, completed{};
std::array<std::size_t, 3> received_budget{};
std::array<std::size_t, 3> received_families{};
metrics::MetricSet sample(std::size_t bytes, std::size_t families = 1) {
  metrics::MetricSet result;
  for (std::size_t i = 0; i < families; ++i)
    result.families.push_back(metrics::MetricFamily::make_scalar("sample_" + std::to_string(i), "gauge", 1,
        i == 0 ? std::string(bytes, 'x') : std::string{}));
  return result;
}
void unit() {
  auto &intent = work_stats.results[static_cast<unsigned>(Work::IntentStorage)][static_cast<unsigned>(WorkResult::Success)];
  auto &signed_vote = work_stats.results[static_cast<unsigned>(Work::SignedStorage)][static_cast<unsigned>(WorkResult::Success)];
  auto &intent_complete = work_stats.complete[static_cast<unsigned>(Work::IntentStorage)];
  auto &signed_complete = work_stats.complete[static_cast<unsigned>(Work::SignedStorage)];
  require(!storage_commit_ack_observed(), "storage ack requires both completed database writes");
  intent.store(1);
  require(!storage_commit_ack_observed(), "intent ack alone cannot establish signed vote ack");
  signed_vote.store(1);
  require(storage_commit_ack_observed(), "both complete commit observations establish local ack");
  signed_complete.store(false);
  require(!storage_commit_ack_observed(), "signed write observation gap revokes storage ack capability");
  signed_complete.store(true);
  intent_complete.store(false);
  require(!storage_commit_ack_observed(), "intent write observation gap revokes storage ack capability");
  intent_complete.store(true);
  intent.store(0);
  signed_vote.store(0);
  constexpr std::size_t limit = 1048576;
  auto baseline = sample(0).render_bounded(limit);
  require(baseline.has_value(), "empty padding renders valid complete body");
  const auto padding = limit - baseline->size();
  auto data = sample(padding);
  const auto resident = data.resident_bytes();
  auto boundary = std::move(data).render_bounded(limit);
  require(boundary && boundary->size() == limit && boundary->capacity() == limit,
          "exact one MiB complete body and actual reservation capacity");
  require(!sample(padding + 1).render_bounded(limit), "one extra byte refuses the complete publication");
  auto invalid = sample(0);
  invalid.families[0].metrics[0].samples[0].value = std::numeric_limits<double>::infinity();
  require(!std::move(invalid).render_bounded(limit), "non-finite body refuses without partial output");
  require(remaining_core_publication_bytes({std::numeric_limits<std::size_t>::max()}) == 0,
          "huge allocation term cannot wrap the budget");
  require(remaining_core_publication_bytes({4 * limit - 1, 2}) == 0, "budget addition overflow refuses");
  require(consensus_core_resident_bytes() < 512 * 1024, "actual core/catalog/index layouts below half MiB");
  const auto room = remaining_core_publication_bytes({consensus_core_resident_bytes(), diagnostic_status_response_bytes, limit, 1,
      64 * 1024, resident, 64 * 1024, 320 * 1024, 1});
  require(room >= limit, "derived budget admits worst boundary with actual capacities");
  NativeCorePublisher publisher;
  require(publisher.set_node("v1") && publisher.set_network(std::string(64, 'a')), "fixed publisher identity");
  const OperationSnapshot zero{0, 0, true};
  require(publisher.prepare(1, 10, 1700000000, *boundary, true, zero, zero, true).has_value(), "v2 boundary accepted");
  require(!publisher.prepare(1, 10, 1700000000, std::string(limit + 1, 'x'), true, zero, zero, true), "v2 oversized refusal");
  require(publisher.prepare(1, 10, 1700000000, std::string(limit + 1, 'x'), true, zero, zero).has_value(), "v1 retains two MiB limit");
  std::printf("C04_PUBLISHER_MEMORY core=%zu diagnostic_response_reserve=%zu metric_set=%zu old_metrics=%zu new_metrics=%zu old_typed=65536 consensus=65536 scratch=327680 remaining=%zu total=%zu\n",
      consensus_core_resident_bytes(), diagnostic_status_response_bytes, resident, limit + 1, boundary->capacity() + 1, room,
      4 * limit - room + boundary->capacity() + 1);
}

class Probe : public td::actor::Actor, public metrics::AsyncCollector {
 public:
  Probe(unsigned index, std::size_t bytes, double delay, std::size_t families)
      : index_(index), bytes_(bytes), delay_(delay), families_(families) {}
  void collect(metrics::MetricsPromise promise) override { collect_with_budget(std::move(promise), {}); }
  void collect_with_budget(metrics::MetricsPromise promise, metrics::CollectionBudget budget) override {
    ++calls[index_]; received_budget[index_] = budget.max_resident_bytes;
    received_families[index_] = budget.max_families;
    pending_ = std::move(promise);
    alarm_timestamp() = td::Timestamp::in(delay_);
  }
 private:
  void alarm() override { ++completed[index_]; pending_.set_value(sample(bytes_, families_)); }
  unsigned index_;
  std::size_t bytes_;
  double delay_;
  std::size_t families_;
  metrics::MetricsPromise pending_;
};
class Driver : public td::actor::Actor {
 public:
  td::actor::Task<> run() {
    auto root = metrics::MultiCollector::create("root");
    if (mode == "parent-family")
      td::actor::send_closure(root.get(), &metrics::MultiCollector::add_sync_collector,
          // The sync parent declares its 255 families, so the bounded path
          // admits it and its real size reduces the nested child's allowance.
          metrics::LambdaCollector::make([] { return sample(0, 255).families; },
                                         metrics::CollectionReservation{255 * 256, 255}));
    std::array<metrics::MultiCollector::Own, 3> nested;
    std::array<td::actor::ActorOwn<Probe>, 3> probes;
    for (unsigned i = 0; i < 3; ++i) {
      const auto bytes = mode == "nested" ? (i == 0 ? 400000U : 100000U)
          : mode == "oversize" && i == 0 ? 950000U : 0U;
      const auto delay = mode == "deadline" || mode == "v1" ? 1.2 : 0;
      const auto families = mode == "family" && i == 0 ? 257U
          : mode == "parent-family" && i == 0 ? 2U : 1U;
      probes[i] = td::actor::create_actor<Probe>("probe", i, bytes, delay, families);
      nested[i] = metrics::MultiCollector::create("nested_" + std::to_string(i));
      td::actor::send_closure(nested[i].get(), &metrics::MultiCollector::add_async_collector<Probe>, "probe", probes[i].get());
      td::actor::send_closure(root.get(), &metrics::MultiCollector::add_async_collector<metrics::MultiCollector>,
          "nested_" + std::to_string(i), nested[i].get());
    }
    auto [task, promise] = td::actor::StartedTask<metrics::MetricSet>::make_bridge();
    const auto start = td::Timestamp::now().at();
    metrics::CollectionBudget budget{.bounded = mode != "v1", .deadline = start + 2, .max_resident_bytes = 700000};
    td::actor::send_closure(root.get(), &metrics::MultiCollector::collect_with_budget, std::move(promise), budget);
    auto result = co_await std::move(task).wrap();
    const auto elapsed = td::Timestamp::now().at() - start;
    if (mode == "nested") {
      require(result.is_ok(), "nested bounded collection succeeds within aggregate capacity");
      require(received_budget[1] < received_budget[0] - 390000, "nested second child gets reduced parent allowance");
    } else if (mode == "v1") {
      require(result.is_ok() && calls[2] == 1 && elapsed < 2, "v1 retains parallel batches");
    } else if (mode == "deadline") {
      require(result.is_error() && calls[0] == 1 && calls[1] == 1 && calls[2] == 0 && elapsed >= 2.3,
          "one total deadline drains started child and stops new children");
    } else {
      require(result.is_error() && calls[0] == 1 && calls[1] == 0 && calls[2] == 0,
          "oversized or too-many-family child refuses before subsequent starts");
      if (mode == "parent-family")
        require(received_families[0] == 1, "sync parent's families reduce the nested child allowance");
    }
    for (unsigned i = 0; i < 3; ++i) require(calls[i] == completed[i], "all actually started work drained before completion");
    std::printf("C04_COLLECTION_PASS %s elapsed=%.3f calls=%u,%u,%u budget=%zu,%zu,%zu\n", mode.c_str(), elapsed,
        calls[0], calls[1], calls[2], received_budget[0], received_budget[1], received_budget[2]);
    std::exit(0);
    co_return td::Unit{};
  }
};
}  // namespace
int main(int argc, char **argv) {
  if (argc == 1) { unit(); return 0; }
  mode = argv[1];
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<Driver> driver;
  scheduler.run_in_context([&] { driver = td::actor::create_actor<Driver>("driver"); td::actor::ask(driver, &Driver::run).detach(); });
  while (scheduler.run(1)) {}
  return 1;
}
