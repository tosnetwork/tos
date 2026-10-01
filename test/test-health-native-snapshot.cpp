#include <algorithm>
#include <iostream>
#include <limits>

#include "metrics/core-health.h"
#include "metrics/native-core-snapshot.h"
#include "metrics/prometheus-exporter.h"
#include "td/actor/actor.h"
#include "td/utils/check.h"
#include "td/utils/JsonBuilder.h"
namespace {
class Fixture final : public td::actor::Actor, public tos::metrics::AsyncCollector {
 public:
  Fixture(std::string mode, std::size_t padding, std::string metric_name = "fixture_calls")
      : mode_(std::move(mode)), padding_(padding), metric_name_(std::move(metric_name)) {
  }
  void collect(tos::metrics::MetricsPromise promise) override {
    ++calls_;
    std::cout << "COLLECT " << calls_ << std::endl;
    CHECK(active_ == 0);
    ++active_;
    peak_ = std::max(peak_, active_);
    if (mode_ == "lease")
      std::cout << "SOURCE_WORK ACTIVE " << active_ << " PEAK " << peak_ << std::endl;
    if (mode_ == "error") {
      --active_;
      promise.set_error(td::Status::Error("synthetic collector error"));
      return;
    }
    pending_ = std::move(promise);
    double delay = 0;
    if (mode_ == "slow")
      delay = 3.5;
    if (mode_ == "lease" && calls_ > 1)
      delay = 16.5;
    if (mode_ == "disconnect" || mode_ == "concurrent")
      delay = 1.0;
    alarm_timestamp() = td::Timestamp::in(delay);
  }

 private:
  void alarm() override {
    CHECK(active_ == 1);
    --active_;
    tos::metrics::MetricSet set;
    set.families.push_back(tos::metrics::MetricFamily::make_scalar(metric_name_, "counter", calls_));
    if (mode_ == "boundary") {
      std::size_t remaining = padding_;
      std::size_t part = 0;
      while (remaining != 0) {
        const auto name = "fixture_padding_" + std::to_string(part++);
        auto family = tos::metrics::MetricFamily::make_scalar(name, "gauge", 1, std::string{});
        const auto overhead = tos::metrics::MetricFamily(family).render().size();
        if (remaining < overhead) {
          CHECK(set.families.size() > 1);
          set.families.back().help->append(remaining, 'x');
          remaining = 0;
          continue;
        }
        const auto content = std::min<std::size_t>(60000, remaining - overhead);
        family.help->assign(content, 'x');
        remaining -= overhead + content;
        set.families.push_back(std::move(family));
      }
    }
    pending_.set_value(std::move(set));
    if (mode_ == "lease")
      std::cout << "COMPLETE " << calls_ << std::endl
                << "SOURCE_WORK ACTIVE " << active_ << " PEAK " << peak_ << std::endl;
  }
  std::string mode_;
  std::size_t padding_ = 0;
  std::string metric_name_;
  unsigned calls_ = 0;
  unsigned active_ = 0;
  unsigned peak_ = 0;
  tos::metrics::MetricsPromise pending_;
};
void unit() {
  using namespace tos::health;
  std::string expected;
  for (int i = 0; i < 32; ++i)
    expected += "ab";
  CHECK(network_identity(std::string(32, char(0xab))) == expected);
  CHECK(network_identity("short").empty());
  NativeCorePublisher publisher;
  OperationSnapshot sign{std::numeric_limits<std::uint64_t>::max(), 9007199254740993ULL, true};
  OperationSnapshot verify{0, 0, true};
  CHECK(!publisher.prepare(1, 10, 1700000000, "# EOF\n", true, sign, verify));
  CHECK(!publisher.set_node("BAD"));
  CHECK(publisher.set_node("v1"));
  CHECK(!publisher.set_node("v2"));
  CHECK(!publisher.set_network("bad"));
  CHECK(publisher.set_network(std::string(64, 'a')));
  auto value =
      publisher.prepare(std::numeric_limits<std::uint64_t>::max(), 10, 1700000000, "# EOF\n", true, sign, verify);
  CHECK(value);
  auto body = value->read(10);
  CHECK(body);
  CHECK(body->find("\"generation\":\"18446744073709551615\"") != std::string::npos);
  CHECK(body->find("\"failed\":\"9007199254740993\"") != std::string::npos);
  CHECK(value->read(40));
  CHECK(!value->read(40.001));
  CHECK(!value->read(9));
  CHECK(!value->read(std::numeric_limits<double>::quiet_NaN()));
  CHECK(value->read(10) == body);
  CHECK(!publisher.prepare(0, 10, 1700000000, "# EOF\n", true, sign, verify));
  CHECK(!publisher.prepare(1, 10, 1700000000, std::string(2097153, 'x'), true, sign, verify));
  auto disabled = publisher.prepare(1, 10, 1700000000, "# EOF\n", false, sign, verify);
  CHECK(disabled && disabled->read(10)->find("\"pq_sign\":null") != std::string::npos);
  // v3 without a published chain anchor still publishes a partial snapshot.
  ConsensusPublication consensus{"{\"synthetic\":true}", true};
  auto v3 = publisher.prepare(1, 10, 1700000000, "# EOF\n", true, sign, verify, true, &consensus, true);
  CHECK(v3);
  auto v3_body = v3->read(10);
  CHECK(v3_body);
  std::cout << "V3_BODY " << *v3_body << std::endl;
  CHECK(v3_body->find("\"source_version\":\"native-core-v3\"") != std::string::npos);
  CHECK(v3_body->find("\"chain\":null") != std::string::npos);
  CHECK(v3_body->find("\"instrumentation_complete\":false") != std::string::npos);
  CHECK(v3_body->find("\"chain_anchors\"") != std::string::npos);
  CHECK(!publisher.prepare(1, 10, 1700000000, "# EOF\n", true, sign, verify, false, nullptr, true));
  // v3 with a fresh published chain anchor: the body must be well-formed JSON
  // carrying both anchor clocks, and the snapshot becomes complete.
  ChainAnchorSnapshot anchor;
  for (std::size_t i = 0; i < 32; ++i) {
    anchor.network_hash[i] = 0xaa;
    anchor.applied.file_hash[i] = static_cast<std::uint8_t>(i + 1);
    anchor.applied.root_hash[i] = static_cast<std::uint8_t>(0x40 + i);
  }
  anchor.applied.seqno = 17166;
  anchor.applied_advanced_unix_seconds = 1700000000;
  anchor.observed_unix_seconds = 1700000000;
  anchor.key_block_seqno = 17000;
  anchor.key_block_unix_seconds = 1699990000;
  chain_anchor_state.publish(anchor);
  auto anchored = publisher.prepare(2, 10, 1700000000, "# EOF\n", true, sign, verify, true, &consensus, true);
  CHECK(anchored);
  auto anchored_body = anchored->read(10);
  CHECK(anchored_body);
  std::string parse_copy = *anchored_body;
  CHECK(td::json_decode(td::MutableSlice(parse_copy)).is_ok());
  CHECK(anchored_body->find("\"applied_advanced_unix_seconds\":\"1700000000\",\"key_block\":") != std::string::npos);
  CHECK(anchored_body->find(",\"observed_unix_seconds\":\"1700000000\",\"served\":") != std::string::npos);
  CHECK(anchored_body->find("\"seqno\":17166") != std::string::npos);
  CHECK(anchored_body->find("\"key_block\":{\"seqno\":17000,\"unix_seconds\":\"1699990000\"}") != std::string::npos);
  // Anchored but without node state: still partial, the three fields named.
  CHECK(anchored_body->find("\"instrumentation_complete\":false") != std::string::npos);
  CHECK(anchored_body->find("\"missing_fields\":[\"local_duties\"") != std::string::npos);
  // A halted chain keeps its anchor: the sample is still refreshed by the
  // publisher, only the applied-advance clock is old. Consumers derive the
  // stall age from the two clocks, so the anchor must stay attached.
  anchor.applied_advanced_unix_seconds = 1700000000 - 600;
  anchor.observed_unix_seconds = 1700000000;
  chain_anchor_state.publish(anchor);
  auto halted = publisher.prepare(3, 10, 1700000005, "# EOF\n", true, sign, verify, true, &consensus, true);
  CHECK(halted);
  auto halted_body = halted->read(10);
  CHECK(halted_body);
  CHECK(halted_body->find("\"applied_advanced_unix_seconds\":\"1699999400\",\"key_block\":") != std::string::npos);
  CHECK(halted_body->find(",\"observed_unix_seconds\":\"1700000000\",\"served\":") != std::string::npos);
  CHECK(halted_body->find("\"instrumentation_complete\":false") != std::string::npos);
  // A sample nobody refreshed for more than 30 s is not evidence about the
  // present: the anchor is dropped and the snapshot is partial again.
  auto stale = publisher.prepare(4, 10, 1700000031, "# EOF\n", true, sign, verify, true, &consensus, true);
  CHECK(stale);
  auto stale_body = stale->read(10);
  CHECK(stale_body);
  CHECK(stale_body->find("\"chain\":null") != std::string::npos);
  CHECK(stale_body->find("\"instrumentation_complete\":false") != std::string::npos);
  // No key block known yet: the field is null, the anchor itself stays.
  anchor.key_block_unix_seconds = 0;
  chain_anchor_state.publish(anchor);
  auto no_key = publisher.prepare(6, 10, 1700000002, "# EOF\n", true, sign, verify, true, &consensus, true);
  CHECK(no_key);
  auto no_key_body = no_key->read(10);
  CHECK(no_key_body);
  CHECK(no_key_body->find("\"key_block\":null") != std::string::npos);
  CHECK(no_key_body->find("\"seqno\":17166") != std::string::npos);
  // A key block clock ahead of the observation is malformed.
  anchor.key_block_unix_seconds = 1700000001;
  chain_anchor_state.publish(anchor);
  auto bad_key = publisher.prepare(7, 10, 1700000002, "# EOF\n", true, sign, verify, true, &consensus, true);
  CHECK(bad_key);
  auto bad_key_body = bad_key->read(10);
  CHECK(bad_key_body);
  CHECK(bad_key_body->find("\"chain\":null") != std::string::npos);
  anchor.key_block_unix_seconds = 1699990000;
  // An applied-advance clock ahead of its own observation is malformed.
  anchor.applied_advanced_unix_seconds = 1700000001;
  chain_anchor_state.publish(anchor);
  auto malformed = publisher.prepare(5, 10, 1700000002, "# EOF\n", true, sign, verify, true, &consensus, true);
  CHECK(malformed);
  auto malformed_body = malformed->read(10);
  CHECK(malformed_body);
  CHECK(malformed_body->find("\"chain\":null") != std::string::npos);
  // Node state (duties, real queues, storage position) attached: the three
  // coverage fields disappear, the snapshot becomes complete, and the JSON is
  // well-formed with the exact key order the consumers hash.
  anchor.applied_advanced_unix_seconds = 1700000000;
  anchor.observed_unix_seconds = 1700000000;
  chain_anchor_state.publish(anchor);
  node_state.validator_member.store(true);
  node_state.leader_windows_assigned.store(12);
  node_state.leader_windows_superseded.store(1);
  node_state.leader_windows_suppressed_behind.store(2);
  node_state.block_data_waiters.depth.store(3);
  node_state.block_data_waiters.oldest_age_ms.store(4500);
  node_state.db_total_bytes.store(1000000000000ULL);
  node_state.db_free_bytes.store(250000000000ULL);
  node_state.gc_seqno.store(17000);
  node_state.persistent_state_seqno.store(16500);
  node_state.storage_valid.store(true);
  node_state.observed_unix_seconds.store(1700000000);
  auto full = publisher.prepare(8, 10, 1700000001, "# EOF\n", true, sign, verify, true, &consensus, true);
  CHECK(full);
  auto full_body = full->read(10);
  CHECK(full_body);
  std::string full_copy = *full_body;
  CHECK(td::json_decode(td::MutableSlice(full_copy)).is_ok());
  CHECK(full_body->find("\"node_state\":{\"duties\":{\"leader_windows\":{\"assigned\":\"12\",\"started\":\"") != std::string::npos);
  CHECK(full_body->find("\"superseded\":\"1\",\"suppressed_behind\":\"2\"},\"member\":true}") != std::string::npos);
  CHECK(full_body->find("{\"depth\":3,\"oldest_age_ms\":\"4500\",\"queue\":\"block_data_waiters\"}") != std::string::npos);
  CHECK(full_body->find("\"storage\":{\"db_free_bytes\":\"250000000000\",\"db_total_bytes\":\"1000000000000\",\"gc_seqno\":17000,\"persistent_state_seqno\":16500}") != std::string::npos);
  CHECK(full_body->find("\"coverage\":{\"status\":\"complete\",\"missing_fields\":[]") != std::string::npos);
  CHECK(full_body->find("\"instrumentation_complete\":true") != std::string::npos);
  // A node-state sample nobody refreshed for more than 30 s is dropped again.
  auto ns_stale = publisher.prepare(9, 10, 1700000031, "# EOF\n", true, sign, verify, true, &consensus, true);
  CHECK(ns_stale);
  auto ns_stale_body = ns_stale->read(10);
  CHECK(ns_stale_body);
  CHECK(ns_stale_body->find("\"node_state\":null") != std::string::npos);
  CHECK(ns_stale_body->find("\"local_duties\",\"queue_state\",\"storage_state\"]") != std::string::npos);
  // A shard session is coverage, not an integrity defect: the field is named
  // and the snapshot stays complete.
  node_state.storage_valid.store(true);
  node_state.observed_unix_seconds.store(1700000031);
  anchor.applied_advanced_unix_seconds = 1700000031;
  anchor.observed_unix_seconds = 1700000031;
  chain_anchor_state.publish(anchor);
  ConsensusPublication shard{"{\"synthetic\":true}", true, true};
  auto sharded = publisher.prepare(11, 10, 1700000031, "# EOF\n", true, sign, verify, true, &shard, true);
  CHECK(sharded);
  auto sharded_body = sharded->read(10);
  CHECK(sharded_body);
  CHECK(sharded_body->find("\"coverage\":{\"status\":\"partial\",\"missing_fields\":[\"shard_consensus_progress\"]") != std::string::npos);
  CHECK(sharded_body->find("\"instrumentation_complete\":true") != std::string::npos);
  // Without a valid disk sample the storage position is not claimed.
  node_state.observed_unix_seconds.store(1700000031);
  node_state.storage_valid.store(false);
  auto no_disk = publisher.prepare(10, 10, 1700000031, "# EOF\n", true, sign, verify, true, &consensus, true);
  CHECK(no_disk);
  auto no_disk_body = no_disk->read(10);
  CHECK(no_disk_body);
  CHECK(no_disk_body->find("\"node_state\":null") != std::string::npos);
  std::cout << "native_snapshot_unit_passed" << std::endl;
}
}  // namespace
int main(int argc, char **argv) {
  if (argc == 1) {
    unit();
    return 0;
  }
  CHECK(argc == 3 || argc == 4);
  std::string mode = argv[2];
  std::size_t padding = argc == 4 ? std::stoull(argv[3]) : 0;
  td::IPAddress address;
  address.init_host_port(td::CSlice((std::string("127.0.0.1:") + argv[1]).c_str())).ensure();
  tos::health::enabled.store(mode != "gateoff");
  tos::health::pq_sign.completed.store(9007199254740993ULL);
  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<tos::PrometheusExporter> exporter;
  td::actor::ActorOwn<Fixture> fixture;
  td::actor::ActorOwn<Fixture> second_fixture;
  scheduler.run_in_context([&] {
    exporter = tos::PrometheusExporter::create("tos");
    fixture = td::actor::create_actor<Fixture>("fixture", mode, padding);
    td::actor::send_closure(exporter.get(), &tos::PrometheusExporter::register_collector<Fixture>, "fixture",
                            fixture.get());
    if (mode == "sources") {
      second_fixture = td::actor::create_actor<Fixture>("second_fixture", mode, padding, "fixture_second_calls");
      td::actor::send_closure(exporter.get(), &tos::PrometheusExporter::register_collector<Fixture>, "second_fixture",
                              second_fixture.get());
      td::actor::send_closure(exporter.get(), &tos::PrometheusExporter::register_collector<tos::PrometheusExporter>,
                              "exporter", exporter.get());
    }
    if (mode != "disabled") {
      td::actor::send_closure(exporter.get(), &tos::PrometheusExporter::set_health_node, std::string("v1"));
      td::actor::send_closure(exporter.get(), &tos::PrometheusExporter::set_health_network, std::string(64, 'a'));
    }
    td::actor::send_closure(exporter.get(), &tos::PrometheusExporter::listen, address);
  });
  scheduler.run();
}
