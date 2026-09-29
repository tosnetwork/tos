#include <iostream>
#include <limits>

#include "metrics/core-health.h"
#include "metrics/native-core-snapshot.h"
#include "metrics/prometheus-exporter.h"
#include "td/actor/actor.h"
#include "td/utils/check.h"
namespace {
class Fixture final : public td::actor::Actor, public tos::metrics::AsyncCollector {
 public:
  Fixture(bool slow, bool after_first) : slow_(slow), after_first_(after_first) {
  }
  void collect(tos::metrics::MetricsPromise promise) override {
    ++calls_;
    std::cout << "COLLECT " << calls_ << std::endl;
    pending_ = std::move(promise);
    alarm_timestamp() = td::Timestamp::in(slow_ && (!after_first_ || calls_ > 1) ? 3.5 : 0.0);
  }

 private:
  void alarm() override {
    tos::metrics::MetricSet set;
    set.families.push_back(tos::metrics::MetricFamily::make_scalar("fixture_calls", "counter", calls_));
    pending_.set_value(std::move(set));
  }
  bool slow_, after_first_;
  unsigned calls_ = 0;
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
  std::cout << "native_snapshot_unit_passed" << std::endl;
}
}  // namespace
int main(int argc, char **argv) {
  if (argc == 1) {
    unit();
    return 0;
  }
  CHECK(argc == 3);
  std::string mode = argv[2];
  td::IPAddress address;
  address.init_host_port(td::CSlice((std::string("127.0.0.1:") + argv[1]).c_str())).ensure();
  tos::health::enabled.store(true);
  tos::health::pq_sign.completed.store(9007199254740993ULL);
  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<tos::PrometheusExporter> exporter;
  td::actor::ActorOwn<Fixture> fixture;
  scheduler.run_in_context([&] {
    exporter = tos::PrometheusExporter::create("tos");
    fixture = td::actor::create_actor<Fixture>("fixture", mode == "slow" || mode == "lease", mode == "lease");
    td::actor::send_closure(exporter.get(), &tos::PrometheusExporter::register_collector<Fixture>, fixture.get());
    if (mode != "disabled") {
      td::actor::send_closure(exporter.get(), &tos::PrometheusExporter::set_health_node, std::string("v1"));
      td::actor::send_closure(exporter.get(), &tos::PrometheusExporter::set_health_network, std::string(64, 'a'));
    }
    td::actor::send_closure(exporter.get(), &tos::PrometheusExporter::listen, address);
  });
  scheduler.run();
}
