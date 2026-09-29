#include <algorithm>
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
