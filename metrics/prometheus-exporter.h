#pragma once

#include "http/http-server.h"
#include "td/actor/common.h"
#include "td/actor/coro_task.h"

#include "metrics-collectors.h"
#include "native-core-snapshot.h"
#include "source-admission.h"

namespace tos {
class PrometheusExporter final : public td::actor::Actor, public virtual metrics::CollectorWrapper {
 public:
  static td::actor::ActorOwn<PrometheusExporter> create(std::string prefix = "tos");

  template <std::derived_from<metrics::AsyncCollector> A>
  void register_collector(std::string source_id, td::actor::ActorId<A> collector);

  void listen(td::IPAddress addr);
  void set_health_node(std::string value);
  void set_health_network(std::string value);
  void set_health_native_v2();
  void set_health_native_v3();
  void set_health_diagnostic(std::string path, int peer_pid, std::uint32_t sampling);
  void tear_down() override;

  explicit PrometheusExporter(std::string prefix);

 private:
  using RequestPtr = std::unique_ptr<http::HttpRequest>;
  using ResponsePtr = std::unique_ptr<http::HttpResponse>;
  using PayloadPtr = std::shared_ptr<http::HttpPayload>;
  using HttpReturn = std::pair<ResponsePtr, PayloadPtr>;

  // To avoid bugs.
  using CollectorWrapper::add_collector;

  class HttpCallback : public http::HttpServer::Callback {
   public:
    explicit HttpCallback(td::actor::ActorId<PrometheusExporter> exporter);

    void receive_request(RequestPtr request, PayloadPtr payload, td::Promise<HttpReturn> promise) override;

   private:
    td::actor::ActorId<PrometheusExporter> exporter_;
  };
  friend HttpCallback;

  using CollectorLambda = std::function<void(metrics::MetricsPromise)>;

  void start_up() override;

  void on_request(RequestPtr request, PayloadPtr payload, td::Promise<HttpReturn> promise);

  void collection_completed(td::Result<metrics::MetricSet> result);
  void alarm() override;
  void respond_metrics(td::Promise<HttpReturn> promise);
  void respond(td::Promise<HttpReturn> promise, int code, const char *reason, std::string body,
               const char *content_type = "application/openmetrics-text; version=1.0.0; charset=utf-8");

  health::NativeCorePublisher core_publisher_;
  std::optional<health::NativeCoreSnapshot> core_snapshot_;
  std::optional<td::Promise<HttpReturn>> waiter_;
  bool loopback_ = false;
  bool native_v2_ = false;
  bool native_v3_ = false;

  metrics::SourceAdmission admission_;
  std::string snapshot_;
  std::uint64_t skipped_ = 0;
  std::uint64_t failures_ = 0;
  std::uint64_t last_publisher_prepare_us_ = 0;

  std::string prefix_;
  td::actor::ActorOwn<http::HttpServer> http_ = {};
  td::actor::ActorOwn<metrics::MultiCollector> main_collector_ = metrics::MultiCollector::create(prefix_);

  metrics::MultiCollector::Own collector_ = metrics::MultiCollector::create("exporter");
  metrics::AtomicGauge<size_t>::Ptr collectors_ =
      metrics::AtomicGauge<size_t>::make("collectors", "Current number of exporter's added collectors.");
  metrics::AtomicCounter<size_t>::Ptr collections_total_ =
      metrics::AtomicCounter<size_t>::make("collections_total", "Total number of collection requests to the exporter.");
  metrics::AtomicGauge<double>::Ptr last_collection_duration_ = metrics::AtomicGauge<double>::make(
      "last_collection_duration_seconds", "Duration of the last collection request to the exporter.");
  metrics::AtomicGauge<double>::Ptr last_collection_timestamp_ = metrics::AtomicGauge<double>::make(
      "last_collection_timestamp_seconds", "Timestamp of the last collection request to the exporter.");
};

template <std::derived_from<metrics::AsyncCollector> A>
void PrometheusExporter::register_collector(std::string source_id, td::actor::ActorId<A> collector) {
  collectors_->add(1);
  td::actor::send_closure(main_collector_.get(), &metrics::MultiCollector::add_async_collector<A>, std::move(source_id),
                          collector);
}

}  // namespace tos
