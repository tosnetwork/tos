#include "td/actor/coro_utils.h"

#include "core-health.h"
#include "metrics-types.h"
#include "prometheus-exporter.h"

namespace tos {

td::actor::ActorOwn<PrometheusExporter> PrometheusExporter::create(std::string prefix) {
  return td::actor::create_actor<PrometheusExporter>(PSTRING() << "PROM@" << prefix, std::move(prefix));
}

PrometheusExporter::PrometheusExporter(std::string prefix) : prefix_(std::move(prefix)) {
  add_collector(collector_.get());
}

PrometheusExporter::HttpCallback::HttpCallback(td::actor::ActorId<PrometheusExporter> exporter)
    : exporter_(std::move(exporter)) {
}

void PrometheusExporter::HttpCallback::receive_request(RequestPtr request, PayloadPtr payload,
                                                       td::Promise<HttpReturn> promise) {
  td::actor::send_closure(exporter_, &PrometheusExporter::on_request, std::move(request), std::move(payload),
                          std::move(promise));
}

void PrometheusExporter::listen(td::IPAddress addr) {
  CHECK(http_.empty());
  auto callback = std::make_unique<HttpCallback>(actor_id(this));
  // Metrics scrapers are few; a modest ceiling keeps a scrape endpoint from
  // being turned into a file-descriptor exhaustion vector.
  http::HttpServer::Limits limits;
  limits.max_connections = 256;
  http_ = td::actor::create_actor<http::HttpServer>(PSTRING() << "HTTP@" << addr, addr, std::move(callback), limits);
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_async_collector<http::HttpServer>,
                          http_.get());
}

void PrometheusExporter::start_up() {
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_sync_collector, collectors_);
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_sync_collector, collections_total_);
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_sync_collector, last_collection_duration_);
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_sync_collector, last_collection_timestamp_);
}

void PrometheusExporter::respond(td::Promise<HttpReturn> promise, int code, const char *reason, std::string body) {
  auto response = http::HttpResponse::create("HTTP/1.1", code, reason, false, false).move_as_ok();
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->add_header({"Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8"});
  response->add_header({"Cache-Control", "no-store"});
  response->complete_parse_header();
  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice{std::move(body)});
  payload->complete_parse();
  promise.set_value(std::pair{std::move(response), std::move(payload)});
}

void PrometheusExporter::on_request(RequestPtr request, PayloadPtr, td::Promise<HttpReturn> promise) {
  if (request->url() != "/metrics") {
    return respond(std::move(promise), 404, "Not Found", "");
  }
  if (request->method() != "GET") {
    return respond(std::move(promise), 405, "Method Not Allowed", "");
  }
  const auto now = td::Timestamp::now().at();
  if (admission_.begin(now)) {
    collections_total_->add(1);
    last_collection_timestamp_->set(td::Timestamp::now().at_unix());
    td::actor::send_closure(main_collector_.get(), &metrics::MultiCollector::collect,
                            td::make_promise([self = actor_id(this)](td::Result<metrics::MetricSet> result) mutable {
                              td::actor::send_closure(self, &PrometheusExporter::collection_completed,
                                                      std::move(result));
                            }));
  } else {
    ++skipped_;
  }
  // No request waits on a business actor. Cold or stale sources explicitly fail.
  if (!admission_.fresh(now)) {
    return respond(std::move(promise), 503, "Service Unavailable", "");
  }
  auto body = snapshot_;
  // Live transport state does not refresh the cached generation's source time.
  auto state = metrics::MetricSet{};
  state.families.push_back(metrics::MetricFamily::make_scalar(prefix_ + "_exporter_collection_inflight", "gauge",
                                                              admission_.inflight() ? 1 : 0));
  state.families.push_back(metrics::MetricFamily::make_scalar(prefix_ + "_exporter_collection_skipped_total", "counter",
                                                              static_cast<double>(skipped_)));
  state.families.push_back(metrics::MetricFamily::make_scalar(prefix_ + "_exporter_collection_failures_total",
                                                              "counter", static_cast<double>(failures_)));
  body += std::move(state).render();
  body += "# EOF\n";
  respond(std::move(promise), 200, "OK", std::move(body));
}

void PrometheusExporter::collection_completed(td::Result<metrics::MetricSet> result) {
  auto now = td::Timestamp::now().at();
  last_collection_duration_->set(now - admission_.started());
  if (result.is_error() || admission_.expired(now)) {
    admission_.finish(now, false, 0);
    ++failures_;
    return;
  }
  const auto wall = td::Timestamp::now().at_unix();
  auto set = result.move_as_ok();
  set.families.push_back(metrics::MetricFamily::make_scalar(prefix_ + "_exporter_snapshot_generation", "gauge",
                                                            static_cast<double>(admission_.generation() + 1)));
  set.families.push_back(
      metrics::MetricFamily::make_scalar(prefix_ + "_exporter_snapshot_completed_timestamp_seconds", "gauge", wall));
  if (health::enabled.load(std::memory_order_relaxed)) {
    auto operations =
        metrics::MetricFamily{.name = prefix_ + "_pq_operations_total",
                              .type = "counter",
                              .help = "Consensus PQ production operations; approximate concurrent snapshot.",
                              .metrics = {}};
    auto duration = metrics::MetricFamily{.name = prefix_ + "_pq_operation_duration_seconds",
                                          .type = "histogram",
                                          .help = "Consensus PQ operation duration.",
                                          .metrics = {}};
    for (auto [operation, stats] : {std::pair{"sign", &health::pq_sign}, std::pair{"verify", &health::pq_verify}}) {
      for (size_t result = 0; result < 2; ++result) {
        auto labels = metrics::LabelSet{
            {{"operation", operation}, {"suite", "mldsa44"}, {"result", result == 0 ? "success" : "failure"}}};
        const auto count = (result == 0 ? stats->completed : stats->failed).load(std::memory_order_relaxed);
        operations.metrics.push_back(
            {.suffix = "", .label_set = labels, .samples = {{.label_set = {}, .value = static_cast<double>(count)}}});
        std::uint64_t cumulative = 0;
        for (size_t bucket = 0; bucket < 13; ++bucket) {
          cumulative += stats->buckets[result][bucket].load(std::memory_order_relaxed);
          auto boundary =
              bucket == 12 ? std::string("+Inf")
                           : std::to_string(static_cast<double>(health::OperationStats::bounds_us[bucket]) / 1000000.0);
          duration.metrics.push_back(
              {.suffix = "_bucket",
               .label_set = labels,
               .samples = {{.label_set = {{{"le", boundary}}}, .value = static_cast<double>(cumulative)}}});
        }
        duration.metrics.push_back({.suffix = "_count",
                                    .label_set = labels,
                                    .samples = {{.label_set = {}, .value = static_cast<double>(cumulative)}}});
        duration.metrics.push_back(
            {.suffix = "_sum",
             .label_set = labels,
             .samples = {
                 {.label_set = {},
                  .value = static_cast<double>(stats->sum_us[result].load(std::memory_order_relaxed)) / 1000000.0}}});
      }
      set.families.push_back(
          std::move(metrics::MetricFamily::make_scalar(prefix_ + "_health_pq_accounting_complete", "gauge",
                                                       stats->complete.load(std::memory_order_relaxed) ? 1 : 0))
              .label({{{"operation", operation}}}));
    }
    set.families.push_back(std::move(operations));
    set.families.push_back(std::move(duration));
  }
  auto rendered = std::move(set).render();
  now = td::Timestamp::now().at();
  if (admission_.finish(now, true, rendered.size() + 2048)) {
    snapshot_ = std::move(rendered);
  } else {
    ++failures_;
  }
}

}  // namespace tos
