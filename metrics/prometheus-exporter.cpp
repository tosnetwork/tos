#include <algorithm>

#include "td/actor/coro_utils.h"

#include "core-health.h"
#include "core-registry.h"
#include "metrics-types.h"
#include "prometheus-exporter.h"

namespace tos {

td::actor::ActorOwn<PrometheusExporter> PrometheusExporter::create(std::string prefix) {
  return td::actor::create_actor<PrometheusExporter>(PSTRING() << "PROM@" << prefix, std::move(prefix));
}

PrometheusExporter::PrometheusExporter(std::string prefix) : prefix_(std::move(prefix)) {
  add_collector("exporter_internal", collector_.get());
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
  limits.max_connections = 8;
  const auto ip = addr.get_ip_str().str();
  loopback_ = ip.starts_with("127.") || ip == "::1";
  http_ = td::actor::create_actor<http::HttpServer>(PSTRING() << "HTTP@" << addr, addr, std::move(callback), limits);
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_async_collector<http::HttpServer>,
                          "http_server", http_.get());
}

void PrometheusExporter::set_health_node(std::string value) {
  if (!core_publisher_.set_node(std::move(value)))
    LOG(ERROR) << "Invalid or changed health node alias";
}
void PrometheusExporter::set_health_network(std::string value) {
  if (!core_publisher_.set_network(std::move(value)))
    LOG(ERROR) << "Invalid or changed health network identity";
}
void PrometheusExporter::alarm() {
  if (waiter_) {
    auto promise = std::move(*waiter_);
    waiter_.reset();
    respond(std::move(promise), 503, "Service Unavailable", "");
  }
  // The actual-work lease remains held until every child completes.
}
void PrometheusExporter::start_up() {
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_sync_collector, collectors_);
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_sync_collector, collections_total_);
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_sync_collector, last_collection_duration_);
  td::actor::send_closure(collector_.get(), &metrics::MultiCollector::add_sync_collector, last_collection_timestamp_);
}

void PrometheusExporter::respond(td::Promise<HttpReturn> promise, int code, const char *reason, std::string body,
                                 const char *content_type) {
  auto response = http::HttpResponse::create("HTTP/1.1", code, reason, false, false).move_as_ok();
  response->add_header({"Transfer-Encoding", "Chunked"});
  response->add_header({"Content-Type", content_type});
  if (code == 200) {
    response->add_header({"X-TOS-Snapshot-Generation", std::to_string(admission_.generation())});
    response->add_header({"X-TOS-Process-Epoch", core_publisher_.epoch()});
    response->add_header({"X-TOS-Publisher-Prepare-Us", std::to_string(last_publisher_prepare_us_)});
  }
  response->add_header({"Cache-Control", "no-store"});
  response->complete_parse_header();
  auto payload = response->create_empty_payload().move_as_ok();
  payload->add_chunk(td::BufferSlice{std::move(body)});
  payload->complete_parse();
  promise.set_value(std::pair{std::move(response), std::move(payload)});
}

void PrometheusExporter::on_request(RequestPtr request, PayloadPtr, td::Promise<HttpReturn> promise) {
  if (request->url() == "/health-snapshot") {
    if (!loopback_ || !core_publisher_.configured())
      return respond(std::move(promise), 404, "Not Found", "");
    if (request->method() != "GET")
      return respond(std::move(promise), 405, "Method Not Allowed", "");
    auto body = core_snapshot_ ? core_snapshot_->read(td::Timestamp::now().at()) : std::nullopt;
    if (!body)
      return respond(std::move(promise), 503, "Service Unavailable", "");
    return respond(std::move(promise), 200, "OK", std::move(*body), "application/json");
  }
  if (request->url() != "/metrics") {
    return respond(std::move(promise), 404, "Not Found", "");
  }
  if (request->method() != "GET") {
    return respond(std::move(promise), 405, "Method Not Allowed", "");
  }
  const auto now = td::Timestamp::now().at();
  if (admission_.begin(now)) {
    waiter_.emplace(std::move(promise));
    alarm_timestamp() = td::Timestamp::in(2.0);
    collections_total_->add(1);
    last_collection_timestamp_->set(td::Timestamp::now().at_unix());
    td::actor::send_closure(main_collector_.get(), &metrics::MultiCollector::collect,
                            td::make_promise([self = actor_id(this)](td::Result<metrics::MetricSet> result) mutable {
                              td::actor::send_closure(self, &PrometheusExporter::collection_completed,
                                                      std::move(result));
                            }));
    return;
  }
  ++skipped_;
  respond_metrics(std::move(promise));
}
void PrometheusExporter::respond_metrics(td::Promise<HttpReturn> promise) {
  const auto now = td::Timestamp::now().at();
  if (!admission_.fresh(now)) {
    return respond(std::move(promise), 503, "Service Unavailable", "");
  }
  // The entire body is the immutable publication paired to the typed snapshot.
  // Current request/transport state belongs in headers or a later generation;
  // mutating the body here would invalidate its content hash.
  respond(std::move(promise), 200, "OK", snapshot_);
}

void PrometheusExporter::collection_completed(td::Result<metrics::MetricSet> result) {
  const auto publisher_prepare_started = td::Timestamp::now().at();
  const auto record_publisher_prepare = [&] {
    const auto elapsed = std::max(0.0, td::Timestamp::now().at() - publisher_prepare_started);
    // This clock may report zero at microsecond resolution. It covers the
    // synchronous collection_completed preparation segment through cache
    // publication, but excludes upstream collectors and the response body copy.
    last_publisher_prepare_us_ = static_cast<std::uint64_t>(elapsed * 1000000.0);
  };
  auto now = td::Timestamp::now().at();
  last_collection_duration_->set(now - admission_.started());
  if (result.is_error() || admission_.expired(now)) {
    admission_.finish(now, false, 0);
    ++failures_;
    record_publisher_prepare();
    alarm();
    return;
  }
  const auto sampled_at = now;
  const auto wall = td::Timestamp::now().at_unix();
  auto set = result.move_as_ok();
  set.families.push_back(metrics::MetricFamily::make_scalar(prefix_ + "_exporter_snapshot_generation", "gauge",
                                                            static_cast<double>(admission_.generation() + 1)));
  set.families.push_back(
      metrics::MetricFamily::make_scalar(prefix_ + "_exporter_snapshot_completed_timestamp_seconds", "gauge", wall));
  const bool pq_enabled = health::enabled.load(std::memory_order_relaxed);
  health::OperationSnapshot sign, verify;
  if (pq_enabled) {
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
      auto &typed = stats == &health::pq_sign ? sign : verify;
      typed.complete = stats->complete.load(std::memory_order_relaxed);
      for (size_t result = 0; result < 2; ++result) {
        auto labels = metrics::LabelSet{
            {{"operation", operation}, {"suite", "mldsa44"}, {"result", result == 0 ? "success" : "failure"}}};
        const auto count = (result == 0 ? stats->completed : stats->failed).load(std::memory_order_relaxed);
        (result == 0 ? typed.succeeded : typed.failed) = count;
        operations.metrics.push_back(
            {.suffix = "", .label_set = labels, .samples = {{.label_set = {}, .value = static_cast<double>(count)}}});
        std::uint64_t cumulative = 0;
        for (size_t bucket = 0; bucket < 13; ++bucket) {
          cumulative += stats->buckets[result][bucket].load(std::memory_order_relaxed);
          auto boundary =
              bucket == 12 ? std::string("+Inf")
                           : std::to_string(static_cast<double>(health::OperationStats::bounds_us[bucket]) / 1000000.0);
          duration.metrics.push_back(
              {.suffix = "bucket",
               .label_set = labels,
               .samples = {{.label_set = {{{"le", boundary}}}, .value = static_cast<double>(cumulative)}}});
        }
        duration.metrics.push_back({.suffix = "count",
                                    .label_set = labels,
                                    .samples = {{.label_set = {}, .value = static_cast<double>(cumulative)}}});
        duration.metrics.push_back(
            {.suffix = "sum",
             .label_set = labels,
             .samples = {
                 {.label_set = {},
                  .value = static_cast<double>(stats->sum_us[result].load(std::memory_order_relaxed)) / 1000000.0}}});
      }
      set.families.push_back(std::move(metrics::MetricFamily::make_scalar(prefix_ + "_health_pq_accounting_complete",
                                                                          "gauge", typed.complete ? 1 : 0))
                                 .label({{{"operation", operation}}}));
    }
    set.families.push_back(std::move(operations));
    set.families.push_back(std::move(duration));
    set = std::move(set).join(health::core_registry.collect());
  }
  set.families.push_back(metrics::MetricFamily::make_scalar(
      prefix_ + "_exporter_snapshot_collection_inflight", "gauge", 0,
      "Source collection inflight state for this completed snapshot at publication; published generations are idle."));
  set.families.push_back(metrics::MetricFamily::make_scalar(
      prefix_ + "_exporter_snapshot_collection_skipped_total", "counter", static_cast<double>(skipped_),
      "Cumulative collection starts skipped as observed when this snapshot was published."));
  set.families.push_back(metrics::MetricFamily::make_scalar(
      prefix_ + "_exporter_snapshot_collection_failures_total", "counter", static_cast<double>(failures_),
      "Cumulative failed collections observed before this successful snapshot publication."));
  auto rendered = std::move(set).render();
  rendered += "# EOF\n";
  std::optional<health::NativeCoreSnapshot> typed;
  if (core_publisher_.configured()) {
    typed = core_publisher_.prepare(admission_.generation() + 1, sampled_at, wall, rendered, pq_enabled, sign, verify);
  }
  now = td::Timestamp::now().at();
  if (admission_.finish(now, !core_publisher_.configured() || typed.has_value(), rendered.size())) {
    snapshot_ = std::move(rendered);
    core_snapshot_ = std::move(typed);
  } else {
    ++failures_;
  }
  alarm_timestamp() = td::Timestamp::never();
  record_publisher_prepare();
  if (waiter_) {
    auto promise = std::move(*waiter_);
    waiter_.reset();
    respond_metrics(std::move(promise));
  }
}

}  // namespace tos
