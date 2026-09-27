/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>

#include "measurement-contract.h"

namespace tos::validator::measurement {
namespace {

std::mutex sink_mutex;
std::shared_ptr<Sink> sink;
std::atomic<bool> sink_enabled{false};

constexpr std::array<std::string_view, 5> forbidden_label_keys = {"validator_id", "block_hash", "candidate_hash",
                                                                  "session_id", "peer_id"};

std::shared_ptr<Sink> enabled_sink() {
  // Production leaves measurement disabled.  Keep that path to one atomic
  // read and a branch: no mutex, shared_ptr refcount traffic, or clock reads.
  if (!sink_enabled.load(std::memory_order_acquire)) {
    return {};
  }
  std::lock_guard guard(sink_mutex);
  return sink;
}

std::string json_escape(std::string_view value) {
  std::string result;
  result.reserve(value.size());
  for (const char ch : value) {
    switch (ch) {
      case '\\':
        result += "\\\\";
        break;
      case '"':
        result += "\\\"";
        break;
      case '\n':
        result += "\\n";
        break;
      case '\r':
        result += "\\r";
        break;
      case '\t':
        result += "\\t";
        break;
      default:
        result += ch;
    }
  }
  return result;
}

std::string trace_id_hex(const TraceId& id) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (const auto byte : id) {
    out << std::setw(2) << static_cast<unsigned>(byte);
  }
  return out.str();
}

class JsonlFileSink final : public Sink {
 public:
  JsonlFileSink(std::string path, std::string node_id)
      : out_(std::move(path), std::ios::app), node_id_(std::move(node_id)) {
  }

  bool is_open() const {
    return out_.is_open();
  }

  void record_trace(TracePoint point) override {
    std::lock_guard guard(mutex_);
    out_ << "{\"kind\":\"trace\",\"node_id\":\"" << json_escape(node_id_) << "\",\"trace_id\":\""
         << trace_id_hex(point.trace_id) << "\",\"stage\":\"" << trace_stage_name(point.stage)
         << "\",\"monotonic_ns\":" << point.clock.monotonic_ns << ",\"wall_unix_ns\":" << point.clock.wall_unix_ns;
    if (point.exact_bytes) {
      out_ << ",\"exact_bytes\":" << *point.exact_bytes;
    }
    out_ << "}\n";
    out_.flush();
  }

  void record_size(SizePoint point) override {
    std::lock_guard guard(mutex_);
    out_ << "{\"kind\":\"size\",\"node_id\":\"" << json_escape(node_id_) << "\",\"artifact\":\""
         << serialized_artifact_name(point.artifact) << "\",\"exact_bytes\":" << point.exact_bytes << "}\n";
    out_.flush();
  }

 private:
  std::mutex mutex_;
  std::ofstream out_;
  std::string node_id_;
};

}  // namespace

void install_sink(std::shared_ptr<Sink> value) {
  std::lock_guard guard(sink_mutex);
  sink = std::move(value);
  sink_enabled.store(static_cast<bool>(sink), std::memory_order_release);
}

bool enabled() noexcept {
  return sink_enabled.load(std::memory_order_acquire);
}

td::Result<std::shared_ptr<Sink>> create_jsonl_file_sink(std::string path, std::string node_id) {
  auto result = std::make_shared<JsonlFileSink>(std::move(path), std::move(node_id));
  if (!result->is_open()) {
    return td::Status::Error("failed to open measurement JSONL output");
  }
  return std::static_pointer_cast<Sink>(std::move(result));
}

ClockSample sample_clocks() {
  const auto monotonic = std::chrono::steady_clock::now().time_since_epoch();
  const auto wall = std::chrono::system_clock::now().time_since_epoch();
  return {
      .monotonic_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(monotonic).count(),
      .wall_unix_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(wall).count(),
  };
}

td::Result<std::int64_t> monotonic_duration_ns(const ClockSample& start, const ClockSample& finish) {
  if (finish.monotonic_ns < start.monotonic_ns) {
    return td::Status::Error("measurement monotonic timestamp moved backwards");
  }
  return finish.monotonic_ns - start.monotonic_ns;
}

void record_trace(TraceId trace_id, TraceStage stage) {
  auto current = enabled_sink();
  if (current) {
    current->record_trace(
        {.trace_id = std::move(trace_id), .stage = stage, .clock = sample_clocks(), .exact_bytes = {}});
  }
}

void record_trace(TraceId trace_id, TraceStage stage, std::size_t exact_bytes) {
  auto current = enabled_sink();
  if (current) {
    current->record_trace(
        {.trace_id = std::move(trace_id), .stage = stage, .clock = sample_clocks(), .exact_bytes = exact_bytes});
  }
}

void record_trace_at(TraceId trace_id, TraceStage stage, ClockSample clock) {
  auto current = enabled_sink();
  if (current) {
    current->record_trace({.trace_id = std::move(trace_id), .stage = stage, .clock = clock, .exact_bytes = {}});
  }
}

void record_serialized_size(SerializedArtifact artifact, std::size_t exact_bytes) {
  auto current = enabled_sink();
  if (current) {
    current->record_size({.artifact = artifact, .exact_bytes = exact_bytes});
  }
}

void record_serialized_size(SerializedArtifact artifact, td::Slice serialized) {
  record_serialized_size(artifact, serialized.size());
}

std::string_view trace_stage_name(TraceStage stage) {
  switch (stage) {
    case TraceStage::candidate_generated:
      return "candidate_generated";
    case TraceStage::candidate_first_sent:
      return "candidate_first_sent";
    case TraceStage::candidate_first_received:
      return "candidate_first_received";
    case TraceStage::notarization_certificate_observed:
      return "notarization_certificate_observed";
    case TraceStage::finalization_certificate_observed:
      return "finalization_certificate_observed";
    case TraceStage::block_signature_set_built:
      return "block_signature_set_built";
    case TraceStage::finalize_block_published:
      return "finalize_block_published";
    case TraceStage::accept_block_started:
      return "accept_block_started";
    case TraceStage::signatures_persisted:
      return "signatures_persisted";
    case TraceStage::block_proof_persisted:
      return "block_proof_persisted";
    case TraceStage::finalized_marker_written:
      return "finalized_marker_written";
    case TraceStage::finality_broadcast_sent:
      return "finality_broadcast_sent";
    case TraceStage::peer_finality_broadcast_received:
      return "peer_finality_broadcast_received";
    case TraceStage::peer_finality_verification_started:
      return "peer_finality_verification_started";
    case TraceStage::peer_finality_broadcast_verified:
      return "peer_finality_broadcast_verified";
    case TraceStage::lite_proof_generated:
      return "lite_proof_generated";
    case TraceStage::lite_proof_verified:
      return "lite_proof_verified";
  }
  return "unknown";
}

std::string_view serialized_artifact_name(SerializedArtifact artifact) {
  switch (artifact) {
    case SerializedArtifact::candidate_auth:
      return "candidate_auth";
    case SerializedArtifact::signed_vote:
      return "signed_vote";
    case SerializedArtifact::simplex_certificate:
      return "simplex_certificate";
    case SerializedArtifact::block_signatures_boc:
      return "block_signatures_boc";
    case SerializedArtifact::block_proof_boc:
      return "block_proof_boc";
    case SerializedArtifact::block_finality_broadcast:
      return "block_finality_broadcast";
    case SerializedArtifact::compressed_v2_broadcast:
      return "compressed_v2_broadcast";
    case SerializedArtifact::top_block_description:
      return "top_block_description";
    case SerializedArtifact::lite_signature_set:
      return "lite_signature_set";
    case SerializedArtifact::lite_forward_proof:
      return "lite_forward_proof";
  }
  return "unknown";
}

std::string_view metric_name(MetricName name) {
  switch (name) {
    case MetricName::crypto_duration_seconds:
      return "pq_crypto_duration_seconds";
    case MetricName::crypto_verify_calls_total:
      return "pq_crypto_verify_calls_total";
    case MetricName::serialized_bytes:
      return "pq_serialized_bytes";
    case MetricName::messages_total:
      return "pq_messages_total";
    case MetricName::message_bytes_total:
      return "pq_message_bytes_total";
    case MetricName::pending_finality_candidates:
      return "pq_pending_finality_candidates";
    case MetricName::pending_finality_bytes:
      return "pq_pending_finality_bytes";
    case MetricName::pending_finality_rejections_total:
      return "pq_pending_finality_rejections_total";
    case MetricName::authority_memo_entries:
      return "pq_authority_memo_entries";
    case MetricName::authority_memo_lookups_total:
      return "pq_authority_memo_lookups_total";
  }
  return "unknown";
}

const std::vector<MetricDescriptor>& metric_schema() {
  static const std::vector<MetricDescriptor> schema = {
      {MetricName::crypto_duration_seconds, {"operation", "result"}},
      {MetricName::crypto_verify_calls_total, {"operation", "result"}},
      {MetricName::serialized_bytes, {"artifact"}},
      {MetricName::messages_total, {"direction", "message_type", "result"}},
      {MetricName::message_bytes_total, {"direction", "message_type"}},
      {MetricName::pending_finality_candidates, {"pool"}},
      {MetricName::pending_finality_bytes, {"pool"}},
      {MetricName::pending_finality_rejections_total, {"reason"}},
      {MetricName::authority_memo_entries, {}},
      {MetricName::authority_memo_lookups_total, {"result"}},
  };
  return schema;
}

td::Status validate_metric_descriptor(const MetricDescriptor& descriptor) {
  if (metric_name(descriptor.name) == "unknown") {
    return td::Status::Error("measurement metric has an unknown name");
  }
  for (const auto label : descriptor.label_keys) {
    if (std::find(forbidden_label_keys.begin(), forbidden_label_keys.end(), label) != forbidden_label_keys.end()) {
      return td::Status::Error("measurement metric uses forbidden high-cardinality label: " + std::string(label));
    }
  }
  return td::Status::OK();
}

td::Status validate_metric_schema() {
  for (const auto& descriptor : metric_schema()) {
    TRY_STATUS(validate_metric_descriptor(descriptor));
  }
  return td::Status::OK();
}

BoundedTraceBuffer::BoundedTraceBuffer(std::size_t max_trace_ids, std::size_t max_events_per_trace)
    : max_trace_ids_(max_trace_ids), max_events_per_trace_(max_events_per_trace) {
}

void BoundedTraceBuffer::record_trace(TracePoint point) {
  if (max_trace_ids_ == 0 || max_events_per_trace_ == 0) {
    ++dropped_events_;
    return;
  }
  auto it = traces_.find(point.trace_id);
  if (it == traces_.end()) {
    if (traces_.size() == max_trace_ids_) {
      traces_.erase(trace_order_.front());
      trace_order_.pop_front();
      ++evicted_traces_;
    }
    trace_order_.push_back(point.trace_id);
    it = traces_.emplace(point.trace_id, std::vector<TracePoint>{}).first;
  }
  if (it->second.size() == max_events_per_trace_) {
    ++dropped_events_;
    return;
  }
  it->second.push_back(std::move(point));
}

void BoundedTraceBuffer::record_size(SizePoint point) {
  sizes_.push_back(point);
}

std::size_t BoundedTraceBuffer::trace_count() const {
  return traces_.size();
}

std::size_t BoundedTraceBuffer::event_count(const TraceId& id) const {
  const auto it = traces_.find(id);
  return it == traces_.end() ? 0 : it->second.size();
}

const std::vector<TracePoint>* BoundedTraceBuffer::trace(const TraceId& id) const {
  const auto it = traces_.find(id);
  return it == traces_.end() ? nullptr : &it->second;
}

const std::vector<SizePoint>& BoundedTraceBuffer::sizes() const {
  return sizes_;
}

std::size_t BoundedTraceBuffer::evicted_traces() const {
  return evicted_traces_;
}

std::size_t BoundedTraceBuffer::dropped_events() const {
  return dropped_events_;
}

}  // namespace tos::validator::measurement
