/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"

namespace tos::validator::measurement {

using TraceId = std::array<std::uint8_t, 32>;

// Stable, bounded vocabulary for the detailed per-block JSONL trace.  Trace ids
// belong in that bounded log, never in OpenMetrics labels.
enum class TraceStage : std::uint8_t {
  candidate_generated,
  candidate_first_sent,
  candidate_first_received,
  notarization_certificate_observed,
  finalization_certificate_observed,
  block_signature_set_built,
  finalize_block_published,
  accept_block_started,
  signatures_persisted,
  block_proof_persisted,
  finalized_marker_written,
  finality_broadcast_sent,
  peer_finality_broadcast_received,
  peer_finality_verification_started,
  peer_finality_broadcast_verified,
  lite_proof_generated,
  lite_proof_verified,
};

enum class SerializedArtifact : std::uint8_t {
  candidate_auth,
  signed_vote,
  simplex_certificate,
  block_signatures_boc,
  block_proof_boc,
  block_finality_broadcast,
  compressed_v2_broadcast,
  top_block_description,
  lite_signature_set,
  lite_forward_proof,
};

enum class MetricName : std::uint8_t {
  crypto_duration_seconds,
  crypto_verify_calls_total,
  serialized_bytes,
  messages_total,
  message_bytes_total,
  pending_finality_candidates,
  pending_finality_bytes,
  pending_finality_rejections_total,
  authority_memo_entries,
  authority_memo_lookups_total,
};

struct MetricDescriptor {
  MetricName name;
  std::vector<std::string_view> label_keys;
};

struct ClockSample {
  std::int64_t monotonic_ns;
  std::int64_t wall_unix_ns;
};

struct TracePoint {
  TraceId trace_id;
  TraceStage stage;
  ClockSample clock;
  std::optional<std::size_t> exact_bytes;
};

struct SizePoint {
  SerializedArtifact artifact;
  std::size_t exact_bytes;
};

class Sink {
 public:
  virtual ~Sink() = default;
  virtual void record_trace(TracePoint point) = 0;
  virtual void record_size(SizePoint point) = 0;
};

// Installing a sink is a runtime measurement choice, not a consensus mode.  A
// null sink disables collection.  Serializers always finish producing bytes
// before the observer sees their immutable Slice.
void install_sink(std::shared_ptr<Sink> sink);
td::Result<std::shared_ptr<Sink>> create_jsonl_file_sink(std::string path, std::string node_id);

// One atomic load.  Use record_trace_lazy when computing the trace id is not
// already part of the caller's work; its provider is never evaluated while
// measurement is disabled.
bool enabled() noexcept;

ClockSample sample_clocks();
td::Result<std::int64_t> monotonic_duration_ns(const ClockSample& start, const ClockSample& finish);
void record_trace(TraceId trace_id, TraceStage stage);
void record_trace(TraceId trace_id, TraceStage stage, std::size_t exact_bytes);
void record_trace_at(TraceId trace_id, TraceStage stage, ClockSample clock);

template <class TraceIdProvider>
void record_trace_lazy(TraceIdProvider&& trace_id_provider, TraceStage stage) {
  if (!enabled()) {
    return;
  }
  record_trace(std::forward<TraceIdProvider>(trace_id_provider)(), stage);
}

template <class TraceIdProvider>
void record_trace_lazy(TraceIdProvider&& trace_id_provider, TraceStage stage, std::size_t exact_bytes) {
  if (!enabled()) {
    return;
  }
  record_trace(std::forward<TraceIdProvider>(trace_id_provider)(), stage, exact_bytes);
}

void record_serialized_size(SerializedArtifact artifact, std::size_t exact_bytes);
void record_serialized_size(SerializedArtifact artifact, td::Slice serialized);

std::string_view trace_stage_name(TraceStage stage);
std::string_view serialized_artifact_name(SerializedArtifact artifact);
std::string_view metric_name(MetricName name);

const std::vector<MetricDescriptor>& metric_schema();
td::Status validate_metric_descriptor(const MetricDescriptor& descriptor);
td::Status validate_metric_schema();

// Testable bounded sink used by the release runner's JSONL writer as its
// in-memory staging policy.  Both dimensions are hard bounds: distinct trace
// ids and events retained for one trace.
class BoundedTraceBuffer final : public Sink {
 public:
  BoundedTraceBuffer(std::size_t max_trace_ids, std::size_t max_events_per_trace);

  void record_trace(TracePoint point) override;
  void record_size(SizePoint point) override;

  std::size_t trace_count() const;
  std::size_t event_count(const TraceId& id) const;
  const std::vector<TracePoint>* trace(const TraceId& id) const;
  const std::vector<SizePoint>& sizes() const;
  std::size_t evicted_traces() const;
  std::size_t dropped_events() const;

 private:
  std::size_t max_trace_ids_;
  std::size_t max_events_per_trace_;
  std::map<TraceId, std::vector<TracePoint>> traces_;
  std::deque<TraceId> trace_order_;
  std::vector<SizePoint> sizes_;
  std::size_t evicted_traces_{0};
  std::size_t dropped_events_{0};
};

}  // namespace tos::validator::measurement
