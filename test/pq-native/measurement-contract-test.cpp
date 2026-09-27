/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "auto/tl/tos_api.h"
#include "crypto/block/signature-set.h"
#include "crypto/pq/mldsa44.h"
#include "td/utils/crypto.h"
#include "td/utils/tests.h"
#include "tl-utils/tl-utils.hpp"
#include "tos/tos-types.h"
#include "validator/full-node-serializer.hpp"
#include "validator/measurement/measurement-contract.h"

namespace {

using namespace tos::validator::measurement;

void require(bool condition, td::Slice reason) {
  if (!condition) {
    LOG(ERROR) << reason;
  }
  ASSERT_TRUE(condition);
}

td::Bits256 hash_of(const std::string& text) {
  td::Bits256 out;
  td::sha256(td::Slice(text), out.as_slice());
  return out;
}

tos::BlockIdExt block_id() {
  return {-1, 0x8000000000000000ULL, 42, hash_of("measurement-root"), hash_of("measurement-file")};
}

tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate() {
  return tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
      tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(-1, static_cast<td::int64>(0x8000000000000000ULL), 42,
                                                              hash_of("measurement-root"), hash_of("measurement-file")),
      tos::create_tl_object<tos::tos_api::consensus_candidateId>(6, hash_of("measurement-parent")));
}

td::BufferSlice patterned_signature(std::size_t signer) {
  td::BufferSlice out(tos::pq::mldsa44_signature_bytes);
  std::size_t offset = 0;
  std::string seed = "measurement-signature-" + std::to_string(signer);
  while (offset < out.size()) {
    const auto block = hash_of(seed);
    const auto take = std::min<std::size_t>(32, out.size() - offset);
    std::memcpy(out.data() + offset, block.data(), take);
    offset += take;
    seed.assign(reinterpret_cast<const char*>(block.data()), 32);
  }
  return out;
}

tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet> node_signature_set(std::size_t signers) {
  std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_pqBlockSignature>> pairs;
  pairs.reserve(signers);
  for (std::size_t i = 0; i < signers; ++i) {
    pairs.push_back(tos::create_tl_object<tos::tos_api::tosNode_pqBlockSignature>(
        hash_of("measurement-validator-" + std::to_string(i)), static_cast<td::int32>(tos::pq::PQAlgorithmId::mldsa44),
        patterned_signature(i)));
  }
  return tos::create_tl_object<tos::tos_api::tosNode_signatureSet_simplexPq>(
      true, 17, 0x31415926, std::move(pairs), hash_of("measurement-session"), 7, candidate());
}

TraceId trace_id(std::uint8_t value) {
  TraceId result{};
  result.fill(value);
  return result;
}

td::Ref<block::BlockSignatureSet> signature_set(std::size_t signers) {
  auto parsed = block::BlockSignatureSet::fetch_node_checked(node_signature_set(signers));
  if (parsed.is_error()) {
    LOG(FATAL) << "fixture signature set failed: " << parsed.error();
  }
  return parsed.move_as_ok();
}

TEST(MeasurementContract, MetricSchema) {
  require(validate_metric_schema().is_ok(), "N6_METRIC_SCHEMA_FAILURE: registered schema is invalid");
  ASSERT_EQ(10u, metric_schema().size());

  constexpr std::array required_stages = {
      TraceStage::candidate_generated,
      TraceStage::candidate_first_sent,
      TraceStage::candidate_first_received,
      TraceStage::notarization_certificate_observed,
      TraceStage::finalization_certificate_observed,
      TraceStage::block_signature_set_built,
      TraceStage::finalize_block_published,
      TraceStage::accept_block_started,
      TraceStage::signatures_persisted,
      TraceStage::block_proof_persisted,
      TraceStage::finalized_marker_written,
      TraceStage::finality_broadcast_sent,
      TraceStage::peer_finality_broadcast_received,
      TraceStage::peer_finality_verification_started,
      TraceStage::peer_finality_broadcast_verified,
      TraceStage::lite_proof_generated,
      TraceStage::lite_proof_verified,
  };
  for (const auto stage : required_stages) {
    ASSERT_TRUE(trace_stage_name(stage) != "unknown");
  }
}

TEST(MeasurementContract, MonotonicTimestamps) {
  // The wall clock jumps backwards by 55 seconds.  Duration remains five
  // seconds because only the steady/monotonic coordinate is authoritative.
  ClockSample start{.monotonic_ns = 10'000'000'000, .wall_unix_ns = 100'000'000'000};
  ClockSample finish{.monotonic_ns = 15'000'000'000, .wall_unix_ns = 45'000'000'000};
  auto duration = monotonic_duration_ns(start, finish);
  require(duration.is_ok(), "N6_MONOTONIC_TIMESTAMP_FAILURE: forward steady interval was refused");
  require(duration.ok() == 5'000'000'000LL,
          "N6_MONOTONIC_TIMESTAMP_FAILURE: duration followed the wall clock instead of the steady clock");

  auto backwards = monotonic_duration_ns(finish, start);
  ASSERT_TRUE(backwards.is_error());
  ASSERT_TRUE(backwards.error().message().str().find("moved backwards") != std::string::npos);
}

TEST(MeasurementContract, LowCardinality) {
  require(validate_metric_schema().is_ok(),
          "N6_LOW_CARDINALITY_FAILURE: registered schema contains a forbidden high-cardinality label");
  MetricDescriptor forbidden{MetricName::messages_total, {"message_type", "validator_id"}};
  auto status = validate_metric_descriptor(forbidden);
  require(status.is_error(), "N6_LOW_CARDINALITY_FAILURE: validator_id metric label was admitted");
  require(status.message().str().find("validator_id") != std::string::npos,
          "N6_LOW_CARDINALITY_FAILURE: forbidden label refusal did not name validator_id");

  BoundedTraceBuffer buffer(2, 2);
  buffer.record_trace({trace_id(1), TraceStage::candidate_generated, {1, 1}, {}});
  buffer.record_trace({trace_id(1), TraceStage::candidate_first_sent, {2, 2}, {}});
  buffer.record_trace({trace_id(1), TraceStage::candidate_first_received, {3, 3}, {}});
  buffer.record_trace({trace_id(2), TraceStage::candidate_generated, {4, 4}, {}});
  buffer.record_trace({trace_id(3), TraceStage::candidate_generated, {5, 5}, {}});
  require(buffer.trace_count() == 2, "N6_LOW_CARDINALITY_FAILURE: trace-id bound was exceeded");
  ASSERT_EQ(1u, buffer.evicted_traces());
  ASSERT_EQ(1u, buffer.dropped_events());
  ASSERT_TRUE(buffer.trace(trace_id(1)) == nullptr);
}

TEST(MeasurementContract, SizeAccounting) {
  constexpr std::size_t signers = 21;
  auto sink = std::make_shared<BoundedTraceBuffer>(1, 1);
  install_sink(sink);
  const tos::validator::BlockFinalityBroadcast finality{block_id(), signature_set(signers)};
  auto serialized = tos::validator::fullnode::serialize_block_finality_broadcast(finality);
  install_sink(nullptr);

  ASSERT_EQ(1u, sink->sizes().size());
  ASSERT_EQ(SerializedArtifact::block_finality_broadcast, sink->sizes().front().artifact);
  require(serialized.size() == sink->sizes().front().exact_bytes,
          "N6_SIZE_ACCOUNTING_FAILURE: recorded finality bytes differ from production serialization");
  require(serialized.size() != signers * 96,
          "N6_SIZE_ACCOUNTING_FAILURE: post-quantum signatures were accounted as 96-byte classical pairs");
}

TEST(MeasurementContract, InstrumentationByteEquivalence) {
  constexpr std::size_t signers = 21;
  const tos::validator::BlockFinalityBroadcast finality{block_id(), signature_set(signers)};
  install_sink(nullptr);
  auto without_instrumentation = tos::validator::fullnode::serialize_block_finality_broadcast(finality);

  auto sink = std::make_shared<BoundedTraceBuffer>(8, 16);
  install_sink(sink);
  auto with_instrumentation = tos::validator::fullnode::serialize_block_finality_broadcast(finality);
  install_sink(nullptr);

  require(without_instrumentation.size() == with_instrumentation.size(),
          "N6_INSTRUMENTATION_BYTE_EQUIVALENCE_FAILURE: instrumentation changed wire length");
  require(without_instrumentation.as_slice() == with_instrumentation.as_slice(),
          "N6_INSTRUMENTATION_BYTE_EQUIVALENCE_FAILURE: instrumentation changed wire bytes");
  ASSERT_EQ(1u, sink->sizes().size());
  ASSERT_EQ(with_instrumentation.size(), sink->sizes().front().exact_bytes);
}

TEST(MeasurementContract, DisabledTraceIdProviderIsLazy) {
  std::size_t provider_calls = 0;
  auto provider = [&] {
    ++provider_calls;
    return trace_id(7);
  };

  install_sink(nullptr);
  record_trace_lazy(provider, TraceStage::peer_finality_verification_started);
  record_trace_lazy(provider, TraceStage::peer_finality_broadcast_received, 984'260);
  require(provider_calls == 0,
          "N6_DISABLED_INSTRUMENTATION_COST_FAILURE: disabled instrumentation evaluated the trace-id provider");

  auto sink = std::make_shared<BoundedTraceBuffer>(1, 2);
  install_sink(sink);
  record_trace_lazy(provider, TraceStage::peer_finality_verification_started);
  record_trace_lazy(provider, TraceStage::peer_finality_broadcast_received, 984'260);
  install_sink(nullptr);

  require(provider_calls == 2,
          "N6_DISABLED_INSTRUMENTATION_COST_FAILURE: enabled instrumentation did not evaluate each provider once");
  require(sink->event_count(trace_id(7)) == 2,
          "N6_DISABLED_INSTRUMENTATION_COST_FAILURE: enabled instrumentation did not record both trace events");
  ASSERT_TRUE(!sink->trace(trace_id(7))->front().exact_bytes.has_value());
  ASSERT_EQ(984'260u, sink->trace(trace_id(7))->back().exact_bytes.value());
}

}  // namespace
