/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "auto/tl/lite_api.h"
#include "auto/tl/tos_api.h"
#include "crypto/block/pq-signature-limits.h"
#include "crypto/block/signature-set.h"
#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-bytes.h"
#include "td/utils/crypto.h"
#include "tl-utils/lite-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "validator/full-node-serializer.hpp"
#include "vm/boc-compression.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

namespace {

constexpr td::int32 algorithm_id = static_cast<td::int32>(tos::pq::PQAlgorithmId::mldsa44);
constexpr td::uint32 catchain_seqno = 1789434;
constexpr td::uint32 validator_set_hash = 0x91a2b3c4;
constexpr td::uint32 slot = 2718281;

[[noreturn]] void fail(const std::string& message) {
  std::fprintf(stderr, "%s\n", message.c_str());
  std::exit(1);
}

td::Bits256 hash_of(std::string_view text) {
  td::Bits256 result;
  td::sha256(td::Slice{text.data(), text.size()}, result.as_slice());
  return result;
}

tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate() {
  return tos::create_tl_object<tos::tos_api::consensus_candidateHashDataEmpty>(
      tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(-1, static_cast<td::int64>(0x8000000000000000ULL), 42,
                                                              hash_of("resource-root"), hash_of("resource-file")),
      tos::create_tl_object<tos::tos_api::consensus_candidateId>(slot - 1, hash_of("resource-parent")));
}

td::BufferSlice signature(std::size_t bytes = tos::pq::mldsa44_signature_bytes) {
  td::BufferSlice result(bytes);
  if (bytes != 0) {
    std::memset(result.data(), 0x5a, bytes);
  }
  return result;
}

tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet> node_set(std::size_t count, std::size_t signature_bytes,
                                                                td::int32 algorithm, bool duplicate = false) {
  std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_pqBlockSignature>> signatures;
  signatures.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    const auto identity =
        duplicate && i == 1 ? hash_of("node-validator-0") : hash_of("node-validator-" + std::to_string(i));
    signatures.push_back(
        tos::create_tl_object<tos::tos_api::tosNode_pqBlockSignature>(identity, algorithm, signature(signature_bytes)));
  }
  return tos::create_tl_object<tos::tos_api::tosNode_signatureSet_simplexPq>(
      true, catchain_seqno, validator_set_hash, std::move(signatures), hash_of("resource-session"), slot, candidate());
}

tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet> lite_set(std::size_t count, std::size_t signature_bytes,
                                                                    td::int32 algorithm, bool duplicate = false,
                                                                    td::BufferSlice candidate_bytes = {}) {
  std::vector<tos::tl_object_ptr<tos::lite_api::liteServer_pqSignature>> signatures;
  signatures.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    const auto identity =
        duplicate && i == 1 ? hash_of("lite-validator-0") : hash_of("lite-validator-" + std::to_string(i));
    signatures.push_back(
        tos::create_tl_object<tos::lite_api::liteServer_pqSignature>(identity, algorithm, signature(signature_bytes)));
  }
  if (candidate_bytes.empty()) {
    candidate_bytes = tos::serialize_tl_object(candidate(), true);
  }
  return tos::create_tl_object<tos::lite_api::liteServer_signatureSet_simplexPq>(
      catchain_seqno, validator_set_hash, std::move(signatures), hash_of("resource-session"), slot,
      std::move(candidate_bytes));
}

std::string reason_code(const td::Status& status) {
  const auto message = status.message().str();
  if (message == "pq tl: signer_count")
    return "signer_count";
  if (message == "pq tl: signature_length")
    return "signature_length";
  if (message == "pq tl: algorithm_range")
    return "algorithm_range";
  if (message == "pq tl: unsupported_algorithm")
    return "unsupported_algorithm";
  if (message == "pq signatures: duplicate validator_id")
    return "duplicate_validator_id";
  if (message == "pq tl: candidate_oversize")
    return "candidate_oversize";
  if (message.find("pq tl: candidate_invalid:") == 0)
    return "candidate_trailing_bytes";
  if (message == "pq candidate data: noncanonical chunk size")
    return "candidate_noncanonical_chain";
  fail("RESOURCE_GATE_UNKNOWN_REASON message=" + message);
}

void expect_node_reject(const std::string& name, const std::string& expected,
                        tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet> input) {
  auto wire = tos::serialize_tl_object(input, true);
  auto parsed = tos::fetch_tl_object<tos::tos_api::tosNode_SignatureSet>(wire.clone(), true);
  if (parsed.is_error()) {
    fail("RESOURCE_GATE_OUTER_PARSE case=" + name + " message=" + parsed.error().message().str());
  }
  tos::pq::reset_mldsa44_verification_calls_for_test();
  auto result = block::BlockSignatureSet::fetch_node_checked(parsed.ok());
  const auto calls = tos::pq::mldsa44_verification_calls_for_test();
  if (result.is_ok()) {
    fail("RESOURCE_GATE_UNEXPECTED_ACCEPT case=" + name);
  }
  if (reason_code(result.error()) != expected) {
    fail("RESOURCE_GATE_REASON case=" + name + " expected=" + expected + " actual=" + reason_code(result.error()));
  }
  if (calls != 0) {
    fail("RESOURCE_GATE_CRYPTO_CALLS case=" + name + " expected=0 actual=" + std::to_string(calls));
  }
  std::printf("RESOURCE_GATE case=%s reason=%s crypto_calls=%llu\n", name.c_str(), expected.c_str(),
              static_cast<unsigned long long>(calls));
}

void expect_lite_reject(const std::string& name, const std::string& expected,
                        tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet> input) {
  auto wire = tos::serialize_tl_object(input, true);
  auto parsed = tos::fetch_tl_object<tos::lite_api::liteServer_SignatureSet>(wire.clone(), true);
  if (parsed.is_error()) {
    fail("RESOURCE_GATE_OUTER_PARSE case=" + name + " message=" + parsed.error().message().str());
  }
  tos::pq::reset_mldsa44_verification_calls_for_test();
  auto result = block::BlockSignatureSet::fetch_lite_checked(parsed.ok());
  const auto calls = tos::pq::mldsa44_verification_calls_for_test();
  if (result.is_ok()) {
    fail("RESOURCE_GATE_UNEXPECTED_ACCEPT case=" + name);
  }
  if (reason_code(result.error()) != expected) {
    fail("RESOURCE_GATE_REASON case=" + name + " expected=" + expected + " actual=" + reason_code(result.error()));
  }
  if (calls != 0) {
    fail("RESOURCE_GATE_CRYPTO_CALLS case=" + name + " expected=0 actual=" + std::to_string(calls));
  }
  std::printf("RESOURCE_GATE case=%s reason=%s crypto_calls=%llu\n", name.c_str(), expected.c_str(),
              static_cast<unsigned long long>(calls));
}

td::Ref<vm::Cell> noncanonical_candidate_signature_set() {
  auto bytes = tos::serialize_tl_object(candidate(), true);
  vm::CellBuilder tail;
  tail.store_bytes(bytes.as_slice().substr(1));
  vm::CellBuilder head;
  head.store_bytes(bytes.as_slice().substr(0, 1));
  head.store_ref(tail.finalize_novm());

  auto signature_bytes = signature();
  auto packed = tos::pq::pack_pq_bytes(signature_bytes.as_slice(), tos::pq::mldsa44_signature_bytes);
  if (packed.is_error()) {
    fail("RESOURCE_GATE_PACK_SIGNATURE message=" + packed.error().message().str());
  }
  vm::CellBuilder pair;
  pair.store_bits(hash_of("persisted-validator").cbits(), 256);
  pair.store_long(algorithm_id, 16);
  pair.store_ref(packed.move_as_ok());
  vm::Dictionary dictionary{16};
  if (!dictionary.set_builder(td::BitArray<16>{static_cast<unsigned>(0)}, pair, vm::Dictionary::SetMode::Add)) {
    fail("RESOURCE_GATE_DICTIONARY");
  }

  vm::CellBuilder root;
  root.store_long(0x13, 8);
  root.store_long(validator_set_hash, 32);
  root.store_long(catchain_seqno, 32);
  root.store_long(1, 32);
  root.store_long(1, 64);
  root.store_maybe_ref(std::move(dictionary).extract_root_cell());
  root.store_bits(hash_of("resource-session").cbits(), 256);
  root.store_long(slot, 32);
  root.store_ref(head.finalize_novm());
  return root.finalize_novm();
}

void check_noncanonical_candidate_chain() {
  tos::pq::reset_mldsa44_verification_calls_for_test();
  tos::ValidatorWeight ignored_weight = 0;
  auto result = block::BlockSignatureSet::fetch(noncanonical_candidate_signature_set(), ignored_weight);
  const auto calls = tos::pq::mldsa44_verification_calls_for_test();
  if (result.is_ok() || reason_code(result.error()) != "candidate_noncanonical_chain") {
    fail("RESOURCE_GATE_REASON case=persisted-noncanonical-candidate-chain");
  }
  if (calls != 0) {
    fail("RESOURCE_GATE_CRYPTO_CALLS case=persisted-noncanonical-candidate-chain expected=0 actual=" +
         std::to_string(calls));
  }
  std::printf(
      "RESOURCE_GATE case=persisted-noncanonical-candidate-chain reason=candidate_noncanonical_chain "
      "crypto_calls=%llu\n",
      static_cast<unsigned long long>(calls));
}

void check_compressed_ordering() {
  auto invalid = node_set(1, tos::pq::mldsa44_signature_bytes - 1, algorithm_id);
  vm::CellBuilder data_builder;
  data_builder.store_long(0x42, 8);
  auto compressed = vm::boc_compress({data_builder.finalize_novm()}, vm::CompressionAlgorithm::ImprovedStructureLZ4);
  if (compressed.is_error()) {
    fail("COMPRESSED_ORDER_FIXTURE message=" + compressed.error().message().str());
  }
  auto id = tos::create_tl_object<tos::tos_api::tosNode_blockIdExt>(
      -1, static_cast<td::int64>(0x8000000000000000ULL), 42, hash_of("compressed-root"), hash_of("compressed-file"));
  auto broadcast = tos::create_tl_object<tos::tos_api::tosNode_blockBroadcastCompressedV2>(
      std::move(id), std::move(invalid), 0, td::BufferSlice("proof"), compressed.move_as_ok());
  tos::validator::fullnode::BlockBroadcastParseStats stats;
  tos::pq::reset_mldsa44_verification_calls_for_test();
  auto result = tos::validator::fullnode::deserialize_block_broadcast(*broadcast, 1 << 20, "resource-gate", {}, &stats);
  const auto calls = tos::pq::mldsa44_verification_calls_for_test();
  if (result.is_ok() || reason_code(result.error()) != "signature_length") {
    fail("COMPRESSED_ORDER_REASON");
  }
  if (stats.decompression_attempts != 0) {
    fail("COMPRESSED_ORDER_DECOMPRESSION expected=0 actual=" + std::to_string(stats.decompression_attempts));
  }
  if (calls != 0) {
    fail("COMPRESSED_ORDER_CRYPTO_CALLS expected=0 actual=" + std::to_string(calls));
  }
  std::printf("COMPRESSED_ORDER reason=signature_length decompression_attempts=%zu crypto_calls=%llu\n",
              stats.decompression_attempts, static_cast<unsigned long long>(calls));
}

void check_signature_volume() {
  auto pq = block::BlockSignatureSet::fetch_node_checked(node_set(1, tos::pq::mldsa44_signature_bytes, algorithm_id));
  if (pq.is_error()) {
    fail("SIGNATURE_VOLUME_PQ_PARSE message=" + pq.error().message().str());
  }
  auto pq_size = pq.ok()->get_signature_data_size();
  if (pq_size.is_error() || pq_size.ok() != 2460) {
    fail("SIGNATURE_VOLUME_PQ expected=2460");
  }

  std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_blockSignature>> signatures;
  signatures.push_back(
      tos::create_tl_object<tos::tos_api::tosNode_blockSignature>(hash_of("classical-validator"), signature(64)));
  tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet> classical =
      tos::create_tl_object<tos::tos_api::tosNode_signatureSet_ordinary>(catchain_seqno, validator_set_hash,
                                                                         std::move(signatures));
  auto parsed = block::BlockSignatureSet::fetch_node_checked(classical);
  if (parsed.is_error()) {
    fail("SIGNATURE_VOLUME_CLASSICAL_PARSE message=" + parsed.error().message().str());
  }
  auto classical_size = parsed.ok()->get_signature_data_size();
  if (classical_size.is_error() || classical_size.ok() != 100) {
    fail("SIGNATURE_VOLUME_CLASSICAL expected=100");
  }
  std::printf("SIGNATURE_VOLUME pq_pair=2460 classical_pair=100\n");
}

}  // namespace

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  expect_node_reject("node-401-signers", "signer_count", node_set(401, tos::pq::mldsa44_signature_bytes, algorithm_id));
  expect_lite_reject("lite-401-signers", "signer_count", lite_set(401, tos::pq::mldsa44_signature_bytes, algorithm_id));
  expect_node_reject("node-signature-2419", "signature_length",
                     node_set(1, tos::pq::mldsa44_signature_bytes - 1, algorithm_id));
  expect_lite_reject("lite-signature-2419", "signature_length",
                     lite_set(1, tos::pq::mldsa44_signature_bytes - 1, algorithm_id));
  expect_node_reject("node-signature-2421", "signature_length",
                     node_set(1, tos::pq::mldsa44_signature_bytes + 1, algorithm_id));
  expect_lite_reject("lite-signature-2421", "signature_length",
                     lite_set(1, tos::pq::mldsa44_signature_bytes + 1, algorithm_id));
  expect_node_reject("node-algorithm-above-u16", "algorithm_range",
                     node_set(1, tos::pq::mldsa44_signature_bytes, 65536));
  expect_lite_reject("lite-algorithm-above-u16", "algorithm_range",
                     lite_set(1, tos::pq::mldsa44_signature_bytes, 65536));
  expect_node_reject("node-unknown-u16-algorithm", "unsupported_algorithm",
                     node_set(1, tos::pq::mldsa44_signature_bytes, 2));
  expect_lite_reject("lite-unknown-u16-algorithm", "unsupported_algorithm",
                     lite_set(1, tos::pq::mldsa44_signature_bytes, 2));
  expect_node_reject("node-duplicate-validator", "duplicate_validator_id",
                     node_set(2, tos::pq::mldsa44_signature_bytes, algorithm_id, true));
  expect_lite_reject("lite-duplicate-validator", "duplicate_validator_id",
                     lite_set(2, tos::pq::mldsa44_signature_bytes, algorithm_id, true));

  td::BufferSlice oversize_candidate(block::pq::pq_candidate_data_max_bytes + 1);
  std::memset(oversize_candidate.data(), 0x3c, oversize_candidate.size());
  expect_lite_reject("lite-candidate-oversize", "candidate_oversize",
                     lite_set(1, tos::pq::mldsa44_signature_bytes, algorithm_id, false, std::move(oversize_candidate)));

  auto trailing_candidate = tos::serialize_tl_object(candidate(), true);
  const auto original_size = trailing_candidate.size();
  td::BufferSlice with_trailing(original_size + 4);
  std::memcpy(with_trailing.data(), trailing_candidate.data(), original_size);
  std::memset(with_trailing.data() + original_size, 0, 4);
  expect_lite_reject("lite-candidate-trailing-bytes", "candidate_trailing_bytes",
                     lite_set(1, tos::pq::mldsa44_signature_bytes, algorithm_id, false, std::move(with_trailing)));

  check_noncanonical_candidate_chain();
  check_compressed_ordering();
  check_signature_volume();
  return 0;
}
