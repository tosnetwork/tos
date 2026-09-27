/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "adnl/adnl-ext-limits.h"
#include "crypto/block/pq-signature-limits.h"
#include "crypto/block/signature-set.h"
#include "crypto/pq/mldsa44.h"
#include "overlay/broadcast-plumtree.hpp"
#include "td/utils/overloaded.h"
#include "tl-utils/lite-utils.hpp"
#include "tl-utils/tl-utils.hpp"

#include "block-signature-carrier-common.h"

namespace {

using namespace block_signature_carrier_test;

bool recorded_size_mismatch = false;

[[noreturn]] void fail(const std::string& message) {
  std::fprintf(stderr, "%s\n", message.c_str());
  std::exit(1);
}

std::vector<std::string> fields(const std::string& line) {
  std::vector<std::string> result;
  std::istringstream input(line);
  std::string field;
  while (std::getline(input, field, '\t')) {
    result.push_back(std::move(field));
  }
  return result;
}

std::size_t number(const std::string& value, const std::string& context) {
  std::size_t end = 0;
  const auto result = std::stoull(value, &end);
  if (end != value.size()) {
    fail("CARRIER_BAD_RECORDED_SIZE context=" + context + " value=" + value);
  }
  return result;
}

struct RecordedSize {
  std::size_t serialized_bytes;
  std::size_t carrier_maximum;
};

RecordedSize recorded_size(std::string_view object, std::size_t signers) {
  std::ifstream input(ROUTES_FILE);
  if (!input) {
    fail("CARRIER_ROUTE_TABLE_MISSING");
  }
  const auto subject = std::string(object) + "/" + std::to_string(signers);
  std::string line;
  while (std::getline(input, line)) {
    if (line.rfind("verdict\t", 0) != 0) {
      continue;
    }
    const auto row = fields(line);
    if (row.size() != 7 || row[1] != subject) {
      continue;
    }
    if (row[2].rfind("measured:", 0) != 0) {
      return {0, number(row[4], subject + " maximum")};
    }
    return {number(row[2].substr(9), subject + " bytes"), number(row[4], subject + " maximum")};
  }
  fail("CARRIER_ROUTE_ROW_MISSING subject=" + subject);
}

std::size_t recorded_signature_set_size(bool node, std::size_t signers) {
  std::ifstream input(MEASUREMENTS_FILE);
  if (!input) {
    fail("CARRIER_MEASUREMENTS_MISSING");
  }
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty() || line[0] == '#' || line.rfind("signers\t", 0) == 0) {
      continue;
    }
    const auto row = fields(line);
    if (row.size() == 11 && row[0] == std::to_string(signers)) {
      return number(row[node ? 6 : 7], "signature-set measurement");
    }
  }
  fail("CARRIER_MEASUREMENT_ROW_MISSING signers=" + std::to_string(signers));
}

void check_decoded_set(const td::Ref<block::BlockSignatureSet>& parsed, const std::vector<SignatureInput>& expected,
                       const std::string& route) {
  if (parsed.is_null() || !parsed->is_final() || parsed->get_catchain_seqno() != catchain_seqno ||
      parsed->get_validator_set_hash() != validator_set_hash) {
    fail("CARRIER_METADATA_MISMATCH route=" + route);
  }
  auto session = parsed->pq_session_id();
  auto parsed_slot = parsed->pq_slot();
  auto candidate_bytes = parsed->pq_candidate_data();
  auto signatures = parsed->export_pq_signatures();
  if (session.is_error() || session.ok() != session_id() || parsed_slot.is_error() || parsed_slot.ok() != slot ||
      candidate_bytes.is_error() ||
      candidate_bytes.ok().as_slice() != tos::serialize_tl_object(candidate(), true).as_slice() ||
      signatures.is_error() || signatures.ok().size() != expected.size()) {
    fail("CARRIER_AUTHORITY_FIELDS_MISMATCH route=" + route);
  }
  for (std::size_t i = 0; i < expected.size(); ++i) {
    const auto& actual = signatures.ok()[i];
    if (actual.validator_id.value != expected[i].validator_id ||
        static_cast<td::uint16>(actual.algorithm_id) != algorithm_id ||
        actual.signature.as_slice() != expected[i].signature.as_slice()) {
      fail("CARRIER_SIGNATURE_MISMATCH route=" + route + " signer=" + std::to_string(i));
    }
  }
}

void expect_signer_count_rejection(const td::Result<td::Ref<block::BlockSignatureSet>>& result,
                                   const std::string& route) {
  const auto calls = tos::pq::mldsa44_verification_calls_for_test();
  if (result.is_ok()) {
    fail("CARRIER_401_UNEXPECTED_ACCEPT route=" + route);
  }
  if (result.error().message() != "pq tl: signer_count") {
    fail("CARRIER_401_REASON route=" + route + " actual=" + result.error().message().str());
  }
  if (calls != 0) {
    fail("CARRIER_401_CRYPTO_CALLS route=" + route + " expected=0 actual=" + std::to_string(calls));
  }
  std::printf("CARRIER_NEGATIVE route=%s case=401-signers reason=signer_count crypto_calls=%llu\n", route.c_str(),
              static_cast<unsigned long long>(calls));
}

void check_node(std::size_t signers) {
  const auto valid = signers <= 100;
  const auto signatures = make_signatures(signers, valid);
  const auto signature_set = node_tl(signatures);
  const auto expected_inner = recorded_signature_set_size(true, signers);
  if (signature_set.size() != expected_inner) {
    fail("CARRIER_SIGNATURE_SET_SIZE_MISMATCH route=node signers=" + std::to_string(signers) +
         " recorded=" + std::to_string(expected_inner) + " actual=" + std::to_string(signature_set.size()));
  }
  auto payload = finality_broadcast_tl(signatures);
  if (signers == block::pq::pq_block_signatures_max_signers &&
      payload.size() != block::pq::pq_block_finality_broadcast_max_bytes) {
    fail("CARRIER_PENDING_BUDGET_SIZE_MISMATCH recorded=" +
         std::to_string(block::pq::pq_block_finality_broadcast_max_bytes) +
         " actual=" + std::to_string(payload.size()));
  }
  const auto recorded = recorded_size("complete-tosNode.blockFinalityBroadcast", signers);
  if (recorded.serialized_bytes != payload.size()) {
    std::fprintf(stderr, "CARRIER_RECORDED_SIZE_MISMATCH route=node signers=%zu recorded=%zu actual=%zu\n", signers,
                 recorded.serialized_bytes, payload.size());
    recorded_size_mismatch = true;
  }
  auto admission = tos::overlay::check_plumtree_payload_size(payload.size());
  if (admission.is_error()) {
    fail("CARRIER_ADMISSION route=node signers=" + std::to_string(signers) + " message=" + admission.message().str());
  }
  auto decoded = tos::fetch_tl_object<tos::tos_api::tosNode_Broadcast>(payload.clone(), true);
  if (decoded.is_error() || decoded.ok()->get_id() != tos::tos_api::tosNode_blockFinalityBroadcast::ID) {
    fail("CARRIER_OUTER_PARSE route=node signers=" + std::to_string(signers));
  }
  auto finality = tos::move_tl_object_as<tos::tos_api::tosNode_blockFinalityBroadcast>(decoded.move_as_ok());
  tos::pq::reset_mldsa44_verification_calls_for_test();
  auto parsed = block::BlockSignatureSet::fetch_node_checked(finality->signature_set_);
  if (parsed.is_error()) {
    fail("CARRIER_SIGNATURE_PARSE route=node signers=" + std::to_string(signers) +
         " message=" + parsed.error().message().str());
  }
  if (tos::pq::mldsa44_verification_calls_for_test() != 0) {
    fail("CARRIER_PARSE_CRYPTO_CALLS route=node");
  }
  check_decoded_set(parsed.ok(), signatures, "node");
  std::printf("CARRIER_VERDICT route=node signers=%zu bytes=%zu maximum=%zu headroom=%zu verdict=ADMITTED\n", signers,
              payload.size(), recorded.carrier_maximum, recorded.carrier_maximum - payload.size());
}

void check_lite(std::size_t signers) {
  const auto valid = signers <= 100;
  const auto signatures = make_signatures(signers, valid);
  const auto signature_set = lite_tl(signatures);
  const auto expected_inner = recorded_signature_set_size(false, signers);
  if (signature_set.size() != expected_inner) {
    fail("CARRIER_SIGNATURE_SET_SIZE_MISMATCH route=lite signers=" + std::to_string(signers) +
         " recorded=" + std::to_string(expected_inner) + " actual=" + std::to_string(signature_set.size()));
  }
  const auto answer_body = lite_forward_proof_tl(signatures);
  auto packet_payload = lite_answer_tl(signatures);
  const auto recorded = recorded_size("complete-lite-answer", signers);
  if (recorded.serialized_bytes != answer_body.size()) {
    std::fprintf(stderr, "CARRIER_RECORDED_SIZE_MISMATCH route=lite signers=%zu recorded=%zu actual=%zu\n", signers,
                 recorded.serialized_bytes, answer_body.size());
    recorded_size_mismatch = true;
  }
  auto admission = tos::adnl::check_adnl_ext_payload_size(packet_payload.size());
  if (admission.is_error()) {
    fail("CARRIER_ADMISSION route=lite signers=" + std::to_string(signers) + " message=" + admission.message().str());
  }
  auto answer = tos::fetch_tl_object<tos::tos_api::adnl_message_answer>(packet_payload.clone(), true);
  if (answer.is_error()) {
    fail("CARRIER_ANSWER_PARSE signers=" + std::to_string(signers));
  }
  auto proof = tos::fetch_tl_object<tos::lite_api::liteServer_partialBlockProof>(answer.ok()->answer_.clone(), true);
  if (proof.is_error() || proof.ok()->steps_.size() != 1 ||
      proof.ok()->steps_[0]->get_id() != tos::lite_api::liteServer_blockLinkForward::ID) {
    fail("CARRIER_OUTER_PARSE route=lite signers=" + std::to_string(signers));
  }
  auto& link = static_cast<tos::lite_api::liteServer_blockLinkForward&>(*proof.ok()->steps_[0]);
  tos::pq::reset_mldsa44_verification_calls_for_test();
  auto parsed = block::BlockSignatureSet::fetch_lite_checked(link.signatures_);
  if (parsed.is_error()) {
    fail("CARRIER_SIGNATURE_PARSE route=lite signers=" + std::to_string(signers) +
         " message=" + parsed.error().message().str());
  }
  if (tos::pq::mldsa44_verification_calls_for_test() != 0) {
    fail("CARRIER_PARSE_CRYPTO_CALLS route=lite");
  }
  check_decoded_set(parsed.ok(), signatures, "lite");
  std::printf(
      "CARRIER_VERDICT route=lite signers=%zu bytes=%zu packet_payload=%zu maximum=%zu headroom=%zu "
      "verdict=ADMITTED\n",
      signers, answer_body.size(), packet_payload.size(), recorded.carrier_maximum,
      recorded.carrier_maximum - answer_body.size());
}

void node_negatives() {
  const auto signatures = make_signatures(21, true);
  auto payload = finality_broadcast_tl(signatures);
  tos::pq::reset_mldsa44_verification_calls_for_test();
  auto limited = tos::overlay::check_plumtree_payload_size(payload.size(), payload.size() - 1);
  if (limited.is_ok() || limited.message() != "Plumtree payload exceeds admission limit") {
    fail("CARRIER_LIMIT_NEGATIVE route=node");
  }
  const auto limit_calls = tos::pq::mldsa44_verification_calls_for_test();
  if (limit_calls != 0) {
    fail("CARRIER_LIMIT_CRYPTO_CALLS route=node expected=0 actual=" + std::to_string(limit_calls));
  }
  std::printf("CARRIER_NEGATIVE route=node case=limit-below-required reason=payload_limit crypto_calls=%llu\n",
              static_cast<unsigned long long>(limit_calls));

  const auto too_many = make_signatures(401, false);
  auto oversized = finality_broadcast_tl(too_many);
  auto decoded = tos::fetch_tl_object<tos::tos_api::tosNode_Broadcast>(oversized.clone(), true);
  if (decoded.is_error()) {
    fail("CARRIER_401_OUTER_PARSE route=node");
  }
  auto finality = tos::move_tl_object_as<tos::tos_api::tosNode_blockFinalityBroadcast>(decoded.move_as_ok());
  tos::pq::reset_mldsa44_verification_calls_for_test();
  expect_signer_count_rejection(block::BlockSignatureSet::fetch_node_checked(finality->signature_set_), "node");
}

void lite_negatives() {
  const auto signatures = make_signatures(21, true);
  auto packet_payload = lite_answer_tl(signatures);
  tos::pq::reset_mldsa44_verification_calls_for_test();
  auto limited = tos::adnl::check_adnl_ext_payload_size(
      packet_payload.size(), packet_payload.size() + tos::adnl::adnl_ext_packet_framing_bytes - 1);
  if (limited.is_ok() || limited.message() != "ADNL external payload exceeds packet limit") {
    fail("CARRIER_LIMIT_NEGATIVE route=lite");
  }
  const auto limit_calls = tos::pq::mldsa44_verification_calls_for_test();
  if (limit_calls != 0) {
    fail("CARRIER_LIMIT_CRYPTO_CALLS route=lite expected=0 actual=" + std::to_string(limit_calls));
  }
  std::printf("CARRIER_NEGATIVE route=lite case=limit-below-required reason=packet_limit crypto_calls=%llu\n",
              static_cast<unsigned long long>(limit_calls));

  const auto too_many = make_signatures(401, false);
  auto answer = tos::fetch_tl_object<tos::tos_api::adnl_message_answer>(lite_answer_tl(too_many), true);
  if (answer.is_error()) {
    fail("CARRIER_401_ANSWER_PARSE route=lite");
  }
  auto proof = tos::fetch_tl_object<tos::lite_api::liteServer_partialBlockProof>(answer.ok()->answer_.clone(), true);
  if (proof.is_error() || proof.ok()->steps_.size() != 1 ||
      proof.ok()->steps_[0]->get_id() != tos::lite_api::liteServer_blockLinkForward::ID) {
    fail("CARRIER_401_OUTER_PARSE route=lite");
  }
  auto& link = static_cast<tos::lite_api::liteServer_blockLinkForward&>(*proof.ok()->steps_[0]);
  tos::pq::reset_mldsa44_verification_calls_for_test();
  expect_signer_count_rejection(block::BlockSignatureSet::fetch_lite_checked(link.signatures_), "lite");
}

}  // namespace

int main(int argc, char** argv) {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  if (argc != 2) {
    fail("usage: pq-carrier-capacity-test node|lite");
  }
  const std::string route = argv[1];
  if (route == "node") {
    std::printf(
        "CARRIER_GATE_SCOPE design_section=6.5 subject=node-finality-deliverability "
        "not_block_acceptance=1\n");
    for (const auto signers : {1U, 21U, 100U, 400U}) {
      check_node(signers);
    }
    node_negatives();
    if (recorded_size_mismatch) {
      fail("CARRIER_RECORDED_SIZE_GATE_FAILED route=node");
    }
    return 0;
  }
  if (route == "lite") {
    std::printf(
        "CARRIER_GATE_SCOPE design_section=6.5 subject=lite-forward-proof-deliverability "
        "not_chain_advancement=1 transport=adnl-ext-framed-tcp\n");
    for (const auto signers : {1U, 21U, 100U, 400U}) {
      check_lite(signers);
    }
    lite_negatives();
    if (recorded_size_mismatch) {
      fail("CARRIER_RECORDED_SIZE_GATE_FAILED route=lite");
    }
    return 0;
  }
  fail("unknown route: " + route);
}
