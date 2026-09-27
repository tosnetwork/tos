/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "auto/tl/lite_api.h"
#include "auto/tl/tos_api.h"
#include "crypto/block/signature-set.h"
#include "td/utils/misc.h"
#include "tl-utils/lite-utils.hpp"
#include "tl-utils/tl-utils.hpp"

#include "block-signature-carrier-common.h"

namespace {

using block_signature_carrier_test::algorithm_id;
using block_signature_carrier_test::candidate;
using block_signature_carrier_test::catchain_seqno;
using block_signature_carrier_test::make_signatures;
using block_signature_carrier_test::session_id;
using block_signature_carrier_test::slot;
using block_signature_carrier_test::validator_set_hash;

[[noreturn]] void fail(const std::string& message) {
  std::fprintf(stderr, "%s\n", message.c_str());
  std::exit(1);
}

struct Case {
  std::string name;
  bool accept;
  std::string reason_code;
  std::string carrier;
  std::string role;
  td::uint32 cc_seqno;
  td::uint32 validator_hash;
  td::Bits256 validator_id;
  td::int32 algorithm;
  td::BufferSlice signature;
  td::Bits256 session;
  td::uint32 candidate_slot;
  td::BufferSlice candidate_bytes;
  td::BufferSlice wire;
};

std::vector<std::string> split(const std::string& line) {
  std::vector<std::string> result;
  std::istringstream input(line);
  std::string field;
  while (std::getline(input, field, '\t')) {
    result.push_back(std::move(field));
  }
  return result;
}

std::string line_for(const Case& item) {
  std::ostringstream out;
  out << item.name << '\t' << (item.accept ? "accept" : "reject") << '\t' << item.reason_code << '\t' << item.carrier
      << '\t' << item.role << '\t' << item.cc_seqno << '\t' << item.validator_hash << '\t' << item.validator_id.to_hex()
      << '\t' << item.algorithm << '\t' << td::hex_encode(item.signature.as_slice()) << '\t' << item.session.to_hex()
      << '\t' << item.candidate_slot << '\t' << td::hex_encode(item.candidate_bytes.as_slice()) << '\t'
      << td::hex_encode(item.wire.as_slice());
  return out.str();
}

td::BufferSlice node_wire(bool final, td::BufferSlice signature) {
  auto input = make_signatures(1, false);
  std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_pqBlockSignature>> pairs;
  pairs.push_back(tos::create_tl_object<tos::tos_api::tosNode_pqBlockSignature>(input[0].validator_id, algorithm_id,
                                                                                std::move(signature)));
  return tos::create_serialize_tl_object<tos::tos_api::tosNode_signatureSet_simplexPq>(
      final, catchain_seqno, validator_set_hash, std::move(pairs), session_id(), slot, candidate());
}

td::BufferSlice lite_wire(td::BufferSlice signature) {
  auto input = make_signatures(1, false);
  std::vector<tos::tl_object_ptr<tos::lite_api::liteServer_pqSignature>> pairs;
  pairs.push_back(tos::create_tl_object<tos::lite_api::liteServer_pqSignature>(input[0].validator_id, algorithm_id,
                                                                               std::move(signature)));
  return tos::create_serialize_tl_object<tos::lite_api::liteServer_signatureSet_simplexPq>(
      catchain_seqno, validator_set_hash, std::move(pairs), session_id(), slot,
      tos::serialize_tl_object(candidate(), true));
}

std::vector<Case> cases() {
  auto input = make_signatures(1, false);
  const auto candidate_bytes = tos::serialize_tl_object(candidate(), true);
  std::vector<Case> result;
  auto add = [&](std::string name, bool accept, std::string reason, std::string carrier, std::string role,
                 td::BufferSlice signature, td::BufferSlice wire) {
    result.push_back(Case{std::move(name), accept, std::move(reason), std::move(carrier), std::move(role),
                          catchain_seqno, validator_set_hash, input[0].validator_id, algorithm_id, std::move(signature),
                          session_id(), slot, candidate_bytes.clone(), std::move(wire)});
  };
  add("node-final", true, "-", "node", "final", input[0].signature.clone(),
      node_wire(true, input[0].signature.clone()));
  add("node-approve", true, "-", "node", "approve", input[0].signature.clone(),
      node_wire(false, input[0].signature.clone()));
  add("lite-final", true, "-", "lite", "final", input[0].signature.clone(), lite_wire(input[0].signature.clone()));
  td::BufferSlice short_signature(input[0].signature.size() - 1);
  std::memcpy(short_signature.data(), input[0].signature.data(), short_signature.size());
  add("node-short-signature", false, "signature_length", "node", "final", short_signature.clone(),
      node_wire(true, short_signature.clone()));
  add("lite-short-signature", false, "signature_length", "lite", "final", short_signature.clone(),
      lite_wire(short_signature.clone()));
  add("lite-refuses-node-approve", false, "wrong_constructor", "lite", "approve", input[0].signature.clone(),
      node_wire(false, input[0].signature.clone()));
  return result;
}

std::string checked_reason(const td::Status& error) {
  const auto message = error.message().str();
  if (message == "pq tl: signature_length") {
    return "signature_length";
  }
  fail("TL_VECTOR_UNKNOWN_REASON message=" + message);
}

void verify_internal(const Case& item, const td::Ref<block::BlockSignatureSet>& parsed) {
  if (parsed.is_null() || parsed->get_catchain_seqno() != item.cc_seqno ||
      parsed->get_validator_set_hash() != item.validator_hash || parsed->is_final() != (item.role == "final")) {
    fail("TL_VECTOR_METADATA_MISMATCH case=" + item.name);
  }
  auto signatures = parsed->export_pq_signatures();
  if (signatures.is_error() || signatures.ok().size() != 1 ||
      signatures.ok()[0].validator_id.value != item.validator_id ||
      static_cast<td::int32>(signatures.ok()[0].algorithm_id) != item.algorithm ||
      signatures.ok()[0].signature.as_slice() != item.signature.as_slice()) {
    fail("TL_VECTOR_SIGNATURE_MISMATCH case=" + item.name);
  }
  auto parsed_session = parsed->pq_session_id();
  auto parsed_slot = parsed->pq_slot();
  auto parsed_candidate = parsed->pq_candidate_data();
  if (parsed_session.is_error() || parsed_session.ok() != item.session || parsed_slot.is_error() ||
      parsed_slot.ok() != item.candidate_slot || parsed_candidate.is_error() ||
      parsed_candidate.ok().as_slice() != item.candidate_bytes.as_slice()) {
    fail("TL_VECTOR_CONTEXT_MISMATCH case=" + item.name);
  }
}

void check_case(const Case& item) {
  if (item.carrier == "node") {
    auto object = tos::fetch_tl_object<tos::tos_api::tosNode_SignatureSet>(item.wire.clone(), true);
    if (object.is_error()) {
      fail("TL_VECTOR_NODE_PARSE_FAILED case=" + item.name);
    }
    if (tos::serialize_tl_object(object.ok(), true).as_slice() != item.wire.as_slice()) {
      fail("TL_VECTOR_NODE_RESERIALIZE_MISMATCH case=" + item.name);
    }
    auto checked = block::BlockSignatureSet::fetch_pq_node_checked(object.ok());
    if (item.accept) {
      if (checked.is_error())
        fail("TL_VECTOR_UNEXPECTED_REJECT case=" + item.name);
      verify_internal(item, checked.ok());
    } else if (checked.is_ok() || checked_reason(checked.error()) != item.reason_code) {
      fail("TL_VECTOR_REASON_MISMATCH case=" + item.name + " expected=" + item.reason_code);
    }
    return;
  }

  auto object = tos::fetch_tl_object<tos::lite_api::liteServer_SignatureSet>(item.wire.clone(), true);
  if (object.is_error()) {
    if (item.reason_code == "wrong_constructor")
      return;
    fail("TL_VECTOR_LITE_PARSE_FAILED case=" + item.name);
  }
  if (tos::serialize_tl_object(object.ok(), true).as_slice() != item.wire.as_slice()) {
    fail("TL_VECTOR_LITE_RESERIALIZE_MISMATCH case=" + item.name);
  }
  auto checked = block::BlockSignatureSet::fetch_pq_lite_checked(object.ok());
  if (item.accept) {
    if (checked.is_error())
      fail("TL_VECTOR_UNEXPECTED_REJECT case=" + item.name);
    verify_internal(item, checked.ok());
  } else if (checked.is_ok() || checked_reason(checked.error()) != item.reason_code) {
    fail("TL_VECTOR_REASON_MISMATCH case=" + item.name + " expected=" + item.reason_code);
  }
}

}  // namespace

int main(int argc, char** argv) {
  const auto expected = cases();
  if (argc == 2 && std::string(argv[1]) == "--write") {
    std::ofstream output(VECTORS_FILE);
    output << "# case outcome reason_code carrier role cc_seqno validator_set_hash validator_id algorithm_id "
              "signature_hex session_id slot candidate_hex wire_hex\n";
    for (const auto& item : expected)
      output << line_for(item) << '\n';
    return output ? 0 : 1;
  }
  std::ifstream input(VECTORS_FILE);
  if (!input)
    fail("TL_VECTOR_FILE_MISSING");
  std::vector<std::string> lines;
  std::string line;
  while (std::getline(input, line))
    if (!line.empty() && line[0] != '#')
      lines.push_back(line);
  if (lines.size() != expected.size()) {
    fail("TL_VECTOR_ROW_COUNT expected=" + std::to_string(expected.size()) + " actual=" + std::to_string(lines.size()));
  }
  for (std::size_t i = 0; i < expected.size(); ++i) {
    if (lines[i] != line_for(expected[i]))
      fail("TL_VECTOR_CONTENT_MISMATCH case=" + expected[i].name);
    if (split(lines[i]).size() != 14)
      fail("TL_VECTOR_BAD_COLUMNS case=" + expected[i].name);
    check_case(expected[i]);
  }
  std::printf("PQ_SIGNATURE_TL_VECTORS_OK cases=%zu\n", expected.size());
  return 0;
}
