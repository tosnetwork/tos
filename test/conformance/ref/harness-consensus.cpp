// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// consensus harness: the deterministic parts of consensus that every implementation must reproduce
// exactly, run through the node's own functions (schema/harness/consensus-v1.schema.json). The field
// "op" selects one operation:
//
//   quorum             tos::quorum_threshold and tos::has_quorum on explicit weights
//   weight_total       tos::checked_add_validator_weight over a list of descriptor weights
//   protocol_version   the NewConsensusConfig predicates of a Simplex protocol version
//   session            block::validator_session_options_hash and derive_validator_session_identity
//   vote               BlockSignatureSet::build_simplex_data_to_sign, optionally verifying one ML-DSA-44
//                      signature under the Simplex signing context
//   validator_set      the short hash, total weight and quorum threshold of a block::ValidatorSet
//   finality           verify_pq_finality / verify_pq_proof_signatures against a trusted validator set and
//                      expected session, for the signatures of a BlockProof cell or an explicit signature set
//   key_block_context  the governing context of a masterchain block as the proof paths derive it from the
//                      previous key block: validator set, session inputs, and both session derivations
//   decode_proof       a BlockProof's block, the state transition of its Merkle header and its certificate
//   proof_link         block::BlockProofLink::validate for a forward link from a key block
//
// A refusal by node code is a verdict {"outcome": "refused", "reason": <class>}; the class is derived
// from the node's message by a fixed table, so two implementations agree on the class, not the wording.
// Malformed contexts (missing fields, bad hex, values the node's own types cannot hold) are harness
// errors instead.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "auto/tl/tos_api.hpp"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "block/check-proof.h"
#include "block/mc-config.h"
#include "block/signature-set.h"
#include "block/validator-session-id.h"
#include "common/checksum.h"
#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-consensus.h"
#include "td/utils/misc.h"
#include "tl-utils/common-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "tos/quorum.h"
#include "tos/tos-tl.hpp"
#include "validator/pq-finality-verification.h"
#include "vm/cells/MerkleProof.h"
#include "vm/cellslice.h"

#include "common.h"

namespace {

constexpr std::size_t kMaxValidators = 1024;
constexpr std::size_t kMaxWeights = 4096;
constexpr std::size_t kMaxHexBytes = 1u << 16;

// ---------------------------------------------------------------------------------------------------------
// Reason classes. The first entry whose text occurs in the node's message names the class.

struct ReasonRule {
  const char *text;
  const char *reason;
};

constexpr ReasonRule kReasonRules[] = {
    {"insufficient verified weight", "insufficient_weight"},
    {"too small sig weight", "insufficient_weight"},
    {"duplicate validator_id", "duplicate_signer"},
    {"duplicate node", "duplicate_signer"},
    {"unknown validator_id", "unknown_signer"},
    {"unknown node", "unknown_signer"},
    {"malformed verification input", "malformed_signature"},
    {"verification backend failure", "backend_failure"},
    {"invalid signature", "invalid_signature"},
    {"signature length", "signature_length"},
    {"unsupported algorithm", "unsupported_algorithm"},
    {"algorithm_range", "unsupported_algorithm"},
    {"validator algorithm mismatch", "algorithm_mismatch"},
    {"validator key_id mismatch", "key_id_mismatch"},
    {"malformed validator public key", "malformed_public_key"},
    {"validator is not post-quantum", "classical_validator"},
    {"classical signature offered for a post-quantum validator", "classical_signature"},
    {"carried session_id does not match", "session_mismatch"},
    {"catchain seqno mismatch", "catchain_seqno_mismatch"},
    {"validator set hash mismatch", "validator_set_hash_mismatch"},
    {"different from", "validator_set_hash_mismatch"},
    {"not final signatures", "role_mismatch"},
    {"not approve signatures", "role_mismatch"},
    {"block id mismatch", "block_mismatch"},
    {"bad signature set weight", "claimed_weight_mismatch"},
    {"signature weight mismatch", "claimed_weight_mismatch"},
    {"signer count exceeds maximum", "too_many_signers"},
    {"serialized bytes exceed maximum", "carrier_oversize"},
    {"mixed validator set", "carrier_mismatch"},
    {"unsupported carrier for post-quantum validator set", "carrier_mismatch"},
    {"post-quantum carrier for classical validator set", "carrier_mismatch"},
    {"post-quantum carrier required", "carrier_mismatch"},
    {"trusted expected session context is required", "carrier_mismatch"},
    {"weight overflow", "weight_overflow"},
    {"pq candidate data", "candidate_malformed"},
    {"simplex candidate data is null", "candidate_malformed"},
    {"incorrect is_key_block value", "key_block_flag_mismatch"},
    {"cannot compute validator set", "no_validator_set"},
    {"selected ConfigParam 30", "consensus_config_unavailable"},
    {"ConfigParam 30 protocol version is unsupported", "consensus_config_unavailable"},
    {"disagrees with ConfigParam 19", "global_id_mismatch"},
    {"cannot extract configuration", "config_unavailable"},
    {"incorrect root hash", "header_mismatch"},
    {"contains block id", "header_mismatch"},
    {"cannot unpack header", "header_mismatch"},
    {"cannot unpack block header", "header_mismatch"},
    {"invalid not_master flag", "header_mismatch"},
    {"Merkle", "proof_malformed"},
    {"virtualization error", "proof_malformed"},
    {"contains no", "proof_incomplete"},
    {"equal height", "link_direction"},
    {"incorrectly declared", "link_direction"},
    {"must have both source and destination blocks in the masterchain", "link_direction"},
    {"pq signatures:", "carrier_malformed"},
    {"failed to unpack signature set", "carrier_malformed"},
    {"block signatures:", "carrier_malformed"},
    {"noncanonical signatures dict", "carrier_malformed"},
    {"failed to parse signatures dict", "carrier_malformed"},
    {"signature count mismatch", "carrier_malformed"},
    {"invalid BlockProof", "carrier_malformed"},
};

std::string reason_class(td::Slice message) {
  for (const auto &rule : kReasonRules) {
    if (message.str().find(rule.text) != std::string::npos) {
      return rule.reason;
    }
  }
  return "unclassified";
}

std::string refused(const td::Status &status) {
  return "{\"outcome\":\"refused\",\"reason\":" + conformance::json_quote(reason_class(status.message())) + "}";
}

// ---------------------------------------------------------------------------------------------------------
// Context decoding. Kept private to this harness: the shared helpers in common.h cover BOCs and stacks.

std::string upper_hex(td::Slice bytes) {
  return td::buffer_to_hex(bytes);
}

std::string lower_hex(td::Slice bytes) {
  auto text = td::buffer_to_hex(bytes);
  std::transform(text.begin(), text.end(), text.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return text;
}

std::string bits_hex(const td::Bits256 &bits) {
  return upper_hex(bits.as_slice());
}

td::Result<std::string> decode_hex(td::Slice text, td::Slice field) {
  if (text.size() % 2 != 0 || text.size() / 2 > kMaxHexBytes) {
    return td::Status::Error(PSLICE() << field << ": hex of bounded even length required");
  }
  for (char c : text) {
    if (!td::is_hex_digit(c)) {
      return td::Status::Error(PSLICE() << field << ": hex required");
    }
  }
  auto bytes = td::hex_decode(text);
  if (bytes.is_error()) {
    return td::Status::Error(PSLICE() << field << ": hex required");
  }
  return bytes.move_as_ok();
}

td::Result<std::string> hex_field(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(text, obj.get_required_string_field(field));
  return decode_hex(text, field);
}

td::Result<td::Bits256> bits_field(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(bytes, hex_field(obj, field));
  if (bytes.size() != 32) {
    return td::Status::Error(PSLICE() << field << ": 32 bytes required");
  }
  td::Bits256 bits;
  std::memcpy(bits.data(), bytes.data(), 32);
  return bits;
}

td::Result<td::uint64> decimal_field(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(text, obj.get_required_string_field(field));
  if (text.empty() || text.size() > 20 || text.find_first_not_of("0123456789") != std::string::npos ||
      (text.size() > 1 && text[0] == '0')) {
    return td::Status::Error(PSLICE() << field << ": canonical unsigned decimal required");
  }
  auto value = td::to_integer_safe<td::uint64>(text);
  if (value.is_error()) {
    return td::Status::Error(PSLICE() << field << ": value out of range");
  }
  return value.move_as_ok();
}

td::Result<td::uint32> uint32_field(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(value, obj.get_required_long_field(field));
  if (value < 0 || value > 0xffffffffLL) {
    return td::Status::Error(PSLICE() << field << ": 0..2^32-1 required");
  }
  return static_cast<td::uint32>(value);
}

td::Result<td::JsonObject *> object_field(td::JsonObject &obj, td::Slice field, td::JsonValue &holder) {
  TRY_RESULT_ASSIGN(holder, obj.extract_required_field(field, td::JsonValue::Type::Object));
  return &holder.get_object();
}

td::Result<tos::ShardId> shard_text(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(bytes, hex_field(obj, field));
  if (bytes.size() != 8) {
    return td::Status::Error(PSLICE() << field << ": 16 hex digits required");
  }
  tos::ShardId shard = 0;
  for (unsigned char c : bytes) {
    shard = (shard << 8) | c;
  }
  if (shard == 0) {
    return td::Status::Error(PSLICE() << field << ": zero is not a shard");
  }
  return shard;
}

td::Result<tos::ShardIdFull> parse_shard(td::JsonObject &obj) {
  TRY_RESULT(workchain, obj.get_required_int_field("workchain"));
  TRY_RESULT(shard, shard_text(obj, "shard"));
  return tos::ShardIdFull{workchain, shard};
}

td::Result<tos::BlockIdExt> parse_block_id(td::JsonObject &ctx, td::Slice field) {
  td::JsonValue holder;
  TRY_RESULT(obj, object_field(ctx, field, holder));
  TRY_RESULT(shard, parse_shard(*obj));
  TRY_RESULT(seqno, uint32_field(*obj, "seqno"));
  TRY_RESULT(root_hash, bits_field(*obj, "root_hash"));
  TRY_RESULT(file_hash, bits_field(*obj, "file_hash"));
  return tos::BlockIdExt{shard.workchain, shard.shard, seqno, root_hash, file_hash};
}

std::string decimal(td::uint64 value) {
  return "\"" + std::to_string(value) + "\"";
}

// Doubles of the session options round-trip through JSON with 17 significant digits.
std::string double_json(double value) {
  char buffer[40];
  std::snprintf(buffer, sizeof buffer, "%.17g", value);
  std::string text = buffer;
  if (text.find_first_of(".eE") == std::string::npos) {
    text += ".0";
  }
  return text;
}

// A descriptor list, as the node holds it after decoding a validator set. ValidatorSet aborts on a zero
// weight, an overflowing total or a repeated identity, so those are refused here, as the decoder would.
td::Result<std::vector<tos::ValidatorDescr>> parse_validators(td::JsonObject &ctx) {
  TRY_RESULT(list_value, ctx.extract_required_field("validators", td::JsonValue::Type::Array));
  auto &list = list_value.get_array();
  if (list.empty() || list.size() > kMaxValidators) {
    return td::Status::Error("validators: 1..1024 descriptors required");
  }
  std::vector<tos::ValidatorDescr> result;
  result.reserve(list.size());
  std::set<td::Bits256> ids;
  std::set<td::Bits256> key_ids;
  tos::ValidatorWeight total = 0;
  for (auto &item : list) {
    if (item.type() != td::JsonValue::Type::Object) {
      return td::Status::Error("validators: descriptor object required");
    }
    auto &descr = item.get_object();
    TRY_RESULT(weight, decimal_field(descr, "weight"));
    TRY_RESULT(adnl, bits_field(descr, "adnl"));
    if (!tos::checked_add_validator_weight(total, weight)) {
      return td::Status::Error("validators: zero weight or total above the protocol cap");
    }
    if (descr.has_field("ed25519")) {
      TRY_RESULT(key, bits_field(descr, "ed25519"));
      tos::ValidatorDescr classical{tos::Ed25519_PublicKey{key}, weight, adnl};
      const auto id = block::classical_validator_id(classical.classical_key()).value;
      if (!ids.insert(id).second || !key_ids.insert(id).second) {
        return td::Status::Error("validators: repeated identity");
      }
      result.push_back(std::move(classical));
      continue;
    }
    TRY_RESULT(validator_id, bits_field(descr, "validator_id"));
    TRY_RESULT(key_id, bits_field(descr, "key_id"));
    TRY_RESULT(algorithm_id, descr.get_required_int_field("algorithm_id"));
    TRY_RESULT(public_key, hex_field(descr, "public_key"));
    if (algorithm_id <= 0 || algorithm_id > 0xffff) {
      return td::Status::Error("validators: algorithm_id must be 1..65535");
    }
    if (!ids.insert(validator_id).second || !key_ids.insert(key_id).second) {
      return td::Status::Error("validators: repeated identity");
    }
    result.emplace_back(tos::ValidatorId{validator_id}, static_cast<td::uint16>(algorithm_id),
                        tos::ConsensusKeyId{key_id}, std::move(public_key), weight, adnl);
  }
  return result;
}

std::string validators_json(const std::vector<tos::ValidatorDescr> &validators) {
  std::string out = "[";
  for (std::size_t i = 0; i < validators.size(); i++) {
    const auto &v = validators[i];
    out += i == 0 ? "{" : ",{";
    if (v.is_pq()) {
      out += "\"validator_id\":\"" + bits_hex(v.validator_id.value) + "\",\"key_id\":\"" + bits_hex(v.key_id.value) +
             "\",\"algorithm_id\":" + std::to_string(v.algorithm_id) + ",\"public_key\":\"" +
             lower_hex(v.pq_public_key) + "\"";
    } else {
      out += "\"ed25519\":\"" + bits_hex(v.classical_key().as_bits256()) + "\"";
    }
    out += ",\"weight\":" + decimal(v.weight) + ",\"adnl\":\"" + bits_hex(v.addr) + "\"}";
  }
  return out + "]";
}

td::Result<tos::ValidatorSessionConfig> parse_options(td::JsonObject &ctx) {
  td::JsonValue holder;
  TRY_RESULT(obj, object_field(ctx, "options", holder));
  tos::ValidatorSessionConfig config;
  TRY_RESULT_ASSIGN(config.proto_version, uint32_field(*obj, "proto_version"));
  TRY_RESULT_ASSIGN(config.new_catchain_ids, obj->get_required_bool_field("new_catchain_ids"));
  TRY_RESULT_ASSIGN(config.catchain_opts.idle_timeout, obj->get_required_double_field("idle_timeout"));
  TRY_RESULT_ASSIGN(config.catchain_opts.max_deps, uint32_field(*obj, "max_deps"));
  TRY_RESULT_ASSIGN(config.catchain_opts.max_serialized_block_size, uint32_field(*obj, "max_serialized_block_size"));
  TRY_RESULT_ASSIGN(config.catchain_opts.block_hash_covers_data,
                    obj->get_required_bool_field("block_hash_covers_data"));
  TRY_RESULT(coeff, uint32_field(*obj, "max_block_height_coeff"));
  config.catchain_opts.max_block_height_coeff = coeff;
  TRY_RESULT_ASSIGN(config.catchain_opts.debug_disable_db, obj->get_required_bool_field("debug_disable_db"));
  TRY_RESULT_ASSIGN(config.round_candidates, uint32_field(*obj, "round_candidates"));
  TRY_RESULT_ASSIGN(config.next_candidate_delay, obj->get_required_double_field("next_candidate_delay"));
  TRY_RESULT_ASSIGN(config.round_attempt_duration, uint32_field(*obj, "round_attempt_duration"));
  TRY_RESULT_ASSIGN(config.max_round_attempts, uint32_field(*obj, "max_round_attempts"));
  TRY_RESULT_ASSIGN(config.max_block_size, uint32_field(*obj, "max_block_size"));
  TRY_RESULT_ASSIGN(config.max_collated_data_size, uint32_field(*obj, "max_collated_data_size"));
  return config;
}

std::string options_json(const tos::ValidatorSessionConfig &c) {
  const auto &cc = c.catchain_opts;
  return "{\"proto_version\":" + std::to_string(c.proto_version) +
         ",\"new_catchain_ids\":" + conformance::json_bool(c.new_catchain_ids) +
         ",\"idle_timeout\":" + double_json(cc.idle_timeout) + ",\"max_deps\":" + std::to_string(cc.max_deps) +
         ",\"max_serialized_block_size\":" + std::to_string(cc.max_serialized_block_size) +
         ",\"block_hash_covers_data\":" + conformance::json_bool(cc.block_hash_covers_data) +
         ",\"max_block_height_coeff\":" + std::to_string(cc.max_block_height_coeff) +
         ",\"debug_disable_db\":" + conformance::json_bool(cc.debug_disable_db) +
         ",\"round_candidates\":" + std::to_string(c.round_candidates) +
         ",\"next_candidate_delay\":" + double_json(c.next_candidate_delay) +
         ",\"round_attempt_duration\":" + std::to_string(c.round_attempt_duration) +
         ",\"max_round_attempts\":" + std::to_string(c.max_round_attempts) +
         ",\"max_block_size\":" + std::to_string(c.max_block_size) +
         ",\"max_collated_data_size\":" + std::to_string(c.max_collated_data_size) + "}";
}

using CandidateRef = tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>;

td::Result<CandidateRef> parse_candidate(td::Slice bytes) {
  auto candidate = tos::fetch_tl_object<tos::tos_api::consensus_CandidateHashData>(bytes, true);
  if (candidate.is_error()) {
    return td::Status::Error("pq candidate data: not a CandidateHashData object");
  }
  return candidate.move_as_ok();
}

td::Result<block::FinalityRole> parse_role(td::JsonObject &ctx) {
  TRY_RESULT(role, ctx.get_required_string_field("role"));
  if (role == "final") {
    return block::FinalityRole::Final;
  }
  if (role == "approve") {
    return block::FinalityRole::Approve;
  }
  return td::Status::Error("role must be final or approve");
}

// ---------------------------------------------------------------------------------------------------------
// Operations.

td::Result<std::string> op_quorum(td::JsonObject &ctx) {
  TRY_RESULT(total, decimal_field(ctx, "total_weight"));
  TRY_RESULT(signed_weight, decimal_field(ctx, "signed_weight"));
  const auto threshold = tos::quorum_threshold(total);
  const auto portable = tos::quorum_threshold_portable(total);
  if (threshold != portable) {
    return td::Status::Error("wide and portable quorum thresholds disagree");
  }
  return "{\"outcome\":\"quorum\",\"threshold\":" + decimal(threshold) +
         ",\"has_quorum\":" + conformance::json_bool(tos::has_quorum(signed_weight, total)) + "}";
}

td::Result<std::string> op_weight_total(td::JsonObject &ctx) {
  TRY_RESULT(list_value, ctx.extract_required_field("weights", td::JsonValue::Type::Array));
  auto &list = list_value.get_array();
  if (list.size() > kMaxWeights) {
    return td::Status::Error("weights: at most 4096 entries");
  }
  tos::ValidatorWeight total = 0;
  for (auto &item : list) {
    if (item.type() != td::JsonValue::Type::String) {
      return td::Status::Error("weights: decimal strings required");
    }
    auto text = item.get_string().str();
    if (text.empty() || text.size() > 20 || text.find_first_not_of("0123456789") != std::string::npos ||
        (text.size() > 1 && text[0] == '0')) {
      return td::Status::Error("weights: canonical unsigned decimal required");
    }
    auto value = td::to_integer_safe<td::uint64>(text);
    if (value.is_error()) {
      return td::Status::Error("weights: value out of range");
    }
    if (!tos::checked_add_validator_weight(total, value.ok())) {
      return std::string("{\"outcome\":\"refused\",\"reason\":\"weight_refused\"}");
    }
  }
  return "{\"outcome\":\"weight_total\",\"total\":" + decimal(total) + "}";
}

td::Result<std::string> op_protocol_version(td::JsonObject &ctx) {
  tos::NewConsensusConfig config;
  TRY_RESULT_ASSIGN(config.protocol_version, uint32_field(ctx, "protocol_version"));
  return "{\"outcome\":\"protocol_version\",\"supported\":" +
         conformance::json_bool(config.protocol_version_supported()) +
         ",\"enable_block_sync\":" + conformance::json_bool(config.enable_block_sync()) +
         ",\"use_new_db_names\":" + conformance::json_bool(config.use_new_db_names()) +
         ",\"observers_in_private_overlay\":" + conformance::json_bool(config.observers_in_private_overlay()) +
         ",\"enable_plumtree_broadcast\":" + conformance::json_bool(config.enable_plumtree_broadcast()) +
         ",\"max_supported\":" + std::to_string(tos::NewConsensusConfig::MAX_SUPPORTED_PROTOCOL_VERSION) + "}";
}

td::Result<std::string> op_session(td::JsonObject &ctx) {
  TRY_RESULT(global_id, ctx.get_required_int_field("global_id"));
  TRY_RESULT(options, parse_options(ctx));
  TRY_RESULT(simplex_hash, bits_field(ctx, "simplex_config_hash"));
  td::JsonValue shard_holder;
  TRY_RESULT(shard_obj, object_field(ctx, "shard", shard_holder));
  TRY_RESULT(shard, parse_shard(*shard_obj));
  TRY_RESULT(catchain_seqno, uint32_field(ctx, "catchain_seqno"));
  TRY_RESULT(vertical_seqno, uint32_field(ctx, "vertical_seqno"));
  TRY_RESULT(last_key_block_seqno, uint32_field(ctx, "last_key_block_seqno"));
  TRY_RESULT(validators, parse_validators(ctx));
  const auto options_hash = block::validator_session_options_hash(options);
  const auto identity =
      block::derive_validator_session_identity(global_id, options_hash, simplex_hash, shard, catchain_seqno, validators,
                                               vertical_seqno, last_key_block_seqno, options.new_catchain_ids);
  return "{\"outcome\":\"session\",\"options_hash\":\"" + bits_hex(options_hash) + "\",\"session_config_hash\":\"" +
         bits_hex(identity.session_config_hash) + "\",\"session_id\":\"" + bits_hex(identity.session_id) + "\"}";
}

td::Result<std::string> op_vote(td::JsonObject &ctx) {
  TRY_RESULT(session_id, bits_field(ctx, "session_id"));
  TRY_RESULT(slot, uint32_field(ctx, "slot"));
  TRY_RESULT(candidate_bytes, hex_field(ctx, "candidate"));
  TRY_RESULT(final, ctx.get_required_bool_field("final"));
  TRY_RESULT(block_id, parse_block_id(ctx, "block"));
  const bool has_public_key = ctx.has_field("public_key");
  if (has_public_key != ctx.has_field("signature")) {
    return td::Status::Error("public_key and signature go together");
  }
  auto candidate = parse_candidate(candidate_bytes);
  if (candidate.is_error()) {
    return refused(candidate.error());
  }
  const td::Bits256 candidate_hash{tos::get_tl_object_sha256(candidate.ok()).raw};
  auto data = block::BlockSignatureSet::build_simplex_data_to_sign(session_id, slot, candidate.ok(), final, block_id);
  if (data.is_error()) {
    return refused(data.error());
  }
  std::string check = "null";
  if (has_public_key) {
    TRY_RESULT(public_key, hex_field(ctx, "public_key"));
    TRY_RESULT(signature, hex_field(ctx, "signature"));
    const auto message = data.ok().as_slice();
    // The verification of one Simplex vote: PeerValidator::check_signature and the PQ carrier both verify
    // the dataToSign bytes under the frozen Simplex signing context with the key the set records.
    switch (tos::pq::verify_mldsa44(std::string_view(message.data(), message.size()), tos::pq::simplex_sign_context,
                                    signature, public_key)) {
      case tos::pq::VerifyResult::valid:
        check = "\"valid\"";
        break;
      case tos::pq::VerifyResult::invalid:
        check = "\"invalid\"";
        break;
      case tos::pq::VerifyResult::malformed_input:
        check = "\"malformed\"";
        break;
      case tos::pq::VerifyResult::backend_error:
        return td::Status::Error("ML-DSA-44 backend failure");
    }
  }
  return "{\"outcome\":\"vote\",\"candidate_hash\":\"" + bits_hex(candidate_hash) + "\",\"data_to_sign\":\"" +
         lower_hex(data.ok().as_slice()) + "\",\"signature_check\":" + check + "}";
}

struct ParsedProof {
  tos::BlockIdExt proof_for;
  td::Ref<vm::Cell> root;
  td::Ref<vm::Cell> signatures;
};

// A BlockProof cell: block_proof#c3 proof_for:BlockIdExt root:^Cell signatures:(Maybe ^BlockSignatures).
td::Result<ParsedProof> parse_block_proof(td::Ref<vm::Cell> cell) {
  block::gen::BlockProof::Record proof;
  ParsedProof result;
  if (!(tlb::unpack_cell(cell, proof) && block::tlb::t_BlockIdExt.unpack(proof.proof_for.write(), result.proof_for))) {
    return td::Status::Error("invalid BlockProof");
  }
  result.root = proof.root;
  result.signatures = proof.signatures->prefetch_ref();
  return result;
}

// An explicit PQ signature set: the fields of the block_signatures_simplex_pq carrier.
td::Result<td::Ref<block::BlockSignatureSet>> explicit_signature_set(td::JsonObject &ctx, block::FinalityRole role,
                                                                     td::Status &refusal) {
  td::JsonValue holder;
  TRY_RESULT(set, object_field(ctx, "signature_set", holder));
  TRY_RESULT(catchain_seqno, uint32_field(*set, "catchain_seqno"));
  TRY_RESULT(validator_set_hash, uint32_field(*set, "validator_set_hash"));
  TRY_RESULT(session_id, bits_field(*set, "session_id"));
  TRY_RESULT(slot, uint32_field(*set, "slot"));
  TRY_RESULT(candidate_bytes, hex_field(*set, "candidate"));
  TRY_RESULT(list_value, set->extract_required_field("signatures", td::JsonValue::Type::Array));
  auto &list = list_value.get_array();
  if (list.size() > kMaxValidators) {
    return td::Status::Error("signature_set.signatures: at most 1024 entries");
  }
  std::vector<block::PQBlockSignature> signatures;
  for (auto &item : list) {
    if (item.type() != td::JsonValue::Type::Object) {
      return td::Status::Error("signature_set.signatures: objects required");
    }
    auto &obj = item.get_object();
    TRY_RESULT(validator_id, bits_field(obj, "validator_id"));
    TRY_RESULT(algorithm_id, obj.get_required_int_field("algorithm_id"));
    TRY_RESULT(signature, hex_field(obj, "signature"));
    if (algorithm_id < 0 || algorithm_id > 0xffff) {
      return td::Status::Error("signature_set.signatures: algorithm_id must be 0..65535");
    }
    signatures.push_back(block::PQBlockSignature{
        tos::ValidatorId{validator_id}, static_cast<tos::pq::PQAlgorithmId>(algorithm_id), td::BufferSlice(signature)});
  }
  auto candidate = parse_candidate(candidate_bytes);
  if (candidate.is_error()) {
    refusal = candidate.move_as_error();
    return td::Ref<block::BlockSignatureSet>{};
  }
  auto created =
      role == block::FinalityRole::Final
          ? block::BlockSignatureSet::create_simplex_pq_final(std::move(signatures), catchain_seqno, validator_set_hash,
                                                              session_id, slot, candidate.move_as_ok())
          : block::BlockSignatureSet::create_simplex_pq_approve(
                std::move(signatures), catchain_seqno, validator_set_hash, session_id, slot, candidate.move_as_ok());
  if (created.is_error()) {
    refusal = created.move_as_error();
    return td::Ref<block::BlockSignatureSet>{};
  }
  return created.move_as_ok();
}

td::Result<std::string> op_finality(td::JsonObject &ctx) {
  TRY_RESULT(validators, parse_validators(ctx));
  TRY_RESULT(catchain_seqno, uint32_field(ctx, "catchain_seqno"));
  TRY_RESULT(block_id, parse_block_id(ctx, "block"));
  TRY_RESULT(expected_session, bits_field(ctx, "expected_session_id"));
  TRY_RESULT(role, parse_role(ctx));
  const bool has_proof = ctx.has_field("block_proof");
  if (has_proof == ctx.has_field("signature_set")) {
    return td::Status::Error("exactly one of block_proof and signature_set is required");
  }
  td::Ref<block::ValidatorSet> vset{true, catchain_seqno, block_id.shard_full(), std::move(validators)};

  td::Ref<block::BlockSignatureSet> set;
  bool has_claim = false;
  tos::ValidatorWeight claimed = 0;
  td::Status refusal;
  if (has_proof) {
    // As CheckProof reads a proof's signature envelope: the carrier states the weight it claims.
    TRY_RESULT(cell, conformance::required_boc(ctx, "block_proof"));
    auto proof = parse_block_proof(cell);
    if (proof.is_error()) {
      return refused(proof.error());
    }
    if (proof.ok().signatures.is_null()) {
      return refused(td::Status::Error("block proof contains no signatures"));
    }
    auto fetched = block::BlockSignatureSet::fetch(proof.ok().signatures, claimed);
    if (fetched.is_error()) {
      return refused(fetched.error());
    }
    set = fetched.move_as_ok();
    has_claim = true;
  } else {
    TRY_RESULT_ASSIGN(set, explicit_signature_set(ctx, role, refusal));
    if (refusal.is_error()) {
      return refused(refusal);
    }
    if (ctx.has_field("claimed_weight")) {
      TRY_RESULT_ASSIGN(claimed, decimal_field(ctx, "claimed_weight"));
      has_claim = true;
    }
  }
  const block::PQFinalityVerificationContext context{vset, block_id, expected_session};
  // A final set with a claimed weight goes through the validator's proof check, which also requires the
  // claim to equal the verified weight; anything else through the verification boundary itself.
  auto verified = role == block::FinalityRole::Final && has_claim
                      ? tos::validator::verify_pq_proof_signatures(context, *set, claimed)
                      : block::verify_pq_finality(context, *set, role);
  if (verified.is_error()) {
    return refused(verified.error());
  }
  return "{\"outcome\":\"finalized\",\"weight\":" + decimal(verified.ok()) +
         ",\"total_weight\":" + decimal(vset->get_total_weight()) +
         ",\"threshold\":" + decimal(tos::quorum_threshold(vset->get_total_weight())) + "}";
}

// The decoded form of a PQ carrier: the same fields an explicit signature_set context gives.
td::Result<std::string> signature_set_json(const block::BlockSignatureSet &set) {
  if (!set.is_pq()) {
    return std::string("null");
  }
  TRY_RESULT(signatures, set.export_pq_signatures());
  TRY_RESULT(session_id, set.pq_session_id());
  TRY_RESULT(slot, set.pq_slot());
  TRY_RESULT(candidate, set.pq_candidate_data());
  std::string out = "{\"final\":" + conformance::json_bool(set.is_final()) +
                    ",\"catchain_seqno\":" + std::to_string(set.get_catchain_seqno()) +
                    ",\"validator_set_hash\":" + std::to_string(set.get_validator_set_hash()) + ",\"session_id\":\"" +
                    bits_hex(session_id) + "\",\"slot\":" + std::to_string(slot) + ",\"candidate\":\"" +
                    lower_hex(candidate.as_slice()) + "\",\"signatures\":[";
  for (std::size_t i = 0; i < signatures.size(); i++) {
    out += (i == 0 ? "{" : ",{");
    out += "\"validator_id\":\"" + bits_hex(signatures[i].validator_id.value) +
           "\",\"algorithm_id\":" + std::to_string(static_cast<int>(signatures[i].algorithm_id)) + ",\"signature\":\"" +
           lower_hex(signatures[i].signature.as_slice()) + "\"}";
  }
  return out + "]}";
}

// The set the node builds from decoded descriptors: its short hash (block headers commit to it), total
// weight and the quorum threshold over that total.
td::Result<std::string> op_validator_set(td::JsonObject &ctx) {
  TRY_RESULT(validators, parse_validators(ctx));
  TRY_RESULT(catchain_seqno, uint32_field(ctx, "catchain_seqno"));
  td::JsonValue shard_holder;
  TRY_RESULT(shard_obj, object_field(ctx, "shard", shard_holder));
  TRY_RESULT(shard, parse_shard(*shard_obj));
  td::Ref<block::ValidatorSet> vset{true, catchain_seqno, shard, std::move(validators)};
  return "{\"outcome\":\"validator_set\",\"validator_set_hash\":" + std::to_string(vset->get_validator_set_hash()) +
         ",\"total_weight\":" + decimal(vset->get_total_weight()) +
         ",\"threshold\":" + decimal(tos::quorum_threshold(vset->get_total_weight())) + "}";
}

// A BlockProof as a validator stores it: the block it proves, the state transition its Merkle header
// declares (as CheckProof reads it) and the decoded finality certificate.
td::Result<std::string> op_decode_proof(td::JsonObject &ctx) {
  TRY_RESULT(cell, conformance::required_boc(ctx, "block_proof"));
  auto proof = parse_block_proof(cell);
  if (proof.is_error()) {
    return refused(proof.error());
  }
  const auto &id = proof.ok().proof_for;
  auto root = vm::MerkleProof::virtualize(proof.ok().root);
  if (root.is_error()) {
    return refused(root.error());
  }
  auto header = block::check_block_header(root.ok(), id);
  if (header.is_error()) {
    return refused(header);
  }
  block::gen::Block::Record blk;
  if (!tlb::unpack_cell(root.ok(), blk)) {
    return refused(td::Status::Error("cannot unpack header"));
  }
  vm::CellSlice update{vm::NoVm(), blk.state_update};
  if (!(update.is_special() && update.prefetch_long(8) == 4 && update.size_ext() == 0x20228)) {
    return refused(td::Status::Error("invalid Merkle update in block header"));
  }
  const td::Bits256 old_hash{update.prefetch_ref(0)->get_hash(0).bits()};
  const td::Bits256 new_hash{update.prefetch_ref(1)->get_hash(0).bits()};
  std::string signature_set = "null";
  std::string claimed = "null";
  if (proof.ok().signatures.not_null()) {
    tos::ValidatorWeight claimed_weight = 0;
    auto decoded = block::BlockSignatureSet::fetch(proof.ok().signatures, claimed_weight);
    if (decoded.is_error()) {
      return refused(decoded.error());
    }
    TRY_RESULT_ASSIGN(signature_set, signature_set_json(*decoded.ok()));
    claimed = decimal(claimed_weight);
  }
  return "{\"outcome\":\"proof\",\"seqno\":" + std::to_string(id.id.seqno) + ",\"root_hash\":\"" +
         bits_hex(id.root_hash) + "\",\"file_hash\":\"" + bits_hex(id.file_hash) + "\",\"state_old_hash\":\"" +
         bits_hex(old_hash) + "\",\"state_hash\":\"" + bits_hex(new_hash) + "\",\"signature_set\":" + signature_set +
         ",\"claimed_weight\":" + claimed + "}";
}

td::Result<std::string> op_proof_link(td::JsonObject &ctx) {
  TRY_RESULT(from, parse_block_id(ctx, "key_block"));
  TRY_RESULT(to, parse_block_id(ctx, "block"));
  TRY_RESULT(is_key, ctx.get_required_bool_field("is_key"));
  TRY_RESULT(key_proof_cell, conformance::required_boc(ctx, "key_block_proof"));
  TRY_RESULT(block_proof_cell, conformance::required_boc(ctx, "block_proof"));
  auto key_proof = parse_block_proof(key_proof_cell);
  if (key_proof.is_error()) {
    return refused(key_proof.error());
  }
  auto block_proof = parse_block_proof(block_proof_cell);
  if (block_proof.is_error()) {
    return refused(block_proof.error());
  }
  block::BlockProofLink link{from, to, is_key};
  link.proof = key_proof.ok().root;
  link.dest_proof = block_proof.ok().root;
  if (block_proof.ok().signatures.not_null()) {
    tos::ValidatorWeight claimed = 0;
    auto set = block::BlockSignatureSet::fetch(block_proof.ok().signatures, claimed);
    if (set.is_error()) {
      return refused(set.error());
    }
    link.sig_set = set.move_as_ok();
  }
  td::uint32 utime = 0;
  block::FinalityVerificationInfo finality;
  auto status = link.validate(&utime, &finality);
  if (status.is_error()) {
    return refused(status);
  }
  return "{\"outcome\":\"linked\",\"gen_utime\":" + std::to_string(utime) + ",\"expected_session_id\":\"" +
         bits_hex(finality.expected_session_id) + "\",\"verified_weight\":" + decimal(finality.verified_weight) +
         ",\"total_weight\":" + decimal(finality.total_weight) + "}";
}

td::Result<std::string> op_key_block_context(td::JsonObject &ctx) {
  TRY_RESULT(from, parse_block_id(ctx, "key_block"));
  TRY_RESULT(to, parse_block_id(ctx, "block"));
  TRY_RESULT(key_proof_cell, conformance::required_boc(ctx, "key_block_proof"));
  TRY_RESULT(block_proof_cell, conformance::required_boc(ctx, "block_proof"));
  if (!to.is_masterchain_ext() || !from.is_masterchain_ext() || from.seqno() == 0 || to.seqno() <= from.seqno()) {
    return td::Status::Error("key_block_context: a later masterchain block and a nonzero key block required");
  }
  auto key_proof = parse_block_proof(key_proof_cell);
  if (key_proof.is_error()) {
    return refused(key_proof.error());
  }
  auto block_proof = parse_block_proof(block_proof_cell);
  if (block_proof.is_error()) {
    return refused(block_proof.error());
  }
  auto key_root = vm::MerkleProof::virtualize(key_proof.ok().root);
  if (key_root.is_error()) {
    return refused(key_root.error());
  }
  auto key_header = block::check_block_header(key_root.ok(), from);
  if (key_header.is_error()) {
    return refused(key_header);
  }
  auto block_root = vm::MerkleProof::virtualize(block_proof.ok().root);
  if (block_root.is_error()) {
    return refused(block_root.error());
  }
  auto block_header = block::check_block_header(block_root.ok(), to);
  if (block_header.is_error()) {
    return refused(block_header);
  }
  block::gen::Block::Record blk;
  block::gen::BlockInfo::Record info;
  if (!(tlb::unpack_cell(block_root.ok(), blk) && tlb::unpack_cell(blk.info, info))) {
    return refused(td::Status::Error("cannot unpack header"));
  }
  // The configuration of the governing key block, extracted as the forward proof link does.
  auto config_r = block::Config::extract_from_key_block(key_root.ok(), block::ConfigInfo::needValidatorSet);
  if (config_r.is_error()) {
    return refused(td::Status::Error(PSLICE() << "cannot extract configuration: " << config_r.error().message()));
  }
  auto config = config_r.move_as_ok();
  const tos::ShardIdFull shard{tos::masterchainId};
  auto nodes = config->compute_validator_set(shard, info.gen_utime, info.gen_catchain_seqno);
  if (nodes.empty()) {
    return refused(td::Status::Error("cannot compute validator set"));
  }
  td::Ref<block::ValidatorSet> vset{true, info.gen_catchain_seqno, shard, nodes};
  const auto session_config = config->get_consensus_config();
  const auto selected = config->get_selected_new_consensus_config(to.id.workchain);
  if (!selected) {
    return refused(td::Status::Error("selected ConfigParam 30 is missing or malformed"));
  }
  std::string config_global_id = "null";
  if (auto param19 = config->get_config_param(19); param19.not_null()) {
    auto cs = vm::load_cell_slice(param19);
    if (cs.size() >= 32) {
      config_global_id = std::to_string(static_cast<td::int32>(cs.prefetch_long(32)));
    }
  }
  const auto lite_identity = block::derive_validator_session_identity(
      config->get_global_blockchain_id(), block::validator_session_options_hash(session_config),
      selected.value().cell_hash, to.shard_full(), vset->get_catchain_seqno(), vset->export_vector(), info.vert_seq_no,
      info.prev_key_block_seqno, session_config.new_catchain_ids);
  auto validator_context =
      tos::validator::detail::derive_pq_finality_context(config->get_global_blockchain_id(), session_config, selected,
                                                         vset, to, info.vert_seq_no, info.prev_key_block_seqno);
  if (validator_context.is_error()) {
    return refused(validator_context.error());
  }
  std::string signature_set = "null";
  std::string claimed = "null";
  if (block_proof.ok().signatures.not_null()) {
    tos::ValidatorWeight claimed_weight = 0;
    auto decoded = block::BlockSignatureSet::fetch(block_proof.ok().signatures, claimed_weight);
    if (decoded.is_error()) {
      return refused(decoded.error());
    }
    TRY_RESULT(text, signature_set_json(*decoded.ok()));
    signature_set = std::move(text);
    claimed = decimal(claimed_weight);
  }
  return "{\"outcome\":\"context\",\"global_id\":" + std::to_string(config->get_global_blockchain_id()) +
         ",\"config_global_id\":" + config_global_id + ",\"options\":" + options_json(session_config) +
         ",\"simplex_config_hash\":\"" + bits_hex(selected.value().cell_hash) +
         "\",\"protocol_version\":" + std::to_string(selected.value().config.protocol_version) +
         ",\"gen_utime\":" + std::to_string(info.gen_utime) +
         ",\"catchain_seqno\":" + std::to_string(info.gen_catchain_seqno) +
         ",\"vertical_seqno\":" + std::to_string(info.vert_seq_no) +
         ",\"prev_key_block_seqno\":" + std::to_string(info.prev_key_block_seqno) +
         ",\"is_key\":" + conformance::json_bool(info.key_block) +
         ",\"header_validator_set_hash\":" + std::to_string(info.gen_validator_list_hash_short) +
         ",\"validator_set_hash\":" + std::to_string(vset->get_validator_set_hash()) +
         ",\"total_weight\":" + decimal(vset->get_total_weight()) + ",\"validators\":" + validators_json(nodes) +
         ",\"session_id\":\"" + bits_hex(lite_identity.session_id) + "\",\"validator_path_session_id\":\"" +
         bits_hex(validator_context.ok().expected_session_id) + "\",\"signature_set\":" + signature_set +
         ",\"claimed_weight\":" + claimed + "}";
}

td::Result<std::string> run_consensus(td::JsonObject &ctx) {
  TRY_RESULT(op, ctx.get_required_string_field("op"));
  try {
    if (op == "quorum") {
      return op_quorum(ctx);
    }
    if (op == "weight_total") {
      return op_weight_total(ctx);
    }
    if (op == "protocol_version") {
      return op_protocol_version(ctx);
    }
    if (op == "session") {
      return op_session(ctx);
    }
    if (op == "validator_set") {
      return op_validator_set(ctx);
    }
    if (op == "vote") {
      return op_vote(ctx);
    }
    if (op == "finality") {
      return op_finality(ctx);
    }
    if (op == "decode_proof") {
      return op_decode_proof(ctx);
    }
    if (op == "proof_link") {
      return op_proof_link(ctx);
    }
    if (op == "key_block_context") {
      return op_key_block_context(ctx);
    }
  } catch (vm::VmError &error) {
    // Node parsers signal malformed cells by throwing; the proof paths turn the same into a refusal.
    return refused(td::Status::Error(PSLICE() << "virtualization error: " << error.get_msg()));
  } catch (vm::VmVirtError &error) {
    return refused(td::Status::Error(PSLICE() << "virtualization error: " << error.get_msg()));
  }
  return td::Status::Error("unknown op");
}

}  // namespace

CONFORMANCE_REGISTER_HARNESS(consensus, run_consensus);
