// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// crypto harness: one call of a cryptographic or consensus-identity function the node uses
// (schema/harness/crypto-v1.schema.json). The context names a scheme, an operation and its
// inputs; optional edits change named byte inputs before the call, so a family of mutations of
// one large signature stores the signature once. Every effect is what the node's own function
// returned; nothing here restates a rule the node implements.
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "auto/tl/lite_api.hpp"
#include "auto/tl/tos_api.hpp"
#include "block/mc-config.h"
#include "block/signature-set.h"
#include "block/validator-session-id.h"
#include "block/validator-session-members.h"
#include "block/validator-set.h"
#include "crypto/Ed25519.h"
#include "crypto/pq/falcon512.h"
#include "crypto/pq/lms-fee.h"
#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-bytes.h"
#include "crypto/pq/pq-consensus.h"
#include "crypto/pq/pq-elector.h"
#include "crypto/pq/slhdsa128s.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "tl-utils/lite-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "tos/quorum.h"
#include "tos/tos-types.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cellslice.h"
#include "vm/dict.h"
#include "vm/poseidon2-params.h"
#include "vm/poseidon2ops.h"

#include "common.h"

namespace {

constexpr std::size_t kMaxInputBytes = 1u << 20;
constexpr std::size_t kMaxEdits = 16;
constexpr std::size_t kMaxResize = 1u << 16;
constexpr std::size_t kMaxValidators = 1024;
constexpr std::size_t kMaxDescriptors = 64;

// ---------------------------------------------------------------------------------------------
// Inputs: variable-length bytes are base64, fixed 32-byte identifiers are 64 hex digits, integers
// that may exceed 2^53 are decimal strings.

struct Edit {
  std::string input;
  std::string op;
  std::size_t offset = 0;
  std::size_t length = 0;
  unsigned value = 0;
  bool used = false;
};

class Inputs {
 public:
  Inputs(td::JsonObject &inputs, std::vector<Edit> edits) : inputs_(inputs), edits_(std::move(edits)) {
  }

  td::Result<std::string> bytes(td::Slice name) {
    TRY_RESULT(text, string_field(name));
    auto decoded = td::base64_decode(text);
    if (decoded.is_error()) {
      return td::Status::Error(PSLICE() << "inputs." << name << " is not base64");
    }
    auto value = decoded.move_as_ok();
    if (value.size() > kMaxInputBytes) {
      return td::Status::Error(PSLICE() << "inputs." << name << " too large");
    }
    for (auto &edit : edits_) {
      if (edit.input != name.str()) {
        continue;
      }
      edit.used = true;
      if (edit.op == "xor") {
        if (edit.offset >= value.size()) {
          return td::Status::Error(PSLICE() << "edit offset " << edit.offset << " outside inputs." << name);
        }
        value[edit.offset] = static_cast<char>(static_cast<unsigned char>(value[edit.offset]) ^ edit.value);
      } else if (edit.op == "resize") {
        value.resize(edit.length, static_cast<char>(edit.value));
      } else {
        value.assign(value.size(), static_cast<char>(edit.value));
      }
    }
    return value;
  }

  td::Result<td::Bits256> bits256(td::Slice name) {
    TRY_RESULT(text, string_field(name));
    return parse_bits256(text, name);
  }

  td::Result<std::uint64_t> uint64(td::Slice name) {
    TRY_RESULT(text, string_field(name));
    return parse_uint64(text, name);
  }

  td::Result<std::int64_t> integer(td::Slice name, std::int64_t low, std::int64_t high) {
    TRY_RESULT(value, inputs_.get_required_long_field(name));
    if (value < low || value > high) {
      return td::Status::Error(PSLICE() << "inputs." << name << " out of range");
    }
    return value;
  }

  td::Result<bool> boolean(td::Slice name) {
    return inputs_.get_required_bool_field(name);
  }

  td::Result<std::string> text(td::Slice name) {
    return string_field(name);
  }

  td::Result<td::JsonValue> field(td::Slice name, td::JsonValue::Type type) {
    return inputs_.extract_required_field(name, type);
  }

  bool has(td::Slice name) const {
    return inputs_.has_field(name);
  }

  td::Status check_edits_used() const {
    for (const auto &edit : edits_) {
      if (!edit.used) {
        return td::Status::Error(PSLICE()
                                 << "edit names inputs." << edit.input << ", which this operation does not read");
      }
    }
    return td::Status::OK();
  }

  static td::Result<td::Bits256> parse_bits256(td::Slice text, td::Slice name) {
    if (text.size() != 64) {
      return td::Status::Error(PSLICE() << name << " must be 64 hex digits");
    }
    auto raw = td::hex_decode(text);
    if (raw.is_error()) {
      return td::Status::Error(PSLICE() << name << " must be 64 hex digits");
    }
    td::Bits256 out;
    std::memcpy(out.data(), raw.ok().data(), 32);
    return out;
  }

  static td::Result<std::uint64_t> parse_uint64(td::Slice text, td::Slice name) {
    if (text.empty() || text.size() > 20) {
      return td::Status::Error(PSLICE() << name << " must be a decimal uint64");
    }
    std::uint64_t value = 0;
    for (char c : text) {
      if (c < '0' || c > '9') {
        return td::Status::Error(PSLICE() << name << " must be a decimal uint64");
      }
      const auto digit = static_cast<std::uint64_t>(c - '0');
      if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
        return td::Status::Error(PSLICE() << name << " exceeds uint64");
      }
      value = value * 10 + digit;
    }
    if (text.size() > 1 && text[0] == '0') {
      return td::Status::Error(PSLICE() << name << " must not have leading zeros");
    }
    return value;
  }

 private:
  td::Result<std::string> string_field(td::Slice name) {
    if (!inputs_.has_field(name)) {
      return td::Status::Error(PSLICE() << "missing inputs." << name);
    }
    return inputs_.get_required_string_field(name);
  }

  td::JsonObject &inputs_;
  std::vector<Edit> edits_;
};

td::Result<std::vector<Edit>> parse_edits(td::JsonObject &ctx) {
  std::vector<Edit> edits;
  if (!ctx.has_field("edits")) {
    return edits;
  }
  TRY_RESULT(value, ctx.extract_required_field("edits", td::JsonValue::Type::Array));
  auto &list = value.get_array();
  if (list.empty() || list.size() > kMaxEdits) {
    return td::Status::Error("edits must hold 1..16 entries");
  }
  for (auto &item : list) {
    if (item.type() != td::JsonValue::Type::Object) {
      return td::Status::Error("edit must be an object");
    }
    auto &obj = item.get_object();
    Edit edit;
    TRY_RESULT_ASSIGN(edit.input, obj.get_required_string_field("input"));
    TRY_RESULT_ASSIGN(edit.op, obj.get_required_string_field("op"));
    TRY_RESULT(value_field, obj.get_required_int_field("value"));
    if (value_field < 0 || value_field > 255) {
      return td::Status::Error("edit value must be a byte");
    }
    edit.value = static_cast<unsigned>(value_field);
    if (edit.op == "xor") {
      TRY_RESULT(offset, obj.get_required_long_field("offset"));
      if (offset < 0 || static_cast<std::uint64_t>(offset) >= kMaxInputBytes || value_field == 0) {
        return td::Status::Error("xor edit needs an offset inside the input and a non-zero value");
      }
      edit.offset = static_cast<std::size_t>(offset);
    } else if (edit.op == "resize") {
      TRY_RESULT(length, obj.get_required_long_field("length"));
      if (length < 0 || static_cast<std::uint64_t>(length) > kMaxResize) {
        return td::Status::Error("resize edit length out of range");
      }
      edit.length = static_cast<std::size_t>(length);
    } else if (edit.op != "fill") {
      return td::Status::Error("edit op must be xor, resize or fill");
    }
    edits.push_back(std::move(edit));
  }
  return edits;
}

// ---------------------------------------------------------------------------------------------
// Effects

std::string hex(td::Slice bytes) {
  return td::hex_encode(bytes);
}

std::string hex(const td::Bits256 &bits) {
  return td::hex_encode(bits.as_slice());
}

std::string verdict(tos::pq::VerifyResult result) {
  const char *name = "backend_error";
  switch (result) {
    case tos::pq::VerifyResult::valid:
      name = "valid";
      break;
    case tos::pq::VerifyResult::invalid:
      name = "invalid";
      break;
    case tos::pq::VerifyResult::malformed_input:
      name = "malformed_input";
      break;
    case tos::pq::VerifyResult::backend_error:
      name = "backend_error";
      break;
  }
  return std::string("{\"outcome\":\"verdict\",\"verdict\":\"") + name + "\"}";
}

std::string bytes_effect(td::Slice bytes) {
  return "{\"outcome\":\"bytes\",\"output\":" + conformance::json_quote(hex(bytes)) + "}";
}

std::string integer_effect(std::uint64_t value) {
  return "{\"outcome\":\"integer\",\"value\":" + conformance::json_quote(std::to_string(value)) + "}";
}

std::string boolean_effect(bool value) {
  return "{\"outcome\":\"boolean\",\"value\":" + conformance::json_bool(value) + "}";
}

std::string rejected(td::Slice reason) {
  return "{\"outcome\":\"rejected\",\"reason\":" + conformance::json_quote(reason) + "}";
}

using Fields = std::map<std::string, std::string>;

std::string record(const Fields &fields) {
  std::string out = "{\"fields\":{";
  bool first = true;
  for (const auto &[key, value] : fields) {
    if (!first) {
      out += ',';
    }
    first = false;
    out += conformance::json_quote(key) + ":" + conformance::json_quote(value);
  }
  return out + "},\"outcome\":\"record\"}";
}

std::string join(const std::vector<std::string> &items) {
  std::string out;
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i != 0) {
      out += ',';
    }
    out += items[i];
  }
  return out.empty() ? "-" : out;
}

std::string_view view(const std::string &s) {
  return {s.data(), s.size()};
}

// ---------------------------------------------------------------------------------------------
// Signature verification

td::Result<std::string> ed25519_verify(Inputs &in) {
  TRY_RESULT(message, in.bytes("message"));
  TRY_RESULT(signature, in.bytes("signature"));
  TRY_RESULT(public_key, in.bytes("public_key"));
  // The call the CHKSIGNU/CHKSIGNS instructions and classical block signatures make.
  td::Ed25519::PublicKey key{td::SecureString(public_key)};
  const bool valid = key.verify_signature(message, signature).is_ok();
  return verdict(valid ? tos::pq::VerifyResult::valid : tos::pq::VerifyResult::invalid);
}

td::Result<std::string> mldsa44_verify(Inputs &in) {
  TRY_RESULT(message, in.bytes("message"));
  TRY_RESULT(context, in.bytes("context"));
  TRY_RESULT(signature, in.bytes("signature"));
  TRY_RESULT(public_key, in.bytes("public_key"));
  return verdict(tos::pq::verify_mldsa44(view(message), view(context), view(signature), view(public_key)));
}

td::Result<std::string_view> consensus_surface(td::Slice name) {
  if (name == "simplex") {
    return tos::pq::simplex_sign_context;
  }
  if (name == "validator_election") {
    return tos::pq::validator_election_context;
  }
  if (name == "validator_config_vote") {
    return tos::pq::validator_config_vote_context;
  }
  if (name == "config_admin") {
    return tos::pq::config_admin_context;
  }
  return td::Status::Error("surface must be simplex, validator_election, validator_config_vote or config_admin");
}

// The verification a consensus surface performs: ML-DSA-44 under that surface's frozen domain.
td::Result<std::string> mldsa44_verify_consensus(Inputs &in) {
  TRY_RESULT(surface, in.text("surface"));
  TRY_RESULT(context, consensus_surface(surface));
  TRY_RESULT(message, in.bytes("message"));
  TRY_RESULT(signature, in.bytes("signature"));
  TRY_RESULT(public_key, in.bytes("public_key"));
  return verdict(tos::pq::verify_mldsa44(view(message), context, view(signature), view(public_key)));
}

td::Result<std::string> mldsa44_derive_key_id(Inputs &in) {
  TRY_RESULT(algorithm, in.integer("algorithm_id", 0, 0xffff));
  TRY_RESULT(public_key, in.bytes("public_key"));
  auto id = tos::pq::derive_key_id(static_cast<tos::pq::PQAlgorithmId>(algorithm), view(public_key));
  if (!id.has_value()) {
    return rejected("refused");
  }
  return bytes_effect(td::Slice(reinterpret_cast<const char *>(id->data()), id->size()));
}

td::Result<std::string> falcon512_verify(Inputs &in) {
  TRY_RESULT(message, in.bytes("message"));
  TRY_RESULT(signature, in.bytes("signature"));
  TRY_RESULT(public_key, in.bytes("public_key"));
  return verdict(tos::pq::verify_falcon512_padded(view(message), view(signature), view(public_key)));
}

td::Result<std::string> slhdsa128s_verify(Inputs &in) {
  TRY_RESULT(message, in.bytes("message"));
  TRY_RESULT(context, in.bytes("context"));
  TRY_RESULT(signature, in.bytes("signature"));
  TRY_RESULT(public_key, in.bytes("public_key"));
  return verdict(tos::pq::verify_slhdsa128s(view(message), view(context), view(signature), view(public_key)));
}

td::Result<std::string> lms_fee_verify(Inputs &in) {
  TRY_RESULT(message, in.bytes("message"));
  TRY_RESULT(signature, in.bytes("signature"));
  TRY_RESULT(public_key, in.bytes("public_key"));
  return verdict(tos::pq::verify_lms_fee(view(message), view(signature), view(public_key)));
}

td::Result<std::string> lms_fee_worst_compressions(Inputs &in) {
  TRY_RESULT(public_key, in.bytes("public_key"));
  TRY_RESULT(message_bytes, in.uint64("message_bytes"));
  if (message_bytes > std::numeric_limits<std::size_t>::max()) {
    return td::Status::Error("message_bytes exceeds size_t");
  }
  auto cost = tos::pq::lms_fee_worst_compressions(view(public_key), static_cast<std::size_t>(message_bytes));
  if (!cost.has_value()) {
    return rejected("unsupported");
  }
  return integer_effect(*cost);
}

// ---------------------------------------------------------------------------------------------
// Hashes

td::Result<std::string> sha256_digest(Inputs &in) {
  TRY_RESULT(data, in.bytes("data"));
  return bytes_effect(td::sha256(data));
}

td::Result<std::string> poseidon2_permute(Inputs &in) {
  TRY_RESULT(state_value, in.field("state", td::JsonValue::Type::Array));
  auto &items = state_value.get_array();
  if (items.size() != 8) {
    return td::Status::Error("state must hold 8 field elements");
  }
  unsigned char state[8][32];
  for (std::size_t i = 0; i < 8; ++i) {
    if (items[i].type() != td::JsonValue::Type::String) {
      return td::Status::Error("field element must be 64 hex digits");
    }
    TRY_RESULT(element, Inputs::parse_bits256(items[i].get_string(), "state element"));
    // permute() is defined on canonical elements only; the instructions refuse anything else
    // before calling it, so a non-canonical element is not a context this function accepts.
    if (std::memcmp(element.data(), vm::poseidon2::modulus_be, 32) >= 0) {
      return td::Status::Error("state element is not below the field modulus");
    }
    std::memcpy(state[i], element.data(), 32);
  }
  vm::poseidon2::permute(state);
  std::string out;
  for (auto &element : state) {
    out.append(reinterpret_cast<const char *>(element), 32);
  }
  return bytes_effect(out);
}

td::Result<std::string> poseidon2_manifest_digest(Inputs &) {
  return bytes_effect(td::sha256(vm::poseidon2::manifest_bytes()));
}

// ---------------------------------------------------------------------------------------------
// Weighted quorum

td::Result<std::string> quorum_threshold(Inputs &in) {
  TRY_RESULT(total, in.uint64("total_weight"));
  return integer_effect(tos::quorum_threshold(total));
}

td::Result<std::string> quorum_has_quorum(Inputs &in) {
  TRY_RESULT(signed_weight, in.uint64("signed_weight"));
  TRY_RESULT(total, in.uint64("total_weight"));
  return boolean_effect(tos::has_quorum(signed_weight, total));
}

// ---------------------------------------------------------------------------------------------
// Validator descriptors as the consensus layer holds them (tos::ValidatorDescr).

td::Result<tos::ValidatorDescr> parse_descriptor(td::JsonValue &value) {
  if (value.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("validator must be an object");
  }
  auto &obj = value.get_object();
  TRY_RESULT(kind, obj.get_required_string_field("kind"));
  TRY_RESULT(weight_text, obj.get_required_string_field("weight"));
  TRY_RESULT(weight, Inputs::parse_uint64(weight_text, "validator weight"));
  TRY_RESULT(adnl_text, obj.get_required_string_field("adnl"));
  TRY_RESULT(adnl, Inputs::parse_bits256(adnl_text, "validator adnl"));
  if (kind == "classical") {
    TRY_RESULT(key_text, obj.get_required_string_field("public_key"));
    TRY_RESULT(key, Inputs::parse_bits256(key_text, "validator public_key"));
    return tos::ValidatorDescr{tos::Ed25519_PublicKey{key}, weight, adnl};
  }
  if (kind != "pq") {
    return td::Status::Error("validator kind must be classical or pq");
  }
  TRY_RESULT(id_text, obj.get_required_string_field("validator_id"));
  TRY_RESULT(validator_id, Inputs::parse_bits256(id_text, "validator_id"));
  TRY_RESULT(key_id_text, obj.get_required_string_field("key_id"));
  TRY_RESULT(key_id, Inputs::parse_bits256(key_id_text, "key_id"));
  TRY_RESULT(algorithm, obj.get_required_int_field("algorithm_id"));
  if (algorithm < 0 || algorithm > 0xffff) {
    return td::Status::Error("algorithm_id must fit 16 bits");
  }
  TRY_RESULT(key_text, obj.get_required_string_field("public_key"));
  auto key = td::base64_decode(key_text);
  if (key.is_error() || key.ok().size() > kMaxInputBytes) {
    return td::Status::Error("validator public_key must be base64");
  }
  return tos::ValidatorDescr{tos::ValidatorId{validator_id},
                             static_cast<td::uint16>(algorithm),
                             tos::ConsensusKeyId{key_id},
                             key.move_as_ok(),
                             weight,
                             adnl};
}

td::Result<std::vector<tos::ValidatorDescr>> parse_descriptors(Inputs &in, td::Slice name) {
  TRY_RESULT(list_value, in.field(name, td::JsonValue::Type::Array));
  auto &list = list_value.get_array();
  if (list.size() > kMaxValidators) {
    return td::Status::Error("too many validators");
  }
  std::vector<tos::ValidatorDescr> out;
  out.reserve(list.size());
  for (auto &item : list) {
    TRY_RESULT(descr, parse_descriptor(item));
    out.push_back(std::move(descr));
  }
  return out;
}

td::Result<std::string> validator_session_members(Inputs &in) {
  TRY_RESULT(validators, parse_descriptors(in, "validators"));
  auto members = block::validator_session_members(validators);
  std::vector<std::string> ids;
  std::vector<std::string> encodings;
  for (const auto &member : members) {
    char id[9];
    std::snprintf(id, sizeof id, "%08x", static_cast<unsigned>(member->get_id()));
    ids.emplace_back(id);
    encodings.push_back(hex(tos::serialize_tl_object(member, true).as_slice()));
  }
  return record({{"constructor_ids", join(ids)}, {"members", join(encodings)}});
}

td::Result<std::string> validator_session_identity(Inputs &in) {
  block::ValidatorSessionIdentityInput input;
  TRY_RESULT(global_id,
             in.integer("global_id", std::numeric_limits<td::int32>::min(), std::numeric_limits<td::int32>::max()));
  input.global_id = static_cast<td::int32>(global_id);
  TRY_RESULT_ASSIGN(input.validator_options_hash, in.bits256("validator_options_hash"));
  TRY_RESULT_ASSIGN(input.simplex_config_cell_hash, in.bits256("simplex_config_cell_hash"));
  TRY_RESULT(workchain,
             in.integer("workchain", std::numeric_limits<td::int32>::min(), std::numeric_limits<td::int32>::max()));
  TRY_RESULT(shard, in.uint64("shard"));
  input.shard = tos::ShardIdFull{static_cast<tos::WorkchainId>(workchain), shard};
  TRY_RESULT(cc_seqno, in.integer("catchain_seqno", 0, 0xffffffffLL));
  input.catchain_seqno = static_cast<tos::CatchainSeqno>(cc_seqno);
  TRY_RESULT(vertical, in.integer("vertical_seqno", 0, 0xffffffffLL));
  input.vertical_seqno = static_cast<td::uint32>(vertical);
  TRY_RESULT(key_seqno, in.integer("last_key_block_seqno", 0, 0xffffffffLL));
  input.last_key_block_seqno = static_cast<tos::BlockSeqno>(key_seqno);
  TRY_RESULT_ASSIGN(input.new_catchain_ids, in.boolean("new_catchain_ids"));
  TRY_RESULT_ASSIGN(input.validators, parse_descriptors(in, "validators"));
  auto identity = block::derive_validator_session_identity(input);
  return record({{"session_config_hash", hex(identity.session_config_hash)}, {"session_id", hex(identity.session_id)}});
}

td::Result<std::string> validator_session_config_hash(Inputs &in) {
  TRY_RESULT(global_id,
             in.integer("global_id", std::numeric_limits<td::int32>::min(), std::numeric_limits<td::int32>::max()));
  TRY_RESULT(options, in.bits256("validator_options_hash"));
  TRY_RESULT(cell_hash, in.bits256("simplex_config_cell_hash"));
  return bytes_effect(
      block::validator_session_config_hash(static_cast<td::int32>(global_id), options, cell_hash).as_slice());
}

td::Result<std::string> validator_session_options_hash(Inputs &in) {
  tos::ValidatorSessionConfig config;
  auto u32 = [&](td::Slice name) -> td::Result<td::uint32> {
    TRY_RESULT(value, in.integer(name, 0, 0xffffffffLL));
    return static_cast<td::uint32>(value);
  };
  auto number = [&](td::Slice name) -> td::Result<double> {
    TRY_RESULT(text, in.text(name));
    // Plain decimal text, so every implementation parses the same double out of the context.
    if (text.empty() || text.size() > 32 || text.find_first_not_of("0123456789.") != std::string::npos ||
        text.front() == '.' || text.back() == '.' || text.find('.') != text.rfind('.')) {
      return td::Status::Error(PSLICE() << "inputs." << name << " must be plain decimal text");
    }
    return td::to_double(text);
  };
  TRY_RESULT_ASSIGN(config.proto_version, u32("proto_version"));
  TRY_RESULT_ASSIGN(config.catchain_opts.idle_timeout, number("idle_timeout"));
  TRY_RESULT_ASSIGN(config.catchain_opts.max_deps, u32("max_deps"));
  TRY_RESULT_ASSIGN(config.catchain_opts.max_serialized_block_size, u32("max_serialized_block_size"));
  TRY_RESULT_ASSIGN(config.catchain_opts.block_hash_covers_data, in.boolean("block_hash_covers_data"));
  TRY_RESULT_ASSIGN(config.catchain_opts.max_block_height_coeff, in.uint64("max_block_height_coeff"));
  TRY_RESULT_ASSIGN(config.catchain_opts.debug_disable_db, in.boolean("debug_disable_db"));
  TRY_RESULT_ASSIGN(config.round_candidates, u32("round_candidates"));
  TRY_RESULT_ASSIGN(config.next_candidate_delay, number("next_candidate_delay"));
  TRY_RESULT_ASSIGN(config.round_attempt_duration, u32("round_attempt_duration"));
  TRY_RESULT_ASSIGN(config.max_round_attempts, u32("max_round_attempts"));
  TRY_RESULT_ASSIGN(config.max_block_size, u32("max_block_size"));
  TRY_RESULT_ASSIGN(config.max_collated_data_size, u32("max_collated_data_size"));
  TRY_RESULT_ASSIGN(config.new_catchain_ids, in.boolean("new_catchain_ids"));
  return bytes_effect(block::validator_session_options_hash(config).as_slice());
}

// ---------------------------------------------------------------------------------------------
// PQBytes

td::Result<std::string> pq_bytes_pack(Inputs &in) {
  TRY_RESULT(data, in.bytes("data"));
  TRY_RESULT(max_bytes, in.integer("max_bytes", 0, kMaxInputBytes));
  auto cell = tos::pq::pack_pq_bytes(data, static_cast<std::size_t>(max_bytes));
  if (cell.is_error()) {
    return rejected("refused");
  }
  TRY_RESULT(boc, vm::std_boc_serialize(cell.ok(), 31));
  return record({{"root_hash", hex(cell.ok()->get_hash().as_slice())}, {"boc", hex(boc.as_slice())}});
}

td::Result<std::string> pq_bytes_unpack(Inputs &in) {
  TRY_RESULT(boc, in.bytes("boc"));
  TRY_RESULT(max_bytes, in.integer("max_bytes", 0, kMaxInputBytes));
  auto root = vm::std_boc_deserialize(boc);
  if (root.is_error()) {
    return td::Status::Error("inputs.boc is not a BOC");
  }
  auto data = tos::pq::unpack_pq_bytes(root.move_as_ok(), static_cast<std::size_t>(max_bytes));
  if (data.is_error()) {
    return rejected("refused");
  }
  return bytes_effect(data.ok().as_slice());
}

// ---------------------------------------------------------------------------------------------
// Consensus signing domain and block signature carriers

td::Result<tos::BlockIdExt> parse_block_id(Inputs &in) {
  TRY_RESULT(value, in.field("block_id", td::JsonValue::Type::Object));
  auto &obj = value.get_object();
  TRY_RESULT(workchain, obj.get_required_int_field("workchain"));
  TRY_RESULT(shard_text, obj.get_required_string_field("shard"));
  TRY_RESULT(shard, Inputs::parse_uint64(shard_text, "block_id.shard"));
  TRY_RESULT(seqno, obj.get_required_long_field("seqno"));
  if (seqno < 0 || seqno > 0xffffffffLL) {
    return td::Status::Error("block_id.seqno out of range");
  }
  TRY_RESULT(root_text, obj.get_required_string_field("root_hash"));
  TRY_RESULT(root_hash, Inputs::parse_bits256(root_text, "block_id.root_hash"));
  TRY_RESULT(file_text, obj.get_required_string_field("file_hash"));
  TRY_RESULT(file_hash, Inputs::parse_bits256(file_text, "block_id.file_hash"));
  return tos::BlockIdExt{workchain, shard, static_cast<tos::BlockSeqno>(seqno), root_hash, file_hash};
}

td::Result<std::string> consensus_simplex_data_to_sign(Inputs &in) {
  TRY_RESULT(session, in.bits256("session_id"));
  TRY_RESULT(slot, in.integer("slot", 0, 0xffffffffLL));
  TRY_RESULT(candidate_bytes, in.bytes("candidate"));
  TRY_RESULT(final, in.boolean("final"));
  TRY_RESULT(block_id, parse_block_id(in));
  auto candidate =
      tos::fetch_tl_object<tos::tos_api::consensus_CandidateHashData>(td::BufferSlice(candidate_bytes), true);
  if (candidate.is_error()) {
    return rejected("candidate_tl");
  }
  auto message = block::BlockSignatureSet::build_simplex_data_to_sign(session, static_cast<td::uint32>(slot),
                                                                      candidate.ok(), final, block_id);
  if (message.is_error()) {
    if (message.error().message() == "block id mismatch") {
      return rejected("block_id_mismatch");
    }
    return td::Status::Error(PSLICE() << "unclassified refusal: " << message.error().message());
  }
  return bytes_effect(message.ok().as_slice());
}

// The stable classification of the node's refusals of a signature carrier; a refusal the table
// does not know is a harness error, so a new failure path shows up instead of being folded in.
td::Result<std::string> carrier_reason(const td::Status &error) {
  const auto message = error.message().str();
  struct Prefix {
    const char *text;
    const char *code;
    bool exact;
  };
  static const Prefix table[] = {
      {"pq signatures: duplicate validator_id", "duplicate_validator_id", true},
      {"pq signatures: unsupported algorithm", "unsupported_algorithm", true},
      {"pq signatures: signature length", "signature_length", false},
      {"pq signatures: noncanonical PQBytes", "noncanonical_pqbytes", false},
      {"pq signatures: dictionary index", "dictionary_index", true},
      {"pq signatures: dictionary missing entry", "dictionary_missing_entry", true},
      {"pq signatures: dictionary extra entry", "dictionary_extra_entry", true},
      {"pq candidate data: oversize", "candidate_oversize", true},
      {"pq candidate data: noncanonical chunk size", "candidate_noncanonical_chunk", true},
      {"pq candidate data: non-byte-aligned cell", "candidate_non_byte_aligned", true},
      {"pq candidate data: multiple continuation refs", "candidate_multiple_refs", true},
      {"pq candidate data: chain too long", "candidate_chain_length", true},
      {"pq candidate data: trailing empty cell", "candidate_trailing_ref", true},
      {"pq candidate data: invalid TL", "candidate_tl", false},
      {"pq signatures: signer count exceeds maximum", "signer_count", true},
      {"pq signatures: unknown validator_id", "unknown_validator_id", true},
      {"pq signatures: validator algorithm mismatch", "validator_algorithm_mismatch", true},
      {"signature weight mismatch", "weight_mismatch", true},
      {"unsupported carrier for post-quantum validator set", "unsupported_carrier", true},
      {"pq tl: signature_length", "signature_length", true},
  };
  for (const auto &entry : table) {
    if (entry.exact ? message == entry.text : message.rfind(entry.text, 0) == 0) {
      return std::string(entry.code);
    }
  }
  return td::Status::Error(PSLICE() << "unclassified refusal: " << message);
}

td::Result<Fields> summarize(const td::Ref<block::BlockSignatureSet> &set) {
  Fields fields;
  fields["is_pq"] = set->is_pq() ? "true" : "false";
  fields["is_final"] = set->is_final() ? "true" : "false";
  fields["size"] = std::to_string(set->get_size());
  fields["validator_set_hash"] = std::to_string(set->get_validator_set_hash());
  fields["catchain_seqno"] = std::to_string(set->get_catchain_seqno());
  TRY_RESULT(signatures, set->export_pq_signatures());
  TRY_RESULT(session, set->pq_session_id());
  TRY_RESULT(slot, set->pq_slot());
  TRY_RESULT(candidate, set->pq_candidate_data());
  std::vector<std::string> ids;
  std::vector<std::string> algorithms;
  std::vector<std::string> digests;
  for (const auto &signature : signatures) {
    ids.push_back(hex(signature.validator_id.value));
    algorithms.push_back(std::to_string(static_cast<unsigned>(signature.algorithm_id)));
    digests.push_back(hex(td::sha256(signature.signature.as_slice())));
  }
  fields["validator_ids"] = join(ids);
  fields["algorithm_ids"] = join(algorithms);
  fields["signature_sha256"] = join(digests);
  fields["session_id"] = hex(session);
  fields["slot"] = std::to_string(slot);
  fields["candidate_sha256"] = hex(td::sha256(candidate.as_slice()));
  return fields;
}

td::Result<td::Ref<block::ValidatorSet>> parse_validator_set(Inputs &in) {
  TRY_RESULT(value, in.field("validator_set", td::JsonValue::Type::Object));
  auto &obj = value.get_object();
  TRY_RESULT(cc_seqno, obj.get_required_long_field("catchain_seqno"));
  if (cc_seqno < 0 || cc_seqno > 0xffffffffLL) {
    return td::Status::Error("validator_set.catchain_seqno out of range");
  }
  TRY_RESULT(list_value, obj.extract_required_field("validators", td::JsonValue::Type::Array));
  auto &list = list_value.get_array();
  if (list.empty() || list.size() > kMaxValidators) {
    return td::Status::Error("validator_set.validators must hold 1..1024 entries");
  }
  std::vector<tos::ValidatorDescr> validators;
  for (auto &item : list) {
    TRY_RESULT(descr, parse_descriptor(item));
    validators.push_back(std::move(descr));
  }
  return td::Ref<block::ValidatorSet>{true, static_cast<tos::CatchainSeqno>(cc_seqno),
                                      tos::ShardIdFull{tos::masterchainId}, std::move(validators)};
}

td::Result<std::string> block_signatures_fetch(Inputs &in) {
  TRY_RESULT(boc, in.bytes("boc"));
  auto root = vm::std_boc_deserialize(boc);
  if (root.is_error()) {
    return td::Status::Error("inputs.boc is not a BOC");
  }
  const bool with_set = in.has("validator_set");
  td::Result<td::Ref<block::BlockSignatureSet>> parsed;
  tos::ValidatorWeight claimed_weight = 0;
  if (with_set) {
    TRY_RESULT(vset, parse_validator_set(in));
    parsed = block::BlockSignatureSet::fetch(root.ok(), std::move(vset));
  } else {
    parsed = block::BlockSignatureSet::fetch(root.ok(), claimed_weight);
  }
  if (parsed.is_error()) {
    TRY_RESULT(reason, carrier_reason(parsed.error()));
    return rejected(reason);
  }
  auto set = parsed.move_as_ok();
  TRY_RESULT(fields, summarize(set));
  if (!with_set) {
    fields["claimed_weight"] = std::to_string(claimed_weight);
    // The carrier must reserialize to the bytes it was read from: one encoding per value.
    TRY_RESULT(signatures, set->export_pq_signatures());
    TRY_RESULT(candidate_bytes, set->pq_candidate_data());
    TRY_RESULT(candidate, tos::fetch_tl_object<tos::tos_api::consensus_CandidateHashData>(candidate_bytes, true));
    TRY_RESULT(session, set->pq_session_id());
    TRY_RESULT(slot, set->pq_slot());
    auto again = block::BlockSignatureSet::serialize_simplex_pq(
        signatures, set->get_catchain_seqno(), set->get_validator_set_hash(), claimed_weight, session, slot, candidate);
    fields["reserialized_equal"] = again.is_ok() && again.ok()->get_hash() == root.ok()->get_hash() ? "true" : "false";
  }
  return record(fields);
}

td::Result<std::string> block_signatures_fetch_tl(Inputs &in) {
  TRY_RESULT(carrier, in.text("carrier"));
  TRY_RESULT(wire, in.bytes("wire"));
  td::Result<td::Ref<block::BlockSignatureSet>> checked;
  bool reserialized_equal = false;
  if (carrier == "node") {
    auto object = tos::fetch_tl_object<tos::tos_api::tosNode_SignatureSet>(td::BufferSlice(wire), true);
    if (object.is_error()) {
      return rejected("tl_parse");
    }
    reserialized_equal = tos::serialize_tl_object(object.ok(), true).as_slice() == td::Slice(wire);
    checked = block::BlockSignatureSet::fetch_pq_node_checked(object.ok());
  } else if (carrier == "lite") {
    auto object = tos::fetch_tl_object<tos::lite_api::liteServer_SignatureSet>(td::BufferSlice(wire), true);
    if (object.is_error()) {
      return rejected("tl_parse");
    }
    reserialized_equal = tos::serialize_tl_object(object.ok(), true).as_slice() == td::Slice(wire);
    checked = block::BlockSignatureSet::fetch_pq_lite_checked(object.ok());
  } else {
    return td::Status::Error("carrier must be node or lite");
  }
  if (checked.is_error()) {
    TRY_RESULT(reason, carrier_reason(checked.error()));
    return rejected(reason);
  }
  TRY_RESULT(fields, summarize(checked.ok()));
  fields["reserialized_equal"] = reserialized_equal ? "true" : "false";
  return record(fields);
}

// ---------------------------------------------------------------------------------------------
// Configuration and validator sets

td::Result<std::string> config43_parse(Inputs &in) {
  TRY_RESULT(boc, in.bytes("boc"));
  auto root = vm::std_boc_deserialize(boc);
  if (root.is_error()) {
    return td::Status::Error("inputs.boc is not a BOC");
  }
  auto parsed = block::Config::do_get_size_limits_config(vm::load_cell_slice_ref(root.move_as_ok()));
  if (parsed.is_error()) {
    return rejected("refused");
  }
  const auto &l = parsed.ok();
  return record({
      {"max_msg_bits", std::to_string(l.max_msg_bits)},
      {"max_msg_cells", std::to_string(l.max_msg_cells)},
      {"max_library_cells", std::to_string(l.max_library_cells)},
      {"max_vm_data_depth", std::to_string(l.max_vm_data_depth)},
      {"max_ext_msg_size", std::to_string(l.ext_msg_limits.max_size)},
      {"max_ext_msg_depth", std::to_string(l.ext_msg_limits.max_depth)},
      {"max_acc_state_cells", std::to_string(l.max_acc_state_cells)},
      {"max_mc_acc_state_cells", std::to_string(l.max_mc_acc_state_cells)},
      {"max_acc_public_libraries", std::to_string(l.max_acc_public_libraries)},
      {"defer_out_queue_size_limit", std::to_string(l.defer_out_queue_size_limit)},
      {"max_msg_extra_currencies", std::to_string(l.max_msg_extra_currencies)},
      {"max_acc_fixed_prefix_length", std::to_string(l.max_acc_fixed_prefix_length)},
      {"acc_state_cells_for_storage_dict", std::to_string(l.acc_state_cells_for_storage_dict)},
      {"max_transaction_library_loads",
       l.max_transaction_library_loads ? std::to_string(l.max_transaction_library_loads.value()) : "-"},
      {"max_total_msg_bits", std::to_string(l.max_total_msg_bits)},
      {"max_total_msg_cells", std::to_string(l.max_total_msg_cells)},
      {"out_msg_queue_size_hard_limit", std::to_string(l.out_msg_queue_size_hard_limit)},
      {"out_msg_queue_size_soft_limit", std::to_string(l.out_msg_queue_size_soft_limit)},
  });
}

// A validators_ext set around the given descriptors, keyed 0..n-1. This is fixture scaffolding,
// the same wrapper the descriptor-verdict generator writes; the verdict is the decoder's.
td::Result<td::Ref<vm::Cell>> wrap_descriptors(Inputs &in) {
  TRY_RESULT(list_value, in.field("descriptors", td::JsonValue::Type::Array));
  auto &list = list_value.get_array();
  if (list.empty() || list.size() > kMaxDescriptors) {
    return td::Status::Error("descriptors must hold 1..64 entries");
  }
  vm::Dictionary dict{16};
  for (std::size_t i = 0; i < list.size(); ++i) {
    if (list[i].type() != td::JsonValue::Type::String) {
      return td::Status::Error("descriptor must be a base64 BOC");
    }
    auto raw = td::base64_decode(list[i].get_string());
    if (raw.is_error()) {
      return td::Status::Error("descriptor must be a base64 BOC");
    }
    auto cell = vm::std_boc_deserialize(raw.move_as_ok());
    if (cell.is_error()) {
      return td::Status::Error("descriptor is not a BOC");
    }
    td::BitArray<16> key;
    key.store_ulong(i);
    if (!dict.set(key, vm::load_cell_slice_ref(cell.move_as_ok()), vm::Dictionary::SetMode::Add)) {
      return td::Status::Error("descriptor dictionary refused an entry");
    }
  }
  TRY_RESULT(since, in.integer("utime_since", 0, 0xffffffffLL));
  TRY_RESULT(until, in.integer("utime_until", 0, 0xffffffffLL));
  TRY_RESULT(total, in.integer("total", 0, 0xffff));
  TRY_RESULT(main, in.integer("main", 0, 0xffff));
  TRY_RESULT(total_weight, in.uint64("total_weight"));
  vm::CellBuilder cb;
  if (!cb.store_long_bool(0x12, 8) || !cb.store_long_bool(since, 32) || !cb.store_long_bool(until, 32) ||
      !cb.store_long_bool(total, 16) || !cb.store_long_bool(main, 16) ||
      !cb.store_long_bool(static_cast<long long>(total_weight), 64) || !cb.store_maybe_ref(dict.get_root_cell())) {
    return td::Status::Error("cannot build the validator set cell");
  }
  return cb.finalize();
}

td::Result<std::string> validator_set_unpack(Inputs &in) {
  td::Ref<vm::Cell> root;
  if (in.has("set")) {
    TRY_RESULT(boc, in.bytes("set"));
    auto cell = vm::std_boc_deserialize(boc);
    if (cell.is_error()) {
      return td::Status::Error("inputs.set is not a BOC");
    }
    root = cell.move_as_ok();
  } else {
    TRY_RESULT_ASSIGN(root, wrap_descriptors(in));
  }
  auto parsed = block::Config::unpack_validator_set(root, false);
  if (parsed.is_error()) {
    return rejected("refused");
  }
  const auto &set = *parsed.ok();
  std::vector<std::string> ids, key_ids, algorithms, weights, adnl, keys;
  for (const auto &descr : set.list) {
    ids.push_back(hex(descr.validator_id.value));
    key_ids.push_back(hex(descr.key_id.value));
    algorithms.push_back(std::to_string(descr.algorithm_id));
    weights.push_back(std::to_string(descr.weight));
    adnl.push_back(hex(descr.adnl_addr));
    keys.push_back(descr.is_pq() ? hex(td::sha256(descr.pq_public_key)) : hex(descr.pubkey.as_bits256()));
  }
  return record({{"utime_since", std::to_string(set.utime_since)},
                 {"utime_until", std::to_string(set.utime_until)},
                 {"total", std::to_string(set.total)},
                 {"main", std::to_string(set.main)},
                 {"total_weight", std::to_string(set.total_weight)},
                 {"validator_ids", join(ids)},
                 {"key_ids", join(key_ids)},
                 {"algorithm_ids", join(algorithms)},
                 {"weights", join(weights)},
                 {"adnl_addrs", join(adnl)},
                 {"public_keys", join(keys)}});
}

// ---------------------------------------------------------------------------------------------
// What each post-quantum authorisation signs

td::Result<std::string> elector_stake_preimage(Inputs &in) {
  TRY_RESULT(global_id,
             in.integer("global_id", std::numeric_limits<td::int32>::min(), std::numeric_limits<td::int32>::max()));
  TRY_RESULT(stake_at, in.integer("stake_at", 0, 0xffffffffLL));
  TRY_RESULT(max_factor, in.integer("max_factor", 0, 0xffffffffLL));
  TRY_RESULT(src, in.bits256("src_addr"));
  TRY_RESULT(adnl, in.bits256("adnl_addr"));
  return bytes_effect(tos::pq::stake_preimage(static_cast<std::int32_t>(global_id),
                                              static_cast<std::uint32_t>(stake_at),
                                              static_cast<std::uint32_t>(max_factor), src, adnl));
}

td::Result<std::string> elector_config_vote_preimage(Inputs &in) {
  TRY_RESULT(global_id,
             in.integer("global_id", std::numeric_limits<td::int32>::min(), std::numeric_limits<td::int32>::max()));
  TRY_RESULT(set_id, in.bits256("validator_set_id"));
  TRY_RESULT(validator_id, in.bits256("validator_id"));
  TRY_RESULT(idx, in.integer("idx", 0, 0xffff));
  TRY_RESULT(proposal, in.bits256("proposal_hash"));
  return bytes_effect(tos::pq::config_vote_preimage(static_cast<std::int32_t>(global_id), set_id, validator_id,
                                                    static_cast<std::uint16_t>(idx), proposal));
}

td::Result<std::string> elector_complaint_vote_preimage(Inputs &in) {
  TRY_RESULT(global_id,
             in.integer("global_id", std::numeric_limits<td::int32>::min(), std::numeric_limits<td::int32>::max()));
  TRY_RESULT(set_id, in.bits256("validator_set_id"));
  TRY_RESULT(validator_id, in.bits256("validator_id"));
  TRY_RESULT(idx, in.integer("idx", 0, 0xffff));
  TRY_RESULT(election_id, in.integer("election_id", 0, 0xffffffffLL));
  TRY_RESULT(complaint, in.bits256("complaint_hash"));
  return bytes_effect(tos::pq::complaint_vote_preimage(static_cast<std::int32_t>(global_id), set_id, validator_id,
                                                       static_cast<std::uint16_t>(idx),
                                                       static_cast<std::uint32_t>(election_id), complaint));
}

// ---------------------------------------------------------------------------------------------

using OperationFn = td::Result<std::string> (*)(Inputs &);

struct Operation {
  const char *scheme;
  const char *operation;
  OperationFn fn;
};

constexpr Operation kOperations[] = {
    {"ed25519", "verify", ed25519_verify},
    {"mldsa44", "verify", mldsa44_verify},
    {"mldsa44", "verify_consensus", mldsa44_verify_consensus},
    {"mldsa44", "derive_key_id", mldsa44_derive_key_id},
    {"falcon512", "verify_padded", falcon512_verify},
    {"slhdsa128s", "verify", slhdsa128s_verify},
    {"lms_fee", "verify", lms_fee_verify},
    {"lms_fee", "worst_compressions", lms_fee_worst_compressions},
    {"sha256", "digest", sha256_digest},
    {"poseidon2", "permute", poseidon2_permute},
    {"poseidon2", "manifest_digest", poseidon2_manifest_digest},
    {"quorum", "threshold", quorum_threshold},
    {"quorum", "has_quorum", quorum_has_quorum},
    {"validator_session", "members", validator_session_members},
    {"validator_session", "identity", validator_session_identity},
    {"validator_session", "config_hash", validator_session_config_hash},
    {"validator_session", "options_hash", validator_session_options_hash},
    {"pq_bytes", "pack", pq_bytes_pack},
    {"pq_bytes", "unpack", pq_bytes_unpack},
    {"consensus", "simplex_data_to_sign", consensus_simplex_data_to_sign},
    {"block_signatures", "fetch", block_signatures_fetch},
    {"block_signatures", "fetch_tl", block_signatures_fetch_tl},
    {"config43", "parse", config43_parse},
    {"validator_set", "unpack", validator_set_unpack},
    {"elector", "stake_preimage", elector_stake_preimage},
    {"elector", "config_vote_preimage", elector_config_vote_preimage},
    {"elector", "complaint_vote_preimage", elector_complaint_vote_preimage},
};

td::Result<std::string> run_crypto(td::JsonObject &ctx) {
  TRY_RESULT(scheme, ctx.get_required_string_field("scheme"));
  TRY_RESULT(operation, ctx.get_required_string_field("operation"));
  OperationFn fn = nullptr;
  for (const auto &entry : kOperations) {
    if (scheme == entry.scheme && operation == entry.operation) {
      fn = entry.fn;
      break;
    }
  }
  if (fn == nullptr) {
    return td::Status::Error(PSLICE() << "unknown operation " << scheme << "/" << operation);
  }
  TRY_RESULT(edits, parse_edits(ctx));
  TRY_RESULT(inputs_value, ctx.extract_required_field("inputs", td::JsonValue::Type::Object));
  Inputs inputs{inputs_value.get_object(), std::move(edits)};
  TRY_RESULT(effects, fn(inputs));
  TRY_STATUS(inputs.check_edits_used());
  return effects;
}

}  // namespace

CONFORMANCE_REGISTER_HARNESS(crypto, run_crypto);
