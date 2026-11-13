// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// validate harness: the node's block-candidate validation (ValidateQuery) of one candidate, offline
// (schema/harness/validate-v1.schema.json). The context carries the candidate and every state the
// validation asks the validator manager for; validate-offline.cpp serves them and runs the node's own
// run_validate_query on a single-threaded actor scheduler. A state may be a Merkle proof of the state,
// holding the cells the validation reads; a read of a pruned cell is part of the outcome.
#include <cmath>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "td/utils/base64.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"

#include "common.h"
#include "validate-offline.hpp"

namespace {

using conformance::validate::Verdict;

constexpr std::size_t kMaxStates = 32;
constexpr std::size_t kMaxBlockBytes = 32 << 20;

td::Result<td::Bits256> hash_field(td::JsonObject &obj, td::Slice field) {
  TRY_RESULT(text, obj.get_required_string_field(field));
  if (text.size() != 64) {
    return td::Status::Error(PSLICE() << field << ": 64 hex digits required");
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
  td::Bits256 bits;
  std::memcpy(bits.data(), bytes.ok().data(), 32);
  return bits;
}

td::Result<tos::BlockIdExt> block_id(td::JsonValue &value, td::Slice where) {
  if (value.type() != td::JsonValue::Type::Object) {
    return td::Status::Error(PSLICE() << where << ": object required");
  }
  auto &obj = value.get_object();
  TRY_RESULT(workchain, obj.get_required_int_field("workchain"));
  TRY_RESULT(shard_text, obj.get_required_string_field("shard"));
  if (shard_text.size() != 16 || shard_text.find_first_not_of("0123456789abcdef") != std::string::npos) {
    return td::Status::Error(PSLICE() << where << ".shard: 16 lowercase hex digits required");
  }
  auto shard = td::hex_to_integer_safe<td::uint64>(shard_text);
  if (shard.is_error() || shard.ok() == 0) {
    return td::Status::Error(PSLICE() << where << ".shard: not a shard");
  }
  TRY_RESULT(seqno, obj.get_required_long_field("seqno"));
  if (seqno < 0 || seqno > 0xffffffffLL) {
    return td::Status::Error(PSLICE() << where << ".seqno: 0..2^32-1 required");
  }
  TRY_RESULT(root_hash, hash_field(obj, "root_hash"));
  TRY_RESULT(file_hash, hash_field(obj, "file_hash"));
  return tos::BlockIdExt{workchain, shard.ok(), static_cast<tos::BlockSeqno>(seqno), root_hash, file_hash};
}

td::Result<tos::BlockIdExt> block_id_field(td::JsonObject &ctx, td::Slice field) {
  TRY_RESULT(value, ctx.extract_required_field(field, td::JsonValue::Type::Object));
  return block_id(value, field);
}

td::Result<td::BufferSlice> base64_field(td::JsonObject &ctx, td::Slice field) {
  TRY_RESULT(b64, ctx.get_required_string_field(field));
  TRY_RESULT(bytes, td::base64_decode(b64));
  if (bytes.size() > kMaxBlockBytes) {
    return td::Status::Error(PSLICE() << field << ": larger than " << kMaxBlockBytes << " bytes");
  }
  return td::BufferSlice(bytes);
}

// A state root, or the virtual root of a Merkle proof of it.
td::Result<td::Ref<vm::Cell>> state_root(td::Slice b64, td::Slice where) {
  TRY_RESULT(root, conformance::boc_from_base64(b64));
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  if (special && cs.special_type() == vm::Cell::SpecialType::MerkleProof) {
    auto virtualized = vm::MerkleProof::virtualize(root);
    if (virtualized.is_error()) {
      return virtualized.move_as_error_prefix(PSLICE() << where << ": ");
    }
    return virtualized.move_as_ok();
  }
  return root;
}

td::Result<std::vector<conformance::validate::ServedState>> states_field(td::JsonObject &ctx) {
  TRY_RESULT(value, ctx.extract_required_field("states", td::JsonValue::Type::Array));
  auto &items = value.get_array();
  if (items.size() > kMaxStates) {
    return td::Status::Error(PSLICE() << "states: more than " << kMaxStates << " items");
  }
  std::vector<conformance::validate::ServedState> states;
  for (std::size_t i = 0; i < items.size(); ++i) {
    std::string where = PSTRING() << "states[" << i << "]";
    if (items[i].type() != td::JsonValue::Type::Object) {
      return td::Status::Error(PSLICE() << where << ": object required");
    }
    auto &item = items[i].get_object();
    TRY_RESULT(id_value, item.extract_required_field("block", td::JsonValue::Type::Object));
    TRY_RESULT(id, block_id(id_value, where + ".block"));
    TRY_RESULT(b64, item.get_required_string_field("state"));
    TRY_RESULT(root, state_root(b64, where + ".state"));
    states.push_back({id, std::move(root)});
  }
  return states;
}

td::Result<std::string> run_validate(td::JsonObject &ctx) {
  conformance::validate::Request request;
  TRY_RESULT_ASSIGN(request.candidate, block_id_field(ctx, "block_id"));
  TRY_RESULT_ASSIGN(request.data, base64_field(ctx, "block"));
  if (ctx.has_field("collated_data")) {
    TRY_RESULT_ASSIGN(request.collated_data, base64_field(ctx, "collated_data"));
  }
  TRY_RESULT_ASSIGN(request.created_by, hash_field(ctx, "created_by"));
  {
    TRY_RESULT(prev, ctx.extract_required_field("prev", td::JsonValue::Type::Array));
    auto &items = prev.get_array();
    if (items.empty() || items.size() > 2) {
      return td::Status::Error("prev: one or two block ids required");
    }
    for (std::size_t i = 0; i < items.size(); ++i) {
      TRY_RESULT(id, block_id(items[i], PSLICE() << "prev[" << i << "]"));
      request.prev.push_back(id);
    }
  }
  TRY_RESULT_ASSIGN(request.min_masterchain, block_id_field(ctx, "min_masterchain"));
  TRY_RESULT_ASSIGN(request.top_masterchain, block_id_field(ctx, "top_masterchain"));
  TRY_RESULT_ASSIGN(request.validator_set_from, block_id_field(ctx, "validator_set_from"));
  TRY_RESULT_ASSIGN(request.skip_shard_signatures, ctx.get_optional_bool_field("skip_shard_signatures", false));
  TRY_RESULT_ASSIGN(request.states, states_field(ctx));

  TRY_RESULT(outcome, conformance::validate::run(std::move(request)));
  switch (outcome.verdict) {
    case Verdict::accepted:
      return PSTRING() << "{\"outcome\":\"accepted\",\"ok_from_utime_ms\":"
                       << static_cast<td::int64>(std::llround(outcome.ok_from_utime * 1000.0)) << "}";
    case Verdict::rejected:
      return "{\"outcome\":\"rejected\",\"reason\":" +
             conformance::json_quote(td::Slice(conformance::validate::classify(outcome))) + "}";
    case Verdict::error:
      return "{\"outcome\":\"error\",\"reason\":" +
             conformance::json_quote(td::Slice(conformance::validate::classify(outcome))) + "}";
  }
  return td::Status::Error("unknown verdict");
}

}  // namespace

CONFORMANCE_REGISTER_HARNESS(validate, run_validate);
