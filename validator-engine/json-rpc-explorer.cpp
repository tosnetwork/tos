/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <cstdlib>
#include <limits>
#include <unordered_set>

#include "block/auth-policy.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/dict.h"

#include "json-rpc-explorer.h"

namespace tos::explorer {
td::Status error(Failure failure) {
  return td::Status::Error(static_cast<int>(failure),
                           td::Slice(error_kind(td::Status::Error(static_cast<int>(failure), "")).reason));
}
const json_rpc::ErrorKind& error_kind(const td::Status& status) {
  switch (static_cast<Failure>(status.code())) {
    case Failure::InvalidArgument:
      return json_rpc::kInvalidArgument;
    case Failure::UnsignedBlock:
      return json_rpc::kUnsignedBlock;
    case Failure::BlockIdMismatch:
      return json_rpc::kBlockIdMismatch;
    case Failure::BlockUnavailable:
      return json_rpc::kBlockUnavailable;
    case Failure::EvidenceInvalid:
      return json_rpc::kEvidenceInvalid;
    case Failure::UnsupportedCarrier:
      return json_rpc::kUnsupportedCarrier;
    case Failure::StateInvalid:
      return json_rpc::kStateInvalid;
    case Failure::ResourceLimit:
      return json_rpc::kResourceLimit;
    case Failure::UpstreamUnavailable:
      return json_rpc::kUpstreamUnavailable;
    case Failure::BackendFailure:
      return json_rpc::kVerificationBackendFailure;
    case Failure::ConfigParamAbsent:
      return json_rpc::kConfigParamAbsent;
  }
  return json_rpc::kEvidenceInvalid;
}
bool retryable(const td::Status& status) {
  return error_kind(status).retryable;
}
td::Status upstream_error(const td::Status& status) {
  // The evidence for a block is built from that block's state and its
  // predecessor's. Once the node has garbage-collected either, the request
  // is outside the history this node serves, and repeating it cannot help.
  if (status.code() == ErrorCode::notready || json_rpc::is_garbage_collected(status))
    return error(Failure::BlockUnavailable);
  if (status.code() == ErrorCode::protoviolation)
    return error(Failure::EvidenceInvalid);
  if (status.code() == block::kPQVerificationBackendFailure)
    return error(Failure::BackendFailure);
  return error(Failure::UpstreamUnavailable);
}
td::Result<td::Bits256> parse_hash(td::Slice encoded) {
  if (encoded.size() != 44)
    return error(Failure::InvalidArgument);
  auto decoded = td::base64_decode(encoded);
  if (decoded.is_error() || decoded.ok().size() != 32 || td::base64_encode(decoded.ok()) != encoded)
    return error(Failure::InvalidArgument);
  td::Bits256 hash;
  hash.as_slice().copy_from(decoded.ok());
  return hash;
}
namespace {
const td::JsonValue* field(const td::JsonObject& object, td::Slice name) {
  for (const auto& item : object.field_values_)
    if (item.first == name)
      return &item.second;
  return nullptr;
}
// The shared strict parsers decide what an integer parameter is; the
// verified views only translate a refusal into their own reason.
td::Result<td::int32> integer(const td::JsonObject& object, td::Slice name) {
  auto result = json_rpc::parse_workchain_param(object, name);
  if (result.is_error())
    return error(Failure::InvalidArgument);
  return result.move_as_ok();
}
}  // namespace
td::Result<Selector> parse_selector(const td::JsonObject& params, bool required) {
  Selector result;
  {
    auto seqno = json_rpc::parse_optional_seqno_param(params);
    if (seqno.is_error())
      return error(Failure::InvalidArgument);
    if (seqno.ok())
      result.seqno = *seqno.ok();
  }
  if (params.has_field("block_id")) {
    auto value = field(params, "block_id");
    if (!value || value->type() != td::JsonValue::Type::Object)
      return error(Failure::InvalidArgument);
    const auto& object = value->get_object();
    std::unordered_set<std::string> fields;
    for (const auto& item : object.field_values_) {
      if (!fields.insert(item.first.str()).second ||
          (item.first == "@type" && item.second.type() != td::JsonValue::Type::String))
        return error(Failure::InvalidArgument);
      if (item.first != "workchain" && item.first != "shard" && item.first != "seqno" && item.first != "root_hash" &&
          item.first != "file_hash" && item.first != "@type")
        return error(Failure::InvalidArgument);
    }
    TRY_RESULT(wc, integer(object, "workchain"));
    TRY_RESULT(seqno, integer(object, "seqno"));
    auto shard = object.get_required_string_field("shard");
    auto root = object.get_required_string_field("root_hash");
    auto file = object.get_required_string_field("file_hash");
    if (wc != -1 || seqno < 0 || shard.is_error() || shard.ok() != "-9223372036854775808" || root.is_error() ||
        file.is_error())
      return error(Failure::InvalidArgument);
    TRY_RESULT(root_hash, parse_hash(root.ok()));
    TRY_RESULT(file_hash, parse_hash(file.ok()));
    result.block_id =
        BlockIdExt{BlockId{masterchainId, shardIdAll, static_cast<BlockSeqno>(seqno)}, root_hash, file_hash};
    if (result.seqno && *result.seqno != seqno)
      return error(Failure::InvalidArgument);
    result.seqno = seqno;
  }
  if (required && !result.seqno)
    return error(Failure::InvalidArgument);
  return result;
}
td::Status Selector::check(const BlockIdExt& resolved) const {
  if (!resolved.is_masterchain_ext() ||
      resolved.seqno() > static_cast<BlockSeqno>(std::numeric_limits<td::int32>::max()) ||
      (seqno && resolved.seqno() != static_cast<BlockSeqno>(*seqno)))
    return error(Failure::EvidenceInvalid);
  if (block_id && *block_id != resolved)
    return error(Failure::BlockIdMismatch);
  return td::Status::OK();
}
std::string raw_address(td::int32 workchain, const td::Bits256& hash) {
  return std::to_string(workchain) + ":" + td::to_lower(hash.to_hex());
}
std::string block_json(const BlockIdExt& id) {
  td::StringBuilder out;
  out << "{\"@type\":\"tos.blockIdExt\",\"workchain\":" << id.id.workchain << ",\"shard\":\""
      << static_cast<td::int64>(id.id.shard) << "\",\"seqno\":" << id.seqno() << ",\"root_hash\":\""
      << td::base64_encode(id.root_hash.as_slice()) << "\",\"file_hash\":\""
      << td::base64_encode(id.file_hash.as_slice()) << "\"}";
  return out.as_cslice().str();
}
std::atomic<unsigned> WorkPermit::active_{0};
unsigned WorkPermit::limit() {
  static const unsigned configured = [] {
    const auto* input = std::getenv("TOS_EXPLORER_RPC_JOBS");
    if (!input)
      return 2u;
    auto value = td::to_integer_safe<unsigned>(td::Slice(input));
    if (value.is_error() || value.ok() < 1 || value.ok() > 8) {
      LOG(WARNING) << "Invalid explorer worker count; using the default";
      return 2u;
    }
    return value.ok();
  }();
  return configured;
}
std::shared_ptr<WorkPermit> WorkPermit::acquire() {
  auto count = active_.load();
  while (count < limit()) {
    if (active_.compare_exchange_weak(count, count + 1))
      return std::shared_ptr<WorkPermit>(new WorkPermit);
  }
  return {};
}
WorkPermit::~WorkPermit() {
  active_.fetch_sub(1);
}
td::Status dispatch_work(control_getter::Executor::Admission& admission, std::shared_ptr<WorkPermit> permit,
                         control_getter::Executor::Work work, control_getter::Executor::Completion completion) {
  // Both closures keep evidence processing charged through actual completion.
  // Destroying a timed-out request cannot grant a third worker a reservation.
  return admission.dispatch([permit, work = std::move(work)] { return work(); },
                            [permit = std::move(permit), completion = std::move(completion)](
                                td::Status status) mutable { completion(std::move(status)); });
}
td::Status inspect_cells(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data) {
  try {
    std::vector<td::Ref<vm::Cell>> pending;
    if (code.not_null())
      pending.push_back(code);
    if (data.not_null())
      pending.push_back(data);
    std::unordered_set<vm::CellHash> seen;
    while (!pending.empty()) {
      auto cell = std::move(pending.back());
      pending.pop_back();
      if (!seen.insert(cell->get_hash()).second)
        continue;
      if (seen.size() > 2048 || cell->get_depth() > 128)
        return error(Failure::ResourceLimit);
      bool special = false;
      auto slice = vm::load_cell_slice_special(cell, special);
      if (special || cell->get_level() != 0)
        return error(Failure::StateInvalid);
      while (slice.size_refs())
        pending.push_back(slice.fetch_ref());
    }
    std::size_t bytes = 0;
    for (const auto& cell : {code, data}) {
      if (cell.is_null())
        continue;
      TRY_RESULT(boc, vm::std_boc_serialize(cell));
      if (boc.size() > kInspectionBytes - bytes)
        return error(Failure::ResourceLimit);
      bytes += boc.size();
    }
    return td::Status::OK();
  } catch (vm::VmError&) {
    return error(Failure::StateInvalid);
  } catch (vm::VmVirtError&) {
    return error(Failure::StateInvalid);
  }
}

td::Result<std::string> decode_config(int param, td::Ref<vm::Cell> cell, td::uint32 version, td::uint32 now) {
  try {
    td::StringBuilder out;
    if (cell.not_null())
      TRY_STATUS(inspect_cells({}, cell));
    if (param == 8) {
      if (cell.is_null())
        return error(Failure::StateInvalid);
      auto s = vm::load_cell_slice(cell);
      if (s.size() != 104 || s.size_refs() || s.fetch_ulong(8) != 0xc4)
        return error(Failure::StateInvalid);
      auto vm_version = s.fetch_ulong(32);
      auto caps = s.fetch_ulong(64);
      out << "{\"kind\":\"global_version\",\"version\":" << vm_version << ",\"capabilities\":\"" << caps << "\"}";
    } else if (param == 48) {
      if (cell.is_null()) {
        if (version >= 16)
          return error(Failure::StateInvalid);
        return std::string("null");
      }
      auto decoded = block::unpack_auth_policy(cell);
      if (decoded.is_error())
        return error(Failure::StateInvalid);
      auto policy = decoded.move_as_ok();
      td::Bits256 profile;
      td::sha256(block::auth_policy_profile, profile.as_slice());
      out << "{\"kind\":\"auth_policy_v1\",\"network_tag\":\"" << td::base64_encode(policy.network.as_slice())
          << "\",\"policy_sequence\":\"" << policy.sequence << "\",\"retired_flags\":" << policy.retired
          << ",\"primary_deadline\":";
      if (policy.deadline)
        out << policy.deadline;
      else
        out << "null";
      out << ",\"policy_spec_hash\":\"" << td::base64_encode(profile.as_slice()) << "\",\"primary_status\":\""
          << (((policy.retired & 2) || (policy.deadline && now >= policy.deadline)) ? "retired" : "not_retired")
          << "\"}";
    } else if (param == 43) {
      td::Ref<vm::CellSlice> slice;
      unsigned wire = 0;
      if (cell.not_null()) {
        slice = vm::load_cell_slice_ref(cell);
        wire = static_cast<unsigned>(slice->prefetch_ulong(8));
        if (wire < 1 || wire > 3 || !block::gen::t_SizeLimitsConfig.validate_ref(10000, cell))
          return error(Failure::StateInvalid);
      }
      auto decoded = block::Config::do_get_size_limits_config(slice);
      if (decoded.is_error())
        return error(Failure::StateInvalid);
      const auto& v = decoded.ok();
      const std::vector<std::string> names = {"max_msg_bits",
                                              "max_msg_cells",
                                              "max_library_cells",
                                              "max_vm_data_depth",
                                              "max_ext_msg_size",
                                              "max_ext_msg_depth",
                                              "max_acc_state_cells",
                                              "max_mc_acc_state_cells",
                                              "max_acc_public_libraries",
                                              "defer_out_queue_size_limit",
                                              "max_msg_extra_currencies",
                                              "max_acc_fixed_prefix_length",
                                              "acc_state_cells_for_storage_dict",
                                              "max_transaction_library_loads",
                                              "max_total_msg_bits",
                                              "max_total_msg_cells",
                                              "out_msg_queue_size_hard_limit",
                                              "out_msg_queue_size_soft_limit"};
      const std::vector<std::string> values = {
          std::to_string(v.max_msg_bits),
          std::to_string(v.max_msg_cells),
          std::to_string(v.max_library_cells),
          std::to_string(v.max_vm_data_depth),
          std::to_string(v.ext_msg_limits.max_size),
          std::to_string(v.ext_msg_limits.max_depth),
          std::to_string(v.max_acc_state_cells),
          std::to_string(v.max_mc_acc_state_cells),
          std::to_string(v.max_acc_public_libraries),
          std::to_string(v.defer_out_queue_size_limit),
          std::to_string(v.max_msg_extra_currencies),
          std::to_string(v.max_acc_fixed_prefix_length),
          std::to_string(v.acc_state_cells_for_storage_dict),
          v.max_transaction_library_loads ? std::to_string(v.max_transaction_library_loads.value()) : "null",
          std::to_string(v.max_total_msg_bits),
          std::to_string(v.max_total_msg_cells),
          std::to_string(v.out_msg_queue_size_hard_limit),
          std::to_string(v.out_msg_queue_size_soft_limit)};
      auto fields = [&](std::size_t n) {
        out << "{";
        for (std::size_t i = 0; i < n; ++i) {
          if (i)
            out << ",";
          out << "\"" << names[i] << "\":" << values[i];
        }
        out << "}";
      };
      auto configured = wire == 1 ? 6u : wire == 2 ? 13u : wire == 3 ? 18u : 0u;
      out << "{\"kind\":\"size_limits\",\"wire_version\":";
      if (wire)
        out << wire;
      else
        out << "null";
      out << ",\"configured\":";
      if (wire)
        fields(configured);
      else
        out << "null";
      out << ",\"effective\":";
      fields(names.size());
      out << ",\"defaulted_fields\":[";
      for (std::size_t i = configured; i < names.size(); ++i) {
        if (i != configured)
          out << ",";
        out << "\"" << names[i] << "\"";
      }
      out << "]}";
    } else
      return error(Failure::InvalidArgument);
    return out.as_cslice().str();
  } catch (vm::VmError&) {
    return error(Failure::StateInvalid);
  } catch (vm::VmVirtError&) {
    return error(Failure::StateInvalid);
  }
}
}  // namespace tos::explorer
