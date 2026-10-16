/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#include <limits>

#include "common/errorcode.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/misc.h"

#include "json-rpc-contract.h"

namespace tos::json_rpc {

const std::vector<ErrorKind> &all_error_kinds() {
  static const std::vector<ErrorKind> kinds = {
      kParseError,
      kInvalidRequest,
      kMethodNotFound,
      kWriteDisabled,
      kInvalidArgument,
      kInternalError,
      kUnauthorized,
      kRateLimited,
      kNotFound,
      kConfigParamAbsent,
      kBlockUnavailable,
      kPermissionSourceUnsupported,
      kPermissionSourceDeferred,
      kIndexedStateStale,
      kLifecycleImmutable,
      kContractKindUnsupported,
      kUpstreamUnavailable,
      kUnsignedBlock,
      kBlockIdMismatch,
      kEvidenceInvalid,
      kUnsupportedCarrier,
      kStateInvalid,
      kResourceLimit,
      kVerificationBackendFailure,
  };
  return kinds;
}

const ErrorKind &error_kind_for_code(int code) {
  switch (code) {
    case -32700:
      return kParseError;
    case -32600:
      return kInvalidRequest;
    case -32601:
      return kMethodNotFound;
    case -32602:
      return kInvalidArgument;
    case -32000:
      return kUnauthorized;
    case -32004:
      return kNotFound;
    case -32005:
      return kRateLimited;
    default:
      return kInternalError;
  }
}

bool is_garbage_collected(const td::Status &cause) {
  auto message = cause.message().str();
  return message.find(kStateGarbageCollected) != std::string::npos ||
         message.find(kPackageGarbageCollected) != std::string::npos;
}

const ErrorKind &error_kind_for_upstream(const td::Status &cause, int fallback_code) {
  // Garbage-collected data never comes back on this node. "Not ready" also
  // covers a node that is still syncing and a block it has not applied yet,
  // so it stays retryable alongside timeouts.
  if (is_garbage_collected(cause)) {
    return kBlockUnavailable;
  }
  if (cause.code() == ErrorCode::timeout || cause.code() == ErrorCode::cancelled ||
      cause.code() == ErrorCode::notready) {
    return kUpstreamUnavailable;
  }
  return error_kind_for_code(fallback_code);
}

std::string result_body(td::Slice id, td::Slice result_json) {
  // A growable builder: a fixed-size one would silently cut a large result.
  td::StringBuilder sb;
  sb << "{\"jsonrpc\":\"2.0\",\"id\":" << (id.empty() ? td::Slice("null") : id) << ",\"result\":" << result_json << "}";
  return sb.as_cslice().str();
}

std::string error_body(td::Slice id, const ErrorKind &kind, td::Slice message) {
  td::StringBuilder sb;
  sb << "{\"jsonrpc\":\"2.0\",\"id\":" << (id.empty() ? td::Slice("null") : id) << ",\"error\":{\"code\":" << kind.code
     << ",\"message\":" << td::JsonString(message) << ",\"data\":{\"schema_version\":1,\"reason\":\"" << kind.reason
     << "\",\"retryable\":" << (kind.retryable ? "true" : "false") << "}}}";
  return sb.as_cslice().str();
}

namespace {

const td::JsonValue *find_field(const td::JsonObject &object, td::Slice name) {
  for (const auto &item : object.field_values_) {
    if (item.first == name) {
      return &item.second;
    }
  }
  return nullptr;
}

td::Status param_error(td::Slice name, td::Slice expectation) {
  return td::Status::Error(-32602, PSLICE() << "Invalid '" << name << "': " << expectation);
}

// A JSON number holding exactly an integer of type T, written canonically:
// "1.0", "1e3", "-0" and out-of-range values are all refused.
template <class T>
td::Result<T> canonical_integer(const td::JsonValue &value) {
  if (value.type() != td::JsonValue::Type::Number) {
    return td::Status::Error("not a number");
  }
  auto text = value.get_number();
  auto parsed = td::to_integer_safe<T>(text);
  if (parsed.is_error() || std::to_string(parsed.ok()) != text.str()) {
    return td::Status::Error("not a canonical integer");
  }
  return parsed.move_as_ok();
}

}  // namespace

td::Result<Envelope> check_envelope(const td::JsonObject &request) {
  Envelope envelope;
  const auto *version = find_field(request, "jsonrpc");
  if (version == nullptr || version->type() != td::JsonValue::Type::String || version->get_string() != "2.0") {
    return td::Status::Error(-32600, "Invalid Request: 'jsonrpc' must be the string \"2.0\"");
  }
  const auto *method = find_field(request, "method");
  if (method == nullptr || method->type() != td::JsonValue::Type::String) {
    return td::Status::Error(-32600, "Invalid Request: 'method' must be a string");
  }
  envelope.method = method->get_string().str();
  const auto *params = find_field(request, "params");
  if (params != nullptr) {
    if (params->type() == td::JsonValue::Type::Array) {
      return td::Status::Error(-32602,
                               "Invalid params: positional parameters are not supported; 'params' must be an object");
    }
    if (params->type() != td::JsonValue::Type::Object) {
      return td::Status::Error(-32600, "Invalid Request: 'params' must be an object when present");
    }
  }
  envelope.notification = find_field(request, "id") == nullptr;
  return envelope;
}

td::Result<td::int32> parse_workchain_param(const td::JsonObject &params, td::Slice name) {
  const auto *value = find_field(params, name);
  if (value == nullptr) {
    return param_error(name, "required");
  }
  auto parsed = canonical_integer<td::int32>(*value);
  if (parsed.is_error()) {
    return param_error(name, "must be a JSON integer in the signed 32-bit range");
  }
  return parsed.move_as_ok();
}

td::Result<std::optional<td::int32>> parse_optional_seqno_param(const td::JsonObject &params, td::Slice name) {
  const auto *value = find_field(params, name);
  if (value == nullptr) {
    return std::optional<td::int32>{};
  }
  auto parsed = canonical_integer<td::int32>(*value);
  if (parsed.is_error() || parsed.ok() < 0) {
    return param_error(name, "must be a JSON integer in [0, 2147483647]");
  }
  return std::optional<td::int32>{parsed.ok()};
}

td::Result<td::int32> parse_seqno_param(const td::JsonObject &params, td::Slice name) {
  TRY_RESULT(seqno, parse_optional_seqno_param(params, name));
  if (!seqno) {
    return param_error(name, "required");
  }
  return *seqno;
}

td::Result<td::int64> parse_shard_param(const td::JsonObject &params, td::Slice name) {
  const auto *value = find_field(params, name);
  if (value == nullptr) {
    return param_error(name, "required");
  }
  if (value->type() != td::JsonValue::Type::String) {
    return param_error(name, "must be a string holding the signed decimal shard id");
  }
  auto text = value->get_string();
  auto parsed = td::to_integer_safe<td::int64>(text);
  if (parsed.is_error() || std::to_string(parsed.ok()) != text.str() || parsed.ok() == 0) {
    return param_error(name, "must be the signed decimal shard id, e.g. \"-9223372036854775808\"");
  }
  return parsed.move_as_ok();
}

td::Result<BlockSelector> parse_block_selector(const td::JsonObject &params) {
  BlockSelector selector;
  TRY_RESULT_ASSIGN(selector.workchain, parse_workchain_param(params));
  TRY_RESULT_ASSIGN(selector.shard, parse_shard_param(params));
  TRY_RESULT_ASSIGN(selector.seqno, parse_seqno_param(params));
  return selector;
}

td::Result<std::optional<td::int64>> parse_optional_lt_param(const td::JsonObject &params, td::Slice name) {
  const auto *value = find_field(params, name);
  if (value == nullptr) {
    return std::optional<td::int64>{};
  }
  td::Slice text;
  if (value->type() == td::JsonValue::Type::String) {
    text = value->get_string();
  } else if (value->type() == td::JsonValue::Type::Number) {
    text = value->get_number();
  } else {
    return param_error(name, "must be a non-negative decimal integer");
  }
  auto parsed = td::to_integer_safe<td::int64>(text);
  if (parsed.is_error() || parsed.ok() < 0 || std::to_string(parsed.ok()) != text.str()) {
    return param_error(name, "must be a non-negative decimal integer");
  }
  return std::optional<td::int64>{parsed.ok()};
}

}  // namespace tos::json_rpc
