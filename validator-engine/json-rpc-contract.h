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
#pragma once

// The wire contract of the JSON-RPC server, kept free of actors and HTTP so
// it can be unit tested: the response bodies, the typed error reasons, the
// request envelope rules and the strict block-selector parameters. doc/openapi.yaml
// documents the same contract; scripts/check-jsonrpc-spec.py keeps the two
// aligned.

#include <optional>
#include <string>
#include <vector>

#include "td/utils/JsonBuilder.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"

namespace tos::json_rpc {

// One kind of error answer. `reason` is the stable machine-readable name a
// client branches on; `code` is the JSON-RPC error code it travels under;
// `retryable` says whether repeating the same request can succeed.
struct ErrorKind {
  const char *reason;
  int code;
  bool retryable;
};

// Protocol-level errors.
inline constexpr ErrorKind kParseError{"PARSE_ERROR", -32700, false};
inline constexpr ErrorKind kInvalidRequest{"INVALID_REQUEST", -32600, false};
inline constexpr ErrorKind kMethodNotFound{"METHOD_NOT_FOUND", -32601, false};
inline constexpr ErrorKind kWriteDisabled{"WRITE_DISABLED", -32601, false};
inline constexpr ErrorKind kInvalidArgument{"INVALID_ARGUMENT", -32602, false};
inline constexpr ErrorKind kInternalError{"INTERNAL_ERROR", -32603, false};
inline constexpr ErrorKind kUnauthorized{"UNAUTHORIZED", -32000, false};
inline constexpr ErrorKind kRateLimited{"RATE_LIMITED", -32005, true};

// Data that is permanently absent from this node's answer.
inline constexpr ErrorKind kNotFound{"NOT_FOUND", -32004, false};
inline constexpr ErrorKind kConfigParamAbsent{"CONFIG_PARAM_ABSENT", -32004, false};
inline constexpr ErrorKind kBlockUnavailable{"BLOCK_UNAVAILABLE", -32004, false};

// The request is well formed but the account or contract does not offer it.
inline constexpr ErrorKind kPermissionSourceUnsupported{"PERMISSION_SOURCE_UNSUPPORTED", -32006, false};
inline constexpr ErrorKind kPermissionSourceDeferred{"PERMISSION_SOURCE_DEFERRED", -32006, false};
inline constexpr ErrorKind kIndexedStateStale{"INDEXED_STATE_STALE", -32006, false};
inline constexpr ErrorKind kLifecycleImmutable{"LIFECYCLE_IMMUTABLE", -32006, false};
inline constexpr ErrorKind kContractKindUnsupported{"CONTRACT_KIND_UNSUPPORTED", -32006, false};

// The node could not answer now; the same request can succeed later.
inline constexpr ErrorKind kUpstreamUnavailable{"UPSTREAM_UNAVAILABLE", -32603, true};

// Verified-view (explorer) failures.
inline constexpr ErrorKind kUnsignedBlock{"UNSIGNED_BLOCK", -32602, false};
inline constexpr ErrorKind kBlockIdMismatch{"BLOCK_ID_MISMATCH", -32009, false};
inline constexpr ErrorKind kEvidenceInvalid{"EVIDENCE_INVALID", -32603, false};
inline constexpr ErrorKind kUnsupportedCarrier{"UNSUPPORTED_CARRIER", -32603, false};
inline constexpr ErrorKind kStateInvalid{"STATE_INVALID", -32603, false};
inline constexpr ErrorKind kResourceLimit{"RESOURCE_LIMIT", -32603, false};
inline constexpr ErrorKind kVerificationBackendFailure{"VERIFICATION_BACKEND_FAILURE", -32603, true};

// Every kind above, in documentation order. The spec check compares this
// list with the reason enum in doc/openapi.yaml.
const std::vector<ErrorKind> &all_error_kinds();

// The kind an error code means when the call site names no reason.
const ErrorKind &error_kind_for_code(int code);

// True when the node's query path failed because the data it needed -- a
// block's state or its archive package -- has been garbage-collected.
bool is_garbage_collected(const td::Status &cause);

// The kind for a failure reported by the node's own query path: data the
// node has garbage-collected is outside its served history
// (BLOCK_UNAVAILABLE), a timeout or a not-ready answer is retryable
// (UPSTREAM_UNAVAILABLE), and anything else falls back to the call site's
// code.
const ErrorKind &error_kind_for_upstream(const td::Status &cause, int fallback_code);

// `{"jsonrpc":"2.0","id":<id>,"result":<result_json>}`. `id` and
// `result_json` are serialized JSON values; an empty id is written as null.
std::string result_body(td::Slice id, td::Slice result_json);

// `{"jsonrpc":"2.0","id":<id>,"error":{"code","message","data":{...}}}`.
std::string error_body(td::Slice id, const ErrorKind &kind, td::Slice message);

// What the request envelope asks for, once it has been validated.
struct Envelope {
  std::string method;
  // No `id` member at all. A null id is a request, not a notification.
  bool notification{false};
};

// Validates a single request object against the envelope rules:
//   jsonrpc  exactly the string "2.0";
//   method   a string;
//   params   absent or an object -- an array is refused as positional
//            parameters, anything else as an invalid request.
// The error's code is the JSON-RPC code to answer with (-32600 or -32602).
// The id is validated separately (reflected_request_id), before this runs.
td::Result<Envelope> check_envelope(const td::JsonObject &request);

// Strict block-selector parameters, shared by every method that takes them.
// A present value must be the whole value of the right JSON type and range;
// a wrong one is an error naming the parameter, never a default.
//
//   workchain  JSON integer in the signed 32-bit range
//   seqno      JSON integer in [0, 2^31 - 1]
//   shard      JSON string holding the signed decimal of the 64-bit shard id,
//              written exactly as responses write it (no sign on positive
//              values, no leading zeros, not zero)
//
// The required variants fail when the parameter is missing.
td::Result<td::int32> parse_workchain_param(const td::JsonObject &params, td::Slice name = td::Slice("workchain"));
td::Result<td::int32> parse_seqno_param(const td::JsonObject &params, td::Slice name = td::Slice("seqno"));
td::Result<std::optional<td::int32>> parse_optional_seqno_param(const td::JsonObject &params,
                                                                td::Slice name = td::Slice("seqno"));
td::Result<td::int64> parse_shard_param(const td::JsonObject &params, td::Slice name = td::Slice("shard"));
// workchain + shard + seqno, all required, as the block-addressed methods take them.
struct BlockSelector {
  td::int32 workchain{0};
  td::int64 shard{0};
  td::int32 seqno{0};
};
td::Result<BlockSelector> parse_block_selector(const td::JsonObject &params);
// A logical time: the canonical decimal of a non-negative 64-bit integer, as a
// JSON string (the form responses use) or a JSON integer.
td::Result<std::optional<td::int64>> parse_optional_lt_param(const td::JsonObject &params, td::Slice name);

}  // namespace tos::json_rpc
