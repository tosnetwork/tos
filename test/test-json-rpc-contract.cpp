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

// The JSON-RPC wire contract: one success shape, one error shape with a typed
// reason, the envelope rules and the strict block-selector parameters. Every
// negative case below checks the specific refusal (its code and the named
// parameter), not merely that something failed.

#include <limits>
#include <set>
#include <string>

#include "common/errorcode.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/tests.h"

#include "json-rpc-contract.h"

namespace {

namespace rpc = tos::json_rpc;

// Decodes `text` and runs `f` on the object. The decoded value borrows from
// the buffer, so both stay in this frame.
template <class F>
void with_object(std::string text, F &&f) {
  auto value = td::json_decode(td::MutableSlice(text));
  ASSERT_TRUE(value.is_ok());
  ASSERT_TRUE(value.ok().type() == td::JsonValue::Type::Object);
  f(value.ok_ref().get_object());
}

void expect_param_error(const td::Status &status, const std::string &name) {
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(status.code(), -32602);
  ASSERT_TRUE(status.message().str().find("'" + name + "'") != std::string::npos);
}

}  // namespace

TEST(JsonRpcContract, error_body_is_one_json_rpc_object_with_typed_data) {
  auto body = rpc::error_body("7", rpc::kConfigParamAbsent, "config param 36 not found");
  ASSERT_EQ(body,
            std::string("{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32004,\"message\":\"config param 36 not "
                        "found\",\"data\":{\"schema_version\":1,\"reason\":\"CONFIG_PARAM_ABSENT\",\"retryable\":"
                        "false}}}"));
  // It parses, and carries no field outside the JSON-RPC 2.0 response object.
  with_object(body, [](td::JsonObject &object) {
    std::set<std::string> fields;
    for (auto &item : object.field_values_) {
      fields.insert(item.first.str());
    }
    ASSERT_TRUE(fields == (std::set<std::string>{"jsonrpc", "id", "error"}));
  });
  // A message is escaped, never spliced.
  auto escaped = rpc::error_body("null", rpc::kInvalidArgument, "bad \"x\"\n");
  with_object(escaped, [](td::JsonObject &) {});
  // An empty id is written as null.
  ASSERT_TRUE(rpc::error_body("", rpc::kInternalError, "x").find("\"id\":null") != std::string::npos);
}

TEST(JsonRpcContract, result_body_has_no_extra_fields_and_is_not_truncated) {
  std::string payload = "\"" + std::string(200 * 1024, 'x') + "\"";
  auto body = rpc::result_body("\"a\"", payload);
  ASSERT_EQ(body, "{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"result\":" + payload + "}");
  ASSERT_TRUE(rpc::result_body("", "1") == "{\"jsonrpc\":\"2.0\",\"id\":null,\"result\":1}");
}

TEST(JsonRpcContract, reasons_are_unique_and_codes_are_json_rpc_codes) {
  std::set<std::string> reasons;
  for (const auto &kind : rpc::all_error_kinds()) {
    ASSERT_TRUE(reasons.insert(kind.reason).second);
    // Reserved protocol codes or the implementation-defined server range.
    ASSERT_TRUE((kind.code <= -32600 && kind.code >= -32700) || (kind.code <= -32000 && kind.code >= -32099));
  }
}

TEST(JsonRpcContract, codes_map_to_their_default_reasons) {
  ASSERT_EQ(std::string(rpc::error_kind_for_code(-32700).reason), "PARSE_ERROR");
  ASSERT_EQ(std::string(rpc::error_kind_for_code(-32600).reason), "INVALID_REQUEST");
  ASSERT_EQ(std::string(rpc::error_kind_for_code(-32601).reason), "METHOD_NOT_FOUND");
  ASSERT_EQ(std::string(rpc::error_kind_for_code(-32602).reason), "INVALID_ARGUMENT");
  ASSERT_EQ(std::string(rpc::error_kind_for_code(-32603).reason), "INTERNAL_ERROR");
  ASSERT_EQ(std::string(rpc::error_kind_for_code(-32005).reason), "RATE_LIMITED");
  ASSERT_TRUE(rpc::error_kind_for_code(-32005).retryable);
  ASSERT_TRUE(!rpc::error_kind_for_code(-32603).retryable);
}

TEST(JsonRpcContract, garbage_collected_history_is_permanent_and_timeouts_are_not) {
  // The exact errors the databases return once a block's state or archive
  // package is gone. Answered as outside the served history, never retryable.
  auto state = td::Status::Error(tos::ErrorCode::error, td::Slice(tos::kStateGarbageCollected));
  auto package = td::Status::Error(tos::ErrorCode::notready, td::Slice(tos::kPackageGarbageCollected));
  // As carried through the query path, with a prefix in front.
  auto prefixed =
      td::Status::Error(tos::ErrorCode::error, PSLICE() << "cannot load state: " << tos::kStateGarbageCollected);
  for (const auto *status : {&state, &package, &prefixed}) {
    ASSERT_TRUE(rpc::is_garbage_collected(*status));
    const auto &kind = rpc::error_kind_for_upstream(*status, -32603);
    ASSERT_EQ(std::string(kind.reason), "BLOCK_UNAVAILABLE");
    ASSERT_TRUE(!kind.retryable);
  }
  auto timeout = td::Status::Error(tos::ErrorCode::timeout, "Request timeout");
  auto syncing = td::Status::Error(tos::ErrorCode::notready, "node not synced");
  for (const auto *status : {&timeout, &syncing}) {
    ASSERT_TRUE(!rpc::is_garbage_collected(*status));
    const auto &kind = rpc::error_kind_for_upstream(*status, -32603);
    ASSERT_EQ(std::string(kind.reason), "UPSTREAM_UNAVAILABLE");
    ASSERT_TRUE(kind.retryable);
  }
  // Anything else keeps the call site's code.
  auto other = td::Status::Error(tos::ErrorCode::error, "cannot find block");
  ASSERT_EQ(std::string(rpc::error_kind_for_upstream(other, -32603).reason), "INTERNAL_ERROR");
}

TEST(JsonRpcContract, envelope_rules) {
  struct Case {
    std::string request;
    int code;  // 0: accepted
  };
  std::vector<Case> cases = {
      {R"({"jsonrpc":"2.0","id":1,"method":"m"})", 0},
      {R"({"jsonrpc":"2.0","id":1,"method":"m","params":{}})", 0},
      {R"({"jsonrpc":"2.0","method":"m"})", 0},
      {R"({"id":1,"method":"m"})", -32600},
      {R"({"jsonrpc":"1.0","id":1,"method":"m"})", -32600},
      {R"({"jsonrpc":2.0,"id":1,"method":"m"})", -32600},
      {R"({"jsonrpc":"2.0","id":1,"method":12})", -32600},
      {R"({"jsonrpc":"2.0","id":1})", -32600},
      {R"({"jsonrpc":"2.0","id":1,"method":"m","params":"x"})", -32600},
      {R"({"jsonrpc":"2.0","id":1,"method":"m","params":null})", -32600},
      {R"({"jsonrpc":"2.0","id":1,"method":"m","params":["a"]})", -32602},
  };
  for (auto &c : cases) {
    with_object(c.request, [&](td::JsonObject &object) {
      auto envelope = rpc::check_envelope(object);
      if (c.code == 0) {
        ASSERT_TRUE(envelope.is_ok());
        ASSERT_EQ(envelope.ok().method, "m");
      } else {
        ASSERT_TRUE(envelope.is_error());
        ASSERT_EQ(envelope.error().code(), c.code);
      }
    });
  }
  with_object(R"({"jsonrpc":"2.0","method":"m"})",
              [](td::JsonObject &object) { ASSERT_TRUE(rpc::check_envelope(object).ok().notification); });
  // A null id is a request, not a notification.
  with_object(R"({"jsonrpc":"2.0","id":null,"method":"m"})",
              [](td::JsonObject &object) { ASSERT_TRUE(!rpc::check_envelope(object).ok().notification); });
}

TEST(JsonRpcContract, block_selectors_are_parsed_strictly) {
  with_object(R"({"workchain":-1,"shard":"-9223372036854775808","seqno":42})", [](td::JsonObject &object) {
    auto selector = rpc::parse_block_selector(object);
    ASSERT_TRUE(selector.is_ok());
    ASSERT_EQ(selector.ok().workchain, -1);
    ASSERT_EQ(selector.ok().shard, std::numeric_limits<td::int64>::min());
    ASSERT_EQ(selector.ok().seqno, 42);
  });
  struct Case {
    std::string params;
    std::string refused;  // the parameter the refusal names
  };
  std::vector<Case> cases = {
      // Text read as zero, the observed failure.
      {R"({"workchain":-1,"shard":"zz","seqno":1})", "shard"},
      // Unsigned spelling of the same shard: one representation only.
      {R"({"workchain":-1,"shard":"9223372036854775808","seqno":1})", "shard"},
      {R"({"workchain":-1,"shard":"0x8000000000000000","seqno":1})", "shard"},
      {R"({"workchain":-1,"shard":"+1","seqno":1})", "shard"},
      {R"({"workchain":-1,"shard":"0","seqno":1})", "shard"},
      {R"({"workchain":-1,"shard":-1,"seqno":1})", "shard"},
      {R"({"workchain":-1,"seqno":1})", "shard"},
      // Wrapped to 4294967293 before.
      {R"({"workchain":-1,"shard":"-9223372036854775808","seqno":-3})", "seqno"},
      {R"({"workchain":-1,"shard":"-9223372036854775808","seqno":"abc"})", "seqno"},
      {R"({"workchain":-1,"shard":"-9223372036854775808","seqno":"7"})", "seqno"},
      {R"({"workchain":-1,"shard":"-9223372036854775808","seqno":1.5})", "seqno"},
      {R"({"workchain":-1,"shard":"-9223372036854775808","seqno":1e3})", "seqno"},
      {R"({"workchain":-1,"shard":"-9223372036854775808","seqno":4294967296})", "seqno"},
      {R"({"workchain":-1,"shard":"-9223372036854775808","seqno":{}})", "seqno"},
      {R"({"workchain":-1,"shard":"-9223372036854775808"})", "seqno"},
      {R"({"workchain":"-1","shard":"-9223372036854775808","seqno":1})", "workchain"},
      {R"({"workchain":2147483648,"shard":"-9223372036854775808","seqno":1})", "workchain"},
  };
  for (auto &c : cases) {
    with_object(c.params, [&](td::JsonObject &object) {
      auto selector = rpc::parse_block_selector(object);
      expect_param_error(selector.is_error() ? selector.error().clone() : td::Status::OK(), c.refused);
    });
  }
}

TEST(JsonRpcContract, optional_seqno_and_lt) {
  with_object(R"({})", [](td::JsonObject &object) {
    ASSERT_TRUE(rpc::parse_optional_seqno_param(object).is_ok());
    ASSERT_TRUE(!rpc::parse_optional_seqno_param(object).ok().has_value());
    ASSERT_TRUE(!rpc::parse_optional_lt_param(object, "lt").ok().has_value());
  });
  // Zero is a block, not "latest".
  with_object(R"({"seqno":0,"lt":"123"})", [](td::JsonObject &object) {
    ASSERT_EQ(*rpc::parse_optional_seqno_param(object).ok(), 0);
    ASSERT_EQ(*rpc::parse_optional_lt_param(object, "lt").ok(), 123);
  });
  with_object(R"({"seqno":"abc","lt":"-1"})", [](td::JsonObject &object) {
    expect_param_error(rpc::parse_optional_seqno_param(object).error().clone(), "seqno");
    expect_param_error(rpc::parse_optional_lt_param(object, "lt").error().clone(), "lt");
  });
  with_object(R"({"lt":"12x"})", [](td::JsonObject &object) {
    expect_param_error(rpc::parse_optional_lt_param(object, "lt").error().clone(), "lt");
  });
}
