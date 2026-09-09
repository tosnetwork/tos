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

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The getSigningPayload response embeds the base64 of the serialized external
// message, which can exceed PSTRING()'s fixed 128 KiB buffer. Building it with
// PSTRING() silently truncates the response into invalid JSON / a corrupt
// signing payload. These tests build an oversized payload through the real
// builders and assert the output is complete and parses, with the payload
// field byte-for-byte equal to the input. With PSTRING() the payload is cut off
// and these assertions fail.

#include <string>

#include "td/utils/JsonBuilder.h"
#include "td/utils/Slice.h"
#include "td/utils/tests.h"
#include "validator-engine/json-rpc-signing-payload.h"

namespace {

// Larger than the 128 KiB PSTRING() buffer, plus the surrounding JSON.
std::string oversized_payload() {
  return std::string(256 * 1024, 'A');
}

// Parses `json` and returns the value of the top-level "payload" string field.
std::string extract_payload_field(const std::string& json) {
  std::string mutable_copy = json;
  auto decoded = td::json_decode(td::MutableSlice(mutable_copy));
  decoded.ensure();
  auto value = decoded.move_as_ok();
  CHECK(value.type() == td::JsonValue::Type::Object);
  auto field = value.get_object().extract_field("payload");
  CHECK(field.type() == td::JsonValue::Type::String);
  return field.get_string().str();
}

}  // namespace

TEST(JsonRpcSigningPayload, DelegationPayloadIsNotTruncated) {
  auto payload = oversized_payload();
  auto json = tos::build_delegation_signing_payload_json(td::Slice(payload), td::Slice("ref-123"));
  ASSERT_TRUE(!json.empty() && json.back() == '}');  // structurally complete
  ASSERT_EQ(extract_payload_field(json), payload);   // full payload, not cut off
}

TEST(JsonRpcSigningPayload, ChainIdPayloadIsNotTruncated) {
  auto payload = oversized_payload();
  auto json = tos::build_signing_payload_json(td::Slice(payload), 42);
  ASSERT_TRUE(!json.empty() && json.back() == '}');
  ASSERT_EQ(extract_payload_field(json), payload);
}

int main(int argc, char** argv) {
  td::TestsRunner& runner = td::TestsRunner::get_default();
  if (argc > 1) {
    runner.add_substr_filter(argv[1]);
  }
  runner.run_all();
  return runner.any_test_failed() ? 1 : 0;
}
