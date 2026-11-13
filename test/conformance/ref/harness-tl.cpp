// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// tl harness: TL wire-format verdicts on boxed bytes (schema/harness/tl-v1.schema.json).
//
// The bytes are fetched with the generated parsers of the node's TL schemas (tl/generate/scheme) as a boxed
// Object or Function of the named schema, then stored again with the generated serializers; the effect is
// the verdict, the constructor and the canonical bytes. The JSON-only toslib_api schema has no generated
// TL codec; its one wire record, raw.extMessageInfo, uses the native primitive TL codecs, as
// test/tl-cli/fixtures.cpp does.
#include <string>

#include "auto/tl/lite_api.h"
#include "auto/tl/tos_api.h"
#include "auto/tl/toslib_api.h"
#include "td/utils/misc.h"
#include "td/utils/tl_parsers.h"
#include "td/utils/tl_storers.h"
#include "tl-utils/lite-utils.hpp"
#include "tl-utils/tl-utils.hpp"

#include "common.h"

namespace {

constexpr std::size_t kMaxWireBytes = 1u << 20;

// Stable classes of a parse refusal; the wording of the C++ message is not part of the effect.
const char *reason_class(td::Slice message) {
  if (td::begins_with(message, "Not enough data to read") || td::begins_with(message, "Wrong vector length")) {
    return "truncated";
  }
  if (td::begins_with(message, "Too much data to fetch")) {
    return "trailing_data";
  }
  if (td::begins_with(message, "Unknown constructor found") || td::begins_with(message, "Wrong constructor found")) {
    return "unknown_constructor";
  }
  if (td::begins_with(message, "Too big string found")) {
    return "oversize";
  }
  return "invalid_value";
}

std::string accepted(td::int32 id, td::Slice canonical) {
  return "{\"outcome\":\"accepted\",\"constructor\":" + std::to_string(id) +
         ",\"bytes\":" + conformance::json_quote(td::hex_encode(canonical)) + "}";
}

std::string rejected(td::Slice message) {
  return "{\"outcome\":\"rejected\",\"reason\":" + conformance::json_quote(td::Slice(reason_class(message))) + "}";
}

template <class Base>
std::string fetch_and_store(td::Slice bytes) {
  auto parsed = tos::fetch_tl_object<Base>(bytes, true);
  if (parsed.is_error()) {
    return rejected(parsed.error().message());
  }
  auto object = parsed.move_as_ok();
  if (object == nullptr) {
    return rejected("Unknown constructor found");
  }
  auto canonical = tos::serialize_tl_object(object.get(), true);
  return accepted(object->get_id(), canonical.as_slice());
}

std::string toslib_record(td::Slice bytes) {
  td::TlParser parser(bytes);
  const auto id = parser.fetch_int();
  if (parser.get_error() == nullptr && id != tos::toslib_api::raw_extMessageInfo::ID) {
    return rejected("Unknown constructor found");
  }
  const auto hash = parser.fetch_string<std::string>();
  const auto normalized = parser.fetch_string<std::string>();
  parser.fetch_end();
  if (parser.get_error() != nullptr) {
    return rejected(td::Slice(parser.get_error()));
  }
  td::TlStorerCalcLength length;
  length.store_int(id);
  length.store_string(hash);
  length.store_string(normalized);
  std::string out(length.get_length(), '\0');
  td::TlStorerUnsafe writer(reinterpret_cast<unsigned char *>(out.data()));
  writer.store_int(id);
  writer.store_string(hash);
  writer.store_string(normalized);
  return accepted(id, out);
}

td::Result<std::string> run_tl(td::JsonObject &ctx) {
  TRY_RESULT(schema, ctx.get_required_string_field("schema"));
  TRY_RESULT(kind, ctx.get_required_string_field("kind"));
  TRY_RESULT(hex, ctx.get_required_string_field("bytes"));
  if (hex.size() > 2 * kMaxWireBytes) {
    return td::Status::Error("bytes: more than 1 MiB");
  }
  TRY_RESULT(bytes, td::hex_decode(hex));
  if (kind != "object" && kind != "function") {
    return td::Status::Error("kind must be object or function");
  }
  const bool function = kind == "function";
  if (schema == "tos_api") {
    return function ? fetch_and_store<tos::tos_api::Function>(bytes) : fetch_and_store<tos::tos_api::Object>(bytes);
  }
  if (schema == "lite_api") {
    return function ? fetch_and_store<tos::lite_api::Function>(bytes) : fetch_and_store<tos::lite_api::Object>(bytes);
  }
  if (schema == "toslib_api") {
    if (function) {
      return td::Status::Error("toslib_api has no TL wire functions");
    }
    return toslib_record(bytes);
  }
  return td::Status::Error("unknown schema");
}

}  // namespace

CONFORMANCE_REGISTER_HARNESS(tl, run_tl);
