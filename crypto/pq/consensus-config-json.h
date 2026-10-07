/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// The consensus key part of a node configuration, checked as written, before the TL
// decoder sees it.
//
// The TL JSON decoder is permissive: an unknown field is ignored and a missing one takes
// its type's default. For most of a node configuration that is harmless. For a consensus
// key's window it is not: a misspelt `validFrom` would be dropped, the key would read as
// valid from election 0, and the next rewrite of the configuration would make that
// silent widening permanent. So the engine and the operator tool both refuse, before
// decoding, any `extraconfig.pq_consensus` that names a field they do not know, omits a
// window field, or gives a window that is not a plain non-negative 32-bit integer.
//
// Forms. A node with one key that is valid for every election and never expires states
// it as `consensus_key_file`, with `keys` empty or absent. Every other set of keys is
// stated in `keys` alone, with `consensus_key_file` empty. Both at once is refused. A
// reader that predates `keys` therefore never misreads a multi-key configuration as a
// single key: it finds an empty key file name and refuses to start.

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

#include "td/utils/JsonBuilder.h"

namespace tos::pq {

namespace detail {

inline const td::JsonValue* json_field(const td::JsonObject& object, std::string_view name) {
  for (const auto& [field, value] : object.field_values_) {
    if (field.str() == name) {
      return &value;
    }
  }
  return nullptr;
}

inline std::optional<std::string> json_only_fields(const td::JsonObject& object, const std::string& at,
                                                   std::initializer_list<std::string_view> allowed) {
  for (const auto& [field, value] : object.field_values_) {
    bool known = false;
    for (const auto name : allowed) {
      known = known || field.str() == name;
    }
    if (!known) {
      return at + "." + field.str() + " is not a field of the consensus key configuration";
    }
  }
  return std::nullopt;
}

inline std::optional<std::string> json_type_is(const td::JsonObject& object, const std::string& at,
                                               std::string_view type) {
  const auto* value = json_field(object, "@type");
  if (value != nullptr && (value->type() != td::JsonValue::Type::String || value->get_string().str() != type)) {
    return at + " is not a " + std::string(type);
  }
  return std::nullopt;
}

// A window bound: a JSON number (or a decimal string, which the TL decoder also takes)
// of decimal digits only, at most 2^31 - 1, so it reads back the same as a signed TL int.
inline std::optional<std::string> json_window(const td::JsonObject& object, const std::string& at,
                                              std::string_view name) {
  const auto* value = json_field(object, name);
  const std::string here = at + "." + std::string(name);
  if (value == nullptr) {
    return here + " is missing; a consensus key's window is stated, never defaulted";
  }
  td::Slice digits;
  if (value->type() == td::JsonValue::Type::Number) {
    digits = value->get_number();
  } else if (value->type() == td::JsonValue::Type::String) {
    digits = value->get_string();
  } else {
    return here + " is not a number";
  }
  if (digits.empty() || digits.size() > 10) {
    return here + " is not a unix time between 0 and 2147483647";
  }
  std::uint64_t parsed = 0;
  for (const char c : digits) {
    if (c < '0' || c > '9') {
      return here + " is not a unix time between 0 and 2147483647";
    }
    parsed = parsed * 10 + static_cast<std::uint64_t>(c - '0');
  }
  if (parsed > 0x7fffffffULL) {
    return here + " is not a unix time between 0 and 2147483647";
  }
  return std::nullopt;
}

}  // namespace detail

// The largest window bound a configuration can state.
inline constexpr std::uint32_t max_consensus_key_time = 0x7fffffffU;

// Why the configuration's consensus key part is refused, or nothing. `root` is the whole
// decoded configuration.
inline std::optional<std::string> check_consensus_key_json(const td::JsonValue& root) {
  using Type = td::JsonValue::Type;
  if (root.type() != Type::Object) {
    return std::string("the configuration is not a JSON object");
  }
  const auto* extra = detail::json_field(root.get_object(), "extraconfig");
  if (extra == nullptr || extra->type() == Type::Null) {
    return std::nullopt;
  }
  if (extra->type() != Type::Object) {
    return std::string("$.extraconfig is not an object");
  }
  const auto* pq = detail::json_field(extra->get_object(), "pq_consensus");
  if (pq == nullptr || pq->type() == Type::Null) {
    return std::nullopt;
  }
  const std::string at = "$.extraconfig.pq_consensus";
  if (pq->type() != Type::Object) {
    return at + " is not an object";
  }
  const auto& binding = pq->get_object();
  if (auto refused = detail::json_only_fields(binding, at, {"@type", "validator_id", "consensus_key_file", "keys"})) {
    return refused;
  }
  if (auto refused = detail::json_type_is(binding, at, "engine.validator.pqConsensus")) {
    return refused;
  }
  if (detail::json_field(binding, "validator_id") == nullptr) {
    return at + ".validator_id is missing";
  }
  bool single = false;
  if (const auto* file = detail::json_field(binding, "consensus_key_file")) {
    if (file->type() != Type::String) {
      return at + ".consensus_key_file is not a string";
    }
    single = !file->get_string().empty();
  }
  std::size_t listed = 0;
  if (const auto* keys = detail::json_field(binding, "keys")) {
    if (keys->type() != Type::Array) {
      return at + ".keys is not a list";
    }
    for (const auto& entry : keys->get_array()) {
      const std::string here = at + ".keys[" + std::to_string(listed) + "]";
      listed++;
      if (entry.type() != Type::Object) {
        return here + " is not an object";
      }
      const auto& key = entry.get_object();
      if (auto refused =
              detail::json_only_fields(key, here, {"@type", "consensus_key_file", "valid_from", "expire_at"})) {
        return refused;
      }
      if (auto refused = detail::json_type_is(key, here, "engine.validator.pqConsensusKey")) {
        return refused;
      }
      const auto* file = detail::json_field(key, "consensus_key_file");
      if (file == nullptr || file->type() != Type::String || file->get_string().empty()) {
        return here + ".consensus_key_file is missing or empty";
      }
      if (auto refused = detail::json_window(key, here, "valid_from")) {
        return refused;
      }
      if (auto refused = detail::json_window(key, here, "expire_at")) {
        return refused;
      }
    }
  }
  if (single && listed != 0) {
    return at + " states both a single consensus_key_file and keys; several keys are stated in keys alone";
  }
  if (!single && listed == 0) {
    return at + " names no consensus key";
  }
  return std::nullopt;
}

}  // namespace tos::pq
