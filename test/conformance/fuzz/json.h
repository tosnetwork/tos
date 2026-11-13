// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Small JSON value for the differential fuzz driver. Serialization is canonical and equal to Python's
// json.dumps(value, separators=(",", ":"), sort_keys=True) for the values the conformance harnesses use
// (objects, arrays, strings, integers, booleans, null), so a context hashes to the same name in the C++
// and the Python driver.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace conformance::fuzz {

class Json {
 public:
  enum class Type { Null, Bool, Int, Number, String, Array, Object };

  Json() = default;
  static Json null();
  static Json boolean(bool value);
  static Json integer(std::int64_t value);
  static Json string(std::string value);
  // A number that does not fit int64 or has a fraction, kept as its literal text.
  static Json number_literal(std::string text);
  static Json array();
  static Json object();

  Type type() const {
    return type_;
  }
  bool is(Type type) const {
    return type_ == type;
  }
  bool as_bool() const {
    return bool_;
  }
  std::int64_t as_int() const {
    return int_;
  }
  const std::string &as_string() const {
    return text_;
  }
  std::vector<Json> &items() {
    return array_;
  }
  const std::vector<Json> &items() const {
    return array_;
  }
  std::map<std::string, Json> &fields() {
    return object_;
  }
  const std::map<std::string, Json> &fields() const {
    return object_;
  }
  // Object access; find returns nullptr when the key is absent or this is not an object.
  const Json *find(const std::string &key) const;
  Json *find(const std::string &key);
  Json &set(const std::string &key, Json value);
  void erase(const std::string &key);
  bool has(const std::string &key) const {
    return find(key) != nullptr;
  }
  void push(Json value) {
    array_.push_back(std::move(value));
  }

  std::string dump() const;
  void dump_to(std::string &out) const;

  // Structural equality; object key order never matters.
  bool operator==(const Json &other) const;
  bool operator!=(const Json &other) const {
    return !(*this == other);
  }

 private:
  Type type_ = Type::Null;
  bool bool_ = false;
  std::int64_t int_ = 0;
  std::string text_;  // string value, or the literal text of a non-int64 number
  std::vector<Json> array_;
  std::map<std::string, Json> object_;
};

struct JsonParseResult {
  std::optional<Json> value;
  std::string error;
};

// Parses one JSON document. Nesting is bounded; trailing non-space text is an error.
JsonParseResult parse_json(const std::string &text);

std::string json_quote(const std::string &text);

}  // namespace conformance::fuzz
