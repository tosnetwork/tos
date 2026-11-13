// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
#include <cerrno>
#include <cstdio>
#include <cstdlib>

#include "json.h"

namespace conformance::fuzz {
namespace {

constexpr int kMaxDepth = 64;

class Parser {
 public:
  explicit Parser(const std::string &text) : text_(text) {
  }

  JsonParseResult run() {
    JsonParseResult result;
    Json value;
    if (!parse_value(value, 0)) {
      result.error = error_.empty() ? "invalid JSON" : error_;
      return result;
    }
    skip_space();
    if (pos_ != text_.size()) {
      result.error = "trailing text after the JSON value";
      return result;
    }
    result.value = std::move(value);
    return result;
  }

 private:
  bool fail(const char *message) {
    if (error_.empty()) {
      error_ = std::string(message) + " at offset " + std::to_string(pos_);
    }
    return false;
  }

  void skip_space() {
    while (pos_ < text_.size() &&
           (text_[pos_] == ' ' || text_[pos_] == '\t' || text_[pos_] == '\n' || text_[pos_] == '\r')) {
      ++pos_;
    }
  }

  bool literal(const char *word) {
    std::size_t i = 0;
    for (; word[i] != '\0'; ++i) {
      if (pos_ + i >= text_.size() || text_[pos_ + i] != word[i]) {
        return fail("invalid literal");
      }
    }
    pos_ += i;
    return true;
  }

  static int hex_digit(char c) {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1;
  }

  bool hex4(unsigned &out) {
    if (pos_ + 4 > text_.size()) {
      return fail("truncated escape");
    }
    out = 0;
    for (int i = 0; i < 4; ++i) {
      const int d = hex_digit(text_[pos_ + i]);
      if (d < 0) {
        return fail("invalid escape");
      }
      out = out * 16 + static_cast<unsigned>(d);
    }
    pos_ += 4;
    return true;
  }

  static void utf8(std::string &out, unsigned cp) {
    if (cp < 0x80) {
      out += static_cast<char>(cp);
    } else if (cp < 0x800) {
      out += static_cast<char>(0xC0 | (cp >> 6));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
      out += static_cast<char>(0xE0 | (cp >> 12));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
      out += static_cast<char>(0xF0 | (cp >> 18));
      out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
      out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      out += static_cast<char>(0x80 | (cp & 0x3F));
    }
  }

  bool parse_string(std::string &out) {
    ++pos_;  // opening quote
    while (pos_ < text_.size()) {
      const char c = text_[pos_++];
      if (c == '"') {
        return true;
      }
      if (static_cast<unsigned char>(c) < 0x20) {
        return fail("control character in string");
      }
      if (c != '\\') {
        out += c;
        continue;
      }
      if (pos_ >= text_.size()) {
        return fail("truncated escape");
      }
      const char e = text_[pos_++];
      switch (e) {
        case '"':
        case '\\':
        case '/':
          out += e;
          break;
        case 'b':
          out += '\b';
          break;
        case 'f':
          out += '\f';
          break;
        case 'n':
          out += '\n';
          break;
        case 'r':
          out += '\r';
          break;
        case 't':
          out += '\t';
          break;
        case 'u': {
          unsigned cp = 0;
          if (!hex4(cp)) {
            return false;
          }
          if (cp >= 0xD800 && cp < 0xDC00) {
            unsigned low = 0;
            if (pos_ + 2 > text_.size() || text_[pos_] != '\\' || text_[pos_ + 1] != 'u') {
              return fail("unpaired surrogate");
            }
            pos_ += 2;
            if (!hex4(low) || low < 0xDC00 || low >= 0xE000) {
              return fail("invalid surrogate pair");
            }
            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
          } else if (cp >= 0xDC00 && cp < 0xE000) {
            return fail("unpaired surrogate");
          }
          utf8(out, cp);
          break;
        }
        default:
          return fail("invalid escape");
      }
    }
    return fail("unterminated string");
  }

  bool parse_number(Json &out) {
    const std::size_t start = pos_;
    if (pos_ < text_.size() && text_[pos_] == '-') {
      ++pos_;
    }
    const std::size_t digits = pos_;
    while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
      ++pos_;
    }
    if (pos_ == digits) {
      return fail("invalid number");
    }
    bool integral = true;
    if (pos_ < text_.size() && text_[pos_] == '.') {
      integral = false;
      ++pos_;
      while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
        ++pos_;
      }
    }
    if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
      integral = false;
      ++pos_;
      if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) {
        ++pos_;
      }
      while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
        ++pos_;
      }
    }
    const std::string literal_text = text_.substr(start, pos_ - start);
    if (integral) {
      errno = 0;
      char *end = nullptr;
      const long long value = std::strtoll(literal_text.c_str(), &end, 10);
      if (errno == 0 && end != nullptr && *end == '\0') {
        out = Json::integer(value);
        return true;
      }
    }
    // Numbers outside int64 or with a fraction keep their literal text.
    out = Json::number_literal(literal_text);
    return true;
  }

  bool parse_value(Json &out, int depth) {
    if (depth > kMaxDepth) {
      return fail("nesting too deep");
    }
    skip_space();
    if (pos_ >= text_.size()) {
      return fail("unexpected end");
    }
    const char c = text_[pos_];
    if (c == '{') {
      ++pos_;
      out = Json::object();
      skip_space();
      if (pos_ < text_.size() && text_[pos_] == '}') {
        ++pos_;
        return true;
      }
      while (true) {
        skip_space();
        if (pos_ >= text_.size() || text_[pos_] != '"') {
          return fail("object key expected");
        }
        std::string key;
        if (!parse_string(key)) {
          return false;
        }
        skip_space();
        if (pos_ >= text_.size() || text_[pos_] != ':') {
          return fail("':' expected");
        }
        ++pos_;
        Json value;
        if (!parse_value(value, depth + 1)) {
          return false;
        }
        out.set(key, std::move(value));
        skip_space();
        if (pos_ < text_.size() && text_[pos_] == ',') {
          ++pos_;
          continue;
        }
        if (pos_ < text_.size() && text_[pos_] == '}') {
          ++pos_;
          return true;
        }
        return fail("',' or '}' expected");
      }
    }
    if (c == '[') {
      ++pos_;
      out = Json::array();
      skip_space();
      if (pos_ < text_.size() && text_[pos_] == ']') {
        ++pos_;
        return true;
      }
      while (true) {
        Json value;
        if (!parse_value(value, depth + 1)) {
          return false;
        }
        out.push(std::move(value));
        skip_space();
        if (pos_ < text_.size() && text_[pos_] == ',') {
          ++pos_;
          continue;
        }
        if (pos_ < text_.size() && text_[pos_] == ']') {
          ++pos_;
          return true;
        }
        return fail("',' or ']' expected");
      }
    }
    if (c == '"') {
      std::string text;
      if (!parse_string(text)) {
        return false;
      }
      out = Json::string(std::move(text));
      return true;
    }
    if (c == 't') {
      out = Json::boolean(true);
      return literal("true");
    }
    if (c == 'f') {
      out = Json::boolean(false);
      return literal("false");
    }
    if (c == 'n') {
      out = Json::null();
      return literal("null");
    }
    return parse_number(out);
  }

  const std::string &text_;
  std::size_t pos_ = 0;
  std::string error_;
};

}  // namespace

Json Json::null() {
  return Json{};
}

Json Json::boolean(bool value) {
  Json j;
  j.type_ = Type::Bool;
  j.bool_ = value;
  return j;
}

Json Json::integer(std::int64_t value) {
  Json j;
  j.type_ = Type::Int;
  j.int_ = value;
  return j;
}

Json Json::number_literal(std::string text) {
  Json j;
  j.type_ = Type::Number;
  j.text_ = std::move(text);
  return j;
}

Json Json::string(std::string value) {
  Json j;
  j.type_ = Type::String;
  j.text_ = std::move(value);
  return j;
}

Json Json::array() {
  Json j;
  j.type_ = Type::Array;
  return j;
}

Json Json::object() {
  Json j;
  j.type_ = Type::Object;
  return j;
}

const Json *Json::find(const std::string &key) const {
  if (type_ != Type::Object) {
    return nullptr;
  }
  auto it = object_.find(key);
  return it == object_.end() ? nullptr : &it->second;
}

Json *Json::find(const std::string &key) {
  if (type_ != Type::Object) {
    return nullptr;
  }
  auto it = object_.find(key);
  return it == object_.end() ? nullptr : &it->second;
}

Json &Json::set(const std::string &key, Json value) {
  type_ = Type::Object;
  return object_[key] = std::move(value);
}

void Json::erase(const std::string &key) {
  object_.erase(key);
}

std::string json_quote(const std::string &text) {
  std::string out = "\"";
  std::size_t i = 0;
  while (i < text.size()) {
    const auto c = static_cast<unsigned char>(text[i]);
    if (c < 0x80) {
      switch (c) {
        case '"':
          out += "\\\"";
          break;
        case '\\':
          out += "\\\\";
          break;
        case '\n':
          out += "\\n";
          break;
        case '\r':
          out += "\\r";
          break;
        case '\t':
          out += "\\t";
          break;
        case '\b':
          out += "\\b";
          break;
        case '\f':
          out += "\\f";
          break;
        default:
          if (c < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\u%04x", c);
            out += buf;
          } else {
            out += static_cast<char>(c);
          }
      }
      ++i;
      continue;
    }
    // Non-ASCII UTF-8 is written as unicode escapes, with surrogate pairs above the BMP, as Python does.
    unsigned cp = 0;
    int extra = 0;
    if ((c & 0xE0) == 0xC0) {
      cp = c & 0x1F;
      extra = 1;
    } else if ((c & 0xF0) == 0xE0) {
      cp = c & 0x0F;
      extra = 2;
    } else if ((c & 0xF8) == 0xF0) {
      cp = c & 0x07;
      extra = 3;
    } else {
      cp = 0xFFFD;
    }
    ++i;
    for (int k = 0; k < extra && i < text.size(); ++k, ++i) {
      cp = (cp << 6) | (static_cast<unsigned char>(text[i]) & 0x3F);
    }
    char buf[16];
    if (cp >= 0x10000) {
      const unsigned v = cp - 0x10000;
      std::snprintf(buf, sizeof buf, "\\u%04x\\u%04x", 0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF));
    } else {
      std::snprintf(buf, sizeof buf, "\\u%04x", cp);
    }
    out += buf;
  }
  return out + "\"";
}

void Json::dump_to(std::string &out) const {
  switch (type_) {
    case Type::Null:
      out += "null";
      return;
    case Type::Bool:
      out += bool_ ? "true" : "false";
      return;
    case Type::Int:
      out += std::to_string(int_);
      return;
    case Type::Number:
      out += text_;
      return;
    case Type::String:
      out += json_quote(text_);
      return;
    case Type::Array: {
      out += '[';
      bool first = true;
      for (const auto &item : array_) {
        if (!first) {
          out += ',';
        }
        first = false;
        item.dump_to(out);
      }
      out += ']';
      return;
    }
    case Type::Object: {
      out += '{';
      bool first = true;
      for (const auto &[key, value] : object_) {
        if (!first) {
          out += ',';
        }
        first = false;
        out += json_quote(key);
        out += ':';
        value.dump_to(out);
      }
      out += '}';
      return;
    }
  }
}

std::string Json::dump() const {
  std::string out;
  dump_to(out);
  return out;
}

bool Json::operator==(const Json &other) const {
  if (type_ != other.type_) {
    return false;
  }
  switch (type_) {
    case Type::Null:
      return true;
    case Type::Bool:
      return bool_ == other.bool_;
    case Type::Int:
      return int_ == other.int_;
    case Type::Number:
    case Type::String:
      return text_ == other.text_;
    case Type::Array:
      return array_ == other.array_;
    case Type::Object:
      return object_ == other.object_;
  }
  return false;
}

JsonParseResult parse_json(const std::string &text) {
  return Parser(text).run();
}

}  // namespace conformance::fuzz
