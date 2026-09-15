#include <map>
#include <optional>

#include "api-types.h"
#include "transport.h"
namespace tos::auth {
namespace {
using Fields = std::map<std::string, std::optional<std::string>>;
int digit(char c) {
  return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}
int escape_digit(char c) {
  return c >= 'A' && c <= 'F' ? c - 'A' + 10 : digit(c);
}
class Json {
  std::string_view raw;
  std::size_t pos = 0;
  void space() {
    while (pos < raw.size() && (raw[pos] == ' ' || raw[pos] == '\n' || raw[pos] == '\r' || raw[pos] == '\t'))
      ++pos;
  }
  bool take(char c) {
    space();
    if (pos == raw.size() || raw[pos] != c)
      return false;
    ++pos;
    return true;
  }
  Result<std::string> string() {
    if (!take('"'))
      return Error{"json-syntax"};
    std::string out;
    while (pos < raw.size()) {
      unsigned char c = raw[pos++];
      if (c == '"')
        return out;
      if (c < 32 || c >= 128)
        return Error{"transport-string"};
      if (c == '\\') {
        if (pos == raw.size())
          return Error{"json-syntax"};
        char esc = raw[pos++];
        switch (esc) {
          case '"':
            c = '"';
            break;
          case '\\':
            c = '\\';
            break;
          case '/':
            c = '/';
            break;
          case 'b':
            c = '\b';
            break;
          case 'f':
            c = '\f';
            break;
          case 'n':
            c = '\n';
            break;
          case 'r':
            c = '\r';
            break;
          case 't':
            c = '\t';
            break;
          case 'u': {
            if (raw.size() - pos < 4)
              return Error{"json-syntax"};
            unsigned value = 0;
            for (int i = 0; i < 4; ++i) {
              int n = escape_digit(raw[pos++]);
              if (n < 0)
                return Error{"json-syntax"};
              value = value * 16 + unsigned(n);
            }
            // Every accepted transport name and value is ASCII. Other Unicode
            // cannot name a valid field or encode the version/hex payload.
            if (value >= 128)
              return Error{"transport-string"};
            c = static_cast<unsigned char>(value);
            break;
          }
          default:
            return Error{"json-syntax"};
        }
      }
      out.push_back(static_cast<char>(c));
    }
    return Error{"json-syntax"};
  }

 public:
  explicit Json(std::string_view input) : raw(input) {
  }
  Result<Fields> parse() {
    Fields fields;
    if (!take('{'))
      return Error{"json-syntax"};
    if (take('}')) {
      space();
      if (pos != raw.size())
        return Error{"json-syntax"};
      return fields;
    }
    for (;;) {
      auto key = string();
      if (!key.ok())
        return key.error();
      if (fields.contains(key.value()))
        return Error{"duplicate-json-key"};
      if (fields.size() >= 4)
        return Error{"transport-fields"};
      if (!take(':'))
        return Error{"json-syntax"};
      space();
      std::optional<std::string> value;
      if (raw.substr(pos, 4) == "null")
        pos += 4;
      else {
        auto s = string();
        if (!s.ok())
          return s.error();
        value = std::move(s.value());
      }
      fields.emplace(std::move(key.value()), std::move(value));
      if (take('}'))
        break;
      if (!take(','))
        return Error{"json-syntax"};
    }
    space();
    if (pos != raw.size())
      return Error{"json-syntax"};
    return fields;
  }
};
Result<Bytes> unhex(const std::optional<std::string>& text, std::size_t limit) {
  if (!text || text->size() % 2 || text->size() / 2 > limit)
    return Error{"hex"};
  Bytes out;
  out.reserve(text->size() / 2);
  for (std::size_t i = 0; i < text->size(); i += 2) {
    int a = digit((*text)[i]), b = digit((*text)[i + 1]);
    if (a < 0 || b < 0)
      return Error{"hex"};
    out.push_back(static_cast<std::uint8_t>(a * 16 + b));
  }
  return out;
}
std::string hex(std::span<const std::uint8_t> raw) {
  constexpr char chars[] = "0123456789abcdef";
  std::string out;
  out.reserve(raw.size() * 2);
  for (auto c : raw) {
    out.push_back(chars[c >> 4]);
    out.push_back(chars[c & 15]);
  }
  return out;
}
bool utf8(std::span<const std::uint8_t> raw) {
  for (std::size_t i = 0; i < raw.size();) {
    auto c = raw[i++];
    if (c < 128)
      continue;
    unsigned count, value, min;
    if (c >= 0xc2 && c <= 0xdf) {
      count = 1;
      value = c & 31;
      min = 0x80;
    } else if (c >= 0xe0 && c <= 0xef) {
      count = 2;
      value = c & 15;
      min = 0x800;
    } else if (c >= 0xf0 && c <= 0xf4) {
      count = 3;
      value = c & 7;
      min = 0x10000;
    } else
      return false;
    if (count > raw.size() - i)
      return false;
    while (count--) {
      auto x = raw[i++];
      if ((x & 0xc0) != 0x80)
        return false;
      value = (value << 6) | (x & 63);
    }
    if (value < min || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
      return false;
  }
  return true;
}
Result<Hash> request_id(std::uint8_t method, std::span<const std::uint8_t> bytes) {
  if (method == 1)
    return Hash{};
  if (method == 5) {
    auto v = decode<SignRequest>(bytes);
    if (!v.ok())
      return v.error();
    return v.value().request_id_;
  }
  if (method == 6) {
    auto v = decode<ResultRequest>(bytes);
    if (!v.ok())
      return v.error();
    return v.value().request_id_;
  }
  Bytes input{method};
  input.insert(input.end(), bytes.begin(), bytes.end());
  return digest("api-request", input);
}
Result<bool> validate_frame(const TransportFrame& frame) {
  if (frame.error && !frame.response)
    return Error{"result-or-error"};
  auto valid = validate_api_binary(frame.method, frame.response, frame.error, frame.payload);
  if (!valid.ok())
    return valid.error();
  if (!frame.response) {
    auto id = request_id(frame.method, frame.payload);
    if (!id.ok())
      return id.error();
    if (id.value() != frame.request_id)
      return Error{"request-correlation"};
  }
  if (frame.error) {
    auto v = decode<ApiError>(frame.payload);
    if (!v.ok())
      return v.error();
    const auto& error = v.value();
    if (error.request_id_ != frame.request_id || error.method_ != frame.method)
      return Error{"error-correlation"};
    if (error.code_ < 1 || error.code_ > 14 || error.request_state_ > 4)
      return Error{"error-code"};
    bool read = frame.method == 1 || frame.method == 2 || frame.method == 6 || frame.method >= 8;
    if (error.retryable_ != static_cast<unsigned>(read && error.code_ >= 10 && error.code_ <= 12))
      return Error{"error-retry"};
    if (!utf8(error.message_))
      return Error{"error-message"};
  }
  return true;
}
}  // namespace
Result<TransportFrame> decode_transport_frame(std::string_view json, std::uint8_t method, bool response,
                                              const Hash* expected) {
  if (json.size() > 4194304)
    return Error{"transport-bound"};
  auto parsed = Json(json).parse();
  if (!parsed.ok())
    return parsed.error();
  const auto& fields = parsed.value();
  if (fields.size() != (response ? 4 : 3) || !fields.contains("api_version") ||
      fields.at("api_version") != std::optional<std::string>("1") || !fields.contains("request_id") ||
      (response ? (!fields.contains("result") || !fields.contains("error")) : !fields.contains("request")))
    return Error{"transport-fields"};
  auto id = unhex(fields.at("request_id"), 32);
  if (!id.ok())
    return id.error();
  if (id.value().size() != 32)
    return Error{"hex-width"};
  TransportFrame frame;
  frame.method = method;
  frame.response = response;
  std::copy(id.value().begin(), id.value().end(), frame.request_id.begin());
  if (expected && *expected != frame.request_id)
    return Error{"response-correlation"};
  if (response) {
    if (fields.at("result").has_value() == fields.at("error").has_value())
      return Error{"result-or-error"};
    frame.error = fields.at("error").has_value();
  }
  auto payload = unhex(fields.at(response ? (frame.error ? "error" : "result") : "request"), 2000000);
  if (!payload.ok())
    return payload.error();
  frame.payload = std::move(payload.value());
  auto valid = validate_frame(frame);
  if (!valid.ok())
    return valid.error();
  return frame;
}
Result<std::string> encode_transport_frame(const TransportFrame& frame) {
  auto valid = validate_frame(frame);
  if (!valid.ok())
    return valid.error();
  std::string result = "{\"api_version\":\"1\",\"request_id\":\"" + hex(frame.request_id) + "\",";
  if (frame.response)
    result += frame.error ? "\"result\":null,\"error\":\"" : "\"error\":null,\"result\":\"";
  else
    result += "\"request\":\"";
  result += hex(frame.payload);
  result += "\"}";
  if (result.size() > 4194304)
    return Error{"transport-bound"};
  return result;
}
}  // namespace tos::auth
