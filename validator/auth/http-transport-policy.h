#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <map>
#include <string>
#include <string_view>
#include <utility>

#include "http-types.h"

namespace tos::auth {

inline constexpr std::size_t http_transport_max_header_bytes = 8192;
inline constexpr std::size_t http_transport_max_headers = 16;
inline constexpr std::size_t http_transport_max_body_bytes = 4194304;
inline constexpr std::size_t http_transport_max_path_bytes = 256;
inline constexpr std::size_t http_transport_max_content_type_bytes = 256;
inline constexpr unsigned http_transport_max_accept_timeout_ms = 5000;
inline constexpr auto http_transport_io_timeout = std::chrono::seconds(5);

inline unsigned bounded_http_accept_timeout(unsigned requested) {
  return std::clamp(requested, 1u, http_transport_max_accept_timeout_ms);
}

inline std::chrono::steady_clock::time_point http_transport_deadline(
    std::chrono::steady_clock::time_point start) {
  return start + http_transport_io_timeout;
}

inline bool http_transport_text(std::string_view text, bool spaces) {
  for (unsigned char c : text)
    if (c < (spaces ? 32 : 33) || c > 126)
      return false;
  return true;
}

inline bool http_transport_forbidden_header(std::string_view name) {
  return name == "transfer-encoding" || name == "content-encoding" ||
         name == "upgrade" || name == "expect";
}

inline Result<bool> admit_http_transport_header(
    std::map<std::string, std::string>& fields, std::string name,
    std::string value) {
  if (fields.size() >= http_transport_max_headers)
    return Error{"http-header"};
  if (fields.contains(name))
    return Error{"http-duplicate-header"};
  if (http_transport_forbidden_header(name))
    return Error{"http-unsupported-framing"};
  fields.emplace(std::move(name), std::move(value));
  return true;
}

inline bool http_transport_response_status_allowed(unsigned status) {
  return status >= 200 && status <= 599 &&
         !(status >= 300 && status < 400);
}

inline Result<std::size_t> parse_http_transport_content_length(
    std::string_view value) {
  if (value.empty() || value.size() > 8 ||
      (value.size() > 1 && value.front() == '0'))
    return Error{"http-content-length"};

  std::size_t length = 0;
  for (char c : value) {
    if (c < '0' || c > '9')
      return Error{"http-content-length"};
    const auto digit = static_cast<std::size_t>(c - '0');
    if (length > http_transport_max_body_bytes / 10)
      return Error{"http-body-bound"};
    length *= 10;
    if (digit > http_transport_max_body_bytes - length)
      return Error{"http-body-bound"};
    length += digit;
  }
  return length;
}

inline Result<bool> validate_http_transport_request_shape(
    const HttpRequest& request) {
  if ((request.verb != "GET" && request.verb != "POST") ||
      request.path.empty() ||
      request.path.size() > http_transport_max_path_bytes ||
      !http_transport_text(request.path, false) ||
      !http_transport_text(request.content_type, true) ||
      request.content_type.size() > http_transport_max_content_type_bytes ||
      request.body.size() > http_transport_max_body_bytes ||
      (request.verb == "GET" && !request.body.empty()))
    return Error{"http-request-bound"};
  return true;
}

}  // namespace tos::auth
