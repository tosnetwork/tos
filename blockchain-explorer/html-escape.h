#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <utility>

inline std::string escape_html(std::string_view value) {
  std::string out;
  for (char c : value) {
    switch (c) {
      case '&':
        out += "&amp;";
        break;
      case '<':
        out += "&lt;";
        break;
      case '>':
        out += "&gt;";
        break;
      case '"':
        out += "&quot;";
        break;
      case '\'':
        out += "&#39;";
        break;
      default:
        out += c;
    }
  }
  return out;
}

// The URL path before the command is written into links and form actions on
// every page. Only unreserved path characters are accepted, and no empty
// segment, so the prefix cannot leave its attribute or form a
// scheme-relative URL.
inline bool is_safe_path_prefix(std::string_view prefix) {
  for (char c : prefix) {
    const bool safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' ||
                      c == '.' || c == '_' || c == '~' || c == '-';
    if (!safe) {
      return false;
    }
  }
  return prefix.find("//") == std::string_view::npos;
}

// Splits a request path into the prefix echoed into every page and the
// command after the last '/'. Returns nothing when the prefix is not a safe
// path prefix, so a request can only be routed with a prefix that pages may
// echo.
inline std::optional<std::pair<std::string, std::string>> split_explorer_url(std::string_view url) {
  auto pos = url.rfind('/');
  std::string_view prefix = pos == std::string_view::npos ? std::string_view() : url.substr(0, pos + 1);
  std::string_view command = pos == std::string_view::npos ? url : url.substr(pos + 1);
  if (!is_safe_path_prefix(prefix)) {
    return std::nullopt;
  }
  return std::make_pair(std::string(prefix), std::string(command));
}

// Content-Security-Policy of every explorer HTML page. Scripts are allowed
// only from this origin and from the exact files the page header loads.
inline constexpr const char *kExplorerHtmlPolicy =
    "default-src 'self'; "
    "script-src 'self' https://ajax.googleapis.com/ajax/libs/jquery/3.4.0/jquery.min.js "
    "https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js "
    "https://maxcdn.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js; "
    "style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css; "
    "img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
