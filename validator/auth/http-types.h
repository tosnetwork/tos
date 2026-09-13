#pragma once
#include <string_view>
#include <sys/types.h>

#include "codec.h"
namespace tos::auth {
inline constexpr std::string_view api_media_type = "application/vnd.tos.validator-auth.v1+json";
struct HttpRequest {
  std::string verb, path, content_type, body;
};
struct HttpResponse {
  unsigned status = 200;
  std::string content_type, body;
};
// HTTP/1.1 over an authenticated local Unix socket only. Remote deployments
// require the separate HTTP/2, TLS 1.3 and mutual-authentication transport gate.
Result<HttpResponse> local_http_call(const std::string& socket_path, uid_t expected_server, const HttpRequest&);
}  // namespace tos::auth
