// Generated from the frozen method table.
#pragma once
#include <array>
#include <string_view>
#include "codec.h"
namespace tos::auth {
struct ApiRoute { std::uint8_t method; std::string_view verb, path; };
inline constexpr std::array<ApiRoute,15> api_routes{{
  {1,"GET","/v1/capabilities"},
  {2,"POST","/v1/keys/public"},
  {3,"POST","/v1/keys/prepare"},
  {4,"POST","/v1/keys/stage"},
  {5,"POST","/v1/sign"},
  {6,"POST","/v1/requests/result"},
  {7,"POST","/v1/keys/retire"},
  {8,"POST","/rpc/validatorAuth/v1/getProfile"},
  {9,"POST","/rpc/validatorAuth/v1/getPolicy"},
  {10,"POST","/rpc/validatorAuth/v1/getRegistry"},
  {11,"POST","/rpc/validatorAuth/v1/getKey"},
  {12,"POST","/rpc/validatorAuth/v1/getCertificate"},
  {13,"POST","/rpc/validatorAuth/v1/verifyCertificate"},
  {14,"POST","/v1/objects/chunk"},
  {15,"POST","/v1/objects/putChunk"},
}};
}
