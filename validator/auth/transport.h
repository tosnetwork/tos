#pragma once
#include "crypto.h"
namespace tos::auth {
// Framing and correlation only. This value carries no authenticated authority;
// endpoint handlers must validate semantics, proof context and authorization.
struct TransportFrame {
  std::uint8_t method{};
  Hash request_id{};
  Bytes payload;
  bool response = false, error = false;
};
Result<TransportFrame> decode_transport_frame(std::string_view json, std::uint8_t method, bool response = false,
                                              const Hash* expected_id = nullptr);
Result<std::string> encode_transport_frame(const TransportFrame&);
}  // namespace tos::auth
