#pragma once
#include "service-auth.h"
#include "transfer.h"
namespace tos::auth {
Result<Hash> api_request_id(std::uint8_t method, std::span<const std::uint8_t> canonical_request);
Result<Hash> registry_query_id(const Anchor&, std::uint8_t limit);
Result<bool> validate_api_request(std::uint8_t method, std::span<const std::uint8_t>, ObjectReader&);
// Association and resource checks only. Success is deliberately not an
// authenticated result type: callers still verify native proofs, actual
// signatures, independent service trust and retained receipt frontiers.
Result<bool> validate_api_response(std::uint8_t method, std::span<const std::uint8_t> request,
                                   std::span<const std::uint8_t> response, ObjectReader&);
}  // namespace tos::auth
