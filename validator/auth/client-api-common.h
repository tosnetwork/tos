#pragma once

#include <cstdint>
#include <string>

#include "api-service.h"

namespace tos::auth {

// One error-classification source is shared by the private signer API and the
// authenticated public client surface. Backend/storage failures must never be
// rewritten as malformed client input.
inline std::uint16_t api_error_code(const Error& error) {
  const auto& e = error.code;
  if (e == "api-bad-request" || e == "chunk-conflict" || e == "chunk-index")
    return 1;
  if (e == "unauthorized" || e == "authority-refused" ||
      e == "api-unauthorized" || e == "local-unauthorized" ||
      e == "service-signature" || e == "duty-not-permitted")
    return 2;
  if (e == "unknown-key")
    return 3;
  if (e == "disabled-suite")
    return 4;
  if (e == "predecessor" || e == "nonce" || e == "admin-context" ||
      e == "sign-permit-association" || e == "operation-chain" ||
      e == "permit-context" || e == "permit-expiry" ||
      e == "permit-current-coordinate" || e == "stale-permit-policy" ||
      e == "stage-provider-key" || e == "api-context-mismatch")
    return 5;
  if (e == "sign-key-context" || e == "snapshot-validity" ||
      e == "new-key-validity")
    return 6;
  if (e == "preparation-conflict" || e == "pending-conflict" ||
      e == "operation-reservation-conflict" ||
      e == "cached-request-conflict" || e == "duty-conflict" ||
      e == "candidate-conflict" || e == "finalize-skip-conflict")
    return 7;
  if (e == "fenced" || e == "primitive-reservation-fence")
    return 8;
  if (e == "provider-key-capacity" || e == "fence-exhausted" ||
      e == "journal-exhausted")
    return 9;
  if (e == "storage-unavailable" || e == "storage-quota" ||
      e == "object-quota" || e == "journal-witness-mismatch" ||
      e == "witness-unavailable" || e == "principal-storage-quota" ||
      e == "global-storage-quota" || e == "storage-clock-regression" ||
      e == "storage-clock-overflow")
    return 10;
  if (e == "result-uncertain" || e == "primitive-already-claimed")
    return 11;
  if (e == "history-unavailable" ||
      e == "provider-history-unavailable" || e == "snapshot-missing" ||
      e == "object-unavailable")
    return 13;
  if (e == "unsupported-profile" || e == "unsupported-native-method")
    return 14;
  return 12;
}

inline Result<HttpResponse> api_failure_response(
    std::uint8_t method, const Hash& id, std::uint16_t code,
    std::uint8_t state) {
  const bool retry =
      (method == 1 || method == 2 || method == 6 || method >= 8) &&
      code >= 10 && code <= 12;
  auto raw = encode(
      ApiError{id, method, code, static_cast<std::uint8_t>(retry), state, {}});
  if (!raw.ok())
    return raw.error();
  auto json =
      encode_transport_frame({method, id, raw.value(), true, true});
  if (!json.ok())
    return json.error();
  return HttpResponse{
      code == 1 ? 400u : code == 2 ? 403u : 200u,
      std::string(api_media_type), json.value()};
}

inline Result<Anchor> client_request_anchor(
    std::uint8_t method, const Bytes& raw) {
#define VALIDATOR_AUTH_CLIENT_ANCHOR_CASE(N, T) \
  case N: {                         \
    auto q = decode<T>(raw);        \
    if (!q.ok())                    \
      return q.error();             \
    return q.value().anchor_;       \
  }
  switch (method) {
    VALIDATOR_AUTH_CLIENT_ANCHOR_CASE(8, GetProfileRequest)
    VALIDATOR_AUTH_CLIENT_ANCHOR_CASE(9, GetPolicyRequest)
    VALIDATOR_AUTH_CLIENT_ANCHOR_CASE(10, GetRegistryRequest)
    VALIDATOR_AUTH_CLIENT_ANCHOR_CASE(11, GetKeyRequest)
    VALIDATOR_AUTH_CLIENT_ANCHOR_CASE(12, GetCertificateRequest)
    VALIDATOR_AUTH_CLIENT_ANCHOR_CASE(13, VerifyCertificateRequest)
    default:
      return Error{"unsupported-profile"};
  }
#undef VALIDATOR_AUTH_CLIENT_ANCHOR_CASE
}

}  // namespace tos::auth
