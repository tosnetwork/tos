#include "remote-transport.h"

#include "crypto.h"

namespace tos::auth {

Result<std::unique_ptr<InstalledRemotePeerTrust>>
InstalledRemotePeerTrust::load(
    const AuthenticatedLocalRemotePeerConfig& source) {
  auto configured = source.load();
  if (!configured.ok())
    return configured.error();
  if (configured.value().empty())
    return Error{"remote-peer-trust-unavailable"};
  if (configured.value().size() > 4096)
    return Error{"remote-peer-trust-capacity"};

  auto result = std::unique_ptr<InstalledRemotePeerTrust>(
      new InstalledRemotePeerTrust());

  for (const auto& binding : configured.value()) {
    if (binding.certificate_id == Hash{} ||
        binding.principal == Hash{} ||
        result->principals_.contains(binding.certificate_id))
      return Error{"remote-peer-trust-record"};
    result->principals_.emplace(
        binding.certificate_id, binding.principal);
  }
  return result;
}

Result<Hash> InstalledRemotePeerTrust::principal_for_certificate(
    std::span<const std::uint8_t> certificate) const {
  if (certificate.empty())
    return Error{"remote-client-certificate-required"};

  auto id = digest("remote-peer-certificate", certificate);
  if (!id.ok())
    return id.error();

  auto found = principals_.find(id.value());
  if (found == principals_.end())
    return Error{"remote-principal-unmapped"};
  return found->second;
}

Result<Hash> RemoteAuthenticatedRequestGate::authenticate(
    const RemoteTlsHandshakeOutcome& outcome) const {
  if (!outcome.certificate_chain_verified)
    return Error{"remote-certificate-unverified"};
  if (!outcome.client_certificate_present ||
      outcome.leaf_certificate.empty())
    return Error{"remote-client-certificate-required"};
  if (outcome.negotiated_version != remote_tls13_version)
    return Error{"remote-tls-version"};
  return trust_.principal_for_certificate(
      outcome.leaf_certificate);
}

Result<HttpResponse> RemoteAuthenticatedRequestGate::dispatch(
    const RemoteTlsHandshakeOutcome& outcome,
    const RemoteDecodedRequest& decoded,
    const AuthenticatedHttpTransport::Handler& handler) const {
  if (!handler)
    return Error{"remote-handler"};

  auto principal = authenticate(outcome);
  if (!principal.ok())
    return principal.error();

  if (decoded.header_bytes >
      http_transport_max_header_bytes)
    return Error{"http-header-bound"};

  std::map<std::string, std::string> fields;
  for (const auto& [name, value] : decoded.headers) {
    auto admitted =
        admit_http_transport_header(fields, name, value);
    if (!admitted.ok())
      return admitted.error();
  }

  auto shape =
      validate_http_transport_request_shape(decoded.request);
  if (!shape.ok())
    return shape.error();

  return handler(principal.value(), decoded.request);
}

Result<bool> RemoteTlsAuthenticatedHttpTransport::serve_one(
    const Handler& handler, unsigned timeout) {
  if (!handler)
    return Error{"remote-handler"};

  const auto deadline =
      http_transport_deadline(std::chrono::steady_clock::now());
  auto outcome = source_.accept(
      bounded_http_accept_timeout(timeout), deadline);
  if (!outcome.ok())
    return outcome.error();

  auto principal = gate_.authenticate(outcome.value());
  if (!principal.ok())
    return principal.error();

  return Error{"http2-framing-unavailable"};
}

}  // namespace tos::auth
