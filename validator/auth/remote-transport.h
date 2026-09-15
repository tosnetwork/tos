#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "crypto.h"
#include "http-transport-policy.h"
#include "public-rpc.h"

namespace tos::auth {

inline constexpr std::uint16_t remote_tls13_version = 0x0304;

struct RemotePeerBinding {
  Hash certificate_id{};
  Hash principal{};
};

// Privileged operator-local configuration seam. It is not populated by a peer,
// request, certificate field or first connection.
class AuthenticatedLocalRemotePeerConfig {
 public:
  virtual ~AuthenticatedLocalRemotePeerConfig() = default;
  virtual Result<std::vector<RemotePeerBinding>> load() const = 0;
};

class InstalledRemotePeerTrust {
 public:
  static Result<std::unique_ptr<InstalledRemotePeerTrust>> load(
      const AuthenticatedLocalRemotePeerConfig&);

  Result<Hash> principal_for_certificate(
      std::span<const std::uint8_t>) const;

 private:
  InstalledRemotePeerTrust() {
  }

  std::map<Hash, Hash> principals_;
};

// Outcome supplied by the TLS adapter after its certificate-chain validation.
// The certificate bytes are the verified leaf certificate, not a peer-declared
// name. This type makes the identity rules testable without a socket.
struct RemoteTlsHandshakeOutcome {
  bool certificate_chain_verified = false;
  bool client_certificate_present = false;
  std::uint16_t negotiated_version = 0;
  Bytes leaf_certificate;
};

// Already-decoded request metadata at the boundary Part B will feed. Arbitrary
// headers remain untrusted. No header is a principal source.
struct RemoteDecodedRequest {
  HttpRequest request;
  std::size_t header_bytes = 0;
  std::vector<std::pair<std::string, std::string>> headers;
};

class RemoteAuthenticatedRequestGate {
 public:
  explicit RemoteAuthenticatedRequestGate(
      const InstalledRemotePeerTrust& trust)
      : trust_(trust) {
  }

  Result<Hash> authenticate(
      const RemoteTlsHandshakeOutcome&) const;

  Result<HttpResponse> dispatch(
      const RemoteTlsHandshakeOutcome&, const RemoteDecodedRequest&,
      const AuthenticatedHttpTransport::Handler&) const;

 private:
  const InstalledRemotePeerTrust& trust_;
};

// Injected TLS-session seam. The concrete socket/TLS adapter must honor both
// deadlines and return only a completed, verified handshake outcome.
class RemoteTlsHandshakeSource {
 public:
  virtual ~RemoteTlsHandshakeSource() = default;
  virtual Result<RemoteTlsHandshakeOutcome> accept(
      unsigned accept_timeout_ms,
      std::chrono::steady_clock::time_point absolute_io_deadline) = 0;
};

// Part A implementation of AuthenticatedHttpTransport. It completes peer
// authentication and then fails closed at the not-yet-implemented HTTP/2
// framing boundary. The handler is never invoked until Part B exists.
class RemoteTlsAuthenticatedHttpTransport final
    : public AuthenticatedHttpTransport {
 public:
  RemoteTlsAuthenticatedHttpTransport(
      const InstalledRemotePeerTrust& trust,
      RemoteTlsHandshakeSource& source)
      : gate_(trust), source_(source) {
  }

  Result<bool> serve_one(
      const Handler&, unsigned accept_timeout_ms = 1000) override;

 private:
  RemoteAuthenticatedRequestGate gate_;
  RemoteTlsHandshakeSource& source_;
};

}  // namespace tos::auth
