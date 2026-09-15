#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <sys/types.h>

#include "api-service.h"
#include "local-channel.h"
#include "native-node-history.h"

namespace tos::auth {

inline constexpr std::size_t public_access_limit = 4096;

// Transport-authenticated serving seam. The request has no authority to choose
// its principal. A future remote mutual-authentication transport can implement
// this interface without changing the public RPC composition.
class AuthenticatedHttpTransport {
 public:
  using Handler =
      std::function<Result<HttpResponse>(const Hash&, const HttpRequest&)>;

  virtual ~AuthenticatedHttpTransport() = default;
  virtual Result<bool> serve_one(
      const Handler&, unsigned accept_timeout_ms = 1000) = 0;
};

// Existing local Unix transport adapted to the authenticated-principal seam.
// The configured logical principal is emitted only after LocalListener admits
// the configured OS credential. HTTP fields never replace this binding.
class LocalAuthenticatedHttpTransport final
    : public AuthenticatedHttpTransport {
 public:
  static Result<std::unique_ptr<LocalAuthenticatedHttpTransport>> create(
      const std::string& socket_path, uid_t admitted_os_principal,
      Hash authenticated_principal);

  Result<bool> serve_one(
      const Handler&, unsigned accept_timeout_ms = 1000) override;

 private:
  LocalAuthenticatedHttpTransport(
      std::unique_ptr<LocalListener> listener, Hash principal)
      : listener_(std::move(listener)), principal_(principal) {
  }

  std::unique_ptr<LocalListener> listener_;
  Hash principal_{};
};

// Client-only dispatcher. It consumes an authenticated principal from the
// transport seam, applies ApiAccess, creates exactly one ObjectReader for each
// methods 8-13 operation, and exposes object transfer only as methods 14-15.
class PublicClientService {
 public:
  static Result<std::unique_ptr<PublicClientService>> create(
      ChainContext, std::vector<ApiAccess>, ScopedObjectStore&, ClientRpc&);

  Result<bool> serve_one(
      AuthenticatedHttpTransport&, std::uint64_t monotonic_seconds,
      unsigned accept_timeout_ms = 1000);

 private:
  PublicClientService(
      ChainContext chain, std::map<Hash, ApiAccess> access,
      ScopedObjectStore& objects, ClientRpc& rpc)
      : chain_(std::move(chain)),
        access_(std::move(access)),
        objects_(objects),
        rpc_(rpc) {
  }

  Result<HttpResponse> dispatch(
      const Hash& authenticated_principal, const HttpRequest&,
      std::uint64_t monotonic_seconds);
  Result<Bytes> invoke(
      const TransportFrame&, const ApiAccess&, std::uint64_t monotonic_seconds);

  ChainContext chain_;
  std::map<Hash, ApiAccess> access_;
  ScopedObjectStore& objects_;
  ClientRpc& rpc_;
};

// Concrete composition requested by this round. The merged node-history
// adapter is the NativeClientRpc history source and must outlive this service.
// The scoped object store is shared by proof publication plus methods 14-15.
// Installation into an actor is deliberately outside this class.
class NativePublicRpcService {
 public:
  static Result<std::unique_ptr<NativePublicRpcService>> create(
      const NativeNodeHistoryAdapter&, std::vector<ApiAccess>,
      std::size_t global_storage_bytes = 268435456,
      std::uint64_t storage_ttl_seconds = 60);

  Result<bool> serve_one(
      AuthenticatedHttpTransport&, std::uint64_t monotonic_seconds,
      unsigned accept_timeout_ms = 1000);

 private:
  NativePublicRpcService(
      const NativeNodeHistoryAdapter& source, std::int32_t network,
      std::size_t global_storage_bytes, std::uint64_t storage_ttl_seconds)
      : objects_(global_storage_bytes, storage_ttl_seconds),
        rpc_(source, objects_, network) {
  }

  ScopedObjectStore objects_;
  NativeClientRpc rpc_;
  std::unique_ptr<PublicClientService> service_;
};

}  // namespace tos::auth
