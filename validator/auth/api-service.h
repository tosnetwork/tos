#pragma once
#include <set>

#include "admin-service.h"
#include "http-types.h"
#include "object-store.h"
#include "transport.h"
namespace tos::auth {
struct ApiAccess {
  Hash principal{}, chain_domain{};
  std::uint16_t methods = 0;
  std::set<Hash> identities;
};
// A trusted node adapter supplies pinned history; the wire request is never its
// own finality or committee trust source. One reader bounds all attachments.
class ClientRpc {
 public:
  virtual ~ClientRpc() = default;
  virtual Result<Bytes> call(std::uint8_t method, const Bytes&, const Hash& principal, std::uint64_t now,
                             ObjectReader&) = 0;
};
class SignerApi {
  ChainContext chain_;
  std::map<Hash, ApiAccess> access_;
  SafetyLedger& ledger_;
  SignerService& signer_;
  AdminSignerService& admin_;
  C0SigningProvider& provider_;
  std::function<Result<std::vector<OpaqueKey>>()> public_keys_;
  ScopedObjectStore& objects_;
  ClientRpc& rpc_;
  bool configured_ = false;
  Result<Bytes> invoke(const TransportFrame&, const ApiAccess&, std::uint64_t now);

 public:
  SignerApi(ChainContext chain, std::vector<ApiAccess> access, SafetyLedger& ledger, SignerService& signer,
            AdminSignerService& admin, C0SigningProvider& provider,
            std::function<Result<std::vector<OpaqueKey>>()> public_keys, ScopedObjectStore& objects, ClientRpc& rpc);
  // principal is set by the authenticated listener/TLS adapter, never a header.
  Result<HttpResponse> dispatch(const Hash& principal, const HttpRequest&, std::uint64_t monotonic_seconds);
};
}  // namespace tos::auth
