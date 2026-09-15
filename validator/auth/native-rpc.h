#pragma once
#include "api-service.h"
#include "certificate-proof.h"
#include "native-proof.h"
namespace tos::auth {
class NativeStateSource {
 public:
  virtual ~NativeStateSource() = default;
  // Only independently validated local block history may implement this lookup.
  // It must bind the complete block ID and resulting state to this exact anchor.
  virtual Result<td::Ref<vm::Cell>> state(const Anchor&) const = 0;
  virtual Result<ChainContext> chain_context() const {
    return Error{"unsupported-native-method"};
  }
  // The claim is a lookup locator only. Resolve session birth/era and native
  // payload permission from authenticated history, retaining old sessions.
  virtual Result<Duty> expected_duty(const Anchor&, const Duty&) const {
    return Error{"history-unavailable"};
  }
  // Public immutable archive, keyed by the entire anchor and canonical ID.
  // Retrieval alone does not grant verification; the RPC rechecks its bytes.
  virtual Result<Certificate> certificate(const Anchor&, const Hash&) const {
    return Error{"history-unavailable"};
  }
};
class NativeClientRpc final : public ClientRpc {
  const NativeStateSource& source_;
  ScopedObjectStore& objects_;
  std::int32_t network_;

 public:
  NativeClientRpc(const NativeStateSource& source, ScopedObjectStore& objects, std::int32_t network)
      : source_(source), objects_(objects), network_(network) {
  }
  Result<Bytes> call(std::uint8_t method, const Bytes&, const Hash& principal, std::uint64_t now,
                     ObjectReader&) override;
};
}  // namespace tos::auth
