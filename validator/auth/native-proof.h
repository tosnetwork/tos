#pragma once
#include "cells.h"
#include "transfer.h"
namespace tos::auth {
class VerifiedNativeResponse {
  Bytes bytes_;
  Anchor anchor_;
  std::uint8_t method_;
  VerifiedNativeResponse(Bytes bytes, Anchor anchor, std::uint8_t method)
      : bytes_(std::move(bytes)), anchor_(anchor), method_(method) {
  }
  friend Result<VerifiedNativeResponse> verify_native_response(std::uint8_t, std::span<const std::uint8_t>,
                                                               std::span<const std::uint8_t>, const Anchor&,
                                                               std::int32_t, ObjectReader&);

 public:
  const Bytes& bytes() const {
    return bytes_;
  }
  const Anchor& anchor() const {
    return anchor_;
  }
  std::uint8_t method() const {
    return method_;
  }
};
// The anchor is obtained from independently established finality/checkpoint
// trust. A hash asserted by the peer supplying this proof is not such an anchor.
Result<Bytes> make_native_response(td::Ref<vm::Cell> masterchain_state, const Anchor&, std::int32_t network,
                                   std::uint8_t method, std::span<const std::uint8_t> request);
Result<VerifiedNativeResponse> verify_native_response(std::uint8_t method, std::span<const std::uint8_t> request,
                                                      std::span<const std::uint8_t> response,
                                                      const Anchor& independently_trusted_anchor, std::int32_t network,
                                                      ObjectReader&);
}  // namespace tos::auth
