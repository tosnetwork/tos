#pragma once
#include <memory>

#include "cells.h"
#include "native-history.h"
namespace tos::auth {
inline constexpr std::uint32_t native_evidence_tag = 0x76616531;
inline constexpr std::size_t native_authorizations_limit = 4 * inline_bytes + 4096;
// Receives a deterministic upper bound before decoding/hashing those bytes.
// Native execution supplies its gas charger; this parser does not establish gas prices.
using EvidenceCharge = std::function<Result<bool>(std::size_t)>;
class NativeEvidence {
  using ChunkKey = std::array<std::uint8_t, 33>;
  Authorizations authorizations_;
  td::Ref<vm::Cell> header_;
  std::shared_ptr<const std::map<ChunkKey, Bytes>> chunks_;
  NativeEvidence(Authorizations a, td::Ref<vm::Cell> h, std::map<ChunkKey, Bytes> chunks)
      : authorizations_(std::move(a))
      , header_(std::move(h))
      , chunks_(std::make_shared<const std::map<ChunkKey, Bytes>>(std::move(chunks))) {
  }

 public:
  // All referenced objects are validated locally before returning. No fetch IO.
  static Result<NativeEvidence> open(td::Ref<vm::Cell>, const EvidenceCharge&);
  const Authorizations& authorizations() const {
    return authorizations_;
  }
  ObjectReader reader() const;
  Result<Anchor> authenticate_owner(const NativeFinalizedHistory&) const;
};
}  // namespace tos::auth
