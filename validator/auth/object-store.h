#pragma once
#include "transfer.h"
namespace tos::auth {
// The principal comes from authenticated transport credentials, never from a
// request field. Storage has no chain authority, even after all chunks arrive.
class ScopedObjectStore {
  struct Usage {
    std::size_t bytes = 0, objects = 0;
  };
  struct Entry {
    Hash principal;
    ObjectRef manifest;
    std::map<std::uint8_t, Bytes> chunks;
    std::uint64_t expires;
  };
  std::map<std::pair<Hash, Hash>, Entry> entries_;
  std::map<Hash, Usage> principals_;
  std::size_t used_ = 0, limit_;
  std::uint64_t ttl_, clock_ = 0;
  Result<bool> expire(std::uint64_t now);
  Result<bool> admit(const Hash&, const ObjectRef&, std::uint64_t now) const;
  static Result<Hash> scope(const Hash&, const Anchor&);

 public:
  explicit ScopedObjectStore(std::size_t global_bytes = 268435456, std::uint64_t ttl = 60)
      : limit_(std::min<std::size_t>(global_bytes, 268435456)), ttl_(std::clamp<std::uint64_t>(ttl, 1, 3600)) {
  }
  Result<Hash> put(const Hash& principal, const Anchor&, const ObjectRef&, std::uint8_t index,
                   std::span<const std::uint8_t>, std::uint64_t now);
  Result<Bytes> get(const Hash& principal, const Anchor&, const ObjectRef&, std::uint8_t index, std::uint64_t now);
  // The entire object is validated and admitted before storage changes. Failure
  // never returns a manifest claiming an object was successfully published.
  Result<bool> publish(const Hash& principal, const Anchor&, const ObjectRef&,
                       std::span<const std::uint8_t> complete_object, std::uint64_t now);
  std::size_t reserved() const {
    return used_;
  }
};
}  // namespace tos::auth
