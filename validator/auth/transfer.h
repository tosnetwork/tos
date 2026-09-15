#pragma once
#include <functional>
#include <map>
#include <optional>

#include "crypto.h"
namespace tos::auth {
inline constexpr std::size_t chunk_bytes = 1048576, inline_bytes = 65536;
Result<Hash> transferred_id(std::uint8_t kind, std::span<const std::uint8_t> raw);
Result<ObjectValue> object_value(std::uint8_t kind, std::span<const std::uint8_t> raw);
Result<bool> validate_manifest(const ObjectRef&);
Result<bool> validate_object(const ObjectValue&, std::uint8_t expected_kind);
Result<bool> validate_chunk(const ObjectRef&, std::uint8_t index, std::span<const std::uint8_t> data);
using FetchChunk = std::function<Result<Bytes>(const ObjectRef&, std::uint8_t)>;
class ObjectReader {
  FetchChunk fetch_;
  std::size_t remaining_ = 67108864;
  std::optional<Error> source_error_;

 public:
  explicit ObjectReader(FetchChunk fetch) : fetch_(std::move(fetch)) {
  }
  Result<Bytes> resolve(const ObjectValue&, std::uint8_t expected_kind);
  // Preserve trusted storage failure provenance separately from malformed
  // objects. Public RPC error classification must not turn outages into input errors.
  const std::optional<Error>& source_error() const {
    return source_error_;
  }
};
// One already-authenticated principal's object storage. The caller serializes access.
class ChunkStore {
  struct Entry {
    ObjectRef ref;
    std::map<std::uint8_t, Bytes> chunks;
    std::uint64_t expires;
  };
  std::map<Hash, Entry> entries_;
  std::size_t used_ = 0, limit_;
  std::uint64_t ttl_;

 public:
  explicit ChunkStore(std::size_t limit = 67108864, std::uint64_t ttl = 60)
      : limit_(std::min(limit, std::size_t(67108864))), ttl_(std::clamp(ttl, std::uint64_t(1), std::uint64_t(3600))) {
  }
  Result<Hash> put(const ObjectRef&, std::uint8_t, std::span<const std::uint8_t>, std::uint64_t now);
  Result<Bytes> get(const ObjectRef&, std::uint8_t, std::uint64_t now);
  void expire(std::uint64_t now);
  std::size_t reserved() const {
    return used_;
  }
};
}  // namespace tos::auth
