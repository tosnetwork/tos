#include "transfer.h"
namespace tos::auth {
namespace {
std::size_t limit(std::uint8_t kind) {
  return kind == 5 ? 67108864 : max_object_bytes;
}
constexpr std::string_view domains[]{"", "key", "policy", "committee", "certificate", "proof", "envelope", "update"};
Result<Hash> chunk_hash(const Hash& id, std::uint8_t index, std::span<const std::uint8_t> data) {
  Bytes bytes(id.begin(), id.end());
  bytes.push_back(index);
  bytes.insert(bytes.end(), data.begin(), data.end());
  return digest("object-chunk", bytes);
}
}  // namespace
Result<Hash> transferred_id(std::uint8_t kind, std::span<const std::uint8_t> raw) {
  if (kind < 1 || kind > 7)
    return Error{"object-kind"};
  if (raw.empty() || raw.size() > limit(kind))
    return Error{"object-length"};
  return digest(domains[kind], raw);
}
Result<ObjectValue> object_value(std::uint8_t kind, std::span<const std::uint8_t> raw) {
  auto id = transferred_id(kind, raw);
  if (!id.ok())
    return id.error();
  ObjectValue value;
  value.kind_ = kind;
  if (raw.size() <= inline_bytes)
    value.inline_.assign(raw.begin(), raw.end());
  else {
    ObjectRef ref;
    ref.kind_ = kind;
    ref.byte_length_ = static_cast<std::uint32_t>(raw.size());
    ref.object_id_ = id.value();
    for (std::size_t i = 0; i < raw.size(); i += chunk_bytes) {
      auto hash = chunk_hash(id.value(), static_cast<std::uint8_t>(i / chunk_bytes),
                             raw.subspan(i, std::min(chunk_bytes, raw.size() - i)));
      if (!hash.ok())
        return hash.error();
      ref.chunk_hashes_.push_back(hash.value());
    }
    value.reference_.push_back(std::move(ref));
  }
  return value;
}
Result<bool> validate_manifest(const ObjectRef& ref) {
  if (ref.kind_ < 1 || ref.kind_ > 7)
    return Error{"object-kind"};
  if (ref.byte_length_ <= inline_bytes || ref.byte_length_ > limit(ref.kind_))
    return Error{"manifest-length"};
  if (ref.chunk_hashes_.size() != (ref.byte_length_ + chunk_bytes - 1) / chunk_bytes)
    return Error{"manifest-count"};
  return true;
}
Result<bool> validate_object(const ObjectValue& value, std::uint8_t expected) {
  if (expected < 1 || expected > 7 || value.kind_ != expected)
    return Error{"object-kind"};
  if (value.inline_.empty()) {
    if (value.reference_.size() != 1)
      return Error{"object-representation"};
    if (value.reference_[0].kind_ != expected)
      return Error{"object-kind"};
    return validate_manifest(value.reference_[0]);
  }
  if (!value.reference_.empty() || value.inline_.size() > inline_bytes)
    return Error{"object-representation"};
  return true;
}
Result<bool> validate_chunk(const ObjectRef& ref, std::uint8_t index, std::span<const std::uint8_t> data) {
  auto valid = validate_manifest(ref);
  if (!valid.ok())
    return valid.error();
  if (index >= ref.chunk_hashes_.size())
    return Error{"chunk-index"};
  if (data.size() != std::min(chunk_bytes, ref.byte_length_ - std::size_t(index) * chunk_bytes))
    return Error{"chunk-length"};
  auto h = chunk_hash(ref.object_id_, index, data);
  if (!h.ok())
    return h.error();
  if (h.value() != ref.chunk_hashes_[index])
    return Error{"chunk-hash"};
  return true;
}
Result<Bytes> ObjectReader::resolve(const ObjectValue& value, std::uint8_t kind) {
  source_error_.reset();
  auto valid = validate_object(value, kind);
  if (!valid.ok())
    return valid.error();
  std::size_t size = value.inline_.empty() ? value.reference_[0].byte_length_ : value.inline_.size();
  if (size > remaining_)
    return Error{"attachment-budget"};
  remaining_ -= size;
  if (!value.inline_.empty())
    return value.inline_;
  if (!fetch_) {
    source_error_ = Error{"object-unavailable"};
    return *source_error_;
  }
  const auto& ref = value.reference_[0];
  Bytes out;
  out.reserve(size);
  for (std::size_t i = 0; i < ref.chunk_hashes_.size(); ++i) {
    auto chunk = fetch_(ref, static_cast<std::uint8_t>(i));
    if (!chunk.ok()) {
      source_error_ = chunk.error();
      return chunk.error();
    }
    auto checked = validate_chunk(ref, static_cast<std::uint8_t>(i), chunk.value());
    if (!checked.ok())
      return checked.error();
    out.insert(out.end(), chunk.value().begin(), chunk.value().end());
  }
  auto id = transferred_id(kind, out);
  if (!id.ok())
    return id.error();
  if (id.value() != ref.object_id_)
    return Error{"object-hash"};
  return out;
}
void ChunkStore::expire(std::uint64_t now) {
  for (auto i = entries_.begin(); i != entries_.end();)
    if (i->second.expires <= now) {
      used_ -= i->second.ref.byte_length_;
      i = entries_.erase(i);
    } else
      ++i;
}
Result<Hash> ChunkStore::put(const ObjectRef& ref, std::uint8_t index, std::span<const std::uint8_t> data,
                             std::uint64_t now) {
  auto checked = validate_chunk(ref, index, data);
  if (!checked.ok())
    return checked.error();
  expire(now);
  auto id = object_id("object_ref", ref);
  if (!id.ok())
    return id.error();
  auto found = entries_.find(id.value());
  if (found == entries_.end()) {
    if (entries_.size() >= 4 || ref.byte_length_ > limit_ - used_ ||
        now > std::numeric_limits<std::uint64_t>::max() - ttl_)
      return Error{"storage-unavailable"};
    found = entries_.emplace(id.value(), Entry{ref, {}, now + ttl_}).first;
    used_ += ref.byte_length_;
  }
  auto chunk = found->second.chunks.find(index);
  if (chunk != found->second.chunks.end()) {
    if (chunk->second.size() != data.size() || !std::equal(data.begin(), data.end(), chunk->second.begin()))
      return Error{"chunk-conflict"};
  } else
    found->second.chunks.emplace(index, Bytes(data.begin(), data.end()));
  return id.value();
}
Result<Bytes> ChunkStore::get(const ObjectRef& ref, std::uint8_t index, std::uint64_t now) {
  auto checked = validate_manifest(ref);
  if (!checked.ok())
    return checked.error();
  if (index >= ref.chunk_hashes_.size())
    return Error{"chunk-index"};
  expire(now);
  auto id = object_id("object_ref", ref);
  if (!id.ok())
    return id.error();
  auto found = entries_.find(id.value());
  if (found == entries_.end())
    return Error{"object-unavailable"};
  auto chunk = found->second.chunks.find(index);
  if (chunk == found->second.chunks.end())
    return Error{"object-unavailable"};
  return chunk->second;
}
}  // namespace tos::auth
