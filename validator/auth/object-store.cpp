#include "object-store.h"
namespace tos::auth {
Result<Hash> ScopedObjectStore::scope(const Hash& principal, const Anchor& anchor) {
  if (principal == Hash{} || anchor.seqno_ == std::numeric_limits<std::uint32_t>::max() || anchor.root_ == Hash{} ||
      anchor.file_ == Hash{} || anchor.state_ == Hash{})
    return Error{"object-scope"};
  Writer w;
  w.bytes(principal);
  write(w, anchor);
  if (!w.ok())
    return Error{w.error};
  return digest("local-object-scope", w.data);
}
Result<bool> ScopedObjectStore::expire(std::uint64_t now) {
  if (now < clock_)
    return Error{"storage-clock-regression"};
  clock_ = now;
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (it->second.expires > now) {
      ++it;
      continue;
    }
    auto principal = principals_.find(it->second.principal);
    if (principal == principals_.end() || principal->second.objects == 0 ||
        principal->second.bytes < it->second.manifest.byte_length_ || used_ < it->second.manifest.byte_length_)
      return Error{"storage-accounting"};
    used_ -= it->second.manifest.byte_length_;
    principal->second.bytes -= it->second.manifest.byte_length_;
    --principal->second.objects;
    if (principal->second.objects == 0)
      principals_.erase(principal);
    it = entries_.erase(it);
  }
  return true;
}
Result<bool> ScopedObjectStore::admit(const Hash& principal, const ObjectRef& ref, std::uint64_t now) const {
  auto current = principals_.find(principal);
  Usage usage;
  if (current != principals_.end())
    usage = current->second;
  else if (principals_.size() >= 1024)
    return Error{"storage-unavailable"};
  if (usage.objects >= 4 || usage.bytes > 67108864 || ref.byte_length_ > 67108864 - usage.bytes)
    return Error{"principal-storage-quota"};
  if (used_ > limit_ || ref.byte_length_ > limit_ - used_)
    return Error{"global-storage-quota"};
  if (now > std::numeric_limits<std::uint64_t>::max() - ttl_)
    return Error{"storage-clock-overflow"};
  return true;
}
Result<Hash> ScopedObjectStore::put(const Hash& principal, const Anchor& anchor, const ObjectRef& ref,
                                    std::uint8_t index, std::span<const std::uint8_t> raw, std::uint64_t now) {
  auto scoped = scope(principal, anchor);
  if (!scoped.ok())
    return scoped.error();
  auto manifest = validate_manifest(ref);
  if (!manifest.ok())
    return manifest.error();
  auto cleanup = expire(now);
  if (!cleanup.ok())
    return cleanup.error();
  auto id = object_id("object_ref", ref);
  if (!id.ok())
    return id.error();
  auto key = std::make_pair(scoped.value(), id.value());
  auto found = entries_.find(key);
  if (found == entries_.end()) {
    auto admitted = admit(principal, ref, now);
    if (!admitted.ok())
      return admitted.error();
  }
  auto checked = validate_chunk(ref, index, raw);
  if (!checked.ok())
    return checked.error();
  if (found == entries_.end()) {
    Entry entry{principal, ref, {}, now + ttl_};
    entry.chunks.emplace(index, Bytes(raw.begin(), raw.end()));
    entries_.emplace(key, std::move(entry));
    used_ += ref.byte_length_;
    auto& usage = principals_[principal];
    usage.bytes += ref.byte_length_;
    ++usage.objects;
  } else {
    auto chunk = found->second.chunks.find(index);
    if (chunk != found->second.chunks.end()) {
      if (chunk->second.size() != raw.size() || !std::equal(chunk->second.begin(), chunk->second.end(), raw.begin()))
        return Error{"chunk-conflict"};
    } else
      found->second.chunks.emplace(index, Bytes(raw.begin(), raw.end()));
  }
  return id.value();
}
Result<Bytes> ScopedObjectStore::get(const Hash& principal, const Anchor& anchor, const ObjectRef& ref,
                                     std::uint8_t index, std::uint64_t now) {
  auto scoped = scope(principal, anchor);
  if (!scoped.ok())
    return scoped.error();
  auto checked = validate_manifest(ref);
  if (!checked.ok())
    return checked.error();
  if (index >= ref.chunk_hashes_.size())
    return Error{"chunk-index"};
  auto cleanup = expire(now);
  if (!cleanup.ok())
    return cleanup.error();
  auto id = object_id("object_ref", ref);
  if (!id.ok())
    return id.error();
  auto found = entries_.find({scoped.value(), id.value()});
  if (found == entries_.end())
    return Error{"object-unavailable"};
  auto chunk = found->second.chunks.find(index);
  if (chunk == found->second.chunks.end())
    return Error{"object-unavailable"};
  return chunk->second;
}
Result<bool> ScopedObjectStore::publish(const Hash& principal, const Anchor& anchor, const ObjectRef& ref,
                                        std::span<const std::uint8_t> raw, std::uint64_t now) {
  auto scoped = scope(principal, anchor);
  if (!scoped.ok())
    return scoped.error();
  auto checked = validate_manifest(ref);
  if (!checked.ok())
    return checked.error();
  if (raw.size() != ref.byte_length_)
    return Error{"object-length"};
  auto cleanup = expire(now);
  if (!cleanup.ok())
    return cleanup.error();
  auto id = object_id("object_ref", ref);
  if (!id.ok())
    return id.error();
  auto key = std::make_pair(scoped.value(), id.value());
  auto found = entries_.find(key);
  if (found == entries_.end()) {
    auto admitted = admit(principal, ref, now);
    if (!admitted.ok())
      return admitted.error();
  }
  auto canonical = object_value(ref.kind_, raw);
  if (!canonical.ok())
    return canonical.error();
  if (canonical.value().reference_ != std::vector<ObjectRef>{ref})
    return Error{"published-object-binding"};
  Entry entry{principal, ref, {}, found == entries_.end() ? now + ttl_ : found->second.expires};
  for (std::size_t offset = 0, index = 0; offset < raw.size(); offset += chunk_bytes, ++index) {
    auto chunk = raw.subspan(offset, std::min(chunk_bytes, raw.size() - offset));
    entry.chunks.emplace(static_cast<std::uint8_t>(index), Bytes(chunk.begin(), chunk.end()));
  }
  if (found == entries_.end()) {
    entries_.emplace(key, std::move(entry));
    used_ += ref.byte_length_;
    auto& usage = principals_[principal];
    usage.bytes += ref.byte_length_;
    ++usage.objects;
  } else
    found->second = std::move(entry);
  return true;
}
}  // namespace tos::auth
