#include <iostream>
#include <stdexcept>

#include "validator/auth/object-store.h"
using namespace tos::auth;
void check(bool value, const char* name) {
  if (!value)
    throw std::runtime_error(name);
}
template <class T>
T value(Result<T> r, const char* label) {
  check(r.ok(), label);
  return std::move(r.value());
}
Hash h(unsigned n) {
  Hash hash{};
  hash[30] = static_cast<std::uint8_t>(n >> 8);
  hash[31] = static_cast<std::uint8_t>(n);
  return hash;
}
int main() {
  try {
    Bytes raw(65537, 7);
    auto carrier = value(object_value(5, raw), "carrier");
    auto manifest = carrier.reference_[0];
    Anchor anchor{0, h(1), h(2), h(3)};
    ScopedObjectStore store;
    value(store.publish(h(10), anchor, manifest, raw, 1), "publish");
    ObjectReader reader(
        [&](const ObjectRef& ref, std::uint8_t index) { return store.get(h(10), anchor, ref, index, 1); });
    check(value(reader.resolve(carrier, 5), "read-published") == raw, "published-bytes");
    check(!store.get(h(11), anchor, manifest, 0, 1).ok(), "principal-scope");
    auto other = anchor;
    other.state_[0] ^= 1;
    check(!store.get(h(10), other, manifest, 0, 1).ok(), "anchor-scope");
    auto wrong = raw;
    wrong[0] ^= 1;
    check(!store.publish(h(10), anchor, manifest, wrong, 1).ok(), "published-object-binding");
    check(store.reserved() == raw.size(), "publication-accounting");
    value(store.put(h(10), anchor, manifest, 0, raw, 1), "idempotent-upload");
    check(store.reserved() == raw.size(), "idempotent-quota");
    for (unsigned n = 1; n < 4; ++n) {
      other = anchor;
      other.seqno_ = n;
      value(store.publish(h(10), other, manifest, raw, 1), "next-scope");
    }
    other.seqno_ = 4;
    check(!store.publish(h(10), other, manifest, raw, 1).ok(), "principal-object-quota");
    value(store.publish(h(11), anchor, manifest, raw, 1), "independent-principal");
    ScopedObjectStore global(raw.size());
    value(global.publish(h(1), anchor, manifest, raw, 1), "global-at-bound");
    check(!global.publish(h(2), anchor, manifest, raw, 1).ok(), "global-storage-quota");
    ScopedObjectStore partial;
    Bytes chunk(1048576, 1);
    ObjectRef large{5, 67108864, h(123), std::vector<Hash>(64, h(999))};
    Bytes chunk_preimage(large.object_id_.begin(), large.object_id_.end());
    chunk_preimage.push_back(0);
    chunk_preimage.insert(chunk_preimage.end(), chunk.begin(), chunk.end());
    large.chunk_hashes_[0] = value(digest("object-chunk", chunk_preimage), "chunk-hash");
    value(partial.put(h(1), anchor, large, 0, chunk, 1), "reserve-full-length");
    check(partial.reserved() == 67108864, "full-length-accounting");
    check(!partial.put(h(1), anchor, large, 1, chunk, 1).ok(), "chunk-admission");
    check(!partial.publish(h(1), anchor, manifest, raw, 1).ok(), "principal-byte-quota");
    check(!partial.get(h(1), anchor, large, 0, 61).ok(), "storage-expiry");
    check(partial.reserved() == 0, "expiry-releases-storage");
    check(!partial.get(h(1), anchor, large, 0, 60).ok(), "clock-regression");
    std::cout << "PASS: principal/anchor scoped objects, atomic publication, full reservations and bounded storage\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
