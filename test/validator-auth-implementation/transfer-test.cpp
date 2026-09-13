#include <iostream>
#include <stdexcept>

#include "validator/auth/transfer.h"
using namespace tos::auth;
void check(bool ok, const char* name) {
  if (!ok)
    throw std::runtime_error(name);
}
template <class T>
void rejected(const Result<T>& result, const char* code) {
  check(!result.ok(), code);
  check(result.error().code == code, "wrong-refusal");
}
int main() {
  try {
    Bytes small(65536, 7), large(1048577, 9);
    auto in = object_value(4, small);
    check(in.ok() && in.value().reference_.empty(), "inline-threshold");
    auto obj = object_value(4, large);
    check(obj.ok() && obj.value().inline_.empty(), "reference-threshold");
    auto ref = obj.value().reference_[0];
    check(ref.chunk_hashes_.size() == 2, "chunk-count");
    rejected(transferred_id(0, small), "object-kind");
    rejected(transferred_id(8, small), "object-kind");
    rejected(transferred_id(1, {}), "object-length");
    auto other = transferred_id(3, large);
    check(other.ok() && other.value() != ref.object_id_, "object-domain");
    auto first = std::span<const std::uint8_t>(large).first(chunk_bytes),
         last = std::span<const std::uint8_t>(large).last(1);
    check(validate_chunk(ref, 0, first).ok() && validate_chunk(ref, 1, last).ok(), "valid-chunks");
    auto changed = ref;
    changed.chunk_hashes_[0][0] ^= 1;
    rejected(validate_chunk(changed, 0, first), "chunk-hash");
    rejected(validate_chunk(ref, 2, last), "chunk-index");
    rejected(validate_chunk(ref, 0, last), "chunk-length");
    changed = ref;
    changed.chunk_hashes_.pop_back();
    rejected(validate_manifest(changed), "manifest-count");
    changed = ref;
    changed.byte_length_ = 65536;
    rejected(validate_manifest(changed), "manifest-length");
    auto both = in.value();
    both.reference_.push_back(ref);
    rejected(validate_object(both, 4), "object-representation");
    ChunkStore store(large.size(), 60);
    check(store.put(ref, 0, first, 100).ok(), "store-first");
    check(store.reserved() == large.size(), "full-reservation");
    check(store.put(ref, 0, first, 100).ok() && store.reserved() == large.size(), "duplicate-idempotent");
    check(store.put(ref, 1, last, 100).ok(), "store-last");
    auto alternate = object_value(3, large);
    check(alternate.ok(), "alternate");
    rejected(store.put(alternate.value().reference_[0], 0, first, 100), "storage-unavailable");
    ObjectReader reader([&](const ObjectRef& r, std::uint8_t i) { return store.get(r, i, 159); });
    auto resolved = reader.resolve(obj.value(), 4);
    check(resolved.ok() && resolved.value() == large, "resolved-object");
    rejected(store.get(ref, 0, 160), "object-unavailable");
    check(store.reserved() == 0, "expired-reservation");
    check(store.put(ref, 0, first, 160).ok(), "reuse-storage");
    ObjectReader broken([&](const ObjectRef&, std::uint8_t) { return Result<Bytes>(Bytes(chunk_bytes, 0)); });
    rejected(broken.resolve(obj.value(), 4), "chunk-hash");
    // A self-consistent manifest still cannot substitute a different whole object ID.
    auto forged = obj.value();
    forged.reference_[0].object_id_[0] ^= 1;
    for (std::size_t i = 0; i < 2; ++i) {
      Bytes bytes(forged.reference_[0].object_id_.begin(), forged.reference_[0].object_id_.end());
      bytes.push_back(i);
      auto part = i ? last : first;
      bytes.insert(bytes.end(), part.begin(), part.end());
      auto h = digest("object-chunk", bytes);
      check(h.ok(), "chunk-digest");
      forged.reference_[0].chunk_hashes_[i] = h.value();
    }
    ObjectReader substituted([&](const ObjectRef&, std::uint8_t i) {
      auto p = i ? last : first;
      return Result<Bytes>(Bytes(p.begin(), p.end()));
    });
    rejected(substituted.resolve(forged, 4), "object-hash");
    ObjectReader budget({});
    for (int i = 0; i < 1024; ++i)
      check(budget.resolve(in.value(), 4).ok(), "budget-admission");
    rejected(budget.resolve(in.value(), 4), "attachment-budget");
    std::cout << "PASS: transfer boundaries\n";
    return 0;
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
