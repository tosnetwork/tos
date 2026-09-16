#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"

#include "native-evidence.h"
namespace tos::auth {
namespace {
void need(bool ok, const char* code) {
  if (!ok)
    throw Error{code};
}
template <class T>
T take(Result<T> r) {
  if (!r.ok())
    throw r.error();
  return std::move(r.value());
}
using ChunkKey = std::array<std::uint8_t, 33>;
ChunkKey key(const Hash& id, std::uint8_t index) {
  ChunkKey k{};
  std::copy(id.begin(), id.end(), k.begin());
  k[32] = index;
  return k;
}
std::size_t declared(td::Ref<vm::Cell> root, std::size_t limit) {
  vm::CellSlice s{vm::NoVm{}, root};
  need(s.is_valid() && !s.is_special() && root->get_level() == 0 && s.size() == 336 && s.size_refs() == 1,
       "auth-bytes-shape");
  need(s.fetch_ulong(32) == 0x76616231 && s.fetch_ulong(16) == 1, "auth-bytes-version");
  auto n = s.fetch_ulong(32);
  need(n != 0 && n <= limit, "evidence-byte-bound");
  return n;
}
}  // namespace
ObjectReader NativeEvidence::reader() const {
  return ObjectReader([chunks = chunks_](const ObjectRef& ref, std::uint8_t index) -> Result<Bytes> {
    auto it = chunks->find(key(ref.object_id_, index));
    // Admission already required every declared chunk to be present, so a
    // resolve that misses one would mean a reference the manifest never
    // declared. No case in the evidence suite reaches this: relabelling it
    // leaves all of them passing. It stays because removing a refusal whose
    // condition is merely believed unreachable is how the belief stops being
    // checked, but it is not a guard anything currently proves.
    if (it == chunks->end())
      return Error{"evidence-missing-chunk"};
    return it->second;
  });
}
Result<NativeEvidence> NativeEvidence::open(td::Ref<vm::Cell> root, const EvidenceCharge& charge) {
  try {
    need(bool(charge), "evidence-charge");
    vm::CellSlice s{vm::NoVm{}, root};
    need(s.is_valid() && !s.is_special() && root->get_level() == 0 && !root->is_virtualized() && s.size() == 49 &&
             s.size_refs() >= 2,
         "evidence-shape");
    need(s.fetch_ulong(32) == native_evidence_tag && s.fetch_ulong(16) == 1, "evidence-version");
    bool present = s.fetch_ulong(1);
    need(s.size_refs() == 2 + unsigned(present), "evidence-shape");
    auto auth = s.fetch_ref();
    auto header = s.fetch_ref();
    auto bytes = declared(auth, native_authorizations_limit);
    need(take(charge(bytes)), "evidence-charge");
    auto a = take(decode<Authorizations>(take(unpack_bytes(auth, native_authorizations_limit))));
    if (a.owner_.empty()) {
      vm::CellSlice h{vm::NoVm{}, header};
      need(!h.is_special() && h.size() == 0 && h.size_refs() == 0, "evidence-unused-header");
    }
    std::vector<std::pair<const ObjectValue*, std::uint8_t>> objects;
    for (const auto& v : a.owner_)
      objects.emplace_back(&v.proof_.proof_, 5);
    for (const auto& v : a.administration_)
      objects.emplace_back(&v.certificate_, 4);
    for (const auto& v : a.governance_)
      objects.emplace_back(&v.certificate_, 4);
    std::map<ChunkKey, std::size_t> expected;
    std::map<Hash, ObjectRef> manifests;
    std::size_t remaining = 67108864;
    for (const auto& [v, kind] : objects) {
      take(validate_object(*v, kind));
      auto size = v->inline_.empty() ? v->reference_[0].byte_length_ : v->inline_.size();
      need(size <= remaining, "attachment-budget");
      remaining -= size;
      if (v->reference_.empty())
        continue;
      const auto& ref = v->reference_[0];
      auto [it, inserted] = manifests.emplace(ref.object_id_, ref);
      need(inserted || it->second == ref, "evidence-manifest-conflict");
      for (std::size_t i = 0; i < ref.chunk_hashes_.size(); ++i)
        expected.emplace(key(ref.object_id_, static_cast<std::uint8_t>(i)),
                         std::min(chunk_bytes, ref.byte_length_ - i * chunk_bytes));
    }
    // At most three objects with at most 64 chunks each. Iterate only as many
    // dictionary leaves as admitted by the typed manifests; never enumerate extras.
    vm::Dictionary supplied(present ? s.fetch_ref() : td::Ref<vm::Cell>{}, 264);
    vm::Dictionary canonical(264);
    std::map<ChunkKey, td::Ref<vm::Cell>> cells;
    need(supplied.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr bits, int width) {
      need(width == 264 && value->size() == 0 && value->size_refs() == 1, "evidence-chunk-shape");
      ChunkKey k{};
      td::BitPtr(k.data()).copy_from(bits, 264);
      auto it = expected.find(k);
      need(it != expected.end(), "evidence-extra-chunk");
      auto cell = value->prefetch_ref();
      need(declared(cell, chunk_bytes) == it->second, "evidence-chunk-length");
      cells.emplace(k, cell);
      need(canonical.set_ref(td::ConstBitPtr(k.data()), 264, cell, vm::Dictionary::SetMode::Add),
           "evidence-dictionary");
      return true;
    }),
         "evidence-dictionary");
    need(cells.size() == expected.size(), "evidence-missing-chunk");
    auto supplied_root = supplied.get_root_cell(), canonical_root = canonical.get_root_cell();
    need(supplied_root.is_null() == canonical_root.is_null() &&
             (supplied_root.is_null() || supplied_root->get_hash() == canonical_root->get_hash()),
         "evidence-dictionary");
    need(take(charge(67108864 - remaining)), "evidence-charge");
    std::map<ChunkKey, Bytes> chunks;
    for (const auto& [k, cell] : cells)
      chunks.emplace(k, take(unpack_bytes(cell, expected.at(k))));
    NativeEvidence result(a, header, std::move(chunks));
    auto reader = result.reader();
    for (const auto& [v, kind] : objects)
      take(reader.resolve(*v, kind));
    return result;
  } catch (const Error& e) {
    return e;
  } catch (const vm::VmError&) {
    return Error{"evidence-cell"};
  } catch (const vm::VmVirtError&) {
    return Error{"evidence-pruned"};
  }
}
Result<Anchor> NativeEvidence::authenticate_owner(const NativeFinalizedHistory& history) const {
  if (authorizations_.owner_.size() != 1)
    return Error{"evidence-owner-absent"};
  const auto& expected = authorizations_.owner_[0].proof_.anchor_;
  auto actual = history.authenticate_header(expected.seqno_, header_);
  if (!actual.ok())
    return actual.error();
  if (actual.value() != expected)
    return Error{"evidence-owner-anchor"};
  return actual;
}
}  // namespace tos::auth
