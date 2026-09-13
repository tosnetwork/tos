#include "vm/boc.h"
#include "vm/cells/CellSlice.h"
#include "vm/cells/MerkleProof.h"
#include "vm/excno.hpp"

#include "committee-proof.h"
namespace tos::auth {
namespace {
Result<td::Ref<vm::Cell>> read_proof(std::span<const std::uint8_t> raw) {
  if (raw.empty() || raw.size() > 67108864)
    return Error{"proof-bound"};
  td::Slice bytes(reinterpret_cast<const char*>(raw.data()), raw.size());
  vm::BagOfCells::Info info;
  auto size = info.parse_serialized_header(bytes.substr(0, std::min<std::size_t>(256, raw.size())));
  if (size <= 0 || static_cast<std::size_t>(size) != raw.size() || info.root_count != 1 || info.cell_count <= 0 ||
      info.cell_count > 400001 || info.absent_count != 0)
    return Error{"proof-header"};
  vm::BagOfCells boc;
  auto consumed = boc.deserialize(bytes, 1);
  if (consumed.is_error() || consumed.ok() != static_cast<long long>(raw.size()) || boc.get_root_count() != 1)
    return Error{"proof-boc"};
  vm::CellStorageStat reachable(info.cell_count);
  auto walked = reachable.compute_used_storage(boc.get_root_cell());
  if (walked.is_error() || reachable.cells != static_cast<unsigned>(info.cell_count))
    return Error{"proof-unreachable-cells"};
  return boc.get_root_cell();
}
}  // namespace
Result<Proofref> make_committee_proof(td::Ref<vm::Cell> root, const Anchor& anchor, const ChainContext& chain,
                                      tos::ShardIdFull shard, std::uint32_t catchain, ObjectPublisher publisher) {
  try {
    vm::MerkleProofBuilder used(root);
    auto committee = NativeCommittee::derive(used.root(), anchor, chain, shard, catchain);
    if (!committee.ok())
      return committee.error();
    auto proof = used.extract_proof_boc();
    if (proof.is_error())
      return Error{"proof-generation"};
    auto bytes = proof.ok().as_slice();
    std::span<const std::uint8_t> raw(bytes.ubegin(), bytes.size());
    auto hash = digest("proof", raw);
    if (!hash.ok())
      return hash.error();
    auto carrier = object_value(5, raw);
    if (!carrier.ok())
      return carrier.error();
    if (!carrier.value().reference_.empty()) {
      if (!publisher)
        return Error{"proof-needs-object-store"};
      auto result = publisher(carrier.value().reference_[0], raw);
      if (!result.ok())
        return result.error();
      if (!result.value())
        return Error{"proof-publication"};
    }
    return Proofref{anchor, 5, committee.value().snapshot().committee_id(), hash.value(), carrier.value()};
  } catch (const vm::VmError&) {
    return Error{"committee-proof"};
  } catch (const vm::VmVirtError&) {
    return Error{"incomplete-proof"};
  }
}
Result<NativeCommittee> verify_committee_proof(const Proofref& proof, const Anchor& anchor, const ChainContext& chain,
                                               tos::ShardIdFull shard, std::uint32_t catchain, ObjectReader& reader) {
  try {
    if (proof.anchor_ != anchor)
      return Error{"proof-anchor"};
    if (proof.kind_ != 5)
      return Error{"proof-kind"};
    auto raw = reader.resolve(proof.proof_, 5);
    if (!raw.ok())
      return raw.error();
    auto hash = digest("proof", raw.value());
    if (!hash.ok())
      return hash.error();
    if (hash.value() != proof.proof_hash_)
      return Error{"proof-hash"};
    auto root = read_proof(raw.value());
    if (!root.ok())
      return root.error();
    auto virtualized = vm::MerkleProof::virtualize(root.value());
    if (virtualized.is_error())
      return Error{"proof-merkle"};
    vm::MerkleProofBuilder used(virtualized.ok());
    auto committee = NativeCommittee::derive(used.root(), anchor, chain, shard, catchain);
    if (!committee.ok())
      return committee.error();
    if (proof.object_id_ != committee.value().snapshot().committee_id())
      return Error{"proof-object"};
    auto minimal = used.extract_proof();
    if (minimal.is_error() || minimal.ok()->get_hash() != root.value()->get_hash())
      return Error{"proof-unrelated-values"};
    return committee;
  } catch (const vm::VmError&) {
    return Error{"committee-proof"};
  } catch (const vm::VmVirtError&) {
    return Error{"incomplete-proof"};
  }
}
}  // namespace tos::auth
