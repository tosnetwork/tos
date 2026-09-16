#include "owner-proof-producer.h"

#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/excno.hpp"
#include "vm/vm.h"

namespace tos::auth {
Result<OwnerAuth> make_owner_execution_proof(td::Ref<vm::Cell> state, td::Ref<vm::Cell> block, const Anchor& anchor,
                                             const ChainContext& chain, const Update& update, const Identity& current,
                                             std::uint64_t lt, std::uint16_t index, ObjectPublisher publisher) {
  try {
    vm::MerkleProofBuilder used_state(state), used_block(block);
    auto verified =
        owner_execution_check(used_state.root(), used_block.root(), anchor, chain, update, current, lt, index);
    if (!verified.ok())
      return verified.error();
    auto state_proof = owner_canonical_proof(used_state), block_proof = owner_canonical_proof(used_block);
    if (!state_proof.ok() || !block_proof.ok())
      return Error{"proof-generation"};
    vm::CellBuilder header;
    header.store_long(owner_proof_tag, 32)
        .store_long(1, 16)
        .store_long(lt, 64)
        .store_long(index, 15)
        .store_ref(state_proof.value())
        .store_ref(block_proof.value());
    auto raw = vm::std_boc_serialize(header.finalize());
    if (raw.is_error())
      return Error{"proof-generation"};
    std::span<const std::uint8_t> bytes(raw.ok().as_slice().ubegin(), raw.ok().size());
    auto carrier = object_value(5, bytes);
    auto hash = digest("proof", bytes);
    auto id = object_id("update", update);
    if (!carrier.ok())
      return carrier.error();
    if (!hash.ok())
      return hash.error();
    if (!id.ok())
      return id.error();
    if (!carrier.value().reference_.empty()) {
      if (!publisher)
        return Error{"proof-needs-object-store"};
      auto published = publisher(carrier.value().reference_[0], bytes);
      if (!published.ok())
        return published.error();
      if (!published.value())
        return Error{"proof-publication"};
    }
    return OwnerAuth{id.value(),
                     current.stake_id_,
                     current.owner_workchain_,
                     current.owner_address_,
                     {anchor, 1, id.value(), hash.value(), carrier.value()}};
  } catch (const vm::VmError&) {
    return Error{"owner-proof"};
  } catch (const vm::VmVirtError&) {
    return Error{"incomplete-proof"};
  }
}
}  // namespace tos::auth
