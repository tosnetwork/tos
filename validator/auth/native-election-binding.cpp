#include <set>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "tos/quorum.h"
#include "vm/dict.h"

#include "native-election-binding.h"
namespace tos::auth {
namespace {
// A member the elector emitted, in the only two shapes it emits.
struct Emitted {
  td::Ref<vm::CellSlice> public_key;
  std::uint64_t weight{};
  td::Bits256 adnl_addr{};
  bool has_address{};
};

Result<Emitted> emitted_member(const td::Ref<vm::CellSlice>& descriptor) {
  Emitted member;
  block::gen::ValidatorDescr::Record_validator_addr addressed;
  if (tlb::csr_unpack(descriptor, addressed)) {
    member.public_key = addressed.public_key;
    member.weight = addressed.weight;
    member.adnl_addr = addressed.adnl_addr;
    member.has_address = true;
    return member;
  }
  block::gen::ValidatorDescr::Record_validator plain;
  if (tlb::csr_unpack(descriptor, plain)) {
    member.public_key = plain.public_key;
    member.weight = plain.weight;
    return member;
  }
  return Error{"election-binding-descriptor"};
}
}  // namespace

Result<td::Ref<vm::Cell>> bind_elected_validators(td::Ref<vm::Cell> elected,
                                                  const std::map<unsigned, ElectedBinding>& bindings,
                                                  const RegistryView& registry) {
  try {
    if (elected.is_null())
      return Error{"election-binding-input"};

    block::gen::ValidatorSet::Record_validators_ext set;
    if (!tlb::unpack_cell(elected, set))
      return Error{"election-binding-set"};
    if (set.total == 0 || set.main == 0 || set.main > set.total || set.utime_since >= set.utime_until ||
        set.total_weight == 0)
      return Error{"election-binding-set"};
    if (bindings.size() != set.total)
      return Error{"election-binding-incomplete"};

    vm::Dictionary emitted(set.list->prefetch_ref(), 16);
    vm::Dictionary bound(16);
    std::set<Hash> identities, stakes;
    std::uint64_t weight = 0;

    for (unsigned index = 0; index < set.total; ++index) {
      td::BitArray<16> key;
      key.store_ulong(index);
      auto descriptor = emitted.lookup(key.cbits(), 16);
      if (descriptor.is_null())
        return Error{"election-binding-incomplete"};

      auto member = emitted_member(descriptor);
      if (!member.ok())
        return member.error();
      // An authenticated descriptor carries an address, so a member elected
      // without one cannot be bound at all. Refusing the set here is the point:
      // the alternative is a set that only fails at derivation.
      if (!member.value().has_address || member.value().weight == 0)
        return Error{"election-binding-descriptor"};

      auto named = bindings.find(index);
      if (named == bindings.end() || named->second.staking_account == Hash{} ||
          named->second.claimed_identity == Hash{})
        return Error{"election-binding-incomplete"};

      auto found = registry.identity(named->second.claimed_identity);
      if (!found.ok())
        return Error{"election-binding-unregistered"};
      // The registry, not the member, decides whose identity this is.
      if (found.value().owner_workchain_ != tos::masterchainId ||
          found.value().owner_address_ != named->second.staking_account)
        return Error{"election-binding-owner"};
      // One identity elected twice would seat one registry member under two
      // network keys, which derivation refuses; refusing it here names it.
      if (!identities.insert(found.value().identity_).second || !stakes.insert(found.value().stake_id_).second)
        return Error{"election-binding-duplicate"};

      td::Ref<vm::Cell> binding;
      if (!block::gen::t_ValidatorAuthBinding.cell_pack_validator_auth_binding(
              binding, td::Bits256(td::ConstBitPtr(found.value().identity_.data())),
              td::Bits256(td::ConstBitPtr(found.value().stake_id_.data()))))
        return Error{"election-binding-pack"};

      vm::CellBuilder cb;
      if (!block::gen::t_ValidatorDescr.pack(
              cb, block::gen::ValidatorDescr::Record_validator_auth{member.value().public_key, member.value().weight,
                                                                    member.value().adnl_addr, binding}))
        return Error{"election-binding-pack"};
      if (!bound.set_builder(key.cbits(), 16, cb))
        return Error{"election-binding-pack"};

      if (!tos::checked_add_validator_weight(weight, member.value().weight))
        return Error{"election-binding-weight"};
    }

    // The set's own declared weight has to survive untouched, so a rewrite that
    // silently changed one member's weight cannot pass as a binding.
    if (weight != set.total_weight)
      return Error{"election-binding-weight"};

    td::Ref<vm::Cell> result;
    vm::CellBuilder wrapper;
    if (!wrapper.store_maybe_ref(bound.get_root_cell()))
      return Error{"election-binding-pack"};
    set.list = vm::load_cell_slice_ref(wrapper.finalize());
    if (!tlb::pack_cell(result, set))
      return Error{"election-binding-pack"};
    return result;
  } catch (const vm::VmError&) {
    return Error{"election-binding-cell"};
  } catch (const vm::VmVirtError&) {
    return Error{"election-binding-pruned"};
  }
}
}  // namespace tos::auth
