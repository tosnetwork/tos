#include "td/utils/tests.h"
#include "uno/core/nullifier-state.h"
#include "vm/boc.h"
#include "vm/vmstate.h"
#include <limits>

using namespace uno_workchain;

namespace {
td::Bits256 key(int last) {
  auto value = td::Bits256::zero();
  value.as_slice()[31] = static_cast<char>(last);
  return value;
}

td::Ref<vm::Cell> persisted(td::Ref<vm::Cell> root) {
  if (root.is_null()) return {};
  return vm::std_boc_deserialize(vm::std_boc_serialize(root).move_as_ok().as_slice()).move_as_ok();
}

td::Result<NullifierState> restore(const NullifierState& state,
                                 NullifierState::LoadLimits limits = {20, 20, 20, 20}) {
  return NullifierState::from_roots(persisted(state.used_root()), persisted(state.reserved_root()),
                                   persisted(state.owners_root()), limits);
}
}  // namespace

TEST(UnoNullifierState, ActorQueriesContainLoadFailuresWithoutReportingAbsence) {
  const auto used = UsedNullifiers{}.with_used({key(1)}).move_as_ok();
  const auto state = NullifierState{}.with_used({key(1)}).move_as_ok()
                         .reserve(key(10), {key(2)}).move_as_ok();
  const auto used_hash = state.used_root()->get_hash();
  const auto reserved_hash = state.reserved_root()->get_hash();
  const auto owners_hash = state.owners_root()->get_hash();
  class FailingLoad final : public vm::VmStateInterface {
   public:
    unsigned kind = 0;
    bool called = false;
    void register_cell_load(const vm::CellHash&) override {
      called = true;
      if (kind == 0) throw vm::VmError{vm::Excno::cell_und};
      if (kind == 1) throw vm::VmVirtError{1};
      throw vm::VmNoGas{};
    }
  } load;
  auto exercise = [&](auto query, const td::Bits256& present) {
    ASSERT_TRUE(query(present).move_as_ok());
    ASSERT_TRUE(!query(key(3)).move_as_ok());
    for (unsigned kind = 0; kind < 3; ++kind) {
      load.kind = kind;
      for (const auto& queried : {present, key(3)}) {
        load.called = false;
        vm::VmStateInterface::Guard guard(&load);
        ASSERT_TRUE(query(queried).is_error());
        ASSERT_TRUE(load.called);
      }
    }
    ASSERT_TRUE(query(present).move_as_ok());
    ASSERT_TRUE(!query(key(3)).move_as_ok());
    ASSERT_TRUE(state.used_root()->get_hash() == used_hash);
    ASSERT_TRUE(state.reserved_root()->get_hash() == reserved_hash);
    ASSERT_TRUE(state.owners_root()->get_hash() == owners_hash);
  };
  exercise([&](const td::Bits256& value) { return used.try_contains(value); }, key(1));
  exercise([&](const td::Bits256& value) { return state.try_is_used(value); }, key(1));
  exercise([&](const td::Bits256& value) { return state.try_is_reserved(value); }, key(2));
}

TEST(UnoNullifierState, EveryReadFailureLeavesSourceUnchanged) {
  const auto original = NullifierState{}.with_used({key(1)}).move_as_ok()
                            .reserve(key(10), {key(0), key(2)}).move_as_ok();
  const auto used_hash = original.used_root()->get_hash();
  const auto reserved_hash = original.reserved_root()->get_hash();
  const auto owners_hash = original.owners_root()->get_hash();
  class Loads final : public vm::VmStateInterface {
   public:
    unsigned calls = 0;
    unsigned fail_at = std::numeric_limits<unsigned>::max();
    unsigned kind = 0;
    void register_cell_load(const vm::CellHash&) override {
      if (calls++ == fail_at) {
        if (kind == 1) throw vm::VmError{vm::Excno::cell_und};
        if (kind == 2) throw vm::VmVirtError{1};
        throw vm::VmNoGas{};
      }
    }
  } loads;
  auto exercise = [&](auto operation) {
    loads.calls = 0;
    loads.fail_at = std::numeric_limits<unsigned>::max();
    unsigned total = 0;
    {
      vm::VmStateInterface::Guard guard(&loads);
      ASSERT_TRUE(operation().is_ok());
      total = loads.calls;
    }
    ASSERT_TRUE(total > 1);
    for (unsigned index = 0; index < total; ++index) {
      loads.calls = 0;
      loads.fail_at = index;
      {
        vm::VmStateInterface::Guard guard(&loads);
        ASSERT_TRUE(operation().is_error());
        ASSERT_EQ(loads.calls, index + 1);
      }
      ASSERT_TRUE(original.used_root()->get_hash() == used_hash);
      ASSERT_TRUE(original.reserved_root()->get_hash() == reserved_hash);
      ASSERT_TRUE(original.owners_root()->get_hash() == owners_hash);
      ASSERT_TRUE(original.is_used(key(1)));
      ASSERT_TRUE(!original.is_used(key(3)));
      ASSERT_TRUE(original.is_reserved(key(0)));
      ASSERT_TRUE(original.is_reserved(key(2)));
    }
    // A failed attempt must not poison subsequent execution or owner status.
    ASSERT_TRUE(operation().is_ok());
  };
  for (unsigned kind = 0; kind < 3; ++kind) {
    loads.kind = kind;
    exercise([&] { return original.with_used({key(3), key(4)}); });
    exercise([&] { return original.reserve(key(11), {key(3), key(4)}); });
    exercise([&] { return original.paid(key(10)); });
    exercise([&] { return original.refund(key(10)); });
  }
}

TEST(UnoNullifierState, RestoreJointStateAndContinue) {
  ASSERT_TRUE(restore(NullifierState{}, {0, 0, 0, 0}).is_ok());
  auto pending = NullifierState{}.with_used({key(1)}).move_as_ok()
                     .reserve(key(10), {key(0), key(2)}).move_as_ok()
                     .reserve(key(11), {key(3)}).move_as_ok();
  ASSERT_TRUE(restore(pending, {0, 3, 2, 3}).is_error());
  ASSERT_TRUE(restore(pending, {1, 2, 2, 3}).is_error());
  ASSERT_TRUE(restore(pending, {1, 3, 1, 3}).is_error());
  ASSERT_TRUE(restore(pending, {1, 3, 2, 2}).is_error());
  auto loaded = restore(pending, {1, 3, 2, 3}).move_as_ok();
  ASSERT_TRUE(loaded.used_root()->get_hash() == pending.used_root()->get_hash());
  ASSERT_TRUE(loaded.owners_root()->get_hash() == pending.owners_root()->get_hash());
  ASSERT_TRUE(loaded.with_used({key(2)}).is_error());
  ASSERT_TRUE(loaded.reserve(key(10), {key(4)}).is_error());
  auto refunded = loaded.refund(key(10)).move_as_ok();
  ASSERT_TRUE(refunded.used_root()->get_hash() == pending.refund(key(10)).move_as_ok().used_root()->get_hash());
  ASSERT_TRUE(loaded.reserved_root()->get_hash() == pending.reserved_root()->get_hash());

  // Historical paid manifests may overlap keys later spent or reserved by a
  // different owner. They are tombstones, not ongoing locks on those keys.
  auto mixed = pending.paid(key(10)).move_as_ok().with_used({key(0)}).move_as_ok()
                   .reserve(key(12), {key(2)}).move_as_ok().refund(key(11)).move_as_ok();
  auto resumed = restore(mixed).move_as_ok();
  for (auto owner : {key(10), key(11)}) {
    ASSERT_TRUE(resumed.paid(owner).is_error());
    ASSERT_TRUE(resumed.refund(owner).is_error());
    ASSERT_TRUE(resumed.reserve(owner, {key(5)}).is_error());
  }
  auto next = resumed.refund(key(12)).move_as_ok();
  ASSERT_TRUE(next.reserved_root().is_null());
  ASSERT_TRUE(next.used_root()->get_hash() == mixed.refund(key(12)).move_as_ok().used_root()->get_hash());
  ASSERT_TRUE(next.owners_root()->get_hash() == mixed.refund(key(12)).move_as_ok().owners_root()->get_hash());
  ASSERT_TRUE(restore(next).is_ok());
}

TEST(UnoNullifierState, RejectInconsistentRoots) {
  auto pending = NullifierState{}.reserve(key(10), {key(2)}).move_as_ok();
  auto load = [&](td::Ref<vm::Cell> used, td::Ref<vm::Cell> reserved, td::Ref<vm::Cell> owners) {
    return NullifierState::from_roots(used, reserved, owners, {20, 20, 20, 20});
  };
  ASSERT_TRUE(load({}, {}, pending.owners_root()).is_error());
  ASSERT_TRUE(load({}, pending.reserved_root(), {}).is_error());
  auto spent = UsedNullifiers{}.with_used({key(2)}).move_as_ok();
  ASSERT_TRUE(load(spent.root(), pending.reserved_root(), pending.owners_root()).is_error());

  vm::Dictionary reserved(pending.reserved_root(), 256);
  vm::CellBuilder binding;
  binding.store_bits(key(10).bits(), 256);
  ASSERT_TRUE(reserved.set_builder(key(3), binding));
  ASSERT_TRUE(load({}, reserved.get_root_cell(), pending.owners_root()).is_error());
  reserved = vm::Dictionary(pending.reserved_root(), 256);
  vm::CellBuilder wrong;
  wrong.store_bits(key(11).bits(), 256);
  ASSERT_TRUE(reserved.set_builder(key(2), wrong));
  ASSERT_TRUE(load({}, reserved.get_root_cell(), pending.owners_root()).is_error());

  vm::Dictionary duplicate_claims(pending.owners_root(), 256);
  auto claimed = duplicate_claims.lookup(key(10));
  vm::CellBuilder duplicate_record;
  duplicate_record.store_long(0, 2).store_ref(claimed->prefetch_ref());
  ASSERT_TRUE(duplicate_claims.set_builder(key(11), duplicate_record));
  ASSERT_TRUE(load({}, pending.reserved_root(), duplicate_claims.get_root_cell()).is_error());

  auto refunded = pending.refund(key(10)).move_as_ok();
  ASSERT_TRUE(load({}, {}, refunded.owners_root()).is_error());
  ASSERT_TRUE(load(refunded.used_root(), {}, refunded.owners_root()).is_ok());
  auto paid = pending.paid(key(10)).move_as_ok();
  ASSERT_TRUE(load({}, pending.reserved_root(), paid.owners_root()).is_error());
  ASSERT_TRUE(load({}, {}, paid.owners_root()).is_ok());

  vm::Dictionary owners(pending.owners_root(), 256);
  vm::Dictionary manifest(256);
  vm::CellBuilder marker;
  ASSERT_TRUE(manifest.set_builder(key(2), marker));
  vm::CellBuilder unknown;
  unknown.store_long(3, 2).store_ref(manifest.get_root_cell());
  ASSERT_TRUE(owners.set_builder(key(10), unknown));
  ASSERT_TRUE(load({}, pending.reserved_root(), owners.get_root_cell()).is_error());
  vm::CellBuilder extra;
  extra.store_bits(key(10).bits(), 256).store_long(0, 1);
  ASSERT_TRUE(reserved.set_builder(key(2), extra));
  ASSERT_TRUE(load({}, reserved.get_root_cell(), pending.owners_root()).is_error());
  vm::CellBuilder nonempty;
  nonempty.store_long(0, 1);
  ASSERT_TRUE(manifest.set_builder(key(2), nonempty));
  vm::CellBuilder malformed_manifest;
  malformed_manifest.store_long(0, 2).store_ref(manifest.get_root_cell());
  ASSERT_TRUE(owners.set_builder(key(10), malformed_manifest));
  ASSERT_TRUE(load({}, pending.reserved_root(), owners.get_root_cell()).is_error());
}

TEST(UnoNullifierState, ReservationConflictAndAtomicity) {
  NullifierState empty;
  auto used = empty.with_used({key(1)}).move_as_ok();
  ASSERT_TRUE(used.reserve(key(10), {key(2), key(1)}).is_error());
  ASSERT_TRUE(used.reserve(key(10), {key(2), key(2)}).is_error());
  ASSERT_TRUE(used.reserve(key(10), {}).is_error());
  ASSERT_TRUE(used.owners_root().is_null());
  ASSERT_TRUE(used.reserved_root().is_null());
  auto pending = used.reserve(key(10), {key(2), key(0)}).move_as_ok();
  ASSERT_TRUE(pending.is_reserved(key(0)));
  ASSERT_TRUE(pending.is_reserved(key(2)));
  ASSERT_TRUE(!pending.is_used(key(2)));
  ASSERT_TRUE(pending.with_used({key(3), key(2)}).is_error());
  ASSERT_TRUE(!pending.is_used(key(3)));
  ASSERT_TRUE(pending.reserve(key(11), {key(3), key(2)}).is_error());
  ASSERT_TRUE(!pending.is_reserved(key(3)));
  ASSERT_TRUE(pending.reserve(key(10), {key(4)}).is_error());
  auto other = pending.reserve(key(11), {key(4)}).move_as_ok();
  ASSERT_TRUE(other.is_reserved(key(4)));
  ASSERT_TRUE(other.is_reserved(key(2)));
  auto reversed = used.reserve(key(11), {key(4)}).move_as_ok().reserve(key(10), {key(0), key(2)}).move_as_ok();
  ASSERT_TRUE(reversed.reserved_root()->get_hash() == other.reserved_root()->get_hash());
  ASSERT_TRUE(reversed.owners_root()->get_hash() == other.owners_root()->get_hash());
}

TEST(UnoNullifierState, CompleteRefundAndPaidRelease) {
  auto pending = NullifierState{}
                     .with_used({key(1)})
                     .move_as_ok()
                     .reserve(key(10), {key(0), key(2)})
                     .move_as_ok()
                     .reserve(key(11), {key(3)})
                     .move_as_ok();
  ASSERT_TRUE(pending.refund(key(12)).is_error());
  ASSERT_TRUE(pending.paid(key(12)).is_error());
  auto refunded = pending.refund(key(10)).move_as_ok();
  for (auto n : {0, 1, 2}) {
    ASSERT_TRUE(refunded.is_used(key(n)));
    ASSERT_TRUE(!refunded.is_reserved(key(n)));
    ASSERT_TRUE(refunded.with_used({key(n)}).is_error());
  }
  ASSERT_TRUE(refunded.is_reserved(key(3)));
  ASSERT_TRUE(!refunded.is_used(key(3)));
  ASSERT_TRUE(refunded.refund(key(10)).is_error());
  ASSERT_TRUE(refunded.paid(key(10)).is_error());
  ASSERT_TRUE(refunded.reserve(key(10), {key(4)}).is_error());
  ASSERT_TRUE(pending.is_reserved(key(2)));
  ASSERT_TRUE(!pending.is_used(key(2)));
  auto paid = pending.paid(key(10)).move_as_ok();
  ASSERT_TRUE(paid.is_used(key(1)));
  for (auto n : {0, 2}) {
    ASSERT_TRUE(!paid.is_used(key(n)));
    ASSERT_TRUE(!paid.is_reserved(key(n)));
  }
  ASSERT_TRUE(paid.is_reserved(key(3)));
  ASSERT_TRUE(paid.with_used({key(0), key(2)}).is_ok());
  ASSERT_TRUE(paid.reserve(key(12), {key(0), key(2)}).is_ok());
  ASSERT_TRUE(paid.reserve(key(10), {key(4)}).is_error());
  ASSERT_TRUE(paid.refund(key(10)).is_error());
  ASSERT_TRUE(paid.paid(key(10)).is_error());
  ASSERT_TRUE(paid.owners_root()->get_hash() != refunded.owners_root()->get_hash());
  auto complete = refunded.paid(key(11)).move_as_ok();
  ASSERT_TRUE(complete.reserved_root().is_null());
  ASSERT_TRUE(complete.owners_root().not_null());
}
