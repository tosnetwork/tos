#include "uno/core/used-nullifiers.h"
#include "td/utils/tests.h"
#include "vm/boc.h"
#include "vm/vmstate.h"

using namespace uno_workchain;

TEST(UnoUsedNullifiers, ForkRequiresExactlyTwoRefsAndNoBits) {
  // Empty root label, then two 255-bit all-zero suffix leaves.
  auto leaf = vm::CellBuilder().store_long(3, 2).store_long(0, 1).store_long(255, 8).finalize();
  auto valid = vm::CellBuilder().store_long(0, 2).store_ref(leaf).store_ref(leaf).finalize();
  auto restored = UsedNullifiers::from_root(valid, 2).move_as_ok();
  ASSERT_EQ(restored.size(), 2u);
  auto high = td::Bits256::zero();
  high.as_slice()[0] = static_cast<char>(128);
  ASSERT_TRUE(restored.contains(td::Bits256::zero()));
  ASSERT_TRUE(restored.contains(high));
  for (unsigned refs : {0u, 1u, 3u}) {
    vm::CellBuilder fork;
    fork.store_long(0, 2);
    for (unsigned i = 0; i < refs; ++i) fork.store_ref(leaf);
    ASSERT_TRUE(UsedNullifiers::from_root(fork.finalize(), 4).is_error());
  }
  auto extra_bit = vm::CellBuilder().store_long(0, 2).store_long(0, 1).store_ref(leaf).store_ref(leaf).finalize();
  ASSERT_TRUE(UsedNullifiers::from_root(extra_bit, 2).is_error());
}

TEST(UnoUsedNullifiers, UpdateReturnsBudgetFailure) {
  auto original = UsedNullifiers{}.with_used({td::Bits256::zero()}).move_as_ok();
  auto fresh = td::Bits256::zero();
  fresh.as_slice()[31] = 1;
  const auto old_hash = original.root()->get_hash();
  class Loads final : public vm::VmStateInterface {
   public:
    unsigned calls = 0;
    void register_cell_load(const vm::CellHash&) override {
      ++calls;
      throw vm::VmNoGas{};
    }
  } loads;
  {
    vm::VmStateInterface::Guard guard(&loads);
    ASSERT_TRUE(original.with_used({fresh}).is_error());
    ASSERT_EQ(loads.calls, 1u);
  }
  ASSERT_TRUE(original.root()->get_hash() == old_hash);
  ASSERT_TRUE(!original.contains(fresh));
  ASSERT_TRUE(original.with_used({fresh}).move_as_ok().contains(fresh));
}

TEST(UnoUsedNullifiers, RestoreAndContinue) {
  auto zero = td::Bits256::zero();
  auto one = zero;
  one.as_slice()[31] = 1;
  auto two = zero;
  two.as_slice()[31] = 2;
  auto original = UsedNullifiers{}.with_used({zero, one}).move_as_ok();
  auto bytes = vm::std_boc_serialize(original.root()).move_as_ok();
  auto persisted = vm::std_boc_deserialize(bytes.as_slice()).move_as_ok();
  ASSERT_TRUE(UsedNullifiers::from_root(persisted, 0).is_error());
  ASSERT_TRUE(UsedNullifiers::from_root(persisted, 1).is_error());
  auto restored = UsedNullifiers::from_root(persisted, 2).move_as_ok();
  ASSERT_TRUE(restored.root()->get_hash() == original.root()->get_hash());
  ASSERT_TRUE(restored.contains(zero));
  ASSERT_TRUE(restored.contains(one));
  ASSERT_TRUE(!restored.contains(two));
  ASSERT_TRUE(restored.with_used({two, one}).is_error());
  ASSERT_TRUE(!restored.contains(two));
  auto continued = restored.with_used({two}).move_as_ok();
  ASSERT_TRUE(continued.root()->get_hash() == original.with_used({two}).move_as_ok().root()->get_hash());
  ASSERT_TRUE(restored.root()->get_hash() == persisted->get_hash());
  ASSERT_TRUE(UsedNullifiers::from_root({}, 0).move_as_ok().root().is_null());
}

TEST(UnoUsedNullifiers, RejectMalformedPersistedState) {
  const auto key = td::Bits256::zero();
  vm::Dictionary dictionary(256);
  vm::CellBuilder bit_marker;
  bit_marker.store_long(0, 1);
  ASSERT_TRUE(dictionary.set_builder(key, bit_marker));
  ASSERT_TRUE(UsedNullifiers::from_root(dictionary.get_root_cell(), 1).is_error());
  vm::CellBuilder ref_marker, empty;
  ref_marker.store_ref(empty.finalize());
  ASSERT_TRUE(dictionary.set_builder(key, ref_marker));
  ASSERT_TRUE(UsedNullifiers::from_root(dictionary.get_root_cell(), 1).is_error());
  ASSERT_TRUE(UsedNullifiers::from_root(vm::CellBuilder{}.finalize(), 1).is_error());
  // An empty label with only one child is a malformed fork, not a one-key set.
  vm::CellBuilder fork;
  fork.store_long(0, 2).store_ref(dictionary.get_root_cell());
  ASSERT_TRUE(UsedNullifiers::from_root(fork.finalize(), 10).is_error());
  vm::CellBuilder marker;
  ASSERT_TRUE(dictionary.set_builder(key, marker));
  ASSERT_TRUE(UsedNullifiers::from_root(dictionary.get_root_cell(), 1).is_ok());
  auto pruned = vm::CellBuilder::do_create_pruned_branch(dictionary.get_root_cell(), 1, 0);
  ASSERT_TRUE(UsedNullifiers::from_root(pruned, 1).is_error());
}

TEST(UnoUsedNullifiers, NeverResolvesLibraryReferences) {
  const auto zero = td::Bits256::zero();
  auto high = zero;
  high.as_slice()[0] = static_cast<char>(128);
  auto state = UsedNullifiers{}.with_used({zero, high}).move_as_ok();
  auto fork = vm::load_cell_slice(state.root());
  class Libraries final : public vm::VmStateInterface {
   public:
    td::Ref<vm::Cell> target;
    unsigned calls = 0;
    td::Ref<vm::Cell> load_library(td::ConstBitPtr) override {
      ++calls;
      return target;
    }
  } libraries;
  libraries.target = fork.prefetch_ref(0);
  vm::CellBuilder ref;
  auto library = ref.store_long(static_cast<unsigned>(vm::DataCell::SpecialType::Library), 8)
                     .store_bits(libraries.target->get_hash().bits(), 256).finalize(true);
  vm::CellBuilder parent;
  td::Ref<vm::Cell> nested = parent.store_bits(fork.data_bits(), fork.size()).store_ref(library)
                     .store_ref(fork.prefetch_ref(1)).finalize();
  vm::VmStateInterface::Guard guard(&libraries);
  ASSERT_TRUE(UsedNullifiers::from_root(nested, 2).is_error());
  ASSERT_EQ(libraries.calls, 0u);
  // Positive control: the generic dictionary really does resolve this node.
  vm::Dictionary generic(nested, 256);
  ASSERT_TRUE(generic.lookup(zero).not_null());
  ASSERT_EQ(libraries.calls, 1u);
  libraries.target = state.root();
  ASSERT_TRUE(UsedNullifiers::from_root(library, 2).is_error());
  ASSERT_EQ(libraries.calls, 1u);
}

TEST(UnoUsedNullifiers, BudgetBeforeLoadingAndExecutionErrors) {
  auto original = UsedNullifiers{}.with_used({td::Bits256::zero()}).move_as_ok();
  class Loads final : public vm::VmStateInterface {
   public:
    unsigned calls = 0;
    bool exhausted = false;
    void register_cell_load(const vm::CellHash&) override {
      ++calls;
      if (exhausted) throw vm::VmNoGas{};
    }
  } loads;
  vm::VmStateInterface::Guard guard(&loads);
  ASSERT_TRUE(UsedNullifiers::from_root(original.root(), 0).is_error());
  ASSERT_EQ(loads.calls, 0u);
  ASSERT_TRUE(UsedNullifiers::from_root(original.root(), 1).is_ok());
  ASSERT_EQ(loads.calls, 1u);
  loads.exhausted = true;
  ASSERT_TRUE(UsedNullifiers::from_root(original.root(), 1).is_error());
  ASSERT_EQ(loads.calls, 2u);
}

TEST(UnoUsedNullifiers, PermanentAndAtomic) {
  td::Bits256 zero = td::Bits256::zero();
  td::Bits256 one = zero;
  one.as_slice()[31] = 1;
  td::Bits256 high = zero;
  high.as_slice()[0] = static_cast<char>(128);
  UsedNullifiers empty;
  ASSERT_TRUE(empty.root().is_null());
  ASSERT_TRUE(!empty.contains(zero));
  auto first = empty.with_used({zero, one}).move_as_ok();
  ASSERT_TRUE(first.contains(zero));
  ASSERT_TRUE(first.contains(one));
  ASSERT_TRUE(!first.contains(high));
  ASSERT_TRUE(!empty.contains(zero));
  auto hash = first.root()->get_hash();
  ASSERT_TRUE(first.with_used({high, zero}).is_error());
  ASSERT_TRUE(!first.contains(high));
  ASSERT_TRUE(first.root()->get_hash() == hash);
  ASSERT_TRUE(empty.with_used({high, high}).is_error());
  ASSERT_TRUE(empty.root().is_null());
  auto second = first.with_used({high}).move_as_ok();
  ASSERT_TRUE(second.contains(zero));
  ASSERT_TRUE(second.contains(one));
  ASSERT_TRUE(second.contains(high));
  ASSERT_TRUE(second.with_used({one}).is_error());
  ASSERT_TRUE(second.with_used({}).move_as_ok().root()->get_hash() == second.root()->get_hash());
  auto reversed = empty.with_used({high, one, zero}).move_as_ok();
  ASSERT_TRUE(reversed.root()->get_hash() == second.root()->get_hash());
}
