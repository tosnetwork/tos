#include "uno/core/note-state.h"
#include "td/utils/tests.h"
#include "vm/boc.h"
#include "vm/vmstate.h"

using namespace uno_workchain;
namespace {
td::Bits256 key(unsigned n) {
  auto result = td::Bits256::zero();
  result.as_slice()[31] = static_cast<char>(n);
  return result;
}
NoteTreeState::Commitment leaf(unsigned n) {
  NoteTreeState::Commitment result{};
  result[0] = static_cast<td::uint8>(n);
  return result;
}
NoteState initial(NullifierState nullifiers = {}) {
  auto tree = NoteTreeState::empty().move_as_ok();
  auto anchors = AnchorWindow::genesis(3, 3, tree.root()).move_as_ok();
  return NoteState::assemble(std::move(tree), std::move(nullifiers), std::move(anchors)).move_as_ok();
}
NoteState restore(const NoteState& state) {
  auto boc = vm::std_boc_serialize(state.to_cell().move_as_ok()).move_as_ok();
  return NoteState::from_cell(vm::std_boc_deserialize(boc.as_slice()).move_as_ok(), 3, 3,
                              {100, 100, 100, 100}).move_as_ok();
}
}

TEST(UnoNoteState, AtomicLateFailureAndReplay) {
  const auto source = initial();
  const auto hash = source.to_cell().move_as_ok()->get_hash();
  NoteState::SpendEffects first{source.tree().root(), {{key(1), leaf(3)}}};
  auto duplicate = first;
  duplicate.actions = {{key(2), leaf(4)}, {key(1), leaf(5)}};
  ASSERT_TRUE(source.apply_spend_effects(1, {first, duplicate}, {2, 2, 3}).is_error());
  ASSERT_TRUE(source.to_cell().move_as_ok()->get_hash() == hash);
  ASSERT_TRUE(!source.nullifiers().is_used(key(2)));
  auto invalid = leaf(0);
  invalid.fill(255);
  auto malformed = first;
  malformed.actions = {{key(2), invalid}};
  // Both dictionaries are staged successfully before the tree ABI rejects.
  ASSERT_TRUE(source.apply_spend_effects(1, {first, malformed}, {2, 2, 2}).is_error());
  ASSERT_TRUE(source.to_cell().move_as_ok()->get_hash() == hash);
  malformed.actions = {{key(2), leaf(4)}};
  auto next = source.apply_spend_effects(1, {first, malformed}, {2, 2, 2}).move_as_ok();
  ASSERT_EQ(next.tree().next_position(), 2u);
  ASSERT_EQ(next.nullifiers().used_count(), 2u);
  ASSERT_EQ(next.anchors().size(), 2u);
  ASSERT_TRUE(next.nullifiers().is_used(key(1)) && next.nullifiers().is_used(key(2)));
  ASSERT_TRUE(next.tree().root() == next.anchors().latest());
  auto reloaded = restore(next);
  ASSERT_TRUE(reloaded.to_cell().move_as_ok()->get_hash() == next.to_cell().move_as_ok()->get_hash());
  ASSERT_TRUE(reloaded.apply_spend_effects(2, {first}, {1, 1, 1}).is_error());
  first.actions = {{key(3), leaf(5)}};
  auto continued = reloaded.apply_spend_effects(2, {first}, {1, 1, 1}).move_as_ok();
  auto replayed = next.apply_spend_effects(2, {first}, {1, 1, 1}).move_as_ok();
  ASSERT_TRUE(continued.to_cell().move_as_ok()->get_hash() == replayed.to_cell().move_as_ok()->get_hash());
}

TEST(UnoNoteState, FrozenAnchorsAndCheapLimits) {
  auto source = initial();
  NoteState::SpendEffects first{source.tree().root(), {{key(1), leaf(3)}}};
  auto intermediate = source.tree().append({leaf(3)}, 0, 1).move_as_ok().root();
  ASSERT_TRUE(intermediate != source.tree().root());
  NoteState::SpendEffects second{intermediate, {{key(2), leaf(4)}}};
  ASSERT_TRUE(source.apply_spend_effects(1, {first, second}, {2, 1, 2}).is_error());
  auto next = source.apply_spend_effects(1, {first}, {1, 1, 1}).move_as_ok();
  ASSERT_TRUE(next.apply_spend_effects(2, {second}, {1, 1, 1}).is_ok());
  ASSERT_TRUE(source.apply_spend_effects(0, {first}, {1, 1, 1}).is_error());
  ASSERT_TRUE(source.apply_spend_effects(2, {first}, {1, 1, 1}).is_error());
  ASSERT_TRUE(source.apply_spend_effects(1, {first}, {0, 1, 1}).is_error());
  ASSERT_TRUE(source.apply_spend_effects(1, {first}, {1, 0, 1}).is_error());
  ASSERT_TRUE(source.apply_spend_effects(1, {first}, {1, 1, 0}).is_error());
  second.anchor = source.tree().root();
  ASSERT_TRUE(source.apply_spend_effects(1, {first, second}, {2, 1, 1}).is_error());
  first.actions.clear();
  ASSERT_TRUE(source.apply_spend_effects(1, {first}, {1, 1, 1}).is_error());
  // An entirely empty block is valid, unlike an empty bundle.
  auto idle = next.apply_spend_effects(2, {}, {}).move_as_ok().apply_spend_effects(3, {}, {}).move_as_ok();
  ASSERT_TRUE(idle.tree().root() == next.tree().root());
  ASSERT_TRUE(!idle.anchors().contains(source.tree().root()));
  ASSERT_EQ(idle.tree().next_position(), 1u);
}

TEST(UnoNoteState, ReservationsAndCrossFieldRestore) {
  auto reserved = NullifierState{}.reserve(key(10), {key(1), key(2)}).move_as_ok();
  ASSERT_EQ(reserved.reserved_count(2).move_as_ok(), 2u);
  ASSERT_TRUE(reserved.reserved_count(1).is_error());
  ASSERT_EQ(reserved.paid(key(10)).move_as_ok().reserved_count(0).move_as_ok(), 0u);
  ASSERT_EQ(reserved.refund(key(10)).move_as_ok().reserved_count(0).move_as_ok(), 0u);
  auto source = restore(initial(reserved));
  ASSERT_EQ(source.reserved_leaves(), 2u);
  NoteState::SpendEffects first{source.tree().root(), {{key(1), leaf(3)}}};
  ASSERT_TRUE(source.apply_spend_effects(1, {first}, {1, 1, 1}).is_error());
  first.actions = {{key(3), leaf(3)}};
  auto next = source.apply_spend_effects(1, {first}, {1, 1, 1}).move_as_ok();
  ASSERT_EQ(next.reserved_leaves(), 2u);
  ASSERT_TRUE(next.nullifiers().is_reserved(key(1)));
  ASSERT_TRUE(NoteState::assemble(next.tree(), next.nullifiers(), source.anchors()).is_error());
  ASSERT_TRUE(NoteState::assemble(next.tree(), source.nullifiers(), next.anchors()).is_error());
  auto source_cell = source.to_cell().move_as_ok();
  ASSERT_TRUE(NoteState::from_cell({}, 3, 3, {100, 100, 100, 100}).is_error());
  auto library = vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true);
  class Libraries final : public vm::VmStateInterface {
   public:
    unsigned calls = 0;
    td::Ref<vm::Cell> load_library(td::ConstBitPtr) override { ++calls; return {}; }
  } libraries;
  {
    vm::VmStateInterface::Guard guard(&libraries);
    ASSERT_TRUE(NoteState::from_cell(library, 3, 3, {100, 100, 100, 100}).is_error());
    ASSERT_EQ(libraries.calls, 0u);
  }
  auto slices = vm::load_cell_slice(source_cell);
  auto tree = slices.fetch_ref();
  auto anchors = slices.fetch_ref();
  auto dictionaries = slices.fetch_ref();
  auto trailing_header = vm::CellBuilder().store_long(0x554e5330, 32).store_long(0, 1)
      .store_ref(tree).store_ref(anchors).store_ref(dictionaries).finalize();
  ASSERT_TRUE(NoteState::from_cell(trailing_header, 3, 3, {100, 100, 100, 100}).is_error());
  auto mismatched = vm::CellBuilder().store_long(0x554e5330, 32)
      .store_ref(next.tree().to_cell().move_as_ok()).store_ref(anchors).store_ref(dictionaries).finalize();
  ASSERT_TRUE(NoteState::from_cell(mismatched, 3, 3, {100, 100, 100, 100}).is_error());
  ASSERT_TRUE(NoteState::from_cell(source_cell, 3, 3, {100, 1, 100, 100}).is_error());
  auto extra = vm::CellBuilder().store_long(0, 3).store_ref(tree).finalize();
  auto malformed = vm::CellBuilder().store_long(0x554e5330, 32)
      .store_ref(tree).store_ref(anchors).store_ref(extra).finalize();
  ASSERT_TRUE(NoteState::from_cell(malformed, 3, 3, {100, 100, 100, 100}).is_error());
}

TEST(UnoNoteState, EveryLoadFailureLeavesSourceUnchanged) {
  auto source = initial(NullifierState{}.reserve(key(10), {key(8), key(9)}).move_as_ok());
  NoteState::SpendEffects first{source.tree().root(), {{key(1), leaf(3)}, {key(2), leaf(4)}}};
  source = source.apply_spend_effects(1, {first}, {1, 2, 2}).move_as_ok();
  const auto cell = source.to_cell().move_as_ok();
  first.actions = {{key(3), leaf(5)}};
  class Loads final : public vm::VmStateInterface {
   public:
    unsigned calls = 0, fail_at = UINT_MAX, kind = 0;
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
    loads.fail_at = UINT_MAX;
    unsigned total = 0;
    {
      vm::VmStateInterface::Guard guard(&loads);
      ASSERT_TRUE(operation().is_ok());
      total = loads.calls;
    }
    ASSERT_TRUE(total > 0);
    for (unsigned kind = 0; kind < 3; ++kind) {
      loads.kind = kind;
      for (unsigned i = 0; i < total; ++i) {
        loads.calls = 0;
        loads.fail_at = i;
        {
          vm::VmStateInterface::Guard guard(&loads);
          ASSERT_TRUE(operation().is_error());
          ASSERT_EQ(loads.calls, i + 1);
        }
        ASSERT_TRUE(source.to_cell().move_as_ok()->get_hash() == cell->get_hash());
      }
    }
  };
  exercise([&] { return NoteState::from_cell(cell, 3, 3, {100, 100, 100, 100}); });
  exercise([&] { return source.apply_spend_effects(2, {first}, {1, 1, 1}); });
  ASSERT_TRUE(!source.nullifiers().is_used(key(3)));
  ASSERT_TRUE(source.apply_spend_effects(2, {first}, {1, 1, 1}).is_ok());
}
