#include "uno/core/note-tree-state.h"
#include "uno/core/anchor-window.h"
#include "td/utils/tests.h"
#include "vm/boc.h"
#include "vm/vmstate.h"

using uno_workchain::NoteTreeState;

TEST(UnoTreeCell, OnlyBlockEndRootEntersNextAnchorWindow) {
  auto tree = NoteTreeState::empty().move_as_ok();
  const auto prestate = uno_workchain::AnchorWindow::genesis(3, 3, tree.root()).move_as_ok();
  NoteTreeState::Commitment first{}, second{};
  first[0] = 1;
  second[0] = 3;
  tree = tree.append({first}, 0, 1).move_as_ok();
  const auto intermediate = tree.root();
  ASSERT_TRUE(!prestate.contains(intermediate));
  tree = tree.append({second}, 0, 1).move_as_ok();
  ASSERT_TRUE(intermediate != tree.root());
  ASSERT_TRUE(!prestate.contains(tree.root()));
  auto poststate = prestate.finish_block(1, tree.root()).move_as_ok();
  ASSERT_TRUE(poststate.contains(tree.root()));
  ASSERT_TRUE(!poststate.contains(intermediate));
  ASSERT_EQ(poststate.size(), 2u);
  auto restored = uno_workchain::AnchorWindow::from_cell(poststate.to_cell().move_as_ok(), 3, 3).move_as_ok();
  ASSERT_TRUE(restored.latest() == NoteTreeState::from_cell(tree.to_cell().move_as_ok()).move_as_ok().root());
  // Idle blocks retain the same tree root but still consume window entries.
  restored = restored.finish_block(2, tree.root()).move_as_ok().finish_block(3, tree.root()).move_as_ok();
  ASSERT_TRUE(!restored.contains(prestate.latest()));
}

namespace {
NoteTreeState::Commitment leaf(unsigned value) {
  NoteTreeState::Commitment result{};
  result[0] = static_cast<td::uint8>(value);
  return result;
}
td::Ref<vm::Cell> header(unsigned count, td::Ref<vm::Cell> tail, std::uint64_t position = 2,
                         std::uint32_t tag = 0x554e4630) {
  vm::CellBuilder value;
  value.store_long(tag, 32).store_long(position, 64).store_bytes(leaf(1).data(), 32).store_long(count, 6);
  if (tail.not_null()) value.store_ref(tail);
  return value.finalize();
}
}

TEST(UnoTreeCell, RestoreAndContinue) {
  auto empty = NoteTreeState::empty().move_as_ok();
  auto current = empty;
  std::vector<NoteTreeState::Commitment> all;
  for (unsigned index = 1; index <= 65; ++index) {
    all.push_back(leaf(index));
    current = current.append({leaf(index)}, 0, 1).move_as_ok();
    auto cell = current.to_cell().move_as_ok();
    auto boc = vm::std_boc_serialize(cell).move_as_ok();
    auto restored = NoteTreeState::from_cell(vm::std_boc_deserialize(boc.as_slice()).move_as_ok()).move_as_ok();
    ASSERT_EQ(restored.next_position(), index);
    ASSERT_TRUE(restored.root() == current.root());
    ASSERT_TRUE(restored.to_cell().move_as_ok()->get_hash() == cell->get_hash());
    current = std::move(restored);
  }
  ASSERT_TRUE(empty.append(all, 0, all.size()).move_as_ok().root() == current.root());
  ASSERT_EQ(empty.next_position(), 0u);
  auto before = current.to_cell().move_as_ok()->get_hash();
  auto invalid = leaf(0);
  invalid.fill(255);
  ASSERT_TRUE(current.append({leaf(99), invalid}, 0, 2).is_error());
  ASSERT_TRUE(current.append({leaf(99)}, 0, 0).is_error());
  ASSERT_TRUE(current.append({leaf(99)}, (std::uint64_t{1} << 32) - 65, 1).is_error());
  ASSERT_TRUE(current.to_cell().move_as_ok()->get_hash() == before);
  ASSERT_TRUE(current.append({leaf(99)}, 0, 1).is_ok());
  ASSERT_TRUE(NoteTreeState::from_cell(empty.to_cell().move_as_ok()).move_as_ok().root() == empty.root());
}

TEST(UnoTreeCell, RejectNonCanonicalCells) {
  auto node = vm::CellBuilder().store_bytes(leaf(2).data(), 32).finalize();
  ASSERT_TRUE(NoteTreeState::from_cell(header(1, node)).is_ok());
  ASSERT_TRUE(NoteTreeState::from_cell({}).is_error());
  ASSERT_TRUE(NoteTreeState::from_cell(header(1, node, 2, 0)).is_error());
  ASSERT_TRUE(NoteTreeState::from_cell(header(1, {})).is_error());
  ASSERT_TRUE(NoteTreeState::from_cell(header(0, node)).is_error());
  ASSERT_TRUE(NoteTreeState::from_cell(header(33, node)).is_error());
  ASSERT_TRUE(NoteTreeState::from_cell(header(1, node, 1)).is_error());
  ASSERT_TRUE(NoteTreeState::from_cell(header(0, {}, 0)).is_error());
  auto extra_bit = vm::CellBuilder().append_cellslice(vm::load_cell_slice(header(1, node))).store_long(0, 1).finalize();
  ASSERT_TRUE(NoteTreeState::from_cell(extra_bit).is_error());
  auto extra_ref = vm::CellBuilder().store_bytes(leaf(2).data(), 32).store_ref(node).finalize();
  ASSERT_TRUE(NoteTreeState::from_cell(header(1, extra_ref)).is_error());
  auto short_node = vm::CellBuilder().store_zeroes(255).finalize();
  ASSERT_TRUE(NoteTreeState::from_cell(header(1, short_node)).is_error());
  auto library = vm::CellBuilder().store_long(2, 8).store_bits(node->get_hash().bits(), 256).finalize(true);
  class Libraries final : public vm::VmStateInterface {
   public:
    unsigned calls = 0;
    td::Ref<vm::Cell> load_library(td::ConstBitPtr) override {
      ++calls;
      return {};
    }
  } libraries;
  vm::VmStateInterface::Guard guard(&libraries);
  ASSERT_TRUE(NoteTreeState::from_cell(library).is_error());
  ASSERT_TRUE(NoteTreeState::from_cell(header(1, library)).is_error());
  ASSERT_EQ(libraries.calls, 0u);
}

TEST(UnoTreeCell, ReadBudgetFailure) {
  auto tree = NoteTreeState::empty().move_as_ok().append({leaf(1), leaf(2)}, 0, 2).move_as_ok();
  auto cell = tree.to_cell().move_as_ok();
  class Loads final : public vm::VmStateInterface {
   public:
    unsigned calls = 0, fail_at = 2;
    void register_cell_load(const vm::CellHash&) override {
      if (calls++ == fail_at) throw vm::VmNoGas{};
    }
  } loads;
  {
    vm::VmStateInterface::Guard guard(&loads);
    ASSERT_TRUE(NoteTreeState::from_cell(cell).is_ok());
    ASSERT_EQ(loads.calls, 2u);
    for (unsigned index = 0; index < 2; ++index) {
      loads.calls = 0;
      loads.fail_at = index;
      ASSERT_TRUE(NoteTreeState::from_cell(cell).is_error());
      ASSERT_EQ(loads.calls, index + 1);
    }
  }
  ASSERT_TRUE(NoteTreeState::from_cell(cell).move_as_ok().root() == tree.root());
}

TEST(UnoTreeCell, FullFrontierUsesAtMost33Reads) {
  td::Ref<vm::Cell> tail;
  for (unsigned i = 0; i < 32; ++i) {
    vm::CellBuilder node;
    node.store_zeroes(256);
    if (tail.not_null()) node.store_ref(tail);
    tail = node.finalize();
  }
  auto cell = header(32, tail, std::uint64_t{1} << 32);
  class Loads final : public vm::VmStateInterface {
   public:
    unsigned calls = 0;
    void register_cell_load(const vm::CellHash&) override { ++calls; }
  } loads;
  vm::VmStateInterface::Guard guard(&loads);
  auto full = NoteTreeState::from_cell(cell).move_as_ok();
  ASSERT_EQ(loads.calls, 33u);
  ASSERT_EQ(full.next_position(), std::uint64_t{1} << 32);
  ASSERT_TRUE(full.append({leaf(1)}, 0, 1).is_error());
  ASSERT_TRUE(full.to_cell().move_as_ok()->get_hash() == cell->get_hash());
  loads.calls = 0;
  ASSERT_TRUE(NoteTreeState::from_cell(header(33, tail)).is_error());
  ASSERT_EQ(loads.calls, 1u);
}
