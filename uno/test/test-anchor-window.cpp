#include "uno/core/anchor-window.h"
#include "td/utils/tests.h"
#include "vm/boc.h"
#include "vm/vmstate.h"

using uno_workchain::AnchorWindow;
namespace {
AnchorWindow::Root root(unsigned n) {
  AnchorWindow::Root value{};
  value[0] = static_cast<td::uint8>(n);
  return value;
}
td::Ref<vm::Cell> header(std::uint64_t height, unsigned count, td::Ref<vm::Cell> tail) {
  return vm::CellBuilder().store_long(0x554e4130, 32).store_long(height, 64)
      .store_long(count, 32).store_ref(tail).finalize();
}
}

TEST(UnoAnchorWindow, FrozenPrestateAndIdleAging) {
  const auto genesis = AnchorWindow::genesis(3, 3, root(0)).move_as_ok();
  ASSERT_TRUE(AnchorWindow::genesis(0, 3, root(0)).is_error());
  ASSERT_TRUE(AnchorWindow::genesis(4, 3, root(0)).is_error());
  auto state = genesis.finish_block(1, root(1)).move_as_ok();
  ASSERT_TRUE(!genesis.contains(root(1)));
  ASSERT_TRUE(state.contains(root(0)));
  ASSERT_TRUE(state.finish_block(1, root(2)).is_error());
  ASSERT_TRUE(state.finish_block(3, root(2)).is_error());
  state = state.finish_block(2, root(1)).move_as_ok();
  ASSERT_EQ(state.size(), 3u);
  ASSERT_TRUE(state.contains(root(0)));
  state = state.finish_block(3, root(1)).move_as_ok();
  ASSERT_EQ(state.size(), 3u);
  ASSERT_TRUE(!state.contains(root(0)));
  ASSERT_TRUE(genesis.contains(root(0)));
}

TEST(UnoAnchorWindow, RestoreAndContinue) {
  auto state = AnchorWindow::genesis(3, 3, root(0)).move_as_ok();
  for (unsigned i = 0; i < 12; ++i) {
    auto cell = state.to_cell().move_as_ok();
    auto boc = vm::std_boc_serialize(cell).move_as_ok();
    auto decoded = vm::std_boc_deserialize(boc.as_slice()).move_as_ok();
    auto restored = AnchorWindow::from_cell(decoded, 3, 3).move_as_ok();
    ASSERT_EQ(restored.height(), i);
    ASSERT_TRUE(restored.latest() == root(i));
    ASSERT_TRUE(restored.to_cell().move_as_ok()->get_hash() == cell->get_hash());
    for (unsigned k = 0; k <= i; ++k) ASSERT_EQ(restored.contains(root(k)), i - k < 3);
    state = restored.finish_block(i + 1, root(i + 1)).move_as_ok();
  }
}

TEST(UnoAnchorWindow, StrictShapeAndHeight) {
  const auto leaf = vm::CellBuilder().store_bytes(root(1).data(), 32).finalize();
  ASSERT_TRUE(AnchorWindow::from_cell(header(0, 1, leaf), 3, 3).is_ok());
  ASSERT_TRUE(AnchorWindow::from_cell({}, 3, 3).is_error());
  ASSERT_TRUE(AnchorWindow::from_cell(header(0, 1, leaf), 0, 3).is_error());
  ASSERT_TRUE(AnchorWindow::from_cell(header(0, 1, leaf), 4, 3).is_error());
  ASSERT_TRUE(AnchorWindow::from_cell(header(1, 1, leaf), 3, 3).is_error());
  ASSERT_TRUE(AnchorWindow::from_cell(header(0, 2, leaf), 3, 3).is_error());
  const auto trailing = vm::CellBuilder().store_bytes(root(1).data(), 32).store_long(0, 1).finalize();
  ASSERT_TRUE(AnchorWindow::from_cell(header(0, 1, trailing), 3, 3).is_error());
  const auto extra_ref = vm::CellBuilder().store_bytes(root(1).data(), 32).store_ref(leaf).finalize();
  ASSERT_TRUE(AnchorWindow::from_cell(header(0, 1, extra_ref), 3, 3).is_error());
  auto max = AnchorWindow::from_cell(header(std::numeric_limits<std::uint64_t>::max(), 1, leaf), 1, 1)
                 .move_as_ok();
  ASSERT_TRUE(max.finish_block(0, root(2)).is_error());
}

TEST(UnoAnchorWindow, NoImplicitResolutionAndBoundedLoads) {
  auto state = AnchorWindow::genesis(3, 3, root(0)).move_as_ok()
                   .finish_block(1, root(1)).move_as_ok();
  auto cell = state.to_cell().move_as_ok();
  auto library = vm::CellBuilder().store_long(2, 8).store_zeroes(256).finalize(true);
  class Loads final : public vm::VmStateInterface {
   public:
    unsigned calls = 0, libraries = 0;
    unsigned fail_at = 100, kind = 0;
    td::Ref<vm::Cell> load_library(td::ConstBitPtr) override { ++libraries; return {}; }
    void register_cell_load(const vm::CellHash&) override {
      if (calls++ == fail_at) {
        if (kind == 1) throw vm::VmError{vm::Excno::cell_und};
        if (kind == 2) throw vm::VmVirtError{1};
        throw vm::VmNoGas{};
      }
    }
  } loads;
  {
    vm::VmStateInterface::Guard guard(&loads);
    ASSERT_TRUE(AnchorWindow::from_cell(cell, 3, 3).is_ok());
    ASSERT_EQ(loads.calls, 3u);
    ASSERT_TRUE(AnchorWindow::from_cell(library, 3, 3).is_error());
    ASSERT_TRUE(AnchorWindow::from_cell(header(0, 1, library), 3, 3).is_error());
    ASSERT_EQ(loads.libraries, 0u);
    loads.calls = 0;
    ASSERT_TRUE(AnchorWindow::from_cell(header(0, 1000, library), 3, 3).is_error());
    ASSERT_EQ(loads.calls, 1u);
    for (unsigned kind = 0; kind < 3; ++kind) {
      loads.kind = kind;
      for (unsigned i = 0; i < 3; ++i) {
        loads.calls = 0;
        loads.fail_at = i;
        ASSERT_TRUE(AnchorWindow::from_cell(cell, 3, 3).is_error());
        ASSERT_EQ(loads.calls, i + 1);
      }
    }
  }
  ASSERT_TRUE(AnchorWindow::from_cell(cell, 3, 3).move_as_ok().latest() == root(1));
  ASSERT_TRUE(state.to_cell().move_as_ok()->get_hash() == cell->get_hash());
}
