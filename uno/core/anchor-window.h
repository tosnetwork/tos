#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <vector>
#include "td/utils/Status.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/excno.hpp"

namespace uno_workchain {

// Unactivated state codec. The enclosing state must authenticate the capacity,
// height and tree root. Roots are opaque here; only the tree implementation may
// produce them. Preserve the pre-state value throughout block verification and
// call finish_block once after all actions, including for an empty block.
class AnchorWindow {
 public:
  using Root = std::array<td::uint8, 32>;

  static td::Result<AnchorWindow> genesis(std::uint32_t capacity, std::uint32_t resource_limit,
                                        const Root& root) {
    if (!capacity || capacity > resource_limit) return td::Status::Error("UNO anchor capacity exceeds limits");
    return AnchorWindow(capacity, 0, {root});
  }

  bool contains(const Root& root) const {
    return std::find(roots_.begin(), roots_.end(), root) != roots_.end();
  }
  std::uint64_t height() const { return height_; }
  std::size_t size() const { return roots_.size(); }
  const Root& latest() const { return roots_.back(); }

  td::Result<AnchorWindow> finish_block(std::uint64_t height, const Root& root) const {
    if (height_ == std::numeric_limits<std::uint64_t>::max() || height != height_ + 1) {
      return td::Status::Error("UNO anchor requires the next block height");
    }
    auto next = *this;
    if (next.roots_.size() == capacity_) next.roots_.erase(next.roots_.begin());
    // Equal roots still occupy separate heights; idle blocks age the window.
    next.roots_.push_back(root);
    next.height_ = height;
    return next;
  }

  td::Result<td::Ref<vm::Cell>> to_cell() const try {
    td::Ref<vm::Cell> tail;
    for (auto i = roots_.size(); i > 0; --i) {
      vm::CellBuilder node;
      node.store_bytes(roots_[i - 1].data(), 32);
      if (tail.not_null()) node.store_ref(tail);
      tail = node.finalize();
    }
    return vm::CellBuilder().store_long(0x554e4130, 32).store_long(height_, 64)
        .store_long(roots_.size(), 32).store_ref(tail).finalize();
  } catch (vm::VmError&) {
    return td::Status::Error("UNO anchor encoding failed");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO anchor encoding encountered incomplete proof");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO anchor encoding exhausted execution budget");
  }

  static td::Result<AnchorWindow> from_cell(const td::Ref<vm::Cell>& cell, std::uint32_t capacity,
                                           std::uint32_t resource_limit) try {
    if (!capacity || capacity > resource_limit || cell.is_null()) {
      return td::Status::Error("UNO missing anchor state or invalid capacity");
    }
    bool special = false;
    auto header = vm::load_cell_slice_special(cell, special);
    if (special || header.size() != 128 || header.size_refs() != 1 ||
        header.fetch_ulong(32) != 0x554e4130) {
      return td::Status::Error("UNO invalid anchor header");
    }
    const auto height = header.fetch_ulong(64);
    const auto count = header.fetch_ulong(32);
    const auto expected = height >= capacity - 1 ? capacity : height + 1;
    if (count != expected) return td::Status::Error("UNO anchor count does not match height and capacity");
    std::vector<Root> roots;
    auto next = header.fetch_ref();
    for (std::uint32_t i = 0; i < count; ++i) {
      auto node = vm::load_cell_slice_special(next, special);
      Root root{};
      if (special || node.size() != 256 || node.size_refs() != (i + 1 < count ? 1u : 0u) ||
          !node.fetch_bytes(root.data(), 32)) {
        return td::Status::Error("UNO invalid anchor node");
      }
      roots.push_back(root);
      next = node.size_refs() ? node.fetch_ref() : td::Ref<vm::Cell>{};
    }
    return AnchorWindow(capacity, height, std::move(roots));
  } catch (vm::VmError&) {
    return td::Status::Error("UNO malformed anchor cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO incomplete anchor cells");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO anchor loading exhausted execution budget");
  }

 private:
  AnchorWindow(std::uint32_t capacity, std::uint64_t height, std::vector<Root> roots)
      : capacity_(capacity), height_(height), roots_(std::move(roots)) {}
  std::uint32_t capacity_;
  std::uint64_t height_;
  std::vector<Root> roots_;
};

}  // namespace uno_workchain
