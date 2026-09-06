#pragma once

#include <array>
#include <algorithm>
#include <cstdint>
#include <vector>
#include "td/utils/Status.h"
#include "uno/crypto/include/uno_crypto.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/excno.hpp"

namespace uno_workchain {

// Unactivated frontier Cell prototype, not a complete StateV2 or output archive.
// Roots are recomputed by the tree ABI; a caller must authenticate the enclosing
// state and commit notes, nullifiers, reservations and amounts atomically.
class NoteTreeState {
 public:
  using Commitment = std::array<td::uint8, 32>;

  static td::Result<NoteTreeState> empty() {
    UnoTreeFrontier frontier{};
    return transition(frontier, {}, 0, 0);
  }

  std::uint64_t next_position() const { return state_.frontier.next_position; }
  Commitment root() const {
    Commitment result;
    std::copy(std::begin(state_.root), std::end(state_.root), result.begin());
    return result;
  }

  td::Result<NoteTreeState> append(const std::vector<Commitment>& commitments,
                                 std::uint64_t reserved, std::size_t max_commitments) const {
    return transition(state_.frontier, commitments, reserved, max_commitments);
  }

  td::Result<td::Ref<vm::Cell>> to_cell() const try {
    const auto& value = state_.frontier;
    td::Ref<vm::Cell> tail;
    for (auto i = value.ommer_count; i > 0; --i) {
      vm::CellBuilder node;
      node.store_bytes(value.ommers[i - 1], 32);
      if (tail.not_null()) node.store_ref(tail);
      tail = node.finalize();
    }
    vm::CellBuilder header;
    header.store_long(0x554e4630, 32).store_long(value.next_position, 64)
        .store_bytes(value.leaf, 32).store_long(value.ommer_count, 6);
    if (tail.not_null()) header.store_ref(tail);
    return header.finalize();
  } catch (vm::CellBuilder::CellWriteError&) {
    return td::Status::Error("UNO frontier encoding exceeds cell limits");
  } catch (vm::CellBuilder::CellCreateError&) {
    return td::Status::Error("UNO frontier cell construction failed");
  } catch (vm::VmError&) {
    return td::Status::Error("UNO frontier cell encoding failed");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO frontier cell encoding encountered incomplete proof");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO frontier cell encoding exhausted execution budget");
  }

  static td::Result<NoteTreeState> from_cell(const td::Ref<vm::Cell>& cell) try {
    if (cell.is_null()) return td::Status::Error("UNO missing frontier cell");
    bool special = false;
    auto header = vm::load_cell_slice_special(cell, special);
    if (special || header.size() != 358 || header.fetch_ulong(32) != 0x554e4630) {
      return td::Status::Error("UNO invalid frontier cell header");
    }
    UnoTreeFrontier value{};
    value.next_position = header.fetch_ulong(64);
    if (!header.fetch_bytes(value.leaf, 32)) return td::Status::Error("UNO missing frontier leaf");
    value.ommer_count = header.fetch_ulong(6);
    if (value.ommer_count > 32 || header.size_refs() != (value.ommer_count ? 1u : 0u)) {
      return td::Status::Error("UNO invalid frontier node count");
    }
    auto next = value.ommer_count ? header.fetch_ref() : td::Ref<vm::Cell>{};
    for (std::uint64_t i = 0; i < value.ommer_count; ++i) {
      auto node = vm::load_cell_slice_special(next, special);
      if (special || node.size() != 256 || node.size_refs() != (i + 1 < value.ommer_count ? 1u : 0u) ||
          !node.fetch_bytes(value.ommers[i], 32)) {
        return td::Status::Error("UNO invalid frontier node cell");
      }
      next = node.size_refs() ? node.fetch_ref() : td::Ref<vm::Cell>{};
    }
    return transition(value, {}, 0, 0);
  } catch (vm::VmError&) {
    return td::Status::Error("UNO malformed frontier cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO incomplete frontier cells");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO frontier loading exhausted execution budget");
  }

 private:
  explicit NoteTreeState(const UnoTreeResult& state) : state_(state) {}
  static td::Result<NoteTreeState> transition(const UnoTreeFrontier& frontier,
                                            const std::vector<Commitment>& commitments,
                                            std::uint64_t reserved, std::size_t limit) {
    if (commitments.size() > limit) return td::Status::Error("UNO tree action limit exceeded");
    static_assert(sizeof(Commitment) == 32 && alignof(Commitment) == 1);
    UnoTreeRequest request{};
    request.abi_version = UNO_CRYPTO_ABI_VERSION;
    request.profile = UNO_CRYPTO_FIXED_PROFILE;
    request.frontier = &frontier;
    request.commitments = reinterpret_cast<const uint8_t (*)[32]>(commitments.data());
    request.commitment_count = commitments.size();
    request.max_commitments = limit;
    request.reserved_leaves = reserved;
    UnoTreeResult result{};
    const auto status = uno_crypto_tree_append_v0(&request, &result);
    if (status != UNO_CRYPTO_OK) return td::Status::Error(static_cast<int>(status), "UNO tree ABI rejected transition");
    return NoteTreeState(result);
  }
  UnoTreeResult state_;
};

}  // namespace uno_workchain
