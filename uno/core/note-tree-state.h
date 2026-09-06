#pragma once

#include <array>
#include <algorithm>
#include <cstdint>
#include <vector>
#include "td/utils/Status.h"
#include "uno/core/tree-error.h"
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
    return transition(frontier, {}, 0, 0, TreeFailure::LocalFailure);
  }

  std::uint64_t next_position() const { return state_.frontier.next_position; }
  Commitment root() const {
    Commitment result;
    std::copy(std::begin(state_.root), std::end(state_.root), result.begin());
    return result;
  }

  td::Result<NoteTreeState> append(const std::vector<Commitment>& commitments,
                                 std::uint64_t reserved, std::size_t max_commitments) const {
    // The ABI reports both frontier and commitment decode failures with the
    // same status. Check the immutable prestate separately before attributing a
    // failure to candidate commitments or their capacity reservation.
    TRY_RESULT(checked, transition(state_.frontier, {}, 0, 0, TreeFailure::AuthenticatedStateCorrupt));
    return transition(checked.state_.frontier, commitments, reserved, max_commitments,
                      TreeFailure::CandidateInvalid);
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
    return tree_error(TreeFailure::LocalFailure, "UNO frontier encoding exceeds cell limits");
  } catch (vm::CellBuilder::CellCreateError&) {
    return tree_error(TreeFailure::LocalFailure, "UNO frontier cell construction failed");
  } catch (vm::VmError&) {
    return tree_error(TreeFailure::LocalFailure, "UNO frontier cell encoding failed");
  } catch (vm::VmVirtError&) {
    return tree_error(TreeFailure::LocalFailure, "UNO frontier cell encoding encountered incomplete proof");
  } catch (vm::VmNoGas&) {
    return tree_error(TreeFailure::LocalFailure, "UNO frontier cell encoding exhausted execution budget");
  }

  static td::Result<NoteTreeState> from_cell(const td::Ref<vm::Cell>& cell) {
    return decode_cell(cell, TreeFailure::CandidateInvalid);
  }

  // Only for a prestate whose enclosing checkpoint/state has been authenticated.
  // This entry does not itself authenticate the cell or its source.
  static td::Result<NoteTreeState> from_authenticated_cell(const td::Ref<vm::Cell>& cell) {
    return decode_cell(cell, TreeFailure::AuthenticatedStateCorrupt);
  }

 private:
  static td::Result<NoteTreeState> decode_cell(const td::Ref<vm::Cell>& cell, TreeFailure invalid) try {
    if (cell.is_null()) return tree_error(invalid, "UNO missing frontier cell");
    bool special = false;
    auto header = vm::load_cell_slice_special(cell, special);
    if (special || header.size() != 358 || header.fetch_ulong(32) != 0x554e4630) {
      return tree_error(invalid, "UNO invalid frontier cell header");
    }
    UnoTreeFrontier value{};
    value.next_position = header.fetch_ulong(64);
    if (!header.fetch_bytes(value.leaf, 32)) return tree_error(invalid, "UNO missing frontier leaf");
    value.ommer_count = header.fetch_ulong(6);
    if (value.ommer_count > 32 || header.size_refs() != (value.ommer_count ? 1u : 0u)) {
      return tree_error(invalid, "UNO invalid frontier node count");
    }
    auto next = value.ommer_count ? header.fetch_ref() : td::Ref<vm::Cell>{};
    for (std::uint64_t i = 0; i < value.ommer_count; ++i) {
      auto node = vm::load_cell_slice_special(next, special);
      if (special || node.size() != 256 || node.size_refs() != (i + 1 < value.ommer_count ? 1u : 0u) ||
          !node.fetch_bytes(value.ommers[i], 32)) {
        return tree_error(invalid, "UNO invalid frontier node cell");
      }
      next = node.size_refs() ? node.fetch_ref() : td::Ref<vm::Cell>{};
    }
    return transition(value, {}, 0, 0, invalid);
  } catch (vm::VmError&) {
    return tree_error(TreeFailure::LocalFailure, "UNO frontier cell loading failed");
  } catch (vm::VmVirtError&) {
    return tree_error(TreeFailure::LocalFailure, "UNO incomplete frontier cells");
  } catch (vm::VmNoGas&) {
    return tree_error(TreeFailure::LocalFailure, "UNO frontier loading exhausted execution budget");
  }

  explicit NoteTreeState(const UnoTreeResult& state) : state_(state) {}
  static td::Result<NoteTreeState> transition(const UnoTreeFrontier& frontier,
                                            const std::vector<Commitment>& commitments,
                                            std::uint64_t reserved, std::size_t limit, TreeFailure invalid) {
    if (commitments.size() > limit) return tree_error(invalid, "UNO tree action limit exceeded");
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
    if (status == UNO_CRYPTO_DECODE) return tree_error(invalid, "UNO tree ABI rejected transition");
    if (status != UNO_CRYPTO_OK) {
      return tree_error(TreeFailure::LocalFailure, "UNO tree ABI reported a local failure");
    }
    return NoteTreeState(result);
  }
  UnoTreeResult state_;
};

}  // namespace uno_workchain
