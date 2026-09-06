#pragma once

#include "uno/core/anchor-window.h"
#include "uno/core/leaf-budget.h"
#include "uno/core/note-tree-state.h"
#include "uno/core/nullifier-state.h"

namespace uno_workchain {

// Persistent note-state component, not the full engine state or an admission
// API. The engine must first verify complete bundles and authenticate all other
// state (amounts, configuration, finality, system messages and output archive),
// then commit those effects together with this result. No crypto acceptance is
// implied by constructing SpendEffects.
class NoteState {
 public:
  struct Action {
    td::Bits256 nullifier;
    NoteTreeState::Commitment commitment;
  };
  struct SpendEffects {
    AnchorWindow::Root anchor;
    std::vector<Action> actions;
  };
  struct Limits {
    std::size_t bundles = 0;
    std::size_t actions_per_bundle = 0;
    std::size_t total_actions = 0;
  };

  // Assembly is used for an authenticated block-end state. Root equality
  // links the frontier to the current block-end anchor; this does not establish
  // historical validity or authorize a genesis allocation.
  static td::Result<NoteState> assemble(NoteTreeState tree, NullifierState nullifiers,
                                       AnchorWindow anchors) {
    if (tree.root() != anchors.latest()) return td::Status::Error("UNO tree and latest anchor disagree");
    if (nullifiers.used_count() != tree.next_position()) {
      return td::Status::Error("UNO paired action count disagrees with tree position");
    }
    TRY_RESULT(reserved, nullifiers.reserved_count(LeafBudget::capacity - tree.next_position()));
    TRY_STATUS(LeafBudget::from_counts(tree.next_position(), reserved));
    return NoteState(std::move(tree), std::move(nullifiers), std::move(anchors), reserved);
  }

  const NoteTreeState& tree() const { return tree_; }
  const NullifierState& nullifiers() const { return nullifiers_; }
  const AnchorWindow& anchors() const { return anchors_; }
  std::uint64_t reserved_leaves() const { return reserved_; }

  td::Result<NoteState> apply_spend_effects(std::uint64_t height, const std::vector<SpendEffects>& bundles,
                                          Limits limits) const {
    if (bundles.size() > limits.bundles) return td::Status::Error("UNO block bundle limit exceeded");
    // Validate height and all cheap shapes before touching the dictionaries or
    // invoking the tree ABI. The actual final root is pushed only after apply.
    TRY_STATUS(anchors_.validate_next_height(height));
    std::size_t total = 0;
    for (const auto& bundle : bundles) {
      if (bundle.actions.empty() || bundle.actions.size() > limits.actions_per_bundle ||
          bundle.actions.size() > limits.total_actions - total) {
        return td::Status::Error("UNO block action limit exceeded");
      }
      total += bundle.actions.size();
      if (!anchors_.contains(bundle.anchor)) return td::Status::Error("UNO anchor absent from block pre-state");
    }
    TRY_RESULT(budget, LeafBudget::from_counts(tree_.next_position(), reserved_));
    TRY_STATUS(budget.checked_append(total));
    auto next_nullifiers = nullifiers_;
    std::vector<NoteTreeState::Commitment> outputs;
    outputs.reserve(total);
    for (const auto& bundle : bundles) {
      std::vector<td::Bits256> keys;
      keys.reserve(bundle.actions.size());
      for (const auto& action : bundle.actions) {
        keys.push_back(action.nullifier);
        outputs.push_back(action.commitment);
      }
      TRY_RESULT(updated, next_nullifiers.with_used(keys));
      next_nullifiers = std::move(updated);
    }
    TRY_RESULT(next_tree, tree_.append(outputs, reserved_, limits.total_actions));
    TRY_RESULT(next_anchors, anchors_.finish_block(height, next_tree.root()));
    return NoteState(std::move(next_tree), std::move(next_nullifiers), std::move(next_anchors), reserved_);
  }

  // Prototype tag and layout; not an activated StateV2 wire assignment.
  // No redundant root/position/reservation counter is trusted on restore.
  td::Result<td::Ref<vm::Cell>> to_cell() const try {
    TRY_RESULT(tree, tree_.to_cell());
    TRY_RESULT(anchors, anchors_.to_cell());
    vm::CellBuilder nullifiers;
    for (const auto& root : {nullifiers_.used_root(), nullifiers_.reserved_root(), nullifiers_.owners_root()}) {
      nullifiers.store_long(root.not_null(), 1);
      if (root.not_null()) nullifiers.store_ref(root);
    }
    return vm::CellBuilder().store_long(0x554e5330, 32).store_ref(tree).store_ref(anchors)
        .store_ref(nullifiers.finalize()).finalize();
  } catch (vm::CellBuilder::CellWriteError&) {
    return td::Status::Error("UNO note state encoding exceeds cell limits");
  } catch (vm::CellBuilder::CellCreateError&) {
    return td::Status::Error("UNO note state cell construction failed");
  } catch (vm::VmError&) {
    return td::Status::Error("UNO note state encoding failed");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO note state encoding encountered incomplete proof");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO note state encoding exhausted execution budget");
  }

  static td::Result<NoteState> from_cell(const td::Ref<vm::Cell>& cell, std::uint32_t window,
                                        std::uint32_t window_limit, NullifierState::LoadLimits limits) try {
    if (cell.is_null()) return td::Status::Error("UNO missing note state");
    bool special = false;
    auto root = vm::load_cell_slice_special(cell, special);
    if (special || root.size() != 32 || root.size_refs() != 3 || root.fetch_ulong(32) != 0x554e5330) {
      return td::Status::Error("UNO invalid note state header");
    }
    TRY_RESULT(tree, NoteTreeState::from_cell(root.fetch_ref()));
    TRY_RESULT(anchors, AnchorWindow::from_cell(root.fetch_ref(), window, window_limit));
    auto dictionary_roots = vm::load_cell_slice_special(root.fetch_ref(), special);
    if (special || dictionary_roots.size() != 3) return td::Status::Error("UNO invalid nullifier root envelope");
    const auto flags = dictionary_roots.prefetch_ulong(3);
    const auto expected_refs = (flags & 1u) + ((flags >> 1) & 1u) + ((flags >> 2) & 1u);
    if (dictionary_roots.size_refs() != expected_refs) {
      return td::Status::Error("UNO nullifier root flags differ from reference count");
    }
    td::Ref<vm::Cell> roots[3];
    for (auto& item : roots) {
      if (dictionary_roots.fetch_ulong(1)) item = dictionary_roots.fetch_ref();
    }
    if (!dictionary_roots.empty_ext()) return td::Status::Error("UNO trailing nullifier root data");
    TRY_RESULT(nullifiers, NullifierState::from_roots(roots[0], roots[1], roots[2], limits));
    return assemble(std::move(tree), std::move(nullifiers), std::move(anchors));
  } catch (vm::VmError&) {
    return td::Status::Error("UNO malformed note state cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO incomplete note state cells");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO note state loading exhausted execution budget");
  }

 private:
  NoteState(NoteTreeState tree, NullifierState nullifiers, AnchorWindow anchors, std::uint64_t reserved)
      : tree_(std::move(tree)), nullifiers_(std::move(nullifiers)), anchors_(std::move(anchors)), reserved_(reserved) {}
  NoteTreeState tree_;
  NullifierState nullifiers_;
  AnchorWindow anchors_;
  std::uint64_t reserved_;
};

}  // namespace uno_workchain
