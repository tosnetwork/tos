#pragma once

#include <cstdint>
#include <vector>
#include "td/utils/Status.h"
#include "vm/dict.h"

namespace uno_workchain {

// Persistent used-set primitive, not complete transaction admission: callers
// must also check authenticated refund reservations and cryptographic validity.
// No deletion API: a spent nullifier cannot become available again.
class UsedNullifiers {
 public:
  UsedNullifiers() = default;

  // Validate once when restoring persisted state, not once per transaction.
  // The outer state loader must authenticate the root and supply its resource
  // policy; valid dictionary contents alone do not authenticate a checkpoint.
  static td::Result<UsedNullifiers> from_root(td::Ref<vm::Cell> root, std::uint64_t max_entries) {
    try {
      std::uint64_t remaining = max_entries;
      if (root.not_null() && !validate_node(root, 256, remaining)) {
        return td::Status::Error("UNO invalid used nullifier dictionary or entry limit exceeded");
      }
      return UsedNullifiers(std::move(root));
    } catch (vm::VmError&) {
      return td::Status::Error("UNO malformed used nullifier cells");
    } catch (vm::VmVirtError&) {
      return td::Status::Error("UNO incomplete used nullifier proof");
    } catch (vm::VmNoGas&) {
      return td::Status::Error("UNO used nullifier loading exhausted execution budget");
    }
  }

  td::Ref<vm::Cell> root() const {
    return root_;
  }

  bool contains(const td::Bits256& nullifier) const {
    vm::Dictionary dictionary(root_, 256);
    return dictionary.lookup(nullifier).not_null();
  }

  // Stage against a private root; even a late duplicate leaves this object
  // unchanged. Every public action, including dummy actions, supplies a key.
  td::Result<UsedNullifiers> with_used(const std::vector<td::Bits256>& nullifiers) const {
    vm::Dictionary staged(root_, 256);
    vm::CellBuilder marker;
    for (const auto& nullifier : nullifiers) {
      if (!staged.set_builder(nullifier, marker, vm::Dictionary::SetMode::Add)) {
        return td::Status::Error("UNO nullifier already used");
      }
    }
    return UsedNullifiers(std::move(staged).extract_root_cell());
  }

 private:
  static bool validate_node(const td::Ref<vm::Cell>& root, int key_bits, std::uint64_t& remaining) {
    if (remaining == 0) {
      return false;
    }
    bool special = false;
    auto slice = vm::load_cell_slice_special(root, special);
    if (special) {
      return false;
    }
    // Reuse the native label and strict fork validator, without implicit library
    // resolution. Key width decreases at every fork, bounding recursion to 257.
    vm::dict::LabelParser label(td::Ref<vm::CellSlice>{true, std::move(slice)}, key_bits);
    label.skip_label();
    if (label.l_bits == key_bits) {
      if (!label.remainder->empty_ext()) {
        return false;
      }
      --remaining;
      return true;
    }
    const int child_bits = key_bits - label.l_bits - 1;
    return validate_node(label.remainder->prefetch_ref(0), child_bits, remaining) &&
           validate_node(label.remainder->prefetch_ref(1), child_bits, remaining);
  }

  // Roots enter only through construction or bounded validation. The complete
  // StateV2 decoder must separately validate schema and cross-field invariants.
  explicit UsedNullifiers(td::Ref<vm::Cell> root) : root_(std::move(root)) {
  }
  td::Ref<vm::Cell> root_;
};

}  // namespace uno_workchain
