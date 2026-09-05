#pragma once

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
  // Only roots constructed by this primitive are accepted. Untrusted state
  // loading needs a separately validated StateV2 decoder.
  explicit UsedNullifiers(td::Ref<vm::Cell> root) : root_(std::move(root)) {
  }
  td::Ref<vm::Cell> root_;
};

}  // namespace uno_workchain
