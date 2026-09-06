#pragma once

#include <cstdint>
#include <vector>
#include "td/utils/Status.h"
#include "vm/dict.h"
#include "uno/core/state-dictionary.h"

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
      if (!detail::validate_state_dictionary(root, 256, remaining,
                                             [](const vm::CellSlice& value) { return value.empty_ext(); })) {
        return td::Status::Error("UNO invalid used nullifier dictionary or entry limit exceeded");
      }
      return UsedNullifiers(std::move(root), max_entries - remaining);
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
  std::uint64_t size() const { return size_; }

  // Low-level lookup: may throw VmError, VmVirtError or VmNoGas while loading
  // cells, even after successful restore. Use only inside an enclosing VM
  // exception boundary; actor-facing callers should use try_contains instead.
  bool contains(const td::Bits256& nullifier) const {
    vm::Dictionary dictionary(root_, 256);
    return dictionary.lookup(nullifier).not_null();
  }

  // A lookup failure is never evidence that a nullifier is absent. This API
  // contains VM exceptions, but does not classify consensus validity: the
  // caller must retain whether the root is candidate or authenticated state.
  td::Result<bool> try_contains(const td::Bits256& nullifier) const try {
    return contains(nullifier);
  } catch (vm::VmError&) {
    return td::Status::Error("UNO used nullifier lookup failed on cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO used nullifier lookup encountered incomplete proof");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO used nullifier lookup exhausted execution budget");
  }

  // Stage against a private root; even a late duplicate leaves this object
  // unchanged. Every public action, including dummy actions, supplies a key.
  td::Result<UsedNullifiers> with_used(const std::vector<td::Bits256>& nullifiers) const try {
    vm::Dictionary staged(root_, 256);
    vm::CellBuilder marker;
    for (const auto& nullifier : nullifiers) {
      if (!staged.set_builder(nullifier, marker, vm::Dictionary::SetMode::Add)) {
        return td::Status::Error("UNO nullifier already used");
      }
    }
    if (nullifiers.size() > UINT64_MAX - size_) return td::Status::Error("UNO used nullifier count overflow");
    return UsedNullifiers(std::move(staged).extract_root_cell(), size_ + nullifiers.size());
  } catch (vm::VmError&) {
    return td::Status::Error("UNO used nullifier update failed on cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO used nullifier update encountered incomplete proof");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO used nullifier update exhausted execution budget");
  }

 private:
  // Roots enter only through construction or bounded validation. The complete
  // StateV2 decoder must separately validate schema and cross-field invariants.
  explicit UsedNullifiers(td::Ref<vm::Cell> root, std::uint64_t size) : root_(std::move(root)), size_(size) {
  }
  td::Ref<vm::Cell> root_;
  std::uint64_t size_ = 0;
};

}  // namespace uno_workchain
