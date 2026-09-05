#pragma once

#include "uno/core/used-nullifiers.h"

namespace uno_workchain {

// Local state mechanics only: the engine must authenticate prepare/terminal
// events and commit this result together with notes, amounts and receipts.
// All three dictionaries are consensus state, not mempool locks. Final owner
// records remain as tombstones; no timeout or deletion reopens an owner ID.
class NullifierState {
 public:
  td::Ref<vm::Cell> used_root() const {
    return used_.root();
  }
  td::Ref<vm::Cell> reserved_root() const {
    return reserved_;
  }
  td::Ref<vm::Cell> owners_root() const {
    return owners_;
  }

  bool is_used(const td::Bits256& key) const {
    return used_.contains(key);
  }
  bool is_reserved(const td::Bits256& key) const {
    vm::Dictionary reserved(reserved_, 256);
    return reserved.lookup(key).not_null();
  }

  td::Result<NullifierState> with_used(const std::vector<td::Bits256>& keys) const {
    for (const auto& key : keys) {
      if (is_reserved(key)) {
        return td::Status::Error("UNO nullifier reserved for refund");
      }
    }
    TRY_RESULT(next_used, used_.with_used(keys));
    auto next = *this;
    next.used_ = std::move(next_used);
    return next;
  }

  td::Result<NullifierState> reserve(const td::Bits256& owner, const std::vector<td::Bits256>& keys) const {
    if (keys.empty()) {
      return td::Status::Error("UNO empty refund nullifier reservation");
    }
    vm::Dictionary owners(owners_, 256);
    if (owners.lookup(owner).not_null()) {
      return td::Status::Error("UNO refund owner already recorded");
    }
    vm::Dictionary reserved(reserved_, 256), manifest(256);
    vm::CellBuilder owner_value, marker;
    owner_value.store_bits(owner.bits(), 256);
    for (const auto& key : keys) {
      if (used_.contains(key) || !reserved.set_builder(key, owner_value, vm::Dictionary::SetMode::Add) ||
          !manifest.set_builder(key, marker, vm::Dictionary::SetMode::Add)) {
        return td::Status::Error("UNO refund nullifier unavailable");
      }
    }
    vm::CellBuilder record;
    record.store_long(0, 2).store_ref(std::move(manifest).extract_root_cell());
    if (!owners.set_builder(owner, record, vm::Dictionary::SetMode::Add)) {
      return td::Status::Error("UNO cannot record refund owner");
    }
    auto next = *this;
    next.reserved_ = std::move(reserved).extract_root_cell();
    next.owners_ = std::move(owners).extract_root_cell();
    return next;
  }

  td::Result<NullifierState> paid(const td::Bits256& owner) const {
    return finish(owner, false);
  }
  td::Result<NullifierState> refund(const td::Bits256& owner) const {
    return finish(owner, true);
  }

 private:
  td::Result<NullifierState> finish(const td::Bits256& owner, bool consume) const {
    vm::Dictionary owners(owners_, 256), reserved(reserved_, 256);
    auto record = owners.lookup(owner);
    if (record.is_null() || record->prefetch_ulong(2) != 0) {
      return td::Status::Error("UNO refund owner is not pending");
    }
    auto manifest_root = record->prefetch_ref();
    vm::Dictionary manifest(manifest_root, 256);
    std::vector<td::Bits256> keys;
    if (!manifest.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr bits, int n) {
          if (n != 256 || !value->empty_ext()) {
            return false;
          }
          td::Bits256 key;
          key.bits().copy_from(bits, 256);
          auto binding = reserved.lookup_delete(key);
          td::Bits256 recorded_owner;
          if (binding.is_null() || !binding.write().fetch_bits_to(recorded_owner) || !binding->empty_ext() ||
              recorded_owner != owner) {
            return false;
          }
          keys.push_back(key);
          return true;
        }) ||
        keys.empty()) {
      return td::Status::Error("UNO inconsistent refund reservation");
    }
    auto next = *this;
    if (consume) {
      TRY_RESULT(next_used, used_.with_used(keys));
      next.used_ = std::move(next_used);
    }
    vm::CellBuilder terminal;
    terminal.store_long(consume ? 2 : 1, 2).store_ref(manifest_root);
    if (!owners.set_builder(owner, terminal, vm::Dictionary::SetMode::Replace)) {
      return td::Status::Error("UNO cannot finalize refund owner");
    }
    next.reserved_ = std::move(reserved).extract_root_cell();
    next.owners_ = std::move(owners).extract_root_cell();
    return next;
  }

  UsedNullifiers used_;
  td::Ref<vm::Cell> reserved_, owners_;
};

}  // namespace uno_workchain
