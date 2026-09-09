#pragma once

#include "uno/core/used-nullifiers.h"

namespace uno_workchain {

// Local state mechanics only: the engine must authenticate prepare/terminal
// events and commit this result together with notes, amounts and receipts.
// All three dictionaries are consensus state, not mempool locks. Final owner
// records remain as tombstones; no timeout or deletion reopens an owner ID.
class NullifierState {
 public:
  struct LoadLimits {
    std::uint64_t used_entries = 0;
    std::uint64_t reserved_entries = 0;
    std::uint64_t owners = 0;
    std::uint64_t total_manifest_entries = 0;
  };

  // Restore-time consistency validation, not authentication of a checkpoint or
  // its terminal receipts. The outer loader must authenticate all three roots
  // as one committed state and supply explicit resource limits.
  static td::Result<NullifierState> from_roots(td::Ref<vm::Cell> used_root,
                                            td::Ref<vm::Cell> reserved_root,
                                            td::Ref<vm::Cell> owners_root, LoadLimits limits) {
    TRY_RESULT(used, UsedNullifiers::from_root(std::move(used_root), limits.used_entries));
    try {
      if (!detail::validate_state_dictionary(reserved_root, 256, limits.reserved_entries,
            [](const vm::CellSlice& value) { return value.size() == 256 && value.size_refs() == 0; }) ||
          !detail::validate_state_dictionary(owners_root, 256, limits.owners,
            [&](const vm::CellSlice& record) {
              return record.size() == 2 && record.size_refs() == 1 && record.prefetch_ulong(2) < 3 &&
                     detail::validate_state_dictionary(record.prefetch_ref(), 256, limits.total_manifest_entries,
                       [](const vm::CellSlice& value) { return value.empty_ext(); });
            })) {
        return td::Status::Error("UNO invalid reservation dictionaries or load limit exceeded");
      }
      vm::Dictionary reserved(reserved_root, 256), owners(owners_root, 256);
      // Check the forward relation for every pending manifest and the permanent
      // used-set obligation for refunded manifests. Paid keys may be reused.
      if (!owners.check_for_each([&](td::Ref<vm::CellSlice> record, td::ConstBitPtr owner_bits, int) {
            td::Bits256 owner(owner_bits);
            auto status = record->prefetch_ulong(2);
            vm::Dictionary manifest(record->prefetch_ref(), 256);
            return manifest.check_for_each([&](td::Ref<vm::CellSlice>, td::ConstBitPtr key_bits, int) {
              td::Bits256 key(key_bits);
              if (status == 2) return used.contains(key);
              if (status == 1) return true;
              auto binding = reserved.lookup(key);
              return !used.contains(key) && binding.not_null() && td::Bits256(binding->data_bits()) == owner;
            });
          })) {
        return td::Status::Error("UNO owner manifest does not match nullifier state");
      }
      // The reverse check excludes extra reservations, terminal owners and
      // ownership bindings that no pending manifest actually contains.
      if (!reserved.check_for_each([&](td::Ref<vm::CellSlice> binding, td::ConstBitPtr key_bits, int) {
            td::Bits256 key(key_bits), owner(binding->data_bits());
            auto record = owners.lookup(owner);
            if (used.contains(key) || record.is_null() || record->prefetch_ulong(2) != 0) return false;
            vm::Dictionary manifest(record->prefetch_ref(), 256);
            return manifest.lookup(key).not_null();
          })) {
        return td::Status::Error("UNO orphaned or conflicting nullifier reservation");
      }
      NullifierState result;
      result.used_ = std::move(used);
      result.reserved_ = std::move(reserved_root);
      result.owners_ = std::move(owners_root);
      return result;
    } catch (vm::VmError&) {
      return td::Status::Error("UNO malformed reservation cells");
    } catch (vm::VmVirtError&) {
      return td::Status::Error("UNO incomplete reservation proof");
    } catch (vm::VmNoGas&) {
      return td::Status::Error("UNO reservation loading exhausted execution budget");
    }
  }

  td::Ref<vm::Cell> used_root() const {
    return used_.root();
  }
  std::uint64_t used_count() const { return used_.size(); }
  td::Ref<vm::Cell> reserved_root() const {
    return reserved_;
  }
  td::Ref<vm::Cell> owners_root() const {
    return owners_;
  }

  // Each reserved paired Action consumes one future tree leaf. Count the
  // authoritative dictionary, never a separately trusted caller counter.
  td::Result<std::uint64_t> reserved_count(std::uint64_t max_entries) const try {
    std::uint64_t count = 0;
    vm::Dictionary reserved(reserved_, 256);
    if (!reserved.check_for_each([&](td::Ref<vm::CellSlice>, td::ConstBitPtr, int) {
          if (count == max_entries) return false;
          ++count;
          return true;
        })) return td::Status::Error("UNO reservation count exceeds limit");
    return count;
  } catch (vm::VmError&) {
    return td::Status::Error("UNO reservation counting failed on cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO reservation counting encountered incomplete proof");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO reservation counting exhausted execution budget");
  }

  // Low-level lookups require an enclosing VM exception boundary. Successful
  // restoration does not guarantee that a later cell load cannot fail.
  bool is_used(const td::Bits256& key) const {
    return used_.contains(key);
  }
  bool is_reserved(const td::Bits256& key) const {
    vm::Dictionary reserved(reserved_, 256);
    return reserved.lookup(key).not_null();
  }

  // Actor-facing queries preserve load failure as Error, never as absence.
  // The caller classifies that failure using the authenticated root's origin;
  // these storage primitives do not decide candidate validity.
  td::Result<bool> try_is_used(const td::Bits256& key) const {
    return used_.try_contains(key);
  }
  td::Result<bool> try_is_reserved(const td::Bits256& key) const try {
    return is_reserved(key);
  } catch (vm::VmError&) {
    return td::Status::Error("UNO reserved nullifier lookup failed on cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO reserved nullifier lookup encountered incomplete proof");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO reserved nullifier lookup exhausted execution budget");
  }

  td::Result<NullifierState> with_used(const std::vector<td::Bits256>& keys) const try {
    for (const auto& key : keys) {
      if (is_reserved(key)) {
        return td::Status::Error("UNO nullifier reserved for refund");
      }
    }
    TRY_RESULT(next_used, used_.with_used(keys));
    auto next = *this;
    next.used_ = std::move(next_used);
    return next;
  } catch (vm::VmError&) {
    return td::Status::Error("UNO nullifier consumption failed on cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO nullifier consumption encountered incomplete proof");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO nullifier consumption exhausted execution budget");
  }

  td::Result<NullifierState> reserve(const td::Bits256& owner, const std::vector<td::Bits256>& keys) const try {
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
  } catch (vm::VmError&) {
    return td::Status::Error("UNO nullifier reservation failed on cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO nullifier reservation encountered incomplete proof");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO nullifier reservation exhausted execution budget");
  }

  td::Result<NullifierState> paid(const td::Bits256& owner) const {
    return finish(owner, false);
  }
  td::Result<NullifierState> refund(const td::Bits256& owner) const {
    return finish(owner, true);
  }

 private:
  td::Result<NullifierState> finish(const td::Bits256& owner, bool consume) const try {
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
  } catch (vm::VmError&) {
    return td::Status::Error("UNO nullifier settlement failed on cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO nullifier settlement encountered incomplete proof");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO nullifier settlement exhausted execution budget");
  }

  UsedNullifiers used_;
  td::Ref<vm::Cell> reserved_, owners_;
};

}  // namespace uno_workchain
