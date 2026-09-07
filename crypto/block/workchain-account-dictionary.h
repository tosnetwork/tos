#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "block/block-parse.h"
#include "block/workchain-account-access.h"
#include "vm/cellslice.h"
#include "vm/dict.h"

namespace block {

// The root is the complete ShardAccounts field of an authenticated shard state,
// or of a candidate whose structure has passed bounded admission. This class
// does not authenticate the containing block. VM/virtualization/allocation
// exceptions propagate to the host's source-aware boundary; missing cells are
// never interpreted as an absent account.
class WorkchainAccountDictionary {
 public:
  explicit WorkchainAccountDictionary(td::Ref<vm::Cell> shard_accounts)
      : accounts_(vm::load_cell_slice_ref(std::move(shard_accounts)), 256, tlb::aug_ShardAccounts) {
  }

  td::Status verify_old_read(WorkchainAccountAccess& access, const td::Bits256& account);
  // Hash-based subtree skipping relies on the old dictionary being validated.
  // Changed-node augmentation in the new dictionary is checked by scan_diff.
  // max_changes bounds returned keys, not all traversal work: structural/state
  // budgets must already bound the input cells at the host admission boundary.
  td::Result<std::vector<td::Bits256>> changed_accounts(WorkchainAccountDictionary& next,
                                                      std::uint64_t max_changes);

 private:
  vm::AugmentedDictionary accounts_;
};

inline td::Status WorkchainAccountDictionary::verify_old_read(WorkchainAccountAccess& access,
                                                            const td::Bits256& account) {
  auto declaration = access.expected_read(account);
  if (declaration.is_error()) return declaration.move_as_error();
  auto value = accounts_.lookup(account);
  if (value.is_null()) return access.record_old_read(account, std::nullopt);
  tlb::ShardAccount::Record record;
  if (value->size_ext() != 0x10140 || !record.unpack(value)) {
    // An invalid authenticated old dictionary is not a candidate mismatch.
    // Keep the exception in the old-state read scope of the source-aware host.
    throw vm::VmError{vm::Excno::dict_err, "invalid old ShardAccount entry"};
  }
  return access.record_old_read(account, td::Bits256(record.account->get_hash().bits()));
}

inline td::Result<std::vector<td::Bits256>> WorkchainAccountDictionary::changed_accounts(
    WorkchainAccountDictionary& next, std::uint64_t max_changes) {
  std::vector<td::Bits256> keys;
  bool limit_reached = false;
  bool scanned = accounts_.scan_diff(
      next.accounts_,
      [&](td::ConstBitPtr key, int key_len, td::Ref<vm::CellSlice>, td::Ref<vm::CellSlice>) {
        if (key_len != 256) throw vm::VmError{vm::Excno::dict_err, "invalid ShardAccounts key width"};
        if (keys.size() >= max_changes) {
          limit_reached = true;
          return false;
        }
        keys.emplace_back(key);
        return true;
      }, 2);
  if (limit_reached) return td::Status::Error("account difference exceeds admitted bound");
  if (!scanned) throw vm::VmError{vm::Excno::dict_err, "invalid ShardAccounts difference"};
  return keys;
}

}  // namespace block
