#pragma once

#include <memory>
#include "block/transaction.h"
#include "block/workchain-account-dictionary.h"
#include "block/workchain-participant-lt.h"
#include "block/workchain-participant-record.h"

namespace block {

struct WorkchainStorageWrite {
  td::Bits256 account;
  td::Bits256 old_account_hash;
  td::Ref<vm::Cell> data;
};

struct WorkchainStorageOverlay {
  td::Ref<vm::Cell> accounts;
  td::Ref<vm::Cell> account_blocks;
  std::uint64_t end_lt;
};

// Post-execution storage-only materialization, not engine or role authorization.
// Inputs and old state require source-aware admission before this call. Limits
// bound record counts, not closure/state traversal. Source/VM/allocation errors
// propagate to that boundary. Mutable Account/Transaction objects never escape;
// only a complete pair of persistent dictionary roots can be returned. No CellDb
// write occurs and the supplied old root is never modified.
inline td::Result<WorkchainStorageOverlay> build_workchain_storage_overlay(
    td::Ref<vm::Cell> old_accounts, tos::WorkchainId workchain, tos::UnixTime now,
    std::uint64_t after_lt, const td::Bits256& input_hash, const td::Bits256& effects_hash,
    const std::vector<WorkchainStorageWrite>& writes, std::uint64_t max_participants,
    const SerializeConfig& cfg) {
  if (workchain < 0 || writes.empty() || writes.size() > max_participants) {
    return td::Status::Error("invalid storage overlay domain or count");
  }
  std::vector<WorkchainAccountRead> reads;
  std::vector<td::Bits256> keys;
  for (const auto& write : writes) {
    reads.push_back({write.account, write.old_account_hash});
    keys.push_back(write.account);
  }
  TRY_RESULT(access, WorkchainAccountAccess::create(reads, keys, max_participants, max_participants));
  TRY_RESULT(bindings, build_workchain_participant_records(input_hash, effects_hash, keys, max_participants));
  WorkchainAccountDictionary original(old_accounts);
  vm::AugmentedDictionary staged(vm::load_cell_slice_ref(old_accounts), 256, tlb::aug_ShardAccounts);
  vm::AugmentedDictionary blocks(256, tlb::aug_ShardAccountBlocks);
  std::vector<std::unique_ptr<Account>> accounts;
  std::vector<WorkchainParticipantTiming> timing;
  for (const auto& write : writes) {
    // Check the declaration before accessing authenticated old account data.
    TRY_STATUS(original.verify_old_read(access, write.account));
    auto account = std::make_unique<Account>(workchain, write.account.bits());
    if (!account->unpack(staged.lookup(write.account), now, false)) {
      throw vm::VmError{vm::Excno::dict_err, "invalid authenticated storage account"};
    }
    timing.push_back({write.account, account->last_trans_end_lt_, 0});
    accounts.push_back(std::move(account));
  }
  TRY_RESULT(schedule, plan_workchain_participant_lts(after_lt, timing, max_participants, 0));
  std::vector<td::Bits256> participants;
  for (std::size_t i = 0; i < writes.size(); ++i) {
    auto& account = *accounts[i];
    transaction::Transaction tx(account, transaction::Transaction::tr_workchain_batch,
                                schedule.start_lt, now);
    TRY_STATUS(tx.prepare_workchain_storage_participant(bindings[i], writes[i].data, cfg));
    if (tx.start_lt != schedule.start_lt || tx.end_lt != schedule.participants[i].end_lt || !tx.serialize(cfg)) {
      return td::Status::Error("storage participant differs from native schedule or limits");
    }
    // No engine/user callback or mutable alias exists between serialize and
    // commit. This Account is private temporary state, not the live manager's.
    tx.commit(account);
    vm::CellBuilder account_block;
    if (!account.create_account_block(account_block) ||
        !blocks.set_builder(account.addr, account_block, vm::Dictionary::SetMode::Add)) {
      return td::Status::Error("cannot construct storage AccountBlock");
    }
    vm::CellBuilder entry;
    entry.store_ref(account.total_state).store_bits(account.last_trans_hash_.bits(), 256)
        .store_long(account.last_trans_lt_, 64);
    if (!staged.set_builder(account.addr, entry, vm::Dictionary::SetMode::Replace)) {
      return td::Status::Error("cannot replace storage ShardAccount");
    }
    TRY_STATUS(access.record_write(account.addr));
    participants.push_back(account.addr);
  }
  auto next_root = staged.get_wrapped_dict_root();
  WorkchainAccountDictionary next(next_root);
  TRY_RESULT(changed, original.changed_accounts(next, max_participants));
  TRY_STATUS(access.finish(changed, participants));
  return WorkchainStorageOverlay{next_root, blocks.get_wrapped_dict_root(), schedule.end_lt};
}

}  // namespace block
