// TEST FIXTURE ONLY. Funding is assumed initial state, not a verified M4 deposit.
#pragma once

#include "block/transaction.h"
#include "block/workchain-confidential-native.h"
#include "block/workchain-confidential-state.h"

namespace block::m3_test {

// Pure-transition fixtures only: edit their Native dictionary after registration.
// Do NOT install this edit as the predecessor of a real block: the preceding
// block's MerkleUpdate would still commit the old root. Live tests instead use
// the D59-scoped test-only block-contained funding operation.
// This is not a transaction: no authorization, AccountBlock, nonce increment or
// fictional history is created. M3 tests transfers from an assumed balance;
// they do not establish how that balance was legally created (M4 Deposit).
inline td::Result<td::Ref<vm::Cell>> fund_registered_test_account(td::Ref<vm::Cell> accounts, const td::Bits256& key,
                                                                  const WorkchainCiphertext& available,
                                                                  tos::UnixTime now) {
  auto fail = [] { return td::Status::Error("invalid M3 test-funding state"); };
  vm::AugmentedDictionary dictionary(vm::load_cell_slice_ref(accounts), 256, tlb::aug_ShardAccounts);
  auto leaf = dictionary.lookup(key);
  Account prior(2, key.bits());
  if (leaf.is_null() || !prior.unpack(leaf, now, false) || prior.status != Account::acc_active ||
      !is_workchain_confidential_native_wrapper(prior.code, prior.tick, prior.tock))
    return fail();
  TRY_RESULT(record, decode_workchain_confidential_account(prior.data));
  if (record.address.workchain_id != 2 || record.address.account != key ||
      !std::holds_alternative<WorkchainAccountActive>(record.lifecycle) || record.auth_nonce != 0 ||
      record.available_revision != 0 || !record.pending.empty() || !record.available.commitment.is_zero() ||
      !record.available.handle.is_zero())
    return fail();
  record.available = available;
  TRY_RESULT(data, encode_workchain_confidential_account(record));
  gen::Account::Record_account account;
  gen::AccountStorage::Record storage;
  gen::AccountState::Record_account_active active;
  gen::StateInit::Record init;
  gen::StorageInfo::Record info;
  if (!tlb::unpack_cell(prior.total_state, account) || !tlb::csr_unpack(account.storage, storage) ||
      !tlb::csr_unpack(storage.state, active) || !tlb::csr_unpack(active.x, init) ||
      !tlb::csr_unpack(account.storage_stat, info))
    return fail();
  init.data = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1).store_ref(data).finalize());
  td::Ref<vm::Cell> packed;
  if (!tlb::pack_cell(packed, init))
    return fail();
  active.x = vm::load_cell_slice_ref(packed);
  if (!tlb::pack_cell(packed, active))
    return fail();
  storage.state = vm::load_cell_slice_ref(packed);
  if (!tlb::pack_cell(packed, storage))
    return fail();
  account.storage = vm::load_cell_slice_ref(packed);
  // Recompute the Native storage metadata; retaining the old counts/hash would
  // give the two actors a malformed fixture, not an authenticated test balance.
  // Test wallets have no extra currencies, so both accounting conventions agree.
  if (prior.balance.extra.not_null())
    return fail();
  AccountStorageStat stat;
  TRY_STATUS(stat.replace_roots(account.storage->prefetch_all_refs()));
  std::uint64_t cells, bits;
  if (__builtin_add_overflow(stat.get_total_cells(), std::uint64_t{1}, &cells) ||
      __builtin_add_overflow(stat.get_total_bits(), static_cast<std::uint64_t>(account.storage->size()), &bits))
    return fail();
  vm::CellBuilder used;
  if (!store_UInt7(used, cells) || !store_UInt7(used, bits))
    return fail();
  info.used = vm::load_cell_slice_ref(used.finalize());
  if (prior.storage_dict_hash) {
    TRY_RESULT(hash, stat.get_dict_hash());
    info.storage_extra =
        vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 3).store_bits(hash.bits(), 256).finalize());
  }
  if (!tlb::pack_cell(packed, info))
    return fail();
  account.storage_stat = vm::load_cell_slice_ref(packed);
  if (!tlb::pack_cell(packed, account))
    return fail();
  vm::CellBuilder entry;
  entry.store_ref(packed).store_bits(prior.last_trans_hash_.bits(), 256).store_long(prior.last_trans_lt_, 64);
  if (!dictionary.set_builder(key, entry, vm::Dictionary::SetMode::Replace))
    return fail();
  return dictionary.get_wrapped_dict_root();
}

}  // namespace block::m3_test
