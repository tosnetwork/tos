#pragma once
// TEST ONLY: explicit fixture edits, not transactions or production state migration.
// Business parameter shapes remain NOT frozen. No identities or balances invented.
#include "block/transaction.h"
#include "block/workchain-resource-policy.h"

namespace block::m3_test {
namespace state_fixture_detail {
using Root = td::Ref<vm::Cell>;
inline td::Status bad() { return td::Status::Error("invalid M3 state fixture edit"); }
template <class T> td::Result<Root> pack(const T& value) {
  Root root; if (!tlb::pack_cell(root,value)) return bad(); return root;
}
inline td::Result<Root> replace_data(Root accounts, int wc, const td::Bits256& key,
                                     Root data, unsigned now) {
  if (accounts.is_null() || data.is_null()) return bad();
  vm::AugmentedDictionary dict(vm::load_cell_slice_ref(accounts),256,tlb::aug_ShardAccounts);
  auto leaf=dict.lookup(key);
  Account prior(wc,key.bits());
  if (leaf.is_null() || !prior.unpack(leaf,now,false) || prior.status!=Account::acc_active ||
      prior.balance.extra.not_null()) return bad(); // TEST profile: native currency only.
  gen::Account::Record_account account;
  gen::AccountStorage::Record storage;
  gen::AccountState::Record_account_active active;
  gen::StateInit::Record init;
  gen::StorageInfo::Record info;
  if (!resource_policy_detail::unpack_exact(prior.total_state,account) ||
      !tlb::csr_unpack(account.storage,storage) || !tlb::csr_unpack(storage.state,active) ||
      !tlb::csr_unpack(active.x,init) || !tlb::csr_unpack(account.storage_stat,info)) return bad();
  init.data=vm::CellBuilder().store_long(1,1).store_ref(data).as_cellslice_ref();
  TRY_RESULT(i,pack(init)); active.x=vm::load_cell_slice_ref(i);
  TRY_RESULT(a,pack(active)); storage.state=vm::load_cell_slice_ref(a);
  TRY_RESULT(s,pack(storage)); account.storage=vm::load_cell_slice_ref(s);
  // Same Native accounting as Transaction::compute_state: referenced cells plus
  // the AccountStorage root. With no extra currencies both counting modes agree.
  AccountStorageStat stat;
  TRY_STATUS(stat.replace_roots(account.storage->prefetch_all_refs()));
  std::uint64_t cells,bits;
  if (__builtin_add_overflow(stat.get_total_cells(),std::uint64_t{1},&cells) ||
      __builtin_add_overflow(stat.get_total_bits(),std::uint64_t(account.storage->size()),&bits)) return bad();
  vm::CellBuilder used;
  if (!store_UInt7(used,cells) || !store_UInt7(used,bits)) return bad();
  info.used=used.as_cellslice_ref();
  if (prior.storage_dict_hash) {
    TRY_RESULT(hash,stat.get_dict_hash());
    info.storage_extra=vm::CellBuilder().store_long(1,3).store_bits(hash.bits(),256).as_cellslice_ref();
  }
  TRY_RESULT(stats,pack(info)); account.storage_stat=vm::load_cell_slice_ref(stats);
  TRY_RESULT(updated,pack(account));
  vm::CellBuilder entry;
  entry.store_ref(updated).store_bits(prior.last_trans_hash_.bits(),256).store_long(prior.last_trans_lt_,64);
  if (!dict.set_builder(key,entry,vm::Dictionary::SetMode::Replace)) return bad();
  return dict.get_wrapped_dict_root();
}
} // namespace state_fixture_detail

inline td::Result<td::Ref<vm::Cell>> replace_m3_test_active_account_data(
    td::Ref<vm::Cell> root, const td::Bits256& key, td::Ref<vm::Cell> data) {
  using namespace state_fixture_detail;
  gen::ShardStateUnsplit::Record state; gen::ShardIdent::Record shard;
  if (!resource_policy_detail::unpack_exact(root,state) || !tlb::csr_unpack(state.shard_id,shard)) return bad();
  TRY_RESULT(accounts,replace_data(state.accounts,shard.workchain_id,key,data,state.gen_utime));
  state.accounts=std::move(accounts);
  return pack(state); // Balance, history, descriptor and ledger remain unchanged.
}

struct M3TestParam84Replacement {
  td::Ref<vm::Cell> root;
  bool config_account_updated; // Caller must assert true when its fixture requires that account.
};
inline td::Result<M3TestParam84Replacement> replace_m3_test_param84(
    td::Ref<vm::Cell> root, td::Ref<vm::Cell> param84) {
  using namespace state_fixture_detail;
  gen::ShardStateUnsplit::Record state; gen::ShardIdent::Record shard;
  if (param84.is_null() || !resource_policy_detail::unpack_exact(root,state) ||
      !tlb::csr_unpack(state.shard_id,shard) || shard.workchain_id!=-1 || state.custom.is_null()) return bad();
  auto custom=*state.custom;
  if (custom.size()!=1 || custom.size_refs()!=1 || custom.fetch_ulong(1)!=1) return bad();
  gen::McStateExtra::Record extra; gen::ConfigParams::Record config;
  if (!resource_policy_detail::unpack_exact(custom.fetch_ref(),extra) ||
      !tlb::csr_unpack(extra.config,config)) return bad();
  auto old_config=config.config;
  vm::Dictionary dictionary(old_config,32);
  if (!dictionary.set_ref(td::BitArray<32>{84LL},param84,vm::Dictionary::SetMode::Replace)) return bad();
  config.config=dictionary.get_root_cell();
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts),256,tlb::aug_ShardAccounts);
  auto leaf=accounts.lookup(config.config_addr);
  bool synchronized=false;
  if (leaf.not_null()) {
    Account account(-1,config.config_addr.bits());
    if (!account.unpack(leaf,state.gen_utime,false) || account.status!=Account::acc_active || account.data.is_null())
      return bad();
    bool special=false; auto data=vm::load_cell_slice_special(account.data,special);
    // create-state.cpp:set_config_smc defines data ref[0] as the config dictionary.
    if (special || data.size_refs()==0 || data.fetch_ref()->get_hash()!=old_config->get_hash())
      return td::Status::Error("M3 config account does not contain the old configuration root");
    vm::CellBuilder replacement;
    replacement.store_ref(config.config).append_cellslice(data);
    TRY_RESULT(updated,replace_data(state.accounts,-1,config.config_addr,replacement.finalize(),state.gen_utime));
    state.accounts=std::move(updated); synchronized=true;
  }
  TRY_RESULT(c,pack(config)); extra.config=vm::load_cell_slice_ref(c);
  TRY_RESULT(e,pack(extra)); state.custom=vm::CellBuilder().store_long(1,1).store_ref(e).as_cellslice_ref();
  TRY_RESULT(result,pack(state));
  return M3TestParam84Replacement{result,synchronized};
}
} // namespace block::m3_test
