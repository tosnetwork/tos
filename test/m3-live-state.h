#pragma once
// TEST ONLY. Read the accepted disk candidate and apply its actual Merkle update.
// No detached engine effects or proposer-side proof files supply resulting state.
#include "tl-utils/common-utils.hpp"
#include "tos/tos-tl.hpp"
#include "vm/cells/MerkleUpdate.h"
#include "crypto/test/workchain-m3-assertions.h"

namespace m3_live {
struct AcceptedStep {
  tos::BlockIdExt id;
  td::Ref<vm::Cell> block;
  td::Ref<vm::Cell> state;
};
// Initial M4 assertion hook, exercised on every accepted M3 block before real
// Deposit integration. The operation set below has no terminal Deposit, hence
// cumulative locked principal and cross-block D are zero. Never infer backing
// from the M3 test-funded confidential balances: that funding is not M4 Deposit.
// Retire test funding only after real Deposit replacement passes per-block
// conservation and same-path ON/OFF acceptance, not before M3 regression passes.
inline td::Status check_m4_backing(const td::RefInt256& actual,
                                   const td::RefInt256& locked, const td::RefInt256& pending_deposit) {
  if (actual.is_null() || locked.is_null() || pending_deposit.is_null() ||
      !actual->is_valid() || !locked->is_valid() || !pending_deposit->is_valid() ||
      td::sgn(actual) < 0 || td::sgn(locked) < 0 || td::sgn(pending_deposit) != 0 || td::cmp(actual, locked) != 0) {
    return td::Status::Error("M4 per-block backing mismatch or nonzero cross-block D");
  }
  return td::Status::OK();
}
inline void assert_pre_deposit_backing(const AcceptedStep& step, const td::Bits256& custody) {
  block::gen::ShardStateUnsplit::Record state;
  CHECK(tlb::unpack_cell(step.state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  auto leaf = accounts.lookup(custody);
  td::RefInt256 actual = td::make_refint(0);
  // An absent leaf in the authenticated dictionary represents no custody coins;
  // malformed present state is never interpreted as zero.
  if (leaf.not_null()) {
    block::Account account(2, custody.bits());
    CHECK(account.unpack(leaf, state.gen_utime, false));
    actual = account.balance.tomis;
  }
  check_m4_backing(actual, td::make_refint(0), td::make_refint(0)).ensure();
  std::cout << "M4 pre-Deposit block=" << step.id.to_str()
            << " R_actual=" << actual << " R_book=0 D=0 P=0 W=0 checked\n";
}
inline AcceptedStep read_accepted_step(const std::filesystem::path& exported, td::Ref<vm::Cell> previous) {
  auto candidate = tos::fetch_tl_object<tos::tos_api::db_candidate>(
      td::read_file(exported.string()).move_as_ok(), true).move_as_ok();
  auto id = tos::create_block_id(candidate->id_);
  auto root = vm::std_boc_deserialize(candidate->data_.as_slice()).move_as_ok();
  CHECK(td::Bits256(root->get_hash().bits()) == id.root_hash && td::sha256_bits256(candidate->data_) == id.file_hash);
  block::gen::Block::Record record;
  CHECK(tlb::unpack_cell(root, record));
  auto next = vm::MerkleUpdate::apply(std::move(previous), record.state_update).move_as_ok();
  return {id, root, next};
}
inline td::Ref<vm::Cell> account_data(const td::Ref<vm::Cell>& root, const td::Bits256& key) {
  block::gen::ShardStateUnsplit::Record state;
  CHECK(tlb::unpack_cell(root, state));
  vm::AugmentedDictionary dictionary(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, key.bits());
  CHECK(account.unpack(dictionary.lookup(key), state.gen_utime, false));
  CHECK(account.status == block::Account::acc_active && account.data.not_null());
  return account.data;
}
inline td::Ref<vm::Cell> accepted_transaction(const AcceptedStep& step, const td::Bits256& key) {
  block::gen::ShardStateUnsplit::Record state;
  CHECK(tlb::unpack_cell(step.state, state));
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, key.bits());
  CHECK(account.unpack(accounts.lookup(key), state.gen_utime, false));
  block::gen::Block::Record header;
  block::gen::BlockExtra::Record extra;
  CHECK(tlb::unpack_cell(step.block, header) && tlb::unpack_cell(header.extra, extra));
  vm::AugmentedDictionary blocks(vm::load_cell_slice_ref(extra.account_blocks), 256,
                                block::tlb::aug_ShardAccountBlocks);
  auto leaf = blocks.lookup(key);
  block::gen::AccountBlock::Record record;
  CHECK(leaf.not_null() && block::gen::t_AccountBlock.unpack(leaf.write(), record) && leaf->empty());
  CHECK(record.account_addr == key);
  vm::AugmentedDictionary transactions(vm::DictNonEmpty(), record.transactions, 64,
                                      block::tlb::aug_AccountTransactions);
  auto transaction = transactions.lookup_ref(td::BitArray<64>(account.last_trans_lt_));
  CHECK(transaction.not_null() && account.last_trans_hash_ == transaction->get_hash().bits());
  return transaction;
}
}  // namespace m3_live
