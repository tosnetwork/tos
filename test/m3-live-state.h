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
