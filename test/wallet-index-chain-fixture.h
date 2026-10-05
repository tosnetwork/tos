/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Real basechain blocks and shard states for wallet-index tests: block and
// state cells in the on-chain layout the indexer parses, built field by field
// with the generated TL-B packers, so the indexer's production walk and its
// state lookups run on them unchanged.
#pragma once

#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "td/utils/bits.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

namespace wallet_index_fixture {

inline void require(bool ok, const char *what) {
  if (!ok) {
    throw std::runtime_error(std::string("wallet-index fixture: ") + what);
  }
}

// An internal wc=0 address as a cell slice: addr_std$10 anycast:nothing$0.
inline td::Ref<vm::Cell> address_cell(const td::Bits256 &address) {
  vm::CellBuilder cb;
  require(cb.store_long_bool(4, 3) && cb.store_long_bool(0, 8) && cb.store_bits_bool(address.bits(), 256), "address");
  return cb.finalize();
}

// One transaction of `account` at `lt` whose inbound external message body
// starts with `op` (0: no body).
struct Tx {
  td::Bits256 account;
  uint64_t lt;
  uint32_t op;
};

inline td::Ref<vm::Cell> inbound_message(const td::Bits256 &account, uint32_t op) {
  vm::CellBuilder cb;
  // ext_in_msg_info$10 src:addr_none$00 dest:addr_std import_fee:Tomis(0)
  require(cb.store_long_bool(2, 2) && cb.store_long_bool(0, 2) && cb.store_long_bool(4, 3) &&
              cb.store_long_bool(0, 8) && cb.store_bits_bool(account.bits(), 256) && cb.store_long_bool(0, 4),
          "message info");
  // init:nothing$0 body:(Either X ^X) inline$0, then the op
  require(cb.store_long_bool(0, 1) && cb.store_long_bool(0, 1), "message init/body");
  if (op != 0) {
    require(cb.store_long_bool(op, 32) && cb.store_long_bool(0, 64), "message op");
  }
  return cb.finalize();
}

inline td::Ref<vm::Cell> transaction(const Tx &tx) {
  vm::CellBuilder aux;
  // in_msg:(Maybe ^(Message Any)) out_msgs:(HashmapE 15 ^(Message Any))
  require(
      aux.store_long_bool(1, 1) && aux.store_ref_bool(inbound_message(tx.account, tx.op)) && aux.store_long_bool(0, 1),
      "transaction aux");
  vm::CellBuilder update;
  require(update.store_long_bool(0x72, 8) && update.store_zeroes_bool(512), "hash update");
  vm::CellBuilder description;
  require(description.store_long_bool(0, 4), "description");
  vm::CellBuilder cb;
  require(cb.store_long_bool(7, 4)                           // transaction$0111
              && cb.store_bits_bool(tx.account.bits(), 256)  // account_addr
              && cb.store_long_bool(static_cast<long long>(tx.lt), 64) && cb.store_zeroes_bool(256) &&
              cb.store_long_bool(0, 64)                // prev_trans_hash, prev_trans_lt
              && cb.store_long_bool(1000, 32)          // now
              && cb.store_long_bool(0, 15)             // outmsg_cnt
              && cb.store_long_bool(2, 2)              // orig_status: active
              && cb.store_long_bool(2, 2)              // end_status: active
              && cb.store_ref_bool(aux.finalize())     // ^[in_msg out_msgs]
              && cb.store_long_bool(0, 4)              // total_fees: Tomis 0
              && cb.store_long_bool(0, 1)              //   extra: empty
              && cb.store_ref_bool(update.finalize())  // state_update
              && cb.store_ref_bool(description.finalize()),
          "transaction");
  auto cell = cb.finalize();
  block::gen::Transaction::Record check;
  require(tlb::unpack_cell(cell, check), "transaction does not parse");
  return cell;
}

inline td::Ref<vm::Cell> account_blocks(const std::vector<Tx> &txs) {
  std::map<td::Bits256, std::vector<const Tx *>> by_account;
  for (const auto &tx : txs) {
    by_account[tx.account].push_back(&tx);
  }
  vm::AugmentedDictionary blocks{256, block::tlb::aug_ShardAccountBlocks};
  for (const auto &entry : by_account) {
    vm::AugmentedDictionary trans{64, block::tlb::aug_AccountTransactions};
    for (const auto *tx : entry.second) {
      require(trans.set_ref(td::BitArray<64>{static_cast<long long>(tx->lt)}, transaction(*tx),
                            vm::Dictionary::SetMode::Add),
              "account transaction");
    }
    vm::CellBuilder cb;
    auto root = std::move(trans).extract_root_cell();
    vm::CellBuilder update;
    require(update.store_long_bool(0x72, 8) && update.store_zeroes_bool(512), "account update");
    require(cb.store_long_bool(5, 4) && cb.store_bits_bool(entry.first.bits(), 256) && root.not_null() &&
                cb.append_cellslice_bool(vm::load_cell_slice(root)) && cb.store_ref_bool(update.finalize()),
            "account block");
    require(blocks.set(entry.first.bits(), 256, vm::load_cell_slice_ref(cb.finalize()), vm::Dictionary::SetMode::Add),
            "account blocks");
  }
  vm::CellBuilder cb;
  require(std::move(blocks).append_dict_to_bool(cb), "account blocks root");
  return cb.finalize();
}

// A basechain block (shard: the whole basechain) holding `txs`.
inline td::Ref<vm::Cell> block(uint32_t seqno, uint64_t end_lt, uint32_t gen_utime, const std::vector<Tx> &txs) {
  block::gen::BlockInfo::Record info;
  info.version = 0;
  info.not_master = true;
  info.after_merge = info.before_split = info.after_split = false;
  info.want_split = info.want_merge = false;
  info.key_block = info.vert_seqno_incr = false;
  info.flags = 0;
  info.seq_no = seqno;
  info.vert_seq_no = 0;
  vm::CellBuilder shard;
  require(block::ShardId{tos::ShardIdFull{0, tos::shardIdAll}}.serialize(shard), "shard");
  info.shard = shard.as_cellslice_ref();
  info.gen_utime = gen_utime;
  info.start_lt = end_lt > 100 ? end_lt - 100 : 0;
  info.end_lt = end_lt;
  info.gen_validator_list_hash_short = 0;
  info.gen_catchain_seqno = 0;
  info.min_ref_mc_seqno = 0;
  info.prev_key_block_seqno = 0;
  vm::CellBuilder ext_ref;
  require(ext_ref.store_long_bool(0, 64) && ext_ref.store_long_bool(0, 32) && ext_ref.store_zeroes_bool(512),
          "ext blk ref");
  auto ext_ref_cell = ext_ref.finalize();
  info.master_ref = ext_ref_cell;
  vm::CellBuilder prev_ref;
  require(prev_ref.store_long_bool(0, 64) && prev_ref.store_long_bool(seqno - 1, 32) && prev_ref.store_zeroes_bool(512),
          "prev ref");
  info.prev_ref = prev_ref.finalize();
  td::Ref<vm::Cell> info_cell;
  require(block::gen::t_BlockInfo.cell_pack(info_cell, info), "block info");

  vm::CellBuilder empty_builder;
  empty_builder.store_long(0, 1);
  auto empty = empty_builder.finalize();
  block::gen::BlockExtra::Record extra;
  extra.in_msg_descr = empty;
  extra.out_msg_descr = empty;
  extra.account_blocks = account_blocks(txs);
  extra.rand_seed.set_zero();
  extra.created_by.set_zero();
  vm::CellBuilder custom;
  custom.store_long(0, 1);
  extra.custom = custom.as_cellslice_ref();
  td::Ref<vm::Cell> extra_cell;
  require(block::gen::t_BlockExtra.cell_pack(extra_cell, extra), "block extra");

  vm::CellBuilder flow;
  flow.store_long(0, 1);
  auto prior_state = vm::CellBuilder{}.store_long(1, 32).finalize();
  auto next_state = vm::CellBuilder{}.store_long(2, 32).finalize();
  auto update = vm::CellBuilder::create_merkle_update(prior_state, next_state);
  vm::CellBuilder root;
  require(root.store_long_bool(0x11ef55aa, 32) && root.store_long_bool(0, 32) && root.store_ref_bool(info_cell) &&
              root.store_ref_bool(flow.finalize()) && root.store_ref_bool(update) && root.store_ref_bool(extra_cell),
          "block root");
  auto cell = root.finalize();
  block::gen::Block::Record blk;
  block::gen::BlockInfo::Record parsed_info;
  block::gen::BlockExtra::Record parsed_extra;
  require(tlb::unpack_cell(cell, blk) && tlb::unpack_cell(blk.info, parsed_info) &&
              tlb::unpack_cell(blk.extra, parsed_extra),
          "block does not parse");
  return cell;
}

// An active account with `code` and `data`.
struct Contract {
  td::Bits256 address;
  td::Ref<vm::Cell> code;
  td::Ref<vm::Cell> data;
};

// An active account whose state has no code: nothing can be run on it, so
// any verification of it is indeterminate.
inline Contract without_code(const td::Bits256 &address) {
  return Contract{address, td::Ref<vm::Cell>{}, vm::CellBuilder{}.store_long(3, 8).finalize()};
}

inline td::Ref<vm::Cell> account(const Contract &contract) {
  vm::CellBuilder cb;
  require(cb.store_long_bool(1, 1)  // account$1
              && cb.store_long_bool(4, 3) && cb.store_long_bool(0, 8) &&
              cb.store_bits_bool(contract.address.bits(), 256)         // addr
              && cb.store_long_bool(0, 3) && cb.store_long_bool(0, 3)  // used: cells 0, bits 0
              && cb.store_long_bool(0, 3)                              // storage_extra_none
              && cb.store_long_bool(0, 32)                             // last_paid
              && cb.store_long_bool(0, 1)                              // due_payment: nothing
              && cb.store_long_bool(0, 64)                             // last_trans_lt
              && cb.store_long_bool(0, 4) && cb.store_long_bool(0, 1)  // balance: 0, no extra
              && cb.store_long_bool(1, 1)                              // account_active
              && cb.store_long_bool(0, 1) && cb.store_long_bool(0, 1)  // fixed_prefix_length, special
              && (contract.code.is_null() ? cb.store_long_bool(0, 1)
                                          : cb.store_long_bool(1, 1) && cb.store_ref_bool(contract.code))  // code
              && cb.store_long_bool(1, 1) && cb.store_ref_bool(contract.data)                              // data
              && cb.store_long_bool(0, 1),                                                                 // library
          "account");
  return cb.finalize();
}

// A jetton wallet whose get_wallet_data answers (0, owner, master, code),
// whatever it is asked.
inline Contract jetton_wallet(const td::Bits256 &address, const td::Bits256 &owner, const td::Bits256 &master) {
  vm::CellBuilder code;
  // DROP (the method id), PUSHINT 0, PUSHREFSLICE owner, PUSHREFSLICE master, PUSHREF code
  require(code.store_long_bool(0x30, 8) && code.store_long_bool(0x70, 8) && code.store_long_bool(0x89, 8) &&
              code.store_long_bool(0x89, 8) && code.store_long_bool(0x88, 8) &&
              code.store_ref_bool(address_cell(owner)) && code.store_ref_bool(address_cell(master)) &&
              code.store_ref_bool(vm::CellBuilder{}.finalize()),
          "wallet code");
  return Contract{address, code.finalize(), vm::CellBuilder{}.store_long(1, 8).finalize()};
}

// A jetton master whose get_wallet_address answers `wallet` for any owner.
inline Contract jetton_master(const td::Bits256 &address, const td::Bits256 &wallet) {
  vm::CellBuilder code;
  // DROP (the method id), DROP (the owner), PUSHREFSLICE wallet
  require(code.store_long_bool(0x30, 8) && code.store_long_bool(0x30, 8) && code.store_long_bool(0x89, 8) &&
              code.store_ref_bool(address_cell(wallet)),
          "master code");
  return Contract{address, code.finalize(), vm::CellBuilder{}.store_long(2, 8).finalize()};
}

// An NFT item whose get_nft_data answers (-1, 0, collection, owner, content).
inline Contract nft_item(const td::Bits256 &address, const td::Bits256 &collection, const td::Bits256 &owner) {
  vm::CellBuilder code;
  // DROP (the method id), PUSHINT -1, PUSHINT 0, PUSHREFSLICE collection,
  // PUSHREFSLICE owner, PUSHREF content
  require(code.store_long_bool(0x30, 8) && code.store_long_bool(0x7F, 8) && code.store_long_bool(0x70, 8) &&
              code.store_long_bool(0x89, 8) && code.store_long_bool(0x89, 8) && code.store_long_bool(0x88, 8) &&
              code.store_ref_bool(address_cell(collection)) && code.store_ref_bool(address_cell(owner)) &&
              code.store_ref_bool(vm::CellBuilder{}.finalize()),
          "item code");
  return Contract{address, code.finalize(), vm::CellBuilder{}.store_long(4, 8).finalize()};
}

// An NFT collection whose get_nft_address_by_index answers `item` for any
// index.
inline Contract nft_collection(const td::Bits256 &address, const td::Bits256 &item) {
  vm::CellBuilder code;
  // DROP (the method id), DROP (the index), PUSHREFSLICE item
  require(code.store_long_bool(0x30, 8) && code.store_long_bool(0x30, 8) && code.store_long_bool(0x89, 8) &&
              code.store_ref_bool(address_cell(item)),
          "collection code");
  return Contract{address, code.finalize(), vm::CellBuilder{}.store_long(5, 8).finalize()};
}

// The post-apply state of the whole basechain holding `contracts`.
inline td::Ref<vm::Cell> shard_state(const std::vector<Contract> &contracts) {
  vm::AugmentedDictionary accounts{256, block::tlb::aug_ShardAccounts};
  for (const auto &contract : contracts) {
    vm::CellBuilder cb;
    require(cb.store_ref_bool(account(contract)) && cb.store_zeroes_bool(256 + 64) &&
                accounts.set_builder(contract.address.bits(), 256, cb, vm::Dictionary::SetMode::Add),
            "shard account");
  }
  vm::CellBuilder accounts_cb;
  require(std::move(accounts).append_dict_to_bool(accounts_cb), "accounts root");
  vm::CellBuilder aux;
  require(aux.store_long_bool(0, 64) && aux.store_long_bool(0, 64)       // overload/underload history
              && aux.store_long_bool(0, 5) && aux.store_long_bool(0, 5)  // total_balance, validator fees
              && aux.store_long_bool(0, 1)                               // libraries
              && aux.store_long_bool(0, 1),                              // master_ref
          "state aux");
  vm::CellBuilder shard;
  require(block::ShardId{tos::ShardIdFull{0, tos::shardIdAll}}.serialize(shard), "state shard");
  vm::CellBuilder cb;
  require(cb.store_long_bool(0x9023afe2, 32) && cb.store_long_bool(0, 32) && cb.append_builder_bool(shard) &&
              cb.store_long_bool(0, 32) && cb.store_long_bool(0, 32) && cb.store_long_bool(0, 32) &&
              cb.store_long_bool(0, 64) && cb.store_long_bool(0, 32) &&
              cb.store_ref_bool(vm::CellBuilder{}.finalize())  // out_msg_queue_info (not read)
              && cb.store_long_bool(0, 1)                      // before_split
              && cb.store_ref_bool(accounts_cb.finalize()) && cb.store_ref_bool(aux.finalize()) &&
              cb.store_long_bool(0, 1),  // custom: nothing
          "shard state");
  auto cell = cb.finalize();
  block::gen::ShardStateUnsplit::Record check;
  require(tlb::unpack_cell(cell, check), "state does not parse");
  return cell;
}

}  // namespace wallet_index_fixture
