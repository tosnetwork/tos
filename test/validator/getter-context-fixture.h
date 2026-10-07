/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "fift/utils.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "vm/boc.h"
#include "vm/dict.h"

namespace getter_fixture {

using td::Ref;

[[noreturn]] inline void setup_failed(const std::string& message) {
  std::fprintf(stderr, "GETTER_CONTEXT_SETUP_FAILURE: %s\n", message.c_str());
  std::exit(2);
}

inline void require(bool ok, const std::string& message) {
  if (!ok) {
    setup_failed(message);
  }
}

template <class T>
T must(td::Result<T> result, const std::string& message) {
  if (result.is_error()) {
    setup_failed(message + ": " + result.error().message().str());
  }
  return result.move_as_ok();
}

inline td::Bits256 filled(unsigned char value) {
  td::Bits256 bits;
  bits.as_slice().fill(value);
  return bits;
}

inline Ref<vm::Cell> load(const std::string& path) {
  auto bytes = must(td::read_file(td::CSlice(path)), "read fixture " + path);
  return must(vm::std_boc_deserialize(bytes.as_slice()), "fixture BOC " + path);
}

inline td::BufferSlice boc(Ref<vm::Cell> root) {
  return must(vm::std_boc_serialize(std::move(root)), "serialize fixture");
}

inline Ref<vm::Cell> empty_dictionary() {
  return vm::CellBuilder{}.store_long(0, 1).finalize_novm();
}

inline Ref<vm::Cell> library_reference(const Ref<vm::Cell>& code) {
  vm::CellBuilder builder;
  require(builder.store_long_bool(static_cast<unsigned>(vm::Cell::SpecialType::Library), 8) &&
              builder.store_bits_bool(code->get_hash().bits(), 256),
          "library reference");
  return builder.finalize_novm(true);
}

inline Ref<vm::Cell> account_libraries(const Ref<vm::Cell>& code) {
  vm::Dictionary dictionary{256};
  vm::CellBuilder entry;
  require(entry.store_bool_bool(true) && entry.store_ref_bool(code), "account library entry");
  require(dictionary.set_builder(code->get_hash().bits(), 256, entry), "account library dictionary");
  return dictionary.get_root_cell();
}

struct Getter {
  std::string name;
  std::string method;
  block::StdAddress address;
  Ref<vm::Cell> code;
  Ref<vm::Cell> data;
  block::CurrencyCollection balance;
  td::RefInt256 due_payment{td::zero_refint()};
  Ref<vm::Cell> libraries{};
  std::vector<vm::StackEntry> arguments{};
};

inline Ref<vm::CellSlice> address_slice(const block::StdAddress& address) {
  vm::CellBuilder builder;
  require(block::tlb::t_MsgAddressInt.store_std_address(builder, address), "address");
  return builder.as_cellslice_ref();
}

inline Ref<vm::CellSlice> extended_reference(const tos::BlockIdExt& id, tos::LogicalTime end_lt) {
  vm::CellBuilder builder;
  require(builder.store_long_bool(static_cast<td::int64>(end_lt), 64) && builder.store_long_bool(id.seqno(), 32) &&
              builder.store_bits_bool(id.root_hash.cbits(), 256) && builder.store_bits_bool(id.file_hash.cbits(), 256),
          "extended block reference");
  return builder.as_cellslice_ref();
}

inline Ref<vm::Cell> shard_account(const Ref<vm::Cell>& account) {
  return vm::CellBuilder{}.store_ref(account).store_bits(filled(0x42).cbits(), 256).store_long(900, 64).finalize_novm();
}

inline Ref<vm::Cell> make_account(const Ref<vm::Cell>& original, const Getter& getter) {
  block::gen::Account::Record_account account;
  require(tlb::unpack_cell(original, account), "template account");
  account.addr = address_slice(getter.address);
  vm::CellBuilder storage;
  require(storage.store_long_bool(900, 64) && getter.balance.store(storage) && storage.store_bool_bool(true) &&
              storage.store_long_bool(0, 2) && storage.store_maybe_ref(getter.code) &&
              storage.store_maybe_ref(getter.data) && storage.store_maybe_ref(getter.libraries),
          "active account storage");
  account.storage = storage.as_cellslice_ref();
  // Account storage statistics and debt are decoded by the same path as a real query.
  block::gen::StorageInfo::Record info;
  require(tlb::csr_unpack(account.storage_stat, info), "storage statistics");
  vm::CellBuilder debt;
  require(debt.store_bool_bool(true) && block::tlb::t_Tomis.store_integer_value(debt, *getter.due_payment), "debt");
  info.due_payment = debt.as_cellslice_ref();
  Ref<vm::Cell> stats;
  require(tlb::pack_cell(stats, info), "storage statistics pack");
  account.storage_stat = vm::load_cell_slice_ref(stats);
  Ref<vm::Cell> result;
  require(tlb::pack_cell(result, account), "account pack");
  return result;
}

inline Ref<vm::Cell> proposal_data() {
  vm::Dictionary votes{256};
  for (unsigned index : {1U, 2U}) {
    vm::CellBuilder proposal;
    require(proposal.store_long_bool(0xf3, 8) && proposal.store_long_bool(1000 + index, 32) &&
                proposal.store_bool_bool(false) && proposal.store_bool_bool(false),
            "proposal");
    vm::CellBuilder record;
    require(record.store_long_bool(0xce, 8) && record.store_long_bool(1900000000, 32) &&
                record.store_ref_bool(proposal.finalize_novm()) && record.store_bool_bool(false) &&
                record.store_bool_bool(false) && record.store_long_bool(100, 64) &&
                record.store_bits_bool(filled(0x51).cbits(), 256) && record.store_long_bool(3, 8) &&
                record.store_long_bool(1, 8) && record.store_long_bool(2, 8),
            "proposal status");
    require(votes.set_builder(filled(static_cast<unsigned char>(index)).cbits(), 256, record), "vote dictionary");
  }
  vm::CellBuilder data;
  require(data.store_ref_bool(empty_dictionary()) && data.store_maybe_ref(votes.get_root_cell()), "proposal data");
  return data.finalize_novm();
}

struct State {
  Ref<vm::Cell> root;
  Ref<vm::Cell> block;
  tos::BlockIdExt id;
  std::unique_ptr<block::ConfigInfo> config;
  std::vector<Getter> getters;
  Ref<vm::Cell> account_library;
  Ref<vm::Cell> global_library;
  tos::UnixTime now{1789434100};
  tos::LogicalTime lt{1000};
};

inline State build(const std::string& zero_path, const std::string& elector_dir, const std::string& config_code_path,
                   int version = 17, bool global_library = true) {
  State fixture;
  auto zero_bytes = must(td::read_file(td::CSlice(zero_path)), "zerostate bytes");
  auto zero = must(vm::std_boc_deserialize(zero_bytes.as_slice()), "zerostate");
  tos::BlockIdExt zero_id{tos::masterchainId, tos::shardIdAll, 0, td::Bits256{zero->get_hash().bits()}, td::Bits256{}};
  td::sha256(zero_bytes.as_slice(), zero_id.file_hash.as_slice());
  block::gen::ShardStateUnsplit::Record state;
  require(tlb::unpack_cell(zero, state), "state header");
  vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts};
  auto template_slice = accounts.lookup(filled(0x33));
  require(template_slice.not_null(), "elector account");
  auto original = template_slice->prefetch_ref();

  auto elector_code = load(elector_dir + "/elector-code.boc");
  auto elector_data = load(elector_dir + "/elector-data.boc");
  auto wide_balance = block::CurrencyCollection{td::make_refint(1) << 100};
  vm::Dictionary extras{32};
  vm::CellBuilder extra_amount;
  require(extra_amount.store_long_bool(1, 5) && extra_amount.store_long_bool(77, 8), "extra currency amount");
  require(extras.set_builder(td::BitArray<32>{7}.cbits(), 32, extra_amount), "extra currency");
  wide_balance.extra = extras.get_root_cell();
  Getter participant{"participants",
                     "participant_list_extended",
                     {tos::masterchainId, filled(0x33)},
                     elector_code,
                     elector_data,
                     block::CurrencyCollection{td::make_refint(10000000000ULL)}};
  Getter active = participant;
  active.name = "election-id";
  active.method = "active_election_id";
  Getter returned = participant;
  returned.name = "returned-stake";
  returned.method = "compute_returned_stake";
  returned.arguments.emplace_back(td::make_refint(12345));
  Getter proposal{"proposals",
                  "list_proposals",
                  {tos::masterchainId, filled(0x55)},
                  load(config_code_path),
                  proposal_data(),
                  block::CurrencyCollection{td::make_refint(20000000000ULL)}};
  Getter peek{"context-fields",
              "context_fields",
              {tos::masterchainId, filled(0x77)},
              must(fift::compile_asm("DROP NOW LTIME BALANCE MYADDR"), "context getter"),
              vm::CellBuilder{}.finalize_novm(),
              wide_balance};
  peek.due_payment = td::make_refint(123456789);
  fixture.getters = {participant, active, returned, proposal, peek};
  for (const auto& getter : {participant, proposal, peek}) {
    require(accounts.set(getter.address.addr.cbits(), 256,
                         vm::load_cell_slice_ref(shard_account(make_account(original, getter)))),
            "install fixture account");
  }
  vm::CellBuilder accounts_builder;
  require(accounts_builder.append_cellslice_bool(accounts.get_root()), "accounts root");
  state.accounts = accounts_builder.finalize_novm();

  block::gen::McStateExtra::Record extra;
  require(tlb::unpack_cell(state.custom->prefetch_ref(), extra), "state extra");
  vm::Dictionary config{extra.config->prefetch_ref(), 32};
  require(
      config.set_ref(td::BitArray<32>{8},
                     vm::CellBuilder{}.store_long(0xc4, 8).store_long(version, 32).store_long(0, 64).finalize_novm()),
      "global version");
  vm::Dictionary precompiled{256};
  require(precompiled.set_builder(peek.code->get_hash().bits(), 256,
                                  vm::CellBuilder{}.store_long(0xb0, 8).store_long(43210, 64)),
          "precompiled entry");
  vm::CellBuilder precompiled_field;
  require(precompiled_field.store_long_bool(0xc0, 8) && precompiled_field.store_maybe_ref(precompiled.get_root_cell()),
          "precompiled field");
  require(config.set_ref(td::BitArray<32>{45}, precompiled_field.finalize_novm()), "precompiled configuration");
  vm::CellSlice old_config = *extra.config;
  td::Bits256 config_address;
  require(old_config.fetch_bits_to(config_address), "config address");
  vm::CellBuilder config_field;
  require(
      config_field.store_bits_bool(config_address.cbits(), 256) && config_field.store_ref_bool(config.get_root_cell()),
      "config field");
  extra.config = config_field.as_cellslice_ref();

  vm::AugmentedDictionary previous{extra.r1.prev_blocks, 32, block::tlb::aug_OldMcBlocksInfo};
  vm::CellBuilder old;
  require(old.store_bool_bool(true) && old.append_cellslice_bool(extended_reference(zero_id, 1)), "previous block");
  td::BitArray<32> zero_key;
  zero_key.as_slice().fill(0);
  require(previous.set(zero_key.cbits(), 32, old.as_cellslice_ref()), "previous dictionary");
  extra.r1.prev_blocks = previous.get_root();
  extra.r1.after_key_block = false;
  vm::CellBuilder last_key;
  require(last_key.store_bool_bool(true) && last_key.append_cellslice_bool(extended_reference(zero_id, 1)), "last key");
  extra.r1.last_key_block = last_key.as_cellslice_ref();
  Ref<vm::Cell> extra_cell;
  require(tlb::pack_cell(extra_cell, extra), "extra pack");
  state.custom = vm::CellBuilder{}.store_long(1, 1).store_ref(extra_cell).as_cellslice_ref();

  auto library = must(fift::compile_asm("DROP 17 PUSHINT"), "global library code");
  auto account_library_code = must(fift::compile_asm("DROP 23 PUSHINT"), "account library code");
  fixture.account_library = account_libraries(account_library_code);
  fixture.global_library = library;
  vm::Dictionary public_libraries{256};
  if (global_library) {
    vm::Dictionary publishers{256};
    require(publishers.set_builder(peek.address.addr.cbits(), 256, vm::CellBuilder{}), "publisher");
    vm::CellBuilder descriptor;
    require(descriptor.store_long_bool(0, 2) && descriptor.store_ref_bool(library) &&
                descriptor.append_cellslice_bool(vm::load_cell_slice(publishers.get_root_cell())),
            "public library");
    require(public_libraries.set(library->get_hash().bits(), 256, descriptor.as_cellslice_ref()), "public libraries");
  }
  vm::CellBuilder libraries_field;
  require(libraries_field.store_maybe_ref(public_libraries.get_root_cell()), "libraries field");
  state.r1.libraries = libraries_field.as_cellslice_ref();
  state.seq_no = 1;
  state.gen_utime = fixture.now;
  state.gen_lt = fixture.lt;
  state.min_ref_mc_seqno = 0;
  require(tlb::pack_cell(fixture.root, state), "state pack");

  block::gen::BlockInfo::Record info;
  info.version = 0;
  info.not_master = info.after_merge = info.before_split = info.after_split = false;
  info.want_split = info.want_merge = info.key_block = info.vert_seqno_incr = false;
  info.flags = 0;
  info.seq_no = 1;
  info.vert_seq_no = 0;
  vm::CellBuilder shard;
  block::ShardId{tos::ShardIdFull{tos::masterchainId}}.serialize(shard);
  info.shard = shard.as_cellslice_ref();
  info.gen_utime = fixture.now;
  info.start_lt = 900;
  info.end_lt = fixture.lt;
  info.gen_validator_list_hash_short = info.gen_catchain_seqno = 0;
  info.min_ref_mc_seqno = info.prev_key_block_seqno = 0;
  info.prev_ref = extended_reference(zero_id, 1)->get_base_cell();
  Ref<vm::Cell> info_cell;
  require(block::gen::t_BlockInfo.cell_pack(info_cell, info), "block info");
  vm::CellBuilder update;
  require(update.store_long_bool(static_cast<unsigned>(vm::Cell::SpecialType::MerkleUpdate), 8) &&
              update.store_bits_bool(zero->get_hash(0).bits(), 256) &&
              update.store_bits_bool(fixture.root->get_hash(0).bits(), 256) &&
              update.store_long_bool(zero->get_depth(0), 16) &&
              update.store_long_bool(fixture.root->get_depth(0), 16) && update.store_ref_bool(zero) &&
              update.store_ref_bool(fixture.root),
          "state update");
  fixture.block = vm::CellBuilder{}
                      .store_long(0x11ef55aa, 32)
                      .store_long(state.global_id, 32)
                      .store_ref(info_cell)
                      .store_ref(empty_dictionary())
                      .store_ref(update.finalize_novm(true))
                      .store_ref(empty_dictionary())
                      .finalize_novm();
  auto block_bytes = boc(fixture.block);
  fixture.id = tos::BlockIdExt{tos::masterchainId, tos::shardIdAll, 1, td::Bits256{fixture.block->get_hash().bits()},
                               td::Bits256{}};
  td::sha256(block_bytes.as_slice(), fixture.id.file_hash.as_slice());
  fixture.config =
      must(block::ConfigInfo::extract_config(fixture.root, fixture.id,
                                             block::ConfigInfo::needLibraries | block::ConfigInfo::needCapabilities |
                                                 block::ConfigInfo::needPrevBlocks),
           "configuration");
  must(fixture.config->get_prev_blocks_info(), "complete previous-block context");
  return fixture;
}

}  // namespace getter_fixture
