/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

// Real masterchain states for the consensus cleanup checkpoint tests, derived
// from a real genesis state. Each derived state records its predecessor in
// prev_blocks, so ancestry is answered by the production
// MasterchainState::check_old_mc_block_id, and its masterchain catchain seqno is
// its height, so cleanup's r < g comparison has real counters.
//
// The default chain is B0..B6 with a fork F4 <- F5 off B3. Callers can extend
// it with blocks at arbitrary heights (archive package boundaries).

#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>

#include "block/block-auto.h"
#include "block/block-db.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "td/utils/crypto.h"
#include "validator/impl/shard.hpp"
#include "vm/boc.h"
#include "vm/dict.h"

namespace tos::validator::checkpoint_chain {

struct ChainBlock {
  BlockIdExt id;
  td::Ref<MasterchainStateQ> state;
  std::optional<BlockIdExt> prev;
  std::optional<BlockIdExt> next;
};

struct Chain {
  td::BufferSlice genesis_boc;
  LogicalTime genesis_lt = 0;
  std::map<std::string, ChainBlock> blocks;
  const ChainBlock& operator[](const std::string& name) const {
    return blocks.at(name);
  }
};

inline td::Bits256 label_hash(td::Slice label) {
  return td::sha256_bits256(label);
}

// The state at `seqno` whose prev_blocks additionally records `prev`. Each step
// advances the generation time by `utime_step` seconds.
inline td::Result<td::Ref<vm::Cell>> derive_state(td::Ref<vm::Cell> prev_root, const BlockIdExt& prev, BlockSeqno seqno,
                                                  const BlockIdExt& genesis, LogicalTime genesis_lt,
                                                  td::uint32 utime_step) {
  block::gen::ShardStateUnsplit::Record info;
  if (!tlb::unpack_cell(prev_root, info)) {
    return td::Status::Error("cannot unpack the previous state");
  }
  auto prev_lt = info.gen_lt;
  info.seq_no = seqno;
  info.gen_utime += utime_step;
  info.gen_lt += 1000000;
  vm::CellSlice custom = *info.custom;
  if (custom.fetch_ulong(1) != 1) {
    return td::Status::Error("the previous state has no masterchain extra");
  }
  block::gen::McStateExtra::Record extra;
  if (!tlb::unpack_cell(custom.prefetch_ref(), extra)) {
    return td::Status::Error("cannot unpack McStateExtra");
  }
  vm::AugmentedDictionary dict{extra.r1.prev_blocks, 32, block::tlb::aug_OldMcBlocksInfo};
  vm::CellBuilder cb;
  if (!(cb.store_bool_bool(prev.seqno() == 0) && cb.store_long_bool(prev_lt, 64) &&
        cb.store_long_bool(prev.seqno(), 32) && cb.store_bits_bool(prev.root_hash) &&
        cb.store_bits_bool(prev.file_hash) &&
        dict.set_builder(td::BitArray<32>(prev.seqno()), cb, vm::Dictionary::SetMode::Add))) {
    return td::Status::Error("cannot add the previous block to prev_blocks");
  }
  extra.r1.prev_blocks = std::move(dict).extract_root();
  // The masterchain catchain seqno grows with the height, so cleanup's r < g
  // check has something to compare against.
  block::gen::ValidatorInfo::Record val_info;
  if (!tlb::csr_unpack(extra.r1.validator_info, val_info)) {
    return td::Status::Error("cannot unpack ValidatorInfo");
  }
  val_info.catchain_seqno = seqno;
  if (!tlb::csr_pack(extra.r1.validator_info, val_info)) {
    return td::Status::Error("cannot pack ValidatorInfo");
  }
  vm::CellBuilder last_key;
  if (!(last_key.store_bool_bool(true) && last_key.store_long_bool(genesis_lt, 64) &&
        last_key.store_long_bool(genesis.seqno(), 32) && last_key.store_bits_bool(genesis.root_hash) &&
        last_key.store_bits_bool(genesis.file_hash))) {
    return td::Status::Error("cannot store last_key_block");
  }
  extra.r1.last_key_block = vm::load_cell_slice_ref(last_key.finalize());
  extra.r1.after_key_block = prev.seqno() == 0;
  td::Ref<vm::Cell> extra_cell;
  if (!tlb::pack_cell(extra_cell, extra)) {
    return td::Status::Error("cannot pack McStateExtra");
  }
  vm::CellBuilder custom_cb;
  if (!(custom_cb.store_bool_bool(true) && custom_cb.store_ref_bool(extra_cell))) {
    return td::Status::Error("cannot store custom");
  }
  info.custom = vm::load_cell_slice_ref(custom_cb.finalize());
  td::Ref<vm::Cell> root;
  if (!tlb::pack_cell(root, info)) {
    return td::Status::Error("cannot pack the state");
  }
  return root;
}

// Adds block `name` at `seqno` on top of `parent`.
inline td::Status extend_chain(Chain& chain, const std::string& parent, const std::string& name, BlockSeqno seqno,
                               td::uint32 utime_step = 1) {
  const auto& p = chain.blocks.at(parent);
  const auto& zero = chain.blocks.at("B0").id;
  TRY_RESULT(state_root, derive_state(p.state->root_cell(), p.id, seqno, zero, chain.genesis_lt, utime_step));
  BlockIdExt id{masterchainId, shardIdAll, seqno, label_hash(PSLICE() << "checkpoint-root-" << name),
                label_hash(PSLICE() << "checkpoint-file-" << name)};
  TRY_RESULT(state, MasterchainStateQ::fetch(id, td::BufferSlice{}, state_root));
  chain.blocks[name] = ChainBlock{id, state, p.id, std::nullopt};
  return td::Status::OK();
}

inline td::Result<Chain> build_chain(const std::string& boc_path) {
  std::ifstream input(boc_path, std::ios::binary);
  std::ostringstream bytes;
  bytes << input.rdbuf();
  if (!input) {
    return td::Status::Error("cannot read the genesis BOC");
  }
  Chain chain;
  chain.genesis_boc = td::BufferSlice{bytes.str()};
  TRY_RESULT(root, vm::std_boc_deserialize(chain.genesis_boc.as_slice()));
  BlockIdExt zero{masterchainId, shardIdAll, 0, td::Bits256(root->get_hash().bits()),
                  block::compute_file_hash(chain.genesis_boc.as_slice())};
  TRY_RESULT(zero_state, MasterchainStateQ::fetch(zero, chain.genesis_boc.clone(), root));
  chain.genesis_lt = zero_state->get_logical_time();
  chain.blocks["B0"] = ChainBlock{zero, zero_state, std::nullopt, std::nullopt};
  for (BlockSeqno s = 1; s <= 6; s++) {
    TRY_STATUS(extend_chain(chain, PSTRING() << "B" << s - 1, PSTRING() << "B" << s, s));
    chain.blocks[PSTRING() << "B" << s - 1].next = chain.blocks[PSTRING() << "B" << s].id;
  }
  TRY_STATUS(extend_chain(chain, "B3", "F4", 4));
  TRY_STATUS(extend_chain(chain, "F4", "F5", 5));
  chain.blocks["F4"].next = chain.blocks["F5"].id;
  return chain;
}

}  // namespace tos::validator::checkpoint_chain
