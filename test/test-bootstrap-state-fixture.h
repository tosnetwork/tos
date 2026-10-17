// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <memory>
#include <string>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "tos/tos-types.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/cells/UsageCell.h"
#include "vm/dict.h"
#include "vm/vm.h"

namespace tos::validator::bootstrap_test {

struct SplitFixture {
  RootHash state_root_hash;
  ShardId effective_shard;
  td::Ref<vm::Cell> wrapped_header;
  td::Ref<vm::Cell> account_part;
  td::BufferSlice header_boc;
  td::BufferSlice part_boc;
};

// Keep one populated half of the existing legitimate account dictionary.
// Its sibling is empty and must not become a required archive file. Build
// the header through the same Merkle usage-tree operations as the serializer.
inline SplitFixture make_split_fixture(const std::string& genesis_path) {
  ASSERT_TRUE(vm::init_vm().is_ok());
  auto encoded = td::read_file(genesis_path);
  ASSERT_TRUE(encoded.is_ok());
  auto decoded = vm::std_boc_deserialize(encoded.move_as_ok());
  ASSERT_TRUE(decoded.is_ok());
  block::gen::ShardStateUnsplit::Record state;
  ASSERT_TRUE(tlb::unpack_cell(decoded.move_as_ok(), state));

  vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts};
  constexpr ShardId left = 1ULL << 62;
  constexpr ShardId right = (1ULL << 63) | left;
  ShardId chosen = left;
  td::BitArray<64> prefix;
  auto selected = [&] {
    prefix.store_ulong(chosen);
    auto left_half = accounts;
    ASSERT_TRUE(left_half.cut_prefix_subdict(prefix.cbits(), 1));
    if (!left_half.is_empty()) {
      return left_half;
    }
    chosen = right;
    prefix.store_ulong(chosen);
    auto right_half = accounts;
    ASSERT_TRUE(right_half.cut_prefix_subdict(prefix.cbits(), 1));
    return right_half;
  }();
  ASSERT_TRUE(!selected.is_empty());
  state.accounts = selected.get_wrapped_dict_root();
  auto total = selected.get_root_extra();
  ASSERT_TRUE(total.write().advance(5));
  block::CurrencyCollection balance;
  ASSERT_TRUE(balance.validate_unpack(total));
  ASSERT_TRUE(balance.pack_to(state.r1.total_balance));
  vm::CellBuilder shard;
  ASSERT_TRUE(block::tlb::t_ShardIdent.pack(shard, ShardIdFull{basechainId, shardIdAll}));
  state.shard_id = shard.as_cellslice_ref();
  state.seq_no = 1;
  state.custom = vm::CellBuilder().store_long(0, 1).as_cellslice_ref();
  td::Ref<vm::Cell> full_state;
  ASSERT_TRUE(tlb::pack_cell(full_state, state));

  auto unwrapped_accounts = state.accounts;
  auto usage = std::make_shared<vm::CellUsageTree>();
  auto tracked_root = vm::UsageCell::create(unwrapped_accounts, usage->root_ptr());
  vm::AugmentedDictionary tracked{vm::load_cell_slice_ref(tracked_root), 256, block::tlb::aug_ShardAccounts, false};
  td::Ref<vm::Cell> account_part;
  unsigned nonempty = 0;
  for (auto effective_shard : {left, right}) {
    prefix.store_ulong(effective_shard);
    auto part = tracked;
    ASSERT_TRUE(part.cut_prefix_subdict(prefix.cbits(), 1));
    if (!part.is_empty()) {
      ASSERT_EQ(effective_shard, chosen);
      account_part = part.get_wrapped_dict_root();
      ++nonempty;
    }
  }
  ASSERT_EQ(nonempty, 1u);

  auto proof = vm::MerkleProof::generate_raw(unwrapped_accounts, usage.get());
  ASSERT_TRUE(proof.is_ok());
  state.accounts = proof.move_as_ok();
  td::Ref<vm::Cell> header;
  ASSERT_TRUE(tlb::pack_cell(header, state));
  ASSERT_TRUE(header->get_hash(0) == full_state->get_hash());
  auto wrapped_header = vm::CellBuilder::create_merkle_proof(header);
  auto header_boc = vm::std_boc_serialize(wrapped_header, 31);
  auto part_boc = vm::std_boc_serialize(account_part, 31);
  ASSERT_TRUE(header_boc.is_ok());
  ASSERT_TRUE(part_boc.is_ok());
  return {RootHash{full_state->get_hash().bits()},
          chosen,
          std::move(wrapped_header),
          std::move(account_part),
          header_boc.move_as_ok(),
          part_boc.move_as_ok()};
}

}  // namespace tos::validator::bootstrap_test
