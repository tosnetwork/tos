/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Proofs a lite server builds must carry every header cell the lite client reads when it
// checks them. Each case builds a proof the way the server does, from a real block, and
// verifies it with the client-side check.
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "block/check-proof.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "validator/impl/liteserver.hpp"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/dict.h"

namespace {

int failures = 0;

void check(const std::string& name, bool ok, const std::string& detail = "") {
  std::printf("LITE_PROOF_CASE %s %s%s%s\n", name.c_str(), ok ? "PASS" : "FAIL", detail.empty() ? "" : " : ",
              detail.c_str());
  if (!ok) {
    ++failures;
  }
}

struct LoadedBlock {
  std::string name;
  td::Ref<vm::Cell> root;
  tos::BlockIdExt id;
};

td::Result<LoadedBlock> load_block(const std::string& path) {
  TRY_RESULT(data, td::read_file(path));
  LoadedBlock res;
  res.name = std::filesystem::path(path).filename().string();
  TRY_RESULT_ASSIGN(res.root, vm::std_boc_deserialize(data.as_slice()));
  block::gen::Block::Record blk;
  block::gen::BlockInfo::Record info;
  tos::ShardIdFull shard;
  if (!(tlb::unpack_cell(res.root, blk) && tlb::unpack_cell(blk.info, info) &&
        block::tlb::t_ShardIdent.unpack(info.shard.write(), shard))) {
    return td::Status::Error("cannot unpack block header");
  }
  res.id.id = tos::BlockId{shard, static_cast<tos::BlockSeqno>(info.seq_no)};
  res.id.root_hash = res.root->get_hash().bits();
  td::sha256(data.as_slice(), res.id.file_hash.as_slice());
  return res;
}

// The same block with its header changed by `edit`; the block id follows the new root hash.
template <class F>
td::Result<LoadedBlock> with_header(const LoadedBlock& b, const std::string& suffix, F&& edit) {
  block::gen::Block::Record blk;
  block::gen::BlockInfo::Record info;
  if (!(tlb::unpack_cell(b.root, blk) && tlb::unpack_cell(blk.info, info))) {
    return td::Status::Error("cannot unpack block header");
  }
  edit(info);
  td::Ref<vm::Cell> root;
  if (!(tlb::pack_cell(blk.info, info) && tlb::pack_cell(root, blk))) {
    return td::Status::Error("cannot pack block header");
  }
  LoadedBlock res{b.name + suffix, root, b.id};
  res.id.root_hash = root->get_hash().bits();
  return res;
}

// The first transaction of the first account in the block, if any.
bool first_transaction(const td::Ref<vm::Cell>& root, tos::StdSmcAddress& addr, tos::LogicalTime& lt) {
  block::gen::Block::Record blk;
  block::gen::BlockExtra::Record extra;
  if (!(tlb::unpack_cell(root, blk) && tlb::unpack_cell(blk.extra, extra))) {
    return false;
  }
  vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(extra.account_blocks), 256,
                                   block::tlb::aug_ShardAccountBlocks};
  if (accounts.is_empty() || accounts.get_minmax_key(addr).is_null()) {
    return false;
  }
  auto value = accounts.lookup(addr);
  if (value.is_null()) {
    return false;
  }
  block::gen::AccountBlock::Record acc_block;
  if (!tlb::csr_unpack(std::move(value), acc_block)) {
    return false;
  }
  vm::AugmentedDictionary trans_dict{vm::DictNonEmpty(), acc_block.transactions, 64,
                                     block::tlb::aug_AccountTransactions};
  td::BitArray<64> key;
  if (trans_dict.get_minmax_key(key).is_null()) {
    return false;
  }
  lt = key.to_ulong();
  return true;
}

void check_state_root_proof(const LoadedBlock& b) {
  block::gen::Block::Record blk;
  if (!tlb::unpack_cell(b.root, blk)) {
    check(b.name + "-state-root-proof", false, "cannot unpack block");
    return;
  }
  auto state_hash = vm::CellSlice{vm::NoVm(), blk.state_update}.prefetch_ref(1)->get_hash(0);
  auto proof = tos::validator::LiteQuery::build_state_root_proof(b.root, state_hash);
  if (proof.is_error()) {
    check(b.name + "-state-root-proof", false, proof.error().to_string());
    return;
  }
  auto virt = vm::MerkleProof::virtualize(proof.move_as_ok());
  if (virt.is_error()) {
    check(b.name + "-state-root-proof", false, virt.error().to_string());
    return;
  }
  tos::Bits256 expected{state_hash.bits()};
  auto status = block::check_block_header_proof(virt.move_as_ok(), b.id, &expected, true);
  check(b.name + "-state-root-proof", status.is_ok(), status.is_ok() ? "" : status.to_string());

  // A state that is not this block's is still refused.
  auto other = tos::validator::LiteQuery::build_state_root_proof(b.root, b.root->get_hash());
  check(b.name + "-state-root-proof-wrong-state-refused", other.is_error());
}

bool check_transaction_proof(const LoadedBlock& b) {
  tos::StdSmcAddress addr;
  tos::LogicalTime lt = 0;
  if (!first_transaction(b.root, addr, lt)) {
    return false;
  }
  auto expected = block::get_block_transaction_try(b.root, b.id, addr, lt);
  if (expected.is_error() || expected.ok().is_null()) {
    check(b.name + "-transaction-proof", false, "transaction not found in the full block");
    return true;
  }
  vm::MerkleProofBuilder pb{b.root};
  auto found = block::get_block_transaction_try(pb.root(), b.id, addr, lt);
  if (found.is_error()) {
    check(b.name + "-transaction-proof", false, found.error().to_string());
    return true;
  }
  auto proof = pb.extract_proof();
  if (proof.is_error()) {
    check(b.name + "-transaction-proof", false, proof.error().to_string());
    return true;
  }
  auto virt = vm::MerkleProof::virtualize(proof.move_as_ok());
  if (virt.is_error()) {
    check(b.name + "-transaction-proof", false, virt.error().to_string());
    return true;
  }
  auto block_root = virt.move_as_ok();
  // What the lite client does with a getOneTransaction answer.
  auto header = block::check_block_header_proof(block_root, b.id);
  check(b.name + "-transaction-proof-header", header.is_ok(), header.is_ok() ? "" : header.to_string());
  auto from_proof = block::get_block_transaction_try(block_root, b.id, addr, lt);
  check(b.name + "-transaction-proof-lookup",
        from_proof.is_ok() && from_proof.ok().not_null() && from_proof.ok()->get_hash() == expected.ok()->get_hash(),
        from_proof.is_error() ? from_proof.error().to_string() : "");

  // The header is checked against the id the caller expects, so another block's id is refused.
  auto wrong_id = b.id;
  wrong_id.id.seqno += 1;
  check(b.name + "-transaction-wrong-block-id-refused",
        block::get_block_transaction_try(b.root, wrong_id, addr, lt).is_error());
  return true;
}

// Header shapes the corpus does not contain, derived from a real shard block.
void check_derived_headers(const LoadedBlock& b) {
  // After a merge the previous-block reference is a cell with two children. Childless cells
  // are never pruned from a Merkle proof, but this one is, unless the proof builder reads it.
  auto merged = with_header(b, "-after-merge", [](block::gen::BlockInfo::Record& info) {
    info.after_merge = true;
    vm::CellBuilder cb;
    cb.store_ref(info.prev_ref);
    cb.store_ref(info.prev_ref);
    info.prev_ref = cb.finalize_novm();
  });
  if (merged.is_error()) {
    check(b.name + "-after-merge", false, merged.error().to_string());
  } else {
    check_state_root_proof(merged.ok());
    check(b.name + "-after-merge-has-transaction", check_transaction_proof(merged.ok()));
  }

  // A shard block whose masterchain reference cannot be read is refused instead of proved.
  auto bad_mc_ref = with_header(b, "-bad-master-ref", [](block::gen::BlockInfo::Record& info) {
    info.master_ref = vm::CellBuilder().finalize_novm();
  });
  if (bad_mc_ref.is_error()) {
    check(b.name + "-bad-master-ref", false, bad_mc_ref.error().to_string());
    return;
  }
  const auto& bad = bad_mc_ref.ok();
  block::gen::Block::Record blk;
  if (!tlb::unpack_cell(bad.root, blk)) {
    check(bad.name, false, "cannot unpack block");
    return;
  }
  auto state_hash = vm::CellSlice{vm::NoVm(), blk.state_update}.prefetch_ref(1)->get_hash(0);
  check(bad.name + "-state-root-proof-refused",
        tos::validator::LiteQuery::build_state_root_proof(bad.root, state_hash).is_error());
  tos::StdSmcAddress addr;
  tos::LogicalTime lt = 0;
  check(bad.name + "-transaction-refused", first_transaction(bad.root, addr, lt) &&
                                               block::get_block_transaction_try(bad.root, bad.id, addr, lt).is_error());
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s <block-corpus-dir>\n", argv[0]);
    return 2;
  }
  std::vector<std::string> files;
  for (const auto& entry : std::filesystem::directory_iterator(argv[1])) {
    if (entry.path().extension() == ".boc") {
      files.push_back(entry.path().string());
    }
  }
  std::sort(files.begin(), files.end());
  bool masterchain_state = false, shard_state = false, masterchain_trans = false, shard_trans = false;
  for (const auto& file : files) {
    auto loaded = load_block(file);
    if (loaded.is_error()) {
      check(file, false, loaded.error().to_string());
      continue;
    }
    auto b = loaded.move_as_ok();
    bool is_master = b.id.is_masterchain();
    bool& state_done = is_master ? masterchain_state : shard_state;
    bool& trans_done = is_master ? masterchain_trans : shard_trans;
    if (!state_done) {
      check_state_root_proof(b);
      state_done = true;
    }
    if (!trans_done) {
      trans_done = check_transaction_proof(b);
      if (trans_done && !is_master) {
        check_derived_headers(b);
      }
    }
  }
  check("corpus-has-masterchain-and-shard-blocks", masterchain_state && shard_state);
  check("corpus-has-masterchain-and-shard-transactions", masterchain_trans && shard_trans);
  return failures ? 1 : 0;
}
