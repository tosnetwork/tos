// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Exports block and get_method harness contexts from the REL-02 corpus (test/rel02/corpus).
//
//   conformance-block-export blocks    <blocks.list> <supplements.list> <out.jsonl>
//       one block context per corpus block, in list order (the chain cross-check's input)
//   conformance-block-export negatives <blocks.list> <supplements.list> <out.jsonl>
//       authored defects of corpus blocks: a wrong or incomplete previous state, a state update
//       that does not apply, an altered transaction, a wrong masterchain context
//   conformance-block-export getters   <blocks.list> <supplements.list> <out.jsonl>
//       get-methods of the elector, the config contract and every other account the corpus
//       touches, on the account state and masterchain snapshot each block executed against
//   conformance-block-export rust-families      <blocks.list> <supplements.list> <out directory>
//       the getter-context families of the Rust node's tests and the c7-shape rows, rebuilt on the
//       corpus's newest masterchain state (see the section comment below)
//
// The list files name one BOC per line, as test-epoch-replay takes them. Previous states are the
// old side of each block's state update with the corpus's supplemental cells filled in, as the
// replay prepares them; masterchain snapshots are pruned to what a get-method can read.
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "common/bitstring.h"
#include "fift/utils.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/misc.h"
#include "test/validator/getter-context-fixture.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/dict.h"
#include "vm/vm.h"

namespace {

using Cell = td::Ref<vm::Cell>;

template <class T>
T require(td::Result<T> result) {
  if (result.is_error()) {
    throw std::runtime_error(result.error().to_string());
  }
  return result.move_as_ok();
}

void check(bool value, const std::string &message) {
  if (!value) {
    throw std::runtime_error(message);
  }
}

std::string hash0(const Cell &cell) {
  return cell->get_hash(0).to_hex();
}

std::string quote(td::Slice s) {
  std::string out = "\"";
  for (char c : s) {
    if (c == '"' || c == '\\') {
      out += '\\';
    }
    out += c;
  }
  return out + "\"";
}

std::string b64_bytes(td::Slice bytes) {
  return quote(td::base64_encode(bytes));
}

std::string b64_cell(const Cell &cell) {
  return b64_bytes(require(vm::std_boc_serialize(cell, 31)).as_slice());
}

// Supplemental cells: original proof and account bytes, accepted by their level-zero hash, as in
// emulator/test/epoch-replay.cpp (a test program whose helpers are not callable from here).
class Cells {
  std::map<std::string, Cell> known_;
  std::set<std::string> seen_;
  mutable std::map<std::string, Cell> hydrated_;

 public:
  void add(const Cell &root) {
    if (!seen_.insert(root->get_hash().to_hex()).second) {
      return;
    }
    auto cs = vm::load_cell_slice_special(root);
    if (!cs.is_special()) {
      auto inserted = known_.emplace(hash0(root), root);
      if (!inserted.second && inserted.first->second->get_hash() != root->get_hash()) {
        inserted.first->second = require(vm::MerkleProof::combine_fast_raw(inserted.first->second, root));
      }
    }
    for (unsigned i = 0; i < cs.size_refs(); ++i) {
      add(cs.prefetch_ref(i));
    }
  }

  Cell hydrate(const Cell &root) const {
    if (root->get_level() == 0) {
      return root;
    }
    auto key = hash0(root);
    auto cached = hydrated_.find(key);
    if (cached != hydrated_.end()) {
      return cached->second;
    }
    auto cs = vm::load_cell_slice_special(root);
    if (cs.special_type() == vm::Cell::SpecialType::PrunnedBranch) {
      auto it = known_.find(key);
      return it == known_.end() ? root : hydrate(it->second);
    }
    if (!cs.is_special()) {
      auto it = known_.find(key);
      if (it != known_.end()) {
        cs = vm::load_cell_slice_special(it->second);
      }
    }
    vm::CellBuilder builder;
    builder.store_bits(cs.fetch_bits(cs.size()));
    while (cs.size_refs()) {
      builder.store_ref(hydrate(cs.fetch_ref()));
    }
    auto result = builder.finalize(cs.is_special());
    check(hash0(result) == key, "supplement changed a state hash");
    hydrated_.emplace(key, result);
    return result;
  }
};

std::vector<std::string> paths(const char *path) {
  std::ifstream input(path);
  check(input.good(), std::string("cannot read ") + path);
  std::vector<std::string> result;
  for (std::string line; std::getline(input, line);) {
    if (!line.empty()) {
      result.push_back(line);
    }
  }
  return result;
}

struct CorpusBlock {
  std::string path;
  std::string bytes;
  Cell root;
  block::gen::BlockInfo::Record info;
  block::gen::BlockExtra::Record extra;
  Cell state_update;
  tos::ShardIdFull shard;
};

struct Corpus {
  Cells cells;
  std::vector<CorpusBlock> blocks;
  std::map<std::string, CorpusBlock> masters;  // by root hash, every masterchain block known

  Cell old_state(const CorpusBlock &b) const {
    return cells.hydrate(vm::load_cell_slice_special(b.state_update).prefetch_ref(0));
  }
  Cell new_state(const CorpusBlock &b) const {
    return cells.hydrate(vm::load_cell_slice_special(b.state_update).prefetch_ref(1));
  }
  const CorpusBlock &master_of(const CorpusBlock &b) const {
    block::gen::ExtBlkRef::Record reference;
    check(tlb::unpack_cell(b.info.master_ref, reference), "shard masterchain reference");
    auto it = masters.find(reference.root_hash.to_hex());
    check(it != masters.end(), "missing masterchain context of " + b.path);
    return it->second;
  }
};

bool parse_block(const std::string &path, std::string bytes, CorpusBlock &out) {
  auto root = vm::std_boc_deserialize(td::Slice(bytes));
  if (root.is_error()) {
    return false;
  }
  out.path = path;
  out.root = root.move_as_ok();
  block::gen::Block::Record block;
  if (!(tlb::unpack_cell(out.root, block) && tlb::unpack_cell(block.info, out.info) &&
        tlb::unpack_cell(block.extra, out.extra) &&
        block::tlb::t_ShardIdent.unpack(out.info.shard.write(), out.shard))) {
    return false;
  }
  out.state_update = block.state_update;
  out.bytes = std::move(bytes);
  return true;
}

Corpus load(const char *blocks_list, const char *supplements_list) {
  Corpus corpus;
  for (const auto &path : paths(supplements_list)) {
    auto bytes = require(td::read_file_str(path));
    auto roots = require(vm::std_boc_deserialize_multi(td::Slice(bytes)));
    for (const auto &root : roots) {
      corpus.cells.add(root);
    }
    CorpusBlock block;
    if (roots.size() == 1 && parse_block(path, bytes, block) && !block.info.not_master) {
      corpus.masters.emplace(hash0(block.root), block);
    }
  }
  for (const auto &path : paths(blocks_list)) {
    CorpusBlock block;
    check(parse_block(path, require(td::read_file_str(path)), block), "invalid corpus block " + path);
    corpus.cells.add(block.root);
    if (!block.info.not_master) {
      corpus.masters.emplace(hash0(block.root), block);
    }
    corpus.blocks.push_back(std::move(block));
  }
  check(!corpus.blocks.empty(), "empty corpus");
  return corpus;
}

std::string block_name(const CorpusBlock &b) {
  return std::to_string(b.shard.workchain) + ":" + std::to_string(b.info.seq_no);
}

struct BlockContext {
  std::string block;  // base64 of the block BOC bytes
  Cell prev_state;
  const CorpusBlock *master = nullptr;
  Cell master_state;
};

BlockContext positive(const Corpus &corpus, const CorpusBlock &b) {
  BlockContext ctx{quote(td::base64_encode(b.bytes)), corpus.old_state(b), nullptr, {}};
  if (b.info.not_master) {
    ctx.master = &corpus.master_of(b);
    ctx.master_state = corpus.new_state(*ctx.master);
  }
  return ctx;
}

void emit_block(std::ostream &out, const std::string &id, const std::string &note, const BlockContext &ctx) {
  out << "{\"fixture_id\":" << quote(id) << ",\"note\":" << quote(note) << ",\"context\":{\"block\":" << ctx.block
      << ",\"prev_state\":" << b64_cell(ctx.prev_state);
  if (ctx.master != nullptr) {
    out << ",\"master_block\":" << b64_bytes(ctx.master->bytes) << ",\"master_state\":" << b64_cell(ctx.master_state);
  }
  out << "}}\n";
}

int command_blocks(const Corpus &corpus, std::ostream &out) {
  for (const auto &b : corpus.blocks) {
    emit_block(out, block_name(b), "corpus block " + hash0(b.root), positive(corpus, b));
  }
  std::cerr << corpus.blocks.size() << " block contexts\n";
  return 0;
}

// ---- negative cases ------------------------------------------------------------------------

std::size_t transaction_count(const CorpusBlock &b) {
  std::size_t count = 0;
  vm::AugmentedDictionary account_blocks(vm::load_cell_slice_ref(b.extra.account_blocks), 256,
                                         block::tlb::aug_ShardAccountBlocks);
  check(account_blocks.check_for_each_extra([&](auto value, auto, auto, int) {
    block::gen::AccountBlock::Record ab;
    check(block::gen::t_AccountBlock.unpack(value.write(), ab), "account block");
    vm::AugmentedDictionary transactions(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
    check(transactions.check_for_each_extra([&](auto, auto, auto, int) {
      ++count;
      return true;
    }),
          "transactions");
    return true;
  }),
        "account blocks");
  return count;
}

std::string repack_bytes(const Cell &root) {
  return require(vm::std_boc_serialize(root, 31)).as_slice().str();
}

Cell with_block_parts(const CorpusBlock &b, const Cell &state_update, const Cell &extra) {
  block::gen::Block::Record block;
  check(tlb::unpack_cell(b.root, block), "block");
  if (state_update.not_null()) {
    block.state_update = state_update;
  }
  if (extra.not_null()) {
    block.extra = extra;
  }
  Cell root;
  check(tlb::pack_cell(root, block), "block repack");
  return root;
}

Cell merkle_update(const Cell &from, const Cell &to) {
  vm::CellBuilder cb;
  check(cb.store_long_bool(static_cast<int>(vm::Cell::SpecialType::MerkleUpdate), 8) &&
            cb.store_bits_bool(from->get_hash(0).bits(), 256) && cb.store_bits_bool(to->get_hash(0).bits(), 256) &&
            cb.store_long_bool(from->get_depth(0), 16) && cb.store_long_bool(to->get_depth(0), 16) &&
            cb.store_ref_bool(from) && cb.store_ref_bool(to),
        "merkle update");
  return cb.finalize(true);
}

// Rebuilds the block with the first transaction of its first account block replaced by edit(tx).
Cell with_first_transaction(const CorpusBlock &b, const std::function<Cell(const Cell &)> &edit) {
  vm::AugmentedDictionary account_blocks(vm::load_cell_slice_ref(b.extra.account_blocks), 256,
                                         block::tlb::aug_ShardAccountBlocks);
  td::Bits256 account_key;
  auto first = account_blocks.get_minmax_key(account_key.bits(), 256, false, false);
  check(first.not_null(), "block without account blocks");
  auto value = account_blocks.lookup(account_key.bits(), 256);
  check(value.not_null() && account_blocks.get_root().not_null(), "account block");
  block::gen::AccountBlock::Record ab;
  check(block::gen::t_AccountBlock.unpack(value.write(), ab), "account block record");
  vm::AugmentedDictionary transactions(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
  td::BitArray<64> lt_key;
  check(transactions.get_minmax_key(lt_key.bits(), 64, false, false).not_null(), "first transaction");
  auto tx_value = transactions.lookup(lt_key.bits(), 64);
  check(tx_value.not_null(), "transaction value");
  auto original = tx_value->prefetch_ref();
  check(original.not_null(), "transaction reference");
  vm::CellBuilder replacement;
  check(replacement.store_ref_bool(edit(original)), "transaction replacement");
  check(transactions.set_builder(lt_key.bits(), 64, replacement, vm::Dictionary::SetMode::Replace), "transaction set");
  // AccountBlock holds the non-empty dictionary's root edge inline.
  ab.transactions = vm::load_cell_slice_ref(transactions.get_root_cell());
  vm::CellBuilder ab_builder;
  check(block::gen::t_AccountBlock.pack(ab_builder, ab), "account block pack");
  check(account_blocks.set_builder(account_key.bits(), 256, ab_builder, vm::Dictionary::SetMode::Replace),
        "account block set");
  auto extra = b.extra;
  vm::CellBuilder account_blocks_cell;
  check(account_blocks_cell.append_cellslice_bool(account_blocks.get_root()), "account blocks root");
  extra.account_blocks = account_blocks_cell.finalize();
  Cell extra_cell;
  check(tlb::pack_cell(extra_cell, extra), "extra repack");
  return with_block_parts(b, {}, extra_cell);
}

// Transaction fields are rewritten in place (Transaction in block.tlb): tag 4, account_addr 256, lt 64,
// prev_trans_hash 256, prev_trans_lt 64, now 32, outmsg_cnt 15, orig_status 2, end_status 2, then
// total_fees:CurrencyCollection, whose first field is the Tomis amount.
constexpr unsigned kNowOffset = 4 + 256 + 64 + 256 + 64;
constexpr unsigned kFeesOffset = kNowOffset + 32 + 15 + 2 + 2;

Cell rewritten(const Cell &tx, unsigned offset, unsigned old_bits, const vm::CellBuilder &replacement) {
  auto cs = vm::load_cell_slice(tx);
  vm::CellBuilder cb;
  check(cb.store_bits_bool(cs.fetch_bits(offset)) && cs.advance(old_bits) && cb.append_builder_bool(replacement) &&
            cb.store_bits_bool(cs.fetch_bits(cs.size())),
        "transaction rewrite");
  while (cs.size_refs()) {
    check(cb.store_ref_bool(cs.fetch_ref()), "transaction rewrite reference");
  }
  return cb.finalize();
}

Cell altered_fees(const Cell &tx) {
  auto cs = vm::load_cell_slice(tx);
  check(cs.advance(kFeesOffset), "transaction fees offset");
  const auto before = cs.size();
  auto tomis = block::tlb::t_Tomis.as_integer_skip(cs);
  check(tomis.not_null(), "transaction fees");
  vm::CellBuilder amount;
  check(block::tlb::t_Tomis.store_integer_value(amount, *(tomis + 1)), "transaction fees store");
  return rewritten(tx, kFeesOffset, before - cs.size(), amount);
}

Cell altered_time(const Cell &tx) {
  block::gen::Transaction::Record record;
  check(tlb::unpack_cell(tx, record), "transaction");
  vm::CellBuilder now;
  check(now.store_long_bool(record.now + 1, 32), "transaction time");
  return rewritten(tx, kNowOffset, 32, now);
}

int command_negatives(const Corpus &corpus, std::ostream &out) {
  // Deterministic picks: the first masterchain and the first basechain block with transactions, the
  // first key block, and the masterchain block that carries the most transactions.
  std::vector<const CorpusBlock *> picks;
  const CorpusBlock *mc = nullptr, *wc = nullptr, *key = nullptr, *busiest = nullptr;
  std::size_t most = 0;
  for (const auto &b : corpus.blocks) {
    auto count = transaction_count(b);
    if (count == 0) {
      continue;
    }
    if (!b.info.not_master && mc == nullptr) {
      mc = &b;
    }
    if (b.info.not_master && wc == nullptr) {
      wc = &b;
    }
    if (b.info.key_block && key == nullptr) {
      key = &b;
    }
    if (!b.info.not_master && count > most) {
      most = count;
      busiest = &b;
    }
  }
  for (auto *p : {mc, wc, key, busiest}) {
    check(p != nullptr, "corpus lacks a negative-case block kind");
    bool duplicate = false;
    for (auto *q : picks) {
      duplicate = duplicate || q == p;
    }
    if (!duplicate) {
      picks.push_back(p);
    }
  }
  std::size_t emitted = 0;
  auto emit = [&](const CorpusBlock &b, const std::string &kind, const std::string &note, const BlockContext &ctx) {
    emit_block(out, block_name(b) + ":" + kind, note, ctx);
    ++emitted;
  };
  for (std::size_t i = 0; i < picks.size(); ++i) {
    const auto &b = *picks[i];
    const auto &other = *picks[(i + 1) % picks.size()];
    // A previous state that is not the block's: another block's previous state.
    auto ctx = positive(corpus, b);
    ctx.prev_state = corpus.old_state(other);
    emit(b, "wrong-prev-state", "previous state of " + block_name(other), ctx);
    // The previous state exactly as the block carries it, without the supplemental cells: the
    // accounts the transactions read are pruned.
    ctx = positive(corpus, b);
    ctx.prev_state = vm::load_cell_slice_special(b.state_update).prefetch_ref(0);
    emit(b, "pruned-prev-state", "state update old side without supplements", ctx);
    // A state update whose new side belongs to another block: it does not apply to this old state.
    auto update = vm::load_cell_slice_special(b.state_update);
    auto foreign = vm::load_cell_slice_special(other.state_update);
    ctx = positive(corpus, b);
    ctx.block = b64_bytes(
        repack_bytes(with_block_parts(b, merkle_update(update.prefetch_ref(0), foreign.prefetch_ref(1)), {})));
    emit(b, "foreign-update", "state update new side of " + block_name(other), ctx);
    // A state update whose two sides are swapped.
    ctx = positive(corpus, b);
    ctx.block =
        b64_bytes(repack_bytes(with_block_parts(b, merkle_update(update.prefetch_ref(1), update.prefetch_ref(0)), {})));
    emit(b, "reversed-update", "state update with old and new sides swapped", ctx);
    // A recorded transaction altered: its fees, then its time.
    ctx = positive(corpus, b);
    ctx.block = b64_bytes(repack_bytes(with_first_transaction(b, altered_fees)));
    emit(b, "tx-fees", "first transaction's total fees increased by one", ctx);
    ctx = positive(corpus, b);
    ctx.block = b64_bytes(repack_bytes(with_first_transaction(b, altered_time)));
    emit(b, "tx-time", "first transaction's time increased by one", ctx);
    if (b.info.not_master) {
      // A shard block with a masterchain state that is not its masterchain block's.
      ctx = positive(corpus, b);
      ctx.master_state = corpus.old_state(*ctx.master);
      emit(b, "wrong-master-state", "previous state of the referenced masterchain block", ctx);
      // A shard block without its masterchain context.
      ctx = positive(corpus, b);
      ctx.master = nullptr;
      emit(b, "no-master", "masterchain block and state omitted", ctx);
    }
  }
  std::cerr << emitted << " negative block contexts\n";
  return 0;
}

// ---- getters ---------------------------------------------------------------------------------

td::int64 method_id(td::Slice name) {
  return (td::crc16(name) & 0xffff) | 0x10000;
}

std::size_t pruned_config_cells = 0;

// A masterchain snapshot reduced to what a get-method reads: the configuration, the libraries and
// the previous-block context; other subtrees are pruned. With whole_config every present cell of the
// configuration and the library dictionary is kept, since a contract can read any parameter through
// c7; otherwise only the cells the context construction itself reads. A context that cannot be built
// (a deliberately broken previous-block history) keeps the cells read up to the failure.
Cell getter_snapshot(const Cell &state, const tos::BlockIdExt &id, const std::vector<tos::UnixTime> &nows,
                     bool whole_config = true) {
  vm::MerkleProofBuilder pb{state->virtualize(0)};
  auto extracted = block::ConfigInfo::extract_config(
      pb.root(), id,
      block::ConfigInfo::needLibraries | block::ConfigInfo::needCapabilities | block::ConfigInfo::needPrevBlocks);
  if (extracted.is_error()) {
    auto proof = require(pb.extract_proof());
    return vm::load_cell_slice_special(proof).prefetch_ref(0);
  }
  auto config = extracted.move_as_ok();
  (void)config->get_prev_blocks_info();
  if (config->get_global_version() >= 6) {
    for (auto now : nows) {
      (void)config->get_unpacked_config_tuple(now);
    }
  }
  (void)config->get_precompiled_contracts_config();
  // Every present cell is kept; a cell the corpus does not hold stays pruned.
  std::function<void(const Cell &, int)> touch = [&](const Cell &cell, int depth) {
    check(depth < 1024, "configuration too deep");
    try {
      auto cs = vm::load_cell_slice_special(cell);
      for (unsigned i = 0; i < cs.size_refs(); ++i) {
        touch(cs.prefetch_ref(i), depth + 1);
      }
    } catch (const vm::VmVirtError &) {
      ++pruned_config_cells;
    }
  };
  if (whole_config) {
    touch(config->get_root_cell(), 0);
  } else {
    // The context looks the code hash up in the precompiled-contract list: keep the list whole.
    vm::Dictionary params{config->get_root_cell(), 32};
    auto precompiled = params.lookup_ref(td::BitArray<32>{45});
    if (precompiled.not_null()) {
      touch(precompiled, 0);
    }
  }
  if (config->get_libraries_root().not_null()) {
    touch(config->get_libraries_root(), 0);
  }
  auto proof = require(pb.extract_proof());
  return vm::load_cell_slice_special(proof).prefetch_ref(0);
}

// True when no descendant of the (virtualized) cell is pruned.
bool complete(const Cell &cell, int depth = 0) {
  if (depth > 1024) {
    return false;
  }
  try {
    auto cs = vm::load_cell_slice_special(cell);
    for (unsigned i = 0; i < cs.size_refs(); ++i) {
      if (!complete(cs.prefetch_ref(i), depth + 1)) {
        return false;
      }
    }
    return true;
  } catch (const vm::VmVirtError &) {
    return false;
  }
}

struct GetterCall {
  std::string name;
  std::vector<std::string> arguments;  // stack items as JSON
};

std::string int_item(const std::string &value) {
  return "{\"type\":\"int\",\"value\":" + quote(value) + "}";
}

std::vector<GetterCall> getters_for(const td::Bits256 &address, int workchain,
                                    const std::vector<std::string> &stakers) {
  td::Bits256 elector, config;
  elector.as_slice().fill(0x33);
  config.as_slice().fill(0x55);
  std::vector<GetterCall> calls;
  if (workchain == tos::masterchainId && address == elector) {
    for (const char *name : {"active_election_id", "participant_list", "participant_list_extended", "past_election_ids",
                             "past_elections", "past_elections_list"}) {
      calls.push_back({name, {}});
    }
    calls.push_back({"compute_returned_stake", {int_item("0")}});
    for (const auto &staker : stakers) {
      calls.push_back({"compute_returned_stake", {int_item(staker)}});
    }
    calls.push_back({"participates_in", {int_item("0")}});
    calls.push_back({"list_complaints", {int_item("0")}});
    calls.push_back({"complaint_storage_price", {int_item("1000"), int_item("10"), int_item("3600")}});
    return calls;
  }
  if (workchain == tos::masterchainId && address == config) {
    for (const char *name : {"seqno", "get_public_key", "list_proposals"}) {
      calls.push_back({name, {}});
    }
    calls.push_back({"get_proposal", {int_item("0")}});
    calls.push_back({"proposal_storage_price", {int_item("-1"), int_item("3600"), int_item("1000"), int_item("10")}});
    calls.push_back({"proposal_storage_price", {int_item("0"), int_item("86400"), int_item("500"), int_item("4")}});
    return calls;
  }
  for (const char *name :
       {"seqno", "get_public_key", "get_subwallet_id", "get_wallet_data", "get_jetton_data", "get_nft_data",
        "get_collection_data", "get_pool_data", "get_plugin_list", "get_token_data", "get_methods"}) {
    calls.push_back({name, {}});
  }
  return calls;
}

int command_getters(const Corpus &corpus, std::ostream &out) {
  // Each account touched by a block is taken in the state the block executed it against, with the
  // masterchain snapshot of that execution. Per address, the first, a middle and the last distinct
  // complete state are kept, so the elector and the config contract appear in several states.
  struct Occurrence {
    const CorpusBlock *block;
    Cell account;
    td::Bits256 address;
  };
  std::map<std::string, std::vector<Occurrence>> by_address;
  std::set<std::string> seen_states;
  std::vector<std::string> stakers;
  for (const auto &b : corpus.blocks) {
    vm::AugmentedDictionary account_blocks(vm::load_cell_slice_ref(b.extra.account_blocks), 256,
                                           block::tlb::aug_ShardAccountBlocks);
    // An empty block's previous state may have its whole account dictionary pruned.
    if (account_blocks.is_empty()) {
      continue;
    }
    auto old = corpus.old_state(b)->virtualize(0);
    block::gen::ShardStateUnsplit::Record state;
    check(tlb::unpack_cell(old, state), "previous state of " + b.path);
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
    check(account_blocks.check_for_each_extra([&](auto, auto, td::ConstBitPtr key, int) {
      td::Bits256 address{key};
      auto entry = accounts.lookup(key, 256);
      if (entry.is_null() || entry->size_refs() < 1) {
        return true;
      }
      auto account = entry->prefetch_ref();
      if (!complete(account) || !seen_states.insert(hash0(account)).second) {
        return true;
      }
      auto name = std::to_string(b.shard.workchain) + ":" + address.to_hex();
      by_address[name].push_back({&b, account, address});
      return true;
    }),
          "account blocks of " + b.path);
  }
  // compute_returned_stake takes a wallet address as an integer: the masterchain accounts that are
  // neither the elector nor the config contract.
  for (const auto &entry : by_address) {
    const auto &first = entry.second.front();
    if (!first.block->info.not_master) {
      td::Bits256 elector, config;
      elector.as_slice().fill(0x33);
      config.as_slice().fill(0x55);
      if (first.address != elector && first.address != config && stakers.size() < 8) {
        td::RefInt256 x{true};
        x.write().import_bits(first.address.cbits(), 256, false);
        stakers.push_back(x->to_dec_string());
      }
    }
  }
  std::map<std::string, Cell> snapshots;
  std::size_t emitted = 0;
  for (const auto &entry : by_address) {
    const auto &list = entry.second;
    std::vector<std::size_t> chosen{0};
    if (list.size() > 2) {
      chosen.push_back(list.size() / 2);
    }
    if (list.size() > 1) {
      chosen.push_back(list.size() - 1);
    }
    for (auto index : chosen) {
      const auto &occurrence = list[index];
      const auto &b = *occurrence.block;
      block::gen::ExtBlkRef::Record reference;
      Cell mc_state;
      if (!b.info.not_master) {
        check(tlb::unpack_cell(b.info.prev_ref, reference), "masterchain parent");
        mc_state = corpus.old_state(b);
      } else {
        check(tlb::unpack_cell(b.info.master_ref, reference), "masterchain reference");
        mc_state = corpus.new_state(corpus.master_of(b));
      }
      tos::BlockIdExt id(tos::masterchainId, tos::shardIdAll, reference.seq_no, reference.root_hash,
                         reference.file_hash);
      auto key = id.root_hash.to_hex();
      auto known = snapshots.find(key);
      if (known == snapshots.end()) {
        known = snapshots.emplace(key, getter_snapshot(mc_state, id, {b.info.gen_utime})).first;
      }
      const auto snapshot = b64_cell(known->second);
      const auto account = b64_cell(occurrence.account);
      td::Bits256 seed = b.extra.rand_seed;
      for (const auto &call : getters_for(occurrence.address, b.shard.workchain, stakers)) {
        std::string stack = "[";
        for (std::size_t i = 0; i < call.arguments.size(); ++i) {
          stack += (i ? "," : "") + call.arguments[i];
        }
        stack += "]";
        auto id_text = entry.first.substr(0, 19) + ":" + std::to_string(b.info.seq_no) + ":" + call.name;
        if (!call.arguments.empty()) {
          unsigned char digest[32];
          td::sha256(stack, td::MutableSlice(digest, 32));
          id_text += ":" + td::hex_encode(td::Slice(digest, 4));
        }
        out << "{\"fixture_id\":" << quote(id_text)
            << ",\"note\":" << quote(entry.first + " in the state block " + block_name(b) + " executed against")
            << ",\"context\":{\"mc_state\":" << snapshot << ",\"mc_block\":{\"seqno\":" << id.seqno()
            << ",\"root_hash\":" << quote(id.root_hash.to_hex()) << ",\"file_hash\":" << quote(id.file_hash.to_hex())
            << "},\"account\":" << account << ",\"now\":" << b.info.gen_utime << ",\"lt\":" << b.info.start_lt
            << ",\"rand_seed\":" << quote(td::to_lower(seed.to_hex()))
            << ",\"method_id\":" << quote(std::to_string(method_id(call.name))) << ",\"stack\":" << stack
            << ",\"gas_limit\":300000}}\n";
        ++emitted;
      }
    }
  }
  std::cerr << emitted << " getter contexts over " << by_address.size() << " addresses, " << snapshots.size()
            << " snapshots, " << pruned_config_cells << " configuration cells absent from the corpus\n";
  return 0;
}

// ---- getter families migrated from the Rust node's getter tests -------------------------------
// The Rust tests (vm/src/tests/test_get_context.rs, test_get_history_context.rs and
// test_get_method_id.rs of the Rust node) freeze only names and results, not contexts. Their
// contexts are rebuilt here from the tests' parameters: the same versions, state edits, probe
// programs (in Fift assembler), account, times, seeds and method ids, on the newest masterchain
// state of the corpus instead of the Rust tests' foreign mainnet state. Their seqnos 61880 and 61700
// (recent and century history entries of a state at 61884) map to seqno-4 and the century before
// the state's. Effects are filled from the C++ reference, never taken from the Rust files.

Cell compile(const std::string &source) {
  auto code = fift::compile_asm(source);
  check(code.is_ok(), "cannot assemble: " + source);
  return code.move_as_ok();
}

// Accepts the empty history entries the "truncated" edits write: their extra is (false, 0).
struct LenientOldMcBlocksAug final : block::tlb::AugmentationCheckData {
  LenientOldMcBlocksAug() : AugmentationCheckData(block::tlb::t_KeyExtBlkRef, block::tlb::t_KeyMaxLt) {
  }
  bool eval_leaf(vm::CellBuilder &cb, vm::CellSlice &cs) const override {
    if (cs.have(65)) {
      return cb.append_bitslice(cs.prefetch_bits(65));
    }
    return cb.store_long_bool(0, 1) && cb.store_long_bool(0, 64);
  }
};

struct StateEdit {
  int version = -1;  // -1 keeps the state's global version
  std::function<void(vm::Dictionary &)> config_edit;
  std::function<void(block::gen::McStateExtra::Record &)> extra_edit;
  Cell global_library;
  td::Bits256 publisher;
};

Cell edited_state(const Cell &base, const StateEdit &edit) {
  block::gen::ShardStateUnsplit::Record state;
  check(tlb::unpack_cell(base, state), "base state");
  block::gen::McStateExtra::Record extra;
  check(tlb::unpack_cell(state.custom->prefetch_ref(), extra), "base state extra");
  auto config_cs = *extra.config;
  td::Bits256 config_address;
  check(config_cs.fetch_bits_to(config_address), "config address");
  vm::Dictionary config{config_cs.prefetch_ref(), 32};
  auto p8 = config.lookup_ref(td::BitArray<32>{8});
  check(p8.not_null(), "ConfigParam 8");
  auto p8_cs = vm::load_cell_slice(p8);
  unsigned long long tag = 0, capabilities = 0;
  unsigned long long version = 0;
  check(p8_cs.fetch_ulong_bool(8, tag) && tag == 0xc4 && p8_cs.fetch_ulong_bool(32, version) &&
            p8_cs.fetch_ulong_bool(64, capabilities),
        "ConfigParam 8 layout");
  if (edit.version >= 0) {
    version = static_cast<unsigned long long>(edit.version);
  }
  check(config.set_ref(td::BitArray<32>{8}, vm::CellBuilder{}
                                                .store_long(0xc4, 8)
                                                .store_long(static_cast<long long>(version), 32)
                                                .store_long(static_cast<long long>(capabilities), 64)
                                                .finalize()),
        "ConfigParam 8 set");
  if (edit.config_edit) {
    edit.config_edit(config);
  }
  vm::CellBuilder config_field;
  check(
      config_field.store_bits_bool(config_address.cbits(), 256) && config_field.store_ref_bool(config.get_root_cell()),
      "config field");
  extra.config = config_field.as_cellslice_ref();
  if (edit.extra_edit) {
    edit.extra_edit(extra);
  }
  Cell extra_cell;
  check(tlb::pack_cell(extra_cell, extra), "state extra pack");
  state.custom = vm::CellBuilder{}.store_long(1, 1).store_ref(extra_cell).as_cellslice_ref();
  if (edit.global_library.not_null()) {
    vm::Dictionary libraries{state.r1.libraries, 256};
    vm::Dictionary publishers{256};
    check(publishers.set_builder(edit.publisher.cbits(), 256, vm::CellBuilder{}), "library publisher");
    vm::CellBuilder descriptor;
    check(descriptor.store_long_bool(0, 2) && descriptor.store_ref_bool(edit.global_library) &&
              descriptor.append_cellslice_bool(vm::load_cell_slice(publishers.get_root_cell())),
          "library descriptor");
    check(libraries.set(edit.global_library->get_hash().bits(), 256, descriptor.as_cellslice_ref()), "library set");
    vm::CellBuilder field;
    check(field.store_maybe_ref(libraries.get_root_cell()), "libraries field");
    state.r1.libraries = field.as_cellslice_ref();
  }
  Cell result;
  check(tlb::pack_cell(result, state), "state pack");
  return result;
}

Cell precompiled_param(const std::vector<std::pair<Cell, Cell>> &entries, int tag = 0xc0) {
  vm::Dictionary dictionary{256};
  for (const auto &entry : entries) {
    vm::CellBuilder value;
    check(value.append_cellslice_bool(vm::load_cell_slice(entry.second)), "precompiled value");
    check(dictionary.set_builder(entry.first->get_hash().bits(), 256, value), "precompiled entry");
  }
  vm::CellBuilder field;
  check(field.store_long_bool(tag, 8) && field.store_maybe_ref(dictionary.get_root_cell()), "precompiled field");
  return field.finalize();
}

Cell gas_entry(long long gas) {
  return vm::CellBuilder{}.store_long(0xb0, 8).store_long(gas, 64).finalize();
}

struct RustFamilyEmitter {
  Cell template_account;
  tos::BlockIdExt id;
  std::map<std::string, std::string> snapshots;
  std::size_t rows = 0;

  // One snapshot per state edit, holding what the contexts at every time of the family read.
  const std::string &snapshot(const std::string &tag, const Cell &state) {
    auto it = snapshots.find(tag);
    if (it == snapshots.end()) {
      it = snapshots.emplace(tag, b64_cell(getter_snapshot(state, id, {0, 199, 200}, false))).first;
    }
    return it->second;
  }

  // The Rust tests' account: -1:5a..5a, 10^10 nanotokens, due payment 123, empty data.
  std::string account(const Cell &code, const Cell &libraries = {}) const {
    td::Bits256 address;
    address.as_slice().fill(0x5a);
    getter_fixture::Getter getter{"probe",
                                  "probe",
                                  {tos::masterchainId, address},
                                  code,
                                  vm::CellBuilder{}.finalize(),
                                  block::CurrencyCollection{td::make_refint(10000000000LL)}};
    getter.due_payment = td::make_refint(123);
    getter.libraries = libraries;
    return b64_cell(getter_fixture::make_account(template_account, getter));
  }

  void emit(std::ostream &file, const std::string &fixture_id, const std::string &note, const std::string &snapshot,
            const std::string &account, tos::UnixTime now, const td::Bits256 &seed, long long method) {
    file << "{\"fixture_id\":" << quote(fixture_id) << ",\"note\":" << quote(note)
         << ",\"context\":{\"mc_state\":" << snapshot << ",\"mc_block\":{\"seqno\":" << id.seqno()
         << ",\"root_hash\":" << quote(id.root_hash.to_hex()) << ",\"file_hash\":" << quote(id.file_hash.to_hex())
         << "},\"account\":" << account << ",\"now\":" << now
         << ",\"lt\":2000000000,\"rand_seed\":" << quote(td::to_lower(seed.to_hex()))
         << ",\"method_id\":" << quote(std::to_string(method)) << ",\"stack\":[],\"gas_limit\":300000}}\n";
    ++rows;
  }
};

const std::string kInfo = "c7 PUSHCTR FIRST ";

std::string field(int index, const std::string &tail = "") {
  return kInfo + std::to_string(index) + " PUSHINT INDEXVAR" + (tail.empty() ? "" : " " + tail);
}

std::string precompiled_probe(int cost) {
  return std::to_string(cost) + " PUSHINT DROP " + field(16);
}

void rust_get_context(RustFamilyEmitter &e, const Cell &base, std::ostream &file) {
  const std::vector<std::pair<std::string, std::string>> probes = {
      {"magic", kInfo + "FIRST"},
      {"actions", field(1)},
      {"msgs", field(2)},
      {"seed", field(6)},
      {"seed-high", field(6)},
      {"seed-max", field(6)},
      {"balance-extra", field(7, "1 PUSHINT INDEXVAR ISNULL")},
      {"address", field(8, "NEWC STSLICE ENDC HASHCU")},
      {"config", field(9, "HASHCU")},
      {"precompiled-zero", precompiled_probe(0)},
      {"precompiled-cost", precompiled_probe(123)},
      {"length", kInfo + "TLEN"},
      {"null", field(18, "ISNULL")},
      {"fields", field(18, "4 UNTUPLE")},
      {"msg-length", field(17, "TLEN")},
      {"msg-time", field(17, "5 PUSHINT INDEXVAR")},
      {"msg-value", field(17, "7 PUSHINT INDEXVAR")},
      {"msg-src", field(17, "2 PUSHINT INDEXVAR SBITS")},
      {"msg-extra", field(17, "8 PUSHINT INDEXVAR ISNULL")},
      {"balance", field(7, "FIRST")},
      {"now", "NOW"},
      {"block-lt", "BLOCKLT"},
      {"trans-lt", "LTIME"},
      {"due", field(15)},
      {"precompiled", field(16, "ISNULL")},
      {"code", field(10, "HASHCU")},
      {"throw", "77 PUSHINT THROWANY"},
      {"underflow", "DROP DROP"},
  };
  const auto precompiled = precompiled_param(
      {{compile(precompiled_probe(0)), gas_entry(0)}, {compile(precompiled_probe(123)), gas_entry(123)}});
  for (int version : {3, 4, 5, 6, 10, 11, 13, 14, 15, 16, 17, 18, 19}) {
    StateEdit edit;
    edit.version = version;
    edit.config_edit = [&](vm::Dictionary &config) {
      check(config.set_ref(td::BitArray<32>{45}, precompiled), "ConfigParam 45");
    };
    auto state = edited_state(base, edit);
    for (tos::UnixTime now : {0u, 200u}) {
      const auto &snapshot = e.snapshot("context-v" + std::to_string(version), state);
      for (const auto &probe : probes) {
        td::Bits256 seed = td::Bits256::zero();
        if (probe.first == "seed-high") {
          seed.bits()[0] = true;
        }
        if (probe.first == "seed-max") {
          seed.as_slice().fill(0xff);
        }
        auto name = "get-v" + std::to_string(version) + "-now" + std::to_string(now) + "-" + probe.first;
        e.emit(file, name, probe.second, snapshot, e.account(compile(probe.second)), now, seed, 12345);
      }
    }
  }
  const auto library = compile("99 PUSHINT");
  auto probe = compile("CTOS DROP 99 PUSHINT");
  vm::CellBuilder code_builder;
  check(code_builder.store_long_bool(0x88, 8) &&
            code_builder.store_ref_bool(getter_fixture::library_reference(library)) &&
            code_builder.append_cellslice_bool(vm::load_cell_slice(probe)),
        "library probe code");
  const auto code = code_builder.finalize();
  td::Bits256 publisher;
  publisher.as_slice().fill(0x5a);
  vm::Dictionary shadow{256};
  vm::CellBuilder shadow_entry;
  check(shadow_entry.store_bool_bool(true) && shadow_entry.store_ref_bool(vm::CellBuilder{}.finalize()),
        "shadow library entry");
  check(shadow.set_builder(library->get_hash().bits(), 256, shadow_entry), "shadow library");
  for (int version : {14, 15, 17, 19}) {
    for (const std::string mode : {"account", "global", "both", "missing", "shadow-invalid"}) {
      StateEdit edit;
      edit.version = version;
      if (mode == "global" || mode == "both" || mode == "shadow-invalid") {
        edit.global_library = library;
        edit.publisher = publisher;
      }
      Cell account_libraries;
      if (mode == "account" || mode == "both") {
        account_libraries = getter_fixture::account_libraries(library);
      }
      if (mode == "shadow-invalid") {
        account_libraries = shadow.get_root_cell();
      }
      auto tag = "library-v" + std::to_string(version) + "-" + mode;
      const auto &snapshot = e.snapshot(tag, edited_state(base, edit));
      e.emit(file, "get-v" + std::to_string(version) + "-library-" + mode, "library " + mode, snapshot,
             e.account(code, account_libraries), 200, td::Bits256::zero(), 12345);
    }
  }
}

void rust_get_history(RustFamilyEmitter &e, const Cell &base, tos::BlockSeqno seqno, std::ostream &file) {
  const tos::BlockSeqno recent = seqno - 4;
  const tos::BlockSeqno century = seqno / 100 * 100 - 100;
  const std::vector<std::pair<std::string, std::string>> probes = {
      {"context", "DROP c7 PUSHCTR"},
      {"previous", field(13)},
      {"unpacked", field(14)},
  };
  vm::Dictionary prices{32};
  for (unsigned index = 0; index < 3; ++index) {
    const long long since = 100 * (index + 1);
    vm::CellBuilder price;
    check(price.store_long_bool(0xcc, 8) && price.store_long_bool(since, 32) && price.store_long_bool(since, 64) &&
              price.store_long_bool(2, 64) && price.store_long_bool(3, 64) && price.store_long_bool(4, 64),
          "storage price");
    check(prices.set_builder(td::BitArray<32>{index}, price), "storage prices");
  }
  const auto storage_prices = prices.get_root_cell();
  for (int version : {3, 4, 5, 6, 8, 9, 10, 11, 14, 15, 16, 17, 19}) {
    for (const std::string mode :
         {"complete", "recent-missing", "century-missing", "key-missing", "key-override", "current-key",
          "recent-truncated", "century-truncated", "recent-sequence", "zero-truncated", "zero-sequence",
          "precompiled-truncated", "precompiled-trailing", "precompiled-tag"}) {
      if (mode.rfind("precompiled", 0) == 0 && version != 14) {
        continue;
      }
      StateEdit edit;
      edit.version = version;
      edit.config_edit = [&](vm::Dictionary &config) {
        check(config.set_ref(td::BitArray<32>{18}, storage_prices), "ConfigParam 18");
        if (mode.rfind("precompiled", 0) == 0) {
          std::vector<std::pair<Cell, Cell>> entries;
          for (const auto &probe : probes) {
            auto value = mode == "precompiled-trailing"
                             ? vm::CellBuilder{}.store_long(0xb0, 8).store_long(123, 64).store_long(1, 8).finalize()
                             : vm::CellBuilder{}.finalize();
            entries.emplace_back(compile(probe.second), value);
          }
          check(
              config.set_ref(td::BitArray<32>{45}, precompiled_param(entries, mode == "precompiled-tag" ? 0xff : 0xc0)),
              "ConfigParam 45");
        }
      };
      edit.extra_edit = [&](block::gen::McStateExtra::Record &extra) {
        vm::AugmentedDictionary history{extra.r1.prev_blocks, 32, block::tlb::aug_OldMcBlocksInfo};
        if (mode == "recent-truncated" || mode == "century-truncated" || mode == "zero-truncated") {
          const tos::BlockSeqno at = mode == "recent-truncated" ? recent : mode == "century-truncated" ? century : 0;
          static const LenientOldMcBlocksAug lenient;
          vm::AugmentedDictionary raw{extra.r1.prev_blocks, 32, lenient};
          check(raw.set_builder(td::BitArray<32>{at}, vm::CellBuilder{}), "truncated history entry");
          extra.r1.prev_blocks = raw.get_root();
        } else if (mode == "recent-sequence" || mode == "zero-sequence") {
          const tos::BlockSeqno at = mode == "recent-sequence" ? recent : 0;
          auto entry = history.lookup(td::BitArray<32>{at});
          check(entry.not_null(), "history entry");
          auto cs = *entry;
          vm::CellBuilder changed;
          // key:Bool blk_ref:ExtBlkRef(end_lt:uint64 seq_no:uint32 ...): the stored seqno plus one.
          check(changed.store_bits_bool(cs.fetch_bits(65)) && cs.advance(32) && changed.store_long_bool(at + 1, 32) &&
                    changed.append_cellslice_bool(cs),
                "history entry rewrite");
          check(history.set_builder(td::BitArray<32>{at}, changed), "history entry set");
          extra.r1.prev_blocks = history.get_root();
        } else if (mode == "recent-missing" || mode == "century-missing") {
          check(history.lookup_delete(td::BitArray<32>{mode == "recent-missing" ? recent : century}).not_null(),
                "history entry delete");
          extra.r1.prev_blocks = history.get_root();
        } else if (mode == "key-missing") {
          extra.r1.after_key_block = false;
          extra.r1.last_key_block = vm::CellBuilder{}.store_long(0, 1).as_cellslice_ref();
        } else if (mode == "key-override") {
          extra.r1.after_key_block = false;
          vm::CellBuilder key;
          check(key.store_long_bool(1, 1) && key.store_long_bool(123456, 64) && key.store_long_bool(60000, 32),
                "key block reference");
          td::Bits256 root_hash, file_hash;
          root_hash.as_slice().fill(0x22);
          file_hash.as_slice().fill(0x33);
          check(key.store_bits_bool(root_hash.cbits(), 256) && key.store_bits_bool(file_hash.cbits(), 256),
                "key block hashes");
          extra.r1.last_key_block = key.as_cellslice_ref();
        } else if (mode == "current-key") {
          extra.r1.after_key_block = true;
        }
      };
      Cell state;
      try {
        state = edited_state(base, edit);
      } catch (const vm::VmError &error) {
        // The corpus state holds the history dictionary only partially; an edit that must read a
        // pruned neighbour cannot be made, and the mode is reported as not migrated.
        std::cerr << "not migrated: history-v" << version << "-" << mode << ": " << error.get_msg() << "\n";
        continue;
      }
      auto tag = "history-v" + std::to_string(version) + "-" + mode;
      for (tos::UnixTime now : {0u, 199u, 200u}) {
        const auto &snapshot = e.snapshot(tag, state);
        for (const auto &probe : probes) {
          e.emit(file,
                 "history-v" + std::to_string(version) + "-" + mode + "-now" + std::to_string(now) + "-" + probe.first,
                 probe.second, snapshot, e.account(compile(probe.second)), now, td::Bits256::zero(), 12345);
        }
      }
    }
  }
}

void rust_method_id(RustFamilyEmitter &e, const Cell &base, std::ostream &file) {
  const long long ids[] = {
      std::numeric_limits<long long>::min(), -4294967296LL, -1, 0, 1, 12345, 4294967295LL, 4294967296LL, 4294979641LL,
      std::numeric_limits<long long>::max()};
  for (int version : {3, 14, 17, 19}) {
    StateEdit edit;
    edit.version = version;
    const auto &snapshot = e.snapshot("method-v" + std::to_string(version), edited_state(base, edit));
    for (std::size_t index = 0; index < std::size(ids); ++index) {
      for (const std::string probe : {"echo", "dispatch"}) {
        const auto source = probe == "echo"
                                ? std::string("NOP")
                                : std::to_string(ids[index]) +
                                      " PUSHINT EQUAL <{ 111 PUSHINT }> PUSHCONT <{ 222 PUSHINT }> PUSHCONT IFELSE";
        e.emit(file, "method-v" + std::to_string(version) + "-" + std::to_string(index) + "-" + probe, source, snapshot,
               e.account(compile(source)), 200, td::Bits256::zero(), ids[index]);
      }
    }
  }
}

// test/validator/data/getter-c7-shape.tsv: the SmartContractInfo length and c7[18] by version.
void c7_shape(RustFamilyEmitter &e, const Cell &base, std::ostream &file) {
  for (int version : {15, 16, 17}) {
    StateEdit edit;
    edit.version = version;
    const auto &snapshot = e.snapshot("shape-v" + std::to_string(version), edited_state(base, edit));
    for (const auto &probe : std::vector<std::pair<std::string, std::string>>{
             {"length", kInfo + "TLEN"}, {"slot18", field(18, "ISNULL")}, {"context", "DROP c7 PUSHCTR"}}) {
      e.emit(file, "c7-shape-v" + std::to_string(version) + "-" + probe.first, probe.second, snapshot,
             e.account(compile(probe.second)), 200, td::Bits256::zero(), 12345);
    }
  }
}

// The corpus holds the masterchain block history dictionary only along the paths the replay read,
// and an edit of an augmented dictionary must read the neighbours of the edited entry. The history
// is therefore rebuilt as a complete dictionary of the entries a get-method context reads (the
// fifteen predecessors, sixteen century entries and entry 0), with their original values; a getter
// reads no other entry.
Cell compact_history(const Cell &state, tos::BlockSeqno seqno) {
  std::set<tos::BlockSeqno> wanted{0};
  for (tos::BlockSeqno i = 1; i < 16 && i <= seqno; ++i) {
    wanted.insert(seqno - i);
  }
  for (tos::BlockSeqno at = seqno / 100 * 100, n = 0; n < 16; ++n, at -= 100) {
    wanted.insert(at);
    if (at < 100) {
      break;
    }
  }
  StateEdit edit;
  edit.extra_edit = [&](block::gen::McStateExtra::Record &extra) {
    vm::AugmentedDictionary original{extra.r1.prev_blocks, 32, block::tlb::aug_OldMcBlocksInfo};
    vm::AugmentedDictionary compact{32, block::tlb::aug_OldMcBlocksInfo};
    for (auto at : wanted) {
      td::Ref<vm::CellSlice> entry;
      try {
        entry = original.lookup(td::BitArray<32>{at});
      } catch (const vm::VmError &) {
        std::cerr << "history entry " << at << " is not in the corpus\n";
        continue;
      }
      if (entry.not_null()) {
        check(compact.set(td::BitArray<32>{at}, entry), "compact history entry");
      }
    }
    extra.r1.prev_blocks = compact.get_root();
  };
  return edited_state(state, edit);
}

int command_rust_families(const Corpus &corpus, const std::string &directory) {
  const CorpusBlock *newest = nullptr;
  for (const auto &b : corpus.blocks) {
    if (!b.info.not_master && (newest == nullptr || b.info.seq_no > newest->info.seq_no)) {
      newest = &b;
    }
  }
  check(newest != nullptr, "no masterchain block in the corpus");
  const auto corpus_state = corpus.old_state(*newest);
  block::gen::ShardStateUnsplit::Record header;
  check(tlb::unpack_cell(corpus_state->virtualize(0), header), "base state header");
  const auto base = compact_history(corpus_state, header.seq_no);
  // A complete corpus account as the template of the probe account's storage statistics.
  Cell template_account;
  {
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(header.accounts), 256, block::tlb::aug_ShardAccounts);
    td::Bits256 config_address;
    config_address.as_slice().fill(0x55);
    auto entry = accounts.lookup(config_address);
    check(entry.not_null() && complete(entry->prefetch_ref()), "complete template account");
    template_account = entry->prefetch_ref();
  }
  td::Bits256 root_hash, file_hash;
  root_hash.as_slice().fill(0x99);
  file_hash.as_slice().fill(0xa5);
  RustFamilyEmitter e{template_account,
                      tos::BlockIdExt{tos::masterchainId, tos::shardIdAll, header.seq_no, root_hash, file_hash},
                      {},
                      0};
  auto open = [&](const std::string &name) {
    std::ofstream file(directory + "/" + name, std::ios::binary | std::ios::trunc);
    check(file.good(), "cannot open " + name);
    return file;
  };
  {
    auto file = open("rust-get-context.jsonl");
    rust_get_context(e, base, file);
  }
  {
    auto file = open("rust-get-history-context.jsonl");
    rust_get_history(e, base, header.seq_no, file);
  }
  {
    auto file = open("rust-get-method-id-context.jsonl");
    rust_method_id(e, base, file);
  }
  {
    auto file = open("c7-shape.jsonl");
    c7_shape(e, base, file);
  }
  std::cerr << e.rows << " migrated getter contexts, " << e.snapshots.size() << " snapshots, base seqno "
            << header.seq_no << "\n";
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  try {
    check(argc == 5,
          "usage: conformance-block-export blocks|negatives|getters|rust-families <blocks.list> <supplements.list> "
          "<out>");
    SET_VERBOSITY_LEVEL(0);
    check(vm::init_vm(false).is_ok(), "VM initialization failed");
    const std::string command = argv[1];
    auto corpus = load(argv[2], argv[3]);
    // rust-families writes several files into the directory argv[4]; the others write the file argv[4].
    std::ofstream out;
    if (command != "rust-families") {
      out.open(argv[4], std::ios::binary | std::ios::trunc);
      check(out.good(), "cannot open the output");
    }
    int rc = 2;
    if (command == "blocks") {
      rc = command_blocks(corpus, out);
    } else if (command == "negatives") {
      rc = command_negatives(corpus, out);
    } else if (command == "getters") {
      rc = command_getters(corpus, out);
    } else if (command == "rust-families") {
      out.close();
      rc = command_rust_families(corpus, argv[4]);
    } else {
      throw std::runtime_error("unknown command " + command);
    }
    if (out.is_open()) {
      out.close();
      check(!out.fail(), "cannot write the output");
    }
    return rc;
  } catch (const vm::VmVirtError &error) {
    std::cerr << "pruned cell: " << error.get_msg() << '\n';
  } catch (const vm::VmError &error) {
    std::cerr << error.get_msg() << '\n';
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
  }
  return 1;
}
