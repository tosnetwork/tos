// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Contexts of the validate harness from archived chain history (docs/validate.md).
//
// The archived blocks are applied from the zero states (every state update must start from the state
// reached so far and end at the hash it declares), so the complete previous states are in memory. Each
// target block is then validated by the node's ValidateQuery (ref/validate-offline.cpp) with every
// state it may ask for wrapped in a usage tree; the context keeps a Merkle proof of each state it did
// ask for, holding exactly the cells it read, and is validated again from those proofs, which must give
// the same outcome. The context also carries the collated data a collator would have attached and the
// archive does not keep: ConsensusExtraData (gen_utime_ms = gen_utime * 1000) and, for a masterchain
// block that registers new shard blocks, their ShardTopBlockDescr built from the archived proof links;
// their signatures are not archived, so such a context sets skip_shard_signatures.
//
// Mutations (--mutations) derive negative contexts from a target: each changes one input as described
// in kMutations, and its context is filled the same way.
//
//   conformance-validate-export --packs LIST --zerostate MC.boc --basestate BASE.boc
//       [--targets FILE] [--mutations FILE] [--range A-B ...] --out CONTEXTS.jsonl
//
// LIST: one package path per line. FILE: lines "<workchain> <seqno>" (targets) or
// "<workchain> <seqno> <mutation>" (mutations). A range A-B: every masterchain block A..B and every
// shard block whose masterchain reference is in A..B. The output is the input of `conformance.py create`.
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "../ref/validate-offline.hpp"
#include "block/block-auto.h"
#include "block/block-db.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "validator/impl/shard.hpp"
#include "vm/boc.h"
#include "vm/cells/CellUsageTree.h"
#include "vm/cells/MerkleProof.h"
#include "vm/cells/MerkleUpdate.h"
#include "vm/cells/UsageCell.h"
#include "vm/dict.h"
#include "vm/vm.h"

namespace {

using Cell = td::Ref<vm::Cell>;
using tos::BlockIdExt;
namespace validate = conformance::validate;

constexpr std::uint32_t kPackageMagic = 0xae8fdd01;
constexpr std::uint16_t kEntryTag = 0x1e8b;
constexpr std::uint64_t kMaxEntryBytes = 64ull << 20;
constexpr std::uint64_t kBaseShard = 0x8000000000000000ull;
constexpr std::uint32_t kStateWindow = 48;  // complete states kept per chain

[[noreturn]] void die(const std::string &message) {
  std::cerr << "validate-export: " << message << std::endl;
  std::exit(2);
}

std::string hex_upper(td::Slice bytes) {
  return td::buffer_to_hex(bytes);
}

std::string read_file(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in.good()) {
    die("cannot open " + path);
  }
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// ---- archive packages ------------------------------------------------------------------------------

struct Entry {
  std::size_t file = 0;
  std::uint64_t offset = 0, size = 0;
};

struct Chain {
  std::map<std::uint32_t, Entry> blocks, links;
};

struct Archive {
  std::vector<std::string> files;
  Chain mc, base;

  // block_(wc,shard,seqno):ROOT:FILE and prooflink_/proof_ entries of the masterchain and basechain.
  void add(const std::string &name, std::size_t file, std::uint64_t offset, std::uint64_t size) {
    auto open = name.find("_(");
    auto close = name.find(')');
    if (open == std::string::npos || close == std::string::npos || close < open) {
      return;
    }
    auto kind = name.substr(0, open);
    auto inner = name.substr(open + 2, close - open - 2);
    auto c1 = inner.find(','), c2 = inner.rfind(',');
    if (c1 == std::string::npos || c2 == c1) {
      return;
    }
    auto wc = td::to_integer_safe<int>(inner.substr(0, c1));
    auto shard = td::hex_to_integer_safe<std::uint64_t>(inner.substr(c1 + 1, c2 - c1 - 1));
    auto seqno = td::to_integer_safe<std::uint32_t>(inner.substr(c2 + 1));
    if (wc.is_error() || shard.is_error() || seqno.is_error() || shard.ok() != kBaseShard) {
      return;
    }
    Chain *chain = wc.ok() == tos::masterchainId ? &mc : wc.ok() == tos::basechainId ? &base : nullptr;
    if (chain == nullptr) {
      return;
    }
    Entry entry{file, offset, size};
    if (kind == "block") {
      chain->blocks.emplace(seqno.ok(), entry);
    } else if (kind == "prooflink" || kind == "proof") {
      // A masterchain block has a proof, a shard block a proof link; either holds the header proof.
      chain->links.emplace(seqno.ok(), entry);
    }
  }

  void index(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) {
      die("cannot open package " + path);
    }
    files.push_back(path);
    in.seekg(0, std::ios::end);
    const auto length = static_cast<std::uint64_t>(in.tellg());
    in.seekg(0);
    unsigned char head[8];
    in.read(reinterpret_cast<char *>(head), 4);
    if (!in.good() || (head[0] | head[1] << 8 | head[2] << 16 | std::uint32_t(head[3]) << 24) != kPackageMagic) {
      die(path + ": not an archive package");
    }
    std::uint64_t offset = 4;
    while (offset < length) {
      if (length - offset < 8) {
        die(path + ": truncated entry header");
      }
      in.seekg(static_cast<std::streamoff>(offset));
      in.read(reinterpret_cast<char *>(head), 8);
      const std::uint16_t tag = static_cast<std::uint16_t>(head[0] | head[1] << 8);
      const std::size_t name_len = head[2] | head[3] << 8;
      const std::uint64_t data_len = head[4] | head[5] << 8 | head[6] << 16 | std::uint64_t(head[7]) << 24;
      if (!in.good() || tag != kEntryTag || name_len == 0 || data_len > kMaxEntryBytes ||
          length - offset - 8 < name_len + data_len) {
        die(path + ": invalid entry at " + std::to_string(offset));
      }
      std::string name(name_len, '\0');
      in.read(name.data(), static_cast<std::streamsize>(name_len));
      add(name, files.size() - 1, offset + 8 + name_len, data_len);
      offset += 8 + name_len + data_len;
    }
  }

  std::string read(const Entry &entry) const {
    std::ifstream in(files[entry.file], std::ios::binary);
    std::string data(entry.size, '\0');
    in.seekg(static_cast<std::streamoff>(entry.offset));
    in.read(data.data(), static_cast<std::streamsize>(entry.size));
    if (!in.good()) {
      die("cannot read " + files[entry.file]);
    }
    return data;
  }
};

// ---- blocks and states -----------------------------------------------------------------------------

struct Block {
  BlockIdExt id;
  std::string bytes;
  Cell root;
  block::gen::BlockInfo::Record info;
  block::gen::BlockExtra::Record extra;
  Cell state_update;
  BlockIdExt master_ref;  // shard block: the masterchain block it references
};

Block parse_block(int wc, std::uint32_t seqno, std::string bytes) {
  Block b;
  b.bytes = std::move(bytes);
  auto root = vm::std_boc_deserialize(b.bytes);
  if (root.is_error()) {
    die(PSTRING() << "block " << wc << ":" << seqno << ": " << root.error());
  }
  b.root = root.move_as_ok();
  block::gen::Block::Record blk;
  if (!(tlb::unpack_cell(b.root, blk) && tlb::unpack_cell(blk.info, b.info) && tlb::unpack_cell(blk.extra, b.extra))) {
    die(PSTRING() << "block " << wc << ":" << seqno << ": cannot unpack");
  }
  if (b.info.seq_no != seqno || b.info.after_merge || b.info.after_split || b.info.before_split) {
    die(PSTRING() << "block " << wc << ":" << seqno << ": unexpected header (split, merge or seqno)");
  }
  b.state_update = blk.state_update;
  td::Bits256 file_hash;
  td::sha256(b.bytes, file_hash.as_slice());
  b.id = BlockIdExt{wc, kBaseShard, seqno, b.root->get_hash().bits(), file_hash};
  if (b.info.not_master) {
    block::gen::ExtBlkRef::Record ref;
    if (!tlb::unpack_cell(b.info.master_ref, ref)) {
      die(PSTRING() << "block " << wc << ":" << seqno << ": master_ref");
    }
    b.master_ref = BlockIdExt{tos::masterchainId, kBaseShard, ref.seq_no, ref.root_hash, ref.file_hash};
  }
  return b;
}

// The previous block a header names (one predecessor; splits and merges never happened).
BlockIdExt header_prev(const Block &b) {
  block::gen::ExtBlkRef::Record ref;
  if (!tlb::unpack_cell(b.info.prev_ref, ref)) {
    die("prev_ref of " + b.id.to_str());
  }
  return BlockIdExt{b.id.id.workchain, kBaseShard, ref.seq_no, ref.root_hash, ref.file_hash};
}

struct StateChain {
  int workchain;
  std::map<std::uint32_t, std::pair<BlockIdExt, Cell>> states;  // seqno -> (block, complete state)
  std::uint32_t last = 0;

  const std::pair<BlockIdExt, Cell> &at(std::uint32_t seqno) const {
    auto it = states.find(seqno);
    if (it == states.end()) {
      die(PSTRING() << "state " << workchain << ":" << seqno << " is outside the kept window");
    }
    return it->second;
  }

  void apply(const Block &b) {
    if (b.info.seq_no != last + 1) {
      die("blocks applied out of order at " + b.id.to_str());
    }
    const auto &[prev_id, prev_state] = at(last);
    if (header_prev(b) != prev_id) {
      die("parent of " + b.id.to_str() + " is not " + prev_id.to_str());
    }
    auto applied = vm::MerkleUpdate::apply(prev_state, b.state_update);
    if (applied.is_error()) {
      die("state update of " + b.id.to_str() + ": " + applied.error().to_string());
    }
    auto update = vm::load_cell_slice_special(b.state_update);
    if (applied.ok()->get_hash(0) != update.prefetch_ref(1)->get_hash(0)) {
      die("state update of " + b.id.to_str() + " does not reach its declared state");
    }
    last = b.info.seq_no;
    states[last] = {b.id, applied.move_as_ok()};
    while (!states.empty() && states.begin()->first + kStateWindow < last) {
      states.erase(states.begin());
    }
  }
};

// ---- collated data ---------------------------------------------------------------------------------

Cell consensus_extra_data(std::uint64_t gen_utime_ms) {
  // consensus_extra_data#638eb292 flags:# gen_utime_ms:uint64 = ConsensusExtraData;
  return vm::CellBuilder{}.store_long(0x638eb292, 32).store_long(0, 32).store_long(gen_utime_ms, 64).finalize();
}

// The header proof inside an archived proof or proof link (block_proof#c3 proof_for root signatures).
Cell header_proof(const Archive &archive, const Chain &chain, std::uint32_t seqno, const BlockIdExt &id) {
  auto it = chain.links.find(seqno);
  if (it == chain.links.end()) {
    die("no proof link for " + id.to_str());
  }
  auto root = vm::std_boc_deserialize(archive.read(it->second));
  block::gen::BlockProof::Record proof;
  BlockIdExt proof_for;
  if (root.is_error() || !tlb::unpack_cell(root.ok(), proof) ||
      !block::tlb::t_BlockIdExt.unpack(proof.proof_for.write(), proof_for) || proof_for != id) {
    die("proof link of " + id.to_str() + " is invalid");
  }
  return proof.root;
}

// ShardTopBlockDescr of a newly registered shard top, as AcceptBlockQuery assembles it from the header
// proofs of the blocks since the previous top, newest first. The shard block's signatures are not
// archived: the set is empty and carries the validator list hash and catchain seqno of the top's header,
// which is what an unsigned description is checked against when signatures are not checked.
Cell top_block_descr(const Archive &archive, const std::vector<BlockIdExt> &chain_newest_first,
                     const block::gen::BlockInfo::Record &top_info) {
  std::vector<Cell> proofs;
  for (const auto &id : chain_newest_first) {
    proofs.push_back(header_proof(archive, archive.base, id.seqno(), id));
  }
  const int n = static_cast<int>(proofs.size());
  Cell link;
  for (int i = n - 1; i > 0; i--) {
    vm::CellBuilder cb;
    if (!(cb.store_ref_bool(proofs[i]) && (link.is_null() || cb.store_ref_bool(link)) && cb.finalize_to(link))) {
      die("cannot serialize ProofChain");
    }
  }
  // block_signatures_ordinary#11 validator_list_hash_short catchain_seqno sig_count sig_weight signatures
  Cell signatures = vm::CellBuilder{}
                        .store_long(0x11, 8)
                        .store_long(top_info.gen_validator_list_hash_short, 32)
                        .store_long(top_info.gen_catchain_seqno, 32)
                        .store_long(0, 32)
                        .store_long(0, 64)
                        .store_long(0, 1)
                        .finalize();
  vm::CellBuilder cb;
  Cell descr;
  if (!(cb.store_long_bool(0xd5, 8) && block::tlb::t_BlockIdExt.pack(cb, chain_newest_first.front()) &&
        cb.store_bool_bool(true) && cb.store_ref_bool(signatures) && cb.store_long_bool(n, 8) &&
        cb.store_ref_bool(proofs[0]) && (link.is_null() || cb.store_ref_bool(link)) && cb.finalize_to(descr)) ||
      !block::gen::t_TopBlockDescr.validate_ref(descr)) {
    die("cannot build TopBlockDescr for " + chain_newest_first.front().to_str());
  }
  return descr;
}

// ---- JSON ------------------------------------------------------------------------------------------

std::string quote(const std::string &s) {
  std::string out = "\"";
  for (char c : s) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          out += ' ';
        } else {
          out += c;
        }
    }
  }
  return out + "\"";
}

std::string id_json(const BlockIdExt &id) {
  char shard[17];
  std::snprintf(shard, sizeof(shard), "%016llx", static_cast<unsigned long long>(id.id.shard));
  return PSTRING() << "{\"workchain\":" << id.id.workchain << ",\"shard\":\"" << shard << "\",\"seqno\":" << id.seqno()
                   << ",\"root_hash\":\"" << hex_upper(id.root_hash.as_slice()) << "\",\"file_hash\":\""
                   << hex_upper(id.file_hash.as_slice()) << "\"}";
}

std::string b64(td::Slice bytes) {
  return td::base64_encode(bytes);
}

std::string boc_b64(const Cell &cell) {
  auto bytes = vm::std_boc_serialize(cell, 0);
  if (bytes.is_error()) {
    die("cannot serialize a cell: " + bytes.error().to_string());
  }
  return b64(bytes.ok().as_slice());
}

// ---- one context -----------------------------------------------------------------------------------

// Everything a context is made of, with complete states.
struct Inputs {
  BlockIdExt candidate;
  std::string data;
  std::vector<Cell> collated;
  td::Bits256 created_by;
  std::vector<BlockIdExt> prev;
  BlockIdExt min_masterchain, top_masterchain, validator_set_from;
  bool skip_shard_signatures = false;
  std::map<BlockIdExt, Cell> states;  // every state the validation may ask for
};

std::string collated_bytes(const std::vector<Cell> &roots) {
  auto bytes = vm::std_boc_serialize_multi(roots, 0);
  if (bytes.is_error()) {
    die("cannot serialize collated data");
  }
  return bytes.ok().as_slice().str();
}

validate::Request request_of(const Inputs &in, std::map<BlockIdExt, Cell> states) {
  validate::Request request;
  request.candidate = in.candidate;
  request.data = td::BufferSlice(in.data);
  request.collated_data = td::BufferSlice(collated_bytes(in.collated));
  request.created_by = in.created_by;
  request.prev = in.prev;
  request.min_masterchain = in.min_masterchain;
  request.top_masterchain = in.top_masterchain;
  request.validator_set_from = in.validator_set_from;
  request.skip_shard_signatures = in.skip_shard_signatures;
  for (auto &[id, root] : states) {
    request.states.push_back({id, root});
  }
  return request;
}

const char *verdict_text(validate::Verdict v) {
  switch (v) {
    case validate::Verdict::accepted:
      return "accepted";
    case validate::Verdict::rejected:
      return "rejected";
    case validate::Verdict::error:
      return "error";
  }
  return "?";
}

// Usage of every state across all contexts, by state root hash: a state several contexts read (the
// previous state of one block is the masterchain state of the next shard blocks) gets one Merkle proof
// of the union of the cells they read, stored once in the family's blob file.
class Usage {
 public:
  // The usage-tracking root of a complete state.
  Cell track(const Cell &root) {
    auto &entry = states_[root->get_hash().bits()];
    if (entry.full.is_null()) {
      entry.full = root;
      entry.tree = std::make_shared<vm::CellUsageTree>();
      entry.tracked = vm::UsageCell::create(root, entry.tree->root_ptr());
    }
    return entry.tracked;
  }
  // The Merkle proof of what was read of the state, and its virtual root; built once, after every
  // context has been run.
  std::pair<Cell, Cell> proof(const td::Bits256 &hash) {
    auto &entry = states_.at(hash);
    if (entry.proof.is_null()) {
      auto proof = vm::MerkleProof::generate(entry.full, entry.tree.get());
      if (proof.is_error()) {
        die("proof of state " + hash.to_hex() + ": " + proof.error().to_string());
      }
      auto virt = vm::MerkleProof::virtualize(proof.ok());
      if (virt.is_error()) {
        die("proof of state " + hash.to_hex() + " does not virtualize");
      }
      entry.proof = proof.move_as_ok();
      entry.virtual_root = virt.move_as_ok();
    }
    return {entry.proof, entry.virtual_root};
  }

 private:
  struct Entry {
    Cell full, tracked, proof, virtual_root;
    std::shared_ptr<vm::CellUsageTree> tree;
  };
  std::map<td::Bits256, Entry> states_;
};

// A context run once with usage-tracked states, waiting for the proofs.
struct Pending {
  std::string fixture_id, note;
  Inputs in;  // states: only those the validation asked for, plus validator_set_from
  validate::Outcome outcome;
};

Pending first_run(const std::string &fixture_id, const std::string &note, Inputs in, Usage &usage) {
  std::map<BlockIdExt, Cell> tracked;
  for (const auto &[id, root] : in.states) {
    tracked[id] = usage.track(root);
  }
  auto first = validate::run(request_of(in, tracked));
  if (first.is_error()) {
    die(fixture_id + ": " + first.error().to_string());
  }
  std::set<BlockIdExt> needed(first.ok().states_requested.begin(), first.ok().states_requested.end());
  needed.insert(in.validator_set_from);
  std::map<BlockIdExt, Cell> kept;
  for (const auto &id : needed) {
    // A state asked for and not supplied stays missing: the harness sees it missing the same way.
    if (auto it = in.states.find(id); it != in.states.end()) {
      kept.insert(*it);
    }
  }
  in.states = std::move(kept);
  return {fixture_id, note, std::move(in), first.move_as_ok()};
}

// Validates again from the proofs, requires the first outcome, and writes the context.
std::string finish(Pending &p, Usage &usage) {
  std::map<BlockIdExt, Cell> virtual_roots;
  std::map<BlockIdExt, Cell> proofs;
  for (const auto &[id, root] : p.in.states) {
    auto [proof, virt] = usage.proof(root->get_hash().bits());
    proofs[id] = proof;
    virtual_roots[id] = virt;
  }
  auto second = validate::run(request_of(p.in, virtual_roots));
  if (second.is_error()) {
    die(p.fixture_id + ": " + second.error().to_string());
  }
  const auto &a = p.outcome;
  const auto &b = second.ok();
  if (a.verdict != b.verdict || a.message != b.message) {
    die(PSTRING() << p.fixture_id << ": outcome changed with pruned states: " << verdict_text(a.verdict) << " '"
                  << a.message << "' vs " << verdict_text(b.verdict) << " '" << b.message << "'");
  }
  const Inputs &in = p.in;
  std::string ctx = "{\"block_id\":" + id_json(in.candidate) + ",\"block\":" + quote(b64(in.data)) +
                    ",\"collated_data\":" + quote(b64(collated_bytes(in.collated))) +
                    ",\"created_by\":" + quote(hex_upper(in.created_by.as_slice())) + ",\"prev\":[";
  for (std::size_t i = 0; i < in.prev.size(); ++i) {
    ctx += (i ? "," : "") + id_json(in.prev[i]);
  }
  ctx += "],\"min_masterchain\":" + id_json(in.min_masterchain) +
         ",\"top_masterchain\":" + id_json(in.top_masterchain) +
         ",\"validator_set_from\":" + id_json(in.validator_set_from) +
         ",\"skip_shard_signatures\":" + (in.skip_shard_signatures ? "true" : "false") + ",\"states\":[";
  bool comma = false;
  for (const auto &[id, proof] : proofs) {
    ctx += (comma ? ",{\"block\":" : "{\"block\":") + id_json(id) + ",\"state\":" + quote(boc_b64(proof)) + "}";
    comma = true;
  }
  ctx += "]}";
  std::string note = p.note + (p.note.empty() ? "" : "; ") + "exporter: " + verdict_text(b.verdict);
  if (!b.message.empty()) {
    note += " (" + std::string(validate::classify(b)) + "): " + b.message.substr(0, 400);
  }
  std::cerr << p.fixture_id << ": " << verdict_text(b.verdict) << " " << validate::classify(b) << " "
            << b.message.substr(0, 300) << "\n";
  return "{\"fixture_id\":" + quote(p.fixture_id) + ",\"note\":" + quote(note) + ",\"context\":" + ctx + "}";
}

// ---- driver ----------------------------------------------------------------------------------------

struct Target {
  int workchain;
  std::uint32_t seqno;
  std::string mutation;  // empty: the archived block as it is
};

class Exporter {
 public:
  Exporter(Archive archive, std::string mc_zero, std::string base_zero)
      : archive_(std::move(archive)), mc_{tos::masterchainId, {}, 0}, base_{tos::basechainId, {}, 0} {
    mc_.states[0] = zero_state(tos::masterchainId, mc_zero);
    base_.states[0] = zero_state(tos::basechainId, base_zero);
  }

  // targets: single blocks; ranges: every masterchain block of the range and every shard block whose
  // masterchain reference is in it.
  void run(std::vector<Target> targets, const std::vector<std::pair<std::uint32_t, std::uint32_t>> &ranges,
           std::ostream &out) {
    std::map<std::pair<int, std::uint32_t>, std::vector<std::string>> wanted;
    for (auto &t : targets) {
      wanted[{t.workchain, t.seqno}].push_back(t.mutation);
    }
    std::uint32_t ranges_end = 0;
    for (const auto &[from, to] : ranges) {
      ranges_end = std::max(ranges_end, to);
    }
    auto in_range = [&](std::uint32_t mc_seqno) {
      return std::any_of(ranges.begin(), ranges.end(),
                         [&](const auto &r) { return r.first <= mc_seqno && mc_seqno <= r.second; });
    };
    std::size_t done = 0;
    for (std::uint32_t s = 1; done < wanted.size() || s <= ranges_end; ++s) {
      auto block = load(archive_.mc, tos::masterchainId, s);
      auto it = wanted.find({tos::masterchainId, s});
      if (it != wanted.end()) {
        for (auto &mutation : it->second) {
          emit(block, mutation);
        }
        ++done;
      }
      if (in_range(s) && (it == wanted.end() || std::count(it->second.begin(), it->second.end(), "") == 0)) {
        emit(block, "");
      }
      mc_.apply(block);
      // Every shard block whose masterchain reference is now applied, in order.
      while (true) {
        auto next = archive_.base.blocks.find(base_.last + 1);
        if (next == archive_.base.blocks.end()) {
          break;
        }
        auto shard_block = load(archive_.base, tos::basechainId, base_.last + 1);
        if (shard_block.master_ref.seqno() > s) {
          break;
        }
        auto shard_it = wanted.find({tos::basechainId, shard_block.info.seq_no});
        if (shard_it != wanted.end()) {
          for (auto &mutation : shard_it->second) {
            emit(shard_block, mutation);
          }
          ++done;
        }
        if (in_range(shard_block.master_ref.seqno()) &&
            (shard_it == wanted.end() || std::count(shard_it->second.begin(), shard_it->second.end(), "") == 0)) {
          emit(shard_block, "");
        }
        base_.apply(shard_block);
      }
    }
    for (auto &p : pending_) {
      out << finish(p, usage_) << "\n";
    }
  }

 private:
  Archive archive_;
  StateChain mc_, base_;
  Usage usage_;
  std::vector<Pending> pending_;

  static std::pair<BlockIdExt, Cell> zero_state(int wc, const std::string &bytes) {
    auto root = vm::std_boc_deserialize(bytes);
    if (root.is_error()) {
      die("zero state: " + root.error().to_string());
    }
    td::Bits256 file_hash;
    td::sha256(bytes, file_hash.as_slice());
    return {BlockIdExt{wc, kBaseShard, 0, root.ok()->get_hash().bits(), file_hash}, root.move_as_ok()};
  }

  Block load(const Chain &chain, int wc, std::uint32_t seqno) const {
    auto it = chain.blocks.find(seqno);
    if (it == chain.blocks.end()) {
      die(PSTRING() << "block " << wc << ":" << seqno << " is in no package");
    }
    return parse_block(wc, seqno, archive_.read(it->second));
  }

  // Inputs of the archived block as the node would validate it, with every kept state offered.
  Inputs inputs_of(const Block &b) const {
    Inputs in;
    in.candidate = b.id;
    in.data = b.bytes;
    in.created_by = b.extra.created_by;
    in.collated.push_back(consensus_extra_data(static_cast<std::uint64_t>(b.info.gen_utime) * 1000));
    for (const auto *chain : {&mc_, &base_}) {
      for (const auto &[seqno, entry] : chain->states) {
        in.states[entry.first] = entry.second;
      }
    }
    if (!b.info.not_master) {
      const auto &prev = mc_.at(b.info.seq_no - 1).first;
      in.prev = {prev};
      in.min_masterchain = in.top_masterchain = in.validator_set_from = prev;
      auto descrs = new_shard_tops(b, mc_.at(b.info.seq_no - 1).second, prev);
      if (descrs.not_null()) {
        in.collated.insert(in.collated.begin(), descrs);
        in.skip_shard_signatures = true;
      }
    } else {
      in.prev = {base_.at(b.info.seq_no - 1).first};
      in.min_masterchain = in.top_masterchain = in.validator_set_from = b.master_ref;
    }
    return in;
  }

  // TopBlockDescrSet for the shard tops the masterchain block registers, or null when it registers none.
  Cell new_shard_tops(const Block &b, const Cell &prev_state, const BlockIdExt &prev_id) const {
    block::gen::McBlockExtra::Record mc_extra;
    if (!tlb::unpack_cell(b.extra.custom->prefetch_ref(), mc_extra)) {
      die("McBlockExtra of " + b.id.to_str());
    }
    block::ShardConfig new_conf(mc_extra.shard_hashes->prefetch_ref());
    auto old_state = tos::validator::MasterchainStateQ::fetch(prev_id, {}, prev_state);
    if (old_state.is_error()) {
      die("masterchain state " + prev_id.to_str() + ": " + old_state.error().to_string());
    }
    vm::Dictionary set{96};
    bool any = false;
    for (const auto &top : new_conf.get_shard_hash_ids(true)) {
      auto now = new_conf.get_shard_hash(top.shard_full());
      auto before = old_state.ok()->get_shard_from_config(top.shard_full(), true);
      if (now.is_null()) {
        die("shard configuration of " + b.id.to_str() + " changed its layout");
      }
      // A shard the previous configuration does not list yet starts at its zero state.
      const std::uint32_t before_seqno = before.is_null() ? 0 : before->top_block_id().seqno();
      if (before.not_null() && now->top_block_id() == before->top_block_id()) {
        continue;
      }
      std::vector<BlockIdExt> chain;
      block::gen::BlockInfo::Record top_info;
      for (auto seqno = now->top_block_id().seqno(); seqno > before_seqno; --seqno) {
        auto block = load(archive_.base, tos::basechainId, seqno);
        if (chain.empty()) {
          top_info = block.info;
        }
        chain.push_back(block.id);
      }
      if (chain.empty()) {
        continue;  // the shard's zero state, registered by the masterchain itself
      }
      if (chain.front() != now->top_block_id() || chain.size() > 8) {
        die("shard top chain of " + b.id.to_str() + " is not in the archive or longer than 8");
      }
      td::BitArray<96> key;
      key.bits().store_int(top.workchain, 32);
      (key.bits() + 32).store_uint(top.shard, 64);
      if (!set.set_ref(key, top_block_descr(archive_, chain, top_info))) {
        die("cannot store a TopBlockDescr");
      }
      any = true;
    }
    if (!any) {
      return {};
    }
    vm::CellBuilder cb;
    Cell root;
    // top_block_descr_set#4ac789f3 collection:(HashmapE 96 ^TopBlockDescr) = TopBlockDescrSet;
    if (!(cb.store_long_bool(0x4ac789f3, 32) && set.append_dict_to_bool(cb) && cb.finalize_to(root))) {
      die("cannot build TopBlockDescrSet");
    }
    return root;
  }

  void emit(const Block &b, const std::string &mutation) {
    Inputs in = inputs_of(b);
    std::string id = PSTRING() << (b.info.not_master ? "base-" : "mc-") << b.info.seq_no;
    std::string note = "archived block " + b.id.to_str();
    if (!mutation.empty()) {
      id += ":" + mutation;
      note = mutate(mutation, b, in);
    }
    pending_.push_back(first_run(id, note, std::move(in), usage_));
  }

  std::string mutate(const std::string &mutation, const Block &b, Inputs &in) const;
};

// ---- mutations -------------------------------------------------------------------------------------

// Replaces the candidate's block by a rebuilt one and gives the candidate the rebuilt block's id.
void set_block(Inputs &in, const Cell &root) {
  auto bytes = vm::std_boc_serialize(root, 31);
  if (bytes.is_error()) {
    die("cannot serialize a mutated block");
  }
  in.data = bytes.ok().as_slice().str();
  td::Bits256 file_hash;
  td::sha256(in.data, file_hash.as_slice());
  in.candidate = BlockIdExt{in.candidate.id, root->get_hash().bits(), file_hash};
}

Cell rebuild(const Block &b, const std::function<void(block::gen::Block::Record &, block::gen::BlockInfo::Record &,
                                                      block::gen::BlockExtra::Record &)> &edit) {
  block::gen::Block::Record blk;
  block::gen::BlockInfo::Record info;
  block::gen::BlockExtra::Record extra;
  if (!(tlb::unpack_cell(b.root, blk) && tlb::unpack_cell(blk.info, info) && tlb::unpack_cell(blk.extra, extra))) {
    die("cannot unpack " + b.id.to_str());
  }
  edit(blk, info, extra);
  Cell root;
  if (!(tlb::pack_cell(blk.info, info) && tlb::pack_cell(blk.extra, extra) && tlb::pack_cell(root, blk))) {
    die("cannot repack " + b.id.to_str());
  }
  return root;
}

// A state with its header changed by edit.
Cell edit_state(const Cell &state, const std::function<void(block::gen::ShardStateUnsplit::Record &)> &edit) {
  block::gen::ShardStateUnsplit::Record record;
  if (!tlb::unpack_cell(state, record)) {
    die("cannot unpack a state");
  }
  edit(record);
  Cell root;
  if (!tlb::pack_cell(root, record)) {
    die("cannot repack a state");
  }
  return root;
}

// The block with its header changed by edit_info, and a state update to the block's new state with
// its header changed by edit_state, so that the new state agrees with the changed header.
Cell rebuild_with_state(const Block &b, const Cell &prev_state,
                        const std::function<void(block::gen::BlockInfo::Record &)> &edit_info,
                        const std::function<void(block::gen::ShardStateUnsplit::Record &)> &edit_new_state) {
  auto next = vm::MerkleUpdate::apply(prev_state, b.state_update);
  if (next.is_error()) {
    die("state update of " + b.id.to_str());
  }
  auto changed = edit_state(next.ok(), edit_new_state);
  auto tree = std::make_shared<vm::CellUsageTree>();
  auto update = vm::MerkleUpdate::generate(prev_state, changed, tree.get());
  if (update.is_error()) {
    die("cannot generate a state update for " + b.id.to_str());
  }
  return rebuild(b, [&](auto &blk, auto &info, auto &) {
    edit_info(info);
    blk.state_update = update.ok();
  });
}

Cell dict_cell(vm::AugmentedDictionary &dict) {
  vm::CellBuilder cb;
  if (!dict.append_dict_to_bool(cb)) {
    die("cannot serialize a dictionary");
  }
  return cb.finalize();
}

std::string Exporter::mutate(const std::string &mutation, const Block &b, Inputs &in) const {
  if (mutation == "prev_state_altered") {
    // The state served for the previous block keeps its header block id but has another root hash.
    const auto &chain = b.info.not_master ? base_ : mc_;
    in.states[in.prev[0]] = edit_state(chain.at(b.info.seq_no - 1).second, [](auto &state) { state.gen_utime += 1; });
    return "the state served for the previous block has gen_utime + 1 (so another root hash)";
  }
  if (mutation == "mc_state_missing") {
    // The state of the referenced masterchain block is withheld; the manager knows up to the one before.
    in.states.erase(b.master_ref);
    in.min_masterchain = in.validator_set_from = in.top_masterchain = mc_.at(b.master_ref.seqno() - 1).first;
    return "the referenced masterchain state is not supplied";
  }
  if (mutation == "fees_collected_plus_one") {
    set_block(in, rebuild(b, [&](auto &blk, auto &, auto &) {
                block::ValueFlow flow;
                if (!flow.unpack(vm::load_cell_slice_ref(blk.value_flow))) {
                  die("value flow of " + b.id.to_str());
                }
                flow.fees_collected += block::CurrencyCollection{td::make_refint(1)};
                vm::CellBuilder cb;
                if (!flow.store(cb)) {
                  die("cannot store a value flow");
                }
                blk.value_flow = cb.finalize();
              }));
    return "ValueFlow fees_collected increased by 1";
  }
  if (mutation == "account_block_removed" || mutation == "transaction_duplicated") {
    const bool remove = mutation == "account_block_removed";
    std::string what;
    set_block(
        in, rebuild(b, [&](auto &, auto &, auto &extra) {
          vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(extra.account_blocks), 256,
                                           block::tlb::aug_ShardAccountBlocks};
          td::Bits256 key;
          bool found = false;
          accounts.check_for_each_extra([&](td::Ref<vm::CellSlice>, td::Ref<vm::CellSlice>, td::ConstBitPtr k, int) {
            if (!found) {
              key = td::Bits256{k};
              found = true;
            }
            return true;
          });
          if (!found) {
            die(b.id.to_str() + " has no transactions");
          }
          if (remove) {
            if (accounts.lookup_delete(key.bits(), 256).is_null()) {
              die("cannot delete an account block");
            }
            what = "the account block of " + key.to_hex() + " (with its transactions) removed";
          } else {
            auto value = accounts.lookup(key.bits(), 256);
            block::gen::AccountBlock::Record ab;
            if (value.is_null() || !block::gen::t_AccountBlock.unpack(value.write(), ab)) {
              die("account block of " + b.id.to_str());
            }
            vm::AugmentedDictionary txs{vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions};
            td::BitArray<64> max_lt;
            if (txs.get_minmax_key(max_lt, true).is_null()) {
              die("transactions of " + b.id.to_str());
            }
            auto last = txs.lookup_ref(max_lt);
            td::BitArray<64> next_lt;
            next_lt.store_ulong(max_lt.to_ulong() + 1);
            if (last.is_null() || !txs.set_ref(next_lt, last, vm::Dictionary::SetMode::Add)) {
              die("cannot add a transaction");
            }
            ab.transactions = vm::load_cell_slice_ref(txs.get_root_cell());
            vm::CellBuilder cb;
            if (!(block::gen::t_AccountBlock.pack(cb, ab) &&
                  accounts.set_builder(key.bits(), 256, cb, vm::Dictionary::SetMode::Replace))) {
              die("cannot store the account block");
            }
            what = PSTRING() << "the last transaction of " << key.to_hex() << " repeated at lt "
                             << max_lt.to_ulong() + 1;
          }
          extra.account_blocks = dict_cell(accounts);
        }));
    return what;
  }
  if (mutation == "transaction_fees_plus_one") {
    std::string what;
    set_block(in, rebuild(b, [&](auto &, auto &, auto &extra) {
                vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(extra.account_blocks), 256,
                                                 block::tlb::aug_ShardAccountBlocks};
                td::Bits256 key;
                if (accounts.get_minmax_key(key, false).is_null()) {
                  die(b.id.to_str() + " has no transactions");
                }
                auto value = accounts.lookup(key.bits(), 256);
                block::gen::AccountBlock::Record ab;
                if (value.is_null() || !block::gen::t_AccountBlock.unpack(value.write(), ab)) {
                  die("account block of " + b.id.to_str());
                }
                vm::AugmentedDictionary txs{vm::DictNonEmpty(), ab.transactions, 64,
                                            block::tlb::aug_AccountTransactions};
                td::BitArray<64> lt;
                if (txs.get_minmax_key(lt, false).is_null()) {
                  die("transactions of " + b.id.to_str());
                }
                // transaction$0111 account_addr lt prev_trans_hash prev_trans_lt now outmsg_cnt orig_status
                // end_status (695 bits) ^[in_msg out_msgs] total_fees:CurrencyCollection state_update description
                auto tx_cell = txs.lookup_ref(lt);
                if (tx_cell.is_null()) {
                  die("transaction of " + b.id.to_str());
                }
                auto cs = vm::load_cell_slice(tx_cell);
                auto head = cs.fetch_bits(695);
                auto aux = cs.fetch_ref();
                block::CurrencyCollection fees;
                if (aux.is_null() || !fees.fetch(cs)) {
                  die("transaction of " + b.id.to_str());
                }
                fees += block::CurrencyCollection{td::make_refint(1)};
                vm::CellBuilder tx_cb;
                Cell changed;
                if (!(tx_cb.append_bitslice(head) && tx_cb.store_ref_bool(aux) && fees.store(tx_cb) &&
                      tx_cb.append_cellslice_bool(cs) && tx_cb.finalize_to(changed))) {
                  die("cannot rebuild a transaction");
                }
                if (!txs.set_ref(lt, changed, vm::Dictionary::SetMode::Replace)) {
                  die("cannot replace a transaction");
                }
                ab.transactions = vm::load_cell_slice_ref(txs.get_root_cell());
                vm::CellBuilder cb;
                if (!(block::gen::t_AccountBlock.pack(cb, ab) &&
                      accounts.set_builder(key.bits(), 256, cb, vm::Dictionary::SetMode::Replace))) {
                  die("cannot store the account block");
                }
                extra.account_blocks = dict_cell(accounts);
                what = PSTRING() << "total_fees of the first transaction of " << key.to_hex() << " (lt "
                                 << lt.to_ulong() << ") increased by 1";
              }));
    return what;
  }
  if (mutation == "prev_block_other") {
    const auto &chain = b.info.not_master ? base_ : mc_;
    in.prev = {chain.at(b.info.seq_no - 2).first};
    if (!b.info.not_master) {
      in.min_masterchain = in.prev[0];
    }
    return "the validation is asked for a candidate whose previous block is the one before the real one";
  }
  if (mutation == "out_msg_removed") {
    set_block(
        in, rebuild(b, [&](auto &, auto &, auto &extra) {
          vm::AugmentedDictionary out_msgs{vm::load_cell_slice_ref(extra.out_msg_descr), 256,
                                           block::tlb::aug_OutMsgDescrDefault};
          td::Bits256 key;
          bool found = false;
          out_msgs.check_for_each_extra([&](td::Ref<vm::CellSlice>, td::Ref<vm::CellSlice>, td::ConstBitPtr k, int) {
            if (!found) {
              key = td::Bits256{k};
              found = true;
            }
            return true;
          });
          if (!found || out_msgs.lookup_delete(key.bits(), 256).is_null()) {
            die(b.id.to_str() + " has no outbound message to remove");
          }
          extra.out_msg_descr = dict_cell(out_msgs);
        }));
    return "one OutMsgDescr entry removed";
  }
  const auto &own_chain = b.info.not_master ? base_ : mc_;
  if (mutation == "gen_utime_earlier") {
    // Header, new state and ConsensusExtraData all say one hour earlier, before the previous state.
    const std::uint32_t utime = b.info.gen_utime - 3600;
    set_block(in, rebuild_with_state(
                      b, own_chain.at(b.info.seq_no - 1).second, [&](auto &info) { info.gen_utime = utime; },
                      [&](auto &state) { state.gen_utime = utime; }));
    in.collated.back() = consensus_extra_data(static_cast<std::uint64_t>(utime) * 1000);
    return "gen_utime one hour earlier in the header, the new state and ConsensusExtraData";
  }
  if (mutation == "gen_utime_header_only") {
    set_block(in, rebuild(b, [&](auto &, auto &info, auto &) { info.gen_utime -= 3600; }));
    in.collated.back() = consensus_extra_data(static_cast<std::uint64_t>(b.info.gen_utime - 3600) * 1000);
    return "gen_utime one hour earlier in the header and ConsensusExtraData only";
  }
  if (mutation == "gen_utime_ms_mismatch") {
    in.collated.back() = consensus_extra_data((static_cast<std::uint64_t>(b.info.gen_utime) + 1) * 1000);
    return "ConsensusExtraData gen_utime_ms one second after gen_utime";
  }
  if (mutation == "start_lt_unaligned") {
    set_block(in, rebuild(b, [&](auto &, auto &info, auto &) { info.start_lt += 1; }));
    return "start_lt increased by 1 (not aligned)";
  }
  if (mutation == "lt_delta_oversize") {
    // Header and new state agree on an end_lt 2^40 after start_lt.
    const auto end_lt = b.info.start_lt + (1ull << 40);
    set_block(in, rebuild_with_state(
                      b, own_chain.at(b.info.seq_no - 1).second, [&](auto &info) { info.end_lt = end_lt; },
                      [&](auto &state) { state.gen_lt = end_lt; }));
    return "end_lt 2^40 after start_lt in the header and the new state (logical time delta above the hard limit)";
  }
  if (mutation == "state_update_noop") {
    set_block(in, rebuild(b, [&](auto &blk, auto &, auto &) {
                const auto &chain = b.info.not_master ? base_ : mc_;
                const auto &prev = chain.at(b.info.seq_no - 1).second;
                auto tree = std::make_shared<vm::CellUsageTree>();
                auto update = vm::MerkleUpdate::generate(prev, prev, tree.get());
                if (update.is_error()) {
                  die("cannot generate a state update");
                }
                blk.state_update = update.move_as_ok();
              }));
    return "state update leaves the previous state unchanged";
  }
  if (mutation == "candidate_file_hash") {
    in.candidate.file_hash.as_slice()[0] ^= 1;
    return "candidate id with another file hash";
  }
  if (mutation == "candidate_shard_other") {
    in.candidate.id.shard = 0x4000000000000000ull;
    return "candidate id names the shard 4000000000000000";
  }
  if (mutation == "created_by_other") {
    in.created_by.as_slice()[0] ^= 1;
    return "candidate producer differs from the block's created_by";
  }
  die("unknown mutation " + mutation);
}

std::vector<Target> read_targets(const std::string &path, bool with_mutation) {
  std::vector<Target> targets;
  std::istringstream lines(read_file(path));
  std::string line;
  while (std::getline(lines, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    std::istringstream fields(line);
    Target t;
    if (!(fields >> t.workchain >> t.seqno) || (with_mutation && !(fields >> t.mutation)) ||
        (t.workchain != tos::masterchainId && t.workchain != tos::basechainId) || t.seqno < 1) {
      die(path + ": bad line '" + line + "'");
    }
    targets.push_back(t);
  }
  return targets;
}

}  // namespace

int main(int argc, char **argv) {
  SET_VERBOSITY_LEVEL(verbosity_FATAL);
  vm::init_vm().ensure();
  std::string packs, zerostate, basestate, targets_path, mutations_path, out_path;
  std::vector<std::pair<std::uint32_t, std::uint32_t>> ranges;
  for (int i = 1; i + 1 < argc; i += 2) {
    std::string flag = argv[i];
    std::string value = argv[i + 1];
    if (flag == "--packs") {
      packs = value;
    } else if (flag == "--zerostate") {
      zerostate = value;
    } else if (flag == "--basestate") {
      basestate = value;
    } else if (flag == "--targets") {
      targets_path = value;
    } else if (flag == "--mutations") {
      mutations_path = value;
    } else if (flag == "--range") {
      auto dash = value.find('-');
      auto from = td::to_integer_safe<std::uint32_t>(value.substr(0, dash));
      auto to = td::to_integer_safe<std::uint32_t>(dash == std::string::npos ? "" : value.substr(dash + 1));
      if (from.is_error() || to.is_error() || from.ok() < 1 || to.ok() < from.ok()) {
        die("--range A-B with 1 <= A <= B required");
      }
      ranges.emplace_back(from.ok(), to.ok());
    } else if (flag == "--out") {
      out_path = value;
    } else {
      die("unknown flag " + flag);
    }
  }
  if (packs.empty() || zerostate.empty() || basestate.empty() || out_path.empty() ||
      (targets_path.empty() && mutations_path.empty() && ranges.empty())) {
    die("usage: --packs LIST --zerostate MC.boc --basestate BASE.boc [--targets FILE] [--mutations FILE] "
        "[--range A-B ...] --out FILE");
  }
  Archive archive;
  {
    std::istringstream lines(read_file(packs));
    std::string line;
    while (std::getline(lines, line)) {
      if (!line.empty()) {
        archive.index(line);
      }
    }
  }
  std::vector<Target> targets;
  if (!targets_path.empty()) {
    targets = read_targets(targets_path, false);
  }
  if (!mutations_path.empty()) {
    auto mutations = read_targets(mutations_path, true);
    targets.insert(targets.end(), mutations.begin(), mutations.end());
  }
  std::ofstream out(out_path);
  Exporter exporter(std::move(archive), read_file(zerostate), read_file(basestate));
  exporter.run(std::move(targets), ranges, out);
  out.close();
  return out.good() ? 0 : 2;
}
