// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Offline whole-history replay of archived chain history (docs/archive.md).
//
// The tool reads archive packages (or plain block BOC files), orders every masterchain and shard block,
// and for each block checks its identity (root hash, file hash, header id, parent link), applies its
// Merkle state update to the previous state and checks the new state root, and re-executes every
// transaction through the production transaction emulator, comparing the transaction hash, the new
// account hash and the account stored in the new state with the chain. The chain is the only oracle.
//
// Two state modes:
//   full      the previous state is complete (from a zero state, or after hydration became complete);
//             the update is applied to it, so the new state is complete too.
//   hydrated  the previous state is not available (the replay starts inside history or after a gap); the
//             block's own update tree is completed from known original cells (a level-zero hash match
//             cannot change any value) and any read of a cell that stays pruned is a counted refusal.
// Every block that is absent, unreadable, refused or not reached is counted with its reason.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "emulator/transaction-emulator.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/misc.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/cells/MerkleUpdate.h"
#include "vm/vm.h"

namespace {
using Cell = td::Ref<vm::Cell>;

constexpr std::uint32_t package_magic = 0xae8fdd01;
constexpr std::uint16_t entry_tag = 0x1e8b;
constexpr std::size_t max_entry_name = 1024;
constexpr std::uint64_t max_entry_bytes = 256ull << 20;
constexpr std::size_t max_list_lines = 1000000;
constexpr std::size_t master_window = 1024;
constexpr std::size_t max_copy_cells = 4000000;
constexpr unsigned max_copy_depth = 2048;
constexpr std::size_t blob_threshold = 2048;
constexpr std::uint64_t max_repro_state_bytes = 64ull << 20;

struct Refusal : std::runtime_error {
  using std::runtime_error::runtime_error;
};

template <class T>
T require(td::Result<T> result) {
  if (result.is_error())
    throw std::runtime_error(result.error().to_string());
  return result.move_as_ok();
}
void check(bool value, const std::string& message) {
  if (!value)
    throw std::runtime_error(message);
}
std::string hash(const Cell& cell) {
  return cell->get_hash(0).to_hex();
}
std::string sha256_hex(td::Slice bytes) {
  td::Bits256 digest;
  td::sha256(bytes, digest.as_slice());
  return digest.to_hex();
}
std::string lower(std::string text) {
  for (auto& c : text)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return text;
}
std::string quote(td::Slice text) {
  std::string out = "\"";
  for (unsigned char c : text) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += static_cast<char>(c);
    } else if (c < 0x20 || c >= 0x7f) {
      char buf[8];
      std::snprintf(buf, sizeof(buf), "\\u%04x", c);
      out += buf;
    } else {
      out += static_cast<char>(c);
    }
  }
  return out + "\"";
}
std::string shard_hex(std::uint64_t shard) {
  char buf[24];
  std::snprintf(buf, sizeof(buf), "%016llX", static_cast<unsigned long long>(shard));
  return buf;
}
// A reason without the hashes it names, so equal causes aggregate in the summary.
std::string reason_class(const std::string& text) {
  std::string out;
  std::size_t run = 0;
  for (char c : text) {
    bool hex = std::isxdigit(static_cast<unsigned char>(c)) != 0;
    run = hex ? run + 1 : 0;
    out += c;
    if (run == 16)
      out.replace(out.size() - 16, 16, "<hash>");
    else if (run > 16)
      out.pop_back();
  }
  return out.substr(0, 200);
}

std::vector<std::string> read_list(const std::string& path) {
  std::ifstream input(path);
  check(input.good(), "cannot read list " + path);
  std::vector<std::string> out;
  for (std::string line; std::getline(input, line);) {
    if (!line.empty())
      out.push_back(line);
    check(out.size() <= max_list_lines, "list too long: " + path);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Archive packages: a 4-byte magic, then entries of (tag u16, name length u16, data length u32, name,
// data), little endian. Only block_ entries are replayed; the others are counted.

struct Entry {
  std::size_t file = 0;  // index into Index::files
  std::uint64_t offset = 0;
  std::uint64_t size = 0;
  std::string root;  // uppercase hex, from the entry name or the file
  std::string file_hash;
};

struct ChainIndex {
  std::map<std::uint32_t, Entry> blocks;
};

struct Index {
  std::vector<std::string> files;
  ChainIndex mc, shard;
  std::uint64_t packages = 0, entries = 0, block_entries = 0, duplicate_entries = 0;
  std::map<std::string, std::uint64_t> other_entries;  // by entry kind (proof, prooflink, ...)
  std::map<std::string, std::uint64_t> other_shards;   // block entries of shards this tool does not replay
  std::vector<std::string> package_errors;
  std::vector<std::string> conflicts;  // two different blocks under one id
};

bool parse_block_name(const std::string& name, int& wc, std::uint64_t& shard, std::uint32_t& seqno, std::string& root,
                      std::string& file) {
  // block_(wc,shardhex,seqno):ROOT:FILE
  if (name.compare(0, 7, "block_(") != 0)
    return false;
  auto close = name.find(')');
  if (close == std::string::npos || name.size() != close + 1 + 1 + 64 + 1 + 64)
    return false;
  auto inner = name.substr(7, close - 7);
  auto c1 = inner.find(','), c2 = inner.rfind(',');
  if (c1 == std::string::npos || c2 == c1)
    return false;
  try {
    wc = std::stoi(inner.substr(0, c1));
    shard = std::stoull(inner.substr(c1 + 1, c2 - c1 - 1), nullptr, 16);
    auto s = std::stoull(inner.substr(c2 + 1));
    if (s > 0xffffffffull)
      return false;
    seqno = static_cast<std::uint32_t>(s);
  } catch (const std::exception&) {
    return false;
  }
  if (name[close + 1] != ':' || name[close + 66] != ':')
    return false;
  root = name.substr(close + 2, 64);
  file = name.substr(close + 67, 64);
  return true;
}

void add_entry(Index& index, int wc, std::uint64_t shard, std::uint32_t seqno, Entry entry, const std::string& what) {
  ChainIndex* chain = nullptr;
  if (wc == -1 && shard == 0x8000000000000000ull)
    chain = &index.mc;
  else if (wc == 0 && shard == 0x8000000000000000ull)
    chain = &index.shard;
  if (chain == nullptr) {
    index.other_shards[std::to_string(wc) + ":" + shard_hex(shard)]++;
    return;
  }
  auto inserted = chain->blocks.emplace(seqno, entry);
  if (!inserted.second) {
    auto& known = inserted.first->second;
    if (known.root == entry.root && known.file_hash == entry.file_hash)
      index.duplicate_entries++;
    else
      index.conflicts.push_back(what + " seqno " + std::to_string(seqno) + ": " + known.root + " vs " + entry.root);
  }
}

// Calls visit(name, data offset, data size) for every entry; returns an error text or "".
template <class F>
std::string scan_package(std::ifstream& in, F&& visit) {
  in.seekg(0, std::ios::end);
  std::uint64_t length = static_cast<std::uint64_t>(in.tellg());
  in.seekg(0);
  unsigned char head[8];
  in.read(reinterpret_cast<char*>(head), 4);
  if (!in.good() ||
      (head[0] | head[1] << 8 | head[2] << 16 | static_cast<std::uint32_t>(head[3]) << 24) != package_magic)
    return "not an archive package";
  std::uint64_t offset = 4;
  while (offset < length) {
    if (length - offset < 8)
      return "truncated entry header at " + std::to_string(offset);
    in.seekg(static_cast<std::streamoff>(offset));
    in.read(reinterpret_cast<char*>(head), 8);
    std::uint16_t tag = static_cast<std::uint16_t>(head[0] | head[1] << 8);
    std::size_t name_len = head[2] | head[3] << 8;
    std::uint64_t data_len = head[4] | head[5] << 8 | head[6] << 16 | static_cast<std::uint64_t>(head[7]) << 24;
    if (!in.good() || tag != entry_tag || name_len == 0 || name_len > max_entry_name || data_len > max_entry_bytes ||
        length - offset - 8 < name_len + data_len)
      return "invalid entry at " + std::to_string(offset);
    std::string name(name_len, '\0');
    in.read(name.data(), static_cast<std::streamsize>(name_len));
    if (!in.good())
      return "cannot read entry name at " + std::to_string(offset);
    visit(name, offset + 8 + name_len, data_len);
    offset += 8 + name_len + data_len;
  }
  return "";
}

void index_package(Index& index, const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in.good()) {
    index.package_errors.push_back(path + ": cannot open");
    return;
  }
  index.files.push_back(path);
  std::size_t file_id = index.files.size() - 1;
  index.packages++;
  auto error = scan_package(in, [&](const std::string& name, std::uint64_t offset, std::uint64_t size) {
    index.entries++;
    int wc = 0;
    std::uint64_t shard = 0;
    std::uint32_t seqno = 0;
    std::string root, file;
    if (parse_block_name(name, wc, shard, seqno, root, file)) {
      index.block_entries++;
      add_entry(index, wc, shard, seqno, Entry{file_id, offset, size, root, file}, path);
    } else {
      index.other_entries[name.substr(0, name.find('_'))]++;
    }
  });
  if (!error.empty())
    index.package_errors.push_back(path + ": " + error);
}

class Reader {
  const Index& index_;
  std::size_t open_ = static_cast<std::size_t>(-1);
  std::ifstream in_;

 public:
  explicit Reader(const Index& index) : index_(index) {
  }
  std::string read(const Entry& entry) {
    if (open_ != entry.file) {
      in_ = std::ifstream(index_.files.at(entry.file), std::ios::binary);
      check(in_.good(), "cannot open " + index_.files.at(entry.file));
      open_ = entry.file;
    }
    std::string bytes(entry.size, '\0');
    in_.seekg(static_cast<std::streamoff>(entry.offset));
    in_.read(bytes.data(), static_cast<std::streamsize>(entry.size));
    check(in_.good(), "cannot read entry of " + index_.files.at(entry.file));
    return bytes;
  }
};

// ---------------------------------------------------------------------------------------------
// Original cells that complete pruned update trees, accepted only by their level-zero hash.

class Cells {
  std::map<std::string, Cell> known_;
  std::set<std::string> seen_;
  std::map<std::string, Cell> hydrated_;

 public:
  void add(const Cell& root) {
    std::vector<Cell> stack{root};
    while (!stack.empty()) {
      Cell cell = stack.back();
      stack.pop_back();
      if (!seen_.insert(cell->get_hash().to_hex()).second)
        continue;
      auto cs = vm::load_cell_slice_special(cell);
      if (!cs.is_special()) {
        auto inserted = known_.emplace(hash(cell), cell);
        if (!inserted.second && inserted.first->second->get_hash() != cell->get_hash() &&
            inserted.first->second->get_level() > 0) {
          // Two authenticated views of one subtree: the production combiner keeps the original hash.
          auto combined = vm::MerkleProof::combine_fast_raw(inserted.first->second, cell);
          if (combined.is_ok())
            inserted.first->second = combined.move_as_ok();
        }
      }
      for (unsigned i = 0; i < cs.size_refs(); ++i)
        stack.push_back(cs.prefetch_ref(i));
    }
  }
  std::size_t size() const {
    return known_.size();
  }
  void clear_cache() {
    hydrated_.clear();
  }
  Cell hydrate(const Cell& root, unsigned depth = 0) {
    check(depth <= max_copy_depth, "hydration depth limit exceeded");
    if (root->get_level() == 0)
      return root;
    auto key = hash(root);
    auto cached = hydrated_.find(key);
    if (cached != hydrated_.end())
      return cached->second;
    auto cs = vm::load_cell_slice_special(root);
    if (cs.special_type() == vm::Cell::SpecialType::PrunnedBranch) {
      auto it = known_.find(key);
      if (it == known_.end() || it->second->get_hash() == root->get_hash())
        return root;
      return hydrate(it->second, depth + 1);
    }
    if (!cs.is_special()) {
      auto it = known_.find(key);
      if (it != known_.end() && it->second->get_level() < root->get_level())
        cs = vm::load_cell_slice_special(it->second);
    }
    vm::CellBuilder builder;
    builder.store_bits(cs.fetch_bits(cs.size()));
    while (cs.size_refs())
      builder.store_ref(hydrate(cs.fetch_ref(), depth + 1));
    auto result = builder.finalize(cs.is_special());
    check(hash(result) == key, "an original cell changed a state hash");
    hydrated_.emplace(key, result);
    return result;
  }
};

// Copies a possibly virtualized cell tree into plain cells that serialize, preserving each
// representation (a pruned branch stays a pruned branch).
Cell materialize(const Cell& cell, std::map<std::pair<std::string, unsigned>, Cell>& copies, unsigned depth) {
  check(depth <= max_copy_depth, "copy depth limit exceeded");
  auto loaded = require(cell->load_cell());
  auto data = loaded.data_cell;
  auto key = std::make_pair(data->get_hash().to_hex(), loaded.effective_level);
  auto known = copies.find(key);
  if (known != copies.end())
    return known->second;
  check(copies.size() < max_copy_cells, "copy cell count limit exceeded");
  auto cs = vm::load_cell_slice_special(Cell(data));
  vm::CellBuilder builder;
  check(builder.store_bits_bool(cs.fetch_bits(cs.size())), "cannot copy cell bits");
  for (unsigned i = 0; i < data->size_refs(); ++i) {
    auto child = materialize(data->get_ref(i), copies, depth + 1);
    check(child.not_null() && builder.store_ref_bool(std::move(child)), "cannot copy cell reference");
  }
  auto result = builder.finalize(cs.is_special());
  check(hash(result) == hash(cell), "copy changed a logical cell hash");
  copies.emplace(key, result);
  return result;
}

std::string boc_bytes(const Cell& cell) {
  std::map<std::pair<std::string, unsigned>, Cell> copies;
  auto bytes = require(vm::std_boc_serialize(materialize(cell, copies, 0), 0));
  return bytes.as_slice().str();
}

// ---------------------------------------------------------------------------------------------
// Options and output

struct Options {
  std::string source = "archive";
  std::vector<std::string> packs, block_files, cell_files, cell_packs;
  std::string zerostate, basestate, out_dir;
  std::uint32_t max_mismatches = 5;
  std::uint32_t mc_limit = 0;  // 0: no bound
  std::string export_dir;
  std::uint32_t export_from = 0, export_to = 0;
  std::uint64_t export_limit = 5000;
};

struct ChainStats {
  std::uint64_t indexed = 0, replayed = 0, ok = 0, mismatched = 0, refused = 0, absent = 0, unlinked_starts = 0;
  std::uint64_t full_mode = 0, hydrated_mode = 0;
  std::map<std::string, std::uint64_t> not_replayed;  // reason -> blocks
};

struct Stats {
  ChainStats mc, shard;
  std::uint64_t tx_onchain = 0, tx_executed = 0, tx_matched = 0, tx_mismatched = 0, tx_refused = 0,
                tx_skipped_after_mismatch = 0, tx_ordinary = 0, tx_tick = 0, tx_tock = 0;
  std::uint64_t account_state_checks = 0, shard_top_checks = 0, exported = 0;
  std::uint64_t mismatches = 0;  // mismatch events, the give-up counter
  std::map<std::string, std::uint64_t> refusal_reasons, mismatch_kinds;
  std::vector<std::string> mismatch_details, gaps;
  bool gave_up = false;
};

struct BlockRecord {
  std::string status = "ok";
  std::vector<std::string> mismatches, refusals;
  std::uint64_t transactions = 0, executed = 0, matched = 0;
  std::string mode = "full";
  bool linked = false;
  std::string old_state, new_state;
};

// ---------------------------------------------------------------------------------------------
// Replay state

struct MasterView {
  tos::BlockIdExt id;
  Cell state;  // state after this masterchain block (or the zero state)
  std::shared_ptr<block::ConfigInfo> config;
  std::string config_error;
  bool built = false;
};

struct ChainState {
  bool linked = false;  // last_id is the replayed predecessor
  tos::BlockIdExt last_id;
  bool have_hash = false;
  std::string state_hash;  // hash of the state after last_id
  Cell state;              // complete state when full
  bool full = false;
};

struct ParsedBlock {
  std::uint32_t seqno = 0;
  std::string bytes;
  Cell root;
  block::gen::Block::Record block;
  block::gen::BlockInfo::Record info;
  block::gen::BlockExtra::Record extra;
  tos::ShardIdFull shard;
};

struct TxContext {
  int type = 0;
  std::uint32_t now = 0;
  std::uint64_t lt = 0;
  std::string seed;
  Cell shard_account, message, config, libraries, prev_blocks;
  std::string chain_tx, chain_account;
  std::string fixture_id, note;
};

class Replay {
 public:
  Replay(Options options, Index& index) : opt_(std::move(options)), index_(index), reader_(index) {
  }
  int run();

 private:
  Options opt_;
  Index& index_;
  Reader reader_;
  Cells cells_;
  Stats stats_;
  std::map<std::uint32_t, MasterView> masters_;
  ChainState mc_, shard_;
  std::ofstream blocks_out_, export_out_;
  std::map<std::string, std::string> export_blobs_;  // digest -> base64
  std::map<std::string, std::string> b64_cache_;     // cell hash -> base64
  std::uint32_t step_ = 0;

  bool full_master_ = false;

  void gap(bool master, std::uint32_t from, std::uint32_t to, const std::string& reason);
  void write_block(const ParsedBlock* parsed, const Entry& entry, bool master, std::uint32_t seqno,
                   const BlockRecord& record);
  bool load(const Entry& entry, std::uint32_t seqno, bool master, ParsedBlock& out, std::string& error);
  void replay_block(const Entry& entry, std::uint32_t seqno, bool master);
  MasterView* master_view(std::uint32_t seqno, const td::Bits256& root, const td::Bits256& file);
  std::shared_ptr<block::ConfigInfo> view_config(MasterView& view);
  void execute(const ParsedBlock& parsed, const Cell& old_state, const Cell& new_state, bool full,
               const std::shared_ptr<block::ConfigInfo>& config, BlockRecord& record);
  void mismatch(BlockRecord& record, const std::string& kind, const std::string& detail, const ParsedBlock* parsed,
                const std::string& old_state_hash, const Cell& old_state, const TxContext* tx,
                const std::string& got_tx, const std::string& got_account);
  void refuse(BlockRecord& record, const std::string& reason);
  void break_chain(ChainState& chain);
  void check_shard_top(const ParsedBlock& parsed, const Cell& new_state, BlockRecord& record);
  std::string b64(const Cell& cell);
  std::string context_json(const TxContext& tx, bool externalize);
  void export_tx(const TxContext& tx);
  void finish(double seconds);
  bool stop() const {
    return stats_.gave_up;
  }
};

void Replay::gap(bool master, std::uint32_t from, std::uint32_t to, const std::string& reason) {
  auto& cs = master ? stats_.mc : stats_.shard;
  std::uint64_t count = static_cast<std::uint64_t>(to) - from + 1;
  cs.absent += count;
  std::string where = master ? "-1" : "0";
  stats_.gaps.push_back(where + ":" + std::to_string(from) + "-" + std::to_string(to) + " (" + std::to_string(count) +
                        " blocks, " + reason + ")");
  blocks_out_ << "{\"source\":" << quote(opt_.source) << ",\"workchain\":" << where
              << ",\"shard\":\"8000000000000000\",\"status\":\"absent\",\"from\":" << from << ",\"to\":" << to
              << ",\"blocks\":" << count << ",\"reason\":" << quote(reason) << "}\n";
}

void Replay::write_block(const ParsedBlock* parsed, const Entry& entry, bool master, std::uint32_t seqno,
                         const BlockRecord& r) {
  blocks_out_ << "{\"source\":" << quote(opt_.source) << ",\"workchain\":" << (master ? -1 : 0)
              << ",\"shard\":\"8000000000000000\",\"seqno\":" << seqno << ",\"root_hash\":\"" << entry.root
              << "\",\"file_hash\":\"" << entry.file_hash << "\",\"status\":\"" << r.status << "\",\"mode\":\""
              << r.mode << "\",\"linked\":" << (r.linked ? "true" : "false");
  if (!r.old_state.empty())
    blocks_out_ << ",\"old_state_hash\":\"" << r.old_state << "\"";
  if (!r.new_state.empty())
    blocks_out_ << ",\"new_state_hash\":\"" << r.new_state << "\"";
  blocks_out_ << ",\"transactions\":" << r.transactions << ",\"executed\":" << r.executed
              << ",\"matched\":" << r.matched;
  auto list = [&](const char* name, const std::vector<std::string>& items) {
    if (items.empty())
      return;
    blocks_out_ << ",\"" << name << "\":[";
    for (std::size_t i = 0; i < items.size(); ++i)
      blocks_out_ << (i ? "," : "") << quote(items[i]);
    blocks_out_ << "]";
  };
  list("mismatches", r.mismatches);
  list("refusals", r.refusals);
  blocks_out_ << "}\n";
}

void Replay::refuse(BlockRecord& record, const std::string& reason) {
  record.refusals.push_back(reason);
  stats_.refusal_reasons[reason_class(reason)]++;
  if (record.status == "ok")
    record.status = "refused";
}

void Replay::break_chain(ChainState& chain) {
  // The next block cannot be checked against a complete predecessor: keep the last complete state's cells
  // as original cells for hydration.
  if (chain.full && chain.state.not_null())
    cells_.add(chain.state);
  chain.linked = false;
  chain.have_hash = false;
  chain.full = false;
  chain.state = Cell{};
}

std::string Replay::b64(const Cell& cell) {
  auto key = cell->get_hash().to_hex();
  auto it = b64_cache_.find(key);
  if (it != b64_cache_.end())
    return it->second;
  auto encoded = td::base64_encode(boc_bytes(cell));
  if (b64_cache_.size() > 4096)
    b64_cache_.clear();
  b64_cache_.emplace(key, encoded);
  return encoded;
}

std::string Replay::context_json(const TxContext& tx, bool externalize) {
  auto field = [&](const char* name, const Cell& cell) -> std::string {
    auto text = b64(cell);
    if (externalize && text.size() > blob_threshold) {
      auto digest = lower(sha256_hex(boc_bytes(cell)));
      export_blobs_.emplace(digest, text);
      return std::string(",\"") + name + "\":{\"blob\":\"" + digest + "\"}";
    }
    return std::string(",\"") + name + "\":\"" + text + "\"";
  };
  std::string out = "{";
  out += field("config", tx.config).substr(1);
  out += field("shard_account", tx.shard_account);
  out += ",\"now\":" + std::to_string(tx.now) + ",\"lt\":" + std::to_string(tx.lt) + ",\"rand_seed\":\"" +
         lower(tx.seed) + "\"";
  if (tx.type == block::transaction::Transaction::tr_ord)
    out += field("message", tx.message);
  else
    out += std::string(",\"tick_tock\":\"") + (tx.type == block::transaction::Transaction::tr_tock ? "tock" : "tick") +
           "\"";
  if (tx.libraries.not_null())
    out += field("libraries", tx.libraries);
  if (tx.prev_blocks.not_null())
    out += field("prev_blocks", tx.prev_blocks);
  return out + "}";
}

void Replay::export_tx(const TxContext& tx) {
  export_out_ << "{\"fixture_id\":" << quote(tx.fixture_id) << ",\"note\":" << quote(tx.note)
              << ",\"context\":" << context_json(tx, true) << ",\"chain\":{\"transaction_hash\":\"" << tx.chain_tx
              << "\",\"account_hash\":\"" << tx.chain_account << "\"}}\n";
  check(export_out_.good(), "cannot write exported contexts");
  stats_.exported++;
}

void Replay::mismatch(BlockRecord& record, const std::string& kind, const std::string& detail,
                      const ParsedBlock* parsed, const std::string& old_state_hash, const Cell& old_state,
                      const TxContext* tx, const std::string& got_tx, const std::string& got_account) {
  stats_.mismatches++;
  stats_.mismatch_kinds[kind]++;
  record.status = "mismatch";
  record.mismatches.push_back(kind + ": " + detail);
  std::string id = parsed != nullptr ? std::to_string(parsed->shard.workchain) + ":" + std::to_string(parsed->seqno)
                                     : std::string("?");
  stats_.mismatch_details.push_back(id + " " + kind + ": " + detail);
  // Minimized reproduction: the predecessor state hash, the block and the first diverging transaction.
  char name[32];
  std::snprintf(name, sizeof(name), "mismatch-%03llu", static_cast<unsigned long long>(stats_.mismatches));
  std::string dir = opt_.out_dir + "/" + name;
  if (td::mkdir(dir).is_ok()) {
    std::ofstream meta(dir + "/record.json");
    meta << "{\"source\":" << quote(opt_.source) << ",\"block\":" << quote(id) << ",\"kind\":" << quote(kind)
         << ",\"detail\":" << quote(detail) << ",\"predecessor_state_hash\":" << quote(old_state_hash);
    if (parsed != nullptr)
      meta << ",\"root_hash\":\"" << hash(parsed->root) << "\",\"file_hash\":\"" << sha256_hex(parsed->bytes) << "\"";
    if (tx != nullptr)
      meta << ",\"transaction\":{\"chain_transaction_hash\":\"" << tx->chain_tx << "\",\"chain_account_hash\":\""
           << tx->chain_account << "\",\"replay_transaction_hash\":" << quote(got_tx)
           << ",\"replay_account_hash\":" << quote(got_account) << ",\"lt\":" << tx->lt << "}";
    meta << "}\n";
    if (parsed != nullptr) {
      std::ofstream block(dir + "/block.boc", std::ios::binary);
      block.write(parsed->bytes.data(), static_cast<std::streamsize>(parsed->bytes.size()));
    }
    if (old_state.not_null()) {
      auto bytes = vm::std_boc_serialize(old_state, 31);
      if (bytes.is_ok() && bytes.ok().size() <= max_repro_state_bytes) {
        std::ofstream state(dir + "/predecessor-state.boc", std::ios::binary);
        state.write(bytes.ok().as_slice().data(), static_cast<std::streamsize>(bytes.ok().size()));
      }
    }
    if (tx != nullptr) {
      std::ofstream ctx(dir + "/txn-context.jsonl");
      ctx << "{\"fixture_id\":" << quote(tx->fixture_id) << ",\"note\":" << quote(tx->note)
          << ",\"context\":" << context_json(*tx, false) << ",\"chain\":{\"transaction_hash\":\"" << tx->chain_tx
          << "\",\"account_hash\":\"" << tx->chain_account << "\"}}\n";
    }
  }
  if (stats_.mismatches >= opt_.max_mismatches)
    stats_.gave_up = true;
}

bool Replay::load(const Entry& entry, std::uint32_t seqno, bool master, ParsedBlock& out, std::string& error) {
  try {
    out.seqno = seqno;
    out.bytes = reader_.read(entry);
    auto file_hash = sha256_hex(out.bytes);
    if (file_hash != entry.file_hash) {
      error = "file hash " + file_hash + " differs from the archived id " + entry.file_hash;
      return false;
    }
    out.root = require(vm::std_boc_deserialize(out.bytes));
    if (hash(out.root) != entry.root) {
      error = "root hash " + hash(out.root) + " differs from the archived id " + entry.root;
      return false;
    }
    if (!(tlb::unpack_cell(out.root, out.block) && tlb::unpack_cell(out.block.info, out.info) &&
          tlb::unpack_cell(out.block.extra, out.extra) &&
          block::tlb::t_ShardIdent.unpack(out.info.shard.write(), out.shard))) {
      error = "block does not parse";
      return false;
    }
    if (out.info.seq_no != seqno || out.shard.workchain != (master ? -1 : 0) ||
        out.shard.shard != 0x8000000000000000ull || out.info.not_master == master) {
      error = "block header id differs from the archived id";
      return false;
    }
    return true;
  } catch (const std::exception& e) {
    error = std::string("unreadable block: ") + e.what();
    return false;
  }
}

std::shared_ptr<block::ConfigInfo> Replay::view_config(MasterView& view) {
  if (!view.built) {
    view.built = true;
    try {
      auto config = block::ConfigInfo::extract_config(
          view.state, view.id,
          block::Config::needWorkchainInfo | block::Config::needSpecialSmc | block::Config::needCapabilities |
              block::ConfigInfo::needLibraries | block::ConfigInfo::needPrevBlocks);
      if (config.is_error())
        view.config_error = "masterchain configuration: " + config.error().to_string();
      else
        view.config = std::shared_ptr<block::ConfigInfo>(config.move_as_ok());
    } catch (const vm::VmVirtError&) {
      view.config_error = "missing data: masterchain configuration reads a pruned cell";
    } catch (const vm::VmError& e) {
      view.config_error = std::string("masterchain configuration: ") + e.get_msg();
    } catch (const std::exception& e) {
      view.config_error = std::string("masterchain configuration: ") + e.what();
    }
  }
  return view.config;
}

MasterView* Replay::master_view(std::uint32_t seqno, const td::Bits256& root, const td::Bits256& file) {
  auto it = masters_.find(seqno);
  if (it == masters_.end() || it->second.id.root_hash != root || it->second.id.file_hash != file)
    return nullptr;
  return &it->second;
}

void Replay::check_shard_top(const ParsedBlock& parsed, const Cell& new_state, BlockRecord& record) {
  // The masterchain block registers the newest shard block; it must be the archived one at that seqno.
  try {
    block::gen::ShardStateUnsplit::Record state;
    block::gen::McStateExtra::Record extra;
    check(tlb::unpack_cell(new_state, state) && state.custom->prefetch_ref().not_null() &&
              tlb::unpack_cell(state.custom->prefetch_ref(), extra),
          "cannot read the masterchain state extra");
    block::ShardConfig config;
    check(config.unpack(extra.shard_hashes), "cannot read shard hashes");
    auto ids = config.get_shard_hash_ids(true);
    if (ids.size() != 1 || ids[0].workchain != 0 || ids[0].shard != 0x8000000000000000ull) {
      refuse(record, "unsupported shard layout: " + std::to_string(ids.size()) + " shards");
      return;
    }
    auto top = config.get_shard_hash(tos::ShardIdFull(0, 0x8000000000000000ull));
    check(top.not_null(), "no shard description");
    auto id = top->top_block_id();
    stats_.shard_top_checks++;
    auto it = index_.shard.blocks.find(id.seqno());
    if (it == index_.shard.blocks.end())
      return;  // counted as an absent shard block
    if (it->second.root != id.root_hash.to_hex() || it->second.file_hash != id.file_hash.to_hex())
      mismatch(record, "shard_top",
               "registered shard block " + std::to_string(id.seqno()) + " " + id.root_hash.to_hex() +
                   " differs from the archived " + it->second.root,
               &parsed, "", Cell{}, nullptr, "", "");
  } catch (const vm::VmVirtError&) {
    refuse(record, "missing data: shard hashes read a pruned cell");
  } catch (const std::exception& e) {
    refuse(record, std::string("shard top: ") + e.what());
  }
}

void Replay::execute(const ParsedBlock& parsed, const Cell& old_state, const Cell& new_state, bool full,
                     const std::shared_ptr<block::ConfigInfo>& config, BlockRecord& record) {
  const auto& info = parsed.info;
  const auto& extra = parsed.extra;
  vm::AugmentedDictionary account_blocks(vm::load_cell_slice_ref(extra.account_blocks), 256,
                                         block::tlb::aug_ShardAccountBlocks);
  // Count every on-chain transaction first, so refusals and skips are accounted per transaction.
  std::uint64_t total = 0;
  check(account_blocks.check_for_each_extra([&](auto value, auto, td::ConstBitPtr, int) {
    block::gen::AccountBlock::Record ab;
    check(block::gen::t_AccountBlock.unpack(value.write(), ab), "invalid account block");
    vm::AugmentedDictionary txs(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
    check(txs.check_for_each_extra([&](auto, auto, auto, int) {
      ++total;
      return true;
    }),
          "invalid transactions dictionary");
    return true;
  }),
        "invalid account blocks dictionary");
  record.transactions = total;
  stats_.tx_onchain += total;
  if (total == 0)
    return;
  if (config == nullptr) {
    stats_.tx_refused += total;
    return;
  }
  std::shared_ptr<block::ConfigInfo> cfg = config;
  td::Ref<vm::Tuple> previous_blocks;
  try {
    previous_blocks = require(cfg->get_prev_blocks_info());
  } catch (const vm::VmVirtError&) {
    refuse(record, "missing data: previous-block context reads a pruned cell");
    stats_.tx_refused += total;
    return;
  } catch (const std::exception& e) {
    refuse(record, std::string("previous-block context: ") + e.what());
    stats_.tx_refused += total;
    return;
  }
  block::gen::ShardStateUnsplit::Record state, after;
  check(tlb::unpack_cell(old_state, state), "cannot unpack the previous state");
  std::unique_ptr<vm::AugmentedDictionary> after_accounts;
  if (full) {
    check(tlb::unpack_cell(new_state, after), "cannot unpack the new state");
    after_accounts = std::make_unique<vm::AugmentedDictionary>(vm::load_cell_slice_ref(after.accounts), 256,
                                                               block::tlb::aug_ShardAccounts);
  }
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  const auto workchain = parsed.shard.workchain;
  std::string old_hash = hash(old_state);

  account_blocks.check_for_each_extra([&](auto value, auto, td::ConstBitPtr key, int) {
    if (stop())
      return false;
    block::gen::AccountBlock::Record ab;
    check(block::gen::t_AccountBlock.unpack(value.write(), ab), "invalid account block");
    vm::AugmentedDictionary txs(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
    std::vector<Cell> originals;
    txs.check_for_each_extra([&](auto tv, auto, auto, int) {
      originals.push_back(tv->prefetch_ref());
      return true;
    });
    std::size_t done = 0;
    auto account_name = ab.account_addr.to_hex();
    try {
      block::Account account(workchain, key);
      auto previous = accounts.lookup(key, 256);
      if (previous.is_null())
        check(account.init_new(info.gen_utime), "cannot initialize a new account");
      else
        check(account.unpack(previous, info.gen_utime, workchain == -1 && cfg->is_special_smartcontract(key)),
              "cannot load the account");
      account.block_lt = info.start_lt;
      emulator::TransactionEmulator emulator(cfg);
      emulator.set_libs(vm::Dictionary(cfg->get_libraries_root(), 256));
      emulator.set_prev_blocks_info(previous_blocks);
      auto seed = extra.rand_seed;
      emulator.set_rand_seed(seed);
      for (const auto& original : originals) {
        block::gen::Transaction::Record tx;
        block::gen::HASH_UPDATE::Record expected;
        check(tlb::unpack_cell(original, tx) &&
                  tlb::type_unpack_cell(tx.state_update, block::gen::t_HASH_UPDATE_Account, expected),
              "invalid original transaction");
        check(tx.account_addr == ab.account_addr && tx.now == info.gen_utime,
              "transaction identity/time differs from its block");
        auto align = block::ConfigInfo::get_lt_align();
        if (tx.lt - tx.lt % align != info.start_lt)
          throw Refusal("transaction logical time is not the block's aligned start");
        int type;
        auto tag = block::gen::t_TransactionDescr.get_tag(vm::load_cell_slice(tx.description));
        if (tag == block::gen::TransactionDescr::trans_ord) {
          type = block::transaction::Transaction::tr_ord;
          stats_.tx_ordinary++;
        } else if (tag == block::gen::TransactionDescr::trans_tick_tock) {
          block::gen::TransactionDescr::Record_trans_tick_tock d;
          check(tlb::unpack_cell(tx.description, d), "invalid tick/tock description");
          type = d.is_tock ? block::transaction::Transaction::tr_tock : block::transaction::Transaction::tr_tick;
          (d.is_tock ? stats_.tx_tock : stats_.tx_tick)++;
        } else {
          throw Refusal("unsupported transaction description " + std::to_string(tag));
        }
        TxContext ctx;
        ctx.type = type;
        ctx.now = tx.now;
        ctx.lt = tx.lt;
        ctx.seed = seed.to_hex();
        ctx.chain_tx = hash(original);
        ctx.chain_account = expected.new_hash.to_hex();
        ctx.fixture_id =
            std::to_string(workchain) + ":" + std::to_string(parsed.seqno) + ":" + ctx.chain_tx.substr(0, 16);
        ctx.note = "block " + hash(parsed.root) + " transaction " + ctx.chain_tx;
        bool want_context = !opt_.export_dir.empty() && step_ >= opt_.export_from && step_ <= opt_.export_to &&
                            stats_.exported < opt_.export_limit;
        auto build_context = [&] {
          vm::CellBuilder sa;
          check(sa.store_ref_bool(account.total_state) && sa.store_bits_bool(account.last_trans_hash_) &&
                    sa.store_long_bool(account.last_trans_lt_, 64),
                "cannot build the input shard account");
          ctx.shard_account = sa.finalize();
          ctx.message = tx.r1.in_msg->prefetch_ref();
          ctx.config = cfg->get_root_cell();
          ctx.libraries = cfg->get_libraries_root();
          vm::CellBuilder pb;
          check(vm::StackEntry(previous_blocks).serialize(pb), "cannot serialize previous blocks");
          ctx.prev_blocks = pb.finalize();
        };
        if (account.total_state.is_null() || expected.old_hash != account.total_state->get_hash().bits()) {
          mismatch(record, "input_account",
                   "account " + account_name + " pre-state differs from transaction " + ctx.chain_tx, &parsed, old_hash,
                   full ? old_state : Cell{}, nullptr, "", "");
          break;
        }
        build_context();
        account.now_ = tx.now;
        auto result =
            emulator.emulate_transaction(std::move(account), tx.r1.in_msg->prefetch_ref(), tx.now, tx.lt, type);
        stats_.tx_executed++;
        record.executed++;
        ++done;
        emulator::TransactionEmulator::EmulationSuccess* ok = nullptr;
        if (result.is_ok())
          ok = dynamic_cast<emulator::TransactionEmulator::EmulationSuccess*>(result.ok().get());
        std::string got_tx = ok != nullptr ? hash(ok->transaction) : "";
        std::string got_account = ok != nullptr ? hash(ok->account.total_state) : "";
        if (ok == nullptr || got_tx != ctx.chain_tx || got_account != ctx.chain_account) {
          std::string detail = ok == nullptr
                                   ? "transaction " + ctx.chain_tx + " not accepted by the emulator" +
                                         (result.is_error() ? ": " + result.error().to_string() : std::string())
                                   : "transaction " + ctx.chain_tx + " replayed as " + got_tx + ", account " +
                                         ctx.chain_account + " replayed as " + got_account;
          stats_.tx_mismatched++;
          mismatch(record, ok == nullptr ? "not_accepted" : "transaction", detail, &parsed, old_hash,
                   full ? old_state : Cell{}, &ctx, got_tx, got_account);
          break;
        }
        stats_.tx_matched++;
        record.matched++;
        if (want_context)
          export_tx(ctx);
        account = std::move(ok->account);
      }
      if (done == originals.size() && after_accounts) {
        // The last replayed account must be the one the new state stores.
        stats_.account_state_checks++;
        auto stored = after_accounts->lookup(key, 256);
        std::string stored_account = "absent", stored_last = "absent";
        if (stored.not_null() && stored->size_refs() >= 1) {
          stored_account = hash(stored->prefetch_ref());
          auto cs = *stored;
          td::Bits256 last_hash;
          unsigned long long last_lt = 0;
          if (cs.advance_refs(1) && cs.fetch_bits_to(last_hash.bits(), 256) && cs.fetch_ulong_bool(64, last_lt))
            stored_last = last_hash.to_hex() + "@" + std::to_string(last_lt);
        }
        std::string replay_last = account.last_trans_hash_.to_hex() + "@" + std::to_string(account.last_trans_lt_);
        std::string replay_account = hash(account.total_state);
        // An account that ends nonexistent is not stored in the account dictionary.
        bool absent_ok = stored.is_null() && account.status == block::Account::acc_nonexist;
        if (!absent_ok && (stored_account != replay_account || stored_last != replay_last))
          mismatch(record, "account_state",
                   "account " + account_name + " in the new state is " + stored_account + " last " + stored_last +
                       ", the replay ends at " + replay_account + " last " + replay_last,
                   &parsed, old_hash, old_state, nullptr, "", "");
      }
    } catch (const Refusal& e) {
      refuse(record, e.what());
      stats_.tx_refused += originals.size() - done;
      done = originals.size();
    } catch (const vm::VmVirtError&) {
      refuse(record, "missing data: account " + account_name + " reads a pruned cell");
      stats_.tx_refused += originals.size() - done;
      done = originals.size();
    } catch (const vm::VmError& e) {
      refuse(record, "account " + account_name + ": " + std::string(e.get_msg()));
      stats_.tx_refused += originals.size() - done;
      done = originals.size();
    } catch (const std::runtime_error& e) {
      refuse(record, std::string("account ") + account_name + ": " + e.what());
      stats_.tx_refused += originals.size() - done;
      done = originals.size();
    }
    if (done < originals.size())
      stats_.tx_skipped_after_mismatch += originals.size() - done;
    return true;
  });
}

void Replay::replay_block(const Entry& entry, std::uint32_t seqno, bool master) {
  auto& chain = master ? mc_ : shard_;
  auto& cs = master ? stats_.mc : stats_.shard;
  BlockRecord record;
  ParsedBlock parsed;
  std::string error;
  cs.replayed++;
  if (!load(entry, seqno, master, parsed, error)) {
    mismatch(record, "block_id", error, nullptr, chain.state_hash, Cell{}, nullptr, "", "");
    cs.mismatched++;
    write_block(nullptr, entry, master, seqno, record);
    break_chain(chain);
    return;
  }
  const auto& info = parsed.info;
  try {
    if (info.after_merge || info.after_split || info.before_split) {
      refuse(record, "split/merge blocks are not replayed");
      cs.refused++;
      write_block(&parsed, entry, master, seqno, record);
      break_chain(chain);
      return;
    }
    block::gen::ExtBlkRef::Record prev;
    check(tlb::unpack_cell(info.prev_ref, prev), "invalid parent reference");
    record.linked = chain.linked;
    if (chain.linked) {
      if (prev.seq_no != chain.last_id.seqno() || prev.root_hash != chain.last_id.root_hash ||
          prev.file_hash != chain.last_id.file_hash)
        mismatch(record, "parent",
                 "parent " + std::to_string(prev.seq_no) + ":" + prev.root_hash.to_hex() + " is not the replayed " +
                     chain.last_id.to_str(),
                 &parsed, chain.state_hash, Cell{}, nullptr, "", "");
    } else {
      cs.unlinked_starts++;
    }

    // State update.
    check(vm::MerkleUpdate::validate(parsed.block.state_update).is_ok(), "invalid state update");
    auto update = vm::load_cell_slice_special(parsed.block.state_update);
    Cell old_raw = update.fetch_ref(), new_raw = update.fetch_ref();
    record.old_state = hash(old_raw);
    record.new_state = hash(new_raw);
    if (chain.have_hash && chain.state_hash != record.old_state) {
      mismatch(record, "old_state",
               "update starts from " + record.old_state + ", replayed state is " + chain.state_hash, &parsed,
               chain.state_hash, chain.full ? chain.state : Cell{}, nullptr, "", "");
      break_chain(chain);
    }
    Cell exec_state, new_state;
    bool full = false;
    if (chain.full) {
      exec_state = chain.state;
      full = true;
    } else {
      cells_.clear_cache();
      cells_.add(old_raw);
      cells_.add(new_raw);
      auto hydrated = cells_.hydrate(old_raw);
      if (hydrated->get_level() == 0) {
        exec_state = hydrated;  // every cell is known: continue with a complete state
        full = true;
      } else {
        exec_state = hydrated->virtualize(0);
      }
    }
    record.mode = full ? "full" : "hydrated";
    (full ? cs.full_mode : cs.hydrated_mode)++;
    if (full) {
      auto applied = vm::MerkleUpdate::apply(exec_state, parsed.block.state_update);
      if (applied.is_error() || hash(applied.ok()) != record.new_state) {
        mismatch(record, "new_state",
                 applied.is_error() ? "update does not apply: " + applied.error().to_string()
                                    : "applied state " + hash(applied.ok()) + " differs from " + record.new_state,
                 &parsed, record.old_state, exec_state, nullptr, "", "");
        full = false;
        new_state = cells_.hydrate(new_raw)->virtualize(0);
      } else {
        new_state = applied.move_as_ok();
      }
    } else {
      auto applied = vm::MerkleUpdate::apply(old_raw->virtualize(0), parsed.block.state_update);
      if (applied.is_error() || hash(applied.ok()) != record.new_state)
        mismatch(record, "new_state", "update is not self-consistent", &parsed, record.old_state, Cell{}, nullptr, "",
                 "");
      auto hydrated_new = cells_.hydrate(new_raw);
      new_state = hydrated_new->get_level() == 0 ? hydrated_new : hydrated_new->virtualize(0);
    }

    // Masterchain context for execution.
    std::shared_ptr<block::ConfigInfo> config;
    if (master) {
      MasterView* view = master_view(prev.seq_no, prev.root_hash, prev.file_hash);
      MasterView local;
      if (view == nullptr) {
        local.id = tos::BlockIdExt(tos::masterchainId, tos::shardIdAll, prev.seq_no, prev.root_hash, prev.file_hash);
        local.state = exec_state;
        view = &local;
      }
      config = view_config(*view);
      if (config == nullptr)
        refuse(record, view->config_error);
    } else {
      block::gen::ExtBlkRef::Record ref;
      check(tlb::unpack_cell(info.master_ref, ref), "invalid masterchain reference");
      MasterView* view = master_view(ref.seq_no, ref.root_hash, ref.file_hash);
      if (view == nullptr) {
        refuse(record, "missing masterchain context " + std::to_string(ref.seq_no));
      } else {
        config = view_config(*view);
        if (config == nullptr)
          refuse(record, view->config_error);
      }
    }
    execute(parsed, exec_state, new_state, full, config, record);
    if (master)
      check_shard_top(parsed, new_state, record);

    if (master) {
      MasterView view;
      view.id =
          tos::BlockIdExt(tos::masterchainId, tos::shardIdAll, seqno, parsed.root->get_hash().bits(), td::Bits256());
      td::sha256(parsed.bytes, view.id.file_hash.as_slice());
      view.state = new_state;
      masters_[seqno] = std::move(view);
      while (masters_.size() > master_window)
        masters_.erase(masters_.begin());
    }
    chain.linked = true;
    chain.last_id = tos::BlockIdExt(parsed.shard.workchain, parsed.shard.shard, seqno, parsed.root->get_hash().bits(),
                                    td::Bits256());
    td::sha256(parsed.bytes, chain.last_id.file_hash.as_slice());
    chain.have_hash = true;
    chain.state_hash = record.new_state;
    chain.full = full && new_state->get_level() == 0;
    chain.state = chain.full ? new_state : Cell{};
  } catch (const std::exception& e) {
    refuse(record, std::string("block not replayable: ") + e.what());
    break_chain(chain);
  }
  if (record.status == "ok")
    cs.ok++;
  else if (record.status == "mismatch")
    cs.mismatched++;
  else
    cs.refused++;
  write_block(&parsed, entry, master, seqno, record);
}

void Replay::finish(double seconds) {
  auto chain_json = [](const ChainStats& c) {
    std::ostringstream o;
    o << "{\"indexed\":" << c.indexed << ",\"replayed\":" << c.replayed << ",\"ok\":" << c.ok
      << ",\"mismatched\":" << c.mismatched << ",\"refused\":" << c.refused << ",\"absent\":" << c.absent
      << ",\"unlinked_starts\":" << c.unlinked_starts << ",\"full_mode\":" << c.full_mode
      << ",\"hydrated_mode\":" << c.hydrated_mode << ",\"not_replayed\":{";
    bool first = true;
    for (const auto& [reason, count] : c.not_replayed) {
      o << (first ? "" : ",") << quote(reason) << ":" << count;
      first = false;
    }
    o << "}}";
    return o.str();
  };
  auto map_json = [](const std::map<std::string, std::uint64_t>& m) {
    std::ostringstream o;
    o << "{";
    bool first = true;
    for (const auto& [k, v] : m) {
      o << (first ? "" : ",") << quote(k) << ":" << v;
      first = false;
    }
    return o.str() + "}";
  };
  auto list_json = [](const std::vector<std::string>& items) {
    std::string out = "[";
    for (std::size_t i = 0; i < items.size(); ++i)
      out += (i ? "," : "") + quote(items[i]);
    return out + "]";
  };
  std::ostringstream s;
  s << "{\"source\":" << quote(opt_.source) << ",\"packages\":" << index_.packages
    << ",\"package_entries\":" << index_.entries << ",\"block_entries\":" << index_.block_entries
    << ",\"duplicate_entries\":" << index_.duplicate_entries << ",\"other_entries\":" << map_json(index_.other_entries)
    << ",\"other_shards\":" << map_json(index_.other_shards)
    << ",\"package_errors\":" << list_json(index_.package_errors) << ",\"conflicts\":" << list_json(index_.conflicts)
    << ",\"masterchain\":" << chain_json(stats_.mc) << ",\"shardchain\":" << chain_json(stats_.shard)
    << ",\"transactions\":{\"onchain\":" << stats_.tx_onchain << ",\"executed\":" << stats_.tx_executed
    << ",\"matched\":" << stats_.tx_matched << ",\"mismatched\":" << stats_.tx_mismatched
    << ",\"refused\":" << stats_.tx_refused << ",\"skipped_after_mismatch\":" << stats_.tx_skipped_after_mismatch
    << ",\"ordinary\":" << stats_.tx_ordinary << ",\"tick\":" << stats_.tx_tick << ",\"tock\":" << stats_.tx_tock
    << "},\"account_state_checks\":" << stats_.account_state_checks
    << ",\"shard_top_checks\":" << stats_.shard_top_checks << ",\"exported_contexts\":" << stats_.exported
    << ",\"mismatches\":" << stats_.mismatches << ",\"mismatch_kinds\":" << map_json(stats_.mismatch_kinds)
    << ",\"mismatch_details\":" << list_json(stats_.mismatch_details)
    << ",\"refusal_reasons\":" << map_json(stats_.refusal_reasons) << ",\"gaps\":" << list_json(stats_.gaps)
    << ",\"gave_up\":" << (stats_.gave_up ? "true" : "false") << ",\"max_mismatches\":" << opt_.max_mismatches
    << ",\"mc_limit\":" << opt_.mc_limit << ",\"original_cells\":" << cells_.size()
    << ",\"wall_seconds\":" << static_cast<std::uint64_t>(seconds) << "}";
  std::ofstream out(opt_.out_dir + "/summary.json");
  out << s.str() << "\n";
  check(out.good(), "cannot write the summary");
  std::cout << s.str() << std::endl;
}

Cell read_boc(const std::string& path, std::string* file_hash) {
  auto bytes = require(td::read_file_str(path));
  if (file_hash != nullptr)
    *file_hash = sha256_hex(bytes);
  return require(vm::std_boc_deserialize(bytes));
}

int Replay::run() {
  auto started = std::chrono::steady_clock::now();
  check(td::mkdir(opt_.out_dir).is_ok() || td::stat(opt_.out_dir).is_ok(), "cannot create " + opt_.out_dir);
  blocks_out_.open(opt_.out_dir + "/blocks.jsonl", std::ios::trunc);
  check(blocks_out_.good(), "cannot write blocks.jsonl");
  if (!opt_.export_dir.empty()) {
    check(td::mkdir(opt_.export_dir).is_ok() || td::stat(opt_.export_dir).is_ok(), "cannot create export dir");
    export_out_.open(opt_.export_dir + "/contexts.jsonl", std::ios::trunc);
    check(export_out_.good(), "cannot write exported contexts");
  }
  stats_.mc.indexed = index_.mc.blocks.size();
  stats_.shard.indexed = index_.shard.blocks.size();

  // Starting state.
  if (!opt_.zerostate.empty()) {
    std::string mc_file, base_file;
    Cell zero = read_boc(opt_.zerostate, &mc_file);
    MasterView view;
    view.id = tos::BlockIdExt(tos::masterchainId, tos::shardIdAll, 0, zero->get_hash().bits(), td::Bits256());
    check(view.id.file_hash.from_hex(mc_file) == 256, "file hash");
    view.state = zero;
    mc_.linked = true;
    mc_.last_id = view.id;
    mc_.have_hash = true;
    mc_.state_hash = hash(zero);
    mc_.state = zero;
    mc_.full = true;
    masters_[0] = view;
    if (!opt_.basestate.empty()) {
      Cell base = read_boc(opt_.basestate, &base_file);
      // The masterchain zero state names the basechain zero state by root and file hash.
      auto config = view_config(masters_[0]);
      check(config != nullptr, "zero state configuration: " + masters_[0].config_error);
      auto wc = config->get_workchain_info(0);
      check(wc.not_null() && wc->zerostate_root_hash == base->get_hash().bits() &&
                wc->zerostate_file_hash.to_hex() == base_file,
            "basechain zero state differs from the one the masterchain zero state names");
      shard_.linked = true;
      shard_.last_id = tos::BlockIdExt(0, 0x8000000000000000ull, 0, base->get_hash().bits(), wc->zerostate_file_hash);
      shard_.have_hash = true;
      shard_.state_hash = hash(base);
      shard_.state = base;
      shard_.full = true;
    }
  }
  for (const auto& path : opt_.cell_files) {
    auto roots = require(vm::std_boc_deserialize_multi(require(td::read_file_str(path))));
    for (const auto& root : roots)
      cells_.add(root);
  }
  for (const auto& path : opt_.cell_packs) {
    // Every entry (blocks, proofs) of these packages is a source of original cells only.
    std::ifstream in(path, std::ios::binary);
    check(in.good(), "cannot open " + path);
    std::vector<std::pair<std::uint64_t, std::uint64_t>> entries;
    auto error = scan_package(
        in, [&](const std::string&, std::uint64_t offset, std::uint64_t size) { entries.emplace_back(offset, size); });
    check(error.empty(), path + ": " + error);
    for (const auto& [offset, size] : entries) {
      std::string bytes(size, '\0');
      in.clear();
      in.seekg(static_cast<std::streamoff>(offset));
      in.read(bytes.data(), static_cast<std::streamsize>(size));
      check(in.good(), "cannot read " + path);
      auto root = vm::std_boc_deserialize(bytes);
      if (root.is_ok())
        cells_.add(root.move_as_ok());
    }
  }

  auto& mc_blocks = index_.mc.blocks;
  auto& shard_blocks = index_.shard.blocks;
  std::uint32_t first = mc_blocks.empty() ? 1 : mc_blocks.begin()->first;
  if (!opt_.zerostate.empty())
    first = 1;
  std::uint32_t last = mc_blocks.empty() ? 0 : mc_blocks.rbegin()->first;
  if (opt_.mc_limit != 0)
    last = std::min(last, opt_.mc_limit);
  if (!opt_.zerostate.empty() && !mc_blocks.empty() && mc_blocks.begin()->first == 0)
    stats_.mc.not_replayed["zero state entry"]++;

  auto shard_it = shard_blocks.begin();
  std::uint32_t shard_last = 0;
  bool shard_started = !opt_.basestate.empty();
  // Replays every shard block whose masterchain reference is at or below seqno.
  auto drain_shards = [&](std::uint32_t upto) {
    while (shard_it != shard_blocks.end() && !stop()) {
      ParsedBlock peek;
      std::string error;
      std::uint32_t seqno = shard_it->first;
      std::uint32_t master_seqno = 0;
      bool readable = load(shard_it->second, seqno, false, peek, error);
      if (readable) {
        block::gen::ExtBlkRef::Record ref;
        if (tlb::unpack_cell(peek.info.master_ref, ref))
          master_seqno = ref.seq_no;
      }
      if (readable && master_seqno > upto)
        return;
      if (shard_started && seqno > shard_last + 1) {
        gap(false, shard_last + 1, seqno - 1, "absent from every package");
        break_chain(shard_);
      }
      shard_started = true;
      replay_block(shard_it->second, seqno, false);
      shard_last = seqno;
      ++shard_it;
    }
  };
  if (!opt_.zerostate.empty())
    drain_shards(0);
  std::uint32_t mc_last = first - 1;
  bool mc_started = !opt_.zerostate.empty();
  for (auto it = mc_blocks.lower_bound(first); it != mc_blocks.end() && it->first <= last && !stop(); ++it) {
    auto seqno = it->first;
    if (mc_started && seqno > mc_last + 1) {
      gap(true, mc_last + 1, seqno - 1, "absent from every package");
      break_chain(mc_);
    }
    mc_started = true;
    step_ = seqno;
    replay_block(it->second, seqno, true);
    mc_last = seqno;
    drain_shards(seqno);
  }
  // Account for every indexed block that was not replayed.
  std::string reason = stop() ? "not replayed: gave up after " + std::to_string(opt_.max_mismatches) + " mismatches"
                              : "not replayed: outside the replayed masterchain range";
  for (const auto& [seqno, entry] : mc_blocks)
    if (seqno > mc_last || (seqno < first && seqno != 0))
      stats_.mc.not_replayed[seqno < first ? "before the starting block" : reason]++;
  for (auto it = shard_it; it != shard_blocks.end(); ++it)
    stats_.shard.not_replayed[stop() ? reason : "not replayed: masterchain context beyond the replayed range"]++;

  if (!opt_.export_dir.empty()) {
    export_out_.close();
    std::ofstream blobs(opt_.export_dir + "/contexts.blobs.json", std::ios::trunc);
    blobs << "{";
    bool first_blob = true;
    for (const auto& [digest, text] : export_blobs_) {
      blobs << (first_blob ? "\n" : ",\n") << "\"" << digest << "\":\"" << text << "\"";
      first_blob = false;
    }
    blobs << "\n}\n";
    check(blobs.good(), "cannot write exported blobs");
  }
  blocks_out_.flush();
  check(blocks_out_.good(), "cannot write blocks.jsonl");
  auto seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  finish(seconds);
  bool clean = stats_.mismatches == 0;
  return clean ? 0 : 3;
}

void index_block_file(Index& index, const std::string& path) {
  auto bytes = require(td::read_file_str(path));
  auto root = require(vm::std_boc_deserialize(bytes));
  block::gen::Block::Record block;
  block::gen::BlockInfo::Record info;
  tos::ShardIdFull shard;
  check(tlb::unpack_cell(root, block) && tlb::unpack_cell(block.info, info) &&
            block::tlb::t_ShardIdent.unpack(info.shard.write(), shard),
        "not a block: " + path);
  index.files.push_back(path);
  add_entry(index, shard.workchain, shard.shard, info.seq_no,
            Entry{index.files.size() - 1, 0, bytes.size(), hash(root), sha256_hex(bytes)}, path);
  index.block_entries++;
}

const char* usage =
    "usage: conformance-archive-replay --out DIR [--source NAME] [--packs LIST] [--blocks LIST] [--cells LIST]\n"
    "    [--cell-packs LIST] [--zerostate MC.boc [--basestate BASE.boc]] [--max-mismatches N] [--mc-limit SEQNO]\n"
    "    [--export DIR --export-from SEQNO --export-to SEQNO [--export-limit N]]\n"
    "LIST files name one path per line. Exit 0: no mismatch; 3: mismatches; 1: the replay could not run.\n";

}  // namespace

int main(int argc, char** argv) {
  try {
    Options opt;
    std::vector<std::string> args(argv + 1, argv + argc);
    auto number = [](const std::string& text) -> std::uint64_t {
      check(!text.empty() && text.find_first_not_of("0123456789") == std::string::npos && text.size() < 12,
            "not a number: " + text);
      return std::stoull(text);
    };
    for (std::size_t i = 0; i < args.size(); ++i) {
      const auto& a = args[i];
      check(i + 1 < args.size(), std::string(usage));
      const auto& v = args[++i];
      if (a == "--out")
        opt.out_dir = v;
      else if (a == "--source")
        opt.source = v;
      else if (a == "--packs")
        opt.packs = read_list(v);
      else if (a == "--blocks")
        opt.block_files = read_list(v);
      else if (a == "--cells")
        opt.cell_files = read_list(v);
      else if (a == "--cell-packs")
        opt.cell_packs = read_list(v);
      else if (a == "--zerostate")
        opt.zerostate = v;
      else if (a == "--basestate")
        opt.basestate = v;
      else if (a == "--max-mismatches")
        opt.max_mismatches = static_cast<std::uint32_t>(std::max<std::uint64_t>(1, number(v)));
      else if (a == "--mc-limit")
        opt.mc_limit = static_cast<std::uint32_t>(number(v));
      else if (a == "--export")
        opt.export_dir = v;
      else if (a == "--export-from")
        opt.export_from = static_cast<std::uint32_t>(number(v));
      else if (a == "--export-to")
        opt.export_to = static_cast<std::uint32_t>(number(v));
      else if (a == "--export-limit")
        opt.export_limit = number(v);
      else
        throw std::runtime_error(std::string("unknown option ") + a + "\n" + usage);
    }
    check(!opt.out_dir.empty() && (!opt.packs.empty() || !opt.block_files.empty()), usage);
    check(opt.basestate.empty() || !opt.zerostate.empty(), "--basestate needs --zerostate");
    SET_VERBOSITY_LEVEL(0);
    check(vm::init_vm(false).is_ok(), "VM initialization failed");
    Index index;
    for (const auto& path : opt.packs)
      index_package(index, path);
    for (const auto& path : opt.block_files)
      index_block_file(index, path);
    std::cerr << "indexed " << index.packages << " packages, " << index.mc.blocks.size() << " masterchain and "
              << index.shard.blocks.size() << " shard blocks" << std::endl;
    Replay replay(std::move(opt), index);
    return replay.run();
  } catch (const vm::VmError& error) {
    std::cerr << error.get_msg() << '\n';
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
  }
  return 1;
}
