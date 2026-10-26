// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Offline replay uses the production codec, authenticated state update and transaction emulator.
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "emulator/transaction-emulator.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/cells/MerkleUpdate.h"
#include "vm/vm.h"

namespace {
using Cell = td::Ref<vm::Cell>;

template <class T>
T require(td::Result<T> result) {
  if (result.is_error())
    throw std::runtime_error(result.error().to_string());
  return result.move_as_ok();
}
void check(bool value, const char* message) {
  if (!value)
    throw std::runtime_error(message);
}
std::string hash(Cell cell) {
  return cell->get_hash(0).to_hex();
}
// Proof-backed state is virtualized and cannot be serialized as it is; copy it
// into ordinary cells, keeping pruned branches as pruned-branch cells.
Cell materialize(Cell cell, std::map<std::string, Cell>& copies) {
  auto key = cell->get_hash(0).to_hex();
  auto known = copies.find(key);
  if (known != copies.end())
    return known->second;
  auto data = require(cell->load_cell()).data_cell;
  auto cs = vm::load_cell_slice_special(Cell(data));
  vm::CellBuilder builder;
  builder.store_bits(cs.fetch_bits(cs.size()));
  for (unsigned i = 0; i < data->size_refs(); ++i)
    builder.store_ref(materialize(data->get_ref(i), copies));
  auto copy = builder.finalize(cs.is_special());
  copies.emplace(key, copy);
  return copy;
}

std::string boc_hex(Cell cell) {
  if (cell.is_null())
    return "-";
  std::map<std::string, Cell> copies;
  return td::hex_encode(require(vm::std_boc_serialize(materialize(std::move(cell), copies), 0)).as_slice());
}

#ifdef TOS_VM_STEP_TRACE
// Writes the steps and cell loads of one transaction, named by its logical time
// in TOS_TRACE_LT, to the file named by TOS_TRACE_FILE.
class FileTrace final : public vm::StepTraceSink {
  std::ofstream out_;

 public:
  explicit FileTrace(const char* path) : out_(path) {
    check(out_.good(), "cannot write the trace file");
  }
  void on_step(const vm::VmState& vm) override {
    auto code = vm.get_code();
    out_ << "S\t" << vm.get_steps_count() << '\t' << vm.get_gas_limits().gas_remaining << '\t' << vm.trace_stack_depth()
         << '\t' << vm.trace_is_child() << '\t'
         << (code.is_null() ? std::string("-") : code->get_base_cell()->get_hash().to_hex()) << '\t'
         << (code.is_null() ? 0 : code->cur_pos()) << '\n';
  }
  void on_cell_load(const vm::VmState& vm, const vm::CellHash& hash, bool first) override {
    out_ << "L\t" << vm.get_steps_count() << '\t' << hash.to_hex() << '\t' << first << '\n';
  }
};

std::unique_ptr<FileTrace> trace_for(tos::LogicalTime lt) {
  auto wanted = std::getenv("TOS_TRACE_LT");
  auto path = std::getenv("TOS_TRACE_FILE");
  if (wanted == nullptr || path == nullptr || std::to_string(lt) != wanted)
    return nullptr;
  return std::make_unique<FileTrace>(path);
}
#endif

// One line per executed transaction with every input the Rust executor needs,
// written only when --dump names an output file.
std::ofstream dump;

Cell load(const std::string& path) {
  return require(vm::std_boc_deserialize(require(td::read_file(path)).as_slice()));
}

// Supplemental cells are original RPC proof/account bytes. A replacement is
// accepted only by its level-zero hash; absent preimages remain pruned.
class Cells {
  std::map<std::string, Cell> known_;
  std::set<std::string> seen_;
  mutable std::map<std::string, Cell> hydrated_;

 public:
  void add(Cell root) {
    if (!seen_.insert(root->get_hash().to_hex()).second)
      return;
    auto cs = vm::load_cell_slice_special(root);
    if (!cs.is_special()) {
      auto inserted = known_.emplace(hash(root), root);
      if (!inserted.second && inserted.first->second->get_hash() != root->get_hash()) {
        // Different authenticated paths can expose different parts of one
        // subtree. The production proof combiner preserves its original hash.
        inserted.first->second = require(vm::MerkleProof::combine_fast_raw(inserted.first->second, root));
      }
    }
    for (unsigned i = 0; i < cs.size_refs(); ++i)
      add(cs.prefetch_ref(i));
  }
  Cell hydrate(Cell root) const {
    if (root->get_level() == 0)
      return root;
    auto key = hash(root);
    auto cached = hydrated_.find(key);
    if (cached != hydrated_.end())
      return cached->second;
    auto cs = vm::load_cell_slice_special(root);
    if (cs.special_type() == vm::Cell::SpecialType::PrunnedBranch) {
      auto it = known_.find(key);
      return it == known_.end() ? root : hydrate(it->second);
    }
    if (!cs.is_special()) {
      auto it = known_.find(key);
      if (it != known_.end())
        cs = vm::load_cell_slice_special(it->second);
    }
    vm::CellBuilder builder;
    builder.store_bits(cs.fetch_bits(cs.size()));
    while (cs.size_refs())
      builder.store_ref(hydrate(cs.fetch_ref()));
    auto result = builder.finalize(cs.is_special());
    check(hash(result) == key, "supplement changed a state hash");
    hydrated_.emplace(key, result);
    return result;
  }
};

std::vector<std::string> paths(const char* path) {
  std::ifstream input(path);
  check(input.good(), "cannot read input list");
  std::vector<std::string> result;
  for (std::string line; std::getline(input, line);)
    if (!line.empty())
      result.push_back(line);
  return result;
}

void execution(Cell transaction, Cell resulting_account) {
  block::gen::Transaction::Record tx;
  check(tlb::unpack_cell(transaction, tx), "invalid transaction");
  auto kind = block::gen::t_TransactionDescr.get_tag(vm::load_cell_slice(tx.description));
  td::Ref<vm::CellSlice> compute, action;
  bool aborted = false;
  const char* description = nullptr;
  if (kind == block::gen::TransactionDescr::trans_ord) {
    block::gen::TransactionDescr::Record_trans_ord desc;
    check(tlb::unpack_cell(tx.description, desc), "invalid ordinary description");
    compute = desc.compute_ph;
    action = desc.action;
    aborted = desc.aborted;
    description = "ordinary";
  } else if (kind == block::gen::TransactionDescr::trans_tick_tock) {
    block::gen::TransactionDescr::Record_trans_tick_tock desc;
    check(tlb::unpack_cell(tx.description, desc), "invalid tick/tock description");
    compute = desc.compute_ph;
    action = desc.action;
    aborted = desc.aborted;
    description = desc.is_tock ? "tock" : "tick";
  } else
    throw std::runtime_error("unhandled transaction description");
  block::gen::HASH_UPDATE::Record update;
  check(tlb::type_unpack_cell(tx.state_update, block::gen::t_HASH_UPDATE_Account, update), "invalid account update");
  std::cout << "{\"kind\":\"transaction\",\"account\":\"" << tx.account_addr.to_hex() << "\",\"lt\":\"" << tx.lt
            << "\",\"result_hash\":\"" << hash(transaction) << "\",\"account_hash\":\"" << hash(resulting_account)
            << "\",\"description_hash\":\"" << hash(tx.description) << "\",\"description\":\"" << description
            << "\",\"description_tag\":" << kind << ",\"aborted\":" << (aborted ? "true" : "false");
  auto ctag = block::gen::t_TrComputePhase.get_tag(*compute);
  if (ctag == block::gen::TrComputePhase::tr_phase_compute_vm) {
    block::gen::TrComputePhase::Record_tr_phase_compute_vm phase;
    check(block::gen::t_TrComputePhase.unpack(compute.write(), phase), "invalid compute phase");
    auto gas = block::tlb::t_VarUInteger_7.as_integer(*phase.r1.gas_used);
    check(gas.not_null() && gas->is_valid(), "invalid gas used");
    std::cout << ",\"gas_used\":\"" << gas->to_dec_string() << "\",\"exit_code\":" << phase.r1.exit_code;
  } else
    std::cout << ",\"gas_used\":\"0\",\"exit_code\":null";
  auto acell = action->prefetch_ref();
  if (acell.not_null()) {
    block::gen::TrActionPhase::Record phase;
    check(tlb::unpack_cell(acell, phase), "invalid action phase");
    std::cout << ",\"action_result_code\":" << phase.result_code;
  } else
    std::cout << ",\"action_result_code\":null";
  std::cout << ",\"out_message_hashes\":[";
  vm::Dictionary messages(tx.r1.out_msgs, 15);
  bool first = true;
  check(messages.check_for_each([&](auto value, auto, int) {
    auto message = value->prefetch_ref();
    check(message.not_null(), "missing outgoing message");
    if (!first)
      std::cout << ',';
    first = false;
    std::cout << '\"' << hash(message) << '\"';
    return true;
  }),
        "invalid outgoing dictionary");
  std::cout << "]}" << std::endl;
}

struct MasterBlock {
  Cell root;
  td::Bits256 file_hash;
};
using MasterBlocks = std::map<std::string, MasterBlock>;

std::shared_ptr<block::ConfigInfo> context(const block::gen::BlockInfo::Record& info, Cell previous_state,
                                           const Cells& cells, const MasterBlocks& masters) {
  block::gen::ExtBlkRef::Record reference;
  Cell master_state;
  if (!info.not_master) {
    check(!info.after_merge && tlb::unpack_cell(info.prev_ref, reference), "invalid masterchain parent");
    master_state = previous_state;
  } else {
    check(tlb::unpack_cell(info.master_ref, reference), "invalid shard masterchain reference");
    auto it = masters.find(reference.root_hash.to_hex());
    check(it != masters.end(), "missing exact masterchain context for shard replay");
    check(it->second.file_hash == reference.file_hash, "masterchain context file hash differs");
    block::gen::Block::Record master;
    block::gen::BlockInfo::Record master_info;
    check(tlb::unpack_cell(it->second.root, master) && tlb::unpack_cell(master.info, master_info) &&
              !master_info.not_master && master_info.seq_no == reference.seq_no,
          "masterchain context identity differs");
    master_state = cells.hydrate(vm::load_cell_slice_special(master.state_update).prefetch_ref(1))->virtualize(0);
  }
  tos::BlockIdExt id(tos::masterchainId, tos::shardIdAll, reference.seq_no, reference.root_hash, reference.file_hash);
  auto config = require(block::ConfigInfo::extract_config(
      master_state, id,
      block::Config::needWorkchainInfo | block::Config::needSpecialSmc | block::Config::needCapabilities |
          block::ConfigInfo::needLibraries | block::ConfigInfo::needPrevBlocks));
  return std::shared_ptr<block::ConfigInfo>(std::move(config));
}

void replay(Cell root, const Cells& cells, const MasterBlocks& masters, bool empty_code_control) {
  block::gen::Block::Record block;
  block::gen::BlockInfo::Record info;
  block::gen::BlockExtra::Record extra;
  check(tlb::unpack_cell(root, block) && tlb::unpack_cell(block.info, info) && tlb::unpack_cell(block.extra, extra),
        "invalid replay block");
  tos::ShardIdFull shard;
  check(block::tlb::t_ShardIdent.unpack(info.shard.write(), shard), "invalid shard identifier");
  auto raw = vm::load_cell_slice_special(block.state_update).prefetch_ref();
  auto old = cells.hydrate(raw)->virtualize(0);
  std::string stage = "previous state";
  vm::MerkleProofBuilder used(old);
  used.set_cell_load_callback([&stage](const vm::LoadedCell& loaded) {
    if (loaded.data_cell->special_type() == vm::Cell::SpecialType::PrunnedBranch &&
        loaded.effective_level < loaded.data_cell->get_level()) {
      std::cerr << "pruned cell " << loaded.data_cell->get_hash(0).to_hex() << " while reading " << stage << '\n';
    }
  });
  old = used.root();
  block::gen::ShardStateUnsplit::Record state;
  check(tlb::unpack_cell(old, state), "cannot unpack previous state");
  check(!info.after_split && !info.after_merge, "split/merge replay needs both exact predecessor states");
  stage = "masterchain configuration";
  auto config = context(info, old, cells, masters);
  stage = "previous-block VM context";
  auto previous_blocks = require(config->get_prev_blocks_info());
  stage = "account dictionaries";
  vm::AugmentedDictionary account_blocks(vm::load_cell_slice_ref(extra.account_blocks), 256,
                                         block::tlb::aug_ShardAccountBlocks);
  if (account_blocks.is_empty())
    return;
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  check(account_blocks.check_for_each_extra([&](auto value, auto, td::ConstBitPtr key, int) {
    block::gen::AccountBlock::Record ab;
    check(block::gen::t_AccountBlock.unpack(value.write(), ab), "invalid account block");
    block::Account account(shard.workchain, key);
    stage = "account " + ab.account_addr.to_hex();
    auto previous = accounts.lookup(key, 256);
    if (previous.is_null())
      check(account.init_new(info.gen_utime), "cannot initialize new account");
    else
      check(account.unpack(previous, info.gen_utime, shard.workchain == -1 && config->is_special_smartcontract(key)),
            "cannot load account");
    account.block_lt = info.start_lt;
    emulator::TransactionEmulator emulator(config);
    emulator.set_libs(vm::Dictionary(config->get_libraries_root(), 256));
    emulator.set_prev_blocks_info(previous_blocks);
    auto seed = extra.rand_seed;
    emulator.set_rand_seed(seed);
    vm::AugmentedDictionary transactions(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
    check(transactions.check_for_each_extra([&](auto value, auto, auto, int) {
      auto original = value->prefetch_ref();
      block::gen::Transaction::Record original_record;
      block::gen::HASH_UPDATE::Record expected_account;
      check(
          tlb::unpack_cell(original, original_record) &&
              tlb::type_unpack_cell(original_record.state_update, block::gen::t_HASH_UPDATE_Account, expected_account),
          "invalid original transaction");
      check(original_record.account_addr == ab.account_addr && original_record.now == info.gen_utime,
            "transaction identity/time differs from its block");
      auto align = block::ConfigInfo::get_lt_align();
      check(original_record.lt - original_record.lt % align == info.start_lt,
            "transaction emulator cannot supply this block's exact logical time");
      check(account.total_state.not_null() && expected_account.old_hash == account.total_state->get_hash().bits(),
            "input account differs from the original transaction's pre-state hash");
      stage = "execution of account " + ab.account_addr.to_hex();
      int type;
      auto tag = block::gen::t_TransactionDescr.get_tag(vm::load_cell_slice(original_record.description));
      if (tag == block::gen::TransactionDescr::trans_ord) {
        type = block::transaction::Transaction::tr_ord;
      } else {
        block::gen::TransactionDescr::Record_trans_tick_tock description;
        check(tag == block::gen::TransactionDescr::trans_tick_tock &&
                  tlb::unpack_cell(original_record.description, description),
              "unsupported execution description");
        type =
            description.is_tock ? block::transaction::Transaction::tr_tock : block::transaction::Transaction::tr_tick;
      }
      // The explicit negative operation follows this same execution path.
      if (empty_code_control)
        account.code = vm::CellBuilder{}.finalize();
      account.now_ = original_record.now;
      if (dump.is_open()) {
        vm::CellBuilder shard_account;
        check(shard_account.store_ref_bool(account.total_state) &&
                  shard_account.store_bits_bool(account.last_trans_hash_) &&
                  shard_account.store_long_bool(account.last_trans_lt_, 64),
              "cannot build the input shard account");
        vm::CellBuilder previous_cb;
        check(vm::StackEntry(previous_blocks).serialize(previous_cb), "cannot serialize previous blocks");
        auto in_msg = original_record.r1.in_msg->prefetch_ref();
        dump << type << '\t' << original_record.now << '\t' << original_record.lt << '\t' << seed.to_hex() << '\t'
             << boc_hex(shard_account.finalize()) << '\t' << boc_hex(in_msg) << '\t' << boc_hex(config->get_root_cell())
             << '\t' << boc_hex(config->get_libraries_root()) << '\t' << boc_hex(previous_cb.finalize()) << '\t'
             << hash(original) << '\t' << expected_account.new_hash.to_hex() << '\t' << boc_hex(original) << '\n';
      }
#ifdef TOS_VM_STEP_TRACE
      auto trace = trace_for(original_record.lt);
      vm::step_trace_sink() = trace.get();
#endif
      auto result = require(emulator.emulate_transaction(std::move(account), original_record.r1.in_msg->prefetch_ref(),
                                                         original_record.now, original_record.lt, type));
#ifdef TOS_VM_STEP_TRACE
      vm::step_trace_sink() = nullptr;
#endif
      auto* emulated = dynamic_cast<emulator::TransactionEmulator::EmulationSuccess*>(result.get());
      check(emulated != nullptr, "an on-chain transaction was not accepted by the emulator");
      execution(emulated->transaction, emulated->account.total_state);
      // Emit the actual result before refusing it, so the comparator can name
      // the first changed consensus field even when replay stops here.
      check(hash(emulated->transaction) == hash(original), "transaction hash mismatch");
      check(expected_account.new_hash == emulated->account.total_state->get_hash().bits(), "account hash mismatch");
      account = std::move(emulated->account);
      return true;
    }),
          "invalid transactions dictionary");
    return true;
  }),
        "invalid account blocks dictionary");
}

void inspect(const std::string& path) {
  auto bytes = require(td::read_file(path));
  auto root = require(vm::std_boc_deserialize(bytes.as_slice()));
  int mode = -1;
  for (int candidate = 0; candidate < 32; ++candidate) {
    auto encoded = vm::std_boc_serialize(root, candidate);
    if (encoded.is_ok() && encoded.ok().as_slice() == bytes.as_slice()) {
      mode = candidate;
      break;
    }
  }
  check(mode >= 0, "block codec did not reproduce the original BOC bytes");
  block::gen::Block::Record block;
  block::gen::BlockInfo::Record info;
  block::gen::BlockExtra::Record extra;
  check(tlb::unpack_cell(root, block) && tlb::unpack_cell(block.info, info) && tlb::unpack_cell(block.extra, extra),
        "invalid block structure");
  Cell repacked;
  check(tlb::pack_cell(repacked, block) && hash(repacked) == hash(root), "block TL-B round trip differs");
  tos::ShardIdFull shard;
  check(block::tlb::t_ShardIdent.unpack(info.shard.write(), shard), "invalid shard identifier");
  auto valid = vm::MerkleUpdate::validate(block.state_update);
  check(valid.is_ok(), "invalid state update");
  auto update = vm::load_cell_slice_special(block.state_update);
  auto before = update.fetch_ref();
  auto after = update.fetch_ref();
  auto applied = require(vm::MerkleUpdate::apply(before->virtualize(0), block.state_update));
  check(hash(applied) == hash(after), "applied state differs from declared state");
  td::Bits256 file_hash;
  td::sha256(bytes.as_slice(), file_hash.as_slice());
  std::cout << "{\"kind\":\"block\",\"seqno\":" << info.seq_no << ",\"workchain\":" << shard.workchain
            << ",\"shard\":\"" << shard.shard << "\",\"root_hash\":\"" << hash(root) << "\",\"file_hash\":\""
            << file_hash.to_hex() << "\",\"old_state_hash\":\"" << hash(before) << "\",\"new_state_hash\":\""
            << hash(applied) << "\",\"boc_mode\":" << mode << "}" << std::endl;
}
}  // namespace

int main(int argc, char** argv) {
  try {
    check(
        argc == 2 || argc == 4 || (argc == 5 && std::string(argv[1]) == "--dump"),
        "usage: test-epoch-replay block.boc OR --run blocks.list cells.list OR --dump blocks.list cells.list out.tsv");
    SET_VERBOSITY_LEVEL(0);
    auto initialized = vm::init_vm(false);
    check(initialized.is_ok(), "VM initialization failed");
    if (argc == 2)
      inspect(argv[1]);
    else {
      bool empty_code_control = std::string(argv[1]) == "--run-empty-code-control";
      if (std::string(argv[1]) == "--dump") {
        dump.open(argv[4]);
        check(dump.good(), "cannot write the dump file");
      } else
        check(std::string(argv[1]) == "--run" || empty_code_control, "unknown operation");
      auto blocks = paths(argv[2]);
      auto supplements = paths(argv[3]);
      check(!blocks.empty(), "empty corpus");
      Cells cells;
      for (const auto& path : supplements) {
        auto roots = require(vm::std_boc_deserialize_multi(require(td::read_file(path)).as_slice()));
        for (const auto& root : roots)
          cells.add(root);
      }
      MasterBlocks masters;
      auto remember = [&](Cell root, td::Slice bytes) {
        cells.add(root);
        block::gen::Block::Record block;
        block::gen::BlockInfo::Record info;
        if (tlb::unpack_cell(root, block) && tlb::unpack_cell(block.info, info) && !info.not_master) {
          td::Bits256 file_hash;
          td::sha256(bytes, file_hash.as_slice());
          masters.emplace(hash(root), MasterBlock{root, file_hash});
        }
      };
      // Original context blocks may be supplemental inputs, without adding replay cases.
      for (const auto& path : supplements) {
        auto bytes = require(td::read_file(path));
        auto roots = require(vm::std_boc_deserialize_multi(bytes.as_slice()));
        if (roots.size() == 1)
          remember(roots[0], bytes.as_slice());
      }
      for (const auto& path : blocks) {
        auto bytes = require(td::read_file(path));
        remember(require(vm::std_boc_deserialize(bytes.as_slice())), bytes.as_slice());
      }

      for (const auto& path : blocks) {
        std::cerr << "replay " << path << std::endl;
        inspect(path);
        replay(load(path), cells, masters, empty_code_control);
      }
    }
    return 0;
  } catch (const vm::VmVirtError& error) {
    std::cerr << error.get_msg() << '\n';
  } catch (const vm::VmError& error) {
    std::cerr << error.get_msg() << '\n';
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
  }
  return 1;
}
