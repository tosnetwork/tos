// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// block harness: offline application and validation of one block against its previous state
// (schema/harness/block-v1.schema.json), the procedure of emulator/test/epoch-replay.cpp.
//
// The block's Merkle state update is validated and applied to the supplied previous state; every
// transaction of the block is re-executed in order through the transaction emulator's C interface
// (one emulator per account, as the replay uses one, and as the txn harness drives it), and the
// result must equal the transaction recorded in the block, the account hash its HASH_UPDATE declares
// and the account the new state holds. The configuration comes from the previous state for a
// masterchain block and from the referenced masterchain block's new state for a shard block.
// Split and merge blocks need two predecessor states and are refused, as the replay refuses them.
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "block/transaction.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cells/MerkleUpdate.h"
#include "vm/dict.h"

#include "common.h"
#include "emulator-extern.h"

namespace {

using Cell = td::Ref<vm::Cell>;

constexpr std::size_t kMaxTransactions = 4096;

// A refusal of the block with a stable reason class. The class is the effect; the detail is not part
// of it, so two implementations may word their diagnostics differently.
struct Rejection {
  const char *reason;
};

std::string rejected(const char *reason) {
  return std::string("{\"outcome\":\"rejected\",\"reason\":") + conformance::json_quote(td::Slice(reason)) + "}";
}

std::string hash0(const Cell &cell) {
  return cell->get_hash(0).to_hex();
}

struct Executed {
  std::string transaction_hash;
  std::string account_hash;
};

struct Original {
  Cell root;
  std::string bytes;
};

std::string accepted(const Cell &root, const Cell &new_state, const std::vector<Executed> &executed) {
  std::string transactions = "[";
  for (std::size_t i = 0; i < executed.size(); ++i) {
    transactions += (i ? ",{" : "{");
    transactions += "\"transaction_hash\":" + conformance::json_quote(executed[i].transaction_hash) +
                    ",\"account_hash\":" + conformance::json_quote(executed[i].account_hash) + "}";
  }
  transactions += "]";
  return "{\"outcome\":\"accepted\",\"block_root_hash\":" + conformance::json_quote(hash0(root)) +
         ",\"new_state_hash\":" + conformance::json_quote(hash0(new_state)) + ",\"transactions\":" + transactions + "}";
}

td::Result<Original> required_original(td::JsonObject &ctx, td::Slice field) {
  TRY_RESULT(b64, ctx.get_required_string_field(field));
  TRY_RESULT(bytes, td::base64_decode(b64));
  auto root = vm::std_boc_deserialize(td::Slice(bytes), false, true);
  if (root.is_error()) {
    return td::Status::Error(PSLICE() << field << ": " << root.error().message());
  }
  return Original{root.move_as_ok(), std::move(bytes)};
}

// Masterchain configuration for the block, as the replay extracts it.
td::Result<std::shared_ptr<block::ConfigInfo>> block_config(const block::gen::BlockInfo::Record &info,
                                                            const Cell &previous_state, const Original *master_block,
                                                            const Cell &master_state, Rejection &why) {
  block::gen::ExtBlkRef::Record reference;
  Cell state;
  if (!info.not_master) {
    if (!tlb::unpack_cell(info.prev_ref, reference)) {
      why = {"malformed_block"};
      return td::Status::Error("masterchain parent reference");
    }
    state = previous_state;
  } else {
    if (!tlb::unpack_cell(info.master_ref, reference)) {
      why = {"malformed_block"};
      return td::Status::Error("shard masterchain reference");
    }
    why = {"master_context_mismatch"};
    if (master_block == nullptr || master_state.is_null()) {
      return td::Status::Error("a shard block needs its masterchain block and state");
    }
    td::Bits256 file_hash;
    td::sha256(master_block->bytes, file_hash.as_slice());
    block::gen::Block::Record master;
    block::gen::BlockInfo::Record master_info;
    if (td::Bits256{master_block->root->get_hash().bits()} != reference.root_hash || file_hash != reference.file_hash ||
        !tlb::unpack_cell(master_block->root, master) || !tlb::unpack_cell(master.info, master_info) ||
        master_info.not_master || master_info.seq_no != reference.seq_no) {
      return td::Status::Error("masterchain block identity differs from the shard block's reference");
    }
    auto update = vm::load_cell_slice_special(master.state_update);
    if (update.special_type() != vm::Cell::SpecialType::MerkleUpdate || update.size_refs() != 2 ||
        update.prefetch_ref(1)->get_hash(0) != master_state->get_hash(0)) {
      return td::Status::Error("masterchain state differs from the masterchain block's new state");
    }
    state = master_state->virtualize(0);
  }
  tos::BlockIdExt id(tos::masterchainId, tos::shardIdAll, reference.seq_no, reference.root_hash, reference.file_hash);
  why = {"config_unavailable"};
  TRY_RESULT(config,
             block::ConfigInfo::extract_config(state, id,
                                               block::Config::needWorkchainInfo | block::Config::needSpecialSmc |
                                                   block::Config::needCapabilities | block::ConfigInfo::needLibraries |
                                                   block::ConfigInfo::needPrevBlocks));
  return std::shared_ptr<block::ConfigInfo>(std::move(config));
}

// Transaction type of an original transaction, as the collator created it.
bool transaction_type(const Cell &description, int &type) {
  auto tag = block::gen::t_TransactionDescr.get_tag(vm::load_cell_slice(description));
  if (tag == block::gen::TransactionDescr::trans_ord) {
    type = block::transaction::Transaction::tr_ord;
    return true;
  }
  block::gen::TransactionDescr::Record_trans_tick_tock tick_tock;
  if (tag != block::gen::TransactionDescr::trans_tick_tock || !tlb::unpack_cell(description, tick_tock)) {
    return false;
  }
  type = tick_tock.is_tock ? block::transaction::Transaction::tr_tock : block::transaction::Transaction::tr_tick;
  return true;
}

// The account the new state holds must be the re-executed one, as the collator updates its account
// dictionary: a deleted account leaves the dictionary, an unchanged account keeps its old entry, and
// a changed account's entry is the ShardAccount the execution produced.
bool new_state_holds(vm::AugmentedDictionary &new_accounts, td::ConstBitPtr key, const Cell &original,
                     const Cell &final_shard_account) {
  auto entry = new_accounts.lookup(key, 256);
  const auto final_account = vm::load_cell_slice(final_shard_account).prefetch_ref(0);
  auto account_cs = vm::load_cell_slice(final_account);
  if (account_cs.size() == 1 && account_cs.size_refs() == 0 && account_cs.prefetch_ulong(1) == 0) {
    return entry.is_null();  // account_none$0
  }
  if (entry.is_null() || entry->size_refs() < 1) {
    return false;
  }
  if (vm::load_cell_slice(original).prefetch_ref(0)->get_hash(0) == final_account->get_hash(0)) {
    return entry->prefetch_ref(0)->get_hash(0) == final_account->get_hash(0);
  }
  vm::CellBuilder cb;
  return cb.append_cellslice_bool(*entry) && cb.finalize()->get_hash(0) == final_shard_account->get_hash(0);
}

struct EmulatorDeleter {
  void operator()(void *emulator) const {
    transaction_emulator_destroy(emulator);
  }
};

// What the transaction emulator's C interface answered for one transaction.
struct Emulated {
  Cell transaction;
  Cell shard_account;
};

td::Result<Emulated> emulate(void *emulator, const std::string &shard_account, const Cell &in_msg, int type) {
  const char *raw = nullptr;
  if (type == block::transaction::Transaction::tr_ord) {
    if (in_msg.is_null()) {
      return td::Status::Error("ordinary transaction without an inbound message");
    }
    TRY_RESULT(message, conformance::boc_to_base64(in_msg));
    raw = transaction_emulator_emulate_transaction(emulator, shard_account.c_str(), message.c_str());
  } else {
    raw = transaction_emulator_emulate_tick_tock_transaction(emulator, shard_account.c_str(),
                                                             type == block::transaction::Transaction::tr_tock);
  }
  if (raw == nullptr) {
    return td::Status::Error("transaction emulator returned no response");
  }
  std::string response{raw};
  string_destroy(raw);
  TRY_RESULT(parsed, td::json_decode(td::MutableSlice(response)));
  if (parsed.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("transaction emulator response is not an object");
  }
  auto &obj = parsed.get_object();
  TRY_RESULT(success, obj.get_required_bool_field("success"));
  if (!success) {
    return td::Status::Error("the transaction was not accepted");
  }
  TRY_RESULT(transaction, conformance::required_boc(obj, "transaction"));
  TRY_RESULT(new_shard_account, conformance::required_boc(obj, "shard_account"));
  if (vm::load_cell_slice(new_shard_account).size_refs() < 1) {
    return td::Status::Error("ShardAccount without an account reference");
  }
  return Emulated{std::move(transaction), std::move(new_shard_account)};
}

// ShardAccount of an account the previous state does not hold: account_none, no last transaction.
Cell absent_shard_account() {
  vm::CellBuilder cb;
  cb.store_ref(vm::CellBuilder{}.store_long(0, 1).finalize()).store_zeroes(256).store_long(0, 64);
  return cb.finalize();
}

td::Result<std::string> apply_block(Original &block_input, const Cell &prev_input, const Original *master_block,
                                    const Cell &master_state, Rejection &why) {
  const Cell &root = block_input.root;
  why = {"malformed_block"};
  block::gen::Block::Record block;
  block::gen::BlockInfo::Record info;
  block::gen::BlockExtra::Record extra;
  if (!(tlb::unpack_cell(root, block) && tlb::unpack_cell(block.info, info) && tlb::unpack_cell(block.extra, extra))) {
    return td::Status::Error("block structure");
  }
  tos::ShardIdFull shard;
  if (!block::tlb::t_ShardIdent.unpack(info.shard.write(), shard)) {
    return td::Status::Error("shard identifier");
  }
  if (info.after_split || info.after_merge) {
    why = {"split_merge_unsupported"};
    return td::Status::Error("split and merge blocks need both predecessor states");
  }
  why = {"state_update_invalid"};
  TRY_STATUS(vm::MerkleUpdate::validate(block.state_update));
  auto update = vm::load_cell_slice_special(block.state_update);
  const auto declared_old = update.prefetch_ref(0);
  const auto declared_new = update.prefetch_ref(1);
  if (prev_input->get_hash(0) != declared_old->get_hash(0)) {
    why = {"prev_state_mismatch"};
    return td::Status::Error("previous state differs from the state update's old state");
  }
  auto previous = prev_input->virtualize(0);
  why = {"state_update_not_applicable"};
  TRY_RESULT(applied, vm::MerkleUpdate::apply(previous, block.state_update));
  if (applied->get_hash(0) != declared_new->get_hash(0)) {
    why = {"state_update_mismatch"};
    return td::Status::Error("applied state differs from the declared new state");
  }

  why = {"prev_state_malformed"};
  block::gen::ShardStateUnsplit::Record state;
  if (!tlb::unpack_cell(previous, state)) {
    return td::Status::Error("cannot unpack the previous state");
  }
  TRY_RESULT(config, block_config(info, previous, master_block, master_state, why));
  why = {"config_unavailable"};
  TRY_RESULT(previous_blocks, config->get_prev_blocks_info());
  // The emulator takes its context as BOCs, as the replay's export hands it to the txn harness.
  struct {
    std::string config, libraries, prev_blocks, seed;
  } contexts;
  {
    TRY_RESULT_ASSIGN(contexts.config, conformance::boc_to_base64(config->get_root_cell()));
    if (config->get_libraries_root().not_null()) {
      TRY_RESULT_ASSIGN(contexts.libraries, conformance::boc_to_base64(config->get_libraries_root()));
    }
    vm::CellBuilder prev_cb;
    if (!vm::StackEntry(previous_blocks).serialize(prev_cb)) {
      return td::Status::Error("cannot serialize the previous-block context");
    }
    TRY_RESULT_ASSIGN(contexts.prev_blocks, conformance::boc_to_base64(prev_cb.finalize()));
    contexts.seed = td::to_lower(extra.rand_seed.to_hex());
  }

  std::vector<Executed> executed;
  vm::AugmentedDictionary account_blocks(vm::load_cell_slice_ref(extra.account_blocks), 256,
                                         block::tlb::aug_ShardAccountBlocks);
  if (account_blocks.is_empty()) {
    // Without transactions the state update may prune both account dictionaries entirely.
    return accepted(root, applied, executed);
  }
  block::gen::ShardStateUnsplit::Record new_state;
  if (!tlb::unpack_cell(applied, new_state)) {
    why = {"state_update_mismatch"};
    return td::Status::Error("cannot unpack the new state");
  }
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  vm::AugmentedDictionary new_accounts(vm::load_cell_slice_ref(new_state.accounts), 256, block::tlb::aug_ShardAccounts);
  td::Status failure;
  why = {"malformed_block"};
  const bool walked = account_blocks.check_for_each_extra([&](auto value, auto, td::ConstBitPtr key, int) {
    block::gen::AccountBlock::Record ab;
    if (!block::gen::t_AccountBlock.unpack(value.write(), ab)) {
      why = {"malformed_block"};
      failure = td::Status::Error("account block");
      return false;
    }
    auto original_entry = accounts.lookup(key, 256);
    Cell original = absent_shard_account();
    if (original_entry.not_null()) {
      vm::CellBuilder cb;
      if (!cb.append_cellslice_bool(*original_entry)) {
        why = {"account_unavailable"};
        failure = td::Status::Error("cannot copy the account entry");
        return false;
      }
      original = cb.finalize();
    }
    // One emulator per account, as the replay creates one, set from the block's context.
    why = {"execution_refused"};
    std::unique_ptr<void, EmulatorDeleter> emulator{transaction_emulator_create(contexts.config.c_str(), 0)};
    if (!emulator || !transaction_emulator_set_rand_seed(emulator.get(), contexts.seed.c_str()) ||
        !transaction_emulator_set_ignore_chksig(emulator.get(), false) ||
        (!contexts.libraries.empty() && !transaction_emulator_set_libs(emulator.get(), contexts.libraries.c_str())) ||
        !transaction_emulator_set_prev_blocks_info(emulator.get(), contexts.prev_blocks.c_str())) {
      failure = td::Status::Error("the transaction emulator refused the block context");
      return false;
    }
    Cell current = original;
    vm::AugmentedDictionary transactions(vm::DictNonEmpty(), ab.transactions, 64, block::tlb::aug_AccountTransactions);
    const bool ran = transactions.check_for_each_extra([&](auto tx_value, auto, auto, int) {
      auto original_tx = tx_value->prefetch_ref();
      block::gen::Transaction::Record record;
      block::gen::HASH_UPDATE::Record expected_account;
      int type = 0;
      why = {"malformed_block"};
      if (original_tx.is_null() || !tlb::unpack_cell(original_tx, record) ||
          !tlb::type_unpack_cell(record.state_update, block::gen::t_HASH_UPDATE_Account, expected_account) ||
          !transaction_type(record.description, type)) {
        failure = td::Status::Error("original transaction");
        return false;
      }
      why = {"transaction_context_mismatch"};
      const auto align = block::ConfigInfo::get_lt_align();
      const auto current_account = vm::load_cell_slice(current).prefetch_ref(0);
      if (record.account_addr != ab.account_addr || record.now != info.gen_utime ||
          record.lt - record.lt % align != info.start_lt ||
          expected_account.old_hash != current_account->get_hash().bits()) {
        failure = td::Status::Error("transaction identity, time, logical time or pre-state differs");
        return false;
      }
      if (executed.size() >= kMaxTransactions) {
        failure = td::Status::Error("too many transactions");
        return false;
      }
      why = {"execution_refused"};
      auto shard_account = conformance::boc_to_base64(current);
      if (shard_account.is_error() ||
          !transaction_emulator_set_unixtime(emulator.get(), static_cast<std::uint32_t>(record.now)) ||
          !transaction_emulator_set_lt(emulator.get(), static_cast<std::uint64_t>(record.lt))) {
        failure = td::Status::Error("the transaction emulator refused the transaction context");
        return false;
      }
      auto result = emulate(emulator.get(), shard_account.ok(), record.r1.in_msg->prefetch_ref(), type);
      if (result.is_error()) {
        failure = result.move_as_error();
        return false;
      }
      auto emulated = result.move_as_ok();
      const auto new_account = vm::load_cell_slice(emulated.shard_account).prefetch_ref(0);
      executed.push_back({hash0(emulated.transaction), hash0(new_account)});
      if (emulated.transaction->get_hash(0) != original_tx->get_hash(0)) {
        why = {"transaction_mismatch"};
        failure = td::Status::Error("re-executed transaction differs from the block's");
        return false;
      }
      if (expected_account.new_hash != new_account->get_hash().bits()) {
        why = {"account_hash_mismatch"};
        failure = td::Status::Error("re-executed account differs from the transaction's new hash");
        return false;
      }
      current = std::move(emulated.shard_account);
      return true;
    });
    if (!ran) {
      if (failure.is_ok()) {
        why = {"malformed_block"};
        failure = td::Status::Error("transactions dictionary");
      }
      return false;
    }
    if (!new_state_holds(new_accounts, key, original, current)) {
      why = {"new_state_mismatch"};
      failure = td::Status::Error("the new state's account differs from the re-executed account");
      return false;
    }
    return true;
  });
  if (!walked) {
    if (failure.is_ok()) {
      why = {"malformed_block"};
      failure = td::Status::Error("account blocks dictionary");
    }
    return std::move(failure);
  }
  return accepted(root, applied, executed);
}

td::Result<std::string> run_block(td::JsonObject &ctx) {
  TRY_RESULT(block_input, required_original(ctx, "block"));
  TRY_RESULT(prev_state, conformance::required_boc(ctx, "prev_state"));
  const bool has_master_block = ctx.has_field("master_block");
  if (has_master_block != ctx.has_field("master_state")) {
    return td::Status::Error("master_block and master_state go together");
  }
  Original master_block;
  Cell master_state;
  if (has_master_block) {
    TRY_RESULT_ASSIGN(master_block, required_original(ctx, "master_block"));
    TRY_RESULT_ASSIGN(master_state, conformance::required_boc(ctx, "master_state"));
  }
  Rejection why{"malformed_block"};
  try {
    auto result = apply_block(block_input, prev_state, has_master_block ? &master_block : nullptr, master_state, why);
    if (result.is_error()) {
      return rejected(why.reason);
    }
    return result.move_as_ok();
  } catch (const vm::VmVirtError &) {
    // A cell the procedure needs is pruned from the supplied state.
    return rejected("pruned_state");
  } catch (const vm::VmError &) {
    return rejected(why.reason);
  } catch (const vm::CellBuilder::CellWriteError &) {
    return rejected(why.reason);
  } catch (const vm::CellBuilder::CellCreateError &) {
    return rejected(why.reason);
  } catch (const vm::CellSlice::CellReadError &) {
    return rejected(why.reason);
  }
}

}  // namespace

CONFORMANCE_REGISTER_HARNESS(block, run_block);
