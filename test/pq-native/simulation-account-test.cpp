/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <cstdlib>
#include <limits>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "lite-client/proof-verify/material.h"
#include "lite-client/proof-verify/simulation-account.h"
#include "lite-client/proof-verify/simulation-config.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "vm/boc.h"
#include "vm/dict.h"

namespace pv = tos::proofverify;
namespace detail = tos::proofverify::detail;

template <class T>
T must(td::Result<T> result) {
  if (result.is_error()) {
    std::fprintf(stderr, "SIMULATION_ACCOUNT_SETUP %s\n", result.error().message().str().c_str());
    std::exit(2);
  }
  return result.move_as_ok();
}

void require(bool ok) {
  if (!ok) {
    std::fprintf(stderr, "SIMULATION_ACCOUNT_SETUP failed\n");
    std::exit(2);
  }
}

int main(int argc, char** argv) {
  if (argc != 2) {
    return 2;
  }
  int failures = 0;
  auto check = [&](const char* name, bool ok) {
    std::printf("SIMULATION_ACCOUNT_CASE %s %s\n", name, ok ? "PASS" : "FAIL");
    failures += !ok;
  };
  auto refused = [](const auto& result, detail::SimulationAccountError error) {
    return result.is_error() && result.error().code() == static_cast<int>(error);
  };
  const std::string directory = argv[1];
  auto request = must(pv::parse_request(must(pv::read_bounded_file(directory + "/historical-request.json", 1u << 20))));
  auto material = must(pv::read_material(directory + "/historical"));
  require(request.account && request.target && material.exec_config && material.account);
  const auto address = *request.account;
  const auto target = *request.target;
  auto config = must(detail::extract_simulation_config(target, material.exec_config->as_slice()));
  constexpr std::int64_t local_now = 1791200932;
  auto prepared = detail::prepare_simulation_account(target, address, material.account->as_slice(), *config, local_now);
  check("real-account-prepared",
        prepared.is_ok() && prepared.ok().existed && prepared.ok().account.status == block::Account::acc_active);
  if (prepared.is_error()) {
    return 2;
  }
  auto answer = must(tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(material.account->clone(), true));
  block::AccountState source;
  source.blk = tos::create_block_id(answer->id_);
  source.shard_blk = tos::create_block_id(answer->shardblk_);
  source.shard_proof = answer->shard_proof_.clone();
  source.proof = answer->proof_.clone();
  source.state = answer->state_.clone();
  auto proven = must(source.validate(target, address));
  auto& native = prepared.ok().account;
  check("real-exact-account-cell", native.orig_total_state->get_hash() == proven.true_root->get_hash() &&
                                       prepared.ok().authenticated_state_hash == proven.true_root->get_hash().bits());
  check("real-distinct-start-and-end",
        native.last_trans_lt_ == proven.last_trans_lt && native.last_trans_hash_ == proven.last_trans_hash &&
            native.last_trans_end_lt_ > native.last_trans_lt_ && native.last_trans_end_lt_ <= proven.gen_lt);
  check("real-special-account", native.is_special);
  check("explicit-native-time-and-block-lt", native.now_ == prepared.ok().context.estimated_time &&
                                                 native.block_lt == prepared.ok().context.estimated_block_start_lt &&
                                                 prepared.ok().context.estimated_transaction_lt == native.block_lt + 1);
  auto wrong_address = address;
  wrong_address.addr.as_slice()[0] ^= 1;
  check("wrong-account-proof", refused(detail::prepare_simulation_account(
                                           target, wrong_address, material.account->as_slice(), *config, local_now),
                                       detail::SimulationAccountError::Proof));
  auto original_id = config->block_id;
  ++config->block_id.id.seqno;
  check("configuration-target-mismatch",
        refused(detail::prepare_simulation_account(target, address, material.account->as_slice(), *config, local_now),
                detail::SimulationAccountError::Proof));
  config->block_id = original_id;
  auto labeled = must(tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(material.account->clone(), true));
  ++labeled->id_->seqno_;
  check("account-answer-label-mismatch",
        refused(detail::prepare_simulation_account(target, address, tos::serialize_tl_object(labeled, true).as_slice(),
                                                   *config, local_now),
                detail::SimulationAccountError::Proof));
  auto missing_state =
      must(tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(material.account->clone(), true));
  missing_state->state_ = {};
  check("existing-account-cannot-become-absent",
        refused(detail::prepare_simulation_account(
                    target, address, tos::serialize_tl_object(missing_state, true).as_slice(), *config, local_now),
                detail::SimulationAccountError::Proof));
  check("reply-byte-limit",
        refused(detail::prepare_simulation_account(
                    target, address, std::string(detail::kMaxSimulationConfigReplyBytes + 1, 'x'), *config, local_now),
                detail::SimulationAccountError::Resource));

  // Synthetic observations below exercise restoration only. They are not proofs
  // from the recorded network and are never passed off as authenticated reads.
  auto make_state = [&](int status) {
    auto info = proven;
    block::gen::Account::Record_account record;
    block::gen::AccountStorage::Record storage;
    block::gen::StorageInfo::Record storage_info;
    require(tlb::unpack_cell(proven.true_root, record) && tlb::csr_unpack(record.storage, storage) &&
            tlb::csr_unpack(record.storage_stat, storage_info));
    vm::CellBuilder due;
    due.store_long(1, 1);
    require(block::tlb::t_Tomis.store_integer_value(due, *td::make_refint(7)));
    storage_info.due_payment = vm::load_cell_slice_ref(due.finalize());
    storage_info.last_paid = 1234;
    vm::CellBuilder usage;
    require(block::tlb::t_VarUInteger_7.store_integer_value(usage, *td::make_refint(11)));
    require(block::tlb::t_VarUInteger_7.store_integer_value(usage, *td::make_refint(337)));
    storage_info.used = usage.as_cellslice_ref();

    td::Ref<vm::Cell> storage_info_cell;
    require(tlb::pack_cell(storage_info_cell, storage_info));
    record.storage_stat = vm::load_cell_slice_ref(storage_info_cell);
    vm::CellBuilder extra_amount;
    require(block::tlb::t_VarUInteger_32.store_integer_value(extra_amount, *td::make_refint(321)));
    vm::Dictionary extras{32};
    require(extras.set(td::BitArray<32>(42), extra_amount.as_cellslice_ref()));
    block::CurrencyCollection balance{999000, extras.get_root_cell()};
    require(balance.pack_to(storage.balance));
    storage.last_trans_lt = 103;
    if (status != block::Account::acc_active) {
      vm::CellBuilder state;
      state.store_long(status == block::Account::acc_frozen ? 1 : 0, 2);
      if (status == block::Account::acc_frozen) {
        state.store_bits(address.addr.bits(), 256);
      }
      storage.state = vm::load_cell_slice_ref(state.finalize());
    }
    td::Ref<vm::Cell> storage_cell;
    require(tlb::pack_cell(storage_cell, storage));
    record.storage = vm::load_cell_slice_ref(storage_cell);
    require(tlb::pack_cell(info.true_root, record));
    info.root = info.true_root;
    info.last_trans_lt = 100;
    info.gen_lt = 500;
    return info;
  };
  auto modified = make_state(block::Account::acc_active);
  auto deep = modified;
  while (deep.true_root->get_depth() <= detail::kMaxSimulationConfigDepth) {
    deep.true_root = vm::CellBuilder().store_ref(deep.true_root).finalize();
  }
  check("account-depth-resource-classification",
        refused(detail::restore_simulation_account(address, deep, *config, local_now),
                detail::SimulationAccountError::Resource));
  auto changed_state =
      must(tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(material.account->clone(), true));
  changed_state->state_ = must(vm::std_boc_serialize(modified.true_root, 2));
  check("modified-account-body-not-proven",
        refused(detail::prepare_simulation_account(
                    target, address, tos::serialize_tl_object(changed_state, true).as_slice(), *config, local_now),
                detail::SimulationAccountError::Proof));
  auto oversized_state =
      must(tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(material.account->clone(), true));
  oversized_state->state_ = td::BufferSlice(detail::kMaxSimulationAccountBytes + 1);
  check("account-state-byte-limit",
        refused(detail::prepare_simulation_account(
                    target, address, tos::serialize_tl_object(oversized_state, true).as_slice(), *config, local_now),
                detail::SimulationAccountError::Resource));
  std::vector<td::Ref<vm::Cell>> level;
  for (unsigned i = 0; i < 32768; ++i) {
    level.push_back(vm::CellBuilder().store_long(i, 32).finalize());
  }
  while (level.size() > 1) {
    std::vector<td::Ref<vm::Cell>> next;
    for (std::size_t i = 0; i < level.size(); i += 2) {
      next.push_back(vm::CellBuilder().store_ref(level[i]).store_ref(level[i + 1]).finalize());
    }
    level = std::move(next);
  }
  auto large_graph = vm::CellBuilder().store_ref(level[0]).finalize();
  auto graph_boc = must(vm::std_boc_serialize(large_graph, 2));
  auto cell_bound = must(tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(material.account->clone(), true));
  cell_bound->state_ = graph_boc.clone();
  check("account-state-cell-limit",
        graph_boc.size() <= detail::kMaxSimulationAccountBytes &&
            refused(detail::prepare_simulation_account(
                        target, address, tos::serialize_tl_object(cell_bound, true).as_slice(), *config, local_now),
                    detail::SimulationAccountError::Resource));
  auto pair_boc = must(vm::std_boc_serialize_multi({large_graph, large_graph}, 2));
  auto proof_bound =
      must(tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(material.account->clone(), true));
  proof_bound->proof_ = pair_boc.clone();
  proof_bound->shard_proof_ = pair_boc.clone();
  check("combined-account-proof-cell-limit",
        refused(detail::prepare_simulation_account(
                    target, address, tos::serialize_tl_object(proof_bound, true).as_slice(), *config, local_now),
                detail::SimulationAccountError::Resource));
  auto restored = detail::restore_simulation_account(address, modified, *config, local_now);
  check("storage-debt-and-last-paid-preserved", restored.is_ok() && restored.ok().account.last_paid == 1234 &&
                                                    restored.ok().account.due_payment->to_dec_string() == "7");
  check("balance-and-extra-currency-preserved", restored.is_ok() &&
                                                    restored.ok().account.balance.tomis->to_dec_string() == "999000" &&
                                                    restored.ok().account.balance.extra.not_null());
  check("storage-usage-preserved", restored.is_ok() && restored.ok().account.storage_used.cells == 11 &&
                                       restored.ok().account.storage_used.bits == 337);
  if (restored.is_ok() && restored.ok().account.balance.extra.not_null()) {
    vm::Dictionary extras{restored.ok().account.balance.extra, 32};
    auto amount = extras.lookup(td::BitArray<32>(42));
    auto value = amount.not_null() ? block::tlb::t_VarUInteger_32.as_integer(*amount) : td::RefInt256{};
    check("extra-currency-value-preserved", value.not_null() && value->to_dec_string() == "321");
  } else {
    check("extra-currency-value-preserved", false);
  }
  check("synthetic-start-and-end-preserved", restored.is_ok() && restored.ok().account.last_trans_lt_ == 100 &&
                                                 restored.ok().account.last_trans_end_lt_ == 103);
  for (int status : {block::Account::acc_uninit, block::Account::acc_frozen}) {
    auto observation = make_state(status);
    auto result = detail::restore_simulation_account(address, observation, *config, local_now);
    check(status == block::Account::acc_frozen ? "frozen-state-preserved" : "uninitialized-state-preserved",
          result.is_ok() && result.ok().account.status == status &&
              result.ok().account.orig_total_state->get_hash() == observation.true_root->get_hash() &&
              result.ok().account.code.is_null() &&
              (status != block::Account::acc_frozen || result.ok().account.state_hash == address.addr));
  }
  block::AccountState::Info absent;
  absent.last_trans_hash.set_zero();
  absent.gen_lt = proven.gen_lt;
  absent.gen_utime = proven.gen_utime;
  auto fresh = detail::restore_simulation_account(address, absent, *config, local_now);
  check("proven-absence-only-native-initialization",
        fresh.is_ok() && !fresh.ok().existed && fresh.ok().account.status == block::Account::acc_nonexist &&
            fresh.ok().account.balance.is_zero() && fresh.ok().account.last_trans_lt_ == 0 &&
            fresh.ok().authenticated_state_hash.is_zero());
  auto present_none = absent;
  present_none.true_root = vm::CellBuilder().store_long(0, 1).finalize();
  present_none.root = present_none.true_root;
  check("present-account-none-not-synthesized",
        refused(detail::restore_simulation_account(address, present_none, *config, local_now),
                detail::SimulationAccountError::State));
  absent.last_trans_lt = 1;
  check("absence-with-history-refused", refused(detail::restore_simulation_account(address, absent, *config, local_now),
                                                detail::SimulationAccountError::State));
  absent.last_trans_lt = 0;
  absent.last_trans_hash.as_slice()[0] = 1;
  check("absence-with-hash-refused", refused(detail::restore_simulation_account(address, absent, *config, local_now),
                                             detail::SimulationAccountError::State));
  auto invalid = modified;
  invalid.last_trans_lt = 104;
  check("start-after-storage-end-refused",
        refused(detail::restore_simulation_account(address, invalid, *config, local_now),
                detail::SimulationAccountError::State));
  invalid = modified;
  invalid.gen_lt = 102;
  check("storage-end-after-shard-refused",
        refused(detail::restore_simulation_account(address, invalid, *config, local_now),
                detail::SimulationAccountError::Context));
  check("embedded-address-mismatch",
        refused(detail::restore_simulation_account(wrong_address, modified, *config, local_now),
                detail::SimulationAccountError::State));
  check("invalid-local-clock", refused(detail::restore_simulation_account(address, modified, *config, -1),
                                       detail::SimulationAccountError::Context));
  const auto saved_lt = config->lt;
  config->lt = std::numeric_limits<td::uint64>::max();
  check("context-overflow-refused", refused(detail::restore_simulation_account(address, modified, *config, local_now),
                                            detail::SimulationAccountError::Context));
  config->lt = saved_lt;
  return failures ? 1 : 0;
}
