/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <sstream>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "lite-client/proof-verify/material.h"
#include "lite-client/proof-verify/self-pay-simulation.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/misc.h"
#include "vm/boc.h"

namespace pv = tos::proofverify;
namespace detail = tos::proofverify::detail;

template <class T>
T must(td::Result<T> result) {
  if (result.is_error()) {
    std::fprintf(stderr, "SELF_PAY_SIMULATION_SETUP refused\n");
    std::exit(2);
  }
  return result.move_as_ok();
}

int main(int argc, char** argv) {
  if (argc < 2 || argc > 4 || (argc == 4 && std::string(argv[3]) != "--zero-seed")) {
    return 2;
  }
  const bool expect_zero_seed_refusal = argc == 4;
  const std::string directory = argv[1];
  auto config_boc = must(pv::read_bounded_file(directory + "/config.boc", 16u << 20));
  auto config_root = must(vm::std_boc_deserialize(config_boc));
  auto config_owned = must(block::Config::unpack_config(
      vm::load_cell_slice_ref(config_root),
      block::Config::needCapabilities | block::Config::needWorkchainInfo | block::Config::needSpecialSmc));
  std::shared_ptr<block::Config> config{std::move(config_owned)};
  auto scenarios = must(pv::read_bounded_file(directory + "/scenarios.tsv", 16u << 20));
  std::istringstream lines{scenarios};
  int failures = 0;
  int cases = 0;
  std::string line;
  // These retained public signing fixtures are diagnostic VM inputs, not an
  // authenticated target or phone-custody transaction. The future full test also
  // exercises the single-call proof path on a fresh self-pay network.
  while (std::getline(lines, line)) {
    std::istringstream fields{line};
    std::vector<std::string> columns;
    std::string column;
    while (std::getline(fields, column, '\t')) {
      columns.push_back(column);
    }
    if (columns.size() != 6) {
      return 2;
    }
    const auto time = static_cast<td::uint32>(std::stoul(columns[1]));
    const auto lt = static_cast<td::uint64>(std::stoull(columns[2]));
    auto shard = must(vm::std_boc_deserialize(must(td::hex_decode(columns[3]))));
    auto message = must(td::hex_decode(columns[4]));
    block::gen::ShardAccount::Record entry;
    block::gen::Account::Record_account account_cell;
    block::StdAddress address;
    entry.account = shard;
    entry.last_trans_lt = 0;
    entry.last_trans_hash.set_zero();
    if (!tlb::unpack_cell(shard, account_cell) ||
        !block::tlb::t_MsgAddressInt.extract_std_address(account_cell.addr, address)) {
      return 2;
    }
    // Parity rows contain Account only. Header metadata is synthetic here;
    // authenticated tests must recover it from the actual ShardAccount proof.
    td::Ref<vm::Cell> wrapped;
    if (!tlb::pack_cell(wrapped, entry)) {
      return 2;
    }
    block::Account account{address.workchain, address.addr.bits()};
    if (!account.unpack(vm::load_cell_slice_ref(wrapped), time, false)) {
      return 2;
    }
    auto context =
        must(detail::derive_self_pay_simulation_context({time, time, std::max(lt, account.last_trans_end_lt_), 0,
                                                         account.last_trans_lt_, account.last_trans_end_lt_, true},
                                                        time, static_cast<td::uint32>(config->get_global_version())));
    account.block_lt = context.estimated_block_start_lt;
    detail::PreparedSimulationAccount prepared{std::move(account), context,
                                               td::Bits256{entry.account->get_hash().bits()}, true};
    // Explicit synthetic prev-block tuple; fixed self-pay code does not inspect
    // it. Production must pass ConfigInfo::get_prev_blocks_info from proofs.
    auto result = detail::execute_prepared_self_pay(tos::BlockIdExt{}, config, vm::make_tuple_ref(),
                                                    std::move(prepared), message);
    const bool expected_execution = columns[0] == "pre-funded-deployment-1" ||
                                    columns[0] == "pre-funded-deployment-2" || columns[0] == "primary" ||
                                    columns[0] == "rescue" || columns[5] != "-";
    const bool ok =
        result.is_ok() &&
        (expect_zero_seed_refusal
             ? result.ok().outcome == pv::SimulationOutcome::Unsupported && !result.ok().transaction
         : expected_execution
             ? result.ok().outcome == pv::SimulationOutcome::Executed && result.ok().transaction.has_value() &&
                   !result.ok().message_bytes_hash.is_zero() && !result.ok().simulation_seed.is_zero()
             : result.ok().outcome == pv::SimulationOutcome::NotAccepted && !result.ok().transaction.has_value() &&
                   result.ok().vm_exit_code.has_value() &&
                   result.ok().vm_exit_code.value() == (columns[0].find("replay") != std::string::npos ? 1804 : 1808));
    std::printf("SELF_PAY_SIMULATION_CASE %s %s outcome=%d\n", columns[0].c_str(), ok ? "PASS" : "FAIL",
                result.is_ok() ? static_cast<int>(result.ok().outcome) : -1);
    failures += !ok;
    if (columns[5] != "-" && !expect_zero_seed_refusal) {
      auto expected = must(td::json_decode(td::MutableSlice(columns[5])));
      bool same = false;
      if (result.is_ok() && result.ok().transaction) {
        auto json = result.ok().transaction->codec_json;
        auto decoded = must(td::json_decode(td::MutableSlice(json)));
        auto& object = decoded.get_object();
        const auto aborted = must(object.get_required_bool_field("aborted"));
        auto outputs = must(object.extract_required_field("out_msgs", td::JsonValue::Type::Array));
        auto compute = must(object.extract_required_field("compute", td::JsonValue::Type::Object));
        same = aborted == must(expected.get_object().get_required_bool_field("aborted")) &&
               outputs.get_array().size() ==
                   static_cast<std::size_t>(must(expected.get_object().get_required_int_field("outputs"))) &&
               must(compute.get_object().get_required_int_field("exit_code")) ==
                   must(expected.get_object().get_required_int_field("exit_code")) &&
               result.ok().transaction->expected_balance ==
                   must(expected.get_object().get_required_string_field("balance"));
      }
      std::printf("SELF_PAY_SIMULATION_CASE %s-value-fee-phase %s\n", columns[0].c_str(), same ? "PASS" : "FAIL");
      failures += !same;
    }
    if (columns[0] == "primary") {
      auto repeat = [&](const tos::BlockIdExt& selected_target, td::Slice selected_message, bool unknown_code = false) {
        block::Account input{address.workchain, address.addr.bits()};
        if (!input.unpack(vm::load_cell_slice_ref(wrapped), time, false)) {
          std::exit(2);
        }
        input.block_lt = context.estimated_block_start_lt;
        if (unknown_code) {
          // Fault input for this internal interface, not a proof-bound read.
          input.code = vm::CellBuilder().store_long(0, 1).finalize();
        }
        return detail::execute_prepared_self_pay(
            selected_target, config, vm::make_tuple_ref(),
            detail::PreparedSimulationAccount{std::move(input), context, td::Bits256{entry.account->get_hash().bits()},
                                              true},
            selected_message);
      };
      if (!expect_zero_seed_refusal) {
        auto check = [&](const char* name, bool passed) {
          std::printf("SELF_PAY_SIMULATION_CASE %s %s\n", name, passed ? "PASS" : "FAIL");
          failures += !passed;
        };
        auto repeated = repeat(tos::BlockIdExt{}, message);
        check("deterministic-explicit-seed", repeated.is_ok() && result.is_ok() &&
                                                 repeated.ok().simulation_seed == result.ok().simulation_seed &&
                                                 !repeated.ok().simulation_seed.is_zero());
        tos::BlockIdExt another_target;
        another_target.root_hash.as_slice()[0] = 1;
        auto changed_target = repeat(another_target, message);
        check("seed-binds-target-root", changed_target.is_ok() && result.is_ok() &&
                                            changed_target.ok().simulation_seed != result.ok().simulation_seed);
        another_target = {};
        another_target.file_hash.as_slice()[0] = 1;
        changed_target = repeat(another_target, message);
        check("seed-binds-target-file", changed_target.is_ok() && result.is_ok() &&
                                            changed_target.ok().simulation_seed != result.ok().simulation_seed);
        auto another_wire = must(vm::std_boc_serialize(must(vm::std_boc_deserialize(message)), 31));
        auto changed_wire = repeat(tos::BlockIdExt{}, another_wire.as_slice());
        check("exact-wire-authorization-binding",
              changed_wire.is_ok() && result.is_ok() && changed_wire.ok().transaction &&
                  changed_wire.ok().message_root_hash == result.ok().message_root_hash &&
                  changed_wire.ok().message_bytes_hash != result.ok().message_bytes_hash &&
                  changed_wire.ok().simulation_seed != result.ok().simulation_seed);
        auto unsupported = repeat(tos::BlockIdExt{}, message, true);
        check("unsupported-execution-code", unsupported.is_ok() &&
                                                unsupported.ok().outcome == pv::SimulationOutcome::Unsupported &&
                                                !unsupported.ok().transaction);
      }
      block::gen::AccountStorage::Record storage;
      if (!tlb::csr_unpack(account_cell.storage, storage)) {
        return 2;
      }
      auto active = *storage.state;
      if (!active.advance(1)) {
        return 2;
      }
      block::gen::StateInit::Record original_init;
      if (!block::gen::t_StateInit.unpack(active, original_init)) {
        return 2;
      }
      auto data = vm::load_cell_slice(original_init.data->prefetch_ref());
      if (!data.advance(40)) {
        return 2;
      }
      auto changed_data = vm::CellBuilder().store_long(1, 8).store_long(1, 32).append_cellslice(data).finalize();
      auto current_init = vm::CellBuilder()
                              .store_long(0, 2)
                              .store_long(1, 1)
                              .store_ref(original_init.code->prefetch_ref())
                              .store_long(1, 1)
                              .store_ref(changed_data)
                              .store_long(0, 1)
                              .finalize();
      storage.state = vm::load_cell_slice_ref(
          vm::CellBuilder().store_long(1, 2).store_bits(current_init->get_hash().bits(), 256).finalize());
      td::Ref<vm::Cell> frozen_storage, frozen_root;
      if (!tlb::pack_cell(frozen_storage, storage)) {
        return 2;
      }
      account_cell.storage = vm::load_cell_slice_ref(frozen_storage);
      if (!tlb::pack_cell(frozen_root, account_cell)) {
        return 2;
      }
      entry.account = frozen_root;
      if (!tlb::pack_cell(wrapped, entry)) {
        return 2;
      }
      block::Account frozen{address.workchain, address.addr.bits()};
      if (!frozen.unpack(vm::load_cell_slice_ref(wrapped), time, false)) {
        return 2;
      }
      frozen.block_lt = context.estimated_block_start_lt;
      block::gen::Message::Record thaw_message;
      if (!block::gen::t_Message_Any.cell_unpack(must(vm::std_boc_deserialize(message)), thaw_message)) {
        return 2;
      }
      thaw_message.init =
          vm::load_cell_slice_ref(vm::CellBuilder().store_long(3, 2).store_ref(current_init).finalize());
      td::Ref<vm::Cell> thaw_root;
      if (!block::gen::t_Message_Any.cell_pack(thaw_root, thaw_message)) {
        return 2;
      }
      detail::PreparedSimulationAccount frozen_input{std::move(frozen), context,
                                                     td::Bits256{frozen_root->get_hash().bits()}, true};
      auto thaw = detail::execute_prepared_self_pay(tos::BlockIdExt{}, config, vm::make_tuple_ref(),
                                                    std::move(frozen_input), must(vm::std_boc_serialize(thaw_root, 2)));
      const bool thawed =
          td::Bits256{current_init->get_hash().bits()} != address.addr && thaw.is_ok() &&
          (expect_zero_seed_refusal
               ? thaw.ok().outcome == pv::SimulationOutcome::Unsupported && !thaw.ok().transaction
               : thaw.ok().outcome == pv::SimulationOutcome::Executed && thaw.ok().transaction.has_value());
      std::printf("SELF_PAY_SIMULATION_CASE frozen-current-state-init-not-birth %s\n", thawed ? "PASS" : "FAIL");
      failures += !thawed;
      block::gen::Account::Record_account empty_record;
      block::gen::AccountStorage::Record empty_storage;
      if (!tlb::unpack_cell(shard, empty_record) || !tlb::csr_unpack(empty_record.storage, empty_storage) ||
          !block::CurrencyCollection::zero().pack_to(empty_storage.balance) ||
          !tlb::pack_cell(frozen_storage, empty_storage)) {
        return 2;
      }
      empty_record.storage = vm::load_cell_slice_ref(frozen_storage);
      if (!tlb::pack_cell(frozen_root, empty_record)) {
        return 2;
      }
      entry.account = frozen_root;
      if (!tlb::pack_cell(wrapped, entry)) {
        return 2;
      }
      block::Account empty{address.workchain, address.addr.bits()};
      if (!empty.unpack(vm::load_cell_slice_ref(wrapped), time, false)) {
        return 2;
      }
      empty.block_lt = context.estimated_block_start_lt;
      detail::PreparedSimulationAccount empty_input{std::move(empty), context,
                                                    td::Bits256{frozen_root->get_hash().bits()}, true};
      auto imported = detail::execute_prepared_self_pay(tos::BlockIdExt{}, config, vm::make_tuple_ref(),
                                                        std::move(empty_input), message);
      const bool import_refused =
          imported.is_ok() && !imported.ok().transaction && !imported.ok().vm_exit_code &&
          imported.ok().authenticated_balance == "0" &&
          imported.ok().outcome ==
              (expect_zero_seed_refusal ? pv::SimulationOutcome::Unsupported : pv::SimulationOutcome::ImportRejected);
      std::printf("SELF_PAY_SIMULATION_CASE import-rejected-with-no-fabricated-fees %s\n",
                  import_refused ? "PASS" : "FAIL");
      failures += !import_refused;
    }
    ++cases;
  }
  if (argc >= 3) {
    const std::string proofs = argv[2];
    auto anchor = must(pv::parse_anchor(must(pv::read_bounded_file(proofs + "/anchor.json", 1u << 20))));
    auto state = must(pv::parse_state(must(pv::read_bounded_file(proofs + "/live-state.json", 1u << 20))));
    auto historical =
        must(pv::parse_request(must(pv::read_bounded_file(proofs + "/historical-request.json", 1u << 20))));
    auto recorded = must(pv::read_material(proofs + "/historical"));
    auto live = must(pv::read_material(proofs + "/live"));
    live.config.reset();
    live.account = recorded.account->clone();
    live.exec_config = recorded.exec_config->clone();
    const auto address = historical.account.value();
    const std::string json = "{\"mode\":\"live\",\"max_age_seconds\":300,\"account\":\"" +
                             std::to_string(address.workchain) + ":" + td::hex_encode(address.addr.as_slice()) + "\"}";
    auto request = must(pv::parse_request(json));
    auto message_cell = vm::CellBuilder()
                            .store_long(8, 4)
                            .store_long(4, 3)
                            .store_long(address.workchain, 8)
                            .store_bits(address.addr.bits(), 256)
                            .store_long(0, 6)
                            .finalize();
    auto message = must(vm::std_boc_serialize(message_cell, 2));
    auto check = [&](const char* name, bool ok) {
      std::printf("SELF_PAY_SIMULATION_CASE %s %s\n", name, ok ? "PASS" : "FAIL");
      failures += !ok;
    };
    auto result = pv::simulate_self_pay(anchor, request, json, live, state, pv::Policy{1791200932}, message.as_slice());
    // Recorded Elector/VM18 is intentionally outside the execution profile.
    // This validates live chain/config/account composition and next_state only;
    // fresh supported basechain proof+execution acceptance remains required.
    check("recorded-live-proof-bound-unsupported-profile",
          result.is_ok() && result.ok().estimate.outcome == pv::SimulationOutcome::Unsupported &&
              !result.ok().estimate.transaction && result.ok().authenticated_read.next_state &&
              result.ok().authenticated_read.next_state->head->id == historical.target.value());
    check("live-state-required",
          pv::simulate_self_pay(anchor, request, json, live, std::nullopt, pv::Policy{1791200932}, message.as_slice())
              .is_error());
    auto clock = pv::Policy{std::numeric_limits<std::int64_t>::max()};
    check("clock-before-proof-arithmetic",
          pv::simulate_self_pay(anchor, request, json, live, state, clock, message.as_slice()).is_error());
    const std::string historical_json =
        "{\"mode\":\"historical\",\"target\":" + pv::block_id_json(historical.target.value()) + ",\"account\":\"" +
        std::to_string(address.workchain) + ":" + td::hex_encode(address.addr.as_slice()) + "\"}";
    auto historical_request = must(pv::parse_request(historical_json));
    auto historical_material = must(pv::read_material(proofs + "/historical"));
    historical_material.config.reset();
    check("historical-mode-refused",
          pv::simulate_self_pay(anchor, historical_request, historical_json, historical_material, std::nullopt,
                                pv::Policy{1791200932}, message.as_slice())
              .is_error());
    live.exec_config = recorded.config->clone();
    check("partial-config-not-simulation-context",
          pv::simulate_self_pay(anchor, request, json, live, state, pv::Policy{1791200932}, message.as_slice())
              .is_error());
    live.exec_config = recorded.exec_config->clone();
    live.config = recorded.config->clone();
    check("unexpected-selected-param-proof-refused",
          pv::simulate_self_pay(anchor, request, json, live, state, pv::Policy{1791200932}, message.as_slice())
              .is_error());
  }
  return failures || cases != 13 ? 1 : 0;
}
