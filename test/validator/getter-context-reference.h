/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// Independent test oracle. Its construction is frozen so changing the production
// helper cannot also change the value against which the helper is compared.
#include "block/mc-config.h"
#include "block/transaction.h"
#include "td/utils/Random.h"
#include "vm/stack.hpp"

namespace getter_reference {

// clang-format off
static td::Ref<vm::Tuple> prepare_vm_c7(tos::UnixTime now, tos::LogicalTime lt, td::Ref<vm::CellSlice> my_addr,
                                        const block::CurrencyCollection& balance,
                                        const block::ConfigInfo* config = nullptr, td::Ref<vm::Cell> my_code = {},
                                        td::RefInt256 due_payment = td::zero_refint()) {
  td::BitArray<256> rand_seed;
  td::RefInt256 rand_seed_int{true};
  td::Random::secure_bytes(rand_seed.as_slice());
  if (!rand_seed_int.unique_write().import_bits(rand_seed.cbits(), 256, false)) {
    return {};
  }
  std::vector<vm::StackEntry> tuple = {
      td::make_refint(0x076ef1ea),                         // [ magic:0x076ef1ea
      td::make_refint(0),                                  //   actions:Integer
      td::make_refint(0),                                  //   msgs_sent:Integer
      td::make_refint(now),                                //   unixtime:Integer
      td::make_refint(lt),                                 //   block_lt:Integer
      td::make_refint(lt),                                 //   trans_lt:Integer
      std::move(rand_seed_int),                            //   rand_seed:Integer
      balance.as_vm_tuple(),                               //   balance_remaining:[Integer (Maybe Cell)]
      my_addr,                                             //   myself:MsgAddressInt
      config ? config->get_root_cell() : vm::StackEntry()  //   global_config:(Maybe Cell) ] = SmartContractInfo;
  };
  if (config && config->get_global_version() >= 4) {
    tuple.push_back(vm::StackEntry::maybe(my_code));                   // code:Cell
    tuple.push_back(block::CurrencyCollection::zero().as_vm_tuple());  // in_msg_value:[Integer (Maybe Cell)]
    tuple.push_back(td::zero_refint());                                // storage_fees:Integer

    // [ wc:Integer shard:Integer seqno:Integer root_hash:Integer file_hash:Integer] = BlockId;
    // [ last_mc_blocks:[BlockId...]
    //   prev_key_block:BlockId ] : PrevBlocksInfo
    auto info = config->get_prev_blocks_info();
    tuple.push_back(info.is_ok() ? info.move_as_ok() : vm::StackEntry());
  }
  if (config && config->get_global_version() >= 6) {
    tuple.push_back(vm::StackEntry::maybe(config->get_unpacked_config_tuple(now)));  // unpacked_config_tuple:[...]
    tuple.push_back(due_payment);                                                    // due_payment:Integer
    // precompiled_gas_usage:(Maybe Integer)
    td::optional<block::PrecompiledContractsConfig::Contract> precompiled;
    if (my_code.not_null()) {
      precompiled = config->get_precompiled_contracts_config().get_contract(my_code->get_hash().bits());
    }
    tuple.push_back(precompiled ? td::make_refint(precompiled.value().gas_usage) : vm::StackEntry());
  }
  if (config && config->get_global_version() >= 11) {
    tuple.push_back(block::transaction::Transaction::prepare_in_msg_params_tuple(nullptr, {}, {}));
  }
  auto tuple_ref = td::make_cnt_ref<std::vector<vm::StackEntry>>(std::move(tuple));
  LOG(DEBUG) << "SmartContractInfo initialized with " << vm::StackEntry(tuple_ref).to_string();
  return vm::make_tuple_ref(std::move(tuple_ref));
}

// clang-format on

inline std::vector<td::Ref<vm::Cell>> libraries(const block::ConfigInfo& config, td::Ref<vm::Cell> account) {
  std::vector<td::Ref<vm::Cell>> result;
  if (config.get_libraries_root().not_null()) {
    result.push_back(config.get_libraries_root());
  }
  if (account.not_null() && config.get_global_version() < 15) {
    result.push_back(account);
  }
  return result;
}

}  // namespace getter_reference
