#include "crypto/vm/memo.h"
#include "crypto/vm/stack.hpp"
#include "td/utils/JsonBuilder.h"
#include "td/utils/Status.h"
#include "td/utils/Variant.h"
#include "td/utils/base64.h"
#include "td/utils/logging.h"
#include "td/utils/overloaded.h"

#include "emulator-extern.h"
#include "git.h"
#include "transaction-emulator.h"
#include "tvm-emulator.hpp"

td::Result<td::Ref<vm::Cell>> boc_b64_to_cell(const char *boc) {
  TRY_RESULT_PREFIX(boc_decoded, td::base64_decode(td::Slice(boc)), "Can't decode base64 boc: ");
  return vm::std_boc_deserialize(boc_decoded);
}

td::Result<std::string> cell_to_boc_b64(td::Ref<vm::Cell> cell) {
  TRY_RESULT_PREFIX(boc, vm::std_boc_serialize(std::move(cell), vm::BagOfCells::Mode::WithCRC32C),
                    "Can't serialize cell: ");
  return td::base64_encode(boc.as_slice());
}

const char *success_response(std::string &&transaction, std::string &&new_shard_account, std::string &&vm_log,
                             td::optional<std::string> &&actions, double elapsed_time) {
  td::JsonBuilder jb;
  auto json_obj = jb.enter_object();
  json_obj("success", td::JsonTrue());
  json_obj("transaction", std::move(transaction));
  json_obj("shard_account", std::move(new_shard_account));
  json_obj("vm_log", std::move(vm_log));
  if (actions) {
    json_obj("actions", actions.unwrap());
  } else {
    json_obj("actions", td::JsonNull());
  }
  json_obj("elapsed_time", elapsed_time);
  json_obj.leave();
  return strdup(jb.string_builder().as_cslice().c_str());
}

const char *error_response(std::string &&error) {
  td::JsonBuilder jb;
  auto json_obj = jb.enter_object();
  json_obj("success", td::JsonFalse());
  json_obj("error", std::move(error));
  json_obj("external_not_accepted", td::JsonFalse());
  json_obj.leave();
  return strdup(jb.string_builder().as_cslice().c_str());
}

const char *external_not_accepted_response(std::string &&vm_log, int vm_exit_code, double elapsed_time) {
  td::JsonBuilder jb;
  auto json_obj = jb.enter_object();
  json_obj("success", td::JsonFalse());
  json_obj("error", "External message not accepted by smart contract");
  json_obj("external_not_accepted", td::JsonTrue());
  json_obj("vm_log", std::move(vm_log));
  json_obj("vm_exit_code", vm_exit_code);
  json_obj("elapsed_time", elapsed_time);
  json_obj.leave();
  return strdup(jb.string_builder().as_cslice().c_str());
}

#define ERROR_RESPONSE(error) return error_response(error)

td::Result<block::Config> decode_config(const char *config_boc) try {
  // Codex audit (round 14, finding #1): all downstream callers of
  // `decode_config` (`transaction_emulator_create`, `emulator_config_create`,
  // `transaction_emulator_set_config`) check the returned Result, so
  // converting any thrown VmError from `vm::load_cell_slice` /
  // `block::Config::unpack` into a structured error here propagates
  // cleanly. Without the function-try-block a malformed/special config
  // BoC threw out of the C ABI and terminated the embedding host.
  TRY_RESULT_PREFIX(config_params_cell, boc_b64_to_cell(config_boc), "Can't deserialize config params boc: ");
  auto config_dict = std::make_unique<vm::Dictionary>(config_params_cell, 32);
  auto config_addr_cell = config_dict->lookup_ref(td::BitArray<32>::zero());
  if (config_addr_cell.is_null()) {
    return td::Status::Error("Can't find config address (param 0) is missing in config params");
  }
  bool config_addr_special = false;
  auto config_addr_cs = vm::load_cell_slice_special(std::move(config_addr_cell), config_addr_special);
  if (config_addr_special) {
    return td::Status::Error("config param 0 root is a special cell");
  }
  if (config_addr_cs.size() != 0x100) {
    return td::Status::Error(PSLICE() << "configuration parameter 0 with config address has wrong size");
  }
  tos::StdSmcAddress config_addr;
  config_addr_cs.fetch_bits_to(config_addr);
  auto global_config =
      block::Config(config_params_cell, std::move(config_addr),
                    block::Config::needWorkchainInfo | block::Config::needSpecialSmc | block::Config::needCapabilities);
  TRY_STATUS_PREFIX(global_config.unpack(), "Can't unpack config params: ");
  return global_config;
} catch (const vm::VmError& e) {
  return td::Status::Error(PSLICE() << "decode_config: vm error: " << e.get_msg());
} catch (const std::exception& e) {
  return td::Status::Error(PSLICE() << "decode_config: " << e.what());
} catch (...) {
  return td::Status::Error("decode_config: unknown exception");
}

void *transaction_emulator_create(const char *config_params_boc, int vm_log_verbosity) {
  auto global_config_res = decode_config(config_params_boc);
  if (global_config_res.is_error()) {
    LOG(ERROR) << global_config_res.move_as_error().message();
    return nullptr;
  }
  auto global_config = std::make_shared<block::Config>(global_config_res.move_as_ok());
  return new emulator::TransactionEmulator(std::move(global_config), vm_log_verbosity);
}

void *emulator_config_create(const char *config_params_boc) {
  auto config = decode_config(config_params_boc);
  if (config.is_error()) {
    LOG(ERROR) << "Error decoding config: " << config.move_as_error();
    return nullptr;
  }
  return new block::Config(config.move_as_ok());
}

const char *transaction_emulator_emulate_transaction(void *transaction_emulator, const char *shard_account_boc,
                                                     const char *message_boc) try {
  // Codex audit (round 13, finding #1): every `vm::load_cell_slice(X)`
  // below throws on PrunedBranch / Library / Merkle*, and the
  // shard_account / message BoCs are FFI-callee-supplied. Wrap the entire
  // function in a function-try-block so a malformed BoC returns a
  // structured ERROR_RESPONSE instead of std::terminate-ing the host.
  auto emulator = static_cast<emulator::TransactionEmulator *>(transaction_emulator);

  auto message_cell_r = boc_b64_to_cell(message_boc);
  if (message_cell_r.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Can't deserialize message boc: " << message_cell_r.move_as_error());
  }
  auto message_cell = message_cell_r.move_as_ok();
  auto message_cs = vm::load_cell_slice(message_cell);
  int msg_tag = block::gen::t_CommonMsgInfo.get_tag(message_cs);

  auto shard_account_cell = boc_b64_to_cell(shard_account_boc);
  if (shard_account_cell.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Can't deserialize shard account boc: " << shard_account_cell.move_as_error());
  }
  auto shard_account_slice = vm::load_cell_slice(shard_account_cell.ok_ref());
  block::gen::ShardAccount::Record shard_account;
  if (!tlb::unpack(shard_account_slice, shard_account)) {
    ERROR_RESPONSE(PSTRING() << "Can't unpack shard account cell");
  }

  td::Ref<vm::CellSlice> addr_slice;
  auto account_slice = vm::load_cell_slice(shard_account.account);
  bool account_exists = block::gen::t_Account.get_tag(account_slice) == block::gen::Account::account;
  if (block::gen::t_Account.get_tag(account_slice) == block::gen::Account::account_none) {
    if (msg_tag == block::gen::CommonMsgInfo::ext_in_msg_info) {
      block::gen::CommonMsgInfo::Record_ext_in_msg_info info;
      if (!tlb::unpack(message_cs, info)) {
        ERROR_RESPONSE(PSTRING() << "Can't unpack inbound external message");
      }
      addr_slice = std::move(info.dest);
    } else if (msg_tag == block::gen::CommonMsgInfo::int_msg_info) {
      block::gen::CommonMsgInfo::Record_int_msg_info info;
      if (!tlb::unpack(message_cs, info)) {
        ERROR_RESPONSE(PSTRING() << "Can't unpack inbound internal message");
      }
      addr_slice = std::move(info.dest);
    } else {
      ERROR_RESPONSE(PSTRING() << "Only ext in and int message are supported");
    }
  } else if (block::gen::t_Account.get_tag(account_slice) == block::gen::Account::account) {
    block::gen::Account::Record_account account_record;
    if (!tlb::unpack(account_slice, account_record)) {
      ERROR_RESPONSE(PSTRING() << "Can't unpack account cell");
    }
    addr_slice = std::move(account_record.addr);
  } else {
    ERROR_RESPONSE(PSTRING() << "Can't parse account cell");
  }
  tos::WorkchainId wc;
  tos::StdSmcAddress addr;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(addr_slice, wc, addr)) {
    ERROR_RESPONSE(PSTRING() << "Can't extract account address");
  }

  auto account = block::Account(wc, addr.bits());
  tos::UnixTime now = emulator->get_unixtime();
  if (!now) {
    now = (unsigned)std::time(nullptr);
  }
  bool is_special = wc == tos::masterchainId && emulator->get_config().is_special_smartcontract(addr);
  if (account_exists) {
    if (!account.unpack(vm::load_cell_slice_ref(shard_account_cell.move_as_ok()), now, is_special)) {
      ERROR_RESPONSE(PSTRING() << "Can't unpack shard account");
    }
  } else {
    if (!account.init_new(now)) {
      ERROR_RESPONSE(PSTRING() << "Can't init new account");
    }
    account.last_trans_lt_ = shard_account.last_trans_lt;
    account.last_trans_hash_ = shard_account.last_trans_hash;
  }

  auto result =
      emulator->emulate_transaction(std::move(account), message_cell, now, 0, block::transaction::Transaction::tr_ord);
  if (result.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Emulate transaction failed: " << result.move_as_error());
  }
  auto emulation_result = result.move_as_ok();

  auto external_not_accepted =
      dynamic_cast<emulator::TransactionEmulator::EmulationExternalNotAccepted *>(emulation_result.get());
  if (external_not_accepted) {
    return external_not_accepted_response(std::move(external_not_accepted->vm_log), external_not_accepted->vm_exit_code,
                                          external_not_accepted->elapsed_time);
  }

  auto emulation_success =
      std::move(dynamic_cast<emulator::TransactionEmulator::EmulationSuccess &>(*emulation_result));
  auto trans_boc_b64 = cell_to_boc_b64(std::move(emulation_success.transaction));
  if (trans_boc_b64.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Can't serialize Transaction to boc " << trans_boc_b64.move_as_error());
  }

  auto new_shard_account_cell = vm::CellBuilder()
                                    .store_ref(emulation_success.account.total_state)
                                    .store_bits(emulation_success.account.last_trans_hash_.as_bitslice())
                                    .store_long(emulation_success.account.last_trans_lt_)
                                    .finalize();
  auto new_shard_account_boc_b64 = cell_to_boc_b64(std::move(new_shard_account_cell));
  if (new_shard_account_boc_b64.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Can't serialize ShardAccount to boc " << new_shard_account_boc_b64.move_as_error());
  }

  td::optional<td::string> actions_boc_b64;
  if (emulation_success.actions.not_null()) {
    auto actions_boc_b64_result = cell_to_boc_b64(std::move(emulation_success.actions));
    if (actions_boc_b64_result.is_error()) {
      ERROR_RESPONSE(PSTRING() << "Can't serialize actions list cell to boc "
                               << actions_boc_b64_result.move_as_error());
    }
    actions_boc_b64 = actions_boc_b64_result.move_as_ok();
  }

  return success_response(trans_boc_b64.move_as_ok(), new_shard_account_boc_b64.move_as_ok(),
                          std::move(emulation_success.vm_log), std::move(actions_boc_b64),
                          emulation_success.elapsed_time);
} catch (const vm::VmError& e) {
  ERROR_RESPONSE(PSTRING() << "transaction_emulator_emulate_transaction: vm error: " << e.get_msg());
} catch (const std::exception& e) {
  ERROR_RESPONSE(PSTRING() << "transaction_emulator_emulate_transaction: " << e.what());
} catch (...) {
  ERROR_RESPONSE("transaction_emulator_emulate_transaction: unknown exception");
}

const char *transaction_emulator_emulate_tick_tock_transaction(void *transaction_emulator,
                                                               const char *shard_account_boc, bool is_tock) try {
  // Codex audit (round 13, finding #1): same hardening as
  // transaction_emulator_emulate_transaction.
  auto emulator = static_cast<emulator::TransactionEmulator *>(transaction_emulator);

  auto shard_account_cell = boc_b64_to_cell(shard_account_boc);
  if (shard_account_cell.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Can't deserialize shard account boc: " << shard_account_cell.move_as_error());
  }
  auto shard_account_slice = vm::load_cell_slice(shard_account_cell.ok_ref());
  block::gen::ShardAccount::Record shard_account;
  if (!tlb::unpack(shard_account_slice, shard_account)) {
    ERROR_RESPONSE(PSTRING() << "Can't unpack shard account cell");
  }

  td::Ref<vm::CellSlice> addr_slice;
  auto account_slice = vm::load_cell_slice(shard_account.account);
  if (block::gen::t_Account.get_tag(account_slice) == block::gen::Account::account_none) {
    ERROR_RESPONSE(PSTRING() << "Can't run tick/tock transaction on account_none");
  }
  block::gen::Account::Record_account account_record;
  if (!tlb::unpack(account_slice, account_record)) {
    ERROR_RESPONSE(PSTRING() << "Can't unpack account cell");
  }
  addr_slice = std::move(account_record.addr);
  tos::WorkchainId wc;
  tos::StdSmcAddress addr;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(addr_slice, wc, addr)) {
    ERROR_RESPONSE(PSTRING() << "Can't extract account address");
  }

  auto account = block::Account(wc, addr.bits());
  tos::UnixTime now = emulator->get_unixtime();
  if (!now) {
    now = (unsigned)std::time(nullptr);
  }
  bool is_special = wc == tos::masterchainId && emulator->get_config().is_special_smartcontract(addr);
  if (!account.unpack(vm::load_cell_slice_ref(shard_account_cell.move_as_ok()), now, is_special)) {
    ERROR_RESPONSE(PSTRING() << "Can't unpack shard account");
  }

  auto trans_type = is_tock ? block::transaction::Transaction::tr_tock : block::transaction::Transaction::tr_tick;
  auto result = emulator->emulate_transaction(std::move(account), {}, now, 0, trans_type);
  if (result.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Emulate transaction failed: " << result.move_as_error());
  }
  auto emulation_result = result.move_as_ok();

  auto emulation_success =
      std::move(dynamic_cast<emulator::TransactionEmulator::EmulationSuccess &>(*emulation_result));
  auto trans_boc_b64 = cell_to_boc_b64(std::move(emulation_success.transaction));
  if (trans_boc_b64.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Can't serialize Transaction to boc " << trans_boc_b64.move_as_error());
  }

  auto new_shard_account_cell = vm::CellBuilder()
                                    .store_ref(emulation_success.account.total_state)
                                    .store_bits(emulation_success.account.last_trans_hash_.as_bitslice())
                                    .store_long(emulation_success.account.last_trans_lt_)
                                    .finalize();
  auto new_shard_account_boc_b64 = cell_to_boc_b64(std::move(new_shard_account_cell));
  if (new_shard_account_boc_b64.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Can't serialize ShardAccount to boc " << new_shard_account_boc_b64.move_as_error());
  }

  td::optional<td::string> actions_boc_b64;
  if (emulation_success.actions.not_null()) {
    auto actions_boc_b64_result = cell_to_boc_b64(std::move(emulation_success.actions));
    if (actions_boc_b64_result.is_error()) {
      ERROR_RESPONSE(PSTRING() << "Can't serialize actions list cell to boc "
                               << actions_boc_b64_result.move_as_error());
    }
    actions_boc_b64 = actions_boc_b64_result.move_as_ok();
  }

  return success_response(trans_boc_b64.move_as_ok(), new_shard_account_boc_b64.move_as_ok(),
                          std::move(emulation_success.vm_log), std::move(actions_boc_b64),
                          emulation_success.elapsed_time);
} catch (const vm::VmError& e) {
  ERROR_RESPONSE(PSTRING() << "transaction_emulator_emulate_tick_tock_transaction: vm error: " << e.get_msg());
} catch (const std::exception& e) {
  ERROR_RESPONSE(PSTRING() << "transaction_emulator_emulate_tick_tock_transaction: " << e.what());
} catch (...) {
  ERROR_RESPONSE("transaction_emulator_emulate_tick_tock_transaction: unknown exception");
}

bool transaction_emulator_set_unixtime(void *transaction_emulator, uint32_t unixtime) {
  auto emulator = static_cast<emulator::TransactionEmulator *>(transaction_emulator);

  emulator->set_unixtime(unixtime);

  return true;
}

bool transaction_emulator_set_lt(void *transaction_emulator, uint64_t lt) {
  auto emulator = static_cast<emulator::TransactionEmulator *>(transaction_emulator);

  emulator->set_lt(lt);

  return true;
}

bool transaction_emulator_set_rand_seed(void *transaction_emulator, const char *rand_seed_hex) {
  auto emulator = static_cast<emulator::TransactionEmulator *>(transaction_emulator);

  auto rand_seed_hex_slice = td::Slice(rand_seed_hex);
  if (rand_seed_hex_slice.size() != 64) {
    LOG(ERROR) << "Rand seed expected as 64 characters hex string";
    return false;
  }
  auto rand_seed_bytes = td::hex_decode(rand_seed_hex_slice);
  if (rand_seed_bytes.is_error()) {
    LOG(ERROR) << "Can't decode hex rand seed";
    return false;
  }
  td::BitArray<256> rand_seed;
  rand_seed.as_slice().copy_from(rand_seed_bytes.move_as_ok());

  emulator->set_rand_seed(rand_seed);
  return true;
}

bool transaction_emulator_set_ignore_chksig(void *transaction_emulator, bool ignore_chksig) {
  auto emulator = static_cast<emulator::TransactionEmulator *>(transaction_emulator);

  emulator->set_ignore_chksig(ignore_chksig);

  return true;
}

bool transaction_emulator_set_config(void *transaction_emulator, const char *config_boc) {
  auto emulator = static_cast<emulator::TransactionEmulator *>(transaction_emulator);

  auto global_config_res = decode_config(config_boc);
  if (global_config_res.is_error()) {
    LOG(ERROR) << global_config_res.move_as_error().message();
    return false;
  }

  emulator->set_config(std::make_shared<block::Config>(global_config_res.move_as_ok()));

  return true;
}

void config_deleter(block::Config *ptr) {
  // We do not delete the config object, since ownership management is delegated to the caller
}

bool transaction_emulator_set_config_object(void *transaction_emulator, void *config) {
  auto emulator = static_cast<emulator::TransactionEmulator *>(transaction_emulator);

  std::shared_ptr<block::Config> config_ptr(static_cast<block::Config *>(config), config_deleter);

  emulator->set_config(config_ptr);

  return true;
}

bool transaction_emulator_set_libs(void *transaction_emulator, const char *shardchain_libs_boc) {
  auto emulator = static_cast<emulator::TransactionEmulator *>(transaction_emulator);

  if (shardchain_libs_boc != nullptr) {
    auto shardchain_libs_cell = boc_b64_to_cell(shardchain_libs_boc);
    if (shardchain_libs_cell.is_error()) {
      LOG(ERROR) << "Can't deserialize shardchain libraries boc: " << shardchain_libs_cell.move_as_error();
      return false;
    }
    emulator->set_libs(vm::Dictionary(shardchain_libs_cell.move_as_ok(), 256));
  }

  return true;
}

bool transaction_emulator_set_debug_enabled(void *transaction_emulator, bool debug_enabled) {
  auto emulator = static_cast<emulator::TransactionEmulator *>(transaction_emulator);

  emulator->set_debug_enabled(debug_enabled);

  return true;
}

bool transaction_emulator_set_prev_blocks_info(void *transaction_emulator, const char *info_boc) try {
  // Codex audit (round 14, finding #1): `vm::StackEntry::deserialize`
  // walks the caller-supplied cell and bare-loads it; a special root
  // throws across the C ABI. Wrap in function-try-block.
  auto emulator = static_cast<emulator::TransactionEmulator *>(transaction_emulator);

  if (info_boc != nullptr) {
    auto info_cell = boc_b64_to_cell(info_boc);
    if (info_cell.is_error()) {
      LOG(ERROR) << "Can't deserialize previous blocks boc: " << info_cell.move_as_error();
      return false;
    }
    vm::StackEntry info_value;
    if (!info_value.deserialize(info_cell.move_as_ok())) {
      LOG(ERROR) << "Can't deserialize previous blocks tuple";
      return false;
    }
    if (info_value.is_null()) {
      emulator->set_prev_blocks_info({});
    } else if (info_value.is_tuple()) {
      emulator->set_prev_blocks_info(info_value.as_tuple());
    } else {
      LOG(ERROR) << "Can't set previous blocks tuple: not a tuple";
      return false;
    }
  }

  return true;
} catch (...) {
  LOG(ERROR) << "transaction_emulator_set_prev_blocks_info: exception";
  return false;
}

void transaction_emulator_destroy(void *transaction_emulator) {
  delete static_cast<emulator::TransactionEmulator *>(transaction_emulator);
}

bool emulator_set_verbosity_level(int verbosity_level) {
  if (0 <= verbosity_level && verbosity_level <= VERBOSITY_NAME(NEVER)) {
    SET_VERBOSITY_LEVEL(VERBOSITY_NAME(FATAL) + verbosity_level);
    return true;
  }
  return false;
}

void *tvm_emulator_create(const char *code, const char *data, int vm_log_verbosity) {
  auto code_cell = boc_b64_to_cell(code);
  if (code_cell.is_error()) {
    LOG(ERROR) << "Can't deserialize code boc: " << code_cell.move_as_error();
    return nullptr;
  }
  auto data_cell = boc_b64_to_cell(data);
  if (data_cell.is_error()) {
    LOG(ERROR) << "Can't deserialize code boc: " << data_cell.move_as_error();
    return nullptr;
  }

  auto emulator = new emulator::TvmEmulator(code_cell.move_as_ok(), data_cell.move_as_ok());
  emulator->set_vm_verbosity_level(vm_log_verbosity);
  return emulator;
}

bool tvm_emulator_set_libraries(void *tvm_emulator, const char *libs_boc) {
  vm::Dictionary libs{256};
  auto libs_cell = boc_b64_to_cell(libs_boc);
  if (libs_cell.is_error()) {
    LOG(ERROR) << "Can't deserialize libraries boc: " << libs_cell.move_as_error();
    return false;
  }
  libs = vm::Dictionary(libs_cell.move_as_ok(), 256);

  auto emulator = static_cast<emulator::TvmEmulator *>(tvm_emulator);
  emulator->set_libraries(std::move(libs));

  return true;
}

bool tvm_emulator_set_c7(void *tvm_emulator, const char *address, uint32_t unixtime, uint64_t balance,
                         const char *rand_seed_hex, const char *config_boc) {
  auto emulator = static_cast<emulator::TvmEmulator *>(tvm_emulator);
  auto std_address = block::StdAddress::parse(td::Slice(address));
  if (std_address.is_error()) {
    LOG(ERROR) << "Can't parse address: " << std_address.move_as_error();
    return false;
  }

  std::shared_ptr<block::Config> global_config;
  if (config_boc != nullptr) {
    auto config_params_cell = boc_b64_to_cell(config_boc);
    if (config_params_cell.is_error()) {
      LOG(ERROR) << "Can't deserialize config params boc: " << config_params_cell.move_as_error();
      return false;
    }
    global_config = std::make_shared<block::Config>(
        config_params_cell.move_as_ok(), td::Bits256::zero(),
        block::Config::needWorkchainInfo | block::Config::needSpecialSmc | block::Config::needCapabilities);
    auto unpack_res = global_config->unpack();
    if (unpack_res.is_error()) {
      LOG(ERROR) << "Can't unpack config params";
      return false;
    }
  }

  auto rand_seed_hex_slice = td::Slice(rand_seed_hex);
  if (rand_seed_hex_slice.size() != 64) {
    LOG(ERROR) << "Rand seed expected as 64 characters hex string";
    return false;
  }
  auto rand_seed_bytes = td::hex_decode(rand_seed_hex_slice);
  if (rand_seed_bytes.is_error()) {
    LOG(ERROR) << "Can't decode hex rand seed";
    return false;
  }
  td::BitArray<256> rand_seed;
  rand_seed.as_slice().copy_from(rand_seed_bytes.move_as_ok());

  emulator->set_c7(std_address.move_as_ok(), unixtime, balance, rand_seed,
                   std::const_pointer_cast<const block::Config>(global_config));

  return true;
}

bool tvm_emulator_set_extra_currencies(void *tvm_emulator, const char *extra_currencies) {
  auto emulator = static_cast<emulator::TvmEmulator *>(tvm_emulator);
  vm::Dictionary dict{32};
  td::Slice extra_currencies_str{extra_currencies};
  while (true) {
    auto next_space_pos = extra_currencies_str.find(' ');
    auto currency_id_amount = next_space_pos == td::Slice::npos ? extra_currencies_str.substr(0)
                                                                : extra_currencies_str.substr(0, next_space_pos);

    if (!currency_id_amount.empty()) {
      auto delim_pos = currency_id_amount.find('=');
      if (delim_pos == td::Slice::npos) {
        LOG(ERROR) << "Invalid extra currency format, missing '='";
        return false;
      }

      auto currency_id_str = currency_id_amount.substr(0, delim_pos);
      auto amount_str = currency_id_amount.substr(delim_pos + 1);

      auto currency_id = td::to_integer_safe<uint32_t>(currency_id_str);
      if (currency_id.is_error()) {
        LOG(ERROR) << "Invalid extra currency id: " << currency_id_str;
        return false;
      }
      auto amount = td::dec_string_to_int256(amount_str);
      if (amount.is_null()) {
        LOG(ERROR) << "Invalid extra currency amount: " << amount_str;
        return false;
      }
      if (amount == 0) {
        continue;
      }
      if (amount < 0) {
        LOG(ERROR) << "Negative extra currency amount: " << amount_str;
        return false;
      }

      vm::CellBuilder cb;
      block::tlb::t_VarUInteger_32.store_integer_value(cb, *amount);
      if (!dict.set_builder(td::BitArray<32>(currency_id.ok()), cb, vm::DictionaryBase::SetMode::Add)) {
        LOG(ERROR) << "Duplicate extra currency id";
        return false;
      }
    }
    if (next_space_pos == td::Slice::npos) {
      break;
    }
    extra_currencies_str.remove_prefix(next_space_pos + 1);
  }
  emulator->set_extra_currencies(std::move(dict).extract_root_cell());
  return true;
}

bool tvm_emulator_set_config_object(void *tvm_emulator, void *config) {
  auto emulator = static_cast<emulator::TvmEmulator *>(tvm_emulator);
  auto global_config = std::shared_ptr<block::Config>(static_cast<block::Config *>(config), config_deleter);
  emulator->set_config(global_config);
  return true;
}

bool tvm_emulator_set_prev_blocks_info(void *tvm_emulator, const char *info_boc) try {
  // Codex audit (round 14, finding #1): see TransactionEmulator equivalent.
  auto emulator = static_cast<emulator::TvmEmulator *>(tvm_emulator);

  if (info_boc != nullptr) {
    auto info_cell = boc_b64_to_cell(info_boc);
    if (info_cell.is_error()) {
      LOG(ERROR) << "Can't deserialize previous blocks boc: " << info_cell.move_as_error();
      return false;
    }
    vm::StackEntry info_value;
    if (!info_value.deserialize(info_cell.move_as_ok())) {
      LOG(ERROR) << "Can't deserialize previous blocks tuple";
      return false;
    }
    if (info_value.is_null()) {
      emulator->set_prev_blocks_info({});
    } else if (info_value.is_tuple()) {
      emulator->set_prev_blocks_info(info_value.as_tuple());
    } else {
      LOG(ERROR) << "Can't set previous blocks tuple: not a tuple";
      return false;
    }
  }

  return true;
} catch (...) {
  LOG(ERROR) << "tvm_emulator_set_prev_blocks_info: exception";
  return false;
}

bool tvm_emulator_set_gas_limit(void *tvm_emulator, int64_t gas_limit) {
  auto emulator = static_cast<emulator::TvmEmulator *>(tvm_emulator);
  emulator->set_gas_limit(gas_limit);
  return true;
}

bool tvm_emulator_set_debug_enabled(void *tvm_emulator, bool debug_enabled) {
  auto emulator = static_cast<emulator::TvmEmulator *>(tvm_emulator);
  emulator->set_debug_enabled(debug_enabled);
  return true;
}

const char *tvm_emulator_run_get_method(void *tvm_emulator, int method_id, const char *stack_boc) try {
  // Codex audit (round 12, finding #3): bare `load_cell_slice` throws on
  // PrunedBranch / Library / Merkle*. The stack BoC is FFI-callee-supplied,
  // so anyone embedding the emulator could terminate the host process.
  // Wrap in a function-try-block and use the special-aware loader.
  auto stack_cell = boc_b64_to_cell(stack_boc);
  if (stack_cell.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Couldn't deserialize stack cell: " << stack_cell.move_as_error().to_string());
  }
  bool stack_special = false;
  auto stack_cs = vm::load_cell_slice_special(stack_cell.move_as_ok(), stack_special);
  if (stack_special) {
    ERROR_RESPONSE("stack BoC root is a special cell");
  }
  td::Ref<vm::Stack> stack;
  if (!vm::Stack::deserialize_to(stack_cs, stack)) {
    ERROR_RESPONSE(PSTRING() << "Couldn't deserialize stack");
  }

  auto emulator = static_cast<emulator::TvmEmulator *>(tvm_emulator);
  auto result = emulator->run_get_method(method_id, stack);

  vm::FakeVmStateLimits fstate(3500);  // limit recursive (de)serialization calls
  vm::VmStateInterface::Guard guard(&fstate);

  vm::CellBuilder stack_cb;
  if (!result.stack->serialize(stack_cb)) {
    ERROR_RESPONSE(PSTRING() << "Couldn't serialize stack");
  }
  auto result_stack_boc = cell_to_boc_b64(stack_cb.finalize());
  if (result_stack_boc.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Couldn't serialize stack cell: " << result_stack_boc.move_as_error().to_string());
  }

  td::JsonBuilder jb;
  auto json_obj = jb.enter_object();
  json_obj("success", td::JsonTrue());
  json_obj("stack", result_stack_boc.move_as_ok());
  json_obj("gas_used", std::to_string(result.gas_used));
  json_obj("vm_exit_code", result.code);
  json_obj("vm_log", result.vm_log);
  if (!result.missing_library) {
    json_obj("missing_library", td::JsonNull());
  } else {
    json_obj("missing_library", result.missing_library.value().to_hex());
  }
  json_obj.leave();

  return strdup(jb.string_builder().as_cslice().c_str());
} catch (const vm::VmError& e) {
  ERROR_RESPONSE(PSTRING() << "tvm_emulator_run_get_method: vm error: " << e.get_msg());
} catch (const std::exception& e) {
  ERROR_RESPONSE(PSTRING() << "tvm_emulator_run_get_method: " << e.what());
} catch (...) {
  ERROR_RESPONSE("tvm_emulator_run_get_method: unknown exception");
}

struct TvmEulatorEmulateRunMethodResponse {
  const char *response;
  const char *log;
};

TvmEulatorEmulateRunMethodResponse emulate_run_method(uint32_t len, const char *params_boc, int64_t gas_limit) try {
  // Codex audit (round 12, finding #3): the previous version called
  // `fetch_ref()` four times without checking ref counts and then
  // bare-loaded each ref with `load_cell_slice` (throws on special
  // cells). FFI input is callee-controlled, so a malformed BoC could
  // either deref a null Ref<Cell> or throw out of this entry point and
  // crash the embedding host. Wrap in function-try-block, validate ref
  // counts, and use the special-aware loader.
  auto params_cell = vm::std_boc_deserialize(td::Slice(params_boc, len));
  if (params_cell.is_error()) {
    return {nullptr, nullptr};
  }
  bool params_special = false;
  auto params_cs = vm::load_cell_slice_special(params_cell.move_as_ok(), params_special);
  if (params_special || params_cs.size_refs() < 4) {
    return {nullptr, nullptr};
  }
  auto code = params_cs.fetch_ref();
  auto data = params_cs.fetch_ref();

  bool stack_special = false;
  auto stack_cs = vm::load_cell_slice_special(params_cs.fetch_ref(), stack_special);
  if (stack_special) return {nullptr, nullptr};
  auto params_ref = params_cs.fetch_ref();
  bool params_inner_special = false;
  auto params = vm::load_cell_slice_special(params_ref, params_inner_special);
  if (params_inner_special || params.size_refs() < 2) return {nullptr, nullptr};
  bool c7_special = false;
  auto c7_cs = vm::load_cell_slice_special(params.fetch_ref(), c7_special);
  if (c7_special) return {nullptr, nullptr};
  auto libs = vm::Dictionary(params.fetch_ref(), 256);

  // Codex audit (round 14, finding #3): method_id is fetched from
  // attacker-controlled bytes; without `have(32)` the underlying
  // `fetch_long(32)` returns an EOF sentinel that gets cast to int and
  // executed as a method id. Reject early on truncated request.
  if (!params_cs.have(32)) {
    return {nullptr, nullptr};
  }
  auto method_id = params_cs.fetch_long(32);

  td::Ref<vm::Stack> stack;
  if (!vm::Stack::deserialize_to(stack_cs, stack)) {
    return {nullptr, nullptr};
  }

  td::Ref<vm::Stack> c7;
  if (!vm::Stack::deserialize_to(c7_cs, c7)) {
    return {nullptr, nullptr};
  }
  // Codex audit (round 13, finding #2): the previous version called
  // `c7->fetch(0).as_tuple()` without checking that c7 actually has any
  // elements, and without verifying the top entry is a tuple. An attacker
  // supplying valid stack BoC bytes that decode to an empty C7 (depth=0)
  // hits underflow before the function-try-block can intercept.
  if (c7->depth() != 1) {
    return {nullptr, nullptr};
  }
  auto c7_tuple = c7->fetch(0).as_tuple();
  if (c7_tuple.is_null()) {
    return {nullptr, nullptr};
  }

  auto emulator = new emulator::TvmEmulator(code, data);
  emulator->set_vm_verbosity_level(0);
  emulator->set_gas_limit(gas_limit);
  emulator->set_c7_raw(std::move(c7_tuple));
  if (!libs.is_empty()) {
    emulator->set_libraries(std::move(libs));
  }
  auto result = emulator->run_get_method(int(method_id), stack);
  delete emulator;

  vm::CellBuilder stack_cb;
  if (!result.stack->serialize(stack_cb)) {
    return {nullptr, nullptr};
  }

  vm::CellBuilder cb;
  cb.store_long(result.code, 32);
  cb.store_long(result.gas_used, 64);
  cb.store_ref(stack_cb.finalize());

  auto ser = vm::std_boc_serialize(cb.finalize());
  if (!ser.is_ok()) {
    return {nullptr, nullptr};
  }
  auto sok = ser.move_as_ok();

  auto sz = uint32_t(sok.size());
  char *rn = (char *)malloc(sz + 4);
  memcpy(rn, &sz, 4);
  memcpy(rn + 4, sok.data(), sz);

  return {rn, strdup(result.vm_log.data())};
} catch (...) {
  return {nullptr, nullptr};
}

const char *tvm_emulator_emulate_run_method(uint32_t len, const char *params_boc, int64_t gas_limit) {
  auto result = emulate_run_method(len, params_boc, gas_limit);
  return result.response;
}

void *tvm_emulator_emulate_run_method_detailed(uint32_t len, const char *params_boc, int64_t gas_limit) {
  auto result = emulate_run_method(len, params_boc, gas_limit);
  return new TvmEulatorEmulateRunMethodResponse(result);
}

void run_method_detailed_result_destroy(void *detailed_result) {
  auto result = static_cast<TvmEulatorEmulateRunMethodResponse *>(detailed_result);
  free(const_cast<char *>(result->response));
  free(const_cast<char *>(result->log));
  delete result;
}

const char *tvm_emulator_send_external_message(void *tvm_emulator, const char *message_body_boc) try {
  // Codex audit (round 14, finding #2): SmartContract::send_external_message
  // bare-loads the body cell — a special root throws across the C ABI
  // and terminates the embedding host. Wrap in function-try-block AND
  // reject special roots before the call. Also defensively handle any
  // throw from the cell_to_boc_b64 .move_as_ok() chain below.
  auto message_body_cell = boc_b64_to_cell(message_body_boc);
  if (message_body_cell.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Can't deserialize message body boc: " << message_body_cell.move_as_error());
  }
  auto body_cell = message_body_cell.move_as_ok();
  bool body_special = false;
  (void)vm::load_cell_slice_special(body_cell, body_special);
  if (body_special) {
    ERROR_RESPONSE("message body root is a special cell");
  }

  auto emulator = static_cast<emulator::TvmEmulator *>(tvm_emulator);
  auto result = emulator->send_external_message(std::move(body_cell));

  td::JsonBuilder jb;
  auto json_obj = jb.enter_object();
  json_obj("success", td::JsonTrue());
  json_obj("gas_used", std::to_string(result.gas_used));
  json_obj("vm_exit_code", result.code);
  json_obj("accepted", td::JsonBool(result.accepted));
  json_obj("vm_log", result.vm_log);
  if (!result.missing_library) {
    json_obj("missing_library", td::JsonNull());
  } else {
    json_obj("missing_library", result.missing_library.value().to_hex());
  }
  if (result.actions.is_null()) {
    json_obj("actions", td::JsonNull());
  } else {
    json_obj("actions", cell_to_boc_b64(result.actions).move_as_ok());
  }
  json_obj("new_code", cell_to_boc_b64(result.new_state.code).move_as_ok());
  json_obj("new_data", cell_to_boc_b64(result.new_state.data).move_as_ok());
  json_obj.leave();

  return strdup(jb.string_builder().as_cslice().c_str());
} catch (const vm::VmError& e) {
  ERROR_RESPONSE(PSTRING() << "tvm_emulator_send_external_message: vm error: " << e.get_msg());
} catch (const std::exception& e) {
  ERROR_RESPONSE(PSTRING() << "tvm_emulator_send_external_message: " << e.what());
} catch (...) {
  ERROR_RESPONSE("tvm_emulator_send_external_message: unknown exception");
}

const char *tvm_emulator_send_internal_message(void *tvm_emulator, const char *message_body_boc, uint64_t amount) try {
  // Codex audit (round 14, finding #2): same hardening as
  // tvm_emulator_send_external_message above.
  auto message_body_cell = boc_b64_to_cell(message_body_boc);
  if (message_body_cell.is_error()) {
    ERROR_RESPONSE(PSTRING() << "Can't deserialize message body boc: " << message_body_cell.move_as_error());
  }
  auto body_cell = message_body_cell.move_as_ok();
  bool body_special = false;
  (void)vm::load_cell_slice_special(body_cell, body_special);
  if (body_special) {
    ERROR_RESPONSE("message body root is a special cell");
  }

  auto emulator = static_cast<emulator::TvmEmulator *>(tvm_emulator);
  auto result = emulator->send_internal_message(std::move(body_cell), amount);

  td::JsonBuilder jb;
  auto json_obj = jb.enter_object();
  json_obj("success", td::JsonTrue());
  json_obj("gas_used", std::to_string(result.gas_used));
  json_obj("vm_exit_code", result.code);
  json_obj("accepted", td::JsonBool(result.accepted));
  json_obj("vm_log", result.vm_log);
  if (!result.missing_library) {
    json_obj("missing_library", td::JsonNull());
  } else {
    json_obj("missing_library", result.missing_library.value().to_hex());
  }
  if (result.actions.is_null()) {
    json_obj("actions", td::JsonNull());
  } else {
    json_obj("actions", cell_to_boc_b64(result.actions).move_as_ok());
  }
  json_obj("new_code", cell_to_boc_b64(result.new_state.code).move_as_ok());
  json_obj("new_data", cell_to_boc_b64(result.new_state.data).move_as_ok());
  json_obj.leave();

  return strdup(jb.string_builder().as_cslice().c_str());
} catch (const vm::VmError& e) {
  ERROR_RESPONSE(PSTRING() << "tvm_emulator_send_internal_message: vm error: " << e.get_msg());
} catch (const std::exception& e) {
  ERROR_RESPONSE(PSTRING() << "tvm_emulator_send_internal_message: " << e.what());
} catch (...) {
  ERROR_RESPONSE("tvm_emulator_send_internal_message: unknown exception");
}

void tvm_emulator_destroy(void *tvm_emulator) {
  delete static_cast<emulator::TvmEmulator *>(tvm_emulator);
}

void emulator_config_destroy(void *config) {
  delete static_cast<block::Config *>(config);
}

void string_destroy(const char *str) {
  if (str != nullptr) {
    free(const_cast<char *>(str));
  }
}

const char *emulator_version() {
  auto version_json = td::JsonBuilder();
  auto obj = version_json.enter_object();
  obj("emulatorLibCommitHash", GitMetadata::CommitSHA1());
  obj("emulatorLibCommitDate", GitMetadata::CommitDate());
  obj.leave();
  return strdup(version_json.string_builder().as_cslice().c_str());
}
