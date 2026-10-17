/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The JSON-RPC estimateFee answers in_fwd_fee, the fee for importing the external
// message. It must be the fee the executor charges for the message sendQuery submits
// for the same request, with and without a StateInit, for a wallet that is not yet
// deployed, one that is active and one that is frozen. Each case runs the handler's
// own answer function on the account state the handler reads, and holds its import
// fee to block::transaction::Transaction's import of the submitted message. A
// request the executor would reject is refused, not priced.
//
// The forwarding prices are the TOS genesis ones, read from
// crypto/smartcont/gen-zerostate.fif; every other parameter is the shared fixture
// config at the TOS genesis global version. No fee is written down here: both sides
// are priced from the same config.

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "block/transaction.h"
#include "block/workchain-execution-dispatch.h"
#include "emulator/test/tos-genesis-config.h"
#include "smc-envelope/GenericAccount.h"
#include "smc-envelope/SmartContractCode.h"
#include "td/utils/base64.h"
#include "td/utils/misc.h"
#include "td/utils/tests.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

#include "json-rpc-server-fee.h"
#include "json-rpc-server-internal.h"

namespace {

constexpr tos::UnixTime kNow = 1'750'000'000;
constexpr tos::LogicalTime kLt = 1'000'000;
constexpr td::int64 kWalletBalance = 10'000'000'000LL;

struct ForwardPrices {
  td::uint64 lump = 0;
  td::uint64 bit = 0;
  td::uint64 cell = 0;
};

// The first three numbers of the genesis line that ends in `setter` (for example
// "config.fwd_prices!"): lump_price, bit_price and cell_price.
ForwardPrices genesis_forward_prices(const std::string& setter) {
  std::ifstream in(TOS_GENESIS_ZEROSTATE_FIF);
  CHECK(in.good());
  std::string line;
  std::vector<ForwardPrices> found;
  while (std::getline(in, line)) {
    auto trimmed = td::trim(td::Slice(line)).str();
    if (td::begins_with(trimmed, "//") || !td::ends_with(trimmed, " " + setter)) {
      continue;
    }
    std::istringstream words(trimmed);
    ForwardPrices prices;
    CHECK(words >> prices.lump >> prices.bit >> prices.cell);
    found.push_back(prices);
  }
  CHECK(found.size() == 1);
  return found[0];
}

td::Ref<vm::Cell> with_prices(td::Ref<vm::Cell> param, const ForwardPrices& prices) {
  block::gen::MsgForwardPrices::Record rec;
  CHECK(param.not_null() && tlb::unpack_cell(std::move(param), rec));
  rec.lump_price = prices.lump;
  rec.bit_price = prices.bit;
  rec.cell_price = prices.cell;
  td::Ref<vm::Cell> out;
  CHECK(tlb::pack_cell(out, rec));
  return out;
}

const ForwardPrices& basechain_prices() {
  static const ForwardPrices prices = genesis_forward_prices("config.fwd_prices!");
  return prices;
}

const ForwardPrices& masterchain_prices() {
  static const ForwardPrices prices = genesis_forward_prices("config.mc_fwd_prices!");
  return prices;
}

// The shared fixture config at the genesis global version, with ConfigParam 24
// and 25 carrying the genesis forwarding prices.
std::shared_ptr<const block::Config> genesis_priced_config() {
  static std::shared_ptr<const block::Config> cfg = [] {
    auto decoded = td::base64_decode(td::Slice(fee_fixture::tos_versioned_config_boc()));
    CHECK(decoded.is_ok());
    auto root = vm::std_boc_deserialize(decoded.move_as_ok());
    CHECK(root.is_ok());
    vm::Dictionary params{root.move_as_ok(), 32};
    for (auto [index, prices] : {std::pair<int, const ForwardPrices*>{24, &masterchain_prices()},
                                 std::pair<int, const ForwardPrices*>{25, &basechain_prices()}}) {
      td::BitArray<32> key;
      key.store_ulong(index);
      CHECK(params.set_ref(key, with_prices(params.lookup_ref(key), *prices)));
    }
    auto boc = vm::std_boc_serialize(params.get_root_cell());
    CHECK(boc.is_ok());
    auto encoded = td::base64_encode(boc.move_as_ok());
    auto raw = static_cast<block::Config*>(emulator_config_create(encoded.c_str()));
    CHECK(raw != nullptr);
    return std::shared_ptr<const block::Config>(raw);
  }();
  return cfg;
}

struct Wallet {
  td::Ref<vm::Cell> code;
  td::Ref<vm::Cell> data;
  block::StdAddress address;
};

// A wallet with the WalletV4 code and a fresh data cell (seqno, wallet id, public
// key, no plugins), at the basechain address its StateInit determines.
Wallet make_wallet() {
  Wallet wallet;
  wallet.code = tos::SmartContractCode::get_code(tos::SmartContractCode::WalletV4);
  CHECK(wallet.code.not_null());
  vm::CellBuilder data;
  CHECK(data.store_long_bool(0, 32) && data.store_long_bool(698983191, 32));
  for (int i = 0; i < 32; i++) {
    CHECK(data.store_long_bool(0x5a, 8));
  }
  CHECK(data.store_zeroes_bool(1));
  wallet.data = data.finalize();
  auto init_state = tos::GenericAccount::get_init_state(wallet.code, wallet.data);
  CHECK(init_state.not_null());
  wallet.address = tos::GenericAccount::get_address(tos::basechainId, init_state);
  return wallet;
}

// A signed-transfer-shaped body: a signature, the signing header and one outbound
// internal message by reference, so the import fee counts a body with a child.
td::Ref<vm::Cell> make_transfer_body(const block::StdAddress& to) {
  vm::CellBuilder message;
  CHECK(tos::GenericAccount::store_int_message(message, to, 1'000'000'000LL, {}));
  CHECK(message.store_zeroes_bool(1 + 1));  // no init, inline empty body
  vm::CellBuilder body;
  for (int i = 0; i < 64; i++) {
    CHECK(body.store_long_bool(0xa5, 8));  // signature
  }
  CHECK(body.store_long_bool(2, 32) && body.store_long_bool(698983191, 32) && body.store_long_bool(kNow + 60, 32) &&
        body.store_long_bool(7, 32) && body.store_long_bool(0, 8) && body.store_long_bool(3, 8) &&
        body.store_ref_bool(message.finalize()));
  return body.finalize();
}

struct Executed {
  td::RefInt256 import_fee;
  // The compute phase's skip reason: sk_none when it runs the message.
  int skip_reason = block::ComputePhase::sk_none;
};

// What the executor does with `message` for `account`: the import fee it charges,
// and whether its compute phase runs the message or skips it.
Executed execute(const block::Account& account, td::Ref<vm::Cell> message) {
  auto cfg = genesis_priced_config();
  td::Ref<vm::Cell> old_mparams;
  std::vector<block::StoragePrices> storage_prices;
  block::StoragePhaseConfig storage_cfg{&storage_prices};
  td::BitArray<256> rand_seed;
  rand_seed.set_zero();
  rand_seed.as_slice().ubegin()[0] = 1;
  block::ComputePhaseConfig compute_cfg;
  block::ActionPhaseConfig action_cfg;
  block::SerializeConfig serialize_cfg;
  td::RefInt256 masterchain_create_fee, basechain_create_fee;
  block::FetchConfigParams::fetch_config_params(*cfg, td::Ref<vm::Tuple>{}, &old_mparams, &storage_prices, &storage_cfg,
                                                &rand_seed, &compute_cfg, &action_cfg, &serialize_cfg,
                                                &masterchain_create_fee, &basechain_create_fee, account.workchain, kNow)
      .ensure();
  compute_cfg.libraries = std::make_unique<vm::Dictionary>(256);
  block::transaction::Transaction trans(account, block::transaction::Transaction::tr_ord, kLt, kNow,
                                        std::move(message));
  CHECK(trans.unpack_input_msg(/*ihr_delivered=*/false, &action_cfg));
  CHECK(trans.in_fwd_fee.not_null());
  Executed executed;
  executed.import_fee = trans.in_fwd_fee;
  CHECK(trans.prepare_storage_phase(storage_cfg, /*force_collect=*/true));
  CHECK(trans.prepare_compute_phase(compute_cfg));
  CHECK(trans.compute_phase != nullptr);
  executed.skip_reason = trans.compute_phase->skip_reason;
  return executed;
}

td::RefInt256 executed_import_fee(const block::Account& account, td::Ref<vm::Cell> message) {
  return execute(account, std::move(message)).import_fee;
}

block::Account undeployed_account(const Wallet& wallet) {
  block::Account account(wallet.address.workchain, wallet.address.addr.cbits());
  CHECK(account.init_new(kNow));
  account.balance = block::CurrencyCollection(kWalletBalance);
  return account;
}

block::Account active_account(const Wallet& wallet) {
  auto account = undeployed_account(wallet);
  account.status = account.orig_status = block::Account::acc_active;
  account.code = wallet.code;
  account.data = wallet.data;
  return account;
}

td::Bits256 state_init_hash(const Wallet& wallet) {
  return tos::GenericAccount::get_init_state(wallet.code, wallet.data)->get_hash().bits();
}

block::Account frozen_account(const Wallet& wallet) {
  auto account = undeployed_account(wallet);
  account.status = account.orig_status = block::Account::acc_frozen;
  account.state_hash = state_init_hash(wallet);
  return account;
}

// The account state the handler reads from the liteserver, in the same shapes
// ParsedAccountState::parse produces for an active, a frozen and an
// uninitialized account.
tos::ParsedAccountState parsed_state(const Wallet& wallet, int status) {
  tos::ParsedAccountState parsed;
  parsed.balance = kWalletBalance;
  parsed.balance_dec = std::to_string(kWalletBalance);
  parsed.sync_utime = kNow;
  parsed.storage_last_paid = kNow;
  if (status == block::Account::acc_active) {
    parsed.state_str = "active";
    parsed.code_cell = wallet.code;
    parsed.data_cell = wallet.data;
  } else if (status == block::Account::acc_frozen) {
    parsed.state_str = "frozen";
    parsed.frozen_hash = td::base64_encode(state_init_hash(wallet).as_slice());
  }
  return parsed;
}

// The handler's answer for a request carrying `init_code`/`init_data` (null when
// the request leaves them out) against `account`.
td::Result<std::string> handler_answer(const Wallet& wallet, const block::Account& account, td::Ref<vm::Cell> body,
                                       td::Ref<vm::Cell> init_code, td::Ref<vm::Cell> init_data) {
  tos::EstimateFeeRequest request{wallet.address, std::move(body), std::move(init_code), std::move(init_data), true};
  return tos::estimate_external_message_fees(request, parsed_state(wallet, account.status), genesis_priced_config(),
                                             td::Ref<vm::Cell>{}, td::Ref<vm::Tuple>{});
}

td::int64 answered_import_fee(const std::string& answer) {
  const std::string key = "\"in_fwd_fee\":";
  auto at = answer.find(key);
  CHECK(at != std::string::npos);
  auto end = answer.find(',', at);
  CHECK(end != std::string::npos);
  auto fee = td::to_integer_safe<td::int64>(td::Slice(answer).substr(at + key.size(), end - at - key.size()));
  CHECK(fee.is_ok());
  return fee.ok();
}

// The message sendQuery submits for the same request.
td::Ref<vm::Cell> submitted_message(const Wallet& wallet, td::Ref<vm::Cell> body, td::Ref<vm::Cell> init_code,
                                    td::Ref<vm::Cell> init_data) {
  auto message = tos::build_query_external_message(wallet.address, init_code, init_data, std::move(body));
  CHECK(message.is_ok());
  return message.move_as_ok();
}

const char* status_name(int status) {
  switch (status) {
    case block::Account::acc_active:
      return "active";
    case block::Account::acc_frozen:
      return "frozen";
    default:
      return "undeployed";
  }
}

void expect_estimate_matches_execution(const Wallet& wallet, const block::Account& account, bool with_state_init) {
  auto body = make_transfer_body(wallet.address);
  auto init_code = with_state_init ? wallet.code : td::Ref<vm::Cell>{};
  auto init_data = with_state_init ? wallet.data : td::Ref<vm::Cell>{};
  auto answer = handler_answer(wallet, account, body, init_code, init_data);
  if (answer.is_error()) {
    LOG(ERROR) << answer.error();
  }
  ASSERT_TRUE(answer.is_ok());
  auto estimated = answered_import_fee(answer.ok());
  auto executed = execute(account, submitted_message(wallet, body, init_code, init_data));
  LOG(INFO) << "import fee: estimated " << estimated << ", executed " << executed.import_fee
            << (with_state_init ? " (with StateInit)" : " (without StateInit)") << ", " << status_name(account.status)
            << " wallet";
  ASSERT_TRUE(td::cmp(executed.import_fee, td::make_refint(estimated)) == 0);
  // And the executor does run this message.
  ASSERT_EQ(static_cast<int>(block::ComputePhase::sk_none), executed.skip_reason);
}

// The estimate refuses the request, and the executor's compute phase skips the
// message for want of a usable state.
void expect_refused_as_the_executor_skips(const Wallet& wallet, const block::Account& account,
                                          td::Ref<vm::Cell> init_code, td::Ref<vm::Cell> init_data, td::Slice text) {
  auto body = make_transfer_body(wallet.address);
  auto answer = handler_answer(wallet, account, body, init_code, init_data);
  ASSERT_TRUE(answer.is_error());
  ASSERT_EQ(tos::kEstimateRejectedCode, answer.error().code());
  ASSERT_TRUE(answer.error().message().str().find(text.str()) != std::string::npos);
  auto executed = execute(account, submitted_message(wallet, body, init_code, init_data));
  ASSERT_TRUE(executed.skip_reason == block::ComputePhase::sk_bad_state ||
              executed.skip_reason == block::ComputePhase::sk_no_state);
}

// A wallet whose StateInit is not the one `wallet` is deployed with.
Wallet other_wallet(const Wallet& wallet) {
  Wallet other = wallet;
  vm::CellBuilder data;
  CHECK(data.store_long_bool(1, 32) && data.store_long_bool(1, 32) && data.store_zeroes_bool(256 + 1));
  other.data = data.finalize();
  return other;
}

}  // namespace

TEST(JsonRpcImportFee, the_config_carries_the_genesis_forwarding_prices) {
  auto cfg = genesis_priced_config();
  auto basechain = cfg->get_msg_prices(false).move_as_ok();
  auto masterchain = cfg->get_msg_prices(true).move_as_ok();
  ASSERT_EQ(basechain.lump_price, basechain_prices().lump);
  ASSERT_EQ(basechain.bit_price, basechain_prices().bit);
  ASSERT_EQ(basechain.cell_price, basechain_prices().cell);
  ASSERT_EQ(masterchain.lump_price, masterchain_prices().lump);
  ASSERT_EQ(masterchain.cell_price, masterchain_prices().cell);
}

TEST(JsonRpcImportFee, deploying_an_undeployed_wallet_prices_its_state_init) {
  auto wallet = make_wallet();
  expect_estimate_matches_execution(wallet, undeployed_account(wallet), /*with_state_init=*/true);
}

TEST(JsonRpcImportFee, an_active_wallet_send_without_state_init_is_priced_without_one) {
  auto wallet = make_wallet();
  expect_estimate_matches_execution(wallet, active_account(wallet), /*with_state_init=*/false);
}

TEST(JsonRpcImportFee, a_state_init_sent_to_an_active_wallet_is_still_priced) {
  // The executor ignores the StateInit of an active account but still charges
  // for importing it, so an estimate for such a request must price it too.
  auto wallet = make_wallet();
  expect_estimate_matches_execution(wallet, active_account(wallet), /*with_state_init=*/true);
}

TEST(JsonRpcImportFee, unfreezing_a_frozen_wallet_prices_its_state_init) {
  auto wallet = make_wallet();
  expect_estimate_matches_execution(wallet, frozen_account(wallet), /*with_state_init=*/true);
}

TEST(JsonRpcImportFee, a_state_init_raises_the_import_fee) {
  auto wallet = make_wallet();
  auto body = make_transfer_body(wallet.address);
  auto account = active_account(wallet);
  auto without = handler_answer(wallet, account, body, {}, {});
  auto with = handler_answer(wallet, account, body, wallet.code, wallet.data);
  ASSERT_TRUE(without.is_ok() && with.is_ok());
  ASSERT_TRUE(answered_import_fee(with.ok()) > answered_import_fee(without.ok()));
}

// Each request the executor's compute phase skips as having no usable state is
// refused, rather than answered with a fee for a message that never executes.
TEST(JsonRpcImportFee, requests_the_executor_rejects_are_refused) {
  auto wallet = make_wallet();
  auto other = other_wallet(wallet);
  // An active account and a StateInit that is not its own.
  expect_refused_as_the_executor_skips(wallet, active_account(wallet), other.code, other.data,
                                       "does not hash to the address of this active account");
  // An undeployed account: no StateInit, or one for another address.
  expect_refused_as_the_executor_skips(wallet, undeployed_account(wallet), {}, {}, "not deployed");
  expect_refused_as_the_executor_skips(wallet, undeployed_account(wallet), other.code, other.data,
                                       "cannot deploy this account");
  // A frozen account: no StateInit, or one it was not frozen with.
  expect_refused_as_the_executor_skips(wallet, frozen_account(wallet), {}, {}, "frozen");
  expect_refused_as_the_executor_skips(wallet, frozen_account(wallet), other.code, other.data, "cannot unfreeze it");
  // A StateInit without code for an undeployed account leaves nothing to run.
  auto body = make_transfer_body(wallet.address);
  auto no_code = handler_answer(wallet, undeployed_account(wallet), body, {}, wallet.data);
  ASSERT_TRUE(no_code.is_error());
  ASSERT_EQ(tos::kEstimateRejectedCode, no_code.error().code());
}

TEST(JsonRpcImportFee, the_estimate_runs_the_code_the_executor_runs) {
  auto wallet = make_wallet();
  auto body = make_transfer_body(wallet.address);
  // The handler reads an active account's code and data from its state.
  auto active = tos::estimate_account_from(parsed_state(wallet, block::Account::acc_active));
  ASSERT_TRUE(active.is_ok());
  ASSERT_TRUE(active.ok().status == tos::EstimateAccount::Status::Active);
  ASSERT_TRUE(active.ok().code->get_hash() == wallet.code->get_hash());
  ASSERT_TRUE(active.ok().data->get_hash() == wallet.data->get_hash());
  // An active account runs its own code, with or without its own StateInit.
  for (bool with_state_init : {false, true}) {
    auto plan =
        tos::plan_external_message_estimate(wallet.address, body, with_state_init ? wallet.code : td::Ref<vm::Cell>{},
                                            with_state_init ? wallet.data : td::Ref<vm::Cell>{}, active.ok());
    ASSERT_TRUE(plan.is_ok());
    ASSERT_TRUE(plan.ok().code->get_hash() == wallet.code->get_hash());
  }
  // An undeployed or frozen one runs the request's.
  auto frozen = tos::estimate_account_from(parsed_state(wallet, block::Account::acc_frozen));
  ASSERT_TRUE(frozen.is_ok());
  ASSERT_TRUE(frozen.ok().status == tos::EstimateAccount::Status::Frozen);
  ASSERT_TRUE(frozen.ok().frozen_state_hash == state_init_hash(wallet));
  auto undeployed = tos::estimate_account_from(parsed_state(wallet, block::Account::acc_uninit));
  ASSERT_TRUE(undeployed.is_ok());
  ASSERT_TRUE(undeployed.ok().status == tos::EstimateAccount::Status::Uninitialized);
  for (const auto& account : {frozen.ok(), undeployed.ok()}) {
    auto plan = tos::plan_external_message_estimate(wallet.address, body, wallet.code, wallet.data, account);
    ASSERT_TRUE(plan.is_ok());
    ASSERT_TRUE(plan.ok().code->get_hash() == wallet.code->get_hash());
    ASSERT_TRUE(plan.ok().data->get_hash() == wallet.data->get_hash());
  }
}

// The executor charges a special account nothing for importing a message.
TEST(JsonRpcImportFee, a_special_account_imports_for_free) {
  auto cfg = genesis_priced_config();
  auto special = cfg->get_special_smartcontracts(false);
  ASSERT_TRUE(special.is_ok() && !special.ok().empty());
  auto wallet = make_wallet();
  wallet.address = block::StdAddress(tos::masterchainId, special.ok().front());
  auto body = make_transfer_body(wallet.address);
  auto account = active_account(wallet);
  account.is_special = true;
  auto answer = handler_answer(wallet, account, body, {}, {});
  ASSERT_TRUE(answer.is_ok());
  auto executed = executed_import_fee(account, submitted_message(wallet, body, {}, {}));
  ASSERT_TRUE(td::sgn(executed) == 0);
  ASSERT_EQ(0, answered_import_fee(answer.ok()));

  // An ordinary masterchain account pays.
  td::Bits256 ordinary;
  ordinary.as_slice().fill(0x77);
  wallet.address = block::StdAddress(tos::masterchainId, ordinary);
  auto ordinary_account = active_account(wallet);
  auto ordinary_answer = handler_answer(wallet, ordinary_account, body, {}, {});
  ASSERT_TRUE(ordinary_answer.is_ok());
  auto ordinary_executed = executed_import_fee(ordinary_account, submitted_message(wallet, body, {}, {}));
  ASSERT_TRUE(td::sgn(ordinary_executed) > 0);
  ASSERT_TRUE(td::cmp(ordinary_executed, td::make_refint(answered_import_fee(ordinary_answer.ok()))) == 0);
}

// A workchain with its own compute phase is charged no import fee and does not
// run TVM, so the estimate refuses it instead of quoting a TVM price.
TEST(JsonRpcImportFee, a_workchain_with_a_custom_compute_phase_is_refused) {
  auto workchain = [](int id, bool basic, td::int32 vm_version, td::uint32 type_id) {
    auto info = td::make_ref<block::WorkchainInfo>();
    info.write().workchain = id;
    info.write().enabled_since = 0;
    info.write().active = true;
    info.write().accept_msgs = true;
    info.write().basic = basic;
    info.write().vm_version = vm_version;
    info.write().workchain_type_id = type_id;
    return info;
  };
  auto tvm = block::tvm_workchain_engine_key();
  block::WorkchainSet workchains;
  workchains[2] = workchain(2, false, 0, 7);
  workchains[3] = workchain(3, true, static_cast<td::int32>(tvm.selector), 0);
  auto refused = tos::check_estimate_workchain(workchains, 2);
  ASSERT_TRUE(refused.is_error());
  ASSERT_EQ(tos::kEstimateUnsupportedCode, refused.code());
  ASSERT_TRUE(tos::check_estimate_workchain(workchains, 3).is_ok());
  ASSERT_TRUE(tos::check_estimate_workchain(workchains, tos::basechainId).is_ok());
  ASSERT_TRUE(tos::check_estimate_workchain(workchains, tos::masterchainId).is_ok());
}

TEST(JsonRpcImportFee, a_message_that_is_not_an_inbound_external_is_refused) {
  auto wallet = make_wallet();
  vm::CellBuilder internal;
  CHECK(tos::GenericAccount::store_int_message(internal, wallet.address, 1, {}));
  CHECK(internal.store_zeroes_bool(2));
  auto prices = genesis_priced_config()->get_msg_prices(false).move_as_ok();
  ASSERT_TRUE(tos::external_message_import_fee(internal.finalize(), prices, false).is_error());
  ASSERT_TRUE(tos::external_message_import_fee({}, prices, false).is_error());
}
