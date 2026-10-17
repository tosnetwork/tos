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
// deployed and for one that is active. Each case below plans the estimate exactly as
// the handler does and holds its import fee to block::transaction::Transaction's
// import of the submitted message.
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
#include "emulator/test/tos-genesis-config.h"
#include "smc-envelope/GenericAccount.h"
#include "smc-envelope/SmartContractCode.h"
#include "td/utils/misc.h"
#include "td/utils/tests.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

#include "json-rpc-server-fee.h"

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

// What the executor charges for importing `message` into `account`.
td::RefInt256 executed_import_fee(const block::Account& account, td::Ref<vm::Cell> message) {
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
  block::transaction::Transaction trans(account, block::transaction::Transaction::tr_ord, kLt, kNow,
                                        std::move(message));
  CHECK(trans.unpack_input_msg(/*ihr_delivered=*/false, &action_cfg));
  CHECK(trans.in_fwd_fee.not_null());
  return trans.in_fwd_fee;
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

// estimateFee's in_fwd_fee for a request carrying `init_code`/`init_data` (null when
// the request leaves them out) against an account in the given state.
td::int64 estimated_import_fee(const Wallet& wallet, td::Ref<vm::Cell> body, td::Ref<vm::Cell> init_code,
                               td::Ref<vm::Cell> init_data, bool account_active) {
  auto plan = tos::plan_external_message_estimate(wallet.address, std::move(body), init_code, init_data, account_active,
                                                  account_active ? wallet.code : td::Ref<vm::Cell>{},
                                                  account_active ? wallet.data : td::Ref<vm::Cell>{});
  CHECK(plan.is_ok());
  auto prices = genesis_priced_config()->get_msg_prices(wallet.address.workchain == tos::masterchainId);
  CHECK(prices.is_ok());
  auto fee = tos::external_message_import_fee(plan.ok().message, prices.ok());
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

void expect_estimate_matches_execution(const Wallet& wallet, const block::Account& account, bool with_state_init) {
  auto body = make_transfer_body(wallet.address);
  auto init_code = with_state_init ? wallet.code : td::Ref<vm::Cell>{};
  auto init_data = with_state_init ? wallet.data : td::Ref<vm::Cell>{};
  bool active = account.status == block::Account::acc_active;
  auto estimated = estimated_import_fee(wallet, body, init_code, init_data, active);
  auto executed = executed_import_fee(account, submitted_message(wallet, body, init_code, init_data));
  LOG(INFO) << "import fee: estimated " << estimated << ", executed " << executed
            << (with_state_init ? " (with StateInit)" : " (without StateInit)")
            << (active ? ", active wallet" : ", undeployed wallet");
  ASSERT_TRUE(td::cmp(executed, td::make_refint(estimated)) == 0);
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

TEST(JsonRpcImportFee, a_state_init_raises_the_import_fee) {
  auto wallet = make_wallet();
  auto body = make_transfer_body(wallet.address);
  auto without = estimated_import_fee(wallet, body, {}, {}, /*account_active=*/true);
  auto with = estimated_import_fee(wallet, body, wallet.code, wallet.data, /*account_active=*/true);
  ASSERT_TRUE(with > without);
}

TEST(JsonRpcImportFee, the_estimate_runs_the_code_the_executor_runs) {
  auto wallet = make_wallet();
  auto body = make_transfer_body(wallet.address);
  vm::CellBuilder other;
  CHECK(other.store_long_bool(0xdead, 16));
  auto other_code = other.finalize();
  // An active account runs its own code whatever StateInit the request carries.
  auto active =
      tos::plan_external_message_estimate(wallet.address, body, other_code, {}, true, wallet.code, wallet.data);
  ASSERT_TRUE(active.is_ok());
  ASSERT_TRUE(active.ok().code->get_hash() == wallet.code->get_hash());
  // An undeployed one runs the request's.
  auto undeployed = tos::plan_external_message_estimate(wallet.address, body, wallet.code, wallet.data, false, {}, {});
  ASSERT_TRUE(undeployed.is_ok());
  ASSERT_TRUE(undeployed.ok().code->get_hash() == wallet.code->get_hash());
  // And one with no code at all cannot be estimated.
  ASSERT_TRUE(tos::plan_external_message_estimate(wallet.address, body, {}, {}, false, {}, {}).is_error());
}

TEST(JsonRpcImportFee, a_message_that_is_not_an_inbound_external_is_refused) {
  auto wallet = make_wallet();
  vm::CellBuilder internal;
  CHECK(tos::GenericAccount::store_int_message(internal, wallet.address, 1, {}));
  CHECK(internal.store_zeroes_bool(2));
  auto prices = genesis_priced_config()->get_msg_prices(false).move_as_ok();
  ASSERT_TRUE(tos::external_message_import_fee(internal.finalize(), prices).is_error());
  ASSERT_TRUE(tos::external_message_import_fee({}, prices).is_error());
}
