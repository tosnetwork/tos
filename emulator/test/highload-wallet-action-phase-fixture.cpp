/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
*/

// =============================================================================
// High-volume wallet requests through the node's own action phase.
//
// crypto/smartcont/highload-wallet-v3-code.fc commits its new state before it
// sends, so that a request failing afterwards has still consumed its query id
// and cannot be replayed to drain gas. That only holds for failures in the
// compute phase. An action that IGNORE_ERRORS cannot skip — a message the
// executor cannot even unpack, such as one addressed to addr_none or carrying
// a malformed extra-currency dictionary — fails the action phase, and the
// executor then discards the committed state as well, returning the id to
// circulation.
//
// The wallet prevents that by forcing IGNORE_ERRORS onto every send, so the
// action phase skips an undeliverable message instead of failing. This fixture
// runs whole transactions on the C++ executor validators use, with requests
// signed without IGNORE_ERRORS, and checks the one property that matters: after
// the request, its query id is recorded.
// =============================================================================

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "crypto/Ed25519.h"
#include "crypto/common/bitstring.h"
#include "crypto/vm/boc.h"
#include "emulator/emulator-extern.h"
#include "emulator/test/tos-genesis-config.h"
#include "smc-envelope/SmartContract.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/base64.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"

namespace {

#ifndef HIGHLOAD_WALLET_V3_BOC
#error "HIGHLOAD_WALLET_V3_BOC must be defined by CMake"
#endif

constexpr td::uint64 kCoin = 1'000'000'000;
constexpr td::uint32 kNow = 1'800'000'000;
constexpr td::uint32 kSubwallet = 0x5157;
constexpr td::uint32 kTimeout = 3'600;

td::Ref<vm::Cell> wallet_code() {
  auto buf = td::read_file(td::CSlice{HIGHLOAD_WALLET_V3_BOC});
  CHECK(buf.is_ok());
  auto cell = vm::std_boc_deserialize(buf.move_as_ok().as_slice());
  CHECK(cell.is_ok());
  return cell.move_as_ok();
}

td::Ed25519::PrivateKey key() {
  return td::Ed25519::PrivateKey(td::SecureString(std::string(32, '\x51')));
}

void store_std_address(vm::CellBuilder &cb, const block::StdAddress &address) {
  td::BigInt256 addr;
  addr.import_bits(address.addr.as_bitslice());
  cb.store_ones(1).store_zeroes(2).store_long(address.workchain, 8).store_int256(addr, 256);
}

void store_coins(vm::CellBuilder &cb, td::uint64 value) {
  auto amount = td::make_refint(value);
  const unsigned len = (static_cast<unsigned>(amount->bit_size(false)) + 7) >> 3;
  CHECK(cb.store_long_bool(len, 4) && cb.store_int256_bool(*amount, len * 8, false));
}

td::Ref<vm::Cell> state_init() {
  auto public_key = key().get_public_key().move_as_ok().as_octet_string();
  vm::CellBuilder data;
  data.store_bytes(public_key.as_slice()).store_long(kSubwallet, 32).store_zeroes(1 + 1);
  data.store_long(0, 64).store_long(kTimeout, 22);
  vm::CellBuilder init;
  init.store_zeroes(2).store_ones(1).store_ref(wallet_code()).store_ones(1).store_ref(data.finalize()).store_zeroes(1);
  return init.finalize();
}

block::StdAddress wallet_address() {
  return block::StdAddress(0, state_init()->get_hash().bits());
}

std::string boc64(td::Ref<vm::Cell> cell) {
  return td::base64_encode(vm::std_boc_serialize(std::move(cell)).move_as_ok());
}

struct Emulated {
  bool success;
  std::string shard_account;
};

Emulated emulate(void *emulator, const std::string &shard_account, td::Ref<vm::Cell> message) {
  auto raw = transaction_emulator_emulate_transaction(emulator, shard_account.c_str(), boc64(message).c_str());
  std::string text(raw);
  string_destroy(raw);
  auto json = td::json_decode(td::MutableSlice(text));
  CHECK(json.is_ok());
  auto value = json.move_as_ok();
  auto &obj = value.get_object();
  Emulated result{obj.get_optional_bool_field("success").move_as_ok(), ""};
  if (result.success) {
    result.shard_account = obj.get_required_string_field("shard_account").move_as_ok();
  } else {
    LOG(INFO) << "emulation refused: " << text;
  }
  return result;
}

// The persistent data of an active account inside a ShardAccount BoC.
td::Ref<vm::Cell> account_data(const std::string &shard_account) {
  auto cell = vm::std_boc_deserialize(td::base64_decode(shard_account).move_as_ok()).move_as_ok();
  block::gen::ShardAccount::Record shard;
  CHECK(tlb::unpack_cell(cell, shard));
  block::gen::Account::Record_account account;
  CHECK(tlb::unpack_cell(shard.account, account));
  block::gen::AccountStorage::Record storage;
  CHECK(tlb::csr_unpack(account.storage, storage));
  auto state = storage.state.write();
  CHECK(state.fetch_ulong(1) == 1);  // account_active
  block::gen::StateInit::Record init;
  CHECK(tlb::csr_unpack(td::Ref<vm::CellSlice>(true, state), init));
  auto data = init.data->prefetch_ref();
  CHECK(data.not_null());
  return data;
}

bool processed(const std::string &shard_account, td::uint64 query_id) {
  auto contract = tos::SmartContract::create(tos::SmartContract::State{wallet_code(), account_data(shard_account)});
  auto answer = contract.write().run_get_method(
      tos::SmartContract::Args()
          .set_method_id(td::Slice("processed?"))
          .set_stack({td::make_refint(static_cast<long long>(query_id)), td::make_refint(0)})
          .set_address(wallet_address())
          .set_now(static_cast<int>(kNow))
          .set_config(fee_fixture::config()));
  CHECK(answer.code == 0);
  return answer.stack.write().pop_int()->sgn() != 0;
}

std::string deployed_wallet(void *emulator) {
  td::Ref<vm::Cell> none;
  CHECK(block::gen::Account().cell_pack_account_none(none));
  vm::CellBuilder shard;
  shard.store_ref(none).store_bits(td::Bits256::zero().as_bitslice()).store_long(0, 64);
  vm::CellBuilder deploy;
  deploy.store_long(0b0100, 4);
  store_std_address(deploy, block::StdAddress(0, td::Bits256::zero()));
  store_std_address(deploy, wallet_address());
  store_coins(deploy, 100 * kCoin);
  deploy.store_zeroes(1 + 4 + 4 + 64 + 32);
  deploy.store_ones(2).store_ref(state_init()).store_zeroes(1);
  auto result = emulate(emulator, boc64(shard.finalize()), deploy.finalize());
  CHECK(result.success);
  return result.shard_account;
}

td::Ref<vm::Cell> signed_request(td::uint64 query_id, td::Ref<vm::Cell> message) {
  vm::CellBuilder inner;
  // Send mode 1, without IGNORE_ERRORS: the signer may omit it, and the wallet must add it.
  inner.store_long(kSubwallet, 32).store_ref(std::move(message)).store_long(1, 8);
  inner.store_long(static_cast<long long>(query_id), 23).store_long(kNow - 1, 64).store_long(kTimeout, 22);
  auto inner_cell = inner.finalize();
  auto signature = key().sign(inner_cell->get_hash().as_slice()).move_as_ok();
  vm::CellBuilder body;
  body.store_ref(inner_cell).store_bytes(signature.as_slice());
  vm::CellBuilder ext;
  ext.store_long(0b10, 2).store_zeroes(2);  // ext_in_msg_info$10, src addr_none
  store_std_address(ext, wallet_address());
  ext.store_zeroes(4 + 1);  // import_fee 0, no StateInit
  ext.store_ones(1).store_ref(body.finalize());
  return ext.finalize();
}

void *new_emulator() {
  static const auto config = fee_fixture::tos_versioned_config_boc();
  void *emulator = transaction_emulator_create(config.c_str(), 0);
  CHECK(emulator != nullptr);
  CHECK(transaction_emulator_set_unixtime(emulator, kNow));
  CHECK(transaction_emulator_set_lt(emulator, 1'000'000));
  return emulator;
}

// An internal message with int_msg_info$0 and src addr_none; `dest_and_value` writes the
// destination, value and extra currencies.
template <class F>
td::Ref<vm::Cell> relaxed(F dest_and_value) {
  vm::CellBuilder cb;
  cb.store_long(0b0100, 4).store_zeroes(2);
  dest_and_value(cb);
  cb.store_zeroes(4 + 4 + 64 + 32 + 1 + 1);  // extra_flags, fwd_fee, lt, at, no init, inline body
  return cb.finalize();
}

void check_request_consumes_its_id(td::uint64 query_id, td::Ref<vm::Cell> message) {
  void *emulator = new_emulator();
  auto wallet = deployed_wallet(emulator);
  CHECK(!processed(wallet, query_id));
  auto after = emulate(emulator, wallet, signed_request(query_id, std::move(message)));
  CHECK(after.success);
  CHECK(processed(after.shard_account, query_id));
  transaction_emulator_destroy(emulator);
}

}  // namespace

TEST(HighloadWalletActionPhase, OrdinaryTransferConsumesItsId) {
  check_request_consumes_its_id(7, relaxed([](vm::CellBuilder &cb) {
                                  store_std_address(cb, block::StdAddress(0, td::Bits256::zero()));
                                  store_coins(cb, kCoin);
                                  cb.store_zeroes(1);
                                }));
}

TEST(HighloadWalletActionPhase, MessageToAddrNoneConsumesItsId) {
  check_request_consumes_its_id(11, relaxed([](vm::CellBuilder &cb) {
                                  cb.store_zeroes(2);  // dest: addr_none
                                  store_coins(cb, kCoin);
                                  cb.store_zeroes(1);
                                }));
}

TEST(HighloadWalletActionPhase, MalformedExtraCurrenciesConsumeTheirId) {
  check_request_consumes_its_id(12, relaxed([](vm::CellBuilder &cb) {
                                  store_std_address(cb, block::StdAddress(0, td::Bits256::zero()));
                                  store_coins(cb, kCoin);
                                  vm::CellBuilder junk;
                                  junk.store_long(0x5, 3);  // not a HashmapE 32 root
                                  cb.store_ones(1).store_ref(junk.finalize());
                                }));
}
