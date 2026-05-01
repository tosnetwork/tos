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

// Slice 5 receive-context fixture.
//
// External author trials found that tol-tester can exercise helper/get-method
// code but cannot drive production receive handlers with real `in.senderAddress`
// and `blockchain.now()` values. This fixture closes that gap at the emulator
// layer: SmartContract::Args can now inject an internal sender, and c7's
// INMSG_* tuple observes the same sender/amount/time as the message cell.

#include "crypto/vm/boc.h"
#include "smc-envelope/SmartContract.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "vm/cells.h"

namespace {

#ifndef SLICE5_RECEIVE_CONTEXT_TOL_BOC
#error "SLICE5_RECEIVE_CONTEXT_TOL_BOC must be defined by CMake"
#endif

constexpr td::uint32 kOpBid = 0x51500001;
constexpr td::uint32 kOpClose = 0x51500002;
constexpr int kThrowUnauthorized = 0x1201;
constexpr int kThrowTooEarly = 0x1202;
constexpr td::uint64 kMessageAmount = 1'000'000'000;
constexpr td::uint64 kAccountBalance = 10'000'000'000ULL;

block::StdAddress std_address(unsigned char byte) {
  block::StdAddress address;
  address.workchain = 0;
  address.addr.as_slice().fill(byte);
  return address;
}

block::StdAddress seller_address() {
  return std_address(0x11);
}

block::StdAddress bidder_address() {
  return std_address(0x22);
}

void store_std_address(vm::CellBuilder& cb, const block::StdAddress& address) {
  td::BigInt256 addr;
  addr.import_bits(address.addr.as_bitslice());
  cb.store_ones(1).store_zeroes(2).store_long(address.workchain, 8).store_int256(addr, 256);
}

void store_tomis(vm::CellBuilder& cb, td::uint64 value) {
  auto amount = td::make_refint(value);
  const unsigned len = (static_cast<unsigned>(amount->bit_size(false)) + 7) >> 3;
  cb.store_long_bool(len, 4) && cb.store_int256_bool(*amount, len * 8, false);
}

td::Ref<vm::Cell> load_code_boc(const char* path) {
  auto buf = td::read_file(td::CSlice{path});
  CHECK(buf.is_ok());
  auto cell = vm::std_boc_deserialize(buf.move_as_ok().as_slice());
  CHECK(cell.is_ok());
  return cell.move_as_ok();
}

td::Ref<vm::Cell> build_storage() {
  vm::CellBuilder cb;
  store_std_address(cb, seller_address());
  store_std_address(cb, seller_address());
  cb.store_long(0, 32);
  cb.store_long(0, 1);
  cb.store_long(100, 32);
  return cb.finalize();
}

td::Ref<vm::Cell> build_bid_body(td::uint64 query_id, block::StdAddress forged_bidder, td::uint64 amount,
                                 td::uint32 forged_now) {
  vm::CellBuilder cb;
  cb.store_long(kOpBid, 32);
  cb.store_long(static_cast<long long>(query_id), 64);
  store_std_address(cb, forged_bidder);
  store_tomis(cb, amount);
  cb.store_long(forged_now, 32);
  return cb.finalize();
}

td::Ref<vm::Cell> build_close_body(td::uint64 query_id, td::uint32 forged_now) {
  vm::CellBuilder cb;
  cb.store_long(kOpClose, 32);
  cb.store_long(static_cast<long long>(query_id), 64);
  cb.store_long(forged_now, 32);
  return cb.finalize();
}

td::Ref<tos::SmartContract> make_contract() {
  tos::SmartContract::State state{load_code_boc(SLICE5_RECEIVE_CONTEXT_TOL_BOC), build_storage()};
  return tos::SmartContract::create(std::move(state));
}

tos::SmartContract::Args context_args(const tos::SmartContract& contract, block::StdAddress sender, int now) {
  return tos::SmartContract::Args()
      .set_amount(kMessageAmount)
      .set_balance(kAccountBalance)
      .set_address(contract.get_address(tos::basechainId))
      .set_sender_address(sender)
      .set_now(now);
}

long long get_int(const tos::SmartContract& contract, td::int32 method_id) {
  auto answer = contract.run_get_method(tos::SmartContract::Args().set_method_id(method_id));
  CHECK(answer.code == 0);
  CHECK(answer.stack->depth() == 1);
  return answer.stack.write().pop_int()->to_long();
}

bool get_bool(const tos::SmartContract& contract, td::int32 method_id) {
  return get_int(contract, method_id) != 0;
}

}  // namespace

TEST(Slice5ReceiveContext, InternalSenderAndNowReachProductionReceive) {
  auto contract = make_contract();

  auto forged_body = build_bid_body(1, seller_address(), 600, 999);
  auto answer = contract.write().send_internal_message(std::move(forged_body),
                                                       context_args(contract.write(), bidder_address(), 20));

  CHECK(answer.code == 0);
  CHECK(get_bool(contract.write(), 0x5101));
  CHECK(!get_bool(contract.write(), 0x5102));
  CHECK(get_int(contract.write(), 0x5103) == 20);
}

TEST(Slice5ReceiveContext, InternalSenderAuthorizesReceiveHandler) {
  auto contract = make_contract();

  auto unauthorized = contract.write().send_internal_message(build_close_body(2, 100),
                                                            context_args(contract.write(), bidder_address(), 100));
  CHECK(unauthorized.code == kThrowUnauthorized);
  CHECK(!get_bool(contract.write(), 0x5104));

  auto too_early = contract.write().send_internal_message(build_close_body(3, 100),
                                                         context_args(contract.write(), seller_address(), 99));
  CHECK(too_early.code == kThrowTooEarly);
  CHECK(!get_bool(contract.write(), 0x5104));

  auto ok = contract.write().send_internal_message(build_close_body(4, 0),
                                                  context_args(contract.write(), seller_address(), 100));
  CHECK(ok.code == 0);
  CHECK(get_bool(contract.write(), 0x5102));
  CHECK(get_int(contract.write(), 0x5103) == 100);
  CHECK(get_bool(contract.write(), 0x5104));
}
