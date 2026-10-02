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
// Jetton wallet fee profile: measured against the build, priced by the config.
//
// crypto/smartcont/jetton-wallet.tol prices transfers and burns through
// `@stdlib/jetton-fees`. The fee *prices* come from the configuration at run
// time, but the *quantities* — gas units of each compute phase and the bits
// and cells that storage and forwarding are charged on — are constants in
// `walletFeeProfile()`. Those constants describe one build of the wallet and
// minter; a code change can make them stale without any other test noticing,
// and a stale profile under-reserves silently.
//
// This fixture runs the real wallet and minter code on the C++ TVM (the one
// validators run) and:
//   1. measures every quantity in the profile and requires
//      measured <= profile <= measured + headroom, so the profile can neither
//      under-reserve nor drift far above the build;
//   2. recomputes the transfer and burn requirements from the configuration's
//      price tables in C++ and requires the contract getters to agree;
//   3. sends a transfer and a burn carrying exactly the requirement (must be
//      refused) and one coin unit more (must succeed).
//
// When (1) fails after an intentional wallet change, update
// `walletFeeProfile()` from the "measured" line this test prints.
// =============================================================================

#include <algorithm>
#include <memory>

#include "block/block.h"
#include "block/mc-config.h"
#include "crypto/vm/boc.h"
#include "emulator/emulator-extern.h"
#include "emulator/test/tos-genesis-config.h"
#include "smc-envelope/SmartContract.h"
#include "td/utils/base64.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "vm/cells.h"

namespace {

using fee_fixture::config;

#ifndef SLICE1_GAS_PARITY_JETTON_WALLET_TOL_BOC
#error "SLICE1_GAS_PARITY_JETTON_WALLET_TOL_BOC must be defined by CMake"
#endif
#ifndef SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC
#error "SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC must be defined by CMake"
#endif

constexpr td::uint32 kOpTransfer = 0x0f8a7ea5;
constexpr td::uint32 kOpInternalTransfer = 0x178d4519;
constexpr td::uint32 kOpBurn = 0x595f07bc;
constexpr td::uint32 kOpBurnNotification = 0x7bdd97de;
constexpr td::int32 kThrowInsufficientTransferValue = 709;
constexpr td::int32 kThrowInsufficientBurnValue = 707;
constexpr td::uint64 kCoin = 1'000'000'000;
constexpr td::int32 kNow = 1'800'000'000;
constexpr td::uint64 kJettons = 1'000'000;

struct FeeProfile {
  td::int64 wallet_storage_bits;
  td::int64 wallet_storage_cells;
  td::int64 wallet_init_state_bits;
  td::int64 wallet_init_state_cells;
  td::int64 burn_notification_bits;
  td::int64 burn_notification_cells;
  td::int64 send_transfer_gas;
  td::int64 receive_transfer_gas;
  td::int64 send_burn_gas;
  td::int64 receive_burn_gas;
  td::int64 min_storage_seconds;
};

td::Ref<vm::Cell> load_code_boc(const char *path) {
  auto buf = td::read_file(td::CSlice{path});
  CHECK(buf.is_ok());
  auto cell = vm::std_boc_deserialize(buf.move_as_ok().as_slice());
  CHECK(cell.is_ok());
  return cell.move_as_ok();
}

td::Ref<vm::Cell> wallet_code() {
  static auto code = load_code_boc(SLICE1_GAS_PARITY_JETTON_WALLET_TOL_BOC);
  return code;
}

td::Ref<vm::Cell> minter_code() {
  static auto code = load_code_boc(SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC);
  return code;
}

block::StdAddress std_address(unsigned char byte) {
  block::StdAddress address;
  address.workchain = 0;
  address.addr.as_slice().fill(byte);
  return address;
}

block::StdAddress owner() {
  return std_address(0x11);
}

block::StdAddress recipient() {
  return std_address(0x22);
}

void store_std_address(vm::CellBuilder &cb, const block::StdAddress &address) {
  td::BigInt256 addr;
  addr.import_bits(address.addr.as_bitslice());
  cb.store_ones(1).store_zeroes(2).store_long(address.workchain, 8).store_int256(addr, 256);
}

void store_coins(vm::CellBuilder &cb, const td::RefInt256 &amount) {
  const unsigned len = (static_cast<unsigned>(amount->bit_size(false)) + 7) >> 3;
  CHECK(cb.store_long_bool(len, 4) && cb.store_int256_bool(*amount, len * 8, false));
}

void store_coins(vm::CellBuilder &cb, td::uint64 amount) {
  store_coins(cb, td::make_refint(amount));
}

td::Ref<vm::Cell> state_init(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data) {
  vm::CellBuilder cb;
  cb.store_long(0, 2).store_long(1, 1).store_ref(std::move(code)).store_long(1, 1).store_ref(std::move(data));
  cb.store_long(0, 1);
  return cb.finalize();
}

block::StdAddress address_of(const td::Ref<vm::Cell> &init) {
  return block::StdAddress(0, init->get_hash().bits());
}

td::Ref<vm::Cell> minter_data(const td::RefInt256 &total_supply) {
  vm::CellBuilder content;
  content.store_long(0x01, 8);
  vm::CellBuilder cb;
  store_coins(cb, total_supply);
  store_std_address(cb, owner());
  cb.store_ref(content.finalize()).store_ref(wallet_code());
  return cb.finalize();
}

block::StdAddress minter() {
  static auto address = address_of(state_init(minter_code(), minter_data(td::zero_refint())));
  return address;
}

td::Ref<vm::Cell> wallet_data(const td::RefInt256 &balance, const block::StdAddress &holder) {
  vm::CellBuilder cb;
  store_coins(cb, balance);
  store_std_address(cb, holder);
  store_std_address(cb, minter());
  cb.store_ref(wallet_code());
  return cb.finalize();
}

td::Ref<vm::Cell> wallet_data(td::uint64 balance, const block::StdAddress &holder) {
  return wallet_data(td::make_refint(balance), holder);
}

block::StdAddress wallet_of(const block::StdAddress &holder) {
  return address_of(state_init(wallet_code(), wallet_data(0, holder)));
}

void store_forward_payload(vm::CellBuilder &cb) {
  cb.store_long(0, 1).store_long(0xfeedbeef, 32);
}

td::Ref<vm::Cell> transfer_body(td::uint64 forward_amount) {
  vm::CellBuilder cb;
  cb.store_long(kOpTransfer, 32).store_long(1, 64);
  store_coins(cb, 1000);
  store_std_address(cb, recipient());
  store_std_address(cb, owner());
  cb.store_long(0, 1);
  store_coins(cb, forward_amount);
  store_forward_payload(cb);
  return cb.finalize();
}

td::Ref<vm::Cell> internal_transfer_body(td::uint64 forward_amount, bool with_response) {
  vm::CellBuilder cb;
  cb.store_long(kOpInternalTransfer, 32).store_long(2, 64);
  store_coins(cb, 1000);
  store_std_address(cb, owner());
  if (with_response) {
    store_std_address(cb, owner());
  } else {
    cb.store_long(0, 2);
  }
  store_coins(cb, forward_amount);
  store_forward_payload(cb);
  return cb.finalize();
}

td::Ref<vm::Cell> burn_body(const td::RefInt256 &amount) {
  vm::CellBuilder cb;
  cb.store_long(kOpBurn, 32).store_long(3, 64);
  store_coins(cb, amount);
  store_std_address(cb, owner());
  cb.store_long(0, 1);
  return cb.finalize();
}

td::Ref<vm::Cell> burn_notification_body(const td::RefInt256 &amount) {
  vm::CellBuilder cb;
  cb.store_long(kOpBurnNotification, 32).store_long(4, 64);
  store_coins(cb, amount);
  store_std_address(cb, owner());
  store_std_address(cb, owner());
  return cb.finalize();
}

tos::SmartContract::Args message_args(const block::StdAddress &self, const block::StdAddress &sender, td::uint64 amount,
                                      td::uint64 balance) {
  return tos::SmartContract::Args()
      .set_amount(amount)
      .set_balance(balance)
      .set_address(self)
      .set_sender_address(sender)
      .set_now(kNow)
      .set_config(config());
}

tos::SmartContract::Answer run(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data, const block::StdAddress &self,
                               const block::StdAddress &sender, td::uint64 amount, td::uint64 balance,
                               td::Ref<vm::Cell> body) {
  auto contract = tos::SmartContract::create(tos::SmartContract::State{std::move(code), std::move(data)});
  return contract.write().send_internal_message(std::move(body), message_args(self, sender, amount, balance));
}

// Largest jetton amount a Coins field can carry; sizes are measured at it.
td::RefInt256 max_coins() {
  auto value = td::make_refint(1);
  value <<= 120;
  value -= 1;
  return value;
}

tos::SmartContract::Answer send_to_owner_wallet(td::uint64 amount, td::Ref<vm::Cell> body,
                                                const td::RefInt256 &jettons = td::make_refint(kJettons)) {
  return run(wallet_code(), wallet_data(jettons, owner()), wallet_of(owner()), owner(), amount, kCoin, body);
}

td::Ref<vm::Stack> get(const char *method, std::vector<vm::StackEntry> args) {
  auto contract = tos::SmartContract::create(tos::SmartContract::State{wallet_code(), wallet_data(kJettons, owner())});
  auto answer = contract.write().run_get_method(tos::SmartContract::Args()
                                                    .set_method_id(td::Slice(method))
                                                    .set_stack(std::move(args))
                                                    .set_address(wallet_of(owner()))
                                                    .set_now(kNow)
                                                    .set_config(config()));
  CHECK(answer.code == 0);
  return answer.stack;
}

FeeProfile contract_profile() {
  auto stack = get("get_fee_profile", {});
  CHECK(stack->depth() == 11);
  FeeProfile p;
  p.min_storage_seconds = stack.write().pop_long();
  p.receive_burn_gas = stack.write().pop_long();
  p.send_burn_gas = stack.write().pop_long();
  p.receive_transfer_gas = stack.write().pop_long();
  p.send_transfer_gas = stack.write().pop_long();
  p.burn_notification_cells = stack.write().pop_long();
  p.burn_notification_bits = stack.write().pop_long();
  p.wallet_init_state_cells = stack.write().pop_long();
  p.wallet_init_state_bits = stack.write().pop_long();
  p.wallet_storage_cells = stack.write().pop_long();
  p.wallet_storage_bits = stack.write().pop_long();
  return p;
}

td::RefInt256 contract_transfer_fee(td::uint64 forward_amount, td::uint64 fwd_fee) {
  auto stack = get("get_transfer_fee", {td::make_refint(forward_amount), td::make_refint(fwd_fee)});
  CHECK(stack->depth() == 1);
  return stack.write().pop_int();
}

td::RefInt256 contract_burn_fee() {
  auto stack = get("get_burn_fee", {});
  CHECK(stack->depth() == 1);
  return stack.write().pop_int();
}

vm::CellStorageStat storage_of(td::Ref<vm::Cell> cell) {
  vm::CellStorageStat stat;
  CHECK(stat.compute_used_storage(std::move(cell)).is_ok());
  return stat;
}

// Forward fees charge a message's cells and bits excluding its root cell
// (the lump price covers the root): skip both the root's cell (mask 1) and
// its bits (mask 2).
vm::CellStorageStat forwarded_part_of(td::Ref<vm::Cell> message) {
  vm::CellStorageStat stat;
  CHECK(stat.compute_used_storage(std::move(message), true, 3).is_ok());
  return stat;
}

// The outbound message of a single-action list (action_send_msg).
td::Ref<vm::Cell> only_out_message(td::Ref<vm::Cell> actions) {
  CHECK(tos::SmartContract::Answer::output_actions_count(actions) == 1);
  auto cs = vm::load_cell_slice(actions);
  cs.fetch_ref();  // previous (empty) action list
  CHECK(cs.fetch_ulong(32) == 0x0ec3c86d);
  cs.skip_first(8);
  return cs.fetch_ref();
}

FeeProfile measure() {
  FeeProfile m{};
  m.min_storage_seconds = 0;

  for (td::uint64 forward : {0ULL, 1ULL}) {
    auto send = send_to_owner_wallet(kCoin, transfer_body(forward));
    CHECK(send.code == 0);
    m.send_transfer_gas = std::max(m.send_transfer_gas, send.gas_used);
    for (bool response : {false, true}) {
      auto receive = run(wallet_code(), wallet_data(0, recipient()), wallet_of(recipient()), wallet_of(owner()), kCoin,
                         kCoin, internal_transfer_body(forward, response));
      CHECK(receive.code == 0);
      m.receive_transfer_gas = std::max(m.receive_transfer_gas, receive.gas_used);
    }
  }

  auto burn = send_to_owner_wallet(kCoin, burn_body(max_coins()), max_coins());
  CHECK(burn.code == 0);
  m.send_burn_gas = burn.gas_used;
  auto notification = forwarded_part_of(only_out_message(burn.actions));
  m.burn_notification_bits = static_cast<td::int64>(notification.bits);
  m.burn_notification_cells = static_cast<td::int64>(notification.cells);

  auto receive_burn = run(minter_code(), minter_data(max_coins()), minter(), wallet_of(owner()), kCoin, kCoin,
                          burn_notification_body(max_coins()));
  CHECK(receive_burn.code == 0);
  m.receive_burn_gas = receive_burn.gas_used;

  // The account a wallet keeps alive, at the largest balance it can hold.
  auto stored = storage_of(state_init(wallet_code(), wallet_data(max_coins(), recipient())));
  m.wallet_storage_bits = static_cast<td::int64>(stored.bits);
  m.wallet_storage_cells = static_cast<td::int64>(stored.cells);

  // The StateInit an internal transfer carries to the receiving wallet.
  auto carried = storage_of(state_init(wallet_code(), wallet_data(0, recipient())));
  m.wallet_init_state_bits = static_cast<td::int64>(carried.bits);
  m.wallet_init_state_cells = static_cast<td::int64>(carried.cells);
  return m;
}

void check_within(const char *name, td::int64 measured, td::int64 profile, td::int64 slack) {
  LOG(INFO) << "jetton-wallet fee profile " << name << ": measured=" << measured << " profile=" << profile;
  CHECK(measured > 0);
  CHECK(measured <= profile);
  CHECK(profile <= measured + std::max(measured / 4, slack));
}

td::RefInt256 ceil_shift16(td::RefInt256 x) {
  x += td::make_refint(0xffff);
  x >>= 16;
  return x;
}

td::RefInt256 gas_fee(const block::GasLimitsPrices &prices, td::int64 gas) {
  return prices.compute_gas_price(static_cast<td::uint64>(gas));
}

td::RefInt256 storage_fee(td::int64 seconds, td::int64 bits, td::int64 cells) {
  auto all = config()->get_storage_prices();
  CHECK(all.is_ok());
  td::RefInt256 fee = td::zero_refint();
  for (const auto &prices : all.ok()) {
    if (prices.valid_since <= static_cast<tos::UnixTime>(kNow)) {
      fee = td::make_refint(cells) * td::make_refint(prices.cell_price) +
            td::make_refint(bits) * td::make_refint(prices.bit_price);
      fee *= td::make_refint(seconds);
      fee = ceil_shift16(fee);
    }
  }
  return fee;
}

}  // namespace

TEST(JettonWalletFeeProfile, ProfileMatchesThisBuild) {
  auto m = measure();
  auto p = contract_profile();
  LOG(INFO) << "jetton-wallet fee profile measured: walletStorageBits=" << m.wallet_storage_bits
            << " walletStorageCells=" << m.wallet_storage_cells << " walletInitStateBits=" << m.wallet_init_state_bits
            << " walletInitStateCells=" << m.wallet_init_state_cells
            << " burnNotificationBits=" << m.burn_notification_bits
            << " burnNotificationCells=" << m.burn_notification_cells << " sendTransferGas=" << m.send_transfer_gas
            << " receiveTransferGas=" << m.receive_transfer_gas << " sendBurnGas=" << m.send_burn_gas
            << " receiveBurnGas=" << m.receive_burn_gas;
  check_within("walletStorageBits", m.wallet_storage_bits, p.wallet_storage_bits, 64);
  check_within("walletStorageCells", m.wallet_storage_cells, p.wallet_storage_cells, 1);
  check_within("walletInitStateBits", m.wallet_init_state_bits, p.wallet_init_state_bits, 64);
  check_within("walletInitStateCells", m.wallet_init_state_cells, p.wallet_init_state_cells, 1);
  check_within("burnNotificationBits", m.burn_notification_bits, p.burn_notification_bits, 64);
  check_within("burnNotificationCells", m.burn_notification_cells, p.burn_notification_cells, 1);
  check_within("sendTransferGas", m.send_transfer_gas, p.send_transfer_gas, 500);
  check_within("receiveTransferGas", m.receive_transfer_gas, p.receive_transfer_gas, 500);
  check_within("sendBurnGas", m.send_burn_gas, p.send_burn_gas, 500);
  check_within("receiveBurnGas", m.receive_burn_gas, p.receive_burn_gas, 500);
  CHECK(p.min_storage_seconds == 5LL * 365 * 24 * 3600);
}

TEST(JettonWalletFeeProfile, GettersAgreeWithConfigPrices) {
  auto p = contract_profile();
  auto gas_prices = config()->get_gas_limits_prices(false);
  auto msg_prices = config()->get_msg_prices(false);
  CHECK(gas_prices.is_ok() && msg_prices.is_ok());
  const auto &gas = gas_prices.ok();
  const auto &msg = msg_prices.ok();

  auto init_overhead = ceil_shift16(td::make_refint(msg.bit_price) * td::make_refint(p.wallet_init_state_bits) +
                                    td::make_refint(msg.cell_price) * td::make_refint(p.wallet_init_state_cells));
  auto min_storage = storage_fee(p.min_storage_seconds, p.wallet_storage_bits, p.wallet_storage_cells);
  auto compute = gas_fee(gas, p.send_transfer_gas) + gas_fee(gas, p.receive_transfer_gas);

  const td::uint64 fwd_fee = 7'000'000;
  auto without_forward = td::make_refint(fwd_fee) + init_overhead + compute + min_storage;
  CHECK(td::cmp(contract_transfer_fee(0, fwd_fee), without_forward) == 0);
  const td::uint64 forward = 50'000'000;
  auto with_forward = td::make_refint(forward) + td::make_refint(2 * fwd_fee) + init_overhead + compute + min_storage;
  CHECK(td::cmp(contract_transfer_fee(forward, fwd_fee), with_forward) == 0);

  auto burn = msg.compute_fwd_fees256(p.burn_notification_cells, p.burn_notification_bits) +
              gas_fee(gas, p.send_burn_gas) + gas_fee(gas, p.receive_burn_gas);
  CHECK(td::cmp(contract_burn_fee(), burn) == 0);
}

TEST(JettonWalletFeeProfile, TransferAndBurnRefuseExactlyTheRequirement) {
  // The emulator delivers messages with a zero forward fee, which is what
  // the wallet reads for `fwdFee`, so the getters are queried with zero too.
  auto transfer_fee = contract_transfer_fee(1, 0)->to_long();
  CHECK(transfer_fee > 0);
  auto refused = send_to_owner_wallet(static_cast<td::uint64>(transfer_fee), transfer_body(1));
  CHECK(refused.code == kThrowInsufficientTransferValue);
  auto accepted = send_to_owner_wallet(static_cast<td::uint64>(transfer_fee + 1), transfer_body(1));
  CHECK(accepted.code == 0);

  auto burn_fee = contract_burn_fee()->to_long();
  CHECK(burn_fee > 0);
  auto refused_burn = send_to_owner_wallet(static_cast<td::uint64>(burn_fee), burn_body(td::make_refint(1000)));
  CHECK(refused_burn.code == kThrowInsufficientBurnValue);
  auto accepted_burn = send_to_owner_wallet(static_cast<td::uint64>(burn_fee + 1), burn_body(td::make_refint(1000)));
  CHECK(accepted_burn.code == 0);
}
