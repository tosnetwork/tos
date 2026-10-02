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
// Jetton wallet and minter, end to end on the node's own transaction executor.
//
// crypto/smartcont/jetton-wallet.tol prices transfers and burns through
// `@stdlib/jetton-fees`. The fee *prices* come from the configuration at run
// time, but the *quantities* — gas units of each compute phase and the bits
// and cells that storage and forwarding are charged on — are constants in
// `walletFeeProfile()` (jetton-wallet-fee-profile.tol). Those constants
// describe one build of the wallet and minter; a code change can make them
// stale without any other test noticing, and a stale profile under-reserves
// silently.
//
// Every message here runs as a whole transaction (storage, credit, compute,
// action and bounce phases) on the C++ executor validators use, with forward
// fees on inbound messages as the chain sets them, and the messages each
// transaction sends are delivered in turn. The fixture:
//   1. measures every quantity in the profile from those transactions — gas
//      from their compute phases, wallet storage from the deployed account's
//      own storage statistics — and requires
//      measured <= profile <= measured + headroom;
//   2. recomputes the transfer and burn requirements from the configuration's
//      price tables in C++ and requires the contract getters to agree;
//   3. sends transfers, burns and mints carrying exactly the requirement (must
//      be refused) and one coin unit more (must complete every hop, leaving
//      the receiving wallet its storage reserve);
//   4. checks the failure paths that the action phase decides: a notification
//      the receiving wallet cannot pay bounces the transfer back, a mint the
//      message cannot pay for leaves the minter's own balance alone, and a
//      bounced mint is taken back out of the total supply.
//
// When (1) fails after an intentional wallet change, update
// `walletFeeProfile()` from the "measured" line this test prints.
// =============================================================================

#include <algorithm>
#include <deque>
#include <map>
#include <memory>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "crypto/vm/boc.h"
#include "emulator/emulator-extern.h"
#include "emulator/test/tos-genesis-config.h"
#include "smc-envelope/SmartContract.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/base64.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "vm/cells.h"
#include "vm/dict.h"

namespace {

using fee_fixture::config;

#ifndef SLICE1_GAS_PARITY_JETTON_WALLET_TOL_BOC
#error "SLICE1_GAS_PARITY_JETTON_WALLET_TOL_BOC must be defined by CMake"
#endif
#ifndef SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC
#error "SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC must be defined by CMake"
#endif

constexpr td::uint32 kOpTransfer = 0x0f8a7ea5;
constexpr td::uint32 kOpTransferNotification = 0x7362d09c;
constexpr td::uint32 kOpExcesses = 0xd53276db;
constexpr td::uint32 kOpInternalTransfer = 0x178d4519;
constexpr td::uint32 kOpBurn = 0x595f07bc;
constexpr td::uint32 kOpBurnNotification = 0x7bdd97de;
constexpr td::uint32 kOpMint = 0x15;
constexpr td::uint32 kOpTopUp = 0xd372158c;
constexpr td::uint32 kBounced = 0xffffffff;
constexpr td::int32 kThrowInsufficientTransferValue = 709;
constexpr td::int32 kThrowInsufficientBurnValue = 707;
constexpr td::uint64 kCoin = 1'000'000'000;
constexpr td::uint32 kNow = 1'800'000'000;
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

// Holders are plain accounts outside this fixture: messages to them are
// recorded, not executed.
block::StdAddress owner() {
  return std_address(0x11);
}

block::StdAddress recipient() {
  return std_address(0x22);
}

bool is_holder(const block::StdAddress &address) {
  return address == owner() || address == recipient();
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

td::Ref<vm::Cell> minter_init() {
  return state_init(minter_code(), minter_data(td::zero_refint()));
}

block::StdAddress minter() {
  static auto address = address_of(minter_init());
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

block::StdAddress wallet_of(const block::StdAddress &holder) {
  return address_of(state_init(wallet_code(), wallet_data(td::zero_refint(), holder)));
}

// Largest jetton amount a Coins field can carry; sizes are measured at it.
td::RefInt256 max_coins() {
  auto value = td::make_refint(1);
  value <<= 120;
  value -= 1;
  return value;
}

// A forward payload of `cells` chained cells in a reference, so that the
// messages carrying it cost real forward fees; inline when `cells` is 0.
void store_forward_payload(vm::CellBuilder &cb, int cells) {
  if (cells == 0) {
    cb.store_long(0, 1).store_long(0xfeedbeef, 32);
    return;
  }
  td::Ref<vm::Cell> chain;
  for (int i = 0; i < cells; i++) {
    vm::CellBuilder link;
    link.store_long(i, 32).store_zeroes(256);
    if (chain.not_null()) {
      link.store_ref(chain);
    }
    chain = link.finalize();
  }
  cb.store_long(1, 1).store_ref(chain);
}

struct Transfer {
  td::RefInt256 amount = td::make_refint(1000);
  bool with_response = true;
  td::uint64 forward_amount = 0;
  int payload_cells = 0;
};

td::Ref<vm::Cell> transfer_body(const Transfer &t) {
  vm::CellBuilder cb;
  cb.store_long(kOpTransfer, 32).store_long(1, 64);
  store_coins(cb, t.amount);
  store_std_address(cb, recipient());
  if (t.with_response) {
    store_std_address(cb, owner());
  } else {
    cb.store_long(0, 2);
  }
  cb.store_long(0, 1);
  store_coins(cb, t.forward_amount);
  store_forward_payload(cb, t.payload_cells);
  return cb.finalize();
}

struct Mint {
  block::StdAddress to = owner();
  td::RefInt256 jettons = td::make_refint(kJettons);
  td::uint64 wallet_value = 0;  // TOS the minter sends with the internal transfer
  bool with_response = true;
  td::uint64 forward_amount = 0;
  int payload_cells = 0;
};

td::Ref<vm::Cell> mint_body(const Mint &m) {
  vm::CellBuilder transfer;
  transfer.store_long(kOpInternalTransfer, 32).store_long(2, 64);
  store_coins(transfer, m.jettons);
  store_std_address(transfer, owner());
  if (m.with_response) {
    store_std_address(transfer, owner());
  } else {
    transfer.store_long(0, 2);
  }
  store_coins(transfer, m.forward_amount);
  store_forward_payload(transfer, m.payload_cells);
  vm::CellBuilder cb;
  cb.store_long(kOpMint, 32).store_long(5, 64);
  store_std_address(cb, m.to);
  store_coins(cb, m.wallet_value);
  cb.store_ref(transfer.finalize());
  return cb.finalize();
}

enum class Response { kNone, kStd, kLargest };

// `kLargest` is the largest response address the wallet accepts: an external
// address of 511 bits (it refuses addr_var), which the wallet copies into the
// notification it sends the minter.
td::Ref<vm::Cell> burn_body(const td::RefInt256 &amount, Response response = Response::kStd) {
  vm::CellBuilder cb;
  cb.store_long(kOpBurn, 32).store_long(3, 64);
  store_coins(cb, amount);
  switch (response) {
    case Response::kNone:
      cb.store_long(0, 2);
      break;
    case Response::kStd:
      store_std_address(cb, owner());
      break;
    case Response::kLargest:
      cb.store_long(0b01, 2).store_long(511, 9).store_ones(511);
      break;
  }
  cb.store_long(0, 1);
  return cb.finalize();
}

td::Ref<vm::Cell> top_up_body() {
  vm::CellBuilder cb;
  cb.store_long(kOpTopUp, 32).store_long(6, 64);
  return cb.finalize();
}

td::uint32 op_of(const td::Ref<vm::CellSlice> &body) {
  return body->size() >= 32 ? static_cast<td::uint32>(body->prefetch_ulong(32)) : 0;
}

const block::MsgPrices &basechain_msg_prices() {
  static const block::MsgPrices prices = [] {
    auto r = config()->get_msg_prices(false);
    CHECK(r.is_ok());
    return r.move_as_ok();
  }();
  return prices;
}

// The shared fixture config with basechain message prices (ConfigParam 25)
// multiplied by `factor`: a governance price change taking effect between two
// hops of one transfer.
std::string config_with_message_prices_times(unsigned factor) {
  auto decoded = td::base64_decode(fee_fixture::tos_versioned_config_boc());
  CHECK(decoded.is_ok());
  auto root = vm::std_boc_deserialize(decoded.move_as_ok());
  CHECK(root.is_ok());
  vm::Dictionary params{root.move_as_ok(), 32};
  td::BitArray<32> key;
  key.store_ulong(25);
  auto current = params.lookup_ref(key);
  CHECK(current.not_null());
  auto cs = vm::load_cell_slice(current);
  CHECK(cs.fetch_ulong(8) == 0xea);
  vm::CellBuilder cb;
  cb.store_long(0xea, 8);
  for (int i = 0; i < 3; i++) {  // lump, bit and cell prices
    cb.store_long(static_cast<long long>(cs.fetch_ulong(64) * factor), 64);
  }
  CHECK(cb.append_cellslice_bool(cs));
  CHECK(params.set_ref(key, cb.finalize()));
  return td::base64_encode(vm::std_boc_serialize(params.get_root_cell()).move_as_ok());
}

std::string boc64(td::Ref<vm::Cell> cell) {
  return td::base64_encode(vm::std_boc_serialize(std::move(cell)).move_as_ok());
}

td::Ref<vm::Cell> from_boc64(td::Slice text) {
  auto cell = vm::std_boc_deserialize(td::base64_decode(text).move_as_ok());
  CHECK(cell.is_ok());
  return cell.move_as_ok();
}

struct Delivered {
  block::StdAddress to;
  td::RefInt256 value;
  bool bounced = false;
  td::Ref<vm::CellSlice> body;
  td::Ref<vm::Cell> init;  // the StateInit the message carried, if any
  td::Ref<vm::Cell> message;
};

Delivered parse_internal(td::Ref<vm::Cell> message) {
  auto cs = vm::load_cell_slice(message);
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  CHECK(tlb::unpack(cs, info));
  Delivered d;
  d.message = message;
  CHECK(block::tlb::t_MsgAddressInt.extract_std_address(info.dest, d.to));
  block::CurrencyCollection value;
  CHECK(value.unpack(info.value));
  d.value = value.tomis;
  d.bounced = info.bounced;
  if (cs.fetch_ulong(1) == 1) {
    if (cs.fetch_ulong(1) == 1) {
      d.init = cs.fetch_ref();
    } else {
      td::Ref<vm::CellSlice> inline_init;
      CHECK(block::gen::t_StateInit.fetch_to(cs, inline_init));
      vm::CellBuilder init;
      CHECK(init.append_cellslice_bool(inline_init));
      d.init = init.finalize();
    }
  }
  if (cs.fetch_ulong(1) == 1) {
    d.body = vm::load_cell_slice_ref(cs.fetch_ref());
  } else {
    d.body = td::Ref<vm::CellSlice>(true, cs);
  }
  return d;
}

// The forward fee a receiver reads for an inbound message: GETORIGINALFWDFEE
// of the remaining fee in its header.
td::uint64 original_fee_of(td::Ref<vm::Cell> message) {
  auto cs = vm::load_cell_slice(message);
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  CHECK(tlb::unpack(cs, info));
  auto remaining = block::tlb::t_Tomis.as_integer(info.fwd_fee);
  CHECK(remaining.not_null());
  return static_cast<td::uint64>(
      td::muldiv(remaining, td::make_refint(1 << 16), td::make_refint((1 << 16) - basechain_msg_prices().first_frac))
          ->to_long());
}

struct Tx {
  block::StdAddress account;
  td::uint32 in_op = 0;
  bool vm_ran = false;
  bool compute_success = false;
  int exit_code = 0;
  td::int64 gas_used = 0;
  bool action_success = false;
  bool bounce_phase = false;
  std::vector<Delivered> out;
};

Tx parse_transaction(const block::StdAddress &account, td::Ref<vm::Cell> root, td::uint32 in_op) {
  Tx tx;
  tx.account = account;
  tx.in_op = in_op;
  block::gen::Transaction::Record trans;
  CHECK(tlb::unpack_cell(root, trans));
  vm::Dictionary out_msgs{trans.r1.out_msgs, 15};
  for (int i = 0; i < trans.outmsg_cnt; i++) {
    auto message = out_msgs.lookup_ref(td::BitArray<15>(i));
    CHECK(message.not_null());
    tx.out.push_back(parse_internal(message));
  }
  block::gen::TransactionDescr::Record_trans_ord ord;
  CHECK(tlb::unpack_cell(trans.description, ord));
  if (block::gen::t_TrComputePhase.get_tag(*ord.compute_ph) == block::gen::TrComputePhase::tr_phase_compute_vm) {
    block::gen::TrComputePhase::Record_tr_phase_compute_vm compute;
    CHECK(tlb::csr_unpack(ord.compute_ph, compute));
    tx.vm_ran = true;
    tx.compute_success = compute.success;
    tx.exit_code = compute.r1.exit_code;
    tx.gas_used = static_cast<td::int64>(block::tlb::t_VarUInteger_7.as_uint(*compute.r1.gas_used));
  }
  if (ord.action->prefetch_ulong(1) == 1) {
    block::gen::TrActionPhase::Record action;
    CHECK(tlb::unpack_cell(ord.action->prefetch_ref(), action));
    tx.action_success = action.success;
  }
  tx.bounce_phase = ord.bounce->prefetch_ulong(1) == 1;
  return tx;
}

// Accounts of one shard and the messages between them, run one transaction at
// a time in the order they were sent.
class Chain {
 public:
  Chain() {
    use_config(fee_fixture::tos_versioned_config_boc());
  }
  ~Chain() {
    transaction_emulator_destroy(emulator_);
  }
  Chain(const Chain &) = delete;
  Chain &operator=(const Chain &) = delete;

  void use_config(const std::string &config_boc) {
    if (emulator_ != nullptr) {
      transaction_emulator_destroy(emulator_);
    }
    emulator_ = transaction_emulator_create(config_boc.c_str(), 0);
    CHECK(emulator_ != nullptr);
    CHECK(transaction_emulator_set_unixtime(emulator_, now_));
  }

  void set_now(td::uint32 now) {
    now_ = now;
    CHECK(transaction_emulator_set_unixtime(emulator_, now_));
  }

  // A message a holder sends, carrying the forward fee the holder's own
  // transaction would have written into its header.
  td::Ref<vm::Cell> holder_message(const block::StdAddress &from, const block::StdAddress &to, td::uint64 value,
                                   td::Ref<vm::Cell> body, td::Ref<vm::Cell> init = {}) const {
    vm::CellStorageStat stat;
    if (init.not_null()) {
      CHECK(stat.add_used_storage(init).is_ok());
    }
    CHECK(stat.add_used_storage(body).is_ok());
    const auto &prices = basechain_msg_prices();
    const auto total = prices.compute_fwd_fees(stat.cells, stat.bits);
    vm::CellBuilder cb;
    cb.store_long(0b0110, 4);  // int_msg_info$0, ihr_disabled, bounce, not bounced
    store_std_address(cb, from);
    store_std_address(cb, to);
    store_coins(cb, value);
    cb.store_long(0, 1);  // no extra currencies
    store_coins(cb, 0);
    store_coins(cb, total - prices.get_first_part(total));
    cb.store_long(static_cast<long long>(lt_), 64).store_long(kNow, 32);
    if (init.not_null()) {
      cb.store_long(0b11, 2).store_ref(init);
    } else {
      cb.store_long(0, 1);
    }
    cb.store_long(1, 1).store_ref(std::move(body));
    return cb.finalize();
  }

  void send(td::Ref<vm::Cell> message) {
    queue_.push_back(parse_internal(std::move(message)));
  }

  // Runs the next queued message on its account; false when nothing is left.
  bool step() {
    while (!queue_.empty()) {
      auto next = queue_.front();
      queue_.pop_front();
      if (is_holder(next.to)) {
        received.push_back(next);
        continue;
      }
      auto tx = execute(next);
      for (const auto &out : tx.out) {
        queue_.push_back(out);
      }
      transactions.push_back(std::move(tx));
      return true;
    }
    return false;
  }

  void settle() {
    while (step()) {
    }
  }

  void run(td::Ref<vm::Cell> message) {
    send(std::move(message));
    settle();
  }

  bool exists(const block::StdAddress &address) const {
    auto it = accounts_.find(key(address));
    if (it == accounts_.end()) {
      return false;
    }
    block::gen::ShardAccount::Record shard;
    CHECK(tlb::unpack_cell(from_boc64(it->second), shard));
    if (block::gen::t_Account.get_tag(vm::load_cell_slice(shard.account)) != block::gen::Account::account) {
      return false;
    }
    return storage(address).state->prefetch_ulong(1) == 1;  // account_active
  }

  td::RefInt256 balance(const block::StdAddress &address) const {
    auto it = accounts_.find(key(address));
    if (it == accounts_.end()) {
      return td::zero_refint();
    }
    block::CurrencyCollection value;
    CHECK(value.unpack(storage(address).balance));
    return value.tomis;
  }

  // The (cells, bits) the storage phase charges this account for.
  std::pair<td::int64, td::int64> storage_used(const block::StdAddress &address) const {
    block::gen::StorageInfo::Record info;
    CHECK(tlb::csr_unpack(account(address).storage_stat, info));
    block::gen::StorageUsed::Record used;
    CHECK(tlb::csr_unpack(info.used, used));
    return {static_cast<td::int64>(block::tlb::t_VarUInteger_7.as_uint(*used.cells)),
            static_cast<td::int64>(block::tlb::t_VarUInteger_7.as_uint(*used.bits))};
  }

  // Storage fees the account owes and could not pay.
  td::RefInt256 storage_due(const block::StdAddress &address) const {
    block::gen::StorageInfo::Record info;
    CHECK(tlb::csr_unpack(account(address).storage_stat, info));
    auto due = info.due_payment.write();
    if (due.fetch_ulong(1) == 0) {
      return td::zero_refint();
    }
    return block::tlb::t_Tomis.as_integer_skip(due);
  }

  td::Ref<vm::Stack> get(const block::StdAddress &address, const char *method) const {
    auto state = storage(address).state.write();
    CHECK(state.fetch_ulong(1) == 1);  // account_active
    block::gen::StateInit::Record init;
    CHECK(tlb::csr_unpack(td::Ref<vm::CellSlice>(true, state), init));
    auto contract =
        tos::SmartContract::create(tos::SmartContract::State{init.code->prefetch_ref(), init.data->prefetch_ref()});
    auto answer = contract.write().run_get_method(tos::SmartContract::Args()
                                                      .set_method_id(td::Slice(method))
                                                      .set_address(address)
                                                      .set_now(static_cast<int>(kNow))
                                                      .set_config(config()));
    CHECK(answer.code == 0);
    return answer.stack;
  }

  td::RefInt256 jetton_balance(const block::StdAddress &holder) const {
    if (!exists(wallet_of(holder))) {
      return td::zero_refint();
    }
    auto stack = get(wallet_of(holder), "get_wallet_data");
    CHECK(stack->depth() == 4);
    stack.write().pop_many(3);
    return stack.write().pop_int();
  }

  td::RefInt256 total_supply() const {
    auto stack = get(minter(), "get_jetton_data");
    CHECK(stack->depth() == 5);
    stack.write().pop_many(4);
    return stack.write().pop_int();
  }

  // Deploys the minter, administered by owner(), with about `value` on its balance.
  void deploy_minter(td::uint64 value = 10 * kCoin) {
    run(holder_message(owner(), minter(), value, top_up_body(), minter_init()));
    CHECK(exists(minter()));
  }

  void mint(const Mint &m, td::uint64 value) {
    run(holder_message(owner(), minter(), value, mint_body(m)));
  }

  // The first transaction that ran on `account` for an inbound `op` (kBounced
  // for a bounce), from transaction `from_index` on.
  const Tx &first(const block::StdAddress &account, td::uint32 op, size_t from_index) const {
    for (size_t i = from_index; i < transactions.size(); i++) {
      if (transactions[i].account == account && transactions[i].in_op == op) {
        return transactions[i];
      }
    }
    LOG(FATAL) << "no transaction for op " << op;
    UNREACHABLE();
  }

  // Messages delivered to `holder` with `op`, from delivery `from_index` on.
  std::vector<Delivered> received_by(const block::StdAddress &holder, td::uint32 op, size_t from_index) const {
    std::vector<Delivered> found;
    for (size_t i = from_index; i < received.size(); i++) {
      if (received[i].to == holder && !received[i].bounced && op_of(received[i].body) == op) {
        found.push_back(received[i]);
      }
    }
    return found;
  }

  std::vector<Tx> transactions;
  std::vector<Delivered> received;

 private:
  static std::string key(const block::StdAddress &address) {
    return address.addr.as_slice().str();
  }

  block::gen::Account::Record_account account(const block::StdAddress &address) const {
    auto it = accounts_.find(key(address));
    CHECK(it != accounts_.end());
    block::gen::ShardAccount::Record shard;
    CHECK(tlb::unpack_cell(from_boc64(it->second), shard));
    block::gen::Account::Record_account record;
    CHECK(tlb::unpack_cell(shard.account, record));
    return record;
  }

  block::gen::AccountStorage::Record storage(const block::StdAddress &address) const {
    block::gen::AccountStorage::Record record;
    CHECK(tlb::csr_unpack(account(address).storage, record));
    return record;
  }

  std::string shard_account_of(const block::StdAddress &address) const {
    auto it = accounts_.find(key(address));
    if (it != accounts_.end()) {
      return it->second;
    }
    td::Ref<vm::Cell> none;
    CHECK(block::gen::Account().cell_pack_account_none(none));
    vm::CellBuilder shard;
    shard.store_ref(none).store_bits(td::Bits256::zero().as_bitslice()).store_long(0, 64);
    return boc64(shard.finalize());
  }

  Tx execute(const Delivered &message) {
    lt_ += 1'000'000;
    CHECK(transaction_emulator_set_lt(emulator_, lt_));
    auto raw = transaction_emulator_emulate_transaction(emulator_, shard_account_of(message.to).c_str(),
                                                        boc64(message.message).c_str());
    std::string text(raw);
    string_destroy(raw);
    auto json = td::json_decode(td::MutableSlice(text));
    CHECK(json.is_ok());
    auto value = json.move_as_ok();
    auto &obj = value.get_object();
    if (!obj.get_optional_bool_field("success").move_as_ok()) {
      LOG(FATAL) << "emulation refused: " << text;
    }
    accounts_[key(message.to)] = obj.get_required_string_field("shard_account").move_as_ok();
    auto tx = from_boc64(obj.get_required_string_field("transaction").move_as_ok());
    return parse_transaction(message.to, tx, message.bounced ? kBounced : op_of(message.body));
  }

  void *emulator_ = nullptr;
  td::uint32 now_ = kNow;
  td::uint64 lt_ = 1'000'000;
  std::deque<Delivered> queue_;
  std::map<std::string, std::string> accounts_;  // by address hash (one workchain)
};

// --- fee profile ------------------------------------------------------------

// The shared config with message prices raised 20 times, parsed.
std::shared_ptr<const block::Config> raised_config() {
  static std::shared_ptr<const block::Config> cfg = [] {
    const auto boc = config_with_message_prices_times(20);
    auto raw = static_cast<block::Config *>(emulator_config_create(boc.c_str()));
    CHECK(raw != nullptr);
    return std::shared_ptr<const block::Config>(raw);
  }();
  return cfg;
}

td::Ref<vm::Stack> wallet_getter(const char *method, std::vector<vm::StackEntry> args,
                                 std::shared_ptr<const block::Config> under = config()) {
  auto contract = tos::SmartContract::create(
      tos::SmartContract::State{wallet_code(), wallet_data(td::make_refint(kJettons), owner())});
  auto answer = contract.write().run_get_method(tos::SmartContract::Args()
                                                    .set_method_id(td::Slice(method))
                                                    .set_stack(std::move(args))
                                                    .set_address(wallet_of(owner()))
                                                    .set_now(static_cast<int>(kNow))
                                                    .set_config(std::move(under)));
  CHECK(answer.code == 0);
  return answer.stack;
}

FeeProfile contract_profile() {
  auto stack = wallet_getter("get_fee_profile", {});
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

// Value a transfer must carry strictly more than.
td::uint64 transfer_quote(td::uint64 forward_amount, td::uint64 fwd_fee,
                          std::shared_ptr<const block::Config> under = config()) {
  auto stack =
      wallet_getter("get_transfer_fee", {td::make_refint(forward_amount), td::make_refint(fwd_fee)}, std::move(under));
  CHECK(stack->depth() == 1);
  return static_cast<td::uint64>(stack.write().pop_long());
}

td::uint64 burn_quote() {
  auto stack = wallet_getter("get_burn_fee", {});
  CHECK(stack->depth() == 1);
  return static_cast<td::uint64>(stack.write().pop_long());
}

// Forward fees charge a message's cells and bits excluding its root cell
// (the lump price covers the root): skip both the root's cell (mask 1) and
// its bits (mask 2).
vm::CellStorageStat forwarded_part_of(td::Ref<vm::Cell> message) {
  vm::CellStorageStat stat;
  CHECK(stat.compute_used_storage(std::move(message), true, 3).is_ok());
  return stat;
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

// The reserve a receiving wallet keeps for storage.
td::RefInt256 wallet_min_storage_fee() {
  auto p = contract_profile();
  return storage_fee(p.min_storage_seconds, p.wallet_storage_bits, p.wallet_storage_cells);
}

// A chain with the minter deployed and `jettons` minted to owner().
std::unique_ptr<Chain> funded_chain(const td::RefInt256 &jettons = td::make_refint(kJettons)) {
  auto chain = std::make_unique<Chain>();
  chain->deploy_minter();
  Mint m;
  m.jettons = jettons;
  m.wallet_value = kCoin;
  chain->mint(m, 2 * kCoin);
  CHECK(td::cmp(chain->jetton_balance(owner()), jettons) == 0);
  return chain;
}

void note_gas(td::int64 &slot, const Tx &tx) {
  CHECK(tx.vm_ran && tx.compute_success && tx.action_success);
  slot = std::max(slot, tx.gas_used);
}

void note_size(td::int64 &bits, td::int64 &cells, const vm::CellStorageStat &stat) {
  bits = std::max(bits, static_cast<td::int64>(stat.bits));
  cells = std::max(cells, static_cast<td::int64>(stat.cells));
}

FeeProfile measure() {
  FeeProfile m{};

  // Transfers in every shape the receive path branches on: with and without a
  // notification and a response, to a new wallet and to an existing one.
  auto chain = funded_chain();
  for (td::uint64 forward : {0ULL, 1ULL}) {
    for (bool response : {false, true}) {
      for (int repeat = 0; repeat < 2; repeat++) {
        const size_t from = chain->transactions.size();
        Transfer t;
        t.forward_amount = forward;
        t.with_response = response;
        chain->run(chain->holder_message(owner(), wallet_of(owner()), kCoin, transfer_body(t)));
        const auto &send = chain->first(wallet_of(owner()), kOpTransfer, from);
        note_gas(m.send_transfer_gas, send);
        note_gas(m.receive_transfer_gas, chain->first(wallet_of(recipient()), kOpInternalTransfer, from));
        // The StateInit every internal transfer carries.
        CHECK(send.out.size() == 1 && send.out[0].init.not_null());
        vm::CellStorageStat carried;
        CHECK(carried.compute_used_storage(send.out[0].init).is_ok());
        note_size(m.wallet_init_state_bits, m.wallet_init_state_cells, carried);
      }
    }
  }
  // A mint is received through the same path.
  for (bool response : {false, true}) {
    const size_t from = chain->transactions.size();
    Mint mint;
    mint.wallet_value = kCoin;
    mint.with_response = response;
    mint.forward_amount = 1;
    chain->mint(mint, 2 * kCoin);
    note_gas(m.receive_transfer_gas, chain->first(wallet_of(owner()), kOpInternalTransfer, from));
  }

  // Storage and burns at the largest amount a Coins field holds.
  auto big = funded_chain(max_coins());
  // Storage as the storage phase charges it, widened to the largest TOS
  // balance the account could hold (the Grams field grows with the balance).
  const auto used = big->storage_used(wallet_of(owner()));
  const auto tos_balance = big->balance(wallet_of(owner()));
  const td::int64 balance_bits = 4 + 8 * ((static_cast<td::int64>(tos_balance->bit_size(false)) + 7) / 8);
  m.wallet_storage_cells = used.first;
  m.wallet_storage_bits = used.second + (4 + 8 * 15) - balance_bits;
  {
    const size_t from = big->transactions.size();
    Transfer t;
    t.amount = max_coins();
    t.forward_amount = 1;
    big->run(big->holder_message(owner(), wallet_of(owner()), kCoin, transfer_body(t)));
    note_gas(m.send_transfer_gas, big->first(wallet_of(owner()), kOpTransfer, from));
    note_gas(m.receive_transfer_gas, big->first(wallet_of(recipient()), kOpInternalTransfer, from));
  }
  CHECK(td::cmp(big->jetton_balance(recipient()), max_coins()) == 0);
  for (auto response : {Response::kNone, Response::kStd, Response::kLargest}) {
    const size_t from = big->transactions.size();
    const auto amount = response == Response::kLargest ? big->jetton_balance(recipient()) : td::make_refint(1);
    big->run(big->holder_message(recipient(), wallet_of(recipient()), kCoin, burn_body(amount, response)));
    const auto &burn = big->first(wallet_of(recipient()), kOpBurn, from);
    note_gas(m.send_burn_gas, burn);
    note_gas(m.receive_burn_gas, big->first(minter(), kOpBurnNotification, from));
    CHECK(burn.out.size() == 1);
    note_size(m.burn_notification_bits, m.burn_notification_cells, forwarded_part_of(burn.out[0].message));
  }
  CHECK(big->total_supply()->sgn() == 0);
  return m;
}

void check_within(const char *name, td::int64 measured, td::int64 profile, td::int64 slack) {
  LOG(INFO) << "jetton-wallet fee profile " << name << ": measured=" << measured << " profile=" << profile;
  CHECK(measured > 0);
  CHECK(measured <= profile);
  CHECK(profile <= measured + std::max(measured / 4, slack));
}

// A transfer request whose value is exactly the quote for its own forward fee
// (`plus` 0) or above it.
td::Ref<vm::Cell> priced_transfer(const Chain &chain, const Transfer &t, td::uint64 plus) {
  auto probe = chain.holder_message(owner(), wallet_of(owner()), 0, transfer_body(t));
  CHECK(original_fee_of(probe) > 0);
  const auto quote = transfer_quote(t.forward_amount, original_fee_of(probe));
  return chain.holder_message(owner(), wallet_of(owner()), quote + plus, transfer_body(t));
}

// The value a mint must send to the new wallet: the quote for the mint
// request's own forward fee, plus `plus`. The request carries that value, so
// its size and fee depend on it; iterate to the fixed point.
td::uint64 priced_mint_value(const Chain &chain, Mint m, td::uint64 plus) {
  for (int round = 0; round < 8; round++) {
    auto probe = chain.holder_message(owner(), minter(), 0, mint_body(m));
    CHECK(original_fee_of(probe) > 0);
    const auto value = transfer_quote(m.forward_amount, original_fee_of(probe)) + plus;
    if (value == m.wallet_value) {
      return value;
    }
    m.wallet_value = value;
  }
  LOG(FATAL) << "mint quote does not converge";
  UNREACHABLE();
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
  CHECK(gas_prices.is_ok());
  const auto &gas = gas_prices.ok();
  const auto &msg = basechain_msg_prices();

  auto init_overhead = ceil_shift16(td::make_refint(msg.bit_price) * td::make_refint(p.wallet_init_state_bits) +
                                    td::make_refint(msg.cell_price) * td::make_refint(p.wallet_init_state_cells));
  auto min_storage = storage_fee(p.min_storage_seconds, p.wallet_storage_bits, p.wallet_storage_cells);
  auto compute = gas_fee(gas, p.send_transfer_gas) + gas_fee(gas, p.receive_transfer_gas);

  const td::uint64 fwd_fee = 7'000'000;
  auto without_forward = td::make_refint(fwd_fee) + init_overhead + compute + min_storage;
  CHECK(td::cmp(td::make_refint(transfer_quote(0, fwd_fee)), without_forward) == 0);
  const td::uint64 forward = 50'000'000;
  auto with_forward = td::make_refint(forward) + td::make_refint(2 * fwd_fee) + init_overhead + compute + min_storage;
  CHECK(td::cmp(td::make_refint(transfer_quote(forward, fwd_fee)), with_forward) == 0);

  auto burn = msg.compute_fwd_fees256(p.burn_notification_cells, p.burn_notification_bits) +
              gas_fee(gas, p.send_burn_gas) + gas_fee(gas, p.receive_burn_gas);
  CHECK(td::cmp(td::make_refint(burn_quote()), burn) == 0);
}

// A transfer carrying exactly the quote is refused and changes nothing; one
// unit more completes every hop: the new wallet is credited and keeps exactly
// its storage reserve, the notification carries the forward amount, and the
// rest comes back as excesses.
TEST(JettonWalletFeeProfile, TransferAtTheQuoteBoundary) {
  auto chain = funded_chain();
  Transfer t;
  t.forward_amount = 10'000'000;
  t.payload_cells = 3;

  size_t from = chain->transactions.size();
  chain->run(priced_transfer(*chain, t, 0));
  const auto &refused = chain->first(wallet_of(owner()), kOpTransfer, from);
  CHECK(refused.exit_code == kThrowInsufficientTransferValue);
  CHECK(refused.bounce_phase);
  CHECK(!chain->exists(wallet_of(recipient())));
  CHECK(td::cmp(chain->jetton_balance(owner()), td::make_refint(kJettons)) == 0);

  from = chain->transactions.size();
  const size_t delivered = chain->received.size();
  chain->run(priced_transfer(*chain, t, 1));
  CHECK(chain->first(wallet_of(owner()), kOpTransfer, from).action_success);
  const auto &receive = chain->first(wallet_of(recipient()), kOpInternalTransfer, from);
  CHECK(receive.compute_success && receive.action_success);
  CHECK(td::cmp(chain->jetton_balance(recipient()), td::make_refint(1000)) == 0);
  CHECK(td::cmp(chain->jetton_balance(owner()) + chain->jetton_balance(recipient()), chain->total_supply()) == 0);
  CHECK(td::cmp(chain->balance(wallet_of(recipient())), wallet_min_storage_fee()) == 0);
  auto notifications = chain->received_by(recipient(), kOpTransferNotification, delivered);
  CHECK(notifications.size() == 1);
  CHECK(td::cmp(notifications[0].value, td::make_refint(t.forward_amount)) == 0);
  auto excesses = chain->received_by(owner(), kOpExcesses, delivered);
  CHECK(excesses.size() == 1 && excesses[0].value->sgn() > 0);
}

// A wallet that already holds more than its reserve keeps exactly what it held:
// everything the transfer brought beyond the fees goes back as excesses.
TEST(JettonWalletFeeProfile, ExcessesReturnEverythingTheWalletDidNotHold) {
  auto chain = funded_chain();
  Transfer t;
  t.forward_amount = 1;
  chain->run(chain->holder_message(owner(), wallet_of(owner()), kCoin, transfer_body(t)));
  chain->run(chain->holder_message(recipient(), wallet_of(recipient()), kCoin, top_up_body()));
  const auto held = chain->balance(wallet_of(recipient()));
  CHECK(td::cmp(held, wallet_min_storage_fee()) > 0);

  const size_t delivered = chain->received.size();
  chain->run(chain->holder_message(owner(), wallet_of(owner()), kCoin, transfer_body(t)));
  CHECK(td::cmp(chain->balance(wallet_of(recipient())), held) == 0);
  CHECK(td::cmp(chain->jetton_balance(recipient()), td::make_refint(2000)) == 0);
  CHECK(chain->received_by(owner(), kOpExcesses, delivered).size() == 1);
}

// A wallet that outlived its storage reserve owes storage fees it could not
// pay. A transfer arriving then keeps that debt on the balance, so the next
// storage phase can settle it, rather than refunding it as excesses.
TEST(JettonWalletFeeProfile, ExcessesLeaveStorageDebtOnTheWallet) {
  auto chain = funded_chain();
  Transfer t;
  t.forward_amount = 1;
  chain->run(priced_transfer(*chain, t, 1));
  CHECK(td::cmp(chain->balance(wallet_of(recipient())), wallet_min_storage_fee()) == 0);

  chain->set_now(kNow + 12 * 365 * 24 * 3600);
  chain->run(chain->holder_message(owner(), wallet_of(owner()), kCoin, transfer_body(t)));
  const auto due = chain->storage_due(wallet_of(recipient()));
  CHECK(td::cmp(due, wallet_min_storage_fee()) > 0);
  CHECK(td::cmp(chain->jetton_balance(recipient()), td::make_refint(2000)) == 0);
  CHECK(td::cmp(chain->balance(wallet_of(recipient())), due) == 0);
}

// Message prices rise between the two hops of a transfer, so the receiving
// wallet cannot pay for the notification. The internal transfer bounces back
// and the sending wallet restores the amount: no jettons are lost.
TEST(JettonWalletFeeProfile, UnaffordableNotificationBouncesTheTransfer) {
  auto chain = funded_chain();
  Transfer t;
  t.forward_amount = 10'000'000;
  t.payload_cells = 200;
  chain->send(priced_transfer(*chain, t, 1));
  const size_t from = chain->transactions.size();
  CHECK(chain->step());  // the sending wallet, at the old prices
  CHECK(chain->first(wallet_of(owner()), kOpTransfer, from).action_success);
  CHECK(td::cmp(chain->jetton_balance(owner()), td::make_refint(kJettons - 1000)) == 0);
  chain->use_config(config_with_message_prices_times(20));
  chain->settle();

  const auto &receive = chain->first(wallet_of(recipient()), kOpInternalTransfer, from);
  CHECK(receive.compute_success && !receive.action_success && receive.bounce_phase);
  CHECK(chain->first(wallet_of(owner()), kBounced, from).compute_success);
  CHECK(chain->jetton_balance(recipient())->sgn() == 0);
  CHECK(td::cmp(chain->jetton_balance(owner()), td::make_refint(kJettons)) == 0);
  CHECK(td::cmp(chain->total_supply(), td::make_refint(kJettons)) == 0);
}

// Message prices rise after the holder sent a transfer request but before the
// wallet runs it. The wallet prices the request by the fee its sender paid, so
// it accepts it, but cannot then pay for the internal transfer: the request
// bounces back with its value instead of leaving it on the wallet.
TEST(JettonWalletFeeProfile, TransferTheWalletCannotSendBouncesTheRequest) {
  auto chain = funded_chain();
  Transfer t;
  t.forward_amount = 10'000'000;
  t.payload_cells = 200;
  // Priced as the wallet will price it: the old fee in the header, the new
  // prices for everything the wallet computes itself.
  auto probe = chain->holder_message(owner(), wallet_of(owner()), 0, transfer_body(t));
  const auto quote = transfer_quote(t.forward_amount, original_fee_of(probe), raised_config());
  auto request = chain->holder_message(owner(), wallet_of(owner()), quote + 1, transfer_body(t));
  chain->use_config(config_with_message_prices_times(20));
  const auto held = chain->balance(wallet_of(owner()));
  const size_t from = chain->transactions.size();
  const size_t delivered = chain->received.size();
  chain->run(request);

  const auto &send = chain->first(wallet_of(owner()), kOpTransfer, from);
  CHECK(send.compute_success && !send.action_success && send.bounce_phase);
  CHECK(td::cmp(chain->jetton_balance(owner()), td::make_refint(kJettons)) == 0);
  CHECK(!chain->exists(wallet_of(recipient())));
  CHECK(td::cmp(chain->balance(wallet_of(owner())), held) == 0);
  size_t bounced = 0;
  for (size_t i = delivered; i < chain->received.size(); i++) {
    bounced += chain->received[i].to == owner() && chain->received[i].bounced;
  }
  CHECK(bounced == 1);
}

// The burn quote covers the notification at the largest response address the
// wallet accepts, so a burn naming one completes at one unit above the quote.
TEST(JettonWalletFeeProfile, BurnWithTheLargestResponseCompletes) {
  auto chain = funded_chain();
  const size_t from = chain->transactions.size();
  chain->run(chain->holder_message(owner(), wallet_of(owner()), burn_quote() + 1,
                                   burn_body(td::make_refint(1000), Response::kLargest)));
  CHECK(chain->first(wallet_of(owner()), kOpBurn, from).action_success);
  const auto &received = chain->first(minter(), kOpBurnNotification, from);
  CHECK(received.compute_success && received.action_success);
  CHECK(td::cmp(chain->total_supply(), td::make_refint(kJettons - 1000)) == 0);
}

TEST(JettonWalletFeeProfile, BurnAtTheQuoteBoundary) {
  auto chain = funded_chain();
  const auto quote = burn_quote();
  size_t from = chain->transactions.size();
  chain->run(chain->holder_message(owner(), wallet_of(owner()), quote, burn_body(td::make_refint(1000))));
  CHECK(chain->first(wallet_of(owner()), kOpBurn, from).exit_code == kThrowInsufficientBurnValue);
  CHECK(td::cmp(chain->total_supply(), td::make_refint(kJettons)) == 0);

  from = chain->transactions.size();
  const size_t delivered = chain->received.size();
  chain->run(chain->holder_message(owner(), wallet_of(owner()), quote + 1, burn_body(td::make_refint(1000))));
  const auto &received = chain->first(minter(), kOpBurnNotification, from);
  CHECK(received.compute_success && received.action_success);
  CHECK(td::cmp(chain->total_supply(), td::make_refint(kJettons - 1000)) == 0);
  CHECK(td::cmp(chain->jetton_balance(owner()), td::make_refint(kJettons - 1000)) == 0);
  CHECK(chain->received_by(owner(), kOpExcesses, delivered).size() == 1);
}

// The minter prices a mint with the wallet's own transfer quote, against the
// value it is told to send to the new wallet.
TEST(JettonWalletFeeProfile, MintAtTheQuoteBoundary) {
  Chain chain;
  chain.deploy_minter();
  Mint m;
  m.forward_amount = 10'000'000;
  m.payload_cells = 3;
  m.wallet_value = priced_mint_value(chain, m, 0);

  size_t from = chain.transactions.size();
  chain.mint(m, 2 * kCoin);
  CHECK(chain.first(minter(), kOpMint, from).exit_code == kThrowInsufficientTransferValue);
  CHECK(chain.total_supply()->sgn() == 0);
  CHECK(!chain.exists(wallet_of(owner())));

  m.wallet_value = priced_mint_value(chain, m, 1);
  from = chain.transactions.size();
  const size_t delivered = chain.received.size();
  chain.mint(m, 2 * kCoin);
  const auto &receive = chain.first(wallet_of(owner()), kOpInternalTransfer, from);
  CHECK(receive.compute_success && receive.action_success);
  CHECK(td::cmp(chain.total_supply(), td::make_refint(kJettons)) == 0);
  CHECK(td::cmp(chain.jetton_balance(owner()), td::make_refint(kJettons)) == 0);
  CHECK(td::cmp(chain.balance(wallet_of(owner())), wallet_min_storage_fee()) == 0);
  CHECK(chain.received_by(owner(), kOpTransferNotification, delivered).size() == 1);
}

// The minter prices a mint at basechain rates, so it refuses to mint to a
// holder on any other workchain.
TEST(JettonWalletFeeProfile, MintToAnotherWorkchainIsRefused) {
  Chain chain;
  chain.deploy_minter();
  Mint m;
  m.to = owner();
  m.to.workchain = -1;
  m.wallet_value = kCoin;
  const size_t from = chain.transactions.size();
  chain.mint(m, 2 * kCoin);
  CHECK(chain.first(minter(), kOpMint, from).exit_code == 333);
  CHECK(chain.total_supply()->sgn() == 0);
}

// A mint told to send more than its message brought must not make up the
// difference from the minter's own balance: the mint bounces whole.
TEST(JettonWalletFeeProfile, MintCannotSpendTheMinterBalance) {
  Chain chain;
  chain.deploy_minter(100 * kCoin);
  const auto before = chain.balance(minter());
  Mint m;
  m.wallet_value = 50 * kCoin;
  const size_t from = chain.transactions.size();
  chain.mint(m, kCoin / 10);
  const auto &mint = chain.first(minter(), kOpMint, from);
  CHECK(mint.compute_success && !mint.action_success && mint.bounce_phase);
  CHECK(td::cmp(chain.balance(minter()), before) >= 0);
  CHECK(chain.total_supply()->sgn() == 0);
  CHECK(!chain.exists(wallet_of(owner())));
}

// A mint whose internal transfer bounces (here: message prices rise before the
// new wallet runs, so it cannot pay its notification) credits nobody, and the
// minter takes the amount back out of the total supply.
TEST(JettonWalletFeeProfile, BouncedMintLeavesTheSupplyUnchanged) {
  Chain chain;
  chain.deploy_minter();
  Mint m;
  m.forward_amount = 10'000'000;
  m.payload_cells = 200;
  m.wallet_value = priced_mint_value(chain, m, 1);
  chain.send(chain.holder_message(owner(), minter(), 2 * kCoin, mint_body(m)));
  const size_t from = chain.transactions.size();
  CHECK(chain.step());  // the minter, at the old prices
  CHECK(chain.first(minter(), kOpMint, from).action_success);
  CHECK(td::cmp(chain.total_supply(), td::make_refint(kJettons)) == 0);
  chain.use_config(config_with_message_prices_times(20));
  chain.settle();

  const auto &receive = chain.first(wallet_of(owner()), kOpInternalTransfer, from);
  CHECK(receive.compute_success && !receive.action_success && receive.bounce_phase);
  CHECK(chain.first(minter(), kBounced, from).compute_success);
  CHECK(chain.total_supply()->sgn() == 0);
  CHECK(chain.jetton_balance(owner())->sgn() == 0);
}

TEST(JettonWalletFeeProfile, TopUpIsAcceptedByWalletAndMinter) {
  auto chain = funded_chain();
  for (const auto &account : {wallet_of(owner()), minter()}) {
    const auto before = chain->balance(account);
    const size_t from = chain->transactions.size();
    chain->run(chain->holder_message(owner(), account, kCoin, top_up_body()));
    const auto &tx = chain->first(account, kOpTopUp, from);
    CHECK(tx.compute_success && tx.action_success && !tx.bounce_phase);
    CHECK(td::cmp(chain->balance(account), before + td::make_refint(kCoin / 2)) > 0);
  }
}
