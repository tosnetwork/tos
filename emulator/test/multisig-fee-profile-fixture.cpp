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
// Multisig fee profile: measured against the build, priced by the config.
//
// crypto/smartcont/multisig-wallet-code.fc refuses a proposal that does not
// prepay the order's whole path to execution. Prices come from the
// configuration at run time; the quantities are constants in fee_profile():
// gas of four compute phases, how the parent's two phases grow per action and
// per signer an update installs, and the fixed bits and cells of two messages
// and the order's state beyond the action and the signer set. A change to
// either contract can make them stale without any functional test noticing,
// and a stale profile lets proposals underfund their orders.
//
// This fixture runs the parent and the order on the C++ TVM through the whole
// path (proposal, order init, the approval that fires, the parent's execute):
//   1. at the base point (3 signers, 1 action), and between two sizes to get
//      the per-action and per-signer slopes, requiring
//      measured <= profile <= measured + headroom for every quantity;
//   2. at the largest wallets and orders the contracts allow (255 signers,
//      255 actions, an update installing 255 signers), requiring the parent's
//      own quote (get_order_estimate) to cover the whole path's actual cost:
//      every measured compute phase, both measured messages and the order's
//      measured state over its lifetime, priced from the configuration. This
//      is the property the profile exists for, and the one a profile measured
//      at a single small point silently lacked.
//
// When check 1 fails after an intentional change, update fee_profile() from
// the "measured" lines this test prints.
// =============================================================================

#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
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

#ifndef MULTISIG_WALLET_BOC
#error "MULTISIG_WALLET_BOC must be defined by CMake"
#endif
#ifndef MULTISIG_ORDER_BOC
#error "MULTISIG_ORDER_BOC must be defined by CMake"
#endif

using fee_fixture::config;

constexpr td::uint32 kOpNewOrder = 0x27bace9f;
constexpr td::uint32 kOpApprove = 0x9c205aee;
constexpr td::uint32 kActionSend = 0x94f8724f;
constexpr td::uint32 kActionUpdate = 0xe9973598;
constexpr td::uint64 kCoin = 1'000'000'000;
constexpr td::int32 kNow = 1'800'000'000;
constexpr td::uint64 kNextSeqno = ~0ULL;

enum Field {
  kParentNewOrderGas,
  kOrderInitGas,
  kOrderExecuteGas,
  kParentExecuteGas,
  kInitMessageBits,
  kInitMessageCells,
  kOrderStateBits,
  kOrderStateCells,
  kExecuteMessageBits,
  kExecuteMessageCells,
  kParentNewOrderGasPerAction,
  kParentExecuteGasPerAction,
  kParentGasPerUpdatedSigner,
  kFieldCount
};

const char *const kFieldNames[kFieldCount] = {"parentNewOrderGas",
                                              "orderInitGas",
                                              "orderExecuteGas",
                                              "parentExecuteGas",
                                              "initMessageBits",
                                              "initMessageCells",
                                              "orderStateBits",
                                              "orderStateCells",
                                              "executeMessageBits",
                                              "executeMessageCells",
                                              "parentNewOrderGasPerAction",
                                              "parentExecuteGasPerAction",
                                              "parentGasPerUpdatedSigner"};

td::Ref<vm::Cell> load_code_boc(const char *path) {
  auto buf = td::read_file(td::CSlice{path});
  CHECK(buf.is_ok());
  auto cell = vm::std_boc_deserialize(buf.move_as_ok().as_slice());
  CHECK(cell.is_ok());
  return cell.move_as_ok();
}

td::Ref<vm::Cell> wallet_code() {
  static auto code = load_code_boc(MULTISIG_WALLET_BOC);
  return code;
}

td::Ref<vm::Cell> order_code() {
  static auto code = load_code_boc(MULTISIG_ORDER_BOC);
  return code;
}

block::StdAddress std_address(unsigned char a, unsigned char b = 0) {
  block::StdAddress address;
  address.workchain = 0;
  address.addr.as_slice().fill(a);
  address.addr.as_slice()[31] = b;
  return address;
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

block::StdAddress parent() {
  return std_address(0x50);
}

block::StdAddress signer(int index) {
  return std_address(0x10, static_cast<unsigned char>(index));
}

block::StdAddress proposer() {
  return std_address(0x40);
}

td::Ref<vm::Cell> signer_dict(int count, unsigned char tag = 0x10) {
  vm::Dictionary dict{8};
  for (int i = 0; i < count; i++) {
    vm::CellBuilder value;
    store_std_address(value, std_address(tag, static_cast<unsigned char>(i)));
    td::BitArray<8> key;
    key.store_ulong(i);
    CHECK(dict.set_builder(key.bits(), 8, value));
  }
  return dict.get_root_cell();
}

td::Ref<vm::Cell> transfer() {
  vm::CellBuilder msg;
  msg.store_long(0b0100, 4).store_zeroes(2);  // int_msg_info$0 ihr_disabled, src addr_none
  store_std_address(msg, std_address(0x77));
  store_coins(msg, kCoin / 1000);
  msg.store_zeroes(1 + 4 + 4 + 64 + 32 + 1 + 1);
  return msg.finalize();
}

// `sends` send actions, optionally preceded by `updates` updates that each install the
// same dictionaries of `install` signers and `install_proposers` proposers.
td::Ref<vm::Cell> actions(int sends, int install = 0, int install_proposers = 0, int updates = 1) {
  td::Ref<vm::Cell> next;
  for (int i = 0; i < sends; i++) {
    vm::CellBuilder action;
    action.store_long(kActionSend, 32).store_long(1, 8).store_ref(transfer());
    if (next.is_null()) {
      action.store_zeroes(1);
    } else {
      action.store_ones(1).store_ref(next);
    }
    next = action.finalize();
  }
  if (install > 0) {
    const auto signers = signer_dict(install, 0x30);
    const auto proposers = install_proposers > 0 ? signer_dict(install_proposers, 0x60) : td::Ref<vm::Cell>();
    for (int u = 0; u < updates; u++) {
      vm::CellBuilder update;
      update.store_long(kActionUpdate, 32).store_long(1, 8).store_ref(signers);
      if (proposers.not_null()) {
        update.store_ones(1).store_ref(proposers);
      } else {
        update.store_zeroes(1);
      }
      update.store_ones(1).store_ref(next);
      next = update.finalize();
    }
  }
  return next;
}

td::Ref<vm::Cell> parent_data(td::uint64 next_seqno, int signers) {
  vm::CellBuilder cb;
  cb.store_long(static_cast<long long>(next_seqno), 64).store_long(2, 8).store_long(signers, 8);
  cb.store_ref(signer_dict(signers)).store_ones(1).store_ref(signer_dict(1, 0x40)).store_ref(order_code());
  return cb.finalize();
}

tos::SmartContract::Answer run(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data, const block::StdAddress &self,
                               const block::StdAddress &sender, td::Ref<vm::Cell> body) {
  auto contract = tos::SmartContract::create(tos::SmartContract::State{std::move(code), std::move(data)});
  return contract.write().send_internal_message(std::move(body), tos::SmartContract::Args()
                                                                     .set_amount(1000 * kCoin)
                                                                     .set_balance(1000 * kCoin)
                                                                     .set_address(self)
                                                                     .set_sender_address(sender)
                                                                     .set_now(kNow)
                                                                     .set_config(config()));
}

// Outbound messages of an action list, in the order they were sent.
std::vector<td::Ref<vm::Cell>> out_messages(td::Ref<vm::Cell> list) {
  std::vector<td::Ref<vm::Cell>> messages;
  while (list.not_null()) {
    auto cs = vm::load_cell_slice(list);
    if (cs.size_refs() == 0) {
      break;
    }
    auto prev = cs.fetch_ref();
    CHECK(cs.fetch_ulong(32) == 0x0ec3c86d);
    cs.skip_first(8);
    messages.push_back(cs.fetch_ref());
    list = prev;
  }
  std::reverse(messages.begin(), messages.end());
  return messages;
}

vm::CellStorageStat storage_of(td::Ref<vm::Cell> cell) {
  vm::CellStorageStat stat;
  CHECK(stat.compute_used_storage(std::move(cell)).is_ok());
  return stat;
}

// Forward fees charge a message's cells and bits excluding its root cell.
vm::CellStorageStat forwarded_part_of(td::Ref<vm::Cell> message) {
  vm::CellStorageStat stat;
  CHECK(stat.compute_used_storage(std::move(message), true, 3).is_ok());
  return stat;
}

td::Ref<vm::Cell> body_ref(td::Ref<vm::Cell> message) {
  auto cs = vm::load_cell_slice(message);
  return cs.prefetch_ref(cs.size_refs() - 1);
}

block::StdAddress order_address() {
  vm::CellBuilder data;
  store_std_address(data, parent());
  data.store_long(0, 64);
  vm::CellBuilder init;
  init.store_long(0, 2).store_ones(1).store_ref(order_code()).store_ones(1).store_ref(data.finalize()).store_zeroes(1);
  return block::StdAddress(0, init.finalize()->get_hash().bits());
}

td::Ref<vm::Cell> order_init_data() {
  vm::CellBuilder data;
  store_std_address(data, parent());
  data.store_long(0, 64);
  return data.finalize();
}

struct Path {
  td::int64 new_order_gas, order_init_gas, order_execute_gas, parent_execute_gas;
  td::int64 init_bits, init_cells, state_bits, state_cells, execute_bits, execute_cells;
  // whole forwarded parts and state, action and signers included, for pricing
  td::int64 init_total_bits, init_total_cells, state_total_bits, state_total_cells;
  td::int64 execute_total_bits, execute_total_cells;
};

// The whole path for a wallet of `signers` signers and the given action chain.
Path run_path(int signers, td::Ref<vm::Cell> chain) {
  Path p{};
  const auto action_size = storage_of(chain);
  const auto signer_size = storage_of(signer_dict(signers));

  vm::CellBuilder proposal;
  proposal.store_long(kOpNewOrder, 32).store_long(1, 64).store_long(static_cast<long long>(kNextSeqno), 64);
  proposal.store_long(0, 1).store_long(0, 8).store_long(kNow + 86'400, 32).store_ref(chain);
  auto proposed = run(wallet_code(), parent_data(0, signers), parent(), proposer(), proposal.finalize());
  CHECK(proposed.code == 0);
  p.new_order_gas = proposed.gas_used;
  auto init_messages = out_messages(proposed.actions);
  CHECK(init_messages.size() == 1);
  auto init_forwarded = forwarded_part_of(init_messages[0]);
  p.init_total_bits = static_cast<td::int64>(init_forwarded.bits);
  p.init_total_cells = static_cast<td::int64>(init_forwarded.cells);
  p.init_bits = static_cast<td::int64>(init_forwarded.bits - action_size.bits - signer_size.bits);
  p.init_cells = static_cast<td::int64>(init_forwarded.cells - action_size.cells - signer_size.cells);

  const auto order = order_address();
  auto inited = run(order_code(), order_init_data(), order, parent(), body_ref(init_messages[0]));
  CHECK(inited.code == 0);
  p.order_init_gas = inited.gas_used;
  auto code = storage_of(order_code());
  auto data = storage_of(inited.new_state.data);
  p.state_total_bits = static_cast<td::int64>(code.bits + data.bits);
  p.state_total_cells = static_cast<td::int64>(code.cells + data.cells);
  p.state_bits = static_cast<td::int64>(code.bits + data.bits - action_size.bits - signer_size.bits);
  p.state_cells = static_cast<td::int64>(code.cells + data.cells - action_size.cells - signer_size.cells);

  auto approve = [](int index) {
    vm::CellBuilder cb;
    cb.store_long(kOpApprove, 32).store_long(7, 64).store_long(index, 8);
    return cb.finalize();
  };
  auto first = run(order_code(), inited.new_state.data, order, signer(0), approve(0));
  CHECK(first.code == 0);
  auto fired = run(order_code(), first.new_state.data, order, signer(1), approve(1));
  CHECK(fired.code == 0);
  p.order_execute_gas = fired.gas_used;
  auto fired_messages = out_messages(fired.actions);
  CHECK(fired_messages.size() == 2);  // the reply, then execute
  auto execute_forwarded = forwarded_part_of(fired_messages[1]);
  p.execute_total_bits = static_cast<td::int64>(execute_forwarded.bits);
  p.execute_total_cells = static_cast<td::int64>(execute_forwarded.cells);
  p.execute_bits = static_cast<td::int64>(execute_forwarded.bits - action_size.bits);
  p.execute_cells = static_cast<td::int64>(execute_forwarded.cells - action_size.cells);

  auto executed = run(wallet_code(), parent_data(1, signers), parent(), order, body_ref(fired_messages[1]));
  CHECK(executed.code == 0);
  p.parent_execute_gas = executed.gas_used;
  return p;
}

std::vector<td::int64> contract_profile() {
  auto contract = tos::SmartContract::create(tos::SmartContract::State{wallet_code(), parent_data(0, 3)});
  auto answer = contract.write().run_get_method(tos::SmartContract::Args()
                                                    .set_method_id(td::Slice("get_fee_profile"))
                                                    .set_address(parent())
                                                    .set_now(kNow)
                                                    .set_config(config()));
  CHECK(answer.code == 0);
  auto tuple = answer.stack.write().pop_tuple();
  CHECK(tuple->size() == kFieldCount);
  std::vector<td::int64> p(kFieldCount);
  for (int i = 0; i < kFieldCount; i++) {
    p[i] = tuple->at(i).as_int()->to_long();
  }
  return p;
}

constexpr td::int64 kLifetime = 86'400;  // run_path proposes orders expiring a day after kNow

td::int64 estimate(int signers, td::Ref<vm::Cell> chain) {
  auto contract = tos::SmartContract::create(tos::SmartContract::State{wallet_code(), parent_data(0, signers)});
  auto answer = contract.write().run_get_method(tos::SmartContract::Args()
                                                    .set_method_id(td::Slice("get_order_estimate"))
                                                    .set_stack({chain, td::make_refint(kNow + kLifetime)})
                                                    .set_address(parent())
                                                    .set_now(kNow)
                                                    .set_config(config()));
  CHECK(answer.code == 0);
  return answer.stack.write().pop_long();
}

// What the whole path actually costs under the configuration's basechain prices.
td::int64 actual_cost(const Path &path) {
  auto gas_prices = config()->get_gas_limits_prices(false).move_as_ok();
  auto msg_prices = config()->get_msg_prices(false).move_as_ok();
  auto gas = [&](td::int64 units) { return gas_prices.compute_gas_price(static_cast<td::uint64>(units))->to_long(); };
  auto fwd = [&](td::int64 bits, td::int64 cells) {
    return msg_prices.compute_fwd_fees(static_cast<td::uint64>(cells), static_cast<td::uint64>(bits));
  };
  td::int64 storage = 0;
  for (const auto &prices : config()->get_storage_prices().move_as_ok()) {
    if (prices.valid_since <= static_cast<tos::UnixTime>(kNow)) {
      auto fee = (td::make_refint(path.state_total_bits) * td::make_refint(prices.bit_price) +
                  td::make_refint(path.state_total_cells) * td::make_refint(prices.cell_price)) *
                 td::make_refint(kLifetime);
      fee += td::make_refint(0xffff);
      fee >>= 16;
      storage = fee->to_long();
    }
  }
  return gas(path.new_order_gas) + gas(path.order_init_gas) + gas(path.order_execute_gas) +
         gas(path.parent_execute_gas) + static_cast<td::int64>(fwd(path.init_total_bits, path.init_total_cells)) +
         static_cast<td::int64>(fwd(path.execute_total_bits, path.execute_total_cells)) + storage;
}

td::int64 ceil_div(td::int64 a, td::int64 b) {
  return (a + b - 1) / b;
}

std::vector<td::int64> measure() {
  std::vector<td::int64> m(kFieldCount);
  auto base = run_path(3, actions(1));
  m[kParentNewOrderGas] = base.new_order_gas;
  m[kOrderInitGas] = base.order_init_gas;
  m[kOrderExecuteGas] = base.order_execute_gas;
  m[kParentExecuteGas] = base.parent_execute_gas;
  m[kInitMessageBits] = base.init_bits;
  m[kInitMessageCells] = base.init_cells;
  m[kOrderStateBits] = base.state_bits;
  m[kOrderStateCells] = base.state_cells;
  m[kExecuteMessageBits] = base.execute_bits;
  m[kExecuteMessageCells] = base.execute_cells;

  auto many = run_path(3, actions(21));
  m[kParentNewOrderGasPerAction] = ceil_div(many.new_order_gas - base.new_order_gas, 20);
  m[kParentExecuteGasPerAction] = ceil_div(many.parent_execute_gas - base.parent_execute_gas, 20);

  // An update installing 3 vs 128 signers, both followed by one send.
  auto small = run_path(3, actions(1, 3));
  auto large = run_path(3, actions(1, 128));
  m[kParentGasPerUpdatedSigner] = std::max(ceil_div(large.new_order_gas - small.new_order_gas, 125),
                                           ceil_div(large.parent_execute_gas - small.parent_execute_gas, 125));
  return m;
}

void log_measured(const std::vector<td::int64> &m) {
  std::string line;
  for (int i = 0; i < kFieldCount; i++) {
    line += std::string(" ") + kFieldNames[i] + "=" + std::to_string(m[i]);
  }
  LOG(INFO) << "multisig fee profile measured:" << line;
}

}  // namespace

TEST(MultisigFeeProfile, ProfileMatchesThisBuild) {
  auto m = measure();
  auto p = contract_profile();
  log_measured(m);
  for (int i = 0; i < kFieldCount; i++) {
    const bool gas = i < 4 || i >= kParentNewOrderGasPerAction;
    const td::int64 slack = gas ? (i >= kParentNewOrderGasPerAction ? 20 : 500) : (i % 2 == 0 ? 64 : 1);
    LOG(INFO) << "multisig fee profile " << kFieldNames[i] << ": measured=" << m[i] << " profile=" << p[i];
    CHECK(m[i] > 0);
    CHECK(m[i] <= p[i]);
    CHECK(p[i] <= m[i] + std::max(m[i] / 4, slack));
  }
}

struct QuoteCase {
  const char *name;
  int signers;
  int sends;
  int install;
  int install_proposers;
  int updates;
};

const QuoteCase kQuoteCases[] = {
    {"3 signers, 1 action", 3, 1, 0, 0, 1},
    {"255 signers, 1 action", 255, 1, 0, 0, 1},
    {"3 signers, 255 actions", 3, 255, 0, 0, 1},
    {"3 signers, update installing 255", 3, 1, 255, 0, 1},
    // Validation walks the proposer set as well as the signer set, on every update.
    {"3 signers, update installing 1 signer and 255 proposers", 3, 1, 1, 255, 1},
    {"3 signers, update installing 255 signers and 255 proposers", 3, 1, 255, 255, 1},
    {"3 signers, two updates sharing 1 signer and 255 proposers", 3, 1, 1, 255, 2},
    {"255 signers, 200 actions and an update installing 255", 255, 200, 255, 0, 1},
    // An update installing both full sets nearly fills the order's action cell limit
    // on its own, so it is combined with a full wallet rather than with more actions.
    {"255 signers, update installing 255 signers and 255 proposers", 255, 1, 255, 255, 1},
};

TEST(MultisigFeeProfile, QuoteCoversTheLargestWalletsAndOrders) {
  auto p = contract_profile();
  for (const auto &c : kQuoteCases) {
    auto chain = actions(c.sends, c.install, c.install_proposers, c.updates);
    auto path = run_path(c.signers, chain);
    const td::int64 quote = estimate(c.signers, chain);
    const td::int64 cost = actual_cost(path);
    LOG(INFO) << "multisig quote, " << c.name << ": quote " << quote << " actual " << cost << " (gas: proposal "
              << path.new_order_gas << ", order init " << path.order_init_gas << ", firing approval "
              << path.order_execute_gas << ", execute " << path.parent_execute_gas << ")";
    CHECK(quote >= cost);
    // The phases whose gas the profile fixes outright must not grow with the wallet.
    CHECK(path.order_init_gas <= p[kOrderInitGas]);
    CHECK(path.order_execute_gas <= p[kOrderExecuteGas]);
  }
}

namespace {

std::string boc64(td::Ref<vm::Cell> cell) {
  return td::base64_encode(vm::std_boc_serialize(std::move(cell)).move_as_ok());
}

td::Ref<vm::Cell> from_boc64(td::Slice text) {
  auto cell = vm::std_boc_deserialize(td::base64_decode(text).move_as_ok());
  CHECK(cell.is_ok());
  return cell.move_as_ok();
}

struct Delivery {
  block::StdAddress to;
  td::RefInt256 value;
  td::Ref<vm::Cell> message;
};

Delivery parse_delivery(td::Ref<vm::Cell> message) {
  auto cs = vm::load_cell_slice(message);
  block::gen::CommonMsgInfo::Record_int_msg_info info;
  CHECK(tlb::unpack(cs, info));
  Delivery d;
  CHECK(block::tlb::t_MsgAddressInt.extract_std_address(info.dest, d.to));
  block::CurrencyCollection value;
  CHECK(value.unpack(info.value));
  d.value = value.tomis;
  d.message = std::move(message);
  return d;
}

struct Outcome {
  block::StdAddress account;
  bool compute_success = false;
  bool action_success = false;
};

// Whole transactions on the node's executor, one shard: contract accounts keep their
// state, and messages to any other address are recorded as delivered.
class Executor {
 public:
  Executor() {
    static const auto boc = fee_fixture::tos_versioned_config_boc();
    emulator_ = transaction_emulator_create(boc.c_str(), 0);
    CHECK(emulator_ != nullptr);
    CHECK(transaction_emulator_set_unixtime(emulator_, kNow));
  }
  ~Executor() {
    transaction_emulator_destroy(emulator_);
  }
  Executor(const Executor &) = delete;
  Executor &operator=(const Executor &) = delete;

  // A message from an outside account; its forward fee does not matter to these contracts.
  static td::Ref<vm::Cell> external_sender_message(const block::StdAddress &from, const block::StdAddress &to,
                                                   td::uint64 value, td::Ref<vm::Cell> body,
                                                   td::Ref<vm::Cell> init = {}) {
    vm::CellBuilder cb;
    cb.store_long(0b0110, 4);  // int_msg_info$0, ihr_disabled, bounce, not bounced
    store_std_address(cb, from);
    store_std_address(cb, to);
    store_coins(cb, value);
    cb.store_zeroes(1 + 4 + 4).store_long(0, 64).store_long(kNow, 32);
    if (init.not_null()) {
      cb.store_long(0b11, 2).store_ref(init);
    } else {
      cb.store_zeroes(1);
    }
    cb.store_ones(1).store_ref(std::move(body));
    return cb.finalize();
  }

  void contract(const block::StdAddress &address) {
    contracts_.insert(key(address));
  }

  void settle(td::Ref<vm::Cell> message) {
    queue_.push_back(parse_delivery(std::move(message)));
    while (!queue_.empty()) {
      auto next = queue_.front();
      queue_.pop_front();
      if (contracts_.count(key(next.to)) == 0) {
        delivered.push_back(next);
        continue;
      }
      outcomes.push_back(execute(next));
    }
  }

  td::RefInt256 balance(const block::StdAddress &address) const {
    auto it = accounts_.find(key(address));
    CHECK(it != accounts_.end());
    block::gen::ShardAccount::Record shard;
    CHECK(tlb::unpack_cell(from_boc64(it->second), shard));
    block::gen::Account::Record_account account;
    CHECK(tlb::unpack_cell(shard.account, account));
    block::gen::AccountStorage::Record storage;
    CHECK(tlb::csr_unpack(account.storage, storage));
    block::CurrencyCollection value;
    CHECK(value.unpack(storage.balance));
    return value.tomis;
  }

  std::vector<Outcome> outcomes;
  std::vector<Delivery> delivered;

 private:
  static std::string key(const block::StdAddress &address) {
    return address.addr.as_slice().str();
  }

  Outcome execute(const Delivery &message) {
    lt_ += 1'000'000;
    CHECK(transaction_emulator_set_lt(emulator_, lt_));
    std::string account;
    auto it = accounts_.find(key(message.to));
    if (it != accounts_.end()) {
      account = it->second;
    } else {
      td::Ref<vm::Cell> none;
      CHECK(block::gen::Account().cell_pack_account_none(none));
      vm::CellBuilder shard;
      shard.store_ref(none).store_bits(td::Bits256::zero().as_bitslice()).store_long(0, 64);
      account = boc64(shard.finalize());
    }
    auto raw = transaction_emulator_emulate_transaction(emulator_, account.c_str(), boc64(message.message).c_str());
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

    block::gen::Transaction::Record trans;
    CHECK(tlb::unpack_cell(from_boc64(obj.get_required_string_field("transaction").move_as_ok()), trans));
    vm::Dictionary out_msgs{trans.r1.out_msgs, 15};
    for (int i = 0; i < trans.outmsg_cnt; i++) {
      auto out = out_msgs.lookup_ref(td::BitArray<15>(i));
      CHECK(out.not_null());
      queue_.push_back(parse_delivery(out));
    }
    Outcome outcome;
    outcome.account = message.to;
    block::gen::TransactionDescr::Record_trans_ord ord;
    CHECK(tlb::unpack_cell(trans.description, ord));
    if (block::gen::t_TrComputePhase.get_tag(*ord.compute_ph) == block::gen::TrComputePhase::tr_phase_compute_vm) {
      block::gen::TrComputePhase::Record_tr_phase_compute_vm compute;
      CHECK(tlb::csr_unpack(ord.compute_ph, compute));
      outcome.compute_success = compute.success;
    }
    if (ord.action->prefetch_ulong(1) == 1) {
      block::gen::TrActionPhase::Record action;
      CHECK(tlb::unpack_cell(ord.action->prefetch_ref(), action));
      outcome.action_success = action.success;
    }
    return outcome;
  }

  void *emulator_ = nullptr;
  td::uint64 lt_ = 1'000'000;
  std::deque<Delivery> queue_;
  std::map<std::string, std::string> accounts_;
  std::set<std::string> contracts_;
};

}  // namespace

// The quote must not only exceed a priced sum; a proposal carrying exactly the quote
// has to take the order all the way to execution on the executor validators run,
// without the wallet's own balance paying for anything but the actions themselves.
TEST(MultisigFeeProfile, QuoteFundedOrdersExecuteWithoutWalletSubsidy) {
  constexpr td::uint64 kWalletFunds = 1000 * kCoin;
  for (const auto &c : kQuoteCases) {
    Executor chain;
    vm::CellBuilder init;
    init.store_long(0, 2).store_ones(1).store_ref(wallet_code()).store_ones(1).store_ref(parent_data(0, c.signers));
    init.store_zeroes(1);
    const auto wallet_init = init.finalize();
    const block::StdAddress wallet(0, wallet_init->get_hash().bits());
    chain.contract(wallet);
    chain.settle(Executor::external_sender_message(std_address(0x01), wallet, kWalletFunds,
                                                   vm::CellBuilder().finalize(), wallet_init));
    const auto before = chain.balance(wallet);

    // The order's address follows from this wallet's address.
    vm::CellBuilder order_data;
    store_std_address(order_data, wallet);
    order_data.store_long(0, 64);
    vm::CellBuilder order_init;
    order_init.store_long(0, 2).store_ones(1).store_ref(order_code()).store_ones(1).store_ref(order_data.finalize());
    order_init.store_zeroes(1);
    const block::StdAddress order(0, order_init.finalize()->get_hash().bits());
    chain.contract(order);

    auto chain_actions = actions(c.sends, c.install, c.install_proposers, c.updates);
    const auto quote = static_cast<td::uint64>(estimate(c.signers, chain_actions));
    vm::CellBuilder proposal;
    proposal.store_long(kOpNewOrder, 32).store_long(1, 64).store_long(static_cast<long long>(kNextSeqno), 64);
    proposal.store_long(0, 1).store_long(0, 8).store_long(kNow + kLifetime, 32).store_ref(chain_actions);
    chain.settle(Executor::external_sender_message(proposer(), wallet, quote, proposal.finalize()));
    for (int index : {0, 1}) {  // the wallet's threshold is 2
      vm::CellBuilder approve;
      approve.store_long(kOpApprove, 32).store_long(7, 64).store_long(index, 8);
      chain.settle(Executor::external_sender_message(signer(index), order, kCoin, approve.finalize()));
    }

    for (const auto &outcome : chain.outcomes) {
      CHECK(outcome.compute_success && outcome.action_success);
    }
    int paid = 0;
    for (const auto &d : chain.delivered) {
      paid += d.to == std_address(0x77) && td::cmp(d.value, td::make_refint(kCoin / 1000)) == 0;
    }
    // The actions themselves are the wallet's payments: their values, and (send mode 1)
    // the forward fees of their messages, which the signers approved with them.
    const auto msg_prices = config()->get_msg_prices(false).move_as_ok();
    const auto sent = forwarded_part_of(transfer());
    const auto per_send = static_cast<td::int64>(kCoin / 1000 + msg_prices.compute_fwd_fees(sent.cells, sent.bits));
    const auto after = chain.balance(wallet);
    const auto payouts = td::make_refint(static_cast<td::int64>(c.sends) * per_send);
    LOG(INFO) << "multisig quote-funded path, " << c.name << ": quote " << quote << ", wallet kept "
              << (after + payouts - before)->to_dec_string() << " beyond its payouts";
    CHECK(paid == c.sends);
    CHECK(td::cmp(after + payouts, before) >= 0);
  }
}
