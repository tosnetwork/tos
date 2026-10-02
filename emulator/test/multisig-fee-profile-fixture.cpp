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
// prepay the order's whole path to execution. The prices come from the
// configuration at run time; the quantities — gas units of four compute
// phases and the fixed bits and cells of two messages and the order's state,
// beyond the action and the signer set — are constants in its fee_profile().
// A change to either contract can make them stale without any functional test
// noticing, and a stale profile lets proposals underfund their orders.
//
// This fixture runs the parent and the order on the C++ TVM through one whole
// path (proposal, order init, the approval that fires, the parent's execute)
// and requires measured <= profile <= measured + headroom for every quantity.
// The parent's proposal gas is measured with its run-time size count included;
// the contract adds that count again on top of the profile, so the profile
// stays an upper bound for larger sets.
//
// When the check fails after an intentional change, update fee_profile() from
// the "measured" line this test prints.
// =============================================================================

#include <algorithm>
#include <vector>

#include "block/block.h"
#include "crypto/vm/boc.h"
#include "emulator/test/tos-genesis-config.h"
#include "smc-envelope/SmartContract.h"
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
constexpr td::uint64 kCoin = 1'000'000'000;
constexpr td::int32 kNow = 1'800'000'000;
constexpr td::uint64 kNextSeqno = ~0ULL;

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

block::StdAddress std_address(unsigned char byte) {
  block::StdAddress address;
  address.workchain = 0;
  address.addr.as_slice().fill(byte);
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
  return std_address(static_cast<unsigned char>(0x10 + index));
}

block::StdAddress proposer() {
  return std_address(0x40);
}

block::StdAddress target() {
  return std_address(0x77);
}

td::Ref<vm::Cell> address_dict(const std::vector<block::StdAddress> &entries) {
  vm::Dictionary dict{8};
  for (unsigned i = 0; i < entries.size(); i++) {
    vm::CellBuilder value;
    store_std_address(value, entries[i]);
    td::BitArray<8> key;
    key.store_ulong(i);
    CHECK(dict.set_builder(key.bits(), 8, value));
  }
  return dict.get_root_cell();
}

td::Ref<vm::Cell> signers() {
  static auto cell = address_dict({signer(0), signer(1), signer(2)});
  return cell;
}

// The action the profile is measured with: one transfer.
td::Ref<vm::Cell> actions() {
  vm::CellBuilder msg;
  msg.store_long(0b0100, 4).store_zeroes(2);  // int_msg_info$0 ihr_disabled, src addr_none
  store_std_address(msg, target());
  store_coins(msg, 5 * kCoin);
  msg.store_zeroes(1 + 4 + 4 + 64 + 32 + 1 + 1);  // no extras, zero fees, lt, at, no init, inline body
  vm::CellBuilder action;
  action.store_long(kActionSend, 32).store_long(1, 8).store_ref(msg.finalize()).store_zeroes(1);
  return action.finalize();
}

td::Ref<vm::Cell> parent_data(td::uint64 next_seqno) {
  vm::CellBuilder cb;
  cb.store_long(static_cast<long long>(next_seqno), 64).store_long(2, 8).store_ref(signers());
  cb.store_ones(1).store_ref(address_dict({proposer()}));
  cb.store_ref(order_code());
  return cb.finalize();
}

tos::SmartContract::Args message_args(const block::StdAddress &self, const block::StdAddress &sender,
                                      td::uint64 amount) {
  return tos::SmartContract::Args()
      .set_amount(amount)
      .set_balance(10 * kCoin)
      .set_address(self)
      .set_sender_address(sender)
      .set_now(kNow)
      .set_config(config());
}

tos::SmartContract::Answer run(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data, const block::StdAddress &self,
                               const block::StdAddress &sender, td::Ref<vm::Cell> body) {
  auto contract = tos::SmartContract::create(tos::SmartContract::State{std::move(code), std::move(data)});
  return contract.write().send_internal_message(std::move(body), message_args(self, sender, 10 * kCoin));
}

// Outbound messages of an action list, in the order they were sent.
std::vector<td::Ref<vm::Cell>> out_messages(td::Ref<vm::Cell> list) {
  std::vector<td::Ref<vm::Cell>> messages;
  while (list.not_null()) {
    auto cs = vm::load_cell_slice(list);
    if (cs.size_refs() == 0) {
      break;  // the empty list
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

// The message body, whether inline or in a reference, and its last reference
// before the body (the StateInit, when present).
td::Ref<vm::Cell> body_ref(td::Ref<vm::Cell> message) {
  auto cs = vm::load_cell_slice(message);
  return cs.prefetch_ref(cs.size_refs() - 1);
}

struct Profile {
  td::int64 values[10];
};

const char *const kFieldNames[10] = {"parentNewOrderGas",  "orderInitGas",       "orderExecuteGas", "parentExecuteGas",
                                     "initMessageBits",    "initMessageCells",   "orderStateBits",  "orderStateCells",
                                     "executeMessageBits", "executeMessageCells"};

Profile contract_profile() {
  auto contract = tos::SmartContract::create(tos::SmartContract::State{wallet_code(), parent_data(0)});
  auto answer = contract.write().run_get_method(tos::SmartContract::Args()
                                                    .set_method_id(td::Slice("get_fee_profile"))
                                                    .set_address(parent())
                                                    .set_now(kNow)
                                                    .set_config(config()));
  CHECK(answer.code == 0);
  auto tuple = answer.stack.write().pop_tuple();
  CHECK(tuple->size() == 10);
  Profile p;
  for (int i = 0; i < 10; i++) {
    p.values[i] = tuple->at(i).as_int()->to_long();
  }
  return p;
}

Profile measure() {
  Profile m{};
  const auto action_size = storage_of(actions());
  const auto signer_size = storage_of(signers());
  const auto variable_bits = static_cast<td::int64>(action_size.bits + signer_size.bits);
  const auto variable_cells = static_cast<td::int64>(action_size.cells + signer_size.cells);

  // 1. The proposal on the parent, and the init message it sends.
  vm::CellBuilder proposal;
  proposal.store_long(kOpNewOrder, 32).store_long(1, 64).store_long(static_cast<long long>(kNextSeqno), 64);
  proposal.store_long(0, 1).store_long(0, 8).store_long(kNow + 86'400, 32).store_ref(actions());
  auto proposed = run(wallet_code(), parent_data(0), parent(), proposer(), proposal.finalize());
  CHECK(proposed.code == 0);
  m.values[0] = proposed.gas_used;
  auto init_messages = out_messages(proposed.actions);
  CHECK(init_messages.size() == 1);
  auto init_forwarded = forwarded_part_of(init_messages[0]);
  m.values[4] = static_cast<td::int64>(init_forwarded.bits) - variable_bits;
  m.values[5] = static_cast<td::int64>(init_forwarded.cells) - variable_cells;

  // 2. The order's initialisation, from the parent.
  vm::CellBuilder init_data;
  store_std_address(init_data, parent());
  init_data.store_long(0, 64);
  auto order_init_data = init_data.finalize();
  vm::CellBuilder order_address_init;
  order_address_init.store_long(0, 2).store_ones(1).store_ref(order_code()).store_ones(1).store_ref(order_init_data);
  order_address_init.store_zeroes(1);
  const block::StdAddress order(0, order_address_init.finalize()->get_hash().bits());
  auto inited = run(order_code(), order_init_data, order, parent(), body_ref(init_messages[0]));
  CHECK(inited.code == 0);
  m.values[1] = inited.gas_used;
  auto state = storage_of(order_code());
  auto data = storage_of(inited.new_state.data);
  m.values[6] = static_cast<td::int64>(state.bits + data.bits) - variable_bits;
  m.values[7] = static_cast<td::int64>(state.cells + data.cells) - variable_cells;

  // 3. Two approvals; the second reaches the threshold and sends execute.
  auto approve = [](int index) {
    vm::CellBuilder cb;
    cb.store_long(kOpApprove, 32).store_long(7, 64).store_long(index, 8);
    return cb.finalize();
  };
  auto first = run(order_code(), inited.new_state.data, order, signer(0), approve(0));
  CHECK(first.code == 0);
  auto fired = run(order_code(), first.new_state.data, order, signer(1), approve(1));
  CHECK(fired.code == 0);
  m.values[2] = fired.gas_used;
  auto fired_messages = out_messages(fired.actions);
  CHECK(fired_messages.size() == 2);  // the reply, then execute
  auto execute_forwarded = forwarded_part_of(fired_messages[1]);
  m.values[8] = static_cast<td::int64>(execute_forwarded.bits) - static_cast<td::int64>(action_size.bits);
  m.values[9] = static_cast<td::int64>(execute_forwarded.cells) - static_cast<td::int64>(action_size.cells);

  // 4. The parent executing the single-transfer action.
  auto executed = run(wallet_code(), parent_data(1), parent(), order, body_ref(fired_messages[1]));
  CHECK(executed.code == 0);
  CHECK(out_messages(executed.actions).size() == 1);
  m.values[3] = executed.gas_used;
  return m;
}

}  // namespace

TEST(MultisigFeeProfile, ProfileMatchesThisBuild) {
  auto m = measure();
  auto p = contract_profile();
  std::string line;
  for (int i = 0; i < 10; i++) {
    line += std::string(" ") + kFieldNames[i] + "=" + std::to_string(m.values[i]);
  }
  LOG(INFO) << "multisig fee profile measured:" << line;
  for (int i = 0; i < 10; i++) {
    const td::int64 slack = i < 4 ? 500 : (i % 2 == 0 ? 64 : 1);
    LOG(INFO) << "multisig fee profile " << kFieldNames[i] << ": measured=" << m.values[i]
              << " profile=" << p.values[i];
    CHECK(m.values[i] > 0);
    CHECK(m.values[i] <= p.values[i]);
    CHECK(p.values[i] <= m.values[i] + std::max(m.values[i] / 4, slack));
  }
}
