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
// Slice 3 Stage 1 deterministic replay harness.
//
// The fixture data lives in
// emulator/test/slice-3-replay-fixtures/jetton-minter-stage1.json. This C++ file
// is the emulator side of the approved hybrid substrate: it executes the checked-in
// replay cases against the compiled Slice 2 jetton-minter Tol BoC that the
// existing slice1_gas_parity_contracts target already materializes.
//
// Stage 1 intentionally starts with one reference contract and one deterministic
// negative generator. Later Slice 3 stdlib stages add more JSON fixtures and C++
// replay cases without changing this runner contract.
// =============================================================================

#include "crypto/vm/boc.h"
#include "smc-envelope/SmartContract.h"
#include "td/utils/Slice.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "vm/cells.h"

#include <array>

namespace {

#ifndef SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC
#error "SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC must be defined by CMake"
#endif

constexpr td::uint64 kReplayAmount = 1'000'000'000;
constexpr td::uint64 kReplayBalance = 1'000'000'000;
constexpr td::uint64 kUnknownOpcodeSeed = 0x0123456789abcdefULL;
constexpr int kUnknownOpcodeCount = 8;

constexpr std::array<td::uint32, 4> kJettonMinterKnownOpcodes = {
    0x00000015,  // OP_MINT
    0x7bdd97de,  // OP_BURN_NOTIFICATION
    0x00000003,  // OP_CHANGE_ADMIN
    0x00000004,  // OP_CHANGE_CONTENT
};

td::uint64 splitmix64(td::uint64& state) {
  state += 0x9e3779b97f4a7c15ULL;
  td::uint64 z = state;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

bool is_known_minter_opcode(td::uint32 opcode) {
  for (auto known : kJettonMinterKnownOpcodes) {
    if (known == opcode) {
      return true;
    }
  }
  return false;
}

td::uint32 next_unknown_minter_opcode(td::uint64& state) {
  td::uint32 opcode = static_cast<td::uint32>(splitmix64(state) >> 32);
  if (is_known_minter_opcode(opcode)) {
    opcode ^= 0xa5a5a5a5U;
  }
  if (opcode == 0) {
    opcode = 0xdeadbeefU;
  }
  return opcode;
}

td::Ref<vm::Cell> load_code_boc(const char* path) {
  auto buf = td::read_file(td::CSlice{path});
  CHECK(buf.is_ok());
  auto cell = vm::std_boc_deserialize(buf.move_as_ok().as_slice());
  CHECK(cell.is_ok());
  return cell.move_as_ok();
}

td::Ref<vm::Cell> build_empty_body() {
  vm::CellBuilder cb;
  return cb.finalize();
}

td::Ref<vm::Cell> build_unknown_opcode_body(td::uint32 opcode, td::uint64 query_id) {
  vm::CellBuilder cb;
  cb.store_long(opcode, 32);
  cb.store_long(static_cast<long long>(query_id), 64);
  return cb.finalize();
}

// Mirrors the Stage 0 baseline builder used by the Slice 1 gas-parity fixture:
// total_supply=0, third-party admin address, tiny content/code refs. These bytes
// are valid for JettonMinterStorage and are intentionally not mutated by Stage 1
// replay cases.
td::Ref<vm::Cell> build_minter_storage_third_admin() {
  vm::CellBuilder content_cb;
  content_cb.store_zeroes(8);
  auto content = content_cb.finalize();

  vm::CellBuilder code_cb;
  code_cb.store_zeroes(8);
  auto wallet_code = code_cb.finalize();

  vm::CellBuilder cb;
  cb.store_long(0, 4);
  cb.store_long(0b100, 3);
  cb.store_zeroes(8);
  for (int i = 0; i < 32; ++i) {
    cb.store_long(0x33, 8);
  }
  cb.store_ref(content);
  cb.store_ref(wallet_code);
  return cb.finalize();
}

struct ReplayExpectation {
  const char* name;
  int exit_code;
  int actions;
  td::int64 max_gas_used;
  bool c4_unchanged;
};

tos::SmartContract::Answer run_replay(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data, td::Ref<vm::Cell> body) {
  tos::SmartContract::State state{std::move(code), std::move(data)};
  auto contract = tos::SmartContract::create(std::move(state));
  auto address = contract->get_address(tos::basechainId);

  auto args = tos::SmartContract::Args()
                  .set_amount(kReplayAmount)
                  .set_balance(kReplayBalance)
                  .set_address(address);
  return contract.write().send_internal_message(std::move(body), std::move(args));
}

int actions_count(const tos::SmartContract::Answer& answer) {
  if (answer.actions.is_null()) {
    return 0;
  }
  return static_cast<int>(tos::SmartContract::Answer::output_actions_count(answer.actions));
}

void check_replay(const tos::SmartContract::Answer& answer, td::Ref<vm::Cell> original_c4,
                  const ReplayExpectation& expected) {
  CHECK(answer.code == expected.exit_code);
  CHECK(actions_count(answer) == expected.actions);
  CHECK(answer.gas_used > 0);
  CHECK(answer.gas_used <= expected.max_gas_used);
  if (expected.c4_unchanged) {
    CHECK(answer.new_state.data.not_null());
    CHECK(answer.new_state.data->get_hash() == original_c4->get_hash());
  }
}

}  // namespace

TEST(Slice3Replay, JettonMinterEmptyBodyUnknownThrow) {
  auto code = load_code_boc(SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC);
  auto data = build_minter_storage_third_admin();
  auto answer = run_replay(code, data, build_empty_body());
  check_replay(answer, data, ReplayExpectation{"empty-body-unknown-throw", 65535, 0, 1000, true});
}

TEST(Slice3Replay, JettonMinterDeterministicUnknownOpcodeGenerator) {
  auto code = load_code_boc(SLICE1_GAS_PARITY_JETTON_MINTER_TOL_BOC);
  auto data = build_minter_storage_third_admin();
  td::uint64 state = kUnknownOpcodeSeed;

  for (int i = 0; i < kUnknownOpcodeCount; ++i) {
    const td::uint32 opcode = next_unknown_minter_opcode(state);
    const td::uint64 query_id = splitmix64(state);
    auto answer = run_replay(code, data, build_unknown_opcode_body(opcode, query_id));
    check_replay(answer, data, ReplayExpectation{"unknown-opcode-generator", 65535, 0, 2000, true});
  }
}
