#pragma once
// The elector as a test drives it: its persistent data, a member record, a
// signed stake message, and the action list it leaves behind.
//
// Shared rather than copied because two suites now run this contract -- one
// asking what it does on its own, one joining its output to the authority that
// binds it -- and a second copy of the record layout would be a second answer
// to what a member record is.
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <sodium.h>
#include <stdexcept>

#include "vm/authops.h"
#include "vm/boc.h"
#include "vm/cellslice.h"
#include "vm/dict.h"
#include "vm/stack.hpp"
#include "vm/vm.h"

namespace {
unsigned passed = 0, failed = 0;

void ok(const char* name) {
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

// Every case runs, including the ones after a failure. Stopping at the first
// makes a case that was never reached indistinguishable from one that passed,
// which is exactly what a mutation asks about.
void guard(const char* name, const std::function<void()>& body) {
  try {
    body();
  } catch (const std::exception& error) {
    ++failed;
    std::cout << "CASE_FAIL " << name << " (" << error.what() << ")\n";
  }
}

void expect(bool condition, const char* name) {
  if (!condition)
    throw std::runtime_error(name);
}

constexpr std::uint64_t elector_account = 0x1111;
constexpr std::uint64_t config_account = 0x2222;
constexpr std::uint64_t staker_account = 0x3333;
constexpr std::uint32_t elect_at = 100000;
constexpr std::uint32_t elect_close = 100100;

// Grams, as the contract's store_tomis writes them.
void store_grams(vm::CellBuilder& cb, std::uint64_t value) {
  unsigned bytes = 0;
  for (auto rest = value; rest; rest >>= 8)
    ++bytes;
  cb.store_long(bytes, 4);
  if (bytes)
    cb.store_long(value, bytes * 8);
}

td::Ref<vm::Cell> address_param(std::uint64_t account) {
  return vm::CellBuilder().store_zeroes(192).store_long(account, 64).finalize();
}

// One member of the current election, in the record shape the contract writes.
td::Ref<vm::Cell> member_record(std::uint64_t stake, std::uint32_t max_factor, std::uint64_t address,
                                std::uint64_t adnl, const unsigned char* identity) {
  vm::CellBuilder cb;
  store_grams(cb, stake);
  cb.store_long(elect_at - 10, 32);
  cb.store_long(max_factor, 32);
  cb.store_zeroes(192).store_long(address, 64);
  cb.store_zeroes(192).store_long(adnl, 64);
  if (identity)
    cb.store_ref(vm::CellBuilder().store_bytes(td::Slice(reinterpret_cast<const char*>(identity), 32)).finalize());
  return cb.finalize();
}

td::Ref<vm::Cell> election(const vm::Dictionary& members, std::uint64_t total_stake) {
  vm::CellBuilder cb;
  cb.store_long(elect_at, 32).store_long(elect_close, 32);
  store_grams(cb, 1000000000);
  store_grams(cb, total_stake);
  expect(cb.store_maybe_ref(members.get_root_cell()), "fixture-members");
  cb.store_long(0, 1).store_long(0, 1);
  return cb.finalize();
}

// The elector's persistent data, in the shape load_data() reads.
td::Ref<vm::Cell> elector_data(const td::Ref<vm::Cell>& elect) {
  vm::CellBuilder cb;
  expect(cb.store_maybe_ref(elect), "fixture-data");
  cb.store_long(0, 1);  // credits
  cb.store_long(0, 1);  // past elections
  store_grams(cb, 0);
  cb.store_long(0, 32);
  cb.store_zeroes(256);
  return cb.finalize();
}

// Only the parameters the election path reads.
td::Ref<vm::Cell> configuration(bool activated) {
  vm::Dictionary dict(32);
  auto put = [&](int index, td::Ref<vm::Cell> value) {
    td::BitArray<32> key;
    key.store_long(index);
    expect(dict.set_ref(key.cbits(), 32, std::move(value)), "fixture-config");
  };
  put(0, address_param(config_account));
  put(1, address_param(elector_account));
  put(15, vm::CellBuilder()
              .store_long(4000, 32)  // elect_for
              .store_long(2000, 32)  // elect_begin_before
              .store_long(500, 32)   // elect_end_before
              .store_long(1000, 32)  // stake_held
              .finalize());
  put(16, vm::CellBuilder().store_long(100, 16).store_long(100, 16).store_long(1, 16).finalize());
  vm::CellBuilder stakes;
  store_grams(stakes, 1000000000);         // min stake
  store_grams(stakes, 10000000000000ULL);  // max stake
  store_grams(stakes, 1000000000);         // min total stake
  stakes.store_long(0x30000, 32);          // max stake factor
  put(17, stakes.finalize());
  if (activated) {
    put(8, vm::CellBuilder()
               .store_long(0xc4, 8)
               .store_long(vm::validator_auth_min_version, 32)
               .store_long(vm::validator_auth_capability, 64)
               .finalize());
  }
  auto root = dict.get_root_cell();
  expect(root.not_null(), "fixture-config");
  return root;
}

td::Ref<vm::CellSlice> masterchain_address(std::uint64_t account) {
  return vm::load_cell_slice_ref(
      vm::CellBuilder().store_long(4, 3).store_long(-1, 8).store_zeroes(192).store_long(account, 64).finalize());
}

struct Outcome {
  int exit;
  td::Ref<vm::Cell> data;
  td::Ref<vm::Cell> actions;
};

Outcome run(const td::Ref<vm::Cell>& code, const td::Ref<vm::Cell>& data, td::Ref<vm::Stack> stack, std::uint32_t now,
            bool activated) {
  auto config = configuration(activated);
  std::vector<vm::StackEntry> info = {
      td::make_refint(0x076ef1ea),
      td::zero_refint(),
      td::zero_refint(),
      td::make_refint(now),
      td::zero_refint(),
      td::zero_refint(),
      td::zero_refint(),
      vm::StackEntry(td::make_refint(1000000000000LL)),
      vm::StackEntry(masterchain_address(elector_account)),
      vm::StackEntry::maybe(config),
      vm::StackEntry::maybe(code),
      vm::StackEntry(td::make_refint(2000000000LL)),
      td::zero_refint(),
      vm::StackEntry(),
  };
  try {
    vm::VmState state{code, 16, std::move(stack), vm::GasLimits{10000000, 10000000}, 1, data, {}, {}, {}, 1024};
    state.set_c7(vm::make_tuple_ref(td::make_ref<vm::Tuple>(std::move(info))));
    int exit = ~state.run();
    return {exit, state.get_c4(), state.get_committed_state().c5};
  } catch (const vm::VmFatal&) {
    return {-1000, {}, {}};
  }
}

// A stake message, signed the way the contract requires, optionally naming an
// identity after the signature reference.
td::Ref<vm::Cell> stake_body(const unsigned char* public_key, const unsigned char* secret, std::uint64_t adnl,
                             const unsigned char* identity) {
  const std::uint32_t max_factor = 0x20000;
  vm::CellBuilder signed_payload;
  signed_payload.store_long(0x654c5074, 32)
      .store_long(elect_at, 32)
      .store_long(max_factor, 32)
      .store_zeroes(192)
      .store_long(staker_account, 64)
      .store_zeroes(192)
      .store_long(adnl, 64);
  auto payload = signed_payload.finalize();
  auto slice = vm::load_cell_slice(payload);
  unsigned char bits[128] = {};
  expect(slice.size() % 8 == 0 && slice.size() / 8 <= sizeof(bits), "fixture-payload");
  const auto length = slice.size() / 8;
  expect(slice.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(bits), length)), "fixture-payload");
  unsigned char signature[64] = {};
  expect(crypto_sign_detached(signature, nullptr, bits, length, secret) == 0, "fixture-signature");

  vm::CellBuilder body;
  body.store_long(0x4e73744b, 32).store_long(1, 64);
  body.store_bytes(td::Slice(reinterpret_cast<const char*>(public_key), 32));
  body.store_long(elect_at, 32).store_long(max_factor, 32);
  body.store_zeroes(192).store_long(adnl, 64);
  body.store_ref(vm::CellBuilder().store_bytes(td::Slice(reinterpret_cast<const char*>(signature), 64)).finalize());
  if (identity)
    body.store_bytes(td::Slice(reinterpret_cast<const char*>(identity), 32));
  return body.finalize();
}

td::Ref<vm::Cell> internal_message(std::uint64_t from, const td::Ref<vm::Cell>& body) {
  vm::CellBuilder cb;
  cb.store_long(0, 4);
  cb.append_cellslice(masterchain_address(from));
  cb.append_cellslice(masterchain_address(elector_account));
  cb.store_long(0, 4);
  cb.store_zeroes(1);
  cb.store_long(0, 4);
  cb.store_long(0, 4);
  cb.store_long(0, 64);
  cb.store_long(0, 32);
  cb.store_long(0, 1);  // no init
  // The body travels by reference; two addresses and a stake message do not fit
  // in one cell beside each other.
  cb.store_long(1, 1);
  cb.store_ref(body);
  return cb.finalize();
}

// The member record the contract left behind for one key.
td::Ref<vm::CellSlice> stored_member(const td::Ref<vm::Cell>& data, const unsigned char* public_key) {
  expect(data.not_null(), "stored-data");
  vm::CellSlice cs{vm::NoVm{}, data};
  expect(cs.fetch_ulong(1) == 1, "stored-election");
  vm::CellSlice elect{vm::NoVm{}, cs.fetch_ref()};
  elect.skip_first(64);
  // Two grams fields, skipped the way they are written: a four-bit length and
  // that many bytes.
  for (unsigned n = 0; n < 2; ++n) {
    auto bytes = elect.fetch_ulong(4);
    expect(bytes != vm::CellSlice::fetch_long_eof, "stored-election");
    elect.skip_first(static_cast<unsigned>(bytes) * 8);
  }
  // A refused stake leaves no members at all, which is an answer rather than a
  // malformed record: the lookup simply finds nothing.
  td::Ref<vm::Cell> root;
  if (elect.fetch_ulong(1) == 1) {
    root = elect.fetch_ref();
  }
  return vm::Dictionary(std::move(root), 256).lookup(td::ConstBitPtr(public_key), 256);
}
// The amount the contract credited back to one masterchain address, or nothing.
td::Ref<vm::CellSlice> credited(const td::Ref<vm::Cell>& data, std::uint64_t address) {
  expect(data.not_null(), "credited-data");
  vm::CellSlice cs{vm::NoVm{}, data};
  if (cs.fetch_ulong(1) == 1) {
    cs.fetch_ref();  // the election
  }
  td::Ref<vm::Cell> root;
  if (cs.fetch_ulong(1) == 1) {
    root = cs.fetch_ref();
  }
  unsigned char key[32] = {};
  for (unsigned n = 0; n < 8; ++n) {
    key[31 - n] = static_cast<unsigned char>(address >> (8 * n));
  }
  return vm::Dictionary(std::move(root), 256).lookup(td::ConstBitPtr(key), 256);
}

std::uint64_t grams_value(td::Ref<vm::CellSlice> value) {
  expect(value.not_null(), "credited-value");
  auto slice = value.write();
  auto bytes = slice.fetch_ulong(4);
  expect(bytes != vm::CellSlice::fetch_long_eof && bytes <= 8, "credited-grams");
  return bytes ? slice.fetch_ulong(static_cast<unsigned>(bytes) * 8) : 0;
}
}  // namespace
