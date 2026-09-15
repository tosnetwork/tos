// Does the elector actually carry the named identity through to the set it
// sends?
//
// Nothing in this repository executes the elector, so nothing would notice if
// these insertions changed what an ordinary election does, or if they added a
// field that some later read walks straight past. Compiling proves neither.
//
// So the first case is the control, and it is the one that has to pass against
// the contract without these insertions: a stake that names nothing is stored
// exactly as before, and an election over it sends exactly what it sent before.
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <stdexcept>

#include "vm/boc.h"
#include "vm/cellslice.h"
#include "vm/dict.h"
#include "vm/stack.hpp"
#include "vm/vm.h"

namespace {
unsigned passed = 0;

void ok(const char* name) {
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
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
td::Ref<vm::Cell> configuration() {
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

Outcome run(const td::Ref<vm::Cell>& code, const td::Ref<vm::Cell>& data, td::Ref<vm::Stack> stack, std::uint32_t now) {
  auto config = configuration();
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
  expect(elect.fetch_ulong(1) == 1, "stored-members");
  vm::Dictionary members(elect.fetch_ref(), 256);
  return members.lookup(td::ConstBitPtr(public_key), 256);
}
}  // namespace

int main(int argc, char** argv) {
  try {
    expect(argc == 2, "arguments");
    expect(sodium_init() >= 0, "sodium");
    vm::init_vm().ensure();
    SET_VERBOSITY_LEVEL(std::getenv("P0_CONTRACT_TRACE") ? VERBOSITY_NAME(DEBUG) : VERBOSITY_NAME(FATAL));

    std::ifstream input(argv[1], std::ios::binary);
    std::string raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    expect(!raw.empty(), "contract-boc");
    auto parsed = vm::std_boc_deserialize(td::Slice(raw));
    expect(parsed.is_ok(), "contract-boc");
    auto code = parsed.move_as_ok();
    ok("contract-assembles-and-loads");

    unsigned char public_key[32] = {}, secret[64] = {};
    expect(crypto_sign_keypair(public_key, secret) == 0, "fixture-keys");
    unsigned char identity[32] = {};
    for (unsigned n = 0; n < 32; ++n)
      identity[n] = static_cast<unsigned char>(n + 1);

    auto stake = [&](const unsigned char* named) {
      vm::Dictionary empty(256);
      auto data = elector_data(election(empty, 0));
      auto body = stake_body(public_key, secret, 0x4444, named);
      td::Ref<vm::Stack> stack{true};
      stack.write().push_int(td::make_refint(1000000000000LL));
      stack.write().push_int(td::make_refint(20000000000LL));
      stack.write().push_cell(internal_message(staker_account, body));
      stack.write().push_cellslice(vm::load_cell_slice_ref(body));
      stack.write().push_bool(false);
      return run(code, data, std::move(stack), elect_at - 50);
    };

    // The control: a stake that names nothing is stored exactly as before.
    {
      auto plain = stake(nullptr);
      expect(plain.exit == 0, "a-stake-naming-nothing-is-stored-as-before");
      auto record = stored_member(plain.data, public_key);
      expect(record.not_null(), "a-stake-naming-nothing-is-stored-as-before");
      // grams + 32 + 32 + 256 + 256, and not one bit more.
      expect(record->size_refs() == 0, "a-stake-naming-nothing-is-stored-as-before");
      expect(record->size() == 4 + 5 * 8 + 32 + 32 + 256 + 256, "a-stake-naming-nothing-is-stored-as-before");
      ok("a-stake-naming-nothing-is-stored-as-before");
    }

    // The election itself. This is what the other four insertions exist for:
    // the walk that reads every member record to its end, and the set that goes
    // to the configuration contract with the named identities beside it.
    auto elect_over = [&](const unsigned char* named) {
      vm::Dictionary members(256);
      // The value lives in the leaf, as udict_set_builder writes it; a
      // reference here would be a record the contract cannot read.
      expect(
          members.set(td::ConstBitPtr(public_key), 256,
                      vm::load_cell_slice_ref(member_record(19000000000ULL, 0x20000, staker_account, 0x4444, named))),
          "fixture-election");
      auto data = elector_data(election(members, 19000000000ULL));
      td::Ref<vm::Stack> stack{true};
      stack.write().push_int(td::make_refint(1000000000000LL));
      stack.write().push_int(td::make_refint(elector_account));
      stack.write().push_bool(false);
      stack.write().push_smallint(-2);
      return run(code, data, std::move(stack), elect_close + 10);
    };

    // The message the election sends to the configuration contract, found by
    // walking the action list the contract committed.
    //
    // out_list_node$_ prev:^OutList action:OutAction, and
    // action_send_msg#0ec3c86d mode:(## 8) out_msg:^MessageRelaxed.
    auto set_query = [](const td::Ref<vm::Cell>& actions) -> vm::CellSlice {
      expect(actions.not_null(), "sent-actions");
      td::Ref<vm::Cell> node = actions;
      for (unsigned guard = 0; guard < 16; ++guard) {
        vm::CellSlice action{vm::NoVm{}, node};
        expect(action.size_refs() == 2, "sent-action-shape");
        expect(action.fetch_ulong(32) == 0x0ec3c86d, "sent-action-kind");
        action.skip_first(8);
        vm::CellSlice message{vm::NoVm{}, action.prefetch_ref(1)};
        // int_msg_info header as the elector writes it, then the query.
        expect(message.fetch_ulong(17) == 0xc4ff, "sent-message-shape");
        message.skip_first(256);
        auto bytes = message.fetch_ulong(4);
        expect(bytes != vm::CellSlice::fetch_long_eof, "sent-message-shape");
        message.skip_first(static_cast<unsigned>(bytes) * 8 + 1 + 4 + 4 + 64 + 32 + 1 + 1);
        if (message.prefetch_ulong(32) == 0x4e565354)
          return message;
        node = action.prefetch_ref(0);
        expect(node.not_null(), "sent-set-query");
      }
      throw std::runtime_error("sent-set-query");
    };

    {
      // The control again, at the other end: an election over a member that
      // named nothing sends exactly one reference, the set.
      auto plain = elect_over(nullptr);
      expect(plain.exit == 0, "an-election-over-unnamed-members-sends-only-the-set");
      auto query = set_query(plain.actions);
      query.skip_first(32 + 64);
      expect(query.size_refs() == 1, "an-election-over-unnamed-members-sends-only-the-set");
      ok("an-election-over-unnamed-members-sends-only-the-set");
    }

    // And one that names an identity keeps it, where the election can reach it.
    {
      auto named = stake(identity);
      expect(named.exit == 0, "a-stake-naming-an-identity-keeps-it");
      auto record = stored_member(named.data, public_key);
      expect(record.not_null(), "a-stake-naming-an-identity-keeps-it");
      // The same bits as before, and the identity in a reference beside them.
      expect(record->size() == 4 + 5 * 8 + 32 + 32 + 256 + 256, "a-stake-naming-an-identity-keeps-it");
      expect(record->size_refs() == 1, "a-stake-naming-an-identity-keeps-it");
      vm::CellSlice tail{vm::NoVm{}, record->prefetch_ref()};
      unsigned char stored[32] = {};
      expect(tail.size() == 256 && tail.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(stored), 32)),
             "a-stake-naming-an-identity-keeps-it");
      expect(std::equal(std::begin(identity), std::end(identity), std::begin(stored)),
             "a-stake-naming-an-identity-keeps-it");
      ok("a-stake-naming-an-identity-keeps-it");
    }

    {
      auto bound = elect_over(identity);
      expect(bound.exit == 0, "an-election-sends-the-named-identities-beside-the-set");
      auto query = set_query(bound.actions);
      query.skip_first(32 + 64);
      expect(query.size_refs() == 2, "an-election-sends-the-named-identities-beside-the-set");
      // The second reference is the bindings, indexed the same as the set, and
      // carrying the account that staked with the identity it named.
      vm::CellSlice wrapper{vm::NoVm{}, query.prefetch_ref(1)};
      expect(wrapper.size() == 1 && wrapper.fetch_ulong(1) == 1 && wrapper.size_refs() == 1,
             "an-election-sends-the-named-identities-beside-the-set");
      vm::Dictionary named_dict(wrapper.prefetch_ref(), 16);
      td::BitArray<16> at;
      at.store_ulong(0);
      auto entry = named_dict.lookup(at.cbits(), 16);
      expect(entry.not_null() && entry->size() == 512 && entry->size_refs() == 0,
             "an-election-sends-the-named-identities-beside-the-set");
      auto fields = entry.write();
      unsigned char account[32] = {}, stored[32] = {};
      expect(fields.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(account), 32)) &&
                 fields.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(stored), 32)),
             "an-election-sends-the-named-identities-beside-the-set");
      expect(td::bitstring::bits_load_ulong(td::ConstBitPtr(account) + 192, 64) == staker_account,
             "an-election-sends-the-named-identities-beside-the-set");
      expect(std::equal(std::begin(identity), std::end(identity), std::begin(stored)),
             "an-election-sends-the-named-identities-beside-the-set");
      ok("an-election-sends-the-named-identities-beside-the-set");
    }

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
