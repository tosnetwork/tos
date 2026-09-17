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


#include "elector-fixture.h"


int main(int argc, char** argv) {
  try {
    expect(argc == 2, "arguments");
    expect(sodium_init() >= 0, "sodium");
    vm::init_vm().ensure();
    SET_VERBOSITY_LEVEL(std::getenv("VALIDATOR_AUTH_CONTRACT_TRACE") ? VERBOSITY_NAME(DEBUG) : VERBOSITY_NAME(FATAL));

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

    auto stake = [&](const unsigned char* named, bool activated) {
      vm::Dictionary empty(256);
      auto data = elector_data(election(empty, 0));
      auto body = stake_body(public_key, secret, 0x4444, named);
      td::Ref<vm::Stack> stack{true};
      stack.write().push_int(td::make_refint(1000000000000LL));
      stack.write().push_int(td::make_refint(20000000000LL));
      stack.write().push_cell(internal_message(staker_account, body));
      stack.write().push_cellslice(vm::load_cell_slice_ref(body));
      stack.write().push_bool(false);
      return run(code, data, std::move(stack), elect_at - 50, activated);
    };

    // The control: before activation a stake that names nothing is stored
    // exactly as it always was.
    guard("inactive-stake-without-identity-is-stored-as-before", [&] {
      auto plain = stake(nullptr, false);
      expect(plain.exit == 0, "inactive-stake-without-identity-is-stored-as-before");
      auto record = stored_member(plain.data, public_key);
      expect(record.not_null(), "inactive-stake-without-identity-is-stored-as-before");
      // grams + 32 + 32 + 256 + 256, and not one bit more.
      expect(record->size_refs() == 0, "inactive-stake-without-identity-is-stored-as-before");
      expect(record->size() == 4 + 5 * 8 + 32 + 32 + 256 + 256,
             "inactive-stake-without-identity-is-stored-as-before");
      ok("inactive-stake-without-identity-is-stored-as-before");
    });

    // After activation it is refused at the door and the stake goes back. A
    // record that could never be selected must not be stored, or its stake
    // would sit in members with nothing left to release it.
    guard("active-stake-without-identity-is-refused", [&] {
      auto refused = stake(nullptr, true);
      expect(refused.exit == 0, "active-stake-without-identity-is-refused");
      expect(stored_member(refused.data, public_key).is_null(), "active-stake-without-identity-is-refused");
      ok("active-stake-without-identity-is-refused");
    });

    // An identity-bearing stake keeps it, where the election can reach it.
    guard("a-stake-naming-an-identity-keeps-it", [&] {
      auto named = stake(identity, false);
      expect(named.exit == 0, "a-stake-naming-an-identity-keeps-it");
      auto record = stored_member(named.data, public_key);
      expect(record.not_null(), "a-stake-naming-an-identity-keeps-it");
      expect(record->size() == 4 + 5 * 8 + 32 + 32 + 256 + 256, "a-stake-naming-an-identity-keeps-it");
      expect(record->size_refs() == 1, "a-stake-naming-an-identity-keeps-it");
      vm::CellSlice tail{vm::NoVm{}, record->prefetch_ref()};
      unsigned char stored[32] = {};
      expect(tail.size() == 256 && tail.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(stored), 32)),
             "a-stake-naming-an-identity-keeps-it");
      expect(std::equal(std::begin(identity), std::end(identity), std::begin(stored)),
             "a-stake-naming-an-identity-keeps-it");
      ok("a-stake-naming-an-identity-keeps-it");
    });

    auto elect_over = [&](const vm::Dictionary& members, std::uint64_t total, bool activated) {
      auto data = elector_data(election(members, total));
      td::Ref<vm::Stack> stack{true};
      stack.write().push_int(td::make_refint(1000000000000LL));
      stack.write().push_int(td::make_refint(elector_account));
      stack.write().push_bool(false);
      stack.write().push_smallint(-2);
      auto result = run(code, data, std::move(stack), elect_close + 10, activated);
      // The most expensive tick-tock this contract has: the one that closes an
      // election and sends the set. A block carrying a governance transaction
      // has to hold this too, so the number is reported rather than left to be
      // guessed from the case that consumed it.
      std::cerr << "MEASURE elector_ticktock_gas=" << result.gas << " activated=" << activated << '\n';
      return result;
    };

    auto one_member = [&](const unsigned char* key, std::uint64_t account, std::uint64_t amount,
                          const unsigned char* named) {
      vm::Dictionary members(256);
      expect(members.set(td::ConstBitPtr(key), 256,
                         vm::load_cell_slice_ref(member_record(amount, 0x20000, account, 0x4444, named))),
             "fixture-election");
      return members;
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

    // The bindings dictionary beside the set, checked to carry exactly the
    // accounts and identities given.
    auto bindings_of = [](vm::CellSlice query) {
      query.skip_first(32 + 64);
      expect(query.size_refs() == 2, "sent-bindings");
      vm::CellSlice wrapper{vm::NoVm{}, query.prefetch_ref(1)};
      expect(wrapper.size() == 1 && wrapper.fetch_ulong(1) == 1 && wrapper.size_refs() == 1, "sent-bindings");
      return vm::Dictionary(wrapper.prefetch_ref(), 16);
    };

    // An identity-bearing election on a chain that has not activated sends the
    // set alone. The records carry identities; activation, not their presence,
    // is what decides whether they travel.
    guard("inactive-identity-bearing-election-sends-no-bindings", [&] {
      auto plain = elect_over(one_member(public_key, staker_account, 19000000000ULL, identity), 19000000000ULL, false);
      expect(plain.exit == 0, "inactive-identity-bearing-election-sends-no-bindings");
      auto query = set_query(plain.actions);
      query.skip_first(32 + 64);
      expect(query.size_refs() == 1, "inactive-identity-bearing-election-sends-no-bindings");
      ok("inactive-identity-bearing-election-sends-no-bindings");
    });

    guard("active-election-sends-one-binding-per-selected-member", [&] {
      auto bound = elect_over(one_member(public_key, staker_account, 19000000000ULL, identity), 19000000000ULL, true);
      expect(bound.exit == 0, "active-election-sends-one-binding-per-selected-member");
      auto named_dict = bindings_of(set_query(bound.actions));
      td::BitArray<16> at;
      at.store_ulong(0);
      auto entry = named_dict.lookup(at.cbits(), 16);
      expect(entry.not_null() && entry->size() == 512 && entry->size_refs() == 0,
             "active-election-sends-one-binding-per-selected-member");
      at.store_ulong(1);
      expect(named_dict.lookup(at.cbits(), 16).is_null(), "active-election-sends-one-binding-per-selected-member");
      auto fields = entry.write();
      unsigned char account[32] = {}, stored[32] = {};
      expect(fields.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(account), 32)) &&
                 fields.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(stored), 32)),
             "active-election-sends-one-binding-per-selected-member");
      expect(td::bitstring::bits_load_ulong(td::ConstBitPtr(account) + 192, 64) == staker_account,
             "active-election-sends-one-binding-per-selected-member");
      expect(std::equal(std::begin(identity), std::end(identity), std::begin(stored)),
             "active-election-sends-one-binding-per-selected-member");
      ok("active-election-sends-one-binding-per-selected-member");
    });

    // What the same tick-tock costs at the committee sizes a masterchain block
    // has to carry alongside a governance transaction. The two are coupled: a
    // masterchain committee of four hundred means an elected set of four
    // hundred, so the block that carries the largest certificate also runs the
    // largest election close.
    guard("election-close-cost-is-reported-at-committee-scale", [&] {
      for (unsigned members : {100u, 400u}) {
        vm::Dictionary set(256);
        std::uint64_t total = 0;
        for (unsigned index = 0; index < members; ++index) {
          unsigned char key[32] = {}, named[32] = {};
          key[0] = static_cast<unsigned char>(index & 0xff);
          key[1] = static_cast<unsigned char>((index >> 8) & 0xff);
          key[31] = 0x11;
          named[0] = static_cast<unsigned char>(index & 0xff);
          named[31] = 0x22;
          const std::uint64_t amount = 19000000000ULL;
          expect(set.set(td::ConstBitPtr(key), 256,
                         vm::load_cell_slice_ref(member_record(amount, 0x20000, staker_account + index, 0x4444 + index,
                                                               named))),
                 "election-close-cost-is-reported-at-committee-scale");
          total += amount;
        }
        // Both sides of activation, because a cost this design did not
        // introduce is not a cost this design has to answer for. The legacy
        // run is the control.
        auto legacy = elect_over(set, total, false);
        expect(legacy.exit == 0, "election-close-cost-is-reported-at-committee-scale");
        auto closed = elect_over(set, total, true);
        expect(closed.exit == 0, "election-close-cost-is-reported-at-committee-scale");
      }
      ok("election-close-cost-is-reported-at-committee-scale");
    });

    // The half-fix this case exists to refuse. Stakes placed before activation
    // name no identity and are already in members when the chain activates;
    // refusing new ones does nothing about them. They cannot be selected -- a
    // set containing one could not be bound -- so they must be excluded and
    // paid back, and paid back exactly once.
    guard("legacy-unbound-stake-is-excluded-and-refunded-after-activation", [&] {
      unsigned char legacy_key[32] = {}, legacy_secret[64] = {};
      expect(crypto_sign_keypair(legacy_key, legacy_secret) == 0, "fixture-legacy-keys");
      constexpr std::uint64_t legacy_account = staker_account + 1;
      constexpr std::uint64_t legacy_stake = 5000000000ULL;
      constexpr std::uint64_t named_stake = 19000000000ULL;

      auto members = one_member(public_key, staker_account, named_stake, identity);
      expect(members.set(td::ConstBitPtr(legacy_key), 256,
                         vm::load_cell_slice_ref(
                             member_record(legacy_stake, 0x20000, legacy_account, 0x5555, nullptr))),
             "fixture-legacy-member");

      auto run_out = elect_over(members, named_stake + legacy_stake, true);
      expect(run_out.exit == 0, "legacy-unbound-stake-is-excluded-and-refunded-after-activation");

      // One selected member, so one binding and no second entry.
      auto named_dict = bindings_of(set_query(run_out.actions));
      td::BitArray<16> at;
      at.store_ulong(0);
      auto first = named_dict.lookup(at.cbits(), 16);
      expect(first.not_null(), "legacy-unbound-stake-is-excluded-and-refunded-after-activation");
      at.store_ulong(1);
      expect(named_dict.lookup(at.cbits(), 16).is_null(),
             "legacy-unbound-stake-is-excluded-and-refunded-after-activation");
      unsigned char account[32] = {};
      auto fields = first.write();
      expect(fields.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(account), 32)),
             "legacy-unbound-stake-is-excluded-and-refunded-after-activation");
      expect(td::bitstring::bits_load_ulong(td::ConstBitPtr(account) + 192, 64) == staker_account,
             "legacy-unbound-stake-is-excluded-and-refunded-after-activation");

      // And the excluded stake came back whole, to the account that placed it.
      expect(grams_value(credited(run_out.data, legacy_account)) == legacy_stake,
             "legacy-unbound-stake-is-excluded-and-refunded-after-activation");
      ok("legacy-unbound-stake-is-excluded-and-refunded-after-activation");
    });

    std::cout << "SUMMARY cases=" << passed + failed << " passed=" << passed << '\n';
    return failed ? 1 : 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
