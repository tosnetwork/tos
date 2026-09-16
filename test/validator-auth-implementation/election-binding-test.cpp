// Attaching the registry binding to an elected validator set.
//
// The link this asserts is the only place two facts meet: which account staked
// for a network key, and which identity that account owns. It is also the only
// place the link can be refused for a reason anyone can read -- a wrong binding
// otherwise surfaces at committee derivation, which can say that the set is
// underivable but not which member is wrong.
//
// So the cases that matter are the ones where a member names an identity that
// is not its own. A stake id is public, so a set built that way is internally
// consistent and passes every check that does not ask the registry whose
// identity it is.
#include <iostream>
#include <map>
#include <stdexcept>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "validator/auth/lifecycle.h"
#include "validator/auth/native-election-binding.h"
#include "vm/dict.h"

#include "native-fixture.h"

using namespace tos::auth;
using namespace auth_fixture;

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

void refuses(const Result<td::Ref<vm::Cell>>& result, const char* code, const char* name) {
  if (result.ok() || result.error().code != code) {
    std::cerr << "DETAIL " << name << " expected=" << code
              << " actual=" << (result.ok() ? "bound" : result.error().code) << '\n';
    throw std::runtime_error(name);
  }
  ok(name);
}

td::Bits256 bits(const Hash& value) {
  return td::Bits256(td::ConstBitPtr(value.data()));
}

// One member exactly as the elector emits it.
void emit(vm::Dictionary& list, unsigned index, const Hash& key, std::uint64_t weight, const Hash& address,
          bool with_address = true) {
  vm::CellBuilder cb;
  cb.store_long(with_address ? 0x73 : 0x53, 8)
      .store_long(0x8e81278a, 32)
      .store_bytes(td::Slice(reinterpret_cast<const char*>(key.data()), key.size()));
  cb.store_long(weight, 64);
  if (with_address)
    cb.store_bytes(td::Slice(reinterpret_cast<const char*>(address.data()), address.size()));
  td::BitArray<16> at;
  at.store_ulong(index);
  check(list.set_builder(at.cbits(), 16, cb), "fixture-member");
}

td::Ref<vm::Cell> elected_set(const vm::Dictionary& list, unsigned total, std::uint64_t total_weight) {
  block::gen::ValidatorSet::Record_validators_ext record;
  record.utime_since = 1000;
  record.utime_until = 2000;
  record.total = total;
  record.main = total;
  record.total_weight = total_weight;
  vm::CellBuilder wrapper;
  check(wrapper.store_maybe_ref(list.get_root_cell()), "fixture-list");
  record.list = vm::load_cell_slice_ref(wrapper.finalize());
  td::Ref<vm::Cell> root;
  check(tlb::pack_cell(root, record), "fixture-set");
  return root;
}
}  // namespace

int main() {
  try {
    auto registry = state(3);
    auto root = value(registry.encode_cell(), "registry");
    auto view = value(RegistryView::open(root, 0, {64, 1 << 20}), "registry-view");

    std::vector<Identity> members;
    for (const auto& [id, identity] : registry.identities())
      members.push_back(identity);
    check(members.size() >= 3, "fixture-identities");

    const std::uint64_t weights[2] = {7, 11};
    vm::Dictionary list(16);
    emit(list, 0, h(9001), weights[0], h(9101));
    emit(list, 1, h(9002), weights[1], h(9102));
    auto set = elected_set(list, 2, weights[0] + weights[1]);

    std::map<unsigned, ElectedBinding> bindings{{0, {members[0].owner_address_, members[0].identity_}},
                                                {1, {members[1].owner_address_, members[1].identity_}}};

    // The whole point: a bound set parses as an authenticated one, and every
    // member carries the binding the registry says belongs to it.
    auto bound = bind_elected_validators(set, bindings, view, 0);
    expect(bound.ok(), "bound-set-carries-the-registry-binding");
    auto parsed = block::Config::unpack_validator_set(bound.value());
    expect(parsed.is_ok(), "bound-set-carries-the-registry-binding");
    const auto& list_out = parsed.ok()->list;
    expect(list_out.size() == 2, "bound-set-carries-the-registry-binding");
    for (unsigned index = 0; index < 2; ++index) {
      const auto& member = list_out[index];
      expect(member.auth_binding.has_value(), "bound-set-carries-the-registry-binding");
      expect(member.auth_binding->identity == bits(members[index].identity_), "bound-set-carries-the-registry-binding");
      expect(member.auth_binding->stake_id == bits(members[index].stake_id_), "bound-set-carries-the-registry-binding");
      // Nothing else may have moved: this adds a binding, it does not rewrite
      // the election.
      expect(member.weight == weights[index], "bound-set-carries-the-registry-binding");
    }
    expect(parsed.ok()->utime_since == 1000 && parsed.ok()->utime_until == 2000 && parsed.ok()->total == 2 &&
               parsed.ok()->main == 2,
           "bound-set-carries-the-registry-binding");
    ok("bound-set-carries-the-registry-binding");

    // A stake id is public, so naming another member's identity produces a set
    // that is internally consistent. Only the registry knows it is wrong.
    auto impostor = bindings;
    impostor[1].claimed_identity = members[2].identity_;
    refuses(bind_elected_validators(set, impostor, view, 0), "election-binding-owner",
            "another-members-identity-is-refused");

    auto unknown = bindings;
    unknown[0].claimed_identity = h(4242);
    refuses(bind_elected_validators(set, unknown, view, 0), "election-binding-unregistered",
            "unregistered-identity-is-refused");

    // One identity seated twice would put one registry member behind two
    // network keys.
    auto twice = bindings;
    twice[1] = twice[0];
    refuses(bind_elected_validators(set, twice, view, 0), "election-binding-duplicate",
            "one-identity-twice-is-refused");

    // The other shape of the same guard: fewer bindings than members. It shares
    // the count check with the case below rather than having one of its own,
    // which is why no mutation names this case.
    auto short_of_one = bindings;
    short_of_one.erase(1);
    refuses(bind_elected_validators(set, short_of_one, view, 0), "election-binding-incomplete",
            "a-set-is-bound-entirely-or-not-at-all");

    // A caller holding a binding for a member this set does not have is a
    // caller with the wrong set. Ignoring the extra one would proceed with a
    // set neither side agrees about.
    auto surplus = bindings;
    surplus[2] = {members[2].owner_address_, members[2].identity_};
    refuses(bind_elected_validators(set, surplus, view, 0), "election-binding-incomplete",
            "bindings-for-members-that-do-not-exist-are-refused");

    // A member elected without an address cannot be authenticated at all, and
    // the set it is in must not be bound around it.
    {
      vm::Dictionary addressless(16);
      emit(addressless, 0, h(9001), weights[0], h(9101));
      emit(addressless, 1, h(9002), weights[1], {}, false);
      refuses(bind_elected_validators(elected_set(addressless, 2, weights[0] + weights[1]), bindings, view, 0),
              "election-binding-descriptor", "member-without-an-address-is-refused");
    }

    // The set's own declared weight has to survive, or a rewrite could change
    // the election while calling itself a binding.
    refuses(bind_elected_validators(elected_set(list, 2, weights[0] + weights[1] + 1), bindings, view, 0),
            "election-binding-weight", "declared-weight-must-survive");

    // The shape a contract hands over. It is decoded next to the operation that
    // consumes it so there is one definition of it, and these cases are what
    // stop that definition from accepting something the operation cannot use.
    {
      auto entries = [](const std::vector<std::pair<unsigned, ElectedBinding>>& items, int width = 0) {
        vm::Dictionary dict(16);
        for (const auto& [index, value] : items) {
          vm::CellBuilder cb;
          cb.store_bytes(
              td::Slice(reinterpret_cast<const char*>(value.staking_account.data()), value.staking_account.size()));
          if (width >= 0)
            cb.store_bytes(
                td::Slice(reinterpret_cast<const char*>(value.claimed_identity.data()), value.claimed_identity.size()));
          if (width > 0)
            cb.store_zeroes(width);
          td::BitArray<16> at;
          at.store_ulong(index);
          check(dict.set_builder(at.cbits(), 16, cb), "fixture-binding-entry");
        }
        vm::CellBuilder wrapper;
        check(wrapper.store_maybe_ref(dict.get_root_cell()), "fixture-binding-dict");
        return wrapper.finalize();
      };

      std::vector<std::pair<unsigned, ElectedBinding>> both{{0, {members[0].owner_address_, members[0].identity_}},
                                                            {1, {members[1].owner_address_, members[1].identity_}}};
      auto decoded = decode_elected_bindings(entries(both), 2);
      expect(decoded.ok() && decoded.value() == bindings, "handed-over-bindings-decode-to-what-was-meant");
      // And the decoded form really does bind the set, so the wire shape and
      // the operation agree rather than each being checked alone.
      auto again = bind_elected_validators(set, decoded.value(), view, 0);
      expect(again.ok(), "handed-over-bindings-decode-to-what-was-meant");
      ok("handed-over-bindings-decode-to-what-was-meant");

      // An entry that is not two hashes is not a binding. This shares the width
      // check with the case below rather than having one of its own: reading
      // the second hash out of a short entry fails either way.
      auto truncated = decode_elected_bindings(entries(both, -1), 2);
      expect(!truncated.ok() && truncated.error().code == "election-binding-shape", "a-short-entry-is-refused");
      ok("a-short-entry-is-refused");

      // An entry with anything after the two hashes is a caller saying more
      // than this shape can carry. Reading the first 512 bits and dropping the
      // rest would accept a message neither side agreed on.
      auto trailing = decode_elected_bindings(entries(both, 8), 2);
      expect(!trailing.ok() && trailing.error().code == "election-binding-shape",
             "an-entry-with-trailing-data-is-refused");
      ok("an-entry-with-trailing-data-is-refused");

      // An entry filed past the end of the set describes a different set. It
      // would otherwise be dropped silently by the index walk.
      auto beyond = both;
      beyond.push_back({7, {members[2].owner_address_, members[2].identity_}});
      auto outside = decode_elected_bindings(entries(beyond), 2);
      expect(!outside.ok() && outside.error().code == "election-binding-shape", "an-entry-past-the-end-is-refused");
      ok("an-entry-past-the-end-is-refused");

      // A gap is carried through as a gap, because refusing an incomplete set
      // is binding's answer to give, with the reason it actually has.
      auto gap = decode_elected_bindings(entries({both[0]}), 2);
      expect(gap.ok() && gap.value().size() == 1, "a-gap-stays-a-gap");
      refuses(bind_elected_validators(set, gap.value(), view, 0), "election-binding-incomplete", "a-gap-stays-a-gap");
    }

    {
      // A member whose consensus key is also one of its registry keys. The set
      // is well formed and every binding in it is genuine, so nothing refuses
      // it until derivation does -- by which time it is installed and no
      // committee can be derived at all. One member, every committee after it.
      auto keys = value(select_identity_keys(members[0], view, 0, {{1, 1, 1}}), "fixture-keys");
      check(!keys.empty() && keys[0].public_key_.size() == 32, "fixture-key-shape");
      Hash network{};
      std::copy(keys[0].public_key_.begin(), keys[0].public_key_.end(), network.begin());
      vm::Dictionary reused(16);
      emit(reused, 0, network, weights[0], h(9101));
      emit(reused, 1, h(9002), weights[1], h(9102));
      refuses(bind_elected_validators(elected_set(reused, 2, weights[0] + weights[1]), bindings, view, 0),
              "network-key-reuse", "a-consensus-key-that-is-also-a-registry-key-is-refused");
    }

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
