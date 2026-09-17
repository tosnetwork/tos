#pragma once
// Running the built configuration contract: the account's data, the messages it
// answers, the configuration it reads, and what a run is observed to have done.
//
// Two files execute this contract -- the case suite that says what it refuses,
// and the capacity bound that says what it costs. Constructing it twice would
// let one keep passing against an account shape the other no longer builds, and
// a cost measured on a shape the refusals never see is not a cost of this
// contract.
#include <sodium.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <optional>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "validator/auth/cells.h"
#include "validator/auth/codec.h"
#include "vm/authops.h"
#include "vm/boc.h"
#include "vm/cellslice.h"
#include "vm/dict.h"
#include "vm/excno.hpp"
#include "vm/stack.hpp"
#include "vm/vm.h"
#include "native-fixture.h"


namespace config_contract_fixture {
namespace auth = tos::auth;

void expect(bool condition, const char* name) {
  if (!condition)
    throw std::runtime_error(name);
}

template <class T>
T value(auth::Result<T> result, const char* name) {
  expect(result.ok(), name);
  return std::move(result.value());
}

template <class T>
auth::Bytes canonical_bytes(const T& input) {
  auto encoded = value(auth::encode(input), "fixture-encode");
  auto decoded = value(auth::decode<T>(encoded), "fixture-decode");
  expect(value(auth::encode(decoded), "fixture-reencode") == encoded, "fixture-roundtrip");
  return encoded;
}

td::Ref<vm::Cell> canonical_cell(td::Ref<vm::Cell> input) {
  auto encoded = vm::std_boc_serialize(input, 2);
  expect(encoded.is_ok(), "fixture-boc-encode");
  auto decoded = vm::std_boc_deserialize(encoded.ok().as_slice());
  expect(decoded.is_ok(), "fixture-boc-decode");
  auto again = vm::std_boc_serialize(decoded.ok(), 2);
  expect(again.is_ok(), "fixture-boc-reencode");
  expect(again.ok().as_slice() == encoded.ok().as_slice(), "fixture-boc-roundtrip");
  return decoded.move_as_ok();
}

bool same_cell(const td::Ref<vm::Cell>& a, const td::Ref<vm::Cell>& b) {
  return a.not_null() && b.not_null() && a->get_hash() == b->get_hash();
}

struct RegistryCells {
  td::Ref<vm::Cell> before, after, update, evidence;
};

RegistryCells registry_cells() {
  auto registry = auth_fixture::state(1);
  expect(registry.identities().size() == 1, "fixture-identity");
  const auto& identity = registry.identities().begin()->second;
  expect(!identity.active_.empty(), "fixture-active-key");
  auth::Update update{3, identity.identity_, 0,
                      value(auth::object_id("identity", identity), "fixture-predecessor"),
                      2, identity.active_[0].key_.key_id_, {}, {}, {}};
  auth::Authorizations evidence;
  evidence.administration_.push_back(
      {value(auth::object_id("update", update), "fixture-update-id"), identity.identity_,
       value(auth::object_value(4, canonical_bytes(auth::Certificate{})), "fixture-carrier")});
  // This fixture tests persistence, not admission. The registry transition is
  // real; its authorization is supplied by the shared accepted-request fixture.
  auto next = value(registry.apply_block(1, {{update, evidence}}, auth_fixture::AcceptedFixtureRequests{}),
                    "fixture-apply");
  RegistryCells result{canonical_cell(value(registry.encode_cell(), "fixture-old-registry")),
                       canonical_cell(value(next.encode_cell(), "fixture-new-registry")),
                       value(auth::pack_bytes(canonical_bytes(update)), "fixture-update-cell"),
                       value(auth::pack_bytes(canonical_bytes(evidence)), "fixture-evidence-cell")};
  expect(!same_cell(result.before, result.after), "fixture-registry-changed");
  return result;
}

// The host's result is fixed by the fixture before execution. It counts and
// binds the actual operands; it does not claim to verify update authorizations.
struct Host final : vm::ValidatorAuthHost {
  unsigned applies = 0, binds = 0, checkpoints = 0;
  td::Ref<vm::Cell> installed, bound, last_elected, last_bindings;
  td::Ref<vm::Cell> expected_update, expected_evidence, returned_registry, returned_checkpoint;
  td::Ref<vm::Cell> checkpoint(const Charge& charge) override {
    charge.gas(10);
    ++checkpoints;
    // A real checkpoint when the case needs one parsed. The tick-tock path
    // reads the registry out of the checkpoint's first reference, so a case
    // about that path cannot use the opaque marker the others are content with.
    if (returned_checkpoint.not_null()) {
      return returned_checkpoint;
    }
    return vm::CellBuilder().store_long(0x5a, 8).finalize();
  }
  td::Ref<vm::Cell> apply(td::Ref<vm::Cell> update, td::Ref<vm::Cell> evidence, const Charge& charge) override {
    charge.gas(10);
    ++applies;
    expect(update.not_null() && evidence.not_null(), "host-operands-present");
    if (expected_update.not_null()) {
      expect(same_cell(update, expected_update) && same_cell(evidence, expected_evidence), "host-operands-bound");
    }
    installed = returned_registry.not_null() ? returned_registry : vm::CellBuilder().store_long(0xa5a5, 16).finalize();
    return installed;
  }
  td::Ref<vm::Cell> bind(td::Ref<vm::Cell> elected, td::Ref<vm::Cell> bindings, const Charge& charge) override {
    charge.gas(10);
    ++binds;
    expect(elected.not_null() && bindings.not_null(), "host-operands-present");
    last_elected = elected;
    last_bindings = bindings;
    bound = vm::CellBuilder().store_long(0x12, 8).store_long(1111, 32).store_long(2222, 32)
                .store_long(1, 16).store_long(1, 16).store_long(5, 64).store_long(0, 1).finalize();
    return bound;
  }
};

Host registry_host(const RegistryCells& cells) {
  Host host;
  host.expected_update = cells.update;
  host.expected_evidence = cells.evidence;
  host.returned_registry = cells.after;
  return host;
}

td::Ref<vm::Cell> read_boc(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  std::string raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  expect(!raw.empty(), "contract-boc");
  auto root = vm::std_boc_deserialize(td::Slice(raw));
  expect(root.is_ok(), "contract-boc");
  return root.move_as_ok();
}

constexpr std::uint64_t elector_account = 0x1234;
constexpr std::uint64_t config_account = 0x5678;

td::Ref<vm::Cell> address_param(std::uint64_t account) {
  return vm::CellBuilder().store_zeroes(192).store_long(account, 64).finalize();
}

td::Ref<vm::Cell> elected_set(std::uint32_t since, std::uint32_t until) {
  return vm::CellBuilder().store_long(0x12, 8).store_long(since, 32).store_long(until, 32)
      .store_long(1, 16).store_long(1, 16).store_long(5, 64).store_long(0, 1).finalize();
}

td::Ref<vm::Cell> bindings_cell() {
  vm::CellBuilder entry;
  entry.store_zeroes(512);
  vm::Dictionary dict(16);
  td::BitArray<16> at;
  at.store_ulong(0);
  expect(dict.set_builder(at.cbits(), 16, entry), "fixture-bindings");
  vm::CellBuilder wrapper;
  expect(wrapper.store_maybe_ref(dict.get_root_cell()), "fixture-bindings");
  return wrapper.finalize();
}

td::Ref<vm::Cell> contract_data(const td::Ref<vm::Cell>& config, td::Ref<vm::Cell> checkpoint = {},
                                td::Ref<vm::Cell> votes = {}, const unsigned char* owner_public = nullptr) {
  vm::CellBuilder data;
  data.store_ref(config).store_long(0, 32);
  if (owner_public) {
    data.store_bytes(td::Slice(reinterpret_cast<const char*>(owner_public), 32));
  } else {
    // The deposed-dictator state, which is what every case that is not about
    // the master key wants: no signature can satisfy a key of zero.
    data.store_zeroes(256);
  }
  if (votes.not_null()) {
    data.store_long(1, 1).store_ref(std::move(votes));
  } else {
    data.store_long(0, 1);
  }
  if (checkpoint.not_null()) {
    data.store_ref(std::move(checkpoint));
  }
  return canonical_cell(data.finalize());
}

// The trailing reference the configuration account carries, or nothing. This is
// what an account is restored from, so a store that dropped it would leave the
// next block with an account nothing can open.
td::Ref<vm::Cell> stored_checkpoint(const td::Ref<vm::Cell>& data) {
  expect(data.not_null(), "stored-data");
  vm::CellSlice cs{vm::NoVm{}, data};
  expect(cs.size() == 289, "stored-data-shape");
  cs.fetch_ref();
  cs.advance(288);
  if (cs.fetch_ulong(1) == 1) {
    cs.fetch_ref();
  }
  return cs.size_refs() == 1 ? cs.fetch_ref() : td::Ref<vm::Cell>{};
}

// `activated` writes Config8, which is where the contract reads activation
// from. It is separate from the capability the virtual machine is given on
// purpose: a case that turned both off at once could not tell a contract that
// consulted Config8 from one that never ran the instruction because the opcode
// was gated.
// The elected set the voting cases run against, built once. The proposal status
// a fixture stores names the set by hash, and the configuration installs the
// same cell: two constructions of it would be two answers to "which set is
// current", and the contract compares them.
// The elected set as the chain would hold it.
//
// On an active chain this is what VAUTH_BIND writes: validator_auth#b3, with
// an address and a binding the registry decides the meaning of. Building the
// legacy shape for an active chain would be testing a set that chain cannot
// have, and it is what let a voting path that refuses 0xb3 look correct.
td::Ref<vm::Cell> validator_set_cell(const unsigned char* voting_key, bool bound = false) {
  vm::CellBuilder descriptor;
  descriptor.store_long(bound ? 0xb3 : 0x53, 8).store_long(0x8e81278a, 32);
  descriptor.store_bytes(td::Slice(reinterpret_cast<const char*>(voting_key), 32));
  descriptor.store_long(5, 64);
  if (bound) {
    descriptor.store_bytes(td::Slice(reinterpret_cast<const char*>(voting_key), 32));
    vm::CellBuilder binding;
    binding.store_bytes(td::Slice(reinterpret_cast<const char*>(voting_key), 32))
        .store_bytes(td::Slice(reinterpret_cast<const char*>(voting_key), 32));
    descriptor.store_ref(binding.finalize());
  }
  vm::Dictionary list(16);
  td::BitArray<16> at;
  at.store_ulong(0);
  expect(list.set_builder(at.cbits(), 16, descriptor), "fixture-config34-member");
  vm::CellBuilder set;
  set.store_long(0x12, 8).store_long(0, 32).store_long(0xffffffff, 32).store_long(1, 16).store_long(1, 16)
      .store_long(5, 64);
  expect(set.store_maybe_ref(list.get_root_cell()), "fixture-config34");
  return set.finalize();
}

// One proposal setup, for both the ordinary and the critical branch. min_wins
// is one so a single vote reaches the threshold and the case is about what
// happens there rather than about counting rounds.
td::Ref<vm::Cell> proposal_setup() {
  return vm::CellBuilder()
      .store_long(0x36, 8)
      .store_long(1, 8)   // min_tot_rounds
      .store_long(4, 8)   // max_tot_rounds
      .store_long(1, 8)   // min_wins
      .store_long(3, 8)   // max_losses
      .store_long(1, 32)
      .store_long(1000000, 32)
      .store_long(1, 32)
      .store_long(1, 32)
      .finalize();
}

// cfg_proposal#f3 param_id:int32 param_value:(Maybe ^Cell) if_hash_equal:(Maybe uint256)
std::array<unsigned char, 32> cell_hash_of(const td::Ref<vm::Cell>& cell) {
  std::array<unsigned char, 32> out{};
  if (cell.not_null())
    std::copy_n(cell->get_hash().as_slice().ubegin(), out.size(), out.begin());
  return out;
}

td::Ref<vm::Cell> config_proposal(long long index, td::Ref<vm::Cell> value,
                                  const std::array<unsigned char, 32>* condition = nullptr) {
  vm::CellBuilder b;
  b.store_long(0xf3, 8).store_long(index, 32);
  expect(b.store_maybe_ref(std::move(value)), "fixture-proposal-value");
  if (condition) {
    b.store_long(1, 1).store_bytes(td::Slice(reinterpret_cast<const char*>(condition->data()), 32));
  } else {
    b.store_long(0, 1);
  }
  return b.finalize();
}

// cfg_proposal_status#ce, one vote short of the threshold unless `wins` says
// otherwise. `weight_remaining` is below the voter's weight so the next vote
// crosses it.
td::Ref<vm::Cell> proposal_status(const td::Ref<vm::Cell>& proposal, const td::Ref<vm::Cell>& set,
                                  unsigned wins, bool current_set) {
  vm::CellBuilder b;
  b.store_long(0xce, 8).store_long(0xfffffff0, 32).store_ref(proposal).store_long(0, 1).store_long(0, 1);
  b.store_long(1, 64);
  // A stale identifier is the interesting half: it is what makes the original
  // code reset the proposal for a new round, so a terminal gate that did not
  // stand in front of that reset would be invisible.
  std::array<unsigned char, 32> id{};
  if (current_set) {
    const auto current = set->get_hash();
    std::copy_n(current.as_slice().ubegin(), id.size(), id.begin());
  }
  b.store_bytes(td::Slice(reinterpret_cast<const char*>(id.data()), 32));
  b.store_long(3, 8).store_long(wins, 8).store_long(0, 8);
  return b.finalize();
}

td::Ref<vm::Cell> configuration(td::Ref<vm::Cell> registry = {}, bool activated = false,
                                const unsigned char* voting_key = nullptr) {
  vm::Dictionary dict(32);
  td::BitArray<32> key;
  key.store_long(1);
  expect(dict.set_ref(key.cbits(), 32, address_param(elector_account)), "fixture-config");
  if (registry.not_null()) {
    key.store_long(46);
    expect(dict.set_ref(key.cbits(), 32, registry), "fixture-config46");
  }
  if (voting_key) {
    key.store_long(34);
    expect(dict.set_ref(key.cbits(), 32, validator_set_cell(voting_key, activated)), "fixture-config34");
    // The voting rules the contract reads its threshold from.
    key.store_long(11);
    auto setup = proposal_setup();
    vm::CellBuilder eleven;
    eleven.store_long(0x91, 8).store_ref(setup).store_ref(setup);
    expect(dict.set_ref(key.cbits(), 32, eleven.finalize()), "fixture-config11");
    // The mandatory and critical indexes are left absent, which reads the same
    // as empty: the contract looks a parameter up in them and an absent
    // dictionary answers "not found". Installing an empty one is not possible
    // anyway -- an empty dictionary has no root cell to store.
  }
  if (activated) {
    key.store_long(8);
    expect(dict.set_ref(key.cbits(), 32,
                        vm::CellBuilder()
                            .store_long(0xc4, 8)
                            .store_long(vm::validator_auth_min_version, 32)
                            .store_long(vm::validator_auth_capability, 64)
                            .finalize()),
           "fixture-config8");
  }
  auto root = dict.get_root_cell();
  expect(root.not_null(), "fixture-config");
  return root;
}

td::Ref<vm::CellSlice> masterchain_address(std::uint64_t account) {
  return vm::load_cell_slice_ref(
      vm::CellBuilder().store_long(4, 3).store_long(-1, 8).store_zeroes(192).store_long(account, 64).finalize());
}

td::Ref<vm::Cell> internal_message(std::uint64_t from, const td::Ref<vm::Cell>& body) {
  vm::CellBuilder cb;
  cb.store_long(0, 4);
  cb.append_cellslice(masterchain_address(from));
  cb.append_cellslice(masterchain_address(config_account));
  cb.store_long(0, 4).store_zeroes(1).store_long(0, 4).store_long(0, 4)
      .store_long(0, 64).store_long(0, 32).store_long(0, 1);
  // The body goes inline when it fits and in a reference when it does not,
  // which is what a real message does. The contract reads only the flags and
  // the source from this cell -- the body reaches it as its own stack entry --
  // but a cell that cannot be built is still a cell that cannot be built.
  auto contents = vm::load_cell_slice_ref(body);
  if (cb.remaining_bits() >= contents->size() + 1 && cb.remaining_refs() >= contents->size_refs()) {
    cb.store_long(0, 1);
    cb.append_cellslice(contents);
  } else {
    cb.store_long(1, 1);
    cb.store_ref(body);
  }
  return canonical_cell(cb.finalize());
}

td::Ref<vm::Cell> external_message(const td::Ref<vm::Cell>& body) {
  vm::CellBuilder cb;
  cb.store_long(2, 2).store_long(0, 2);
  cb.append_cellslice(masterchain_address(config_account));
  cb.store_long(0, 4).store_long(0, 1).store_long(1, 1).store_ref(body);
  return canonical_cell(cb.finalize());
}

td::Ref<vm::Cell> registry_body(const RegistryCells& cells, td::Ref<vm::Cell> proposal = {}) {
  vm::CellBuilder b;
  b.store_zeroes(512).store_long(0x56417531, 32).store_long(0, 32).store_long(2000, 32);
  b.store_ref(cells.update).store_ref(cells.evidence);
  // A third reference is the proposal a governance operation finalizes. Which
  // operations take one is decided where the update is decoded, not here.
  if (proposal.not_null())
    b.store_ref(std::move(proposal));
  return canonical_cell(b.finalize());
}

// The execution an external message gets before it is accepted. Production
// derives it from configuration parameters 20 and 21; what matters to a case
// about ordering is that it is a real bound and far smaller than the account's,
// so a run that only fits by being accepted first cannot pass.
// The credit an external message runs on before it accepts, as the zerostate
// installs it for the masterchain: gas_price, gas_limit, special_gas_limit,
// then this.
constexpr long long external_gas_credit = 10000;

struct Outcome {
  int exit = -1000;
  td::Ref<vm::Cell> data, committed_data;
  bool committed = false;
  long long gas = 0;
  // Whether the run reached accept_message. An external message runs on a
  // credit until it accepts; accepting raises the ceiling and zeroes the
  // credit, so a credit still standing at the end is a run that never accepted
  // and therefore never committed the account to paying.
  bool accepted = false;
  // The action list. A vote's result reaches the outside only as the tag of the
  // confirmation the contract sends, so a case about what a voter is told has
  // nothing else to read.
  td::Ref<vm::Cell> actions;
};

// The tag of the confirmation the contract sent, or nothing.
//
// A vote's result reaches the outside only here: register_vote returns a status
// and the contract answers with it added to a fixed base. A case about what a
// voter is told therefore has to read the action list; the persisted state says
// what happened, not what was reported.
//
// The message shape is the one send_answer builds: six header bits, the
// destination address, a fixed run of zero fields, then the tag.
std::optional<std::uint32_t> answer_tag(const td::Ref<vm::Cell>& actions) {
  if (actions.is_null())
    return {};
  try {
    // out_list_node$_ prev:^Cell action:OutAction -- the action's own fields are
    // in this cell's bits, and the message is its second reference. Reading the
    // action out of a reference instead finds a well-formed cell that is not an
    // action, which is why the first version of this reported no tag at all.
    vm::CellSlice list{vm::NoVm{}, actions};
    if (list.size_refs() < 2)
      return {};
    list.fetch_ref();
    // action_send_msg#0ec3c86d mode:(## 8) out_msg:^MessageRelaxed
    if (list.fetch_ulong(32) != 0x0ec3c86d || !list.advance(8) || list.size_refs() == 0)
      return {};
    vm::CellSlice message{vm::NoVm{}, list.prefetch_ref(0)};
    if (message.fetch_ulong(6) != 0x18)
      return {};
    // The destination is a standard internal address: two tag bits, no anycast,
    // the workchain and the account.
    if (message.fetch_ulong(2) != 2 || message.fetch_ulong(1) != 0 || !message.advance(8 + 256))
      return {};
    if (!message.advance(5 + 4 + 4 + 64 + 32 + 1 + 1))
      return {};
    auto tag = message.fetch_ulong(32);
    if (tag == vm::CellSlice::fetch_long_eof)
      return {};
    return static_cast<std::uint32_t>(tag);
  } catch (const vm::VmError&) {
    return {};
  }
}

td::Ref<vm::Cell> installed_parameter(const td::Ref<vm::Cell>& data, long long index) {
  if (data.is_null())
    return {};
  vm::CellSlice cs{vm::NoVm{}, data};
  if (cs.size_refs() == 0)
    return {};
  vm::Dictionary dict(cs.prefetch_ref(), 32);
  td::BitArray<32> key;
  key.store_long(index);
  return dict.lookup_ref(key.cbits(), 32);
}

long long stored_sequence(const td::Ref<vm::Cell>& data) {
  expect(data.not_null(), "data-present");
  vm::CellSlice cs{vm::NoVm{}, data};
  expect(cs.size() >= 32 && cs.size_refs() >= 1, "data-shape");
  return cs.fetch_long(32);
}

// three index references. Only the first reference is read by the contract;
// the rest are present because a checkpoint with fewer is not one.
td::Ref<vm::Cell> shaped_checkpoint(const td::Ref<vm::Cell>& registry, std::uint32_t coordinate) {
  auto filler = vm::CellBuilder().finalize();
  return vm::CellBuilder()
      .store_long(0x76616e31, 32)
      .store_long(1, 16)
      .store_long(coordinate, 32)
      .store_ref(registry)
      .store_ref(filler)
      .store_ref(filler)
      .store_ref(filler)
      .finalize();
}

// An active chain always has a checkpoint. Genesis seeds the registry
// parameter and the checkpoint together or seeds neither, and the contract
// refuses an active account that carries none rather than seeding one. A case
// that starts an active chain without a checkpoint is therefore describing a
// chain that cannot exist, so one is supplied here rather than in eighteen
// call sites.
td::Ref<vm::Cell> seeded_checkpoint(const td::Ref<vm::Cell>& registry, bool config8_active,
                                    td::Ref<vm::Cell> checkpoint) {
  if (!config8_active || checkpoint.not_null()) {
    return checkpoint;
  }
  return shaped_checkpoint(registry.not_null() ? registry : vm::CellBuilder().finalize(), 0);
}

Outcome run_contract(const td::Ref<vm::Cell>& contract, const td::Ref<vm::Cell>& body, std::uint64_t from,
                     std::uint32_t now, vm::ValidatorAuthHost* host, td::uint64 capabilities, int version,
                     bool external = false, td::Ref<vm::Cell> registry = {}, long long gas_limit = 1000000,
                     bool config8_active = false, td::Ref<vm::Cell> checkpoint = {},
                     const unsigned char* voting_key = nullptr, td::Ref<vm::Cell> votes = {},
                     long long credit = 0, const unsigned char* owner_public = nullptr) {
  expect(contract.not_null(), "contract-loaded");
  checkpoint = seeded_checkpoint(registry, config8_active, std::move(checkpoint));
  auto config = configuration(std::move(registry), config8_active, voting_key);
  auto message = external ? external_message(body) : internal_message(from, body);
  auto data = contract_data(config, std::move(checkpoint), std::move(votes), owner_public);
  td::Ref<vm::Stack> stack{true};
  stack.write().push_int(td::make_refint(1000000000000LL));
  stack.write().push_int(td::make_refint(external ? 0LL : 2000000000LL));
  stack.write().push_cell(message);
  stack.write().push_cellslice(vm::load_cell_slice_ref(body));
  stack.write().push_bool(external);
  std::vector<vm::StackEntry> info = {
      td::make_refint(0x076ef1ea), td::zero_refint(), td::zero_refint(), td::make_refint(now),
      td::zero_refint(), td::zero_refint(), td::zero_refint(),
      vm::StackEntry(td::make_refint(1000000000000LL)), vm::StackEntry(masterchain_address(config_account)),
      vm::StackEntry::maybe(config), vm::StackEntry::maybe(contract),
      vm::StackEntry(td::make_refint(external ? 0LL : 2000000000LL)), td::zero_refint(), vm::StackEntry()};
  auto registers = vm::make_tuple_ref(td::make_ref<vm::Tuple>(std::move(info)));
  try {
    // Flag 1 initializes c3 from the built contract. An external entry needs
    // selector -1, not the internal selector 0 used by the election cases.
    // With a credit the run starts with no limit of its own, exactly as an
    // unaccepted external message does: everything before accept_message has to
    // fit in the credit, and accepting is what raises the ceiling to the limit.
    // A credit still standing at the end is therefore a run that never accepted.
    // The configuration account is special -- the masterchain configuration
    // makes it so unconditionally, by address -- and a special account's
    // compute phase is entered with `gas_limit` already raised to `gas_max`
    // rather than with a limit it must accept to obtain. The credit is still
    // granted for an external message and is still zeroed by accepting, so
    // whether a run accepted is still observable; what it no longer is, for
    // this account, is the thing that bounds the run.
    //
    // Modelling it as a limit of zero before acceptance describes an ordinary
    // account. It is not one, and a bound measured that way is a bound on an
    // account the network does not have here.
    auto gas = credit ? vm::GasLimits{gas_limit, gas_limit, credit} : vm::GasLimits{gas_limit, gas_limit};
    vm::VmState state{contract, version, std::move(stack), gas, 1, data, {}, {}, registers, capabilities};
    if (host)
      state.set_validator_auth_host(std::shared_ptr<vm::ValidatorAuthHost>(host, [](vm::ValidatorAuthHost*) {}));
    const int exit = ~state.run();
    const bool accepted = credit != 0 && state.get_gas_limits().gas_credit == 0;
    return {exit,          state.get_c4(),      state.get_committed_state().c4,
            state.committed(), state.gas_consumed(), accepted, state.get_committed_state().c5};
  } catch (const vm::VmFatal&) {
    return {};
  }
}

Outcome registry_run(const td::Ref<vm::Cell>& contract, const RegistryCells& cells, Host& host,
                     bool previous, long long gas = 1000000) {
  return run_contract(contract, registry_body(cells), 0, 1000, &host, vm::validator_auth_capability,
                      vm::validator_auth_min_version, true, previous ? cells.before : td::Ref<vm::Cell>{}, gas);
}

// Find the smallest real gas limit that produces a committed checkpoint. After
// the safe ordering there need not be a gas-consuming instruction after commit,
// so a successful full run may be the first committed execution. The invariant
// is about checkpoint contents, not about manufacturing a later exception: once
// VAUTH_APPLY has succeeded, every committed c4 must already contain both the
// returned registry and the consumed external-message sequence number.
Outcome first_committed_registry_run(const td::Ref<vm::Cell>& contract, const RegistryCells& cells, bool previous) {
  auto full_host = registry_host(cells);
  auto full = registry_run(contract, cells, full_host, previous);
  expect(full.exit == 0 && full.committed && full_host.applies == 1, "checkpoint-control-runs-contract");
  expect(full.gas > 1 && full.gas < 1000000, "checkpoint-search-bound");
  long long low = 1, high = full.gas;
  while (low < high) {
    const auto middle = low + (high - low) / 2;
    auto host = registry_host(cells);
    const auto attempt = registry_run(contract, cells, host, previous, middle);
    if (attempt.committed)
      high = middle;
    else
      low = middle + 1;
  }
  auto host = registry_host(cells);
  auto first = registry_run(contract, cells, host, previous, low);
  std::cout << "MEASURE first_committed_gas=" << low << " full_gas=" << full.gas << " exit=" << first.exit
            << " committed=" << first.committed << " applies=" << host.applies
            << " checkpoint_has_new_registry="
            << same_cell(installed_parameter(first.committed_data, 46), cells.after) << '\n' << std::flush;
  expect(first.committed && host.applies == 1 && (first.exit == 0 || first.exit == -14),
         "first-committed-checkpoint-reached");
  return first;
}

int run_apply(bool with_host, Host& host, td::uint64 capabilities, int version) {
  try {
    auto cells = registry_cells();
    vm::CellBuilder body;
    body.store_long(vm::validator_auth_apply_opcode, 16);
    auto stack = td::make_ref<vm::Stack>();
    stack.write().push_cell(cells.update);
    stack.write().push_cell(cells.evidence);
    vm::VmState state{vm::load_cell_slice_ref(body.finalize()), version, std::move(stack),
                      vm::GasLimits{100000, 100000}, 0, {}, {}, {}, {}, capabilities};
    if (with_host)
      state.set_validator_auth_host(std::shared_ptr<vm::ValidatorAuthHost>(&host, [](vm::ValidatorAuthHost*) {}));
    return ~state.run();
  } catch (const vm::VmFatal&) {
    return -1000;
  }
}

using Case = std::pair<std::string, std::function<void()>>;

// A checkpoint shaped the way the registry encodes one: eighty bits of header
// and coordinate, then the registry state parameter 46 must hold, then the

// One tick-tock of the configuration account. No message, which is the whole
// point: this is the transaction a block with nothing to process still runs.
// `unseeded` is the one way to build an account state the policy says cannot
// exist: active, with no checkpoint. It exists so the refusal that guards that
// state has something to refuse. Every other caller gets the seeding above,
// because a case starting there would be describing a chain that cannot exist.
Outcome run_ticktock(const td::Ref<vm::Cell>& contract, vm::ValidatorAuthHost* host, td::uint64 capabilities,
                     int version,
                     bool config8_active, td::Ref<vm::Cell> registry = {}, td::Ref<vm::Cell> checkpoint = {},
                     long long gas_limit = 1000000, const unsigned char* voting_key = nullptr,
                     td::Ref<vm::Cell> votes = {}, bool unseeded = false) {
  expect(contract.not_null(), "contract-loaded");
  if (!unseeded) {
    checkpoint = seeded_checkpoint(registry, config8_active, std::move(checkpoint));
  }
  auto config = configuration(std::move(registry), config8_active, voting_key);
  auto data = contract_data(config, std::move(checkpoint), std::move(votes));
  td::Ref<vm::Stack> stack{true};
  stack.write().push_int(td::make_refint(1000000000000LL));
  stack.write().push_int(td::make_refint(static_cast<long long>(config_account)));
  stack.write().push_int(td::zero_refint());
  stack.write().push_int(td::make_refint(-2));
  std::vector<vm::StackEntry> info = {
      td::make_refint(0x076ef1ea), td::zero_refint(), td::zero_refint(), td::make_refint(1000),
      td::zero_refint(), td::zero_refint(), td::zero_refint(),
      vm::StackEntry(td::make_refint(1000000000000LL)), vm::StackEntry(masterchain_address(config_account)),
      vm::StackEntry::maybe(config), vm::StackEntry::maybe(contract),
      td::zero_refint(), td::zero_refint(), vm::StackEntry()};
  auto registers = vm::make_tuple_ref(td::make_ref<vm::Tuple>(std::move(info)));
  try {
    vm::VmState state{contract, version, std::move(stack), vm::GasLimits{gas_limit, gas_limit}, 1, data, {},
                      {}, registers, capabilities};
    if (host)
      state.set_validator_auth_host(std::shared_ptr<vm::ValidatorAuthHost>(host, [](vm::ValidatorAuthHost*) {}));
    const int exit = ~state.run();
    // A tick-tock is never an external message, so there is no credit to model.
    return {exit,          state.get_c4(),      state.get_committed_state().c4,
            state.committed(), state.gas_consumed(), true, state.get_committed_state().c5};
  } catch (const vm::VmFatal&) {
    return {};
  }
}

// One voter, generated once so the configuration, the stored status and the
// signature all name the same key. Two keypairs here would be two answers to
// "who is voting", and the contract compares them.
struct Voter {
  unsigned char key[32] = {}, secret[64] = {};
};
// The configuration master key. A generic parameter write can also arrive
// signed by it, and a message the contract refuses for its signature proves
// nothing about what it refuses for its content, so the account has to carry a
// key a case can actually sign with.
const Voter& owner() {
  static const Voter identity = [] {
    Voter made;
    expect(crypto_sign_keypair(made.key, made.secret) == 0, "fixture-owner");
    return made;
  }();
  return identity;
}

const Voter& voter() {
  static const Voter identity = [] {
    Voter made;
    expect(crypto_sign_keypair(made.key, made.secret) == 0, "fixture-voter");
    return made;
  }();
  return identity;
}
const unsigned char* voter_public() {
  return voter().key;
}

// A generic parameter write arriving the way the configuration master key
// sends one: an external message the owner signed. This is the second writer
// that takes an index and a cell and carries no bindings, so it is the second
// place a validator set could be installed without reaching the registry.
Outcome run_owner_action(const td::Ref<vm::Cell>& contract, long long index, td::Ref<vm::Cell> value,
                         Host* host, bool active) {
  // recv_external reads the signature, then the action, sequence number and
  // expiry, and checks the signature over everything after the signature.
  vm::CellBuilder payload;
  payload.store_long(0x43665021, 32).store_long(0, 32).store_long(0xfffffff0, 32).store_long(index, 32);
  payload.store_ref(std::move(value));
  auto signed_part = payload.finalize();
  auto digest = signed_part->get_hash().as_slice();
  unsigned char signature[64] = {};
  expect(crypto_sign_detached(signature, nullptr, digest.ubegin(), digest.size(), owner().secret) == 0,
         "fixture-owner-signature");

  vm::CellBuilder body;
  body.store_bytes(td::Slice(reinterpret_cast<const char*>(signature), 64));
  body.append_cellslice(vm::load_cell_slice_ref(signed_part));
  return run_contract(contract, body.finalize(), 0, 1000, host,
                      active ? vm::validator_auth_capability : 0, vm::validator_auth_min_version, true, {},
                      1000000, active, {}, nullptr, {}, 0, owner().key);
}

// One vote, arriving the way a validator sends one: an internal message whose
// body the voter signed. The external vote branch answers nothing, so a case
// about what a voter is told has to use this one.
Outcome cast_vote(const td::Ref<vm::Cell>& contract, const td::Ref<vm::Cell>& proposal,
                  const td::Ref<vm::Cell>& votes, Host* host, bool active) {
  auto id = proposal->get_hash().as_array();
  vm::CellBuilder signed_part;
  signed_part.store_long(0x566f7445, 32).store_long(0, 16);
  signed_part.store_bytes(td::Slice(reinterpret_cast<const char*>(id.data()), 32));
  auto payload = signed_part.finalize();
  auto slice = vm::load_cell_slice(payload);
  unsigned char bits[64] = {};
  expect(slice.size() % 8 == 0 && slice.size() / 8 <= sizeof(bits), "fixture-vote-payload");
  const auto length = slice.size() / 8;
  expect(slice.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(bits), length)), "fixture-vote-payload");
  unsigned char signature[64] = {};
  expect(crypto_sign_detached(signature, nullptr, bits, length, voter().secret) == 0, "fixture-vote-signature");

  vm::CellBuilder body;
  body.store_long(0x566f7465, 32).store_long(0, 64);
  body.store_bytes(td::Slice(reinterpret_cast<const char*>(signature), 64));
  body.append_cellslice(vm::load_cell_slice_ref(payload));
  return run_contract(contract, body.finalize(), 1, 1000, host,
                      active ? vm::validator_auth_capability : 0, vm::validator_auth_min_version, false, {},
                      1000000, active, {}, voter_public(), votes);
}


// The vote dictionary the contract loads, holding one proposal at its own hash.
td::Ref<vm::Cell> vote_dictionary(const td::Ref<vm::Cell>& proposal, const unsigned char* voting_key, unsigned wins,
                                  bool current_set) {
  auto status = proposal_status(proposal, validator_set_cell(voting_key), wins, current_set);
  vm::Dictionary votes(256);
  auto id = proposal->get_hash().as_array();
  expect(votes.set(td::ConstBitPtr(id.data()), 256, vm::load_cell_slice_ref(status)), "fixture-vote-entry");
  return votes.get_root_cell();
}

// The vote dictionary as the account holds it after a run.
td::Ref<vm::Cell> stored_votes(const td::Ref<vm::Cell>& data) {
  if (data.is_null())
    return {};
  vm::CellSlice cs{vm::NoVm{}, data};
  if (cs.size() < 289 || cs.size_refs() < 1)
    return {};
  cs.fetch_ref();
  if (!cs.advance(288))
    return {};
  if (cs.fetch_ulong(1) != 1 || cs.size_refs() == 0)
    return {};
  return cs.prefetch_ref();
}

// The wins field of one proposal's stored status, or -1 when it is gone.
int stored_wins(const td::Ref<vm::Cell>& data, const td::Ref<vm::Cell>& proposal) {
  auto root = stored_votes(data);
  if (root.is_null())
    return -1;
  vm::Dictionary votes(root, 256);
  auto id = proposal->get_hash().as_array();
  auto entry = votes.lookup(td::ConstBitPtr(id.data()), 256);
  if (entry.is_null())
    return -1;
  auto status = *entry;
  // cfg_proposal_status#ce expires proposal is_critical voters weight vset_id
  // rounds_remaining wins losses
  if (status.fetch_ulong(8) != 0xce || !status.advance(32) || status.size_refs() == 0)
    return -1;
  status.fetch_ref();
  if (!status.advance(1))
    return -1;
  if (status.fetch_ulong(1) == 1) {
    if (status.size_refs() == 0)
      return -1;
    status.fetch_ref();
  }
  if (!status.advance(64 + 256 + 8))
    return -1;
  auto wins = status.fetch_ulong(8);
  return wins == vm::CellSlice::fetch_long_eof ? -1 : static_cast<int>(wins);
}

}  // namespace config_contract_fixture
