// Executes the built configuration contract. Persistent data and the committed
// checkpoint are separate observations: a successful host call proves neither.
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

namespace {
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
    charge(10);
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
    charge(10);
    ++applies;
    expect(update.not_null() && evidence.not_null(), "host-operands-present");
    if (expected_update.not_null()) {
      expect(same_cell(update, expected_update) && same_cell(evidence, expected_evidence), "host-operands-bound");
    }
    installed = returned_registry.not_null() ? returned_registry : vm::CellBuilder().store_long(0xa5a5, 16).finalize();
    return installed;
  }
  td::Ref<vm::Cell> bind(td::Ref<vm::Cell> elected, td::Ref<vm::Cell> bindings, const Charge& charge) override {
    charge(10);
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
                                td::Ref<vm::Cell> votes = {}) {
  vm::CellBuilder data;
  data.store_ref(config).store_long(0, 32).store_zeroes(256);
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
td::Ref<vm::Cell> validator_set_cell(const unsigned char* voting_key) {
  vm::CellBuilder descriptor;
  descriptor.store_long(0x53, 8).store_long(0x8e81278a, 32);
  descriptor.store_bytes(td::Slice(reinterpret_cast<const char*>(voting_key), 32));
  descriptor.store_long(5, 64);
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
    expect(dict.set_ref(key.cbits(), 32, validator_set_cell(voting_key)), "fixture-config34");
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

Outcome run_contract(const td::Ref<vm::Cell>& contract, const td::Ref<vm::Cell>& body, std::uint64_t from,
                     std::uint32_t now, Host* host, td::uint64 capabilities, int version,
                     bool external = false, td::Ref<vm::Cell> registry = {}, long long gas_limit = 1000000,
                     bool config8_active = false, td::Ref<vm::Cell> checkpoint = {},
                     const unsigned char* voting_key = nullptr, td::Ref<vm::Cell> votes = {},
                     long long credit = 0) {
  expect(contract.not_null(), "contract-loaded");
  auto config = configuration(std::move(registry), config8_active, voting_key);
  auto message = external ? external_message(body) : internal_message(from, body);
  auto data = contract_data(config, std::move(checkpoint), std::move(votes));
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
    // With a credit the run starts with no limit of its own, exactly as an
    // unaccepted external message does: everything before accept_message has to
    // fit in the credit, and accepting is what raises the ceiling to the limit.
    // A credit still standing at the end is therefore a run that never accepted.
    auto gas = credit ? vm::GasLimits{0, gas_limit, credit} : vm::GasLimits{gas_limit, gas_limit};
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

// One tick-tock of the configuration account. No message, which is the whole
// point: this is the transaction a block with nothing to process still runs.
Outcome run_ticktock(const td::Ref<vm::Cell>& contract, Host* host, td::uint64 capabilities, int version,
                     bool config8_active, td::Ref<vm::Cell> registry = {}, td::Ref<vm::Cell> checkpoint = {},
                     long long gas_limit = 1000000, const unsigned char* voting_key = nullptr,
                     td::Ref<vm::Cell> votes = {}) {
  expect(contract.not_null(), "contract-loaded");
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

std::vector<Case> cases(const td::Ref<vm::Cell>& contract) {
  return {
      // A block with no registry message. The account's own tick-tock is what
      // persists the state that fell due in it, through the ordinary
      // compute/commit path every other transaction uses -- not through a
      // native write that would be a second installer beside the contract.
      //
      // Both homes are asserted, and both come out of the one cell the host
      // returned: the parameter is the checkpoint's first reference, so the
      // account and parameter 46 cannot end up describing different registries.
      {"a-due-only-tick-tock-persists-the-prefix", [=] {
         Host host;
         auto registry = vm::CellBuilder().store_long(0x76617131, 32).store_long(7777, 32).finalize();
         host.returned_checkpoint = shaped_checkpoint(registry, 11);
         auto outcome = run_ticktock(contract, &host, vm::validator_auth_capability,
                                     vm::validator_auth_min_version, true);
         expect(outcome.exit == 0, "a-due-only-tick-tock-persists-the-prefix");
         expect(host.checkpoints == 1, "a-due-only-tick-tock-persists-the-prefix");
         expect(same_cell(installed_parameter(outcome.data, 46), registry),
                "a-due-only-tick-tock-persists-the-prefix");
         expect(same_cell(stored_checkpoint(outcome.data), host.returned_checkpoint),
                "a-due-only-tick-tock-persists-the-prefix");
       }},
      // And an inactive chain reaches no instruction at all, so a tick-tock
      // there is exactly the tick-tock it has always been.
      {"an-inactive-chain-tick-tock-asks-for-nothing", [=] {
         Host host;
         auto outcome = run_ticktock(contract, &host, 0, vm::validator_auth_min_version, false);
         expect(outcome.exit == 0, "an-inactive-chain-tick-tock-asks-for-nothing");
         expect(host.checkpoints == 0, "an-inactive-chain-tick-tock-asks-for-nothing");
         expect(installed_parameter(outcome.data, 46).is_null(), "an-inactive-chain-tick-tock-asks-for-nothing");
       }},
      // Normal configuration voting reaching its threshold no longer installs
      // anything on an active chain. The proposal stays where it is, marked
      // terminal, and a governance operation is what finalizes it: a
      // configuration parameter needs that quorum as well as the vote.
      //
      // Three separate paths could undo that, and each has its own case: the
      // vote that reaches the threshold, a later vote arriving at a terminal
      // proposal, and the tick-tock scan, which reaches the rotation reset
      // without any vote at all.
      {"a-completed-vote-installs-nothing-under-governance", [=] {
         Host host;
         auto value = vm::CellBuilder().store_long(0x5151, 16).finalize();
         auto proposal = config_proposal(17, value);
         auto votes = vote_dictionary(proposal, voter_public(), 0, true);
         auto run = cast_vote(contract, proposal, votes, &host, true);
         expect(run.exit == 0, "a-completed-vote-installs-nothing-under-governance");
         expect(installed_parameter(run.committed_data, 17).is_null(),
                "a-completed-vote-installs-nothing-under-governance");
         expect(stored_wins(run.committed_data, proposal) == 255,
                "a-completed-vote-installs-nothing-under-governance");
         expect(answer_tag(run.actions) == std::optional<std::uint32_t>{0xd6745240 + 3},
                "a-completed-vote-installs-nothing-under-governance");
       }},
      // A later vote changes nothing. Without the gate it would be registered,
      // and on a stale set it would first be reset for a new round.
      {"a-terminal-proposal-takes-no-further-votes", [=] {
         Host host;
         auto proposal = config_proposal(17, vm::CellBuilder().store_long(0x5151, 16).finalize());
         auto votes = vote_dictionary(proposal, voter_public(), 255, false);
         auto run = cast_vote(contract, proposal, votes, &host, true);
         expect(run.exit == 0, "a-terminal-proposal-takes-no-further-votes");
         expect(stored_wins(run.committed_data, proposal) == 255,
                "a-terminal-proposal-takes-no-further-votes");
         expect(same_cell(stored_votes(run.committed_data), votes),
                "a-terminal-proposal-takes-no-further-votes");
         expect(answer_tag(run.actions) == std::optional<std::uint32_t>{0xd6745240 + 3},
                "a-terminal-proposal-takes-no-further-votes");
       }},
      // The tick-tock scan reaches the rotation reset without any vote, so a
      // terminal proposal recognised only in the vote path would still be reset
      // by a random scan.
      {"a-terminal-proposal-survives-a-tick-tock-scan", [=] {
         Host host;
         auto proposal = config_proposal(17, vm::CellBuilder().store_long(0x5151, 16).finalize());
         auto votes = vote_dictionary(proposal, voter_public(), 255, false);
         host.returned_checkpoint = shaped_checkpoint(
             vm::CellBuilder().store_long(0x76617131, 32).store_long(7777, 32).finalize(), 11);
         auto run = run_ticktock(contract, &host, vm::validator_auth_capability,
                                 vm::validator_auth_min_version, true, {}, {}, 1000000, voter_public(), votes);
         expect(run.exit == 0, "a-terminal-proposal-survives-a-tick-tock-scan");
         expect(same_cell(stored_votes(run.data), votes), "a-terminal-proposal-survives-a-tick-tock-scan");
       }},
      // And a chain that has not activated installs on the threshold exactly as
      // it always did.
      {"an-inactive-chain-installs-on-the-threshold", [=] {
         Host host;
         auto value = vm::CellBuilder().store_long(0x5151, 16).finalize();
         auto proposal = config_proposal(17, value);
         auto votes = vote_dictionary(proposal, voter_public(), 0, true);
         auto run = cast_vote(contract, proposal, votes, &host, false);
         expect(run.exit == 0, "an-inactive-chain-installs-on-the-threshold");
         expect(same_cell(installed_parameter(run.committed_data, 17), value),
                "an-inactive-chain-installs-on-the-threshold");
       }},
      // The second of the two gates. A proposal that completed normal voting is
      // finalized by a governance operation and only then installed, in the one
      // transaction that also commits the registry the operation produced.
      {"a-governance-operation-finalizes-a-completed-proposal", [=] {
         auto cells = registry_cells();
         auto host = registry_host(cells);
         auto value = vm::CellBuilder().store_long(0x5151, 16).finalize();
         auto proposal = config_proposal(17, value);
         auto votes = vote_dictionary(proposal, voter_public(), 255, false);
         auto stale = vm::CellBuilder().store_long(0x7b, 8).finalize();
         auto run = run_contract(contract, registry_body(cells, proposal), 0, 1000, &host,
                                 vm::validator_auth_capability, vm::validator_auth_min_version, true, {},
                                 1000000, true, stale, voter_public(), votes);
         expect(run.exit == 0 && host.applies == 1 && host.checkpoints == 1,
                "a-governance-operation-finalizes-a-completed-proposal");
         // The checkpoint is restaged here as it is for any registry update:
         // the account and parameter 46 have to describe the same registry, and
         // a finalization that kept the old one would leave them describing two.
         auto written = stored_checkpoint(run.committed_data);
         expect(written.not_null() && !same_cell(written, stale),
                "a-governance-operation-finalizes-a-completed-proposal");
         // Both halves in one commit: the parameter the proposal names and the
         // registry the operation produced.
         expect(same_cell(installed_parameter(run.committed_data, 17), value),
                "a-governance-operation-finalizes-a-completed-proposal");
         expect(same_cell(installed_parameter(run.committed_data, 46), cells.after),
                "a-governance-operation-finalizes-a-completed-proposal");
         // And the proposal is consumed, so the same quorum cannot finalize it
         // again against a later state.
         expect(stored_wins(run.committed_data, proposal) == -1,
                "a-governance-operation-finalizes-a-completed-proposal");
       }},
      // A finalization the acceptance rules refuse changes nothing at all: not
      // the parameter, not the registry, and not the proposal, which stays
      // awaiting governance rather than being spent. The proposal here states a
      // condition the parameter does not currently meet.
      {"a-refused-finalization-leaves-the-proposal", [=] {
         auto cells = registry_cells();
         auto host = registry_host(cells);
         auto value = vm::CellBuilder().store_long(0x5151, 16).finalize();
         auto wrong = cell_hash_of(vm::CellBuilder().store_long(0x9999, 16).finalize());
         auto proposal = config_proposal(17, value, &wrong);
         auto votes = vote_dictionary(proposal, voter_public(), 255, false);
         auto run = run_contract(contract, registry_body(cells, proposal), 0, 1000, &host,
                                 vm::validator_auth_capability, vm::validator_auth_min_version, true, {},
                                 1000000, true, {}, voter_public(), votes);
         // Nothing is committed at all, which is what leaves the proposal
         // where it was: the account is never written, so it still holds the
         // status marked awaiting governance and a later attempt can use it.
         expect(run.exit == 53 && !run.committed, "a-refused-finalization-leaves-the-proposal");
         expect(run.committed_data.is_null(), "a-refused-finalization-leaves-the-proposal");
       }},
      // And it never accepts the message. The conditions that refused it can
      // refuse a finalization whose governance is perfectly valid -- the
      // parameter moved since the vote, or it is mandatory, or it is critical
      // and this was not a critical vote -- and the request is unsigned, so
      // anyone can replay it. Accepting first would make the configuration
      // account pay each time for a request that could never have succeeded.
      //
      // The gas limit here is the credit an unaccepted external message runs
      // on, not the account's. A run that reached accept_message would exceed
      // it and fail differently, which is what distinguishes "refused inside
      // the credit" from "refused after the account was committed to paying".
      {"a-refused-finalization-never-accepts", [=] {
         auto cells = registry_cells();
         auto host = registry_host(cells);
         auto value = vm::CellBuilder().store_long(0x5151, 16).finalize();
         auto wrong = cell_hash_of(vm::CellBuilder().store_long(0x9999, 16).finalize());
         auto proposal = config_proposal(17, value, &wrong);
         auto votes = vote_dictionary(proposal, voter_public(), 255, false);
         auto run = run_contract(contract, registry_body(cells, proposal), 0, 1000, &host,
                                 vm::validator_auth_capability, vm::validator_auth_min_version, true, {}, 1000000,
                                 true, {}, voter_public(), votes, external_gas_credit);
         expect(run.exit == 53, "a-refused-finalization-never-accepts");
         expect(!run.accepted, "a-refused-finalization-never-accepts");
         expect(!run.committed && run.committed_data.is_null(), "a-refused-finalization-never-accepts");
       }},
      // The other half of moving the conditions before the acceptance: a
      // finalization that should succeed has to still reach accept_message
      // inside the credit an external message runs on before it is accepted.
      // Refusing early is only an improvement if the valid path still fits.
      //
      // Measured rather than asserted from a constant: the case reports what
      // the successful run consumed up to and including the instruction that
      // stages the checkpoint, and requires real headroom under the credit. If
      // this ever fails the answer is the gas this operation is allocated, not
      // moving the conditions back after the account is committed to paying.
      // The other half of moving the conditions before the acceptance: a
      // finalization that should succeed must still reach accept_message inside
      // the credit an external message runs on before it is accepted. Refusing
      // early is only an improvement if the valid path still fits.
      //
      // What it needs is found rather than asserted from a constant, which
      // would be a claim about a build that may no longer exist: the credit is
      // raised until the run accepts, and the answer is compared with the
      // network's. The ordinary registry update is measured beside it so a
      // regression in one is not read as the cost of the other.
      //
      // If this ever fails, the answer is the gas this operation is allocated.
      // Moving the conditions back after the account is committed to paying
      // would hide a pre-accept budget problem behind account-paid execution.
      {"a-valid-finalization-reaches-accept-with-real-gas-credit", [=] {
         const auto needed = [&](bool finalizing) {
           auto value = vm::CellBuilder().store_long(0x5151, 16).finalize();
           auto proposal = config_proposal(17, value);
           for (long long credit = 500; credit <= external_gas_credit * 8; credit += 250) {
             auto cells = registry_cells();
             auto host = registry_host(cells);
             auto votes = finalizing ? vote_dictionary(proposal, voter_public(), 255, false) : td::Ref<vm::Cell>{};
             auto run = run_contract(contract, registry_body(cells, finalizing ? proposal : td::Ref<vm::Cell>{}), 0,
                                     1000, &host, vm::validator_auth_capability, vm::validator_auth_min_version,
                                     true, {}, 1000000, true, {}, finalizing ? voter_public() : nullptr, votes,
                                     credit);
             if (run.accepted)
               return credit;
           }
           return -1LL;
         };
         const auto finalization = needed(true), update = needed(false);
         std::cerr << "MEASURE registry_update_credit=" << update << " finalization_credit=" << finalization
                   << " network_credit=" << external_gas_credit << '\n';
         expect(update > 0 && finalization > 0, "a-valid-finalization-reaches-accept-with-real-gas-credit");
         // It fits, and the margin is reported rather than asserted against a
         // number chosen here. How much margin is enough is a statement about
         // the worst registry this operation can be asked to walk, which the
         // host's read budget bounds and this fixture does not exercise; a
         // threshold invented to match one measurement would go green at any
         // later cost that still squeaked under it.
         expect(finalization < external_gas_credit,
                "a-valid-finalization-reaches-accept-with-real-gas-credit");

         // And the run that fits actually installs both halves.
         auto cells = registry_cells();
         auto host = registry_host(cells);
         auto value = vm::CellBuilder().store_long(0x5151, 16).finalize();
         auto proposal = config_proposal(17, value);
         auto votes = vote_dictionary(proposal, voter_public(), 255, false);
         auto run = run_contract(contract, registry_body(cells, proposal), 0, 1000, &host,
                                 vm::validator_auth_capability, vm::validator_auth_min_version, true, {}, 1000000,
                                 true, {}, voter_public(), votes, external_gas_credit);
         expect(run.exit == 0 && run.committed && run.accepted,
                "a-valid-finalization-reaches-accept-with-real-gas-credit");
         expect(same_cell(installed_parameter(run.committed_data, 17), value),
                "a-valid-finalization-reaches-accept-with-real-gas-credit");
         expect(same_cell(installed_parameter(run.committed_data, 46), cells.after),
                "a-valid-finalization-reaches-accept-with-real-gas-credit");
       }},
      // A proposal that has not completed normal voting is not finalizable: the
      // governing quorum is the second gate, not a way around the first.
      {"a-proposal-still-in-voting-is-not-finalizable", [=] {
         auto cells = registry_cells();
         auto host = registry_host(cells);
         auto proposal = config_proposal(17, vm::CellBuilder().store_long(0x5151, 16).finalize());
         auto votes = vote_dictionary(proposal, voter_public(), 0, false);
         auto run = run_contract(contract, registry_body(cells, proposal), 0, 1000, &host,
                                 vm::validator_auth_capability, vm::validator_auth_min_version, true, {},
                                 1000000, true, {}, voter_public(), votes);
         // The exact refusal, not merely a refusal: the unpack below throws on
         // its own for some shapes, so a case asking only "did it fail" would
         // stay green with this gate removed and be measuring the decoder.
         expect(run.exit == 52, "a-proposal-still-in-voting-is-not-finalizable");
         expect(installed_parameter(run.committed_data, 17).is_null(),
                "a-proposal-still-in-voting-is-not-finalizable");
       }},
      // And one that was never voted on at all.
      {"an-unknown-proposal-is-not-finalizable", [=] {
         auto cells = registry_cells();
         auto host = registry_host(cells);
         auto proposal = config_proposal(17, vm::CellBuilder().store_long(0x5151, 16).finalize());
         auto other = config_proposal(18, vm::CellBuilder().store_long(0x6262, 16).finalize());
         auto votes = vote_dictionary(other, voter_public(), 255, false);
         auto run = run_contract(contract, registry_body(cells, proposal), 0, 1000, &host,
                                 vm::validator_auth_capability, vm::validator_auth_min_version, true, {},
                                 1000000, true, {}, voter_public(), votes);
         expect(run.exit == 50, "an-unknown-proposal-is-not-finalizable");
         expect(installed_parameter(run.committed_data, 17).is_null(), "an-unknown-proposal-is-not-finalizable");
       }},
      {"contract-assembles-and-loads", [=] { expect(contract.not_null(), "contract-assembles-and-loads"); }},
      {"registry-action-reaches-the-host", [] {
         Host host;
         expect(run_apply(true, host, vm::validator_auth_capability, vm::validator_auth_min_version) == 0 &&
                    host.applies == 1, "registry-action-reaches-the-host");
       }},
      {"absent-host-refuses", [] {
         Host host;
         expect(run_apply(false, host, vm::validator_auth_capability, vm::validator_auth_min_version) != 0 &&
                    host.applies == 0, "absent-host-refuses");
       }},
      {"absent-capability-refuses", [] {
         Host host;
         expect(run_apply(true, host, 0, vm::validator_auth_min_version) != 0 && host.applies == 0,
                "absent-capability-refuses");
       }},
      {"earlier-version-refuses", [] {
         Host host;
         expect(run_apply(true, host, vm::validator_auth_capability, vm::validator_auth_min_version - 1) != 0 &&
                    host.applies == 0, "earlier-version-refuses");
       }},
      // What decides whether a set is bound is Config8, not whether the sender
      // attached bindings. The four cases below hold the virtual machine
      // active throughout and move only Config8, so a contract that ignored
      // Config8 and branched on the message would pass two of them and fail
      // two.
      {"inactive-unbound-set-installs-legacy-unchanged", [=] {
         auto set = elected_set(5000, 6000);
         auto body = vm::CellBuilder().store_long(0x4e565354, 32).store_long(7, 64).store_ref(set).finalize();
         Host host;
         auto run = run_contract(contract, body, elector_account, 1000, &host, vm::validator_auth_capability,
                                 vm::validator_auth_min_version, false, {}, 1000000, false);
         expect(run.exit == 0 && same_cell(installed_parameter(run.data, 36), set) && host.binds == 0,
                "inactive-unbound-set-installs-legacy-unchanged");
       }},
      // Bindings offered to a chain that has not activated are ignored, not
      // honoured: a sender cannot opt the chain into the registry early.
      {"inactive-set-with-bindings-installs-legacy-unchanged", [=] {
         auto set = elected_set(5000, 6000);
         auto body = vm::CellBuilder().store_long(0x4e565354, 32).store_long(7, 64)
                         .store_ref(set).store_ref(bindings_cell()).finalize();
         Host host;
         auto run = run_contract(contract, body, elector_account, 1000, &host, vm::validator_auth_capability,
                                 vm::validator_auth_min_version, false, {}, 1000000, false);
         expect(run.exit == 0 && same_cell(installed_parameter(run.data, 36), set) && host.binds == 0,
                "inactive-set-with-bindings-installs-legacy-unchanged");
       }},
      // The bypass this reordering exists to close. An unbound set is exactly
      // what an attacker would send once the chain is active, so it is refused
      // rather than installed without the registry ever being consulted.
      {"active-unbound-set-is-refused", [=] {
         auto body = vm::CellBuilder().store_long(0x4e565354, 32).store_long(7, 64)
                         .store_ref(elected_set(5000, 6000)).finalize();
         Host host;
         auto run = run_contract(contract, body, elector_account, 1000, &host, vm::validator_auth_capability,
                                 vm::validator_auth_min_version, false, {}, 1000000, true);
         expect(run.exit == 45 && host.binds == 0 && installed_parameter(run.data, 36).is_null(),
                "active-unbound-set-is-refused");
       }},
      {"active-set-with-bindings-is-installed-bound", [=] {
         auto set = elected_set(5000, 6000);
         auto named = bindings_cell();
         auto body = vm::CellBuilder().store_long(0x4e565354, 32).store_long(7, 64)
                         .store_ref(set).store_ref(named).finalize();
         Host host;
         auto run = run_contract(contract, body, elector_account, 1000, &host, vm::validator_auth_capability,
                                 vm::validator_auth_min_version, false, {}, 1000000, true);
         expect(run.exit == 0 && host.binds == 1 && same_cell(host.last_elected, set) &&
                    same_cell(host.last_bindings, named) && same_cell(installed_parameter(run.data, 36), host.bound),
                "active-set-with-bindings-is-installed-bound");
       }},
      // Config8 says active and the virtual machine refuses the instruction --
      // a node that disagrees with its own chain. Nothing is installed. This is
      // the case the capability gate is for, and it only exists because the two
      // switches are separate.
      {"a-chain-whose-vm-refuses-the-instruction-installs-nothing", [=] {
         auto body = vm::CellBuilder().store_long(0x4e565354, 32).store_long(7, 64)
                         .store_ref(elected_set(5000, 6000)).store_ref(bindings_cell()).finalize();
         Host host;
         auto run = run_contract(contract, body, elector_account, 1000, &host, 0, vm::validator_auth_min_version,
                                 false, {}, 1000000, true);
         expect(run.exit != 0 && host.binds == 0 && installed_parameter(run.data, 36).is_null(),
                "a-chain-whose-vm-refuses-the-instruction-installs-nothing");
       }},
      {"a-set-from-anyone-else-is-not-installed", [=] {
         auto body = vm::CellBuilder().store_long(0x4e565354, 32).store_long(7, 64)
                         .store_ref(elected_set(5000, 6000)).store_ref(bindings_cell()).finalize();
         Host host;
         auto run = run_contract(contract, body, elector_account + 1, 1000, &host, vm::validator_auth_capability,
                                 vm::validator_auth_min_version);
         expect(host.binds == 0 && installed_parameter(run.data, 36).is_null(),
                "a-set-from-anyone-else-is-not-installed");
       }},
      // The account carries the checkpoint its registry is restored from, beside
      // the parameter that holds the registry itself. Every store has to carry
      // it forward, which is why the store lives in store_data rather than in
      // the registry branch: an ordinary operation has nothing to do with the
      // registry and must not drop it.
      //
      // What is pinned below is the registry path. The vote path also stores,
      // and is not exercised here: reaching it needs an elected set in
      // parameter 34 and a signature from one of its members, which no fixture
      // in this file builds. The mechanism it would exercise is the same one,
      // in the same function.
      // The path the fix exists for. A vote has nothing to do with the
      // registry, and it stores; if the store dropped the checkpoint, the next
      // block would open an account it cannot restore -- and no registry case
      // would see it, because they all begin from an account that has one.
      {"a-vote-keeps-the-checkpoint", [=] {
         unsigned char voter[32] = {}, voter_secret[64] = {};
         expect(crypto_sign_keypair(voter, voter_secret) == 0, "fixture-voter");
         auto carried = vm::CellBuilder().store_long(0x7b, 8).finalize();

         // Everything the contract signs over, after the signature it strips.
         vm::CellBuilder signed_part;
         signed_part.store_long(0x566f7465, 32).store_long(0, 32).store_long(0xfffffffe, 32);
         signed_part.store_long(0, 16).store_zeroes(256);
         auto payload = signed_part.finalize();
         auto slice = vm::load_cell_slice(payload);
         unsigned char bits[64] = {};
         expect(slice.size() % 8 == 0 && slice.size() / 8 <= sizeof(bits), "fixture-vote-payload");
         const auto length = slice.size() / 8;
         expect(slice.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(bits), length)), "fixture-vote-payload");
         unsigned char signature[64] = {};
         expect(crypto_sign_detached(signature, nullptr, bits, length, voter_secret) == 0, "fixture-vote-signature");

         vm::CellBuilder body;
         body.store_bytes(td::Slice(reinterpret_cast<const char*>(signature), 64));
         body.append_cellslice(vm::load_cell_slice_ref(payload));
         Host host;
         auto run = run_contract(contract, body.finalize(), 0, 1000, &host, vm::validator_auth_capability,
                                 vm::validator_auth_min_version, true, {}, 1000000, false, carried, voter);
         expect(run.committed, "a-vote-keeps-the-checkpoint");
         expect(same_cell(stored_checkpoint(run.committed_data), carried), "a-vote-keeps-the-checkpoint");
         expect(host.applies == 0 && host.binds == 0, "a-vote-keeps-the-checkpoint");
       }},
      // A registry update replaces it with the one for the state it just
      // staged, taken from the state instruction rather than invented.
      {"a-registry-update-stores-the-staged-checkpoint", [=] {
         auto cells = registry_cells();
         auto stale = vm::CellBuilder().store_long(0x7b, 8).finalize();
         auto host = registry_host(cells);
         auto run = run_contract(contract, registry_body(cells), 0, 1000, &host, vm::validator_auth_capability,
                                 vm::validator_auth_min_version, true, {}, 1000000, false, stale);
         expect(run.exit == 0 && host.applies == 1 && host.checkpoints == 1,
                "a-registry-update-stores-the-staged-checkpoint");
         auto written = stored_checkpoint(run.committed_data);
         expect(written.not_null() && !same_cell(written, stale),
                "a-registry-update-stores-the-staged-checkpoint");
         expect(same_cell(installed_parameter(run.committed_data, 46), cells.after),
                "a-registry-update-stores-the-staged-checkpoint");
       }},
      {"registry-c4-installs-parameter-46", [=] {
         auto cells = registry_cells();
         expect(installed_parameter(contract_data(configuration()), 46).is_null(), "fixture-parameter-absent");
         auto host = registry_host(cells);
         const auto run = registry_run(contract, cells, host, false);
         expect(run.exit == 0 && host.applies == 1 && same_cell(installed_parameter(run.data, 46), cells.after) &&
                    same_cell(installed_parameter(run.committed_data, 46), cells.after) && stored_sequence(run.data) == 1,
                "registry-c4-installs-parameter-46");
       }},
      {"registry-c4-replaces-old-parameter-46", [=] {
         auto cells = registry_cells();
         expect(same_cell(installed_parameter(contract_data(configuration(cells.before)), 46), cells.before),
                "fixture-old-parameter-present");
         auto host = registry_host(cells);
         const auto run = registry_run(contract, cells, host, true);
         expect(run.exit == 0 && host.applies == 1 && same_cell(installed_parameter(run.data, 46), cells.after) &&
                    same_cell(installed_parameter(run.committed_data, 46), cells.after) && stored_sequence(run.data) == 1,
                "registry-c4-replaces-old-parameter-46");
       }},
      {"registry-first-checkpoint-installs-new-parameter", [=] {
         auto cells = registry_cells();
         const auto run = first_committed_registry_run(contract, cells, false);
         expect(same_cell(installed_parameter(run.committed_data, 46), cells.after) &&
                    stored_sequence(run.committed_data) == 1, "registry-first-checkpoint-installs-new-parameter");
       }},
      {"registry-first-checkpoint-replaces-old-parameter", [=] {
         auto cells = registry_cells();
         const auto run = first_committed_registry_run(contract, cells, true);
         expect(same_cell(installed_parameter(run.committed_data, 46), cells.after) &&
                    stored_sequence(run.committed_data) == 1, "registry-first-checkpoint-replaces-old-parameter");
       }},
  };
}

void write_cell(const std::filesystem::path& path, const td::Ref<vm::Cell>& cell) {
  auto boc = vm::std_boc_serialize(canonical_cell(cell), 2);
  expect(boc.is_ok(), "export-encode");
  std::ofstream file(path, std::ios::binary);
  const auto bytes = boc.ok().as_slice();
  file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  expect(file.good(), "export-write");
}

void export_cells(const std::filesystem::path& dir, const td::Ref<vm::Cell>& contract) {
  std::filesystem::create_directories(dir);
  auto cells = registry_cells();
  write_cell(dir / "contract.boc", contract);
  write_cell(dir / "before.boc", cells.before);
  write_cell(dir / "after.boc", cells.after);
  write_cell(dir / "update.boc", cells.update);
  write_cell(dir / "evidence.boc", cells.evidence);
  write_cell(dir / "body.boc", registry_body(cells));
  write_cell(dir / "data-empty.boc", contract_data(configuration()));
  write_cell(dir / "data-old.boc", contract_data(configuration(cells.before)));
  std::cout << "EXPORTED_CONFIG_PERSISTENCE_CELLS\n";
}
}  // namespace

int main(int argc, char** argv) {
  try {
    expect(argc >= 2 && argc <= 4, "arguments");
    auto initialized = vm::init_vm();
    expect(initialized.is_ok(), "vm-initialized");
    SET_VERBOSITY_LEVEL(std::getenv("VALIDATOR_AUTH_CONTRACT_TRACE") ? VERBOSITY_NAME(DEBUG) : VERBOSITY_NAME(FATAL));
    auto contract = read_boc(argv[1]);
    if (argc == 4 && std::string(argv[2]) == "--export") {
      export_cells(argv[3], contract);
      return 0;
    }
    const auto inventory = cases(contract);
    const std::string selected = argc == 3 ? argv[2] : "";
    if (selected == "--list") {
      for (const auto& item : inventory)
        std::cout << item.first << '\n';
      return 0;
    }
    std::size_t passed = 0;
    for (const auto& [name, test] : inventory) {
      if (!selected.empty() && selected != name)
        continue;
      std::cout << "SETUP_OK " << name << '\n' << std::flush;
      try {
        test();
      } catch (const std::exception& error) {
        std::cerr << "DETAIL " << error.what() << '\n';
        std::cerr << "ASSERTION_FAILED " << name << '\n';
        return 1;
      } catch (const vm::VmError& error) {
        // Not a std::exception, so without this the process aborts and says
        // nothing at all about which case or which cell was wrong.
        std::cerr << "DETAIL vm-error " << error.get_msg() << '\n';
        std::cerr << "ASSERTION_FAILED " << name << '\n';
        return 1;
      }
      ++passed;
      std::cout << "CASE_PASS " << name << '\n';
    }
    expect(passed != 0, "unknown-case");
    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "HARNESS_FAILURE " << error.what() << '\n';
    return 2;
  }
}
