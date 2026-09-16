// Executes the built configuration contract. Persistent data and the committed
// checkpoint are separate observations: a successful host call proves neither.
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
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
  auto registry = p0_fixture::state(1);
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
  auto next = value(registry.apply_block(1, {{update, evidence}}, p0_fixture::AcceptedFixtureRequests{}),
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
  unsigned applies = 0, binds = 0;
  td::Ref<vm::Cell> installed, bound, last_elected, last_bindings;
  td::Ref<vm::Cell> expected_update, expected_evidence, returned_registry;
  td::Ref<vm::Cell> checkpoint(const Charge& charge) override {
    charge(10);
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

td::Ref<vm::Cell> contract_data(const td::Ref<vm::Cell>& config) {
  return canonical_cell(vm::CellBuilder().store_ref(config).store_long(0, 32).store_zeroes(256)
                            .store_long(0, 1).finalize());
}

// `activated` writes Config8, which is where the contract reads activation
// from. It is separate from the capability the virtual machine is given on
// purpose: a case that turned both off at once could not tell a contract that
// consulted Config8 from one that never ran the instruction because the opcode
// was gated.
td::Ref<vm::Cell> configuration(td::Ref<vm::Cell> registry = {}, bool activated = false) {
  vm::Dictionary dict(32);
  td::BitArray<32> key;
  key.store_long(1);
  expect(dict.set_ref(key.cbits(), 32, address_param(elector_account)), "fixture-config");
  if (registry.not_null()) {
    key.store_long(46);
    expect(dict.set_ref(key.cbits(), 32, registry), "fixture-config46");
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
      .store_long(0, 64).store_long(0, 32).store_long(0, 1).store_long(0, 1);
  cb.append_cellslice(vm::load_cell_slice_ref(body));
  return canonical_cell(cb.finalize());
}

td::Ref<vm::Cell> external_message(const td::Ref<vm::Cell>& body) {
  vm::CellBuilder cb;
  cb.store_long(2, 2).store_long(0, 2);
  cb.append_cellslice(masterchain_address(config_account));
  cb.store_long(0, 4).store_long(0, 1).store_long(1, 1).store_ref(body);
  return canonical_cell(cb.finalize());
}

td::Ref<vm::Cell> registry_body(const RegistryCells& cells) {
  return canonical_cell(vm::CellBuilder().store_zeroes(512).store_long(0x56417531, 32)
                            .store_long(0, 32).store_long(2000, 32)
                            .store_ref(cells.update).store_ref(cells.evidence).finalize());
}

struct Outcome {
  int exit = -1000;
  td::Ref<vm::Cell> data, committed_data;
  bool committed = false;
  long long gas = 0;
};

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
                     bool config8_active = false) {
  expect(contract.not_null(), "contract-loaded");
  auto config = configuration(std::move(registry), config8_active);
  auto message = external ? external_message(body) : internal_message(from, body);
  auto data = contract_data(config);
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
    vm::VmState state{contract, version, std::move(stack), vm::GasLimits{gas_limit, gas_limit}, 1, data, {},
                      {}, registers, capabilities};
    if (host)
      state.set_validator_auth_host(std::shared_ptr<vm::ValidatorAuthHost>(host, [](vm::ValidatorAuthHost*) {}));
    const int exit = ~state.run();
    return {exit, state.get_c4(), state.get_committed_state().c4, state.committed(), state.gas_consumed()};
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
std::vector<Case> cases(const td::Ref<vm::Cell>& contract) {
  return {
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
    SET_VERBOSITY_LEVEL(std::getenv("P0_CONTRACT_TRACE") ? VERBOSITY_NAME(DEBUG) : VERBOSITY_NAME(FATAL));
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
