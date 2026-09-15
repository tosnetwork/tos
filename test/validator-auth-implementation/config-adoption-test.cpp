// Does a registry the contract installed become the configuration the chain
// serves, and the one a validator then reads?
//
// The persistence evidence ends at the account's data. Between that and the
// committee every validator derives stand the masterchain gates: admission of
// the configuration data, the transition between two configurations, and the
// predicate that decides whether the result replaces the installed root and
// marks a key block. These cases construct the configuration the collator
// builds and carry it to the readers that consume it.

#include "config-gates-fixture.h"
#include "validator/auth/native-registry.h"
#include "validator/auth/registry-view.h"

using namespace p0_config_gates_fixture;
using tos::auth::NativeRegistry;
using tos::auth::RegistryView;

namespace {

struct Case {
  const char* name;
  std::function<void()> run;
};

// The collator writes the installed configuration as the configuration address
// followed by a reference to the parameter dictionary. Building it the same way
// here is what makes the readback evidence rather than a restatement of the
// dictionary this test already holds.
td::Ref<vm::Cell> installed_configuration(td::Ref<vm::Cell> parameters, const td::Bits256& address) {
  vm::CellBuilder cb;
  check(cb.store_bits_bool(address) && cb.store_ref_bool(parameters), "installed-configuration");
  return cb.finalize();
}

td::Ref<vm::Cell> parameter_of(td::Ref<vm::Cell> configuration, int index) {
  block::gen::ConfigParams::Record params;
  check(tlb::csr_unpack(vm::load_cell_slice_ref(configuration), params), "installed-configuration-shape");
  vm::Dictionary dictionary(params.config, 32);
  return dictionary.lookup_ref(td::BitArray<32>{index});
}

td::Bits256 configuration_address(td::Ref<vm::Cell> parameters) {
  vm::CellSlice address(vm::NoVm{}, get(parameters, 0));
  td::Bits256 result;
  check(address.fetch_bits_to(result), "configuration-address");
  return result;
}

struct Fixtures {
  td::Ref<vm::Cell> parameters;   // the configuration dictionary with a registry
  td::Ref<vm::Cell> registry;     // the registry root parameter 46 carries
  td::Bits256 address;            // the configuration account
};

Fixtures build(const std::filesystem::path& input) {
  auto raw = read(input);
  auto parsed = vm::std_boc_deserialize(td::Slice(raw.data(), raw.size()));
  check(parsed.is_ok(), "fixture-config");
  auto legacy = parsed.move_as_ok();
  auto registry = value(state(3).encode_cell(), "registry");
  auto parameters = put(put(put(legacy, 8, cap(16)), 16, counts(400)), 46, registry);
  parameters = required(required(parameters, 9, true), 10, true);
  return {parameters, registry, configuration_address(parameters)};
}

// Both readers, because they answer different questions about the same cell and
// a registry only reaches a committee if both accept it.
bool readers_accept(td::Ref<vm::Cell> registry) {
  return NativeRegistry::bootstrap(registry, 0).ok() && RegistryView::open(registry, 0).ok();
}

std::vector<Case> cases(const std::filesystem::path& input) {
  return {
      {"installed-configuration-carries-the-registry",
       [input] {
         auto f = build(input);
         auto configuration = installed_configuration(f.parameters, f.address);
         auto found = parameter_of(configuration, 46);
         check(found.not_null(), "parameter-46-present");
         // Equality of the cell, not merely of something decodable: the chain
         // must serve the registry the contract installed, not one that happens
         // to parse.
         check(hash(found) == hash(f.registry), "parameter-46-is-the-installed-registry");
         check(readers_accept(found), "readers-accept-the-installed-registry");
       }},

      {"a-refused-shape-reaches-no-reader",
       [input] {
         auto f = build(input);
         // Control first. Without it a setup that never produced a usable
         // configuration would satisfy every refusal below.
         check(block::valid_config_data(f.parameters, f.address, true), "control-admits-the-registry");
         check(readers_accept(f.registry), "control-readers-accept");

         auto wrong_magic = change_registry(f.registry, 0, 32, integer(0x76617132, 32));
         auto refused = put(f.parameters, 46, wrong_magic);
         check(!block::valid_config_data(refused, f.address, true), "admission-refuses-the-shape");
         check(!NativeRegistry::bootstrap(wrong_magic, 0).ok(), "bootstrap-refuses-the-shape");
         check(!RegistryView::open(wrong_magic, 0).ok(), "view-refuses-the-shape");
       }},

      {"a-refused-transition-is-not-a-setup-failure",
       [input] {
         auto f = build(input);
         check(block::valid_config_transition(f.parameters, f.parameters).is_ok(), "control-transition-accepted");

         auto other_domain = h(909);
         auto moved = change_registry(f.registry, 48, 256, Bytes(other_domain.begin(), other_domain.end()));
         auto next = put(f.parameters, 46, moved);
         // The refused configuration is structurally valid, so admission still
         // accepts it. That is what makes this a transition refusal rather than
         // a malformed root refused twice.
         check(block::valid_config_data(next, f.address, true), "refused-transition-is-well-formed");
         auto status = block::valid_config_transition(f.parameters, next);
         check(status.is_error() && status.message().str() == "validator-auth-domain", "transition-refuses-the-domain");
       }},

      {"a-registry-change-is-an-important-change",
       [input] {
         auto f = build(input);
         auto revised = put(f.parameters, 46, change_registry(f.registry, 560, 64, integer(1, 64)));
         check(!block::important_config_parameters_changed(f.parameters, f.parameters), "unchanged-is-not-important");
         // Not important means the collator leaves the installed root alone and
         // does not mark a key block, so a registry every validator has
         // committed to would never become the one they read.
         check(block::important_config_parameters_changed(f.parameters, revised), "registry-change-is-important");
       }},

      {"the-important-change-predicate-is-order-insensitive",
       [input] {
         auto f = build(input);
         auto revised = put(f.parameters, 46, change_registry(f.registry, 560, 64, integer(1, 64)));
         // The predicate names its arguments old and new, and today decides by
         // comparing hashes, which makes the order immaterial. Its own comment
         // says that parameters will eventually be distinguished. When that
         // happens this case fails, and whoever makes the change has to look at
         // every caller instead of discovering the swap in production.
         check(block::important_config_parameters_changed(f.parameters, revised) ==
                   block::important_config_parameters_changed(revised, f.parameters),
               "order-does-not-decide");
       }},
  };
}

}  // namespace

int main(int argc, char** argv) {
  // The production readers log while they work. Silencing them keeps this
  // driver's error stream to its own verdict, so a harness can require the
  // named assertion and nothing else.
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(FATAL));
  if (argc == 2 && std::string(argv[1]) == "--list") {
    for (const auto& item : cases({})) {
      std::cout << item.name << '\n';
    }
    return 0;
  }
  if (argc < 2) {
    std::cerr << "ASSERTION: arguments\n";
    return 2;
  }
  const std::filesystem::path input(argv[1]);
  const std::string selected = argc == 3 ? argv[2] : "";
  const auto inventory = cases(input);
  std::size_t passed = 0;
  for (const auto& item : inventory) {
    if (!selected.empty() && selected != item.name) {
      continue;
    }
    std::cout << "SETUP_OK " << item.name << '\n' << std::flush;
    try {
      item.run();
    } catch (const std::runtime_error& e) {
      std::cerr << "DETAIL " << item.name << ' ' << e.what() << '\n';
      std::cerr << "ASSERTION_FAILED " << item.name << '\n';
      return 1;
    }
    ++passed;
    std::cout << "CASE_PASS " << item.name << '\n';
  }
  if (!selected.empty() && passed != 1) {
    std::cerr << "UNKNOWN_CASE " << selected << '\n';
    return 2;
  }
  std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
  return 0;
}
