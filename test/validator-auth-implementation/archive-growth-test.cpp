// Measure what one block costs as the archive grows.
//
// The implementation record declines to claim that per-block work is constant
// with archive size, and nothing measured it: the existing cases assert that a
// block fits one fixed budget at one archive size, which is a bound and not a
// curve. An adapter whose per-block reads grow with retained history degrades
// on exactly the timescale a short run cannot show -- a testnet that is fine
// for three days and a mainnet that is not fine for three months.
//
// The read budget decrements as entries and bytes are read, so the difference
// between the budget given and the budget left is the work actually done.
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "validator/auth/native-registry.h"

#include "native-fixture.h"

using namespace tos::auth;
using namespace p0_fixture;

namespace {
struct Measurement {
  std::size_t archive = 0;
  std::size_t entries = 0;
  std::size_t bytes = 0;
};

// A registry carrying `history` retired key versions beyond its active set.
// Retired versions are exactly what must stay retainable, so they are what
// makes the archive grow in production.
RegistryState archived(std::size_t history) {
  check(sodium_init() >= 0, "sodium");
  auto seed = h(7);
  Hash public_key{};
  std::array<unsigned char, 64> secret{};
  check(crypto_sign_seed_keypair(public_key.data(), secret.data(), seed.data()) == 0, "keygen");
  Policy policy{1, {}, interface_fingerprint, 0, 0, {{1, 1}}, 4096, 524288};

  Identity id;
  id.identity_ = h(1);
  id.stake_id_ = h(1001);
  id.owner_workchain_ = -1;
  id.owner_address_ = h(2001);
  std::vector<Key> keys;
  for (unsigned role = 1; role <= 5; ++role) {
    Key key{id.identity_, static_cast<std::uint8_t>(role), 1, 1, 1, 0, 1000,
            Bytes(public_key.begin(), public_key.end()), {}, 0};
    id.active_.push_back({static_cast<std::uint8_t>(role), value(key_reference(key), "keyref")});
    keys.push_back(key);
  }
  // Superseded versions of one role, each at its own epoch. They are reachable
  // history, never active, which is the shape the archive actually accumulates.
  for (std::size_t n = 0; n < history; ++n) {
    Key old{id.identity_, 1, 1, 1, static_cast<std::uint64_t>(n + 2), 0, 1000,
            Bytes(public_key.begin(), public_key.end()), {}, 0};
    keys.push_back(old);
  }
  return value(RegistryState::genesis(h(5000), policy, {id}, keys), "genesis");
}

// One lookup of one active key, with a budget large enough that it cannot be
// the thing that bounds the answer.
Measurement cost(std::size_t history) {
  auto state = archived(history);
  auto cell = value(state.encode_cell(), "encode");
  StateReadBudget budget{1000000, 268435456};
  auto registry = value(NativeRegistry::bootstrap(cell, 0, budget), "bootstrap");
  auto before = registry.remaining();
  auto found = registry.identity(h(1));
  check(found.ok(), "identity-read");
  auto after = registry.remaining();
  return {history, before.entries - after.entries, before.bytes - after.bytes};
}
}  // namespace

int main(int argc, char** argv) {
  try {
    std::vector<Measurement> measured;
    for (std::size_t history : {std::size_t{0}, std::size_t{100}, std::size_t{1000}, std::size_t{5000}})
      measured.push_back(cost(history));

    for (const auto& m : measured)
      std::cout << "archive=" << m.archive << " entries=" << m.entries << " bytes=" << m.bytes << '\n';

    // The claim under test: reading one identity costs the same regardless of
    // how much retired history sits beside it. If this ever stops holding, the
    // cost is a function of retention and the retention policy becomes a
    // performance decision rather than a correctness one.
    const auto& base = measured.front();
    for (const auto& m : measured) {
      if (m.entries != base.entries || m.bytes != base.bytes) {
        std::cerr << "ASSERTION: lookup-cost-grows-with-archive\n";
        return 1;
      }
    }

    if (argc == 2) {
      std::filesystem::path out(argv[1]);
      std::filesystem::create_directories(out);
      std::ofstream report(out / "archive-growth.txt");
      for (const auto& m : measured)
        report << m.archive << ' ' << m.entries << ' ' << m.bytes << '\n';
    }
    std::cout << "PASS: one identity read costs " << base.entries << " entries and " << base.bytes
              << " bytes at every archive size measured\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
