// Each privileged host implements only the operation its transaction is for.
//
// The privileged surface is one interface with three operations, but no
// transaction legitimately performs all three: a registry update arrives as an
// external message carrying evidence and applies it, while an elected set
// arrives from the elector and is bound against the registry. Sharing one host
// between them would mean a single object built from two unrelated message
// shapes, and which operation a contract could reach would depend on which
// shape happened to build it.
//
// A comment saying so is not enforceable. These cases call the operations this
// host does not implement and require the refusal a contract would get with no
// host at all -- the instruction does not exist for this caller, which is the
// same answer whether it arrived with the wrong authority or with none.
//
// The matching case for the update host lives with the admission suite, where a
// real one is already assembled from a real message. Building a second valid
// one here would have meant a committee and a governing snapshot that the
// property does not depend on.
#include <iostream>
#include <stdexcept>
#include <string>

#include "validator/auth/native-election-binding-host.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"
#include "vm/excno.hpp"

#include "native-fixture.h"

using namespace tos::auth;
using namespace p0_fixture;

namespace {
unsigned passed = 0, failed = 0;

void report(bool condition, const std::string& name) {
  if (condition) {
    ++passed;
    std::cout << "CASE_PASS " << name << '\n';
  } else {
    ++failed;
    std::cout << "CASE_FAIL " << name << '\n';
  }
}

// The refusal an absent host produces, so a host that is present but wrong is
// indistinguishable from one that was never installed.
bool refuses_as_absent(const std::function<void()>& call) {
  try {
    call();
  } catch (const vm::VmError& error) {
    return error.get_errno() == static_cast<int>(vm::Excno::inv_opcode);
  } catch (...) {
    return false;
  }
  return false;
}

NativeRegistryBlock registry_block() {
  auto encoded = value(p0_fixture::state(1).encode_cell(), "fixture-registry-cell");
  auto registry = value(NativeRegistry::bootstrap(encoded, 0), "fixture-registry");
  return value(NativeRegistryBlock::begin(registry, 1), "fixture-block");
}
}  // namespace

int main() {
  try {
    const auto charge = [](long long) {};
    auto cell = vm::CellBuilder().finalize();

    // And the binding host is reached by an internal elector message, which
    // carries no evidence and stages no update.
    {
      NativeElectionBindingHost host(registry_block(), 1);
      report(refuses_as_absent([&] { host.checkpoint(charge); }), "election-binding-host-refuses-state");
      report(refuses_as_absent([&] { host.apply(cell, cell, charge); }), "election-binding-host-refuses-apply");
      // The operation it does implement is reached, and refuses its own way:
      // an operand failure is not the absent-host answer, or the two cases
      // above would pass for a host that refused everything.
      report(!refuses_as_absent([&] { host.bind({}, {}, charge); }), "election-binding-host-reaches-bind");
    }

    // What a host charges must count the reads that happened, not the reads
    // that turned out to be useful. A refusal rolls the registry back; it must
    // not roll back the work, or arranging to fail at the end would read the
    // registry for nothing -- repeatedly, since the next attempt would start
    // from the same allowance.
    // A set the binder walks and then refuses: shaped correctly, bound to
    // nothing the registry knows.
    td::Ref<vm::Cell> elected, bindings;
    {
      elected = vm::CellBuilder()
                         .store_long(0x12, 8)
                         .store_long(0, 32)
                         .store_long(0, 32)
                         .store_long(1, 16)
                         .store_long(1, 16)
                         .store_long(5, 64)
                         .store_long(0, 1)
                         .finalize();
      vm::CellBuilder entry;
      entry.store_zeroes(512);
      vm::Dictionary named(16);
      td::BitArray<16> at;
      at.store_ulong(0);
      check(named.set_builder(at.cbits(), 16, entry), "fixture-bindings");
      vm::CellBuilder wrapper;
      check(wrapper.store_maybe_ref(named.get_root_cell()), "fixture-bindings");
      bindings = wrapper.finalize();
    }

    {
      NativeElectionBindingHost host(registry_block(), 1);
      long long charged = 0;
      const auto meter = [&](long long gas) { charged += gas; };
      bool refused = false;
      try {
        host.bind(elected, bindings, meter);
      } catch (const vm::VmError&) {
        refused = true;
      }
      report(refused && charged > 0, "a-refused-binding-still-charges");

    }

    // And the allowance actually runs down. Charging for a refusal is not the
    // same as remembering it: a meter that reset would charge every attempt and
    // still let a caller read the registry forever. With an allowance that
    // permits only a few reads, repeated refusals must stop being refusals
    // about binding and become refusals about the allowance -- which only
    // happens if what each attempt consumed survived it.
    {
      auto encoded = value(p0_fixture::state(1).encode_cell(), "fixture-registry-cell");
      auto registry = value(NativeRegistry::bootstrap(encoded, 0), "fixture-registry");
      // An allowance a few reads wide, so exhaustion is reachable in a bounded
      // loop rather than after a million attempts.
      NativeElectionBindingHost host(
          value(NativeRegistryBlock::begin(registry, 1, StateReadBudget{16, 1 << 20}), "fixture-block"), 1);
      bool exhausted = false;
      for (unsigned attempt = 0; attempt < 64 && !exhausted; ++attempt) {
        try {
          host.bind(elected, bindings, [](long long) {});
        } catch (const vm::VmError& error) {
          exhausted = std::string(error.get_msg()).find("unreadable") != std::string::npos;
        }
      }
      report(exhausted, "repeated-refusals-exhaust-the-allowance");
    }

    std::cout << "SUMMARY cases=" << passed + failed << " passed=" << passed << '\n';
    return failed ? 1 : 0;
  } catch (const std::exception& error) {
    std::cerr << "HARNESS_FAILURE " << error.what() << '\n';
    return 2;
  }
}
