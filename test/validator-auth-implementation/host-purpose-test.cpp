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

    std::cout << "SUMMARY cases=" << passed + failed << " passed=" << passed << '\n';
    return failed ? 1 : 0;
  } catch (const std::exception& error) {
    std::cerr << "HARNESS_FAILURE " << error.what() << '\n';
    return 2;
  }
}
