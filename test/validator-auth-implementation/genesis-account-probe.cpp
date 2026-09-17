// Run the configuration account's own tick-tock on an account a genesis wrote.
//
// The rule this exists to exercise is the contract's: on a chain that has
// activated the design, an account carrying no registry checkpoint is not one
// that has yet to migrate, it is one whose configuration context can never
// open, and the contract refuses it. That rule presumes a genesis seeds the
// registry parameter and the checkpoint together, and a rule about what genesis
// writes cannot be established by a fixture that writes it in the same
// translation unit as the reader.
//
// So the account and its configuration are loaded from cells the genesis
// interpreter produced, and the only thing done here is to execute them.
#include <iostream>
#include <string>

#include "td/utils/filesystem.h"
#include "vm/boc.h"
#include "vm/vm.h"

#include "config-contract-fixture.h"

using namespace config_contract_fixture;

namespace {
int fail(const std::string& why) {
  std::cerr << "ASSERTION: " << why << '\n';
  return 1;
}

td::Ref<vm::Cell> load(const std::string& path, const char* label) {
  auto raw = td::read_file(td::CSlice(path));
  if (raw.is_error())
    throw std::runtime_error(std::string(label) + "-read");
  auto cell = vm::std_boc_deserialize(raw.move_as_ok());
  if (cell.is_error())
    throw std::runtime_error(std::string(label) + "-boc");
  return cell.move_as_ok();
}
}  // namespace

int main(int argc, char** argv) {
  std::string contract_path, account_path, config_path, checkpoint_path;
  int expect_exit = 0;
  bool active = true;
  for (int i = 1; i + 1 < argc; i += 2) {
    std::string flag = argv[i], value = argv[i + 1];
    if (flag == "--contract")
      contract_path = value;
    else if (flag == "--account")
      account_path = value;
    else if (flag == "--config")
      config_path = value;
    else if (flag == "--checkpoint")
      checkpoint_path = value;
    else if (flag == "--expect-exit")
      expect_exit = std::stoi(value);
    else if (flag == "--inactive")
      active = value != "1";
    else
      return fail("unknown-flag-" + flag);
  }
  if (contract_path.empty() || account_path.empty() || config_path.empty())
    return fail("arguments");
  try {
    auto initialized = vm::init_vm();
    if (initialized.is_error())
      return fail("vm-init");
    auto contract = load(contract_path, "contract");
    auto account = load(account_path, "account");
    auto config = load(config_path, "config");

    Host host;
    // The privileged instruction answers with the registry state the chain
    // holds. At genesis that is exactly the checkpoint the genesis writer
    // produced beside parameter 46, so the probe answers with that rather than
    // with a marker: the tick-tock reads the registry out of its first
    // reference, and a marker would fail for the shape of the answer instead
    // of telling us anything about the account.
    if (!checkpoint_path.empty()) {
      host.returned_checkpoint = load(checkpoint_path, "checkpoint");
    }
    const auto outcome = execute_ticktock(contract, account, config, &host,
                                          active ? vm::validator_auth_capability : 0,
                                          vm::validator_auth_min_version, 1000000);
    std::cout << "GENESIS_TICKTOCK exit=" << outcome.exit << " committed=" << outcome.committed
              << " checkpoints=" << host.checkpoints << '\n';
    if (outcome.exit != expect_exit)
      return fail("expected-exit-" + std::to_string(expect_exit) + "-got-" + std::to_string(outcome.exit));
    std::cout << "PASS: the account a genesis wrote runs its own tick-tock as expected\n";
    return 0;
  } catch (const std::exception& error) {
    return fail(error.what());
  }
}
