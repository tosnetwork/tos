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

#include "config-contract-fixture.h"

namespace {
using namespace config_contract_fixture;

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
         // On the case protocol's own stream, like every other measurement this
         // file prints. The persistence harness runs one case at a time and
         // treats anything on the error stream as the case having failed, so a
         // measurement written there reports a passing case as broken.
         std::cout << "MEASURE registry_update_credit=" << update << " finalization_credit=" << finalization
                   << " network_credit=" << external_gas_credit << '\n';
         expect(update > 0 && finalization > 0, "a-valid-finalization-reaches-accept-with-real-gas-credit");
         // What this case claims, and nothing more: the contract's own work
         // reaches acceptance inside the credit. The host here is a stub that
         // checks its operands and hands back a prepared registry -- it never
         // verifies a governance certificate -- so this number is the cost of
         // the instructions around the authority and not of the authority.
         //
         // It is therefore not a statement that the credit is sufficient. What
         // the real verification costs is measured where it can be: a
         // certificate carrying the largest legal number of signer records
         // exceeds this credit many times over, and the governance gas suite
         // reports by how much.
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
