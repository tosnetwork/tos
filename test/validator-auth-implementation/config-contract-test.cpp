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
      // The three states the activation policy distinguishes, including the one
      // it says cannot exist. That last one is why the fixture has an opt-out:
      // the seeding it does everywhere else would remove the very state this
      // refusal guards, and a guard whose input cannot be built is a guard
      // nobody has heard.
      {"an-active-chain-without-a-checkpoint-is-refused", [=] {
         Host host;
         auto outcome = run_ticktock(contract, &host, vm::validator_auth_capability,
                                     vm::validator_auth_min_version, true, {}, {}, 1000000, nullptr, {}, true);
         expect(outcome.exit == 47, "an-active-chain-without-a-checkpoint-is-refused");
       }},
      {"an-inactive-chain-without-a-checkpoint-is-accepted", [=] {
         Host host;
         auto outcome = run_ticktock(contract, &host, 0, vm::validator_auth_min_version, false, {}, {}, 1000000,
                                     nullptr, {}, true);
         expect(outcome.exit == 0, "an-inactive-chain-without-a-checkpoint-is-accepted");
       }},
      // An account whose registry context can never open is not an account that
      // must die. These six cases are the whole of what such an account may and
      // may not do: it can still be read, it can still be voted on, it may take
      // exactly two decisions about itself, and every path that would produce
      // state the chain treats as authenticated refuses.
      //
      // The refusal above is the tick-tock, which is a writer. What follows is
      // everything else.
      {"a-checkpointless-active-chain-still-registers-votes", [=] {
         Host host;
         auto proposal = config_proposal(17, vm::CellBuilder().store_long(0x5151, 16).finalize());
         auto votes = vote_dictionary(proposal, voter_public(), 0, false);
         auto id = proposal->get_hash().as_array();
         vm::CellBuilder signed_part;
         signed_part.store_long(0x566f7445, 32).store_long(0, 16);
         signed_part.store_bytes(td::Slice(reinterpret_cast<const char*>(id.data()), 32));
         auto payload = signed_part.finalize();
         auto slice = vm::load_cell_slice(payload);
         unsigned char bits[64] = {};
         const auto length = slice.size() / 8;
         expect(slice.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(bits), length)), "fixture-vote");
         unsigned char signature[64] = {};
         expect(crypto_sign_detached(signature, nullptr, bits, length, voter().secret) == 0, "fixture-vote");
         vm::CellBuilder body;
         body.store_long(0x566f7465, 32).store_long(0, 64);
         body.store_bytes(td::Slice(reinterpret_cast<const char*>(signature), 64));
         body.append_cellslice(vm::load_cell_slice_ref(payload));
         auto run = run_contract(contract, body.finalize(), 1, 1000, &host, vm::validator_auth_capability,
                                 vm::validator_auth_min_version, false, {}, 1000000, true, {}, voter_public(),
                                 votes, 0, nullptr, true);
         // The account was read. A loader that refused would have taken this
         // down with it, and with it every get-method and any diagnosis of the
         // fault.
         expect(run.exit == 0, "a-checkpointless-active-chain-still-registers-votes");
       }},
      // But nothing it could vote through installs, except the two below.
      {"a-checkpointless-active-chain-changes-no-ordinary-parameter", [=] {
         Host host;
         auto run = run_owner_action(contract, 17, vm::CellBuilder().store_long(0x5151, 16).finalize(), &host,
                                     true, true);
         expect(run.exit == 47, "a-checkpointless-active-chain-changes-no-ordinary-parameter");
       }},
      // The registry update is refused before the update is even read, so the
      // instruction that would hand the account a checkpoint is never reached.
      // A recovery that seeded one would be the second initialization route
      // this design exists to remove, arrived at by the back door.
      {"a-checkpointless-active-chain-applies-no-registry-update", [=] {
         auto cells = registry_cells();
         auto host = registry_host(cells);
         auto run = run_contract(contract, registry_body(cells), 0, 1000, &host, vm::validator_auth_capability,
                                 vm::validator_auth_min_version, true, {}, 1000000, true, {}, nullptr, {}, 0,
                                 nullptr, true);
         expect(run.exit == 47 && host.applies == 0 && host.checkpoints == 0,
                "a-checkpointless-active-chain-applies-no-registry-update");
       }},
      {"a-checkpointless-active-chain-installs-no-elected-set", [=] {
         Host host;
         // A set that carries its bindings, so the refusal is the checkpoint's
         // and not the one that refuses an unbound set.
         auto body = vm::CellBuilder().store_long(0x4e565354, 32).store_long(7, 64)
                         .store_ref(elected_set(5000, 6000)).store_ref(bindings_cell()).finalize();
         auto run = run_contract(contract, body, elector_account, 1000, &host, vm::validator_auth_capability,
                                 vm::validator_auth_min_version, false, {}, 1000000, true, {}, nullptr, {}, 0,
                                 nullptr, true);
         expect(run.exit == 47 && host.binds == 0,
                "a-checkpointless-active-chain-installs-no-elected-set");
       }},
      // And the two decisions it may take. Deactivation first: a chain that
      // stops being authenticated has no registry context to be missing.
      {"a-checkpointless-active-chain-may-stop-being-authenticated", [=] {
         Host host;
         auto inactive = vm::CellBuilder().store_long(0xc4, 8)
                             .store_long(vm::validator_auth_min_version, 32).store_long(0, 64).finalize();
         auto run = run_owner_action(contract, 8, inactive, &host, true, true);
         expect(run.exit == 0, "a-checkpointless-active-chain-may-stop-being-authenticated");
         expect(same_cell(installed_parameter(run.data, 8), inactive),
                "a-checkpointless-active-chain-may-stop-being-authenticated");
         // And it did not acquire a checkpoint on the way out.
         expect(stored_checkpoint(run.data).is_null(),
                "a-checkpointless-active-chain-may-stop-being-authenticated");
       }},
      // Replacing this contract's code is the other. It installs on the normal
      // vote alone, because the governing quorum such a chain would otherwise
      // need is exactly what it has no way to consult.
      {"a-checkpointless-active-chain-may-replace-its-code", [=] {
         Host host;
         auto upgrade = vm::CellBuilder().store_ref(vm::CellBuilder().store_long(0, 8).finalize()).finalize();
         auto proposal = config_proposal(-1000, upgrade);
         auto votes = vote_dictionary(proposal, voter_public(), 0, true);
         auto run = cast_vote(contract, proposal, votes, &host, true, true);
         expect(run.exit == 0, "a-checkpointless-active-chain-may-replace-its-code");
         // The exit code says nothing here: a proposal marked terminal and a
         // code upgrade both end at zero. What distinguishes them is whether
         // the proposal was spent. Asserting the exit alone left this case
         // passing with the carve-out removed, which the mutation for it
         // reported as a survivor.
         expect(stored_wins(run.committed_data, proposal) == -1,
                "a-checkpointless-active-chain-may-replace-its-code");
         expect(stored_checkpoint(run.committed_data).is_null(),
                "a-checkpointless-active-chain-may-replace-its-code");
       }},
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
      // A validator set has one writer on an active chain: the elector's
      // message, where the set passes through the registry. These four cases
      // are about the two writers that are generic -- they take an index and a
      // cell, carry no bindings, and reach no registry -- and about the fact
      // that closing them closes nothing else.
      {"a-finalization-cannot-install-a-validator-set", [=] {
         auto cells = registry_cells();
         auto host = registry_host(cells);
         auto proposal = config_proposal(34, validator_set_cell(voter_public(), true));
         auto votes = vote_dictionary(proposal, voter_public(), 255, false);
         auto run = run_contract(contract, registry_body(cells, proposal), 0, 1000, &host,
                                 vm::validator_auth_capability, vm::validator_auth_min_version, true, {},
                                 1000000, true, {}, voter_public(), votes);
         // Refused where every other condition of the vote is refused, so the
         // same thing follows: nothing is committed, and the proposal is still
         // awaiting governance rather than spent on an attempt that installed
         // nothing. A set built in the shape the binder writes, so the refusal
         // is not about the descriptor but about the route.
         expect(run.exit == 53 && !run.committed, "a-finalization-cannot-install-a-validator-set");
         expect(run.committed_data.is_null(), "a-finalization-cannot-install-a-validator-set");
       }},
      // The master key is the other generic writer. This case exists first
      // because it is the one that proves the signed owner message reaches
      // perform_action at all: without it the refusal below would pass for any
      // reason the message failed, including a fixture that never got there.
      {"an-owner-action-installs-an-ordinary-parameter", [=] {
         Host host;
         auto value = vm::CellBuilder().store_long(0x5151, 16).finalize();
         auto run = run_owner_action(contract, 17, value, &host, true);
         expect(run.exit == 0, "an-owner-action-installs-an-ordinary-parameter");
         expect(same_cell(installed_parameter(run.data, 17), value),
                "an-owner-action-installs-an-ordinary-parameter");
       }},
      {"an-owner-action-cannot-install-a-validator-set", [=] {
         Host host;
         auto run = run_owner_action(contract, 34, validator_set_cell(voter_public(), true), &host, true);
         // Thrown rather than declined: this message is signed by a key that is
         // meant to know what it is doing, and reporting success for a change
         // that did not happen is worse than refusing it.
         expect(run.exit == 48, "an-owner-action-cannot-install-a-validator-set");
         expect(installed_parameter(run.data, 34).is_null(),
                "an-owner-action-cannot-install-a-validator-set");
       }},
      // Every index in the group, through both generic writers. The three this
      // contract moves between are covered above; these are the three it does
      // not, and 35 and 37 are the ones that matter most: the node and
      // committee derivation read the current set as "35 if present, else 34"
      // and the next set as "37 if present, else 36", so a set written there is
      // the set the chain runs under while the index the registry decided still
      // holds what it decided.
      {"no-generic-writer-installs-any-validator-set-index", [=] {
         for (long long index : {32, 33, 34, 35, 36, 37}) {
           Host proposed;
           auto cells = registry_cells();
           auto host = registry_host(cells);
           auto proposal = config_proposal(index, validator_set_cell(voter_public(), true));
           auto votes = vote_dictionary(proposal, voter_public(), 255, false);
           auto finalization = run_contract(contract, registry_body(cells, proposal), 0, 1000, &host,
                                            vm::validator_auth_capability, vm::validator_auth_min_version, true,
                                            {}, 1000000, true, {}, voter_public(), votes);
           expect(finalization.exit == 53 && !finalization.committed,
                  "no-generic-writer-installs-any-validator-set-index");
           auto owned = run_owner_action(contract, index, validator_set_cell(voter_public(), true), &proposed, true);
           expect(owned.exit == 48 && installed_parameter(owned.data, index).is_null(),
                  "no-generic-writer-installs-any-validator-set-index");
         }
       }},
      // And a chain that has not activated keeps every one of them writable,
      // so the rule above is the activation's rather than the index's.
      {"an-inactive-chain-keeps-every-validator-set-index-writable", [=] {
         for (long long index : {32, 33, 34, 35, 36, 37}) {
           Host host;
           auto set = validator_set_cell(voter_public());
           auto run = run_owner_action(contract, index, set, &host, false);
           expect(run.exit == 0 && same_cell(installed_parameter(run.data, index), set),
                  "an-inactive-chain-keeps-every-validator-set-index-writable");
         }
       }},
      // And the rule is the activation's, not the parameter index's. A chain
      // that has not activated the design has no registry to route through, so
      // closing the route there would remove governance it still needs.
      {"an-inactive-chain-lets-the-owner-install-a-validator-set", [=] {
         Host host;
         auto set = validator_set_cell(voter_public());
         auto run = run_owner_action(contract, 34, set, &host, false);
         expect(run.exit == 0, "an-inactive-chain-lets-the-owner-install-a-validator-set");
         expect(same_cell(installed_parameter(run.data, 34), set),
                "an-inactive-chain-lets-the-owner-install-a-validator-set");
       }},
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
  // The account an active chain actually has. The sandbox that consumes these
  // runs with the capability set, and on such a chain an account carrying no
  // registry checkpoint is one whose configuration context can never open --
  // the contract refuses it rather than treating it as yet to migrate. An
  // exported account without one is a state the policy says cannot exist, and
  // every case built on it fails for that reason instead of its own.
  write_cell(dir / "data-empty.boc",
             contract_data(configuration({}, true), seeded_checkpoint({}, true, {})));
  write_cell(dir / "data-old.boc",
             contract_data(configuration(cells.before, true), seeded_checkpoint(cells.before, true, {})));
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
