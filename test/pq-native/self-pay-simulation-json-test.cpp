/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <limits>

#include "lite-client/proof-verify/self-pay-simulation.h"
#include "td/utils/JsonBuilder.h"
namespace pv = tos::proofverify;
// Explicit synthetic formatter inputs. They are not authenticated observations.
pv::ProofBoundSelfPaySimulation sample() {
  pv::Verified read;
  read.target = tos::BlockIdExt{-1, tos::shardIdAll, 1, td::Bits256::zero(), td::Bits256::zero()};
  pv::ProvenAccount account;
  account.address = block::StdAddress{0, td::Bits256::zero()};
  account.exists = false;
  read.account = std::move(account);
  read.next_state = pv::LiveState{};
  pv::SelfPaySimulation estimate;
  estimate.authenticated_balance = "0";
  return {std::move(read), std::move(estimate)};
}
int main() {
  int failures = 0;
  auto check = [&](const char* name, bool ok) {
    std::printf("SIMULATION_JSON_CASE %s %s\n", name, ok ? "PASS" : "FAIL");
    failures += !ok;
  };
  auto input = sample();
  auto unsupported = pv::render_self_pay_simulation(input);
  check("unsupported-without-context", unsupported.is_ok() &&
                                           unsupported.ok().find("\"context\"") == std::string::npos &&
                                           unsupported.ok().find("\"seed\"") == std::string::npos &&
                                           unsupported.ok().find("\"state_hash\"") == std::string::npos);
  input.estimate.outcome = pv::SimulationOutcome::Executed;
  auto missing = pv::render_self_pay_simulation(input);
  check("missing-transaction-internal", missing.is_error() && missing.error().code() == -4);
  input.estimate.context = pv::detail::SelfPaySimulationContext{1, std::numeric_limits<td::uint64>::max() - 1,
                                                                std::numeric_limits<td::uint64>::max()};
  input.estimate.simulation_seed.as_slice()[0] = 1;
  input.estimate.transaction = pv::SimulatedTransaction{"{}", "0", td::Bits256::zero()};
  auto wide = pv::render_self_pay_simulation(input);
  check("uint64-maximum-is-string",
        wide.is_ok() && wide.ok().find("\"transaction_lt\":\"18446744073709551615\"") != std::string::npos);
  input.estimate.transaction->codec_json.assign(3u << 20, ' ');
  auto full = pv::render_self_pay_simulation(input);
  check("bounded-render-resource", full.is_error() && full.error().code() == -5);
  input.estimate.transaction->codec_json = "{}";
  input.estimate.context->estimated_transaction_lt = 0;
  auto context = pv::render_self_pay_simulation(input);
  check("invalid-context-internal", context.is_error() && context.error().code() == -4);
  input = sample();
  input.estimate.vm_exit_code = 0;
  auto exit = pv::render_self_pay_simulation(input);
  check("exit-code-only-notaccepted", exit.is_error() && exit.error().code() == -4);
  input = sample();
  input.estimate.authenticated_balance = "01";
  auto balance = pv::render_self_pay_simulation(input);
  check("noncanonical-balance-internal", balance.is_error() && balance.error().code() == -4);
  input = sample();
  input.estimate.outcome = static_cast<pv::SimulationOutcome>(999);
  auto tag = pv::render_self_pay_simulation(input);
  check("unknown-outcome-internal", tag.is_error() && tag.error().code() == -4);
  return failures ? 1 : 0;
}
