/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <cstdlib>
#include <string>

#include "lite-client/proof-verify/material.h"
#include "lite-client/proof-verify/self-pay-simulation.h"
#include "td/utils/JsonBuilder.h"
namespace pv = tos::proofverify;
template <class T>
T must(td::Result<T> result) {
  if (result.is_error()) {
    std::fprintf(stderr, "probe setup: %s\n", result.error().message().str().c_str());
    std::exit(2);
  }
  return result.move_as_ok();
}
int main(int argc, char** argv) {
  if (argc != 2)
    return 2;
  std::string root = argv[1];
  auto anchor = must(pv::parse_anchor(must(pv::read_bounded_file(root + "/anchor.json", 1u << 20))));
  auto request_json = must(pv::read_bounded_file(root + "/request.json", 1u << 20));
  auto request = must(pv::parse_request(request_json));
  auto message = must(pv::read_bounded_file(root + "/message.boc", 1u << 20));
  auto material = must(pv::read_material(root + "/material"));
  auto now = std::stoll(must(pv::read_bounded_file(root + "/clock.txt", 64)));
  std::optional<pv::LiveState> state{pv::LiveState{anchor, std::nullopt, std::nullopt}};
  auto result = pv::simulate_self_pay(anchor, request, request_json, material, state, pv::Policy{now}, message);
  if (result.is_error()) {
    std::fprintf(stderr, "simulation: %s\n", result.error().message().str().c_str());
    return 1;
  }
  auto& value = result.ok();
  bool executed = value.authenticated_read.next_state.has_value() &&
                  value.estimate.outcome == pv::SimulationOutcome::Executed && value.estimate.transaction.has_value();
  std::printf("LIVE_SIMULATION_CASE authenticated-supported-execution %s outcome=%d\n", executed ? "PASS" : "FAIL",
              static_cast<int>(value.estimate.outcome));
  if (!executed)
    return 1;
  auto expected_text = must(pv::read_bounded_file(root + "/expected.json", 4096));
  auto expected = must(td::json_decode(td::MutableSlice(expected_text)));
  auto transaction_text = value.estimate.transaction->codec_json;
  auto transaction = must(td::json_decode(td::MutableSlice(transaction_text)));
  auto& object = transaction.get_object();
  auto outputs = must(object.extract_required_field("out_msgs", td::JsonValue::Type::Array));
  auto compute = must(object.extract_required_field("compute", td::JsonValue::Type::Object));
  auto action = must(object.extract_required_field("action", td::JsonValue::Type::Object));
  auto field = [&](td::Slice name) { return must(expected.get_object().get_required_string_field(name)); };
  bool payment =
      outputs.get_array().size() == 1 && must(object.get_required_string_field("account")) == field("account") &&
      must(object.get_required_string_field("hash")) == field("transaction_hash") &&
      must(object.get_required_string_field("fees")) == field("fees") &&
      !must(object.get_required_bool_field("aborted")) &&
      must(compute.get_object().get_required_bool_field("success")) &&
      must(action.get_object().get_required_bool_field("success")) &&
      must(outputs.get_array()[0].get_object().get_required_string_field("destination")) == field("recipient") &&
      must(outputs.get_array()[0].get_object().get_required_string_field("value")) == field("value") &&
      value.estimate.authenticated_balance == field("balance_before") &&
      value.estimate.transaction->expected_balance == field("balance_after");
  std::printf("LIVE_SIMULATION_CASE payment-fee-state-projection %s\n", payment ? "PASS" : "FAIL");
  auto forged_message = must(pv::read_bounded_file(root + "/forged-message.boc", 1u << 20));
  auto forged = pv::simulate_self_pay(anchor, request, request_json, material, state, pv::Policy{now}, forged_message);
  bool signature_refused = forged.is_ok() && forged.ok().estimate.outcome == pv::SimulationOutcome::NotAccepted &&
                           forged.ok().estimate.vm_exit_code == 1808 && !forged.ok().estimate.transaction;
  std::printf("LIVE_SIMULATION_CASE forged-signature-no-transaction %s\n", signature_refused ? "PASS" : "FAIL");
  auto saved = material.account->copy();
  auto bytes = material.account->as_slice();
  material.account->as_slice()[bytes.size() - 5] ^= 1;
  bool refused =
      pv::simulate_self_pay(anchor, request, request_json, material, state, pv::Policy{now}, message).is_error();
  std::printf("LIVE_SIMULATION_CASE damaged-account-proof %s\n", refused ? "PASS" : "FAIL");
  material.account = std::move(saved);
  auto restored = pv::simulate_self_pay(anchor, request, request_json, material, state, pv::Policy{now}, message);
  bool restored_ok =
      restored.is_ok() && restored.ok().estimate.transaction &&
      restored.ok().estimate.transaction->expected_state_hash == value.estimate.transaction->expected_state_hash;
  std::printf("LIVE_SIMULATION_CASE restored-identical-state %s\n", restored_ok ? "PASS" : "FAIL");
  return payment && signature_refused && refused && restored_ok ? 0 : 1;
}
