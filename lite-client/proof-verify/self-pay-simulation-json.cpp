/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "td/utils/JsonBuilder.h"
#include "td/utils/misc.h"

#include "self-pay-simulation.h"

namespace tos::proofverify {
namespace {
bool amount(const std::string& value) {
  if (value.empty() || value.size() > 37 || (value.size() > 1 && value.front() == '0'))
    return false;
  for (auto c : value)
    if (c < '0' || c > '9')
      return false;
  return true;
}
}  // namespace

td::Result<std::string> render_self_pay_simulation(const ProofBoundSelfPaySimulation& value) {
  const auto& read = value.authenticated_read;
  const auto& estimate = value.estimate;
  if (!read.account || !read.next_state || !amount(estimate.authenticated_balance))
    return self_pay_simulation_error(SelfPaySimulationError::Internal);
  const auto& account = *read.account;
  if (account.exists ? estimate.authenticated_balance != account.balance
                     : estimate.authenticated_balance != "0" || (!account.balance.empty() && account.balance != "0"))
    return self_pay_simulation_error(SelfPaySimulationError::Internal);
  const bool executed = estimate.outcome == SimulationOutcome::Executed;
  const bool rejected = estimate.outcome == SimulationOutcome::NotAccepted;
  if (estimate.transaction.has_value() != executed || estimate.vm_exit_code.has_value() != rejected ||
      (executed && (!amount(estimate.transaction->expected_balance) || estimate.transaction->codec_json.empty())))
    return self_pay_simulation_error(SelfPaySimulationError::Internal);
  const char* status;
  switch (estimate.outcome) {
    case SimulationOutcome::Unsupported:
      status = "unsupported";
      break;
    case SimulationOutcome::ImportRejected:
      status = "import_rejected";
      break;
    case SimulationOutcome::NotAccepted:
      status = "not_accepted";
      break;
    case SimulationOutcome::Executed:
      status = "executed";
      break;
    default:
      return self_pay_simulation_error(SelfPaySimulationError::Internal);
  }
  if (estimate.outcome != SimulationOutcome::Unsupported && (!estimate.context || estimate.simulation_seed.is_zero()))
    return self_pay_simulation_error(SelfPaySimulationError::Internal);
  // Fixed storage: StringBuilder cannot grow when untrusted/result text fills it.
  td::BufferSlice storage(kMaxSelfPaySimulationResultBytes);
  td::StringBuilder out(storage.as_slice(), false);
  auto hex = [](const td::Bits256& bits) { return td::hex_encode(bits.as_slice()); };
  out << "{\"interface\":\"tos-self-pay-simulation/1\",\"scope\":\"local_estimate\",\"status\":"
      << td::JsonString(td::Slice(status)) << ",\"target\":" << block_id_json(read.target)
      << ",\"account\":{\"address\":"
      << td::JsonString(std::to_string(account.address.workchain) + ":" + hex(account.address.addr))
      << ",\"exists\":" << (account.exists ? "true" : "false")
      << ",\"observed_balance\":" << td::JsonString(estimate.authenticated_balance);
  if (account.exists)
    out << ",\"state_hash\":" << td::JsonString(hex(account.state_hash));
  out << "},\"config_root_hash\":" << td::JsonString(hex(estimate.config_root_hash))
      << ",\"message_bytes_hash\":" << td::JsonString(hex(estimate.message_bytes_hash))
      << ",\"message_root_hash\":" << td::JsonString(hex(estimate.message_root_hash));
  if (estimate.outcome == SimulationOutcome::Unsupported)
    out << ",\"reason\":\"unsupported_profile\"";
  if (estimate.context) {
    const auto& context = *estimate.context;
    if (!context.estimated_time || !context.estimated_block_start_lt || !context.estimated_transaction_lt ||
        context.estimated_transaction_lt - 1 != context.estimated_block_start_lt)
      return self_pay_simulation_error(SelfPaySimulationError::Internal);
    out << ",\"context\":{\"estimated_time\":" << context.estimated_time
        << ",\"block_start_lt\":" << td::JsonString(std::to_string(context.estimated_block_start_lt))
        << ",\"transaction_lt\":" << td::JsonString(std::to_string(context.estimated_transaction_lt)) << "}";
  }
  if (!estimate.simulation_seed.is_zero())
    out << ",\"seed\":" << td::JsonString(hex(estimate.simulation_seed));
  if (rejected)
    out << ",\"vm_exit_code\":" << *estimate.vm_exit_code;
  if (executed) {
    out << ",\"transaction\":{\"codec\":" << estimate.transaction->codec_json
        << ",\"expected_balance\":" << td::JsonString(estimate.transaction->expected_balance)
        << ",\"expected_state_hash\":" << td::JsonString(hex(estimate.transaction->expected_state_hash)) << "}";
  }
  out << "}";
  if (out.is_error())
    return self_pay_simulation_error(SelfPaySimulationError::Resource);
  return out.as_cslice().str();
}
}  // namespace tos::proofverify
