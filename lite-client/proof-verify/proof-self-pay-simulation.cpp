/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <exception>
#include <limits>

#include "common/global-version.h"
#include "vm/cells/CellSlice.h"

#include "self-pay-simulation.h"
#include "simulation-config.h"
#include "wallet-transaction.h"

namespace tos::proofverify {
namespace {
td::Status refuse(SelfPaySimulationError error = SelfPaySimulationError::Proof) {
  return self_pay_simulation_error(error);
}
td::Status account_error(const td::Status& error) {
  using E = detail::SimulationAccountError;
  return refuse(error.code() == static_cast<int>(E::Resource)  ? SelfPaySimulationError::Resource
                : error.code() == static_cast<int>(E::Context) ? SelfPaySimulationError::Context
                                                               : SelfPaySimulationError::Proof);
}
}  // namespace

td::Result<ProofBoundSelfPaySimulation> simulate_self_pay(const Anchor& anchor, const Request& request,
                                                          td::Slice request_bytes, const Material& material,
                                                          const std::optional<LiveState>& state, const Policy& policy,
                                                          td::Slice message_boc) {
  try {
    if (request.mode != Mode::Live || !request.account || !request.get_methods.empty() ||
        !request.config_params.empty() || material.config || material.libraries || !state ||
        state->anchor.id != anchor.id || state->anchor.kind != anchor.kind || policy.now <= 0 ||
        policy.now > std::numeric_limits<td::uint32>::max() || request_bytes.empty()) {
      return refuse(SelfPaySimulationError::Input);
    }
    if (request_bytes.size() > (1u << 20) || material.chain.size() > kMaxChainResponses ||
        material.descent.size() > kMaxDescentLinks)
      return refuse(SelfPaySimulationError::Resource);
    if (!material.exec_config || !material.account)
      return refuse();
    auto account_preflight = detail::preflight_simulation_account_reply(material.account->as_slice());
    if (account_preflight.is_error())
      return account_error(account_preflight);
    // Bound the borrowed input aggregate before making any read-path copies.
    std::size_t remaining = kMaxFileBytes;
    auto charge = [&](const td::BufferSlice& bytes) {
      if (bytes.size() > remaining) {
        return false;
      }
      remaining -= bytes.size();
      return true;
    };
    for (const auto* bytes : {&material.masterchain_info, &material.config, &material.account, &material.exec_config}) {
      if (*bytes && !charge(**bytes)) {
        return refuse(SelfPaySimulationError::Resource);
      }
    }
    for (const auto& bytes : material.chain) {
      if (!charge(bytes)) {
        return refuse(SelfPaySimulationError::Resource);
      }
    }
    for (const auto& bytes : material.descent) {
      if (!charge(bytes)) {
        return refuse(SelfPaySimulationError::Resource);
      }
    }
    Material read_material;
    if (material.masterchain_info) {
      read_material.masterchain_info = material.masterchain_info->clone();
    }
    if (material.config) {
      read_material.config = material.config->clone();
    }
    if (material.account) {
      read_material.account = material.account->clone();
    }
    for (const auto& bytes : material.chain) {
      read_material.chain.push_back(bytes.clone());
    }
    for (const auto& bytes : material.descent) {
      read_material.descent.push_back(bytes.clone());
    }
    // The existing read verifier continues to reject execution material in its
    // ordinary path. The full configuration is separately bound below to the
    // exact target that this call first authenticates from its live anchor.
    auto authenticated = verify(anchor, request, request_bytes, read_material, state, policy);
    if (authenticated.is_error()) {
      return refuse();
    }
    auto extracted = detail::extract_simulation_config(authenticated.ok().target, material.exec_config->as_slice());
    if (extracted.is_error()) {
      return refuse(extracted.error().code() == static_cast<int>(detail::SimulationConfigError::Resource)
                        ? SelfPaySimulationError::Resource
                        : SelfPaySimulationError::Proof);
    }
    std::shared_ptr<block::ConfigInfo> config{extracted.move_as_ok()};
    auto global_id = config->get_config_param(19);
    if (global_id.is_null()) {
      return refuse();
    }
    auto global_id_slice = vm::load_cell_slice(global_id);
    if (global_id_slice.size() != 32 || global_id_slice.size_refs() != 0 ||
        global_id_slice.fetch_long(32) != config->get_global_blockchain_id()) {
      return refuse();
    }
    if (!material.account || !authenticated.ok().account) {
      return refuse();
    }
    // Bind a structurally valid exact message before classifying unsupported
    // versions. No execution context is invented for those versions.
    TRY_RESULT(message, detail::bind_simulation_message(*request.account, message_boc));
    if (config->get_global_version() < 16 || config->get_global_version() > tos::SUPPORTED_VERSION ||
        request.account->workchain != 0) {
      SelfPaySimulation estimate;
      estimate.authenticated_balance = authenticated.ok().account->exists ? authenticated.ok().account->balance : "0";
      estimate.message_bytes_hash = message.bytes_hash;
      estimate.message_root_hash = message.root_hash;
      estimate.config_root_hash = td::Bits256{config->get_root_cell()->get_hash().bits()};
      return ProofBoundSelfPaySimulation{authenticated.move_as_ok(), std::move(estimate)};
    }
    auto prepared = detail::prepare_simulation_account(authenticated.ok().target, *request.account,
                                                       material.account->as_slice(), *config, policy.now);
    if (prepared.is_error())
      return account_error(prepared.error());
    if (prepared.ok().existed != authenticated.ok().account->exists ||
        (prepared.ok().existed && prepared.ok().authenticated_state_hash != authenticated.ok().account->state_hash)) {
      return refuse();
    }
    auto previous_blocks = config->get_prev_blocks_info();
    if (previous_blocks.is_error()) {
      return refuse(SelfPaySimulationError::Context);
    }
    auto execution = detail::execute_prepared_self_pay(authenticated.ok().target, config, previous_blocks.move_as_ok(),
                                                       prepared.move_as_ok(), message_boc);
    if (execution.is_error()) {
      return execution.move_as_error();
    }
    return ProofBoundSelfPaySimulation{authenticated.move_as_ok(), execution.move_as_ok()};
  } catch (vm::VmError&) {
    return refuse();
  } catch (vm::VmVirtError&) {
    return refuse();
  } catch (const std::exception&) {
    return refuse(SelfPaySimulationError::Internal);
  }
}

}  // namespace tos::proofverify
