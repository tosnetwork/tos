/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <exception>
#include <limits>

#include "vm/cells/CellSlice.h"

#include "self-pay-simulation.h"
#include "simulation-config.h"
#include "wallet-transaction.h"

namespace tos::proofverify {
namespace {
td::Status refuse() {
  return td::Status::Error("self-pay simulation proof or input refused");
}
}  // namespace

td::Result<ProofBoundSelfPaySimulation> simulate_self_pay(const Anchor& anchor, const Request& request,
                                                          td::Slice request_bytes, const Material& material,
                                                          const std::optional<LiveState>& state, const Policy& policy,
                                                          td::Slice message_boc) {
  try {
    if (request.mode != Mode::Live || !request.account || !request.get_methods.empty() ||
        !request.config_params.empty() || material.config || !material.exec_config || !material.account ||
        policy.now <= 0 || policy.now > std::numeric_limits<td::uint32>::max() || material.libraries ||
        request_bytes.empty() || request_bytes.size() > (1u << 20) || preflight_wallet_boc(message_boc).is_error() ||
        material.chain.size() > kMaxChainResponses || material.descent.size() > kMaxDescentLinks) {
      return refuse();
    }
    if (detail::preflight_simulation_account_reply(material.account->as_slice()).is_error()) {
      return refuse();
    }
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
        return refuse();
      }
    }
    for (const auto& bytes : material.chain) {
      if (!charge(bytes)) {
        return refuse();
      }
    }
    for (const auto& bytes : material.descent) {
      if (!charge(bytes)) {
        return refuse();
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
      return refuse();
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
    auto prepared = detail::prepare_simulation_account(authenticated.ok().target, *request.account,
                                                       material.account->as_slice(), *config, policy.now);
    if (prepared.is_error() || prepared.ok().existed != authenticated.ok().account->exists ||
        (prepared.ok().existed && prepared.ok().authenticated_state_hash != authenticated.ok().account->state_hash)) {
      return refuse();
    }
    auto previous_blocks = config->get_prev_blocks_info();
    if (previous_blocks.is_error()) {
      return refuse();
    }
    auto execution = detail::execute_prepared_self_pay(authenticated.ok().target, config, previous_blocks.move_as_ok(),
                                                       prepared.move_as_ok(), message_boc);
    if (execution.is_error()) {
      return refuse();
    }
    return ProofBoundSelfPaySimulation{authenticated.move_as_ok(), execution.move_as_ok()};
  } catch (vm::VmError&) {
    return refuse();
  } catch (vm::VmVirtError&) {
    return refuse();
  } catch (const std::exception&) {
    return refuse();
  }
}

}  // namespace tos::proofverify
