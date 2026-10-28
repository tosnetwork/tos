/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstring>
#include <limits>

#include "embedded.h"
#include "self-pay-simulation.h"
#include "simulation-config.h"
#include "wallet-transaction.h"

extern "C" int tos_proof_simulate_self_pay_embedded(const char* anchor, size_t anchor_size, const char* request,
                                                    size_t request_size, const char* state, size_t state_size,
                                                    int64_t local_now, const tos_proof_material* parts, size_t count,
                                                    const uint8_t* message, size_t message_size, char* result,
                                                    size_t capacity, size_t* result_size, char* next_state,
                                                    size_t state_capacity, size_t* next_state_size) {
  namespace pv = tos::proofverify;
  if (result_size)
    *result_size = 0;
  if (next_state_size)
    *next_state_size = 0;
  if (!result || !next_state || capacity > pv::kMaxSelfPaySimulationResultBytes ||
      state_capacity > pv::kMaxSelfPaySimulationStateBytes)
    return -1;
  std::memset(result, 0, capacity);
  std::memset(next_state, 0, state_capacity);
  if (!result_size || !next_state_size || !anchor || !request || !state || !message || !anchor_size || !request_size ||
      !state_size || !message_size || (!parts && count) || local_now <= 0 ||
      local_now > std::numeric_limits<uint32_t>::max())
    return -1;
  if (anchor_size > (1u << 20) || request_size > (1u << 20) || state_size > (1u << 20) ||
      message_size > pv::kMaxWalletTransactionBytes || count > pv::kMaxChainResponses + pv::kMaxDescentLinks + 3)
    return -5;
  try {
    // Validate the entire borrowed aggregate before copying even its first part.
    size_t remaining = pv::kMaxFileBytes;
    for (auto size : {anchor_size, request_size, state_size, message_size}) {
      if (size > remaining)
        return -5;
      remaining -= size;
    }
    bool seen[8]{};
    size_t chains = 0, descents = 0;
    for (size_t i = 0; i < count; ++i) {
      const auto& p = parts[i];
      if (!p.data || !p.size || (p.kind != 1 && p.kind != 2 && p.kind != 3 && p.kind != 5 && p.kind != 6))
        return -1;
      if ((p.kind == 2 && ++chains > pv::kMaxChainResponses) || (p.kind == 3 && ++descents > pv::kMaxDescentLinks))
        return -5;
      if (p.kind != 2 && p.kind != 3) {
        if (seen[p.kind])
          return -1;
        seen[p.kind] = true;
      }
      if (p.size > remaining || ((p.kind == 5 || p.kind == 6) && p.size > pv::detail::kMaxSimulationConfigReplyBytes))
        return -5;
      remaining -= p.size;
    }
    auto a = pv::parse_anchor(td::Slice(anchor, anchor_size));
    auto r = pv::parse_request(td::Slice(request, request_size));
    auto s = pv::parse_state(td::Slice(state, state_size));
    if (a.is_error() || r.is_error() || s.is_error())
      return -1;
    if (r.ok().mode != pv::Mode::Live || !r.ok().account || !r.ok().get_methods.empty() ||
        !r.ok().config_params.empty() || s.ok().anchor.id != a.ok().id || s.ok().anchor.kind != a.ok().kind)
      return -1;
    // Account header/graph budgets precede any copied material or proof cell allocation.
    for (size_t i = 0; i < count; ++i)
      if (parts[i].kind == 5) {
        auto preflight = pv::detail::preflight_simulation_account_reply(
            td::Slice(reinterpret_cast<const char*>(parts[i].data), parts[i].size));
        if (preflight.is_error())
          return preflight.code() == static_cast<int>(pv::detail::SimulationAccountError::Resource) ? -5 : -2;
      }
    pv::Material material;
    for (size_t i = 0; i < count; ++i) {
      const auto& p = parts[i];
      td::BufferSlice bytes(td::Slice(reinterpret_cast<const char*>(p.data), p.size));
      if (p.kind == 2)
        material.chain.push_back(std::move(bytes));
      else if (p.kind == 3)
        material.descent.push_back(std::move(bytes));
      else if (p.kind == 1)
        material.masterchain_info = std::move(bytes);
      else if (p.kind == 5)
        material.account = std::move(bytes);
      else
        material.exec_config = std::move(bytes);
    }
    auto simulated = pv::simulate_self_pay(a.ok(), r.ok(), td::Slice(request, request_size), material,
                                           std::optional<pv::LiveState>{s.move_as_ok()}, pv::Policy{local_now},
                                           td::Slice(reinterpret_cast<const char*>(message), message_size));
    auto error_code = [](const td::Status& error) {
      switch (error.code()) {
        case -1:
        case -2:
        case -4:
        case -5:
        case -6:
          return error.code();
        default:
          return -4;
      }
    };
    if (simulated.is_error())
      return error_code(simulated.error());
    auto rendered = pv::render_self_pay_simulation(simulated.ok());
    if (rendered.is_error())
      return error_code(rendered.error());
    if (!simulated.ok().authenticated_read.next_state)
      return -4;
    // LiveState contains only three fixed-width block identities and timestamps;
    // its canonical renderer has no endpoint-sized strings or containers.
    auto next = pv::render_state(*simulated.ok().authenticated_read.next_state);
    if (next.size() > pv::kMaxSelfPaySimulationStateBytes)
      return -5;
    if (rendered.ok().size() > capacity || next.size() > state_capacity)
      return -3;
    std::memcpy(result, rendered.ok().data(), rendered.ok().size());
    std::memcpy(next_state, next.data(), next.size());
    *result_size = rendered.ok().size();
    *next_state_size = next.size();
    return 0;
  } catch (...) {
    return -4;
  }
}
