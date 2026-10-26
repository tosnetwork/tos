/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstring>
#include <optional>

#include "embedded.h"
#include "proof-verify.h"
#include "wallet-transaction.h"

extern "C" int tos_proof_verify_embedded(const char *anchor, size_t anchor_size, const char *request,
                                         size_t request_size, const char *state, size_t state_size, int64_t local_now,
                                         const tos_proof_material *parts, size_t count, char *result, size_t capacity,
                                         size_t *result_size, char *next_state, size_t state_capacity,
                                         size_t *next_state_size) {
  namespace pv = tos::proofverify;
  // Capacity limits also bound clearing work before parsing untrusted material.
  if (result_size)
    *result_size = 0;
  if (next_state_size)
    *next_state_size = 0;
  if (!result || !next_state || capacity > pv::kMaxFileBytes || state_capacity > (1u << 20))
    return -1;
  std::memset(result, 0, capacity);
  std::memset(next_state, 0, state_capacity);
  if (!result_size || !next_state_size || !anchor || !request || (!parts && count) || !anchor_size ||
      anchor_size > (1u << 20) || !request_size || request_size > (1u << 20) || state_size > (1u << 20) ||
      (state_size && !state) || local_now <= 0 || count > 1045)
    return -1;
  try {
    auto a = pv::parse_anchor(td::Slice(anchor, anchor_size));
    auto r = pv::parse_request(td::Slice(request, request_size));
    if (a.is_error() || r.is_error())
      return -1;
    std::optional<pv::LiveState> prior;
    if (state_size) {
      auto s = pv::parse_state(td::Slice(state, state_size));
      if (s.is_error())
        return -1;
      prior = s.move_as_ok();
    }
    pv::Material m;
    size_t total = 0;
    for (size_t i = 0; i < count; ++i) {
      const auto &p = parts[i];
      if (!p.data || !p.size || p.size > pv::kMaxFileBytes - total)
        return -1;
      total += p.size;
      if (p.kind < 1 || p.kind > 7)
        return -1;
      if (p.kind == 2) {
        if (m.chain.size() >= pv::kMaxChainResponses)
          return -1;
        m.chain.emplace_back(td::Slice(reinterpret_cast<const char *>(p.data), p.size));
      } else if (p.kind == 3) {
        if (m.descent.size() >= pv::kMaxDescentLinks)
          return -1;
        m.descent.emplace_back(td::Slice(reinterpret_cast<const char *>(p.data), p.size));
      } else {
        auto *slot = p.kind == 1   ? &m.masterchain_info
                     : p.kind == 4 ? &m.config
                     : p.kind == 5 ? &m.account
                     : p.kind == 6 ? &m.exec_config
                                   : &m.libraries;
        if (slot->has_value())
          return -1;
        slot->emplace(td::Slice(reinterpret_cast<const char *>(p.data), p.size));
      }
    }
    auto verified = pv::verify(a.ok(), r.ok(), td::Slice(request, request_size), m, prior, pv::Policy{local_now});
    if (verified.is_error())
      return -2;
    auto answer = verified.move_as_ok();
    auto rendered = pv::render_verified(answer);
    auto rendered_state = answer.next_state ? pv::render_state(*answer.next_state) : std::string();
    if (rendered.size() > capacity || rendered_state.size() > state_capacity)
      return -3;
    std::memcpy(result, rendered.data(), rendered.size());
    std::memcpy(next_state, rendered_state.data(), rendered_state.size());
    *result_size = rendered.size();
    *next_state_size = rendered_state.size();
    return 0;
  } catch (...) {
    return -4;
  }
}

extern "C" int tos_proof_verify_wallet_transaction(int32_t workchain, const uint8_t *account_hash,
                                                   uint64_t logical_time, const uint8_t *transaction_hash,
                                                   const uint8_t *boc, size_t boc_size, char *result,
                                                   size_t capacity, size_t *result_size) {
  namespace pv = tos::proofverify;
  if (result_size)
    *result_size = 0;
  if (!result || capacity > pv::kMaxWalletTransactionResultBytes)
    return -1;
  std::memset(result, 0, capacity);
  if (!result_size || workchain != 0 || !account_hash || !transaction_hash || !logical_time || !boc ||
      !boc_size || boc_size > pv::kMaxWalletTransactionBytes)
    return -1;
  try {
    auto verified = pv::verify_wallet_transaction(
        td::Slice(reinterpret_cast<const char *>(account_hash), 32), logical_time,
        td::Slice(reinterpret_cast<const char *>(transaction_hash), 32),
        td::Slice(reinterpret_cast<const char *>(boc), boc_size));
    if (verified.is_error())
      return -2;
    const auto &rendered = verified.ok();
    if (rendered.size() > capacity)
      return -3;
    std::memcpy(result, rendered.data(), rendered.size());
    *result_size = rendered.size();
    return 0;
  } catch (...) {
    return -4;
  }
}
