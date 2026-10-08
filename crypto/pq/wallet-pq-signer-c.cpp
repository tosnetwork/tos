/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstring>
#include <optional>
#include <utility>

#include "wallet-pq-signer-c.h"
#include "wallet-pq-signer.h"

using tos::pq::WalletPQPurpose;
using tos::pq::WalletPQRole;
using tos::pq::WalletPQSigner;

struct tos_wallet_pq_signer {
  WalletPQSigner signer;
};

namespace {
std::optional<WalletPQRole> role(int value) {
  if (value == TOS_WALLET_PQ_PRIMARY)
    return WalletPQRole::primary;
  if (value == TOS_WALLET_PQ_RESCUE)
    return WalletPQRole::rescue;
  return std::nullopt;
}
std::optional<WalletPQPurpose> purpose(int value) {
  if (value == TOS_WALLET_PQ_AUTH)
    return WalletPQPurpose::auth;
  if (value == TOS_WALLET_PQ_POP)
    return WalletPQPurpose::pop;
  if (value == TOS_WALLET_PQ_PREPARATION)
    return WalletPQPurpose::preparation;
  return std::nullopt;
}
std::string_view view(const uint8_t* data, size_t size) {
  return {reinterpret_cast<const char*>(data), size};
}
}  // namespace

extern "C" tos_wallet_pq_signer* tos_wallet_pq_generate(int value) {
  try {
    const auto selected = role(value);
    if (!selected)
      return nullptr;
    auto signer = WalletPQSigner::generate(*selected);
    return signer ? new tos_wallet_pq_signer{std::move(*signer)} : nullptr;
  } catch (...) {
    return nullptr;
  }
}
extern "C" tos_wallet_pq_signer* tos_wallet_pq_import(int value, const uint8_t* seed, size_t size) {
  try {
    const auto selected = role(value);
    if (!selected || !seed)
      return nullptr;
    auto signer = WalletPQSigner::from_seed(*selected, view(seed, size));
    return signer ? new tos_wallet_pq_signer{std::move(*signer)} : nullptr;
  } catch (...) {
    return nullptr;
  }
}
extern "C" void tos_wallet_pq_destroy(tos_wallet_pq_signer* signer) {
  delete signer;
}
extern "C" int tos_wallet_pq_public_key(const tos_wallet_pq_signer* signer, uint8_t* output, size_t size) {
  if (!signer || !output || signer->signer.public_key().size() != size)
    return 0;
  std::memcpy(output, signer->signer.public_key().data(), size);
  return 1;
}
extern "C" int tos_wallet_pq_sign(const tos_wallet_pq_signer* signer, int expected_role, int requested_purpose,
                                  const uint8_t* expected_key, size_t key_size, const uint8_t* digest,
                                  size_t digest_size, uint8_t* signature, size_t signature_size) {
  try {
    const auto selected = role(expected_role);
    const auto operation = purpose(requested_purpose);
    if (!signer || !selected || !operation || !expected_key || !digest || !signature)
      return 0;
    if (signer->signer.role() != *selected || signer->signer.public_key() != view(expected_key, key_size))
      return 0;
    const size_t required_size = *selected == WalletPQRole::primary ? 2420 : 7856;
    if (signature_size != required_size || digest_size != 32)
      return 0;
    const auto result = signer->signer.sign(*operation, view(digest, digest_size));
    if (!result || result->size() != required_size)
      return 0;
    std::memcpy(signature, result->data(), required_size);
    return 1;
  } catch (...) {
    return 0;
  }
}
