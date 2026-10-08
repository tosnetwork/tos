/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <array>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <vector>

#include "mldsa44.h"
#include "mldsa_native.h"
#include "slh_dsa.h"
#include "slhdsa128s.h"
#include "wallet-pq-signer.h"

namespace tos::pq {
namespace {
template <std::size_t N>
struct Wiped {
  std::array<std::uint8_t, N> bytes{};
  ~Wiped() {
    OPENSSL_cleanse(bytes.data(), bytes.size());
  }
};
std::string_view context(WalletPQRole role, WalletPQPurpose purpose) {
  if (role != WalletPQRole::primary && role != WalletPQRole::rescue)
    return {};
  switch (purpose) {
    case WalletPQPurpose::auth:
      return role == WalletPQRole::primary ? "TOS-AUTH-V2-ML-DSA-44-v1" : "TOS-AUTH-SLH-DSA-SHA2-128S-v1";
    case WalletPQPurpose::pop:
      return "TOS-RESCUE-POP-v1";
    case WalletPQPurpose::preparation:
      return role == WalletPQRole::rescue ? "TOS-RESCUE-FEE-PREP-v1" : "";
  }
  return {};
}
std::string_view view(const std::uint8_t* data, std::size_t size) {
  return {reinterpret_cast<const char*>(data), size};
}
}  // namespace
struct WalletPQSigner::Secret {
  Wiped<MLDSA44_SECRETKEYBYTES> mldsa;
  Wiped<64> slh;
};
WalletPQSigner::WalletPQSigner() = default;
WalletPQSigner::WalletPQSigner(WalletPQSigner&&) noexcept = default;
WalletPQSigner& WalletPQSigner::operator=(WalletPQSigner&&) noexcept = default;
WalletPQSigner::~WalletPQSigner() = default;

std::optional<WalletPQSigner> WalletPQSigner::generate(WalletPQRole role) {
  const int size = role == WalletPQRole::primary ? 32 : role == WalletPQRole::rescue ? 48 : 0;
  if (size == 0)
    return std::nullopt;
  Wiped<48> seed;
  if (RAND_priv_bytes(seed.bytes.data(), size) != 1)
    return std::nullopt;
  return from_seed(role, view(seed.bytes.data(), static_cast<std::size_t>(size)));
}
std::optional<WalletPQSigner> WalletPQSigner::from_seed(WalletPQRole role, std::string_view seed) {
  const std::size_t size = role == WalletPQRole::primary ? 32 : role == WalletPQRole::rescue ? 48 : 0;
  if (size == 0 || seed.size() != size)
    return std::nullopt;
  WalletPQSigner result;
  result.role_ = role;
  result.secret_ = std::make_unique<Secret>();
  auto bytes = reinterpret_cast<const std::uint8_t*>(seed.data());
  if (role == WalletPQRole::primary) {
    std::array<std::uint8_t, MLDSA44_PUBLICKEYBYTES> pk{};
    if (tos_wallet_pq_native_keypair_internal(pk.data(), result.secret_->mldsa.bytes.data(), bytes) != 0)
      return std::nullopt;
    result.public_key_.assign(view(pk.data(), pk.size()));
  } else {
    std::array<std::uint8_t, 32> pk{};
    if (slh_keygen_internal(result.secret_->slh.bytes.data(), pk.data(), bytes, bytes + 16, bytes + 32,
                            &slh_dsa_sha2_128s) != 0)
      return std::nullopt;
    result.public_key_.assign(view(pk.data(), pk.size()));
  }
  return std::optional<WalletPQSigner>(std::move(result));
}
std::optional<std::string> WalletPQSigner::sign(WalletPQPurpose purpose, std::string_view digest) const {
  const auto ctx = context(role_, purpose);
  if (!secret_ || digest.size() != 32 || ctx.empty())
    return std::nullopt;
  Wiped<32> random;
  const int random_size = role_ == WalletPQRole::primary ? 32 : 16;
  if (RAND_priv_bytes(random.bytes.data(), random_size) != 1)
    return std::nullopt;
  auto message = reinterpret_cast<const std::uint8_t*>(digest.data());
  std::string result;
  VerifyResult verified;
  if (role_ == WalletPQRole::primary) {
    std::vector<std::uint8_t> prefix{0, static_cast<std::uint8_t>(ctx.size())};
    prefix.insert(prefix.end(), ctx.begin(), ctx.end());
    std::array<std::uint8_t, MLDSA44_BYTES> signature{};
    if (tos_wallet_pq_native_signature_internal(signature.data(), message, digest.size(), prefix.data(), prefix.size(),
                                                random.bytes.data(), secret_->mldsa.bytes.data(), 0) != 0)
      return std::nullopt;
    result.assign(view(signature.data(), signature.size()));
    verified = verify_mldsa44(digest, ctx, result, public_key_);
  } else {
    std::array<std::uint8_t, 7856> signature{};
    if (slh_sign(signature.data(), message, digest.size(), reinterpret_cast<const std::uint8_t*>(ctx.data()),
                 ctx.size(), secret_->slh.bytes.data(), random.bytes.data(), &slh_dsa_sha2_128s) != signature.size())
      return std::nullopt;
    result.assign(view(signature.data(), signature.size()));
    verified = verify_slhdsa128s(digest, ctx, result, public_key_);
  }
  if (verified != VerifyResult::valid)
    return std::nullopt;
  return result;
}
}  // namespace tos::pq
