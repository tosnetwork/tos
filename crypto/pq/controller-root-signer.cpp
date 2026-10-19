/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "controller-root-signer.h"
#include "mldsa_native.h"
#include "pq-controller-domain.h"
#include "pq-sign-under.h"

namespace tos::pq {

struct ValidatorControllerRootKeyStore::Secret {
  std::array<std::uint8_t, MLDSA44_SECRETKEYBYTES> sk{};
  ~Secret() {
    OPENSSL_cleanse(sk.data(), sk.size());
  }
};

ValidatorControllerRootKeyStore::ValidatorControllerRootKeyStore(ValidatorControllerRootKeyStore&&) noexcept = default;
ValidatorControllerRootKeyStore& ValidatorControllerRootKeyStore::operator=(
    ValidatorControllerRootKeyStore&&) noexcept = default;
ValidatorControllerRootKeyStore::~ValidatorControllerRootKeyStore() = default;

std::optional<ValidatorControllerRootKeyStore> ValidatorControllerRootKeyStore::from_seed(
    std::string_view seed) noexcept {
  ValidatorControllerRootKeyStore store;
  store.secret_ = std::make_unique<Secret>();
  if (!detail::derive_from_seed(seed, store.key_, store.secret_->sk.data())) {
    return std::nullopt;  // store's Secret dtor wipes the secret key
  }
  return std::optional<ValidatorControllerRootKeyStore>(std::move(store));
}

std::optional<ValidatorControllerRootKeyStore> ValidatorControllerRootKeyStore::generate() noexcept {
  std::array<std::uint8_t, MLDSA_SEEDBYTES> seed{};
  if (RAND_priv_bytes(seed.data(), static_cast<int>(seed.size())) != 1) {
    OPENSSL_cleanse(seed.data(), seed.size());  // wipe on every exit, including RNG failure
    return std::nullopt;
  }
  auto out = from_seed(std::string_view(reinterpret_cast<const char*>(seed.data()), seed.size()));
  OPENSSL_cleanse(seed.data(), seed.size());
  return out;
}

std::optional<ConsensusPQSignature> ValidatorControllerRootKeyStore::sign_controller_authorization(
    std::string_view message) const noexcept {
  return detail::sign_under(key_, secret_ ? secret_->sk.data() : nullptr, controller_auth_context, message);
}

}  // namespace tos::pq
