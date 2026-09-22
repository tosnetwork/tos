/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "consensus-pq-signer.h"
#include "mldsa_native.h"
#include "pq-sign-under.h"

namespace tos::pq {

struct ValidatorPQKeyStore::Secret {
  std::array<std::uint8_t, MLDSA44_SECRETKEYBYTES> sk{};
  ~Secret() {
    OPENSSL_cleanse(sk.data(), sk.size());
  }
};

// The signature counter is an atomic and so not movable; it is carried across by value.
// A moved-from store keeps its own count, which is correct: the tally belongs to the key
// material that is moving, not to the shell left behind.
ValidatorPQKeyStore::ValidatorPQKeyStore(ValidatorPQKeyStore&& other) noexcept
    : key_(std::move(other.key_))
    , secret_(std::move(other.secret_))
    , consensus_signatures_produced_(other.consensus_signatures_produced_.load(std::memory_order_relaxed)) {
}

ValidatorPQKeyStore& ValidatorPQKeyStore::operator=(ValidatorPQKeyStore&& other) noexcept {
  if (this != &other) {
    key_ = std::move(other.key_);
    secret_ = std::move(other.secret_);
    consensus_signatures_produced_.store(other.consensus_signatures_produced_.load(std::memory_order_relaxed),
                                         std::memory_order_relaxed);
  }
  return *this;
}

ValidatorPQKeyStore::~ValidatorPQKeyStore() = default;

std::optional<ValidatorPQKeyStore> ValidatorPQKeyStore::from_seed(std::string_view seed) noexcept {
  ValidatorPQKeyStore store;
  store.secret_ = std::make_unique<Secret>();
  if (!detail::derive_from_seed(seed, store.key_, store.secret_->sk.data())) {
    return std::nullopt;  // store's Secret dtor wipes the secret key
  }
  return std::optional<ValidatorPQKeyStore>(std::move(store));
}

std::optional<ValidatorPQKeyStore> ValidatorPQKeyStore::generate() noexcept {
  std::array<std::uint8_t, MLDSA_SEEDBYTES> seed{};
  if (RAND_priv_bytes(seed.data(), static_cast<int>(seed.size())) != 1) {
    OPENSSL_cleanse(seed.data(), seed.size());  // wipe on every exit, including RNG failure
    return std::nullopt;
  }
  auto out = from_seed(std::string_view(reinterpret_cast<const char*>(seed.data()), seed.size()));
  OPENSSL_cleanse(seed.data(), seed.size());
  return out;
}

std::optional<ConsensusPQSignature> ValidatorPQKeyStore::sign_consensus(std::string_view message) const noexcept {
  auto signature = detail::sign_under(key_, secret_ ? secret_->sk.data() : nullptr, simplex_sign_context, message);
  if (signature.has_value()) {
    consensus_signatures_produced_.fetch_add(1, std::memory_order_relaxed);
  }
  return signature;
}

std::optional<ConsensusPQSignature> ValidatorPQKeyStore::sign_config_vote(std::string_view message) const noexcept {
  return detail::sign_under(key_, secret_ ? secret_->sk.data() : nullptr, validator_config_vote_context, message);
}

std::optional<ConsensusPQSignature> ValidatorPQKeyStore::sign_election(std::string_view message) const noexcept {
  return detail::sign_under(key_, secret_ ? secret_->sk.data() : nullptr, validator_election_context, message);
}

}  // namespace tos::pq
