/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <chrono>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "../../metrics/core-health.h"

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
    , consensus_signatures_produced_(other.consensus_signatures_produced_.load(std::memory_order_relaxed))
    , expire_at_(other.expire_at_)
    , signatures_refused_after_expiry_(other.signatures_refused_after_expiry_.load(std::memory_order_relaxed))
    , retired_(other.retired_.load(std::memory_order_relaxed)) {
}

ValidatorPQKeyStore& ValidatorPQKeyStore::operator=(ValidatorPQKeyStore&& other) noexcept {
  if (this != &other) {
    key_ = std::move(other.key_);
    secret_ = std::move(other.secret_);
    consensus_signatures_produced_.store(other.consensus_signatures_produced_.load(std::memory_order_relaxed),
                                         std::memory_order_relaxed);
    expire_at_ = other.expire_at_;
    signatures_refused_after_expiry_.store(other.signatures_refused_after_expiry_.load(std::memory_order_relaxed),
                                           std::memory_order_relaxed);
    retired_.store(other.retired_.load(std::memory_order_relaxed), std::memory_order_relaxed);
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

namespace {

std::int64_t system_unix_time() noexcept {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::atomic<ValidatorPQKeyStore::UnixClock> deadline_clock{&system_unix_time};

}  // namespace

void ValidatorPQKeyStore::set_clock_for_test(UnixClock clock) noexcept {
  deadline_clock.store(clock != nullptr ? clock : &system_unix_time, std::memory_order_relaxed);
}

bool ValidatorPQKeyStore::expired_now() const noexcept {
  if (expire_at_ == 0) {
    return false;
  }
  if (retired_.load(std::memory_order_relaxed)) {
    return true;
  }
  const auto now = deadline_clock.load(std::memory_order_relaxed)();
  // A clock before the epoch is not a time this key is valid at.
  if (now < 0 || expired_at(static_cast<std::uint64_t>(now))) {
    // Latched: once seen expired, the key stays retired for the life of this process,
    // whatever the wall clock does afterwards -- a clock stepped back must not revive it.
    retired_.store(true, std::memory_order_relaxed);
    return true;
  }
  return false;
}

bool ValidatorPQKeyStore::refuse_if_expired() const noexcept {
  if (!expired_now()) {
    return false;
  }
  signatures_refused_after_expiry_.fetch_add(1, std::memory_order_relaxed);
  return true;
}

// The deadline is checked before signing and again before the signature is handed out: a
// signature whose computation crossed the deadline is discarded, not released.
std::optional<ConsensusPQSignature> ValidatorPQKeyStore::sign_within_deadline(std::string_view context,
                                                                              std::string_view message) const noexcept {
  if (refuse_if_expired()) {
    return std::nullopt;
  }
  auto signature = detail::sign_under(key_, secret_ ? secret_->sk.data() : nullptr, context, message);
  if (signature.has_value() && refuse_if_expired()) {
    return std::nullopt;
  }
  return signature;
}

std::optional<ConsensusPQSignature> ValidatorPQKeyStore::sign_consensus(std::string_view message) const noexcept {
  tos::health::OperationTimer timer(tos::health::pq_sign);
  auto signature = sign_within_deadline(simplex_sign_context, message);
  timer.finish(signature.has_value());
  if (signature.has_value()) {
    consensus_signatures_produced_.fetch_add(1, std::memory_order_relaxed);
  }
  return signature;
}

std::optional<ConsensusPQSignature> ValidatorPQKeyStore::sign_config_vote(std::string_view message) const noexcept {
  return sign_within_deadline(validator_config_vote_context, message);
}

std::optional<ConsensusPQSignature> ValidatorPQKeyStore::sign_election(std::string_view message) const noexcept {
  return sign_within_deadline(validator_election_context, message);
}

}  // namespace tos::pq
