/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
// Validator CONSENSUS PQ signer. Holds consensus secret-key material and produces
// signatures under the consensus finality context only. Deliberately separate from
// wallet signing and from the ADNL keyring / validator temp keys (which stay Ed25519).
#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

#include "pq-consensus.h"

namespace tos::pq {

class ValidatorPQKeyStore {
 public:
  ValidatorPQKeyStore(ValidatorPQKeyStore&&) noexcept;
  ValidatorPQKeyStore& operator=(ValidatorPQKeyStore&&) noexcept;
  ~ValidatorPQKeyStore();

  // Fresh consensus keypair from a secure random 32-byte seed; nullopt on RNG/backend failure.
  static std::optional<ValidatorPQKeyStore> generate() noexcept;
  // Deterministic keypair from a caller-owned 32-byte seed (test vectors / recovery).
  static std::optional<ValidatorPQKeyStore> from_seed(std::string_view seed) noexcept;

  const ConsensusPQKey& consensus_key() const noexcept {
    return key_;
  }

  // Sign under the frozen simplex_sign_context (domain-separated from wallet/agent
  // ML-DSA use and from the other frozen consensus authority surfaces).
  // nullopt on backend failure; the returned signature is always signature_bytes long.
  std::optional<ConsensusPQSignature> sign_consensus(std::string_view message) const noexcept;

  // How many consensus signatures this store has produced. Signing is randomized, so a
  // signature this node cannot reproduce is one it must have kept; the count is how an
  // operator, or a restart test, sees whether a recovery path signed anything at all.
  // A correct journal replay of already-signed votes leaves it unchanged.
  std::uint64_t consensus_signatures_produced() const noexcept {
    return consensus_signatures_produced_.load(std::memory_order_relaxed);
  }

  // Sign a validator's vote on a configuration proposal, under
  // validator_config_vote_context. The message is the preimage the configuration
  // contract rebuilds and verifies; this signs it, and decides nothing about it.
  std::optional<ConsensusPQSignature> sign_config_vote(std::string_view message) const noexcept;

  // Sign a validator's vote on a complaint against a validator of a past election,
  // under validator_election_context, which the elector shares with stake requests.
  std::optional<ConsensusPQSignature> sign_election(std::string_view message) const noexcept;

  // A hard deadline: from unix time `expire_at` on (0: never), every sign_* above returns
  // nullopt, whatever holds this store -- a running validator group, a vote, a stake.
  // Every caller already fails closed on nullopt (no candidate, no vote, no
  // authorization), so an expired consensus key stops signing at the instant it expires
  // rather than when the next lookup happens to notice, and nothing substitutes another
  // key for it. Set once, before the store is shared.
  void set_expire_at(std::uint32_t expire_at) noexcept {
    expire_at_ = expire_at;
  }
  std::uint32_t expire_at() const noexcept {
    return expire_at_;
  }
  bool expired_at(std::uint64_t unix_now) const noexcept {
    return expire_at_ != 0 && unix_now >= expire_at_;
  }
  // Whether the deadline has passed by the system clock, which is what signing consults.
  bool expired_now() const noexcept;
  // How many signatures the deadline has refused.
  std::uint64_t signatures_refused_after_expiry() const noexcept {
    return signatures_refused_after_expiry_.load(std::memory_order_relaxed);
  }

 private:
  ValidatorPQKeyStore() = default;
  struct Secret;
  ConsensusPQKey key_{};
  std::unique_ptr<Secret> secret_;  // wiped on destruction
  mutable std::atomic<std::uint64_t> consensus_signatures_produced_{0};
  std::uint32_t expire_at_ = 0;
  mutable std::atomic<std::uint64_t> signatures_refused_after_expiry_{0};
  bool refuse_if_expired() const noexcept;
};

}  // namespace tos::pq
