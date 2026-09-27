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

 private:
  ValidatorPQKeyStore() = default;
  struct Secret;
  ConsensusPQKey key_{};
  std::unique_ptr<Secret> secret_;  // wiped on destruction
  mutable std::atomic<std::uint64_t> consensus_signatures_produced_{0};
};

}  // namespace tos::pq
