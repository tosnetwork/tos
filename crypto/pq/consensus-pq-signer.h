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
  //
  // The deadline is read from the host's wall clock, checked before a signature is made
  // and again before it is returned (one whose computation crossed the deadline is
  // discarded), and latched: once the key has been seen expired, its identity is retired
  // for the life of the process (see `consensus_key_retired`), so neither a clock stepped
  // back nor a fresh store built from the same seed revives it. Clock skew still shifts
  // the deadline itself by the skew; operators run NTP.
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
  // Whether this key's identity has been retired in this process; it then stays so.
  bool retired() const noexcept;
#if defined(TOS_PQ_SIGNER_TEST_CLOCK)
  // Test builds only (the tos_pq_consensus_signer_test_clock library): the wall clock the
  // deadline is read from, as unix seconds. Tests replace it to put the deadline inside a
  // signing call or to step the clock back; nullptr restores the system clock. The
  // production library is compiled without this, and a guard checks it has no such
  // symbol.
  using UnixClock = std::int64_t (*)() noexcept;
  static void set_clock_for_test(UnixClock clock) noexcept;
#endif
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
  std::optional<ConsensusPQSignature> sign_within_deadline(std::string_view context,
                                                           std::string_view message) const noexcept;
};

// The consensus keys retired in this process: every key identity seen past its deadline,
// by a store when it was asked to sign or by custody when it was asked about the key.
// One registry for the whole process, keyed by key identity rather than held by a store,
// and never cleared while the process runs: within one process a key is not revived by
// a clock stepped back, by a new store built from the same seed (from any file path), or
// by removing it and adding it again. It is not persisted: a restart with a wall clock
// rolled back before a configured key's expire_at loads that key again, by its window.
// Entries accumulate across rotations for the life of the process; the limit of eight
// held keys does not bound them (each is 32 bytes).
//
// Lookup is open to every reader. The only writers are a store's own deadline check
// and `retire_expired_consensus_key`, which custody calls when its own clock reading
// finds a key's window closed.
bool consensus_key_retired(const std::array<std::uint8_t, 32>& key_id) noexcept;
// Records that `key_id` was seen past its deadline. Aborts the process if the record
// cannot be stored: a key that might be revived later must not be left signing.
void retire_expired_consensus_key(const std::array<std::uint8_t, 32>& key_id) noexcept;
#if defined(TOS_PQ_SIGNER_TEST_CLOCK)
// Test builds only: make the next registry insertion fail as an allocation would.
void fail_next_retirement_for_test() noexcept;
#endif

}  // namespace tos::pq
