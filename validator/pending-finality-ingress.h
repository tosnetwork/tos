/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <cstddef>
#include <deque>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

#include "block/validator-set.h"
#include "keys/keys.hpp"
#include "validator/validator-transport-authority.h"

namespace tos::validator {

struct PendingBlockFinalitySender {
  bool local{true};
  PublicKeyHash peer;

  static PendingBlockFinalitySender local_source() {
    return {};
  }
  static PendingBlockFinalitySender remote(PublicKeyHash peer) {
    return {false, peer};
  }
  bool operator==(const PendingBlockFinalitySender &other) const {
    return local == other.local && (local || peer == other.peer);
  }
  bool operator<(const PendingBlockFinalitySender &other) const {
    if (local != other.local) {
      return local < other.local;
    }
    return !local && peer < other.peer;
  }
};

enum class PendingFinalityIngressRejection { None, MissingRemoteByteCount, MissingLocalMeasurement };

constexpr const char *pending_finality_ingress_rejection_name(PendingFinalityIngressRejection rejection) {
  switch (rejection) {
    case PendingFinalityIngressRejection::None:
      return "none";
    case PendingFinalityIngressRejection::MissingRemoteByteCount:
      return "missing_remote_byte_count";
    case PendingFinalityIngressRejection::MissingLocalMeasurement:
      return "missing_local_measurement";
  }
  return "unknown";
}

struct PendingFinalityIngressDecision {
  PendingBlockFinalitySender sender;
  std::size_t accounted_bytes{0};
  PendingFinalityIngressRejection rejection{PendingFinalityIngressRejection::None};

  bool admitted() const {
    return rejection == PendingFinalityIngressRejection::None;
  }
};

// This is the manager's admission boundary between authenticated transport
// metadata and the byte-bounded pending store. Remote evidence must carry the
// exact received payload size; treating a missing size as zero would give it a
// free resource charge. Local evidence has no wire payload and instead must
// supply its measured intrinsic signature size.
inline PendingFinalityIngressDecision prepare_pending_finality_ingress(
    const PublicKeyHash *source_peer, std::size_t received_bytes,
    std::optional<std::size_t> local_signature_bytes = std::nullopt) {
  if (source_peer != nullptr) {
    if (received_bytes == 0) {
      return {PendingBlockFinalitySender::remote(*source_peer), 0,
              PendingFinalityIngressRejection::MissingRemoteByteCount};
    }
    return {PendingBlockFinalitySender::remote(*source_peer), received_bytes, PendingFinalityIngressRejection::None};
  }
  if (!local_signature_bytes) {
    return {PendingBlockFinalitySender::local_source(), 0, PendingFinalityIngressRejection::MissingLocalMeasurement};
  }
  return {PendingBlockFinalitySender::local_source(), *local_signature_bytes, PendingFinalityIngressRejection::None};
}

// Only the transport identity carried by a descriptor in the exact validator
// set governing this evidence is entitled to the committee-reserved capacity.
// Public-overlay peers remain authenticated transport senders, but they are not
// consensus authorities and therefore draw from the shared public pool.
inline bool pending_finality_sender_is_validator(const PendingBlockFinalitySender &sender,
                                                 const std::vector<ValidatorDescr> &validators) {
  if (sender.local) {
    return true;
  }
  for (const auto &validator : validators) {
    if (validator_transport_root(validator) == sender.peer) {
      return true;
    }
  }
  return false;
}

struct PendingFinalityAuthorityKey {
  ShardIdFull shard;
  CatchainSeqno catchain_seqno;

  bool operator==(const PendingFinalityAuthorityKey &other) const {
    return shard == other.shard && catchain_seqno == other.catchain_seqno;
  }
};

struct PendingFinalityAuthoritySet {
  td::uint32 validator_set_hash;
  std::vector<PublicKeyHash> roots;
  td::Ref<block::ValidatorSet> validator_set;
};

constexpr bool pending_finality_catchain_is_current_or_next(CatchainSeqno current, CatchainSeqno claimed) {
  if (claimed == current) {
    return true;
  }
  return current != std::numeric_limits<CatchainSeqno>::max() && claimed == current + 1;
}

// get_shard_cc_seqno() deliberately resolves descendants to their containing
// configured shard. That is useful to chain logic, but an untrusted block id
// must not use such a descendant as a fresh validator-set memo key. Require an
// exact configured shard before any validator-set computation.
constexpr bool pending_finality_coordinate_is_admissible(bool exact_configured_shard, CatchainSeqno current,
                                                         CatchainSeqno claimed) {
  return exact_configured_shard && pending_finality_catchain_is_current_or_next(current, claimed);
}

inline constexpr std::size_t pending_finality_authority_memo_max_entries = 8;

// Only current and next catchain coordinates can be legitimate for one shard
// at one trusted state, so a small cache has a high honest-path hit rate. That
// observation does not bound the number of attacker-selected shard ids: the
// global LRU cap below bounds the structure regardless of which key component
// an arrival varies. The attacker-controlled set hash is deliberately not part
// of the key: entries store locally computed hashes beside their roots, so
// cycling claimed hashes is a cheap comparison rather than another
// validator-set computation. The manager clears the memo when its trusted
// masterchain state changes, so a cached negative result cannot survive the
// state update that makes a set known.
class PendingFinalityAuthorityMemo {
 public:
  template <class Loader>
  const std::vector<PendingFinalityAuthoritySet> &get(const PendingFinalityAuthorityKey &key, Loader &&loader) {
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
      if (it->key == key) {
        auto sets = std::move(it->sets);
        entries_.erase(it);
        entries_.push_back({key, std::move(sets)});
        return entries_.back().sets;
      }
    }
    auto sets = loader();
    if (entries_.size() == pending_finality_authority_memo_max_entries) {
      entries_.pop_front();
    }
    entries_.push_back({key, std::move(sets)});
    return entries_.back().sets;
  }

  template <class Loader>
  bool contains(const PendingFinalityAuthorityKey &key, td::uint32 claimed_validator_set_hash,
                const PublicKeyHash &peer, Loader &&loader) {
    return contains_peer(get(key, std::forward<Loader>(loader)), claimed_validator_set_hash, peer);
  }

  void clear() {
    entries_.clear();
  }

  std::size_t size() const {
    return entries_.size();
  }

 private:
  struct Entry {
    PendingFinalityAuthorityKey key;
    std::vector<PendingFinalityAuthoritySet> sets;
  };

  static bool contains_peer(const std::vector<PendingFinalityAuthoritySet> &sets, td::uint32 claimed_validator_set_hash,
                            const PublicKeyHash &peer) {
    for (const auto &set : sets) {
      if (set.validator_set_hash == claimed_validator_set_hash) {
        for (const auto &root : set.roots) {
          if (root == peer) {
            return true;
          }
        }
      }
    }
    return false;
  }

  std::deque<Entry> entries_;
};

template <class Loader>
bool pending_finality_sender_is_validator(PendingFinalityAuthorityMemo &memo, ShardIdFull shard,
                                          CatchainSeqno current_catchain_seqno, CatchainSeqno claimed_catchain_seqno,
                                          td::uint32 claimed_validator_set_hash, const PublicKeyHash &peer,
                                          Loader &&loader) {
  if (!pending_finality_catchain_is_current_or_next(current_catchain_seqno, claimed_catchain_seqno)) {
    return false;
  }
  return memo.contains({shard, claimed_catchain_seqno}, claimed_validator_set_hash, peer, std::forward<Loader>(loader));
}

}  // namespace tos::validator
