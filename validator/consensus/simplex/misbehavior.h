/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "td/utils/buffer.h"
#include "validator/consensus/misbehavior.h"

namespace tos::validator::consensus::simplex {

class ConflictingVotes : public Misbehavior {
 public:
  static MisbehaviorRef create(td::BufferSlice vote1, td::BufferSlice vote2) {
    return td::make_ref<ConflictingVotes>(std::move(vote1), std::move(vote2));
  }

  ConflictingVotes(td::BufferSlice vote1, td::BufferSlice vote2) : vote1_(std::move(vote1)), vote2_(std::move(vote2)) {
  }

 private:
  td::BufferSlice vote1_;
  td::BufferSlice vote2_;
};

class ConflictingCandidateAndCertificate : public Misbehavior {
 public:
  static MisbehaviorRef create() {
    return td::make_ref<ConflictingCandidateAndCertificate>();
  }

  ConflictingCandidateAndCertificate() {
  }
};

// V-018: leader signed a candidate whose parent_slot >= own slot (slot inversion).
// Evidence: the serialized candidate (contains the signed slot and parent fields).
class SlotInversionCandidate : public Misbehavior {
 public:
  static MisbehaviorRef create(td::BufferSlice candidate_bytes) {
    return td::make_ref<SlotInversionCandidate>(std::move(candidate_bytes));
  }

  explicit SlotInversionCandidate(td::BufferSlice candidate_bytes)
      : candidate_bytes_(std::move(candidate_bytes)) {
  }

 private:
  td::BufferSlice candidate_bytes_;
};

// V-019: leader signed two distinct candidates for the same slot (double proposal).
// Evidence: serialized forms of both conflicting candidates.
class ConflictingCandidates : public Misbehavior {
 public:
  static MisbehaviorRef create(td::BufferSlice candidate1_bytes, td::BufferSlice candidate2_bytes) {
    return td::make_ref<ConflictingCandidates>(std::move(candidate1_bytes), std::move(candidate2_bytes));
  }

  ConflictingCandidates(td::BufferSlice candidate1_bytes, td::BufferSlice candidate2_bytes)
      : candidate1_bytes_(std::move(candidate1_bytes)), candidate2_bytes_(std::move(candidate2_bytes)) {
  }

 private:
  td::BufferSlice candidate1_bytes_;
  td::BufferSlice candidate2_bytes_;
};

// V-020: leader signed a candidate that was rejected by the local validator.
// Evidence: serialized candidate plus the rejection reason string.
class RejectedCandidate : public Misbehavior {
 public:
  static MisbehaviorRef create(td::BufferSlice candidate_bytes, std::string reason) {
    return td::make_ref<RejectedCandidate>(std::move(candidate_bytes), std::move(reason));
  }

  RejectedCandidate(td::BufferSlice candidate_bytes, std::string reason)
      : candidate_bytes_(std::move(candidate_bytes)), reason_(std::move(reason)) {
  }

 private:
  td::BufferSlice candidate_bytes_;
  std::string reason_;
};

}  // namespace tos::validator::consensus::simplex
