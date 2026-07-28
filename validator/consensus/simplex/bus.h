/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include "consensus/bus.h"

#include "certificate.h"

namespace tos::validator::consensus::simplex {

struct BroadcastVote {
  using ReturnType = td::Unit;

  Vote vote;

  std::string contents_to_string() const;
};

struct NotarizationObserved {
  CandidateId id;
  NotarCertRef certificate;

  std::string contents_to_string() const;
};

struct FinalizationObserved {
  CandidateId id;
  FinalCertRef certificate;

  std::string contents_to_string() const;
};

struct LeaderWindowObserved {
  using ReturnType = td::Unit;

  td::uint32 start_slot;
  ParentId base;

  std::string contents_to_string() const;
};

struct WaitForParent {
  using ReturnType = std::optional<MisbehaviorRef>;

  CandidateRef candidate;

  std::string contents_to_string() const;
};

struct ResolveCandidate {
  struct Result {
    CandidateRef candidate;
    NotarCertRef notar;
  };

  using ReturnType = Result;

  CandidateId id;

  std::string contents_to_string() const;
};

// Purely local query answered from Pool's own in-memory slot state -- no
// network round-trip, no candidate resolution. Lets StateResolver check
// whether a slot has already been skip-certified (and, if so, which real
// ancestor to build on top of) before ever attempting ResolveCandidate,
// which has nothing to find for a slot that timed out without any leader
// ever broadcasting so much as an empty-candidate placeholder.
struct QuerySlotSkipped {
  using ReturnType = std::optional<ParentId>;

  td::uint32 slot;

  std::string contents_to_string() const;
};

struct StoreCandidate {
  using ReturnType = td::Unit;

  CandidateRef candidate;
  std::string contents_to_string() const;
};

struct ResolveState {
  struct Result {
    ChainStateRef state;
    std::optional<double> gen_utime_exact = std::nullopt;
  };

  using ReturnType = Result;

  ParentId id;

  std::string contents_to_string() const;
  static std::string response_to_string(const ReturnType&);
};

struct SaveCertificate {
  using ReturnType = td::Unit;

  CertificateRef<Vote> cert;

  std::string contents_to_string() const;
};

// Litequery: snapshot of the current round for the lite server.
struct QueryValidatorGroupInfo {
  struct CandidateWeight {
    CandidateId id;
    ValidatorWeight notarize_weight;  // "approved" in liteServer terms
    ValidatorWeight finalize_weight;  // "signed" in liteServer terms
    // Present when the candidate data was locally observed.
    std::optional<CandidateRef> candidate;
  };

  struct Result {
    td::uint32 current_slot;
    ParentId last_finalized_block;
    std::vector<CandidateWeight> candidates;
  };

  using ReturnType = Result;

  std::string contents_to_string() const;
};

class Bus : public consensus::Bus {
 public:
  using Parent = consensus::Bus;
  using Events = td::TypeList<BroadcastVote, NotarizationObserved, FinalizationObserved, LeaderWindowObserved,
                              WaitForParent, ResolveCandidate, StoreCandidate, ResolveState, SaveCertificate,
                              QueryValidatorGroupInfo, QuerySlotSkipped>;

  Bus() = default;

  std::vector<CertificateRef<Vote>> bootstrap_certificates;
  std::vector<Vote> bootstrap_votes;

  td::uint32 first_nonannounced_window = 0;
};

using BusHandle = td::actor::BusHandle<Bus>;

struct Pool {
  static void register_in(td::actor::Runtime&);
};

struct Consensus {
  static void register_in(td::actor::Runtime&);
};

struct CandidateResolver {
  static void register_in(td::actor::Runtime&);
};

struct StateResolver {
  static void register_in(td::actor::Runtime&);
};

struct MetricCollector {
  static void register_in(td::actor::Runtime&);
};

struct Db {
  static void register_in(td::actor::Runtime&);
};

struct DefaultCollatorSchedule {
  static void provide_for(td::actor::Runtime&);
};

}  // namespace tos::validator::consensus::simplex
