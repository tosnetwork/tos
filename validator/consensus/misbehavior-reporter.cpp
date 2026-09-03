/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

/*
 * MisbehaviorReporter — consensus bus subscriber
 *
 * Subscribes to MisbehaviorReport events published by the simplex consensus
 * layer (pool.cpp, consensus.cpp) and records each report for operators.
 *
 * Current handling
 * ----------------
 * 1. A structured LOG(ERROR) entry is written immediately so node operators
 *    can act without waiting for on-chain settlement.
 *
 * Reports are deliberately not submitted as external messages.  The current
 * Misbehavior objects are local allegations: rejected candidates and malformed
 * broadcasts in particular do not carry the signed, replay-protected bytes an
 * on-chain verifier would need.  Sending a private binary envelope to the
 * external-message ingress only makes the BOC parser reject it and creates a
 * false impression that slashing evidence reached the chain.
 *
 * TODO (on-chain slashing): define a canonical evidence envelope only when a
 * consumer exists.  It must retain the signed protocol messages, bind them to
 * the chain and session, identify the destination contract, and include replay
 * protection.  Until then these records are telemetry, not proof.
 */

#include "bus.h"
#include "simplex/misbehavior.h"
#include "td/utils/crypto.h"

namespace tos::validator::consensus {

namespace {

// One-byte tag that identifies the class of misbehavior in the evidence cell.
enum class MisbehaviorKind : td::uint8 {
  conflicting_votes                = 0x01,
  conflicting_candidate_and_cert   = 0x02,
  slot_inversion_candidate         = 0x03,  // V-018
  conflicting_candidates           = 0x04,  // V-019
  rejected_candidate               = 0x05,  // V-020
  malformed_broadcast              = 0x06,  // V-025
  unknown                          = 0xff,
};

// Returns the kind tag and a concatenated byte string of all proof payloads.
// The byte string is hashed to produce `evidence_hash` in the cell.
std::pair<MisbehaviorKind, std::string> classify(const Misbehavior& proof) {
  using simplex::ConflictingVotes;
  using simplex::ConflictingCandidateAndCertificate;
  using simplex::SlotInversionCandidate;
  using simplex::ConflictingCandidates;
  using simplex::RejectedCandidate;
  using simplex::MalformedBroadcast;

  if (const auto* p = dynamic_cast<const ConflictingVotes*>(&proof)) {
    std::string ev;
    ev.append(p->vote1().begin(), p->vote1().size());
    ev.append(p->vote2().begin(), p->vote2().size());
    return {MisbehaviorKind::conflicting_votes, std::move(ev)};
  }
  if (dynamic_cast<const ConflictingCandidateAndCertificate*>(&proof)) {
    return {MisbehaviorKind::conflicting_candidate_and_cert, {}};
  }
  if (const auto* p = dynamic_cast<const SlotInversionCandidate*>(&proof)) {
    return {MisbehaviorKind::slot_inversion_candidate,
            std::string(p->candidate_bytes().begin(), p->candidate_bytes().size())};
  }
  if (const auto* p = dynamic_cast<const ConflictingCandidates*>(&proof)) {
    std::string ev;
    ev.append(p->candidate1_bytes().begin(), p->candidate1_bytes().size());
    ev.append(p->candidate2_bytes().begin(), p->candidate2_bytes().size());
    return {MisbehaviorKind::conflicting_candidates, std::move(ev)};
  }
  if (const auto* p = dynamic_cast<const RejectedCandidate*>(&proof)) {
    std::string ev;
    ev.append(p->candidate_bytes().begin(), p->candidate_bytes().size());
    ev.append(p->reason());
    return {MisbehaviorKind::rejected_candidate, std::move(ev)};
  }
  if (const auto* p = dynamic_cast<const MalformedBroadcast*>(&proof)) {
    std::string ev;
    ev.append(p->raw_bytes().begin(), p->raw_bytes().size());
    ev.append(p->error());
    return {MisbehaviorKind::malformed_broadcast, std::move(ev)};
  }
  return {MisbehaviorKind::unknown, {}};
}

static const char* kind_name(MisbehaviorKind k) {
  switch (k) {
    case MisbehaviorKind::conflicting_votes:              return "ConflictingVotes";
    case MisbehaviorKind::conflicting_candidate_and_cert: return "ConflictingCandidateAndCertificate";
    case MisbehaviorKind::slot_inversion_candidate:       return "SlotInversionCandidate(V-018)";
    case MisbehaviorKind::conflicting_candidates:         return "ConflictingCandidates(V-019)";
    case MisbehaviorKind::rejected_candidate:             return "RejectedCandidate(V-020)";
    case MisbehaviorKind::malformed_broadcast:            return "MalformedBroadcast(V-025)";
    default:                                              return "Unknown";
  }
}

class MisbehaviorReporterImpl : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  void start_up() override {
    auto& bus = *owning_bus();
    session_id_ = bus.session_id;
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(BusHandle bus_handle, std::shared_ptr<const MisbehaviorReport> event) {
    auto& bus = *bus_handle;

    if (event->id.value() >= bus.validator_set.size()) {
      LOG(ERROR) << "MisbehaviorReporter: invalid validator index " << event->id.value()
                 << " (validator_set size=" << bus.validator_set.size() << "), dropping report";
      return;
    }
    const PeerValidator& offender = bus.validator_set[event->id.value()];

    auto [kind, evidence_bytes] = classify(*event->proof);

    auto fingerprint = td::sha256_bits256(td::Slice(evidence_bytes));

    // This is an allegation fingerprint for correlation between validator
    // logs.  It is not independently verifiable slashing evidence.
    LOG(ERROR) << "MISBEHAVIOR DETECTED"
               << " kind=" << kind_name(kind)
               << " validator=" << offender.short_id.bits256_value().to_hex()
               << " adnl=" << offender.adnl_id.bits256_value().to_hex()
               << " session=" << session_id_.to_hex()
               << " allegation_bytes=" << evidence_bytes.size()
               << " allegation_fingerprint=" << fingerprint.to_hex();
  }

 private:
  ValidatorSessionId session_id_;
};

}  // namespace

void MisbehaviorReporter::register_in(td::actor::Runtime& runtime) {
  runtime.register_actor<MisbehaviorReporterImpl>("MisbehaviorReporter");
}

}  // namespace tos::validator::consensus
