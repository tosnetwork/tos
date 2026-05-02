/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

/*
 * MisbehaviorReporter — consensus bus subscriber
 *
 * Subscribes to MisbehaviorReport events published by the simplex consensus
 * layer (pool.cpp, consensus.cpp) and forwards each report toward the
 * masterchain so that the elector contract can slash the offending validator.
 *
 * Current forwarding path
 * -----------------------
 * 1. A structured LOG(ERROR) entry is written immediately so node operators
 *    can act without waiting for on-chain settlement.
 * 2. A minimal evidence cell is built and handed to
 *    ManagerFacade::send_misbehavior_report, which calls
 *    ValidatorManager::new_external_message_broadcast.  The external message
 *    enters the normal ext-message queue and is included in the next
 *    masterchain block.
 *
 * Evidence cell layout (TL-B, opcode 0xd1)
 * -----------------------------------------
 * The cell is intentionally small so that it fits in a single masterchain
 * block even if many validators misbehave simultaneously.  A future upgrade
 * will replace this with a full ValidatorComplaint cell once the elector
 * contract's slash handler is deployed.
 *
 *   simplex_misbehavior_report#d1
 *     validator_pubkey:bits256   -- offending validator's Ed25519 key hash
 *     session_id:bits256         -- consensus session that observed the fault
 *     kind:uint8                 -- see MisbehaviorKind enum below
 *     evidence_hash:bits256      -- SHA-256 of the raw proof bytes
 *   = SimplexMisbehaviorReport;
 *
 * TODO (on-chain slashing): once the elector contract exposes a
 * `report_simplex_misbehavior` method, replace the cell above with a full
 * `ValidatorComplaint` (block.tlb:877) and set the destination address to
 * config param #1 (elector address).  The `send_misbehavior_report` path in
 * ManagerFacadeImpl already routes the message through
 * `new_external_message_broadcast`, so only the cell builder here needs to
 * change.
 */

#include "bus.h"
#include "manager-facade.h"
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

// Build the evidence cell described in the module comment.
//
//   4 bytes  opcode  0xd1 00 00 00   (little-endian uint32 written as big-endian bits)
//  32 bytes  validator_pubkey
//  32 bytes  session_id
//   1 byte   kind
//  32 bytes  evidence_hash
// = 101 bytes = 808 bits — well within the 1023-bit cell limit.
td::BufferSlice build_evidence_cell(const PublicKeyHash& short_id, const ValidatorSessionId& session_id,
                                    MisbehaviorKind kind, const std::string& evidence_bytes) {
  td::uint8 buf[1 + 32 + 32 + 1 + 32];  // opcode(1) + pubkey(32) + session(32) + kind(1) + hash(32) = 99 bytes
  // Opcode 0xd1 (simplex misbehavior report)
  buf[0] = 0xd1;
  // validator short_id (pubkey hash, 32 bytes)
  auto key_slice = short_id.as_slice();
  CHECK(key_slice.size() == 32);
  std::memcpy(buf + 1, key_slice.data(), 32);
  // session_id (32 bytes)
  std::memcpy(buf + 33, session_id.as_slice().data(), 32);
  // kind (1 byte)
  buf[65] = static_cast<td::uint8>(kind);
  // evidence_hash: SHA-256 of the concatenated proof bytes
  td::uint8 hash[32];
  td::sha256(td::Slice(evidence_bytes), td::MutableSlice(hash, 32));
  std::memcpy(buf + 66, hash, 32);

  return td::BufferSlice(td::Slice(reinterpret_cast<const char*>(buf), sizeof(buf)));
}

class MisbehaviorReporterImpl : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  void start_up() override {
    auto& bus = *owning_bus();
    session_id_ = bus.session_id;
    manager_ = bus.manager;
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

    // Always emit a structured ERROR log so the node operator has an
    // auditable record even if the on-chain path is not yet deployed.
    LOG(ERROR) << "MISBEHAVIOR DETECTED"
               << " kind=" << kind_name(kind)
               << " validator=" << offender.short_id.bits256_value().to_hex()
               << " adnl=" << offender.adnl_id.bits256_value().to_hex()
               << " session=" << session_id_.to_hex()
               << " evidence_bytes=" << evidence_bytes.size();

    auto cell = build_evidence_cell(offender.short_id, session_id_, kind, evidence_bytes);
    td::actor::ask(manager_, &ManagerFacade::send_misbehavior_report, std::move(cell)).detach("MisbehaviorReporter::send");
  }

 private:
  ValidatorSessionId session_id_;
  td::actor::ActorId<ManagerFacade> manager_;
};

}  // namespace

void MisbehaviorReporter::register_in(td::actor::Runtime& runtime) {
  runtime.register_actor<MisbehaviorReporterImpl>("MisbehaviorReporter");
}

}  // namespace tos::validator::consensus
