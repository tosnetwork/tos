/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "bus.h"
#include "finalized-slot-dedup.h"

namespace tos::validator::consensus::simplex {

namespace tl {

using db_key_vote = tos_api::consensus_simplex_db_key_vote;
using db_key_voteRef = tl_object_ptr<db_key_vote>;

using db_ourVoteIntent = tos_api::consensus_simplex_db_ourVoteIntent;
using db_ourVoteIntentRef = tl_object_ptr<db_ourVoteIntent>;

using db_ourSignedVote = tos_api::consensus_simplex_db_ourSignedVote;
using db_ourSignedVoteRef = tl_object_ptr<db_ourSignedVote>;

using db_cert = tos_api::consensus_simplex_db_cert;
using db_certRef = tl_object_ptr<db_cert>;

using db_Vote = tos_api::consensus_simplex_db_Vote;
using db_VoteRef = tl_object_ptr<db_Vote>;

using db_key_poolState = tos_api::consensus_simplex_db_key_poolState;
using db_key_poolStateRef = tl_object_ptr<db_key_poolState>;

using db_poolState = tos_api::consensus_simplex_db_poolState;
using db_poolStateRef = tl_object_ptr<db_poolState>;

using db_key_candidateResolver_notarCert = tos_api::consensus_simplex_db_key_candidateResolver_notarCert;
using db_key_candidateResolver_notarCertRef = tl_object_ptr<db_key_candidateResolver_notarCert>;

using db_candidateResolver_notarCert = tos_api::consensus_simplex_db_candidateResolver_notarCert;
using db_candidateResolver_notarCertRef = tl_object_ptr<db_candidateResolver_notarCert>;

}  // namespace tl

namespace {

// What a stored record claims to be, readable even when the rest of it -- or the key it is
// filed under -- cannot be parsed, as long as the record is still enumerated at all. The
// leading constructor tag is the last thing to go, and it is enough to tell a record of
// this node's own vote, which must never be silently dropped, from a cached certificate,
// which can be obtained again.
bool claims_to_be_our_vote(td::Slice serialized) {
  td::uint32 tag = 0;
  if (serialized.size() < sizeof(tag)) {
    return false;
  }
  std::memcpy(&tag, serialized.data(), sizeof(tag));
  return tag == tl::db_ourVoteIntent::ID || tag == tl::db_ourSignedVote::ID;
}

class DbImpl : public td::actor::SpawnsWith<Bus>, public td::actor::ConnectsTo<Bus> {
 public:
  TOS_RUNTIME_DEFINE_EVENT_HANDLER();

  DbImpl(Bus& bus) {
    init_pool_state(bus);
    init_votes(bus);
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(BusHandle, std::shared_ptr<const FinalizationObserved> event) {
    saved_vote_hash_evictions_ += saved_vote_hashes_.prune_through(event->id.slot);
  }

  void start_up() override {
    if (td::memory_tracker_enabled()) {
      alarm_timestamp() = td::Timestamp::in(60.0);
    }
  }

  void alarm() override {
    LOG(WARNING) << "MEMORY_DIAGNOSTICS simplex-db saved_vote_hashes=" << saved_vote_hashes_.size()
                 << " active_slots=" << saved_vote_hashes_.slot_count() << " evictions=" << saved_vote_hash_evictions_;
    alarm_timestamp() = td::Timestamp::in(60.0);
  }

  // Commit the decision to cast this vote, before anything is signed. Returns the journal
  // sequence number the record was written under; the signed record replaces it under the
  // same key and carries the same number.
  //
  // A failed write is consensus-significant and is reported, not swallowed: the caller must
  // not sign a vote whose decision is not durable. This is deliberately unlike the other
  // writes below, where losing a record costs nothing a restart cannot rebuild.
  template <>
  td::actor::Task<td::int64> process(BusHandle, std::shared_ptr<PersistOwnVoteIntent> event) {
    auto referenced_slot = event->vote.referenced_slot();
    auto vote = event->vote.to_tl();
    auto hash = sha256_bits256(serialize_tl_object(vote, true));

    if (!saved_vote_hashes_.insert(referenced_slot, hash)) {
      co_return td::Status::Error(cancelled, "Vote was already casted");
    }

    const auto seqno = next_seqno_++;
    auto key = create_serialize_tl_object<tl::db_key_vote>(hash);
    auto value = create_serialize_tl_object<tl::db_ourVoteIntent>(std::move(vote), seqno);

    auto written = co_await owning_bus()->db->set(std::move(key), std::move(value)).wrap();
    if (written.is_error()) {
      co_return written.move_as_error();
    }
    co_return seqno;
  }

  // Commit the exact signature bytes, replacing the intent under the same key in one write.
  // Until this returns the vote may not be applied locally, put into a certificate or sent,
  // so a signature lost to a crash here was never observable and may be produced again.
  template <>
  td::actor::Task<> process(BusHandle, std::shared_ptr<PersistOwnSignedVote> event) {
    auto vote = event->vote.to_tl();
    auto hash = sha256_bits256(serialize_tl_object(vote, true));

    auto key = create_serialize_tl_object<tl::db_key_vote>(hash);
    auto value =
        create_serialize_tl_object<tl::db_ourSignedVote>(std::move(vote), event->seqno, std::move(event->signature));

    auto written = co_await owning_bus()->db->set(std::move(key), std::move(value)).wrap();
    if (written.is_error()) {
      co_return written.move_as_error();
    }
    co_return td::Unit{};
  }

  template <>
  td::actor::Task<> process(BusHandle, std::shared_ptr<SaveCertificate> event) {
    auto referenced_slot = event->cert->vote.referenced_slot();
    auto cert = event->cert->to_tl();
    auto hash = sha256_bits256(serialize_tl_object(cert, true));

    if (!saved_vote_hashes_.insert(referenced_slot, hash)) {
      co_return td::Status::Error(cancelled, "Certificate was already saved");
    }

    auto key = create_serialize_tl_object<tl::db_key_vote>(hash);
    auto value = create_serialize_tl_object<tl::db_cert>(std::move(cert));
    auto result = co_await owning_bus()->db->set(std::move(key), std::move(value)).wrap();
    CHECK(result.is_ok() || result.error().code() == cancelled);  // See above.
    co_return result;
  }

  template <>
  td::actor::Task<> process(BusHandle, std::shared_ptr<LeaderWindowObserved> event) {
    auto window = event->start_slot / owning_bus()->config.slots_per_leader_window;
    CHECK(first_nonannounced_window_ <= window);
    first_nonannounced_window_ = window + 1;

    auto value = create_serialize_tl_object<tl::db_poolState>(first_nonannounced_window_);
    auto result = co_await owning_bus()->db->set(pool_state_key.clone(), std::move(value)).wrap();
    CHECK(result.is_ok() || result.error().code() == cancelled);  // See above.
    co_return result;
  }

 private:
  void init_pool_state(Bus& bus) {
    auto pool_state_str = bus.db->get(pool_state_key);
    if (pool_state_str.has_value()) {
      auto pool_state_result = fetch_tl_object<tl::db_poolState>(*pool_state_str, true);
      if (pool_state_result.is_error()) {
        LOG(WARNING) << "Simplex db: ignoring malformed pool state: " << pool_state_result.error();
        return;
      }
      auto pool_state = pool_state_result.move_as_ok();
      first_nonannounced_window_ = pool_state->first_nonannounced_window_;
      bus.first_nonannounced_window = first_nonannounced_window_;
    }
  }

  void init_votes(Bus& bus) {
    struct OurVote {
      td::int64 seqno;
      Vote vote;
      td::BufferSlice signature;  // empty: the intent was durable, the signature was not

      std::strong_ordering operator<=>(const OurVote& other) const {
        return seqno <=> other.seqno;
      }
    };

    std::vector<OurVote> our_votes;
    std::vector<CertificateRef<Vote>> certs;

    // What this enumeration can and cannot see, stated because the checks below are only
    // as complete as it is.
    //
    // Every record whose key still carries this constructor prefix is returned, and each
    // one is then classified: a damaged key, a damaged value, or a key that does not bind
    // its value all stop the session when the record is one of this node's own votes. The
    // shape outside reach is a record whose four-byte prefix itself is damaged. It is not
    // in the range, so nothing here is asked about it, and a vote that vanishes that way
    // leaves no trace to fail on -- it is indistinguishable from a vote never cast.
    //
    // Two things bound that. The store computes a checksum per block, so damage to a key
    // that was written correctly surfaces as a read error rather than as different bytes;
    // and the reader turns a read error into an abort instead of a shorter result, so the
    // records this loop sees are all the records there are. What remains is damage
    // introduced above the storage layer -- a bug writing the wrong key -- which no check
    // inside this function can detect. Closing it needs an independent record of what the
    // journal should contain, and that is a design decision, not a local fix.
    auto votes = bus.db->get_by_prefix(tl::db_key_vote::ID);

    for (auto& [key_str, value_str] : votes) {
      // Round 142 MEDIUM fix: validate that the parsed value's
      // inner-tl-hash matches the key's vote_hash_ before
      // replaying into the consensus pool.  Pre-fix init_votes
      // trusted the key→value pairing implicitly and used
      // .move_as_ok() on the parsed cert; a corrupted RocksDB
      // record where db_key_vote(hash_A) → db_cert(certB) (with
      // sha256(certB_tl) == hash_B != hash_A) replayed both the
      // saved_votes hash_A and the cert payload for B, and
      // Pool::start_up()'s CertificateBundle::store() then
      // tripped CHECK(rc) at pool.cpp:908 on the duplicate.  Now
      // we recompute the inner hash and skip-with-warning on
      // mismatch.  This is the same integrity-gate class as
      // round 136 (CellLoader::load) and round 140
      // (candidate-resolver DB resume).
      auto key_r = fetch_tl_object<tl::db_key_vote>(key_str, true);
      if (key_r.is_error()) {
        // The record can still say whose it is. A damaged key under which one of this
        // node's own votes is filed loses that vote from recovery exactly as a damaged
        // value would, so it stops the session rather than being skipped.
        if (claims_to_be_our_vote(value_str)) {
          bus.vote_journal_failure = PSTRING() << "a journalled vote is filed under an unreadable key: "
                                               << key_r.error().message();
          LOG(ERROR) << "Simplex db init_votes: " << bus.vote_journal_failure;
          continue;
        }
        LOG(WARNING) << "Simplex db init_votes: malformed vote key: " << key_r.error().message();
        continue;
      }
      auto key = key_r.move_as_ok();

      auto value_r = fetch_tl_object<tl::db_Vote>(value_str, true);
      if (value_r.is_error()) {
        // A damaged record of our own vote is a reason to stop rather than to decide that
        // vote again; a damaged certificate is peers' data and can be obtained again.
        if (claims_to_be_our_vote(value_str)) {
          bus.vote_journal_failure = PSTRING() << "a journalled vote under key 0x" << key->vote_hash_.to_hex()
                                               << " cannot be read: " << value_r.error().message();
          LOG(ERROR) << "Simplex db init_votes: " << bus.vote_journal_failure;
          continue;
        }
        LOG(WARNING) << "Simplex db init_votes: malformed vote value "
                        "for key vote_hash 0x"
                     << key->vote_hash_.to_hex() << ": " << value_r.error().message();
        continue;
      }
      auto value = value_r.move_as_ok();

      bool hash_ok = false;
      Bits256 actual_hash;
      auto intent_fn = [&](tl::db_ourVoteIntent& vote) {
        if (vote.vote_) {
          actual_hash = sha256_bits256(serialize_tl_object(vote.vote_, true));
          hash_ok = (actual_hash == key->vote_hash_);
        }
      };
      auto signed_fn = [&](tl::db_ourSignedVote& vote) {
        if (vote.vote_) {
          actual_hash = sha256_bits256(serialize_tl_object(vote.vote_, true));
          hash_ok = (actual_hash == key->vote_hash_);
        }
      };
      auto cert_fn = [&](tl::db_cert& vote) {
        if (vote.cert_) {
          actual_hash = sha256_bits256(serialize_tl_object(vote.cert_, true));
          hash_ok = (actual_hash == key->vote_hash_);
        }
      };
      bool is_own_vote = false;
      auto own_vote_fn = [&](auto& record) {
        using Record = std::decay_t<decltype(record)>;
        is_own_vote = std::same_as<Record, tl::db_ourVoteIntent> || std::same_as<Record, tl::db_ourSignedVote>;
      };
      tos_api::downcast_call(*value, td::overloaded(intent_fn, signed_fn, cert_fn));
      tos_api::downcast_call(*value, own_vote_fn);
      if (!hash_ok) {
        if (is_own_vote) {
          // A record of this node's own vote whose key does not bind its contents cannot be
          // skipped. The skipped vote is then absent from the dedup set, so the node would
          // decide it afresh and sign it again -- and the record may hold the signature it
          // already emitted. Verifying the signature would not catch this: the signature
          // inside can be perfectly valid for the vote inside. Storage corruption here is a
          // reason to stop, not to re-sign.
          bus.vote_journal_failure = PSTRING() << "a journalled vote is stored under key 0x" << key->vote_hash_.to_hex()
                                               << " but its contents hash to 0x" << actual_hash.to_hex();
          LOG(ERROR) << "Simplex db init_votes: " << bus.vote_journal_failure;
          continue;
        }
        // A certificate is peers' signatures, which this node can be handed again. Skipping
        // one costs availability of cached evidence, never the integrity of what this node
        // has itself attested, so it stays a warning.
        LOG(WARNING) << "Simplex db init_votes: hash binding error for "
                        "key vote_hash 0x"
                     << key->vote_hash_.to_hex() << " (value parses but inner hash is 0x" << actual_hash.to_hex()
                     << "); skipping";
        continue;
      }

      bool value_valid = true;
      auto remember_own_vote = [&](Vote parsed_vote, td::int64 seqno, td::BufferSlice signature) {
        if (!saved_vote_hashes_.insert(parsed_vote.referenced_slot(), key->vote_hash_)) {
          ++saved_vote_hash_evictions_;
        }
        our_votes.push_back(OurVote{seqno, std::move(parsed_vote), std::move(signature)});
      };
      auto append_intent = [&](tl::db_ourVoteIntent& vote) {
        remember_own_vote(Vote::from_tl(*vote.vote_), vote.seqno_, td::BufferSlice());
      };
      auto append_signed = [&](tl::db_ourSignedVote& vote) {
        auto parsed_vote = Vote::from_tl(*vote.vote_);
        // These bytes may already be inside a certificate a peer holds, so they are the
        // only signature this node may present for this vote. If they do not verify under
        // the consensus key the set records for us, the node must not paper over it by
        // signing again: refuse to participate in this session and say why.
        if (!bus.is_validator() ||
            !bus.local_id->check_signature(bus.session_id, serialize_tl_object(vote.vote_, true), vote.signature_)) {
          bus.vote_journal_failure = PSTRING() << "the journalled signature for " << parsed_vote
                                               << " does not verify under this node's consensus key";
          LOG(ERROR) << "Simplex db init_votes: " << bus.vote_journal_failure;
          value_valid = false;
          return;
        }
        remember_own_vote(std::move(parsed_vote), vote.seqno_, std::move(vote.signature_));
      };
      auto append_cert = [&](tl::db_cert& vote) {
        auto cert_result = Certificate<Vote>::from_tl(std::move(*vote.cert_), bus);
        if (cert_result.is_error()) {
          LOG(WARNING) << "Simplex db init_votes: invalid certificate for key vote_hash 0x" << key->vote_hash_.to_hex()
                       << ": " << cert_result.error();
          value_valid = false;
          return;
        }
        auto cert = cert_result.move_as_ok();
        auto referenced_slot = cert->vote.referenced_slot();
        if (!saved_vote_hashes_.insert(referenced_slot, key->vote_hash_)) {
          ++saved_vote_hash_evictions_;
        }
        if (std::holds_alternative<FinalizeVote>(cert->vote.vote)) {
          saved_vote_hash_evictions_ += saved_vote_hashes_.prune_through(referenced_slot);
        }
        certs.push_back(std::move(cert));
      };
      tos_api::downcast_call(*value, td::overloaded(append_intent, append_signed, append_cert));
      if (!value_valid) {
        continue;
      }
    }
    std::sort(our_votes.begin(), our_votes.end());
    if (!our_votes.empty()) {
      next_seqno_ = our_votes.back().seqno + 1;
    }

    bus.bootstrap_certificates = std::move(certs);
    bus.bootstrap_votes.reserve(our_votes.size());
    for (auto& v : our_votes) {
      bus.bootstrap_votes.push_back(BootstrapVote{std::move(v.vote), v.seqno, std::move(v.signature)});
    }
  }

  const td::BufferSlice pool_state_key = create_serialize_tl_object<tl::db_key_poolState>();
  FinalizedSlotDedup<Bits256> saved_vote_hashes_;
  size_t saved_vote_hash_evictions_ = 0;
  td::uint32 first_nonannounced_window_ = 0;
  td::int64 next_seqno_ = 0;
};

}  // namespace

void Db::register_in(td::actor::Runtime& runtime) {
  runtime.register_actor<DbImpl>("SimplexDb");
}

}  // namespace tos::validator::consensus::simplex
