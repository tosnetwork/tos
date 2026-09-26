/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#pragma once

#include <variant>

#include "consensus/misbehavior.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "keyring/keyring.hpp"
#include "overlay/overlays.h"
#include "quic/quic-sender.h"
#include "rldp2/rldp.h"
#include "td/actor/BusRuntime.h"
#include "td/db/KeyValueAsync.h"
#include "tos/tos-types.h"

#include "chain-state.h"
#include "manager-facade.h"
#include "types.h"

namespace tos::validator::consensus {

struct Start {
  ChainStateRef state;

  std::string contents_to_string() const;
};

using StartEvent = std::shared_ptr<const Start>;

struct StopRequested {};

// Finality has fallen far enough behind that this group must stop getting further ahead of
// it, or has caught up again.
//
// Consensus does not wait for a certificate to be converted: the pool advances the round the
// moment a quorum finalizes a slot. That is right while conversion keeps up, and it is how
// an agreed certificate that cannot be converted turns into an unbounded problem -- every
// later slot adds another certificate the resolver must hold, with its own retry, while the
// one at the front never completes. Certificates are never dropped to make room, so the
// group stops producing instead, and starts again when the backlog clears.
//
// The condition is reversible, and the event says which way it went.
struct FinalizationBacklog {
  bool over_limit;
  size_t pending;

  std::string contents_to_string() const;
};

struct FinalizeBlock {
  using ReturnType = td::Unit;

  CandidateRef candidate;
  td::Ref<block::BlockSignatureSet> signatures;

  std::string contents_to_string() const;
};

struct OurLeaderWindowStarted {
  ParentId base;
  ChainStateRef state;
  td::uint32 start_slot;
  td::uint32 end_slot;
  td::Timestamp start_time;

  std::string contents_to_string() const;
};

struct CandidateGenerated {
  CandidateRef candidate;
  std::optional<adnl::AdnlNodeIdShort> collator_id;

  std::string contents_to_string() const;
};

// The only guarantee is that the candidate has a valid signature from `candidate->leader`.
struct CandidateReceived {
  CandidateRef candidate;

  std::string contents_to_string() const;
};

struct ValidationRequest {
  using ReturnType = ValidateCandidateResult;

  ChainStateRef state;
  CandidateRef candidate;

  std::string contents_to_string() const;
  static std::string response_to_string(const ReturnType&);
};

struct IncomingProtocolMessage {
  using LogToDebug = std::true_type;

  std::optional<PeerValidatorId> source_validator;
  adnl::AdnlNodeIdShort source;
  ProtocolMessage message;

  std::string contents_to_string() const;
};

struct OutgoingProtocolMessage {
  using LogToDebug = std::true_type;

  struct BroadcastToAll {};
  struct BroadcastToValidators {};
  struct BroadcastToRandom {
    size_t count;
  };

  using Recipient = std::variant<BroadcastToAll, BroadcastToValidators, BroadcastToRandom>;

  Recipient recipient;
  ProtocolMessage message;

  std::string contents_to_string() const;
};

struct IncomingOverlayRequest {
  using LogToDebug = std::true_type;
  using ReturnType = ProtocolMessage;

  std::optional<PeerValidatorId> source_validator;
  adnl::AdnlNodeIdShort source;
  ProtocolMessage request;

  std::string contents_to_string() const;
  static std::string response_to_string(const ReturnType&);
};

struct OutgoingOverlayRequest {
  using LogToDebug = std::true_type;
  using ReturnType = ProtocolMessage;

  std::optional<adnl::AdnlNodeIdShort> destination;
  td::Timestamp timeout;
  ProtocolMessage request;

  std::string contents_to_string() const;
  static std::string response_to_string(const ReturnType&);
};

struct BlockFinalizedInMasterchain {
  BlockIdExt block;

  std::string contents_to_string() const;
};

struct MisbehaviorReport {
  PeerValidatorId id;
  MisbehaviorRef proof;

  std::string contents_to_string() const;
};

struct TraceEvent {
  std::unique_ptr<const stats::Event> event;

  std::string contents_to_string() const;
};

struct NoncriticalParamsUpdated {
  NewConsensusConfig::NoncriticalParams params;

  std::string contents_to_string() const;
};

struct PrecheckCandidateBroadcast {
  using ReturnType = td::Unit;

  td::uint32 slot;
  td::Bits256 broadcast_id;
  bool signature_checked;

  std::string contents_to_string() const;
};

class Db {
 public:
  virtual ~Db() = default;

  // Note: `get` and `get_by_prefix` use db snapshot from the start
  // `set` waits for syncing data to disk
  virtual std::optional<td::BufferSlice> get(td::Slice key) const = 0;
  virtual std::vector<std::pair<td::BufferSlice, td::BufferSlice>> get_by_prefix(td::uint32 prefix) const = 0;
  // Point lookup against the current database state. Unlike get(), this sees
  // successful writes performed by this process. Keep it asynchronous so the
  // RocksDB access remains serialized through KeyValueAsync.
  virtual td::actor::Task<std::optional<td::BufferSlice>> get_latest(td::BufferSlice key) const = 0;
  virtual td::actor::Task<> set(td::BufferSlice key, td::BufferSlice value) = 0;
  virtual td::actor::Task<> close() = 0;
};

// Bridge and restart-cut fixtures open the same durable consensus journal
// implementation. The caller owns the session-specific path.
std::unique_ptr<Db> open_rocksdb_consensus_db(std::string path);

class Bus : public td::actor::Bus {
 public:
  using Events =
      td::TypeList<Start, StopRequested, FinalizeBlock, OurLeaderWindowStarted, CandidateGenerated, CandidateReceived,
                   ValidationRequest, IncomingProtocolMessage, OutgoingProtocolMessage, IncomingOverlayRequest,
                   OutgoingOverlayRequest, BlockFinalizedInMasterchain, MisbehaviorReport, TraceEvent,
                   NoncriticalParamsUpdated, PrecheckCandidateBroadcast, FinalizationBacklog>;

  Bus() = default;
  ~Bus() override {
    db = {};
    stop_promise.set_value(td::Unit());
  }

  bool is_validator() const {
    return local_id.has_value();
  }

  ValidatorSessionId session_id;

  ShardIdFull shard;
  td::actor::ActorId<ManagerFacade> manager;
  td::actor::ActorId<keyring::Keyring> keyring;
  // The post-quantum consensus signer for the local validator, if this node is one. It is
  // the exact key the set records for us (resolved by PqConsensusCustody::get_matching_store
  // at group creation), and is the only key consensus signs with — never the keyring.
  // Null for an observer, which produces nothing.
  std::shared_ptr<const tos::pq::ValidatorPQKeyStore> pq_signer;
  td::Ref<ValidatorManagerOptions> validator_opts;

  std::vector<PeerValidator> validator_set;
  ValidatorWeight total_weight;
  tos::CatchainSeqno cc_seqno;
  td::uint32 validator_set_hash;
  std::optional<PeerValidator> local_id;
  adnl::AdnlNodeIdShort local_adnl_id;
  std::vector<adnl::AdnlNodeIdShort> all_validators;

  NewConsensusConfig config;

  td::Ref<CollatorSchedule> collator_schedule;

  td::actor::ActorId<overlay::Overlays> overlays;
  td::actor::ActorId<adnl::AdnlSenderEx> adnl_sender;
  std::unique_ptr<Db> db;

  td::Promise<td::Unit> stop_promise;
};

using BusHandle = td::actor::BusHandle<Bus>;

struct BlockAccepter {
  static void register_in(td::actor::Runtime&);
};

struct BlockProducer {
  static void register_in(td::actor::Runtime&);
};

struct BlockSyncOverlay {
  static void register_in(td::actor::Runtime&);
};

struct CandidateBroadcastRelay {
  static void register_in(td::actor::Runtime&);
};

struct BlockValidator {
  static void register_in(td::actor::Runtime&);
};

struct PrivateOverlay {
  static void register_in(td::actor::Runtime&);
};

struct TraceCollector {
  static void register_in(td::actor::Runtime&);
};

struct MisbehaviorReporter {
  static void register_in(td::actor::Runtime&);
};

}  // namespace tos::validator::consensus
