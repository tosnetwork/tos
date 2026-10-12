/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <memory>
#include <vector>

#include "overlay/overlays.h"
#include "tos/tos-types.h"
#include "validator/startup-catchup.h"
#include "validator/validator.h"

namespace tos {

namespace validator {

namespace fullnode {

// Startup catch-up discovery: one probe of one named peer for a verified successor
// of the exact masterchain block `prev`.
//
// It asks the peer for the next full block (downloadNextBlockFull), bounded in size
// and in time by the discovery window, decodes it, and hands its proof to the
// manager's verification entry, which checks it against the exact local tip. Only a
// proof that passes there is progress. The block is never stored or applied.
// Answers are classified as verified, an explicit empty answer, inconclusive (any
// timeout, transport error, malformed answer, proof link, hash mismatch, wrong seqno
// or failed proof), or "the local tip moved".
//
// The transport, the predecessor-state wait and the verification go through
// protected virtual methods, so the classification can be exercised with
// substituted peers.
class ProbeNextMasterchainBlock : public td::actor::Actor {
 public:
  ProbeNextMasterchainBlock(adnl::AdnlNodeIdShort local_id, overlay::OverlayIdShort overlay_id, BlockIdExt prev,
                            adnl::AdnlNodeIdShort peer, td::Timestamp deadline,
                            td::actor::ActorId<ValidatorManagerInterface> manager,
                            td::actor::ActorId<adnl::AdnlSenderInterface> rldp,
                            td::actor::ActorId<overlay::Overlays> overlays,
                            td::Promise<startup_catchup::ProbeAnswer> promise);

  void start_up() override;
  td::actor::Task<startup_catchup::ProbeAnswer> run();

  // The largest answer accepted from a peer.
  static size_t max_answer_size();

 protected:
  virtual double clock_now() const;
  virtual void send_query(td::BufferSlice query, size_t max_size, td::Timestamp timeout,
                          td::Promise<td::BufferSlice> promise);
  virtual void wait_prev_state(td::Timestamp timeout, td::Promise<td::Ref<ShardState>> promise);
  virtual void verify_successor(BlockIdExt next, td::BufferSlice proof,
                                td::Promise<startup_catchup::SuccessorVerdict> promise);

  const BlockIdExt& prev() const {
    return prev_;
  }
  td::Timestamp deadline() const {
    return deadline_;
  }

 private:
  // What is left of the window, capped at `cap_seconds`; nothing when none is left.
  std::optional<td::Timestamp> bounded_timeout(double cap_seconds) const;

  adnl::AdnlNodeIdShort local_id_;
  overlay::OverlayIdShort overlay_id_;
  BlockIdExt prev_;
  adnl::AdnlNodeIdShort peer_;
  td::Timestamp deadline_;
  td::actor::ActorId<ValidatorManagerInterface> manager_;
  td::actor::ActorId<adnl::AdnlSenderInterface> rldp_;
  td::actor::ActorId<overlay::Overlays> overlays_;
  td::Promise<startup_catchup::ProbeAnswer> promise_;
};

// One discovery round about one exact local tip: draws distinct peers, probes them in
// parallel, retries peer selection while fewer than K were probed, and reports the
// round's decision (startup_catchup::DiscoveryRound) once, at the first verified
// successor, at K distinct explicit negatives, when the tip moved, or at the
// deadline. Answers arriving after the decision are dropped with the actor.
class StartupDiscoveryRound : public td::actor::Actor {
 public:
  class Transport {
   public:
    virtual ~Transport() = default;
    virtual void get_peers(td::uint32 count, td::Promise<std::vector<adnl::AdnlNodeIdShort>> promise) = 0;
    virtual void probe(adnl::AdnlNodeIdShort peer, BlockIdExt prev, td::Timestamp deadline,
                       td::Promise<startup_catchup::ProbeAnswer> promise) = 0;
  };

  StartupDiscoveryRound(BlockIdExt prev, td::Timestamp deadline, td::uint32 probe_budget,
                        std::unique_ptr<Transport> transport, td::Promise<startup_catchup::RoundResult> promise);

  void start_up() override;
  void alarm() override;

  void got_peers(td::Result<std::vector<adnl::AdnlNodeIdShort>> R);
  void got_answer(adnl::AdnlNodeIdShort peer, td::Result<startup_catchup::ProbeAnswer> R);

 private:
  void request_peers();
  void arm();
  void maybe_decide();

  BlockIdExt prev_;
  td::Timestamp deadline_;
  std::unique_ptr<Transport> transport_;
  td::Promise<startup_catchup::RoundResult> promise_;
  startup_catchup::DiscoveryRound<adnl::AdnlNodeIdShort> round_;
  bool peers_requested_ = false;
  td::Timestamp next_reselect_;
};

}  // namespace fullnode

}  // namespace validator

}  // namespace tos
