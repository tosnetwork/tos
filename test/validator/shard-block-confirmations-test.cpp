/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Drives the store of shard-block confirmations sent by trusted verifiers. A
// trusted verifier may still not make this node retain unbounded state: far
// future blocks are deferred within a bounded queue, peer-created entries are
// capped per peer and globally by count and bytes, and entries are pruned as
// the masterchain registers progress. Local waits are never refused, because a
// wait that found no entry would complete as though nothing were required.
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "validator/shard-block-confirmations.h"
#include "validator/shard-block-subscription.h"

namespace {

using tos::BlockIdExt;
using tos::BlockSeqno;
using tos::validator::ShardBlockConfirmationLimits;
using tos::validator::ShardBlockConfirmations;
using tos::validator::ShardBlockVerifierConfig;
using Result = ShardBlockConfirmations::ConfirmResult;
using Peer = ShardBlockConfirmations::Peer;

[[noreturn]] void fail(const std::string &message) {
  std::cerr << "SHARD_BLOCK_CONFIRMATIONS_FAILURE: " << message << '\n';
  std::exit(1);
}

void require(bool condition, const std::string &message) {
  if (!condition) {
    fail(message);
  }
}

td::Bits256 fill(unsigned char value) {
  td::Bits256 result;
  std::memset(result.data(), value, result.as_slice().size());
  return result;
}

Peer peer(unsigned char value) {
  return Peer{fill(value)};
}

BlockIdExt block_at(BlockSeqno seqno, unsigned char variant = 0) {
  return BlockIdExt{tos::basechainId, tos::shardIdAll, seqno, fill(variant),
                    fill(static_cast<unsigned char>(~variant))};
}

const Peer kA = peer(0xa1);
const Peer kB = peer(0xb2);
const Peer kC = peer(0xc3);
const Peer kStranger = peer(0x55);

td::Ref<ShardBlockVerifierConfig> config(std::vector<Peer> trusted, td::uint32 required) {
  auto result = td::Ref<ShardBlockVerifierConfig>(true);
  result.write().shards.push_back(ShardBlockVerifierConfig::Shard{tos::ShardIdFull{tos::basechainId, tos::shardIdAll},
                                                                  std::move(trusted), required});
  return result;
}

// The masterchain view: the registered top seqno of the basechain shard.
struct Masterchain {
  std::optional<BlockSeqno> top = 100;
  ShardBlockConfirmations::RegisteredSeqno view() {
    return [this](const BlockIdExt &) { return top; };
  }
};

struct Waiter {
  bool done = false;
  td::Promise<td::Unit> promise() {
    return [this](td::Result<td::Unit> result) {
      require(result.is_ok(), "a wait completes successfully");
      done = true;
    };
  }
};

}  // namespace

int main() {
  // Happy path: two of three trusted verifiers confirm; the waiter completes
  // and the entry is pruned once the masterchain registers the block.
  {
    Masterchain mc;
    ShardBlockConfirmations store(mc.view());
    store.set_config(config({kA, kB, kC}, 2));
    Waiter waiter;
    store.wait({block_at(101)}, waiter.promise());
    require(!waiter.done, "an unconfirmed block is waited for");
    require(store.confirm(kA, block_at(101)) == Result::Accepted, "the first confirmation is counted");
    require(store.confirm(kA, block_at(101)) == Result::Duplicate, "a repeated confirmation is a duplicate");
    require(store.confirm(kStranger, block_at(101)) == Result::UnknownSource, "an untrusted source is refused");
    require(!waiter.done, "one confirmation is not enough");
    require(store.confirm(kB, block_at(101)) == Result::Confirmed, "the second confirmation completes it");
    require(waiter.done, "the waiter completes on confirmation");
    require(store.peer_entries() == 0, "an entry a local wait created is not charged to any peer");
    mc.top = 101;
    store.prune_registered();
    require(store.size() == 0, "the masterchain registering the block prunes it");
  }

  // Lookahead: a confirmation far beyond the registered top creates no entry;
  // it is deferred and counted once the masterchain's progress brings it
  // within reach. A block at the edge of the lookahead is accepted directly.
  {
    Masterchain mc;
    ShardBlockConfirmations store(mc.view());
    store.set_config(config({kA, kB}, 2));
    const BlockSeqno lookahead = store.limits().max_lookahead;
    require(store.confirm(kA, block_at(100 + lookahead)) == Result::Accepted, "a block at the lookahead edge counts");
    require(store.confirm(kA, block_at(100 + lookahead + 1)) == Result::Deferred, "a block past it is deferred");
    require(!store.contains(block_at(100 + lookahead + 1)), "a deferred confirmation creates no entry");
    require(store.deferred(kA) == 1, "the deferral is held for its peer");
    require(store.confirm(kA, block_at(100 + lookahead + 1)) == Result::Deferred && store.deferred(kA) == 1,
            "a repeated deferral is held once");
    mc.top = 101;
    store.prune_registered();
    require(store.contains(block_at(100 + lookahead + 1)), "masterchain progress admits the deferred confirmation");
    require(store.deferred() == 0, "an admitted deferral leaves the queue");
    require(store.confirm(kB, block_at(100 + lookahead + 1)) == Result::Confirmed,
            "the deferred confirmation was counted toward the quorum");

    // A far-future block id is held only within the deferral bounds.
    ShardBlockConfirmationLimits small;
    small.max_deferred_per_peer = 2;
    small.max_deferred = 3;
    ShardBlockConfirmations bounded(mc.view(), small);
    bounded.set_config(config({kA, kB}, 2));
    require(bounded.confirm(kA, block_at(1000000)) == Result::Deferred, "within the peer's deferral bound");
    require(bounded.confirm(kA, block_at(1000001)) == Result::Deferred, "at the peer's deferral bound");
    require(bounded.take_resend_requests().empty(), "nothing was dropped yet");
    require(bounded.confirm(kA, block_at(1000002)) == Result::Dropped, "past the peer's deferral bound");
    require(bounded.confirm(kB, block_at(1000003)) == Result::Deferred, "another peer has its own bound");
    require(bounded.confirm(kB, block_at(1000004)) == Result::Dropped, "past the global deferral bound");
    require(bounded.size() == 0 && bounded.deferred() == 3, "nothing beyond the bounds was retained");
    auto resend = bounded.take_resend_requests();
    require(resend.size() == 2 && resend.contains(kA) && resend.contains(kB),
            "every peer whose confirmation was dropped is asked to resend");
    require(bounded.take_resend_requests().empty(), "a resend request is handed over once");
  }

  // An unknown shard top gives no lookahead reference: nothing is created.
  {
    Masterchain mc;
    mc.top = std::nullopt;
    ShardBlockConfirmations store(mc.view());
    store.set_config(config({kA}, 1));
    require(store.confirm(kA, block_at(5)) == Result::Deferred, "without a registered top the confirmation waits");
    require(store.size() == 0, "and creates no entry");
  }

  // Per-peer budget: one peer cannot exhaust what other peers need.
  {
    Masterchain mc;
    ShardBlockConfirmationLimits limits;
    limits.max_entries_per_peer = 4;
    limits.max_entries = 6;
    ShardBlockConfirmations store(mc.view(), limits);
    store.set_config(config({kA, kB, kC}, 2));
    for (BlockSeqno seqno = 101; seqno <= 104; ++seqno) {
      require(store.confirm(kA, block_at(seqno, 0x10)) == Result::Accepted, "within the peer's entry budget");
    }
    require(store.confirm(kA, block_at(105, 0x10)) == Result::PeerBudget, "past the peer's entry budget");
    require(store.peer_entries(kA) == 4 && store.size() == 4, "the refused confirmation created nothing");
    require(store.confirm(kB, block_at(101, 0x20)) == Result::Accepted, "another peer still has budget");
    require(store.confirm(kA, block_at(101, 0x20)) == Result::Confirmed,
            "a peer at its budget still confirms entries it did not create");
    require(store.confirm(kB, block_at(102, 0x20)) == Result::Accepted, "the global budget is not yet reached");
    require(store.confirm(kC, block_at(103, 0x20)) == Result::GlobalBudget, "past the global entry budget");
    require(store.peer_entries() == 6, "the global entry budget holds");

    require(store.deferred(kA) == 1 && store.deferred(kC) == 1, "confirmations refused for budget are held");

    // Validated progress releases the budget, and the held confirmations are
    // admitted without being sent again.
    mc.top = 102;
    store.prune_registered();
    require(store.contains(block_at(105, 0x10)) && store.contains(block_at(103, 0x20)),
            "held confirmations create their entries once budget is released");
    require(store.deferred() == 0, "admitted confirmations leave the queue");
    require(store.peer_entries(kA) == 3 && store.peer_entries(kC) == 1 && store.peer_entries(kB) == 0,
            "pruned entries released their charge and admitted ones are charged");
  }

  // Byte budget, per peer and global, with entry slots to spare.
  {
    Masterchain mc;
    ShardBlockConfirmations probe(mc.view());
    const std::size_t charge = probe.entry_charge(3);
    ShardBlockConfirmationLimits limits;
    limits.max_bytes_per_peer = charge * 2;
    limits.max_bytes = charge * 3;
    ShardBlockConfirmations store(mc.view(), limits);
    store.set_config(config({kA, kB, kC}, 3));
    require(store.confirm(kA, block_at(101)) == Result::Accepted, "within the peer's byte budget");
    require(store.confirm(kA, block_at(102)) == Result::Accepted, "at the peer's byte budget");
    require(store.confirm(kA, block_at(103)) == Result::PeerBudget, "past the peer's byte budget");
    require(store.peer_bytes(kA) == charge * 2, "a peer is charged for the entries it created");
    require(store.confirm(kB, block_at(103)) == Result::Accepted, "at the global byte budget");
    require(store.confirm(kC, block_at(104)) == Result::GlobalBudget, "past the global byte budget");
    require(store.peer_bytes() == charge * 3, "the global byte budget holds");
  }

  // A local wait is never refused, even with every budget exhausted: a wait
  // that found no entry would complete as if no confirmation were needed.
  {
    Masterchain mc;
    ShardBlockConfirmationLimits limits;
    limits.max_entries_per_peer = 1;
    limits.max_entries = 1;
    ShardBlockConfirmations store(mc.view(), limits);
    store.set_config(config({kA, kB}, 1));
    require(store.confirm(kA, block_at(101)) == Result::Confirmed, "the budget is used up");
    Waiter waiter;
    store.wait({block_at(103)}, waiter.promise());
    require(!waiter.done, "a local wait on an unconfirmed block waits despite exhausted budgets");
    require(store.confirm(kB, block_at(103)) == Result::Confirmed, "a confirmation for an awaited block counts");
    require(waiter.done, "and completes the wait");
  }

  // A confirmation sent once and refused for capacity is not lost. The peer
  // never sends it again; it still completes a local wait, both when the wait
  // comes first and when capacity is released first.
  {
    Masterchain mc;
    ShardBlockConfirmationLimits limits;
    limits.max_entries_per_peer = 1;
    limits.max_entries = 1;
    ShardBlockConfirmations store(mc.view(), limits);
    store.set_config(config({kA, kB}, 1));
    require(store.confirm(kA, block_at(101)) == Result::Confirmed, "the budget is used up");
    require(store.confirm(kB, block_at(102)) == Result::GlobalBudget, "a confirmation refused for capacity");
    require(store.confirm(kB, block_at(103)) == Result::GlobalBudget, "another one");

    // The wait comes first: it creates the entry, and the held confirmation
    // completes it.
    Waiter first;
    store.wait({block_at(102)}, first.promise());
    require(first.done, "a held confirmation completes a later local wait");

    // Capacity is released first: the held confirmation creates its entry,
    // and a later wait finds it confirmed.
    mc.top = 101;
    store.prune_registered();
    require(store.is_confirmed(block_at(103)), "released capacity admits the held confirmation");
    Waiter second;
    store.wait({block_at(103)}, second.promise());
    require(second.done, "a local wait after the release completes at once");
    require(store.deferred() == 0, "nothing is left held");
  }

  // A configuration change keeps confirmations by nodes still trusted and
  // the entries local waits created. A peer-created entry stays charged to its
  // creator, or to another node that confirmed it if the creator is no longer
  // trusted, and is dropped if no such node remains.
  {
    Masterchain mc;
    ShardBlockConfirmations store(mc.view());
    store.set_config(config({kA, kB, kC}, 3));
    require(store.confirm(kA, block_at(101)) == Result::Accepted, "an entry created by A");
    require(store.confirm(kB, block_at(102)) == Result::Accepted, "an entry created by B");
    require(store.confirm(kA, block_at(102)) == Result::Accepted, "A also confirms B's entry");
    require(store.confirm(kB, block_at(103)) == Result::Accepted, "an entry only B confirmed");
    Waiter waiter;
    store.wait({block_at(104)}, waiter.promise());
    require(store.confirm(kB, block_at(104)) == Result::Accepted, "B confirms an awaited block");
    store.set_config(config({kA, kC}, 2));
    require(store.contains(block_at(101)) && store.contains(block_at(102)) && !store.contains(block_at(103)),
            "only the entry no remaining trusted node confirmed is dropped");
    require(store.peer_entries(kA) == 2 && store.peer_entries(kB) == 0, "B's surviving entry is charged to A");
    require(store.contains(block_at(104)) && !waiter.done, "an awaited entry stays and keeps its waiter");
    require(store.confirm(kC, block_at(101)) == Result::Confirmed, "A's carried-over confirmation still counts");
    require(store.confirm(kC, block_at(102)) == Result::Confirmed, "and on the entry it now carries");
    require(store.confirm(kA, block_at(104)) == Result::Accepted, "B's confirmation of the awaited block lapsed");
    require(store.confirm(kC, block_at(104)) == Result::Confirmed, "two remaining nodes confirm it");
    require(waiter.done, "the waiter completes under the new configuration");
  }

  // Recovery of lost confirmations through subscriptions. The harness moves
  // the production requests and answers (ShardBlockVerifierSubscriptions on
  // the verifier side, ShardBlockRetainerSubscriptions on the retainer side)
  // over a fake transport that can fail a request or lose the replay
  // messages, with the verifier's confirmation store behind it.
  {
    using tos::validator::kShardBlockRetainerReplayedFlag;
    using tos::validator::kShardBlockRetainerSubscriptionTtl;
    using tos::validator::kShardBlockVerifierResendFlag;
    using tos::validator::kShardBlockVerifierSubscribePeriod;
    using tos::validator::ShardBlockRetainerSubscriptions;
    using tos::validator::ShardBlockVerifierSubscriptions;
    using Key = ShardBlockVerifierSubscriptions::Key;
    using Recovery = ShardBlockVerifierSubscriptions::Recovery;
    const double period = kShardBlockVerifierSubscribePeriod;
    const tos::ShardIdFull shard{tos::basechainId, tos::shardIdAll};
    const Key key{kA, shard};

    // A retainer as it was before confirmation recovery: it ignores request
    // flags, never acknowledges, replays only when it has no subscription at
    // all, and here never confirms another block, so an expired subscription
    // is never cleaned up.
    struct OldRetainer {
      std::optional<double> ttl;
      bool subscribe(double now, td::BufferSlice &reply) {
        bool replay = !ttl.has_value();
        ttl = now + kShardBlockRetainerSubscriptionTtl;
        reply = tos::create_serialize_tl_object<tos::tos_api::shardBlockVerifier_subscribed>(0);
        return replay;
      }
    };

    struct Harness {
      tos::ShardIdFull shard{tos::basechainId, tos::shardIdAll};
      Key key{kA, shard};
      Masterchain mc;
      td::Ref<ShardBlockVerifierConfig> cfg = config({kA}, 1);
      ShardBlockConfirmations store;
      ShardBlockVerifierSubscriptions verifier;
      ShardBlockRetainerSubscriptions retainer;
      OldRetainer old_retainer;
      bool old = false;
      std::vector<BlockIdExt> held;
      bool fail_next = false;
      bool lose_replay_next = false;
      unsigned replays = 0;
      std::vector<td::uint32> request_flags;

      explicit Harness(ShardBlockConfirmationLimits limits) : store(mc.view(), limits) {
        store.set_config(cfg);
        verifier.configured(*cfg);
      }
      void collect() {
        auto dropped = store.take_resend_requests();
        if (!dropped.empty()) {
          verifier.dropped(dropped, *cfg);
        }
      }
      void round(double now) {
        for (auto &out : verifier.round(*cfg, store.unresolved_wait_sources())) {
          auto request = ShardBlockRetainerSubscriptions::parse_request(out.request.as_slice());
          require(request.is_ok() && request.ok().shard == shard, "the request names its shard");
          request_flags.push_back(request.ok().flags);
          if (fail_next) {
            fail_next = false;
            require(verifier.answered(out.key, td::Status::Error("timeout")).is_error(), "a failure is reported");
            continue;
          }
          td::BufferSlice reply;
          bool replay = false;
          if (old) {
            replay = old_retainer.subscribe(now, reply);
          } else {
            auto answer = retainer.subscribe(kA, request.ok().shard, request.ok().flags, now);
            replay = answer.send_retained;
            reply = std::move(answer.reply);
          }
          if (replay) {
            ++replays;
            if (lose_replay_next) {
              lose_replay_next = false;
            } else {
              for (const auto &block_id : held) {
                store.confirm(kA, block_id);
              }
            }
          }
          require(verifier.answered(out.key, std::move(reply)).is_ok(), "an answer is accepted");
          collect();
        }
      }
      // The retainer confirms three blocks and sends each confirmation once;
      // the verifier holds one for budget and drops the next.
      void overflow() {
        held = {block_at(101), block_at(102), block_at(103)};
        require(store.confirm(kA, block_at(101)) == Result::Confirmed, "the peer's budget is used");
        require(store.confirm(kA, block_at(102)) == Result::PeerBudget, "one confirmation is held");
        require(store.confirm(kA, block_at(103)) == Result::Dropped, "the next is dropped");
        collect();
        require(verifier.recovery().outstanding(key), "a dropped confirmation starts recovery");
        mc.top = 101;
        store.prune_registered();
      }
    };
    ShardBlockConfirmationLimits limits;
    limits.max_entries_per_peer = 1;
    limits.max_deferred_per_peer = 1;
    limits.max_deferred = 1;

    // The wire adapter: the request carries its flags, the answer its
    // acknowledgement, and an unreadable answer counts as a failure.
    {
      auto request = ShardBlockRetainerSubscriptions::parse_request(
          tos::validator::make_shard_block_subscribe_request(shard, kShardBlockVerifierResendFlag).as_slice());
      require(request.is_ok() && request.ok().shard == shard && request.ok().flags == kShardBlockVerifierResendFlag,
              "a request round-trips");
      ShardBlockRetainerSubscriptions retainer;
      auto first = retainer.subscribe(kA, shard, 0, 0);
      auto parsed = tos::validator::parse_shard_block_subscribe_reply(std::move(first.reply));
      require(first.send_retained && parsed.is_ok() && parsed.ok() == kShardBlockRetainerReplayedFlag,
              "a replay is acknowledged in the answer");
      auto renewal = retainer.subscribe(kA, shard, 0, period);
      parsed = tos::validator::parse_shard_block_subscribe_reply(std::move(renewal.reply));
      require(!renewal.send_retained && parsed.is_ok() && parsed.ok() == 0, "a plain renewal is not");
      ShardBlockVerifierSubscriptions verifier;
      verifier.recovery().request(key);
      require(verifier.answered(key, td::BufferSlice("garbage")).is_error(), "an unreadable answer is a failure");
      require(verifier.recovery().outstanding(key), "and leaves recovery outstanding");
    }

    // The retainer answers a subscription whose time to live passed as a new
    // one, even though it still has an entry for it.
    {
      ShardBlockRetainerSubscriptions retainer;
      require(retainer.subscribe(kA, shard, 0, 0).send_retained, "a new subscription is replayed");
      require(!retainer.subscribe(kA, shard, 0, 30).send_retained, "a renewal is not");
      require(retainer.size() == 1, "the expired subscription is still recorded");
      require(retainer.subscribe(kA, shard, 0, 30 + kShardBlockRetainerSubscriptionTtl).send_retained,
              "an expired one is treated as new");
      require(retainer.subscribe(kA, shard, kShardBlockVerifierResendFlag, 100).send_retained,
              "a resend request is answered");
      require(!retainer.subscribe(kA, shard, kShardBlockVerifierResendFlag, 101).send_retained,
              "but not twice within the interval");
    }

    // The acknowledgement arrives but the replay is lost, before any wait:
    // recovery ends. A later local wait for the lost block starts it again
    // by itself, and the next replay completes the wait. No overflow, and no
    // confirmation is injected.
    {
      Harness h(limits);
      h.round(0);
      h.overflow();
      h.lose_replay_next = true;
      h.round(period);
      require(h.replays == 2, "the dropped confirmation was replayed");
      require(!h.verifier.recovery().outstanding(key), "the acknowledgement ended recovery");
      h.request_flags.clear();
      h.round(2 * period);
      require(h.request_flags == std::vector<td::uint32>{0}, "nothing is asked while nothing waits");
      Waiter waiter;
      h.store.wait({block_at(103)}, waiter.promise());
      require(!waiter.done, "the lost confirmation leaves the wait unresolved");
      h.round(3 * period);
      require(h.request_flags.back() == kShardBlockVerifierResendFlag, "the unresolved wait asks for a replay");
      require(waiter.done, "the replay completes the wait");
      h.request_flags.clear();
      h.round(4 * period);
      require(h.request_flags == std::vector<td::uint32>{0}, "a resolved wait asks for nothing more");
    }

    // The same with the wait already outstanding: an acknowledged replay that
    // is lost does not end the asking.
    {
      Harness h(limits);
      h.round(0);
      h.overflow();
      Waiter waiter;
      h.store.wait({block_at(103)}, waiter.promise());
      h.lose_replay_next = true;
      h.round(period);
      require(!waiter.done, "the replay was lost");
      h.round(2 * period);
      require(waiter.done, "the next round asks again and completes the wait");
    }

    // A failed request leaves recovery outstanding, and the retry completes
    // it and the wait.
    {
      Harness h(limits);
      h.round(0);
      h.overflow();
      h.fail_next = true;
      h.round(period);
      require(h.verifier.recovery().outstanding(key), "a failed request leaves recovery outstanding");
      h.round(2 * period);
      require(!h.verifier.recovery().outstanding(key), "an acknowledged retry ends recovery");
      Waiter waiter;
      h.store.wait({block_at(103)}, waiter.promise());
      require(waiter.done, "the replayed confirmation completes a later wait");
    }

    // Recovery started by a dropped confirmation that no wait needs is given
    // up after a bounded number of attempts.
    {
      Harness h(limits);
      h.round(0);
      h.overflow();
      for (unsigned i = 0; i < Recovery::kMaxAttempts; ++i) {
        h.fail_next = true;
        h.round((i + 1) * period);
      }
      require(h.verifier.recovery().outstanding(key), "spent attempts are given up at the next round");
      h.round((Recovery::kMaxAttempts + 1) * period);
      require(!h.verifier.recovery().outstanding(key), "recovery no wait needs is given up");
    }

    // A retainer that predates recovery, with an expired subscription it
    // never cleans up: no request makes it replay. The verifier keeps asking
    // while the wait is unresolved, reports the retainer as needing an
    // upgrade, and the wait resolves only when its block is registered.
    {
      Harness h(limits);
      h.old = true;
      h.round(0);
      h.overflow();
      Waiter waiter;
      h.store.wait({block_at(103)}, waiter.promise());
      double now = 0;
      bool reported = false;
      for (unsigned i = 0; i < 20; ++i) {
        now += period;
        h.round(now);
        require(h.request_flags.back() == kShardBlockVerifierResendFlag, "the verifier keeps asking");
        reported = reported || h.verifier.recovery().take_newly_unsupported().contains(key);
      }
      require(now > 2 * kShardBlockRetainerSubscriptionTtl, "the subscription expired meanwhile");
      require(h.replays == 1, "the old retainer never replayed");
      require(!waiter.done, "the wait stays unresolved");
      require(reported && h.verifier.recovery().unsupported(key), "the retainer is reported as unsupported");
      require(h.verifier.recovery().take_newly_unsupported().empty(), "and reported once");
      h.mc.top = 103;
      h.store.prune_registered();
      require(waiter.done, "registering the block resolves the wait");
      for (unsigned i = 0; i <= Recovery::kMaxAttempts; ++i) {
        now += period;
        h.round(now);
      }
      require(!h.verifier.recovery().outstanding(key), "recovery stops once nothing needs it");
    }
  }

  std::cout << "SHARD_BLOCK_CONFIRMATIONS_OK\n";
  return 0;
}
