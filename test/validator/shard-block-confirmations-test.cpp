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

  // The retainer side of a resend request: a new subscription is always
  // answered with every held confirmation, a flagged renewal only when the
  // retainer's interval allows, and an unflagged renewal never.
  {
    using tos::validator::kShardBlockVerifierResendFlag;
    using tos::validator::shard_block_retainer_sends_retained;
    require(shard_block_retainer_sends_retained(true, 0, false), "a new subscription is answered");
    require(shard_block_retainer_sends_retained(false, kShardBlockVerifierResendFlag, true),
            "a flagged renewal is answered when allowed");
    require(!shard_block_retainer_sends_retained(false, kShardBlockVerifierResendFlag, false),
            "a flagged renewal within the interval is not");
    require(!shard_block_retainer_sends_retained(false, 0, true), "an unflagged renewal is not");
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

  // Recovery of dropped confirmations through subscriptions, driven through a
  // small harness: a fake transport that can fail requests, and a fake
  // retainer that decides with the real retainer rules. A retainer that
  // predates the resend flag ignores it and never acknowledges a replay; it
  // forgets a subscription that is not renewed within its time to live (the
  // real one erases expired subscriptions as it confirms new blocks).
  {
    using tos::validator::kShardBlockRetainerMinResendInterval;
    using tos::validator::kShardBlockRetainerReplayedFlag;
    using tos::validator::kShardBlockRetainerSubscriptionTtl;
    using tos::validator::kShardBlockVerifierResendFlag;
    using tos::validator::kShardBlockVerifierSubscribePeriod;
    using tos::validator::shard_block_retainer_is_new_subscription;
    using tos::validator::shard_block_retainer_sends_retained;
    using Key = std::pair<Peer, tos::ShardIdFull>;
    using Recovery = tos::validator::ShardBlockSubscriptionRecovery<Key>;
    const Key key{kA, tos::ShardIdFull{tos::basechainId, tos::shardIdAll}};

    struct FakeRetainer {
      bool understands_flags = true;
      std::vector<BlockIdExt> held;
      std::optional<double> ttl;
      double resend_allowed_at = 0;
      unsigned replays = 0;
      td::uint32 subscribe(td::uint32 flags, double now, std::vector<BlockIdExt> &sent) {
        bool expired = ttl && *ttl <= now;
        bool is_new = shard_block_retainer_is_new_subscription(ttl.has_value(), expired);
        td::uint32 seen = understands_flags ? flags : 0;
        td::uint32 reply = 0;
        if (shard_block_retainer_sends_retained(is_new, seen, now >= resend_allowed_at)) {
          sent = held;
          ++replays;
          resend_allowed_at = now + kShardBlockRetainerMinResendInterval;
          if (understands_flags) {
            reply |= kShardBlockRetainerReplayedFlag;
          }
        }
        ttl = now + kShardBlockRetainerSubscriptionTtl;
        return reply;
      }
    };

    struct Scenario {
      Masterchain mc;
      ShardBlockConfirmations store;
      Recovery recovery;
      FakeRetainer retainer;
      std::vector<bool> fail_next;
      unsigned requests = 0;
      Key key;
      Scenario(ShardBlockConfirmationLimits limits, Key key) : store(mc.view(), limits), key(std::move(key)) {
        store.set_config(config({kA}, 1));
      }
      void collect() {
        for (const auto &peer : store.take_resend_requests()) {
          if (peer == kA) {
            recovery.request(key);
          }
        }
      }
      // One regular subscription round at `now`.
      void tick(double now) {
        auto flags = recovery.subscription(key, now);
        if (!flags) {
          return;
        }
        ++requests;
        if (!fail_next.empty()) {
          bool fail = fail_next.front();
          fail_next.erase(fail_next.begin());
          if (fail) {
            recovery.on_failure(key, now);
            return;
          }
        }
        std::vector<BlockIdExt> sent;
        auto reply = retainer.subscribe(*flags, now, sent);
        for (const auto &block_id : sent) {
          store.confirm(kA, block_id);
        }
        recovery.on_reply(key, reply, now);
        collect();
      }
      // The retainer confirms blocks and sends each confirmation once; the
      // verifier holds one for budget and must drop the next.
      void overflow() {
        retainer.held = {block_at(101), block_at(102), block_at(103)};
        require(store.confirm(kA, block_at(101)) == Result::Confirmed, "the peer's budget is used");
        require(store.confirm(kA, block_at(102)) == Result::PeerBudget, "one confirmation is held");
        require(store.confirm(kA, block_at(103)) == Result::Dropped, "the next is dropped");
        collect();
        require(recovery.outstanding(key), "a dropped confirmation starts recovery");
      }
    };
    ShardBlockConfirmationLimits limits;
    limits.max_entries_per_peer = 1;
    limits.max_deferred_per_peer = 1;
    limits.max_deferred = 1;
    const double period = kShardBlockVerifierSubscribePeriod;

    // An upgraded retainer: the resend request fails once, the retry
    // succeeds and is acknowledged, and a local wait on the dropped block
    // completes without the confirmation being injected again.
    {
      Scenario sc(limits, key);
      sc.tick(0);
      require(sc.retainer.replays == 1, "the first subscription is new");
      sc.overflow();
      sc.mc.top = 101;
      sc.store.prune_registered();
      sc.fail_next = {true};
      sc.tick(period);
      require(sc.recovery.outstanding(key), "a failed resend request leaves recovery outstanding");
      sc.tick(2 * period);
      require(sc.retainer.replays == 2, "the retried request was answered with a replay");
      require(!sc.recovery.outstanding(key), "an acknowledged replay completes recovery");
      Waiter waiter;
      sc.store.wait({block_at(103)}, waiter.promise());
      require(waiter.done, "the dropped confirmation completes a local wait after recovery");
      sc.tick(3 * period);
      require(sc.retainer.replays == 2, "a recovered subscription asks for nothing more");
    }

    // A retainer that predates the flag: resend requests go unacknowledged,
    // so after kMaxResendAttempts the subscription is let lapse, and the next
    // one, new to the retainer, is answered with everything it holds.
    {
      Scenario sc(limits, key);
      sc.retainer.understands_flags = false;
      sc.tick(0);
      sc.overflow();
      sc.mc.top = 101;
      sc.store.prune_registered();
      double now = 0;
      for (unsigned i = 0; i < Recovery::kMaxResendAttempts; ++i) {
        now += period;
        sc.tick(now);
        require(sc.retainer.replays == 1, "an old retainer does not replay on a renewal");
      }
      require(sc.recovery.stage(key) == Recovery::Stage::Lapse, "unacknowledged requests let the subscription lapse");
      const unsigned before_lapse = sc.requests;
      while (sc.recovery.outstanding(key) && now < 1000) {
        now += period;
        sc.tick(now);
      }
      require(!sc.recovery.outstanding(key), "recovery completes");
      require(sc.retainer.replays == 2, "the fresh subscription was answered with a replay");
      require(sc.requests == before_lapse + 1, "no subscription was renewed during the lapse");
      Waiter waiter;
      sc.store.wait({block_at(103)}, waiter.promise());
      require(waiter.done, "the dropped confirmation completes a local wait after the fresh subscription");
    }

    // A fresh subscription that fails may still have reached the retainer
    // and made the subscription current again, so it lapses again.
    {
      Recovery recovery;
      recovery.request(key);
      for (unsigned i = 0; i < Recovery::kMaxResendAttempts; ++i) {
        require(recovery.subscription(key, 0) == kShardBlockVerifierResendFlag, "a resend is requested");
        recovery.on_failure(key, 0);
      }
      require(recovery.stage(key) == Recovery::Stage::Lapse, "repeated failures let the subscription lapse");
      require(!recovery.subscription(key, Recovery::kLapse - 1), "nothing is sent during the lapse");
      require(recovery.subscription(key, Recovery::kLapse) == td::uint32{0}, "then a fresh subscription");
      recovery.on_failure(key, Recovery::kLapse);
      require(recovery.stage(key) == Recovery::Stage::Lapse, "a failed fresh subscription lapses again");
      recovery.retain_if([](const Key &) { return false; });
      require(!recovery.outstanding(key), "an unconfigured subscription is forgotten");
    }
  }

  std::cout << "SHARD_BLOCK_CONFIRMATIONS_OK\n";
  return 0;
}
