/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// How long an RLDP answer is kept by the node that sends it, when the answer
// carries a delivery deadline of its own.
//
// Everything runs over real RLDP on a loopback ADNL network. To make the
// answering side hold its answer, the requester is cut off from receiving:
// it can still send, so its query arrives, but it never sees the answer and
// never acknowledges it. The answering side's outbound transfers are then
// counted through RLDP's own diagnostics.
//
//   1. The adapters between plain and annotated answers keep errors whole,
//      a plain answer carries no deadline, and a deadline never extends the
//      transport's own.
//   2. Over RLDP alone: an answer with a 3 s deadline is gone after 3 s
//      despite a 50 s request; plain answers, small and multi-part, keep the
//      request's deadline; a request deadline under 3 s stays in charge; a
//      deadline later than the request's does not extend it; an expired
//      deadline opens no transfer at all; a subscriber that only answers
//      plain data is reached through the annotated path and keeps the
//      request's deadline.
//   3. Through the overlay manager's buffer: a query that waits for its
//      overlay to be created gets the deadline its answerer set, unchanged,
//      and an answer whose deadline passed meanwhile opens no transfer.
//   4. Through a production full-node shard and its admission, with the
//      production downloader as the requester: a capacity refusal reaches
//      the downloader as notready and its download token is given back, and
//      with the requester cut off, the refusal answer is dropped by the
//      answering side after the refusal lifetime.

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "adnl/adnl-query-answer.h"
#include "adnl/adnl-test-loopback-implementation.h"
#include "adnl/adnl.h"
#include "auto/tl/tos_api.hpp"
#include "dht/dht.h"
#include "keyring/keyring.h"
#include "overlay/overlays.h"
#include "quic/quic-sender.h"
#include "rldp2/rldp.h"
#include "td/utils/Time.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "td/utils/port/signals.h"
#include "tl-utils/tl-utils.hpp"
#include "tos/tos-tl.hpp"
#include "validator/fabric.h"
#include "validator/full-node-shard-admission.h"
#include "validator/full-node-shard.h"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager.hpp"
#include "validator/net/download-block-new.hpp"

namespace {

using namespace tos;
using namespace tos::validator;
using namespace tos::validator::fullnode;

[[noreturn]] void fail(const std::string &message) {
  std::fprintf(stderr, "RLDP_REFUSAL_LIFETIME_FAILURE: %s\n", message.c_str());
  std::fflush(stderr);
  std::_Exit(1);
}

void require(bool condition, const std::string &message) {
  if (!condition) {
    fail(message);
  }
}

void pass(const std::string &what) {
  std::printf("  ok: %s\n", what.c_str());
  std::fflush(stdout);
}

// Answers withheld by a subscriber until the test releases them with the
// metadata it chooses. Released from inside the scheduler, since an answer
// is handed on by messages to actors.
struct Held {
  std::mutex mutex;
  std::vector<td::Promise<adnl::AdnlQueryAnswer>> promises;
  std::vector<td::BufferSlice> queries;
  size_t count() {
    std::lock_guard lock(mutex);
    return promises.size();
  }
  void release(td::BufferSlice answer, td::Timestamp deadline) {
    std::vector<td::Promise<adnl::AdnlQueryAnswer>> taken;
    {
      std::lock_guard lock(mutex);
      taken.swap(promises);
    }
    for (auto &promise : taken) {
      promise.set_value(adnl::AdnlQueryAnswer{answer.clone(), deadline});
    }
  }
};

class AnnotatingSubscriber : public adnl::Adnl::Callback {
 public:
  explicit AnnotatingSubscriber(std::shared_ptr<Held> held) : held_(std::move(held)) {
  }
  void receive_query_ex(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice data,
                        td::Promise<adnl::AdnlQueryAnswer> promise) override {
    std::lock_guard lock(held_->mutex);
    held_->queries.push_back(std::move(data));
    held_->promises.push_back(std::move(promise));
  }

 private:
  std::shared_ptr<Held> held_;
};

// A subscriber written before answers could carry metadata.
class PlainSubscriber : public adnl::Adnl::Callback {
 public:
  void receive_query(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    promise.set_value(std::move(data));
  }
};

class AnnotatingOverlayCallback : public overlay::Overlays::Callback {
 public:
  explicit AnnotatingOverlayCallback(std::shared_ptr<Held> held) : held_(std::move(held)) {
  }
  void receive_query_ex(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, td::BufferSlice data,
                        td::Promise<adnl::AdnlQueryAnswer> promise) override {
    std::lock_guard lock(held_->mutex);
    held_->queries.push_back(std::move(data));
    held_->promises.push_back(std::move(promise));
  }

 private:
  std::shared_ptr<Held> held_;
};

class PlainOverlayCallback : public overlay::Overlays::Callback {
 public:
  void receive_query(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    promise.set_value(std::move(data));
  }
};

}  // namespace

namespace tos::validator {

// The production manager with its start-up suppressed: the requester's side
// counts download tokens and has no blocks; the server's side is never asked
// anything, since every query it sees is refused.
class LifetimeTestManager : public ValidatorManagerImpl {
 public:
  explicit LifetimeTestManager(std::shared_ptr<std::atomic<int>> live_tokens)
      : ValidatorManagerImpl(ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{}), "", {}, {}, {}, {}, {})
      , live_tokens_(std::move(live_tokens)) {
  }
  void start_up() override {
  }
  void get_block_handle(BlockIdExt id, bool, td::Promise<BlockHandle> promise) override {
    promise.set_value(create_empty_block_handle(id));
  }
  void get_download_token(size_t, td::uint32, td::Timestamp,
                          td::Promise<std::unique_ptr<ActionToken>> promise) override {
    promise.set_value(std::make_unique<Token>(live_tokens_));
  }
  void register_stats_provider(
      td::uint64, std::string,
      std::function<void(td::Promise<std::vector<std::pair<std::string, std::string>>>)>) override {
  }
  void unregister_stats_provider(td::uint64) override {
  }

 private:
  class Token : public ActionToken {
   public:
    explicit Token(std::shared_ptr<std::atomic<int>> live) : live_(std::move(live)) {
      live_->fetch_add(1);
    }
    ~Token() override {
      live_->fetch_sub(1);
    }

   private:
    std::shared_ptr<std::atomic<int>> live_;
  };
  std::shared_ptr<std::atomic<int>> live_tokens_;
};

}  // namespace tos::validator

namespace {

void adapters() {
  // Errors keep their code and message through both adapters.
  {
    std::optional<td::Result<adnl::AdnlQueryAnswer>> got;
    auto plain = adnl::drop_answer_metadata([&](td::Result<adnl::AdnlQueryAnswer> R) { got = std::move(R); });
    plain.set_error(td::Status::Error(ErrorCode::notready, "not here yet"));
    require(got && got->is_error() && got->error().code() == ErrorCode::notready &&
                got->error().message() == "not here yet",
            "an error lost its code or message through drop_answer_metadata");
  }
  {
    std::optional<td::Result<td::BufferSlice>> got;
    auto annotated = adnl::ignore_answer_metadata([&](td::Result<td::BufferSlice> R) { got = std::move(R); });
    annotated.set_error(td::Status::Error(ErrorCode::timeout, "too slow"));
    require(got && got->is_error() && got->error().code() == ErrorCode::timeout && got->error().message() == "too slow",
            "an error lost its code or message through ignore_answer_metadata");
  }
  // A plain answer carries no deadline; an annotated one keeps its data.
  {
    std::optional<td::Result<adnl::AdnlQueryAnswer>> got;
    auto plain = adnl::drop_answer_metadata([&](td::Result<adnl::AdnlQueryAnswer> R) { got = std::move(R); });
    plain.set_value(td::BufferSlice("data"));
    require(got && got->is_ok() && got->ok().data.as_slice() == "data" && !got->ok().delivery_deadline,
            "a plain answer gained a deadline");
  }
  {
    std::optional<td::Result<td::BufferSlice>> got;
    auto annotated = adnl::ignore_answer_metadata([&](td::Result<td::BufferSlice> R) { got = std::move(R); });
    annotated.set_value(adnl::AdnlQueryAnswer{td::BufferSlice("data"), td::Timestamp::in(3.0)});
    require(got && got->is_ok() && got->ok().as_slice() == "data", "an annotated answer lost its data");
  }
  // A deadline only ever shortens the transport's own.
  {
    auto transport = td::Timestamp::at(1000.0);
    auto later = adnl::AdnlQueryAnswer{td::BufferSlice(), td::Timestamp::at(1010.0)};
    auto earlier = adnl::AdnlQueryAnswer{td::BufferSlice(), td::Timestamp::at(997.0)};
    auto none = adnl::AdnlQueryAnswer{td::BufferSlice(), td::Timestamp{}};
    require(adnl::answer_delivery_deadline(transport, later).at() == 1000.0,
            "a later deadline extended the transport's");
    require(adnl::answer_delivery_deadline(transport, earlier).at() == 997.0, "an earlier deadline was ignored");
    require(adnl::answer_delivery_deadline(transport, none).at() == 1000.0, "no deadline changed the transport's");
    require(adnl::answer_delivery_deadline(td::Timestamp{}, earlier).at() == 997.0,
            "a deadline was ignored without a transport deadline");
  }
  // Subscribers that only answer plain data are reached through the annotated
  // entry points, and their answers carry no deadline.
  {
    PlainSubscriber subscriber;
    std::optional<td::Result<adnl::AdnlQueryAnswer>> got;
    subscriber.receive_query_ex(adnl::AdnlNodeIdShort::zero(), adnl::AdnlNodeIdShort::zero(), td::BufferSlice("q"),
                                [&](td::Result<adnl::AdnlQueryAnswer> R) { got = std::move(R); });
    require(got && got->is_ok() && got->ok().data.as_slice() == "q" && !got->ok().delivery_deadline,
            "a plain ADNL subscriber did not answer, unannotated, through receive_query_ex");
  }
  {
    PlainOverlayCallback callback;
    std::optional<td::Result<adnl::AdnlQueryAnswer>> got;
    callback.receive_query_ex(adnl::AdnlNodeIdShort::zero(), overlay::OverlayIdShort{}, td::BufferSlice("q"),
                              [&](td::Result<adnl::AdnlQueryAnswer> R) { got = std::move(R); });
    require(got && got->is_ok() && got->ok().data.as_slice() == "q" && !got->ok().delivery_deadline,
            "a plain overlay callback did not answer, unannotated, through receive_query_ex");
  }
  pass("adapters keep errors, plain answers carry no deadline, deadlines only shorten");
}

class Harness {
 public:
  Harness() : scheduler_({1}) {
    root_ = "tmp-dir-test-rldp2-refusal-lifetime";
    td::rmrf(root_).ignore();
    td::mkdir(root_).ensure();
    requester_tokens_ = std::make_shared<std::atomic<int>>(0);
    server_tokens_ = std::make_shared<std::atomic<int>>(0);
    scheduler_.run_in_context([&] {
      keyring_ = keyring::Keyring::create(root_);
      net_ = td::actor::create_actor<adnl::TestLoopbackNetworkManager>("test net");
      adnl_ = adnl::Adnl::create(root_, keyring_.get());
      rldp_ = rldp2::Rldp::create(adnl_.get());
      td::actor::send_closure(adnl_, &adnl::Adnl::register_network_manager, net_.get());
      // Public overlays need a DHT; a one-node one is enough, since every peer
      // here is reached directly.
      {
        auto key = PrivateKey{privkeys::Ed25519::random()};
        auto pub = key.compute_public_key();
        auto id = adnl::AdnlNodeIdShort{pub.compute_short_id()};
        auto node = create_tl_object<tos_api::dht_node>(pub.tl(), address_.tl(), -1, td::BufferSlice());
        node->signature_ = key.create_decryptor().move_as_ok()->sign(serialize_tl_object(node, true)).move_as_ok();
        std::vector<tl_object_ptr<tos_api::dht_node>> nodes;
        nodes.push_back(std::move(node));
        auto config = dht::Dht::create_global_config(create_tl_object<tos_api::dht_config_global>(
                                                         create_tl_object<tos_api::dht_nodes>(std::move(nodes)), 6, 3))
                          .move_as_ok();
        td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(key), true, [](td::Result<>) {});
        td::actor::send_closure(adnl_, &adnl::Adnl::add_id, adnl::AdnlNodeIdFull{pub}, address_, td::uint8(0));
        td::actor::send_closure(net_, &adnl::TestLoopbackNetworkManager::add_node_id, id, true, true);
        dht_ = dht::Dht::create(id, root_, std::move(config), keyring_.get(), adnl_.get()).move_as_ok();
      }
      overlays_ = overlay::Overlays::create(root_, keyring_.get(), adnl_.get(), dht_.get(),
                                            overlay::OverlayManagerBufferLimits{64, 1 << 20});
      requester_manager_ = td::actor::create_actor<LifetimeTestManager>("requester manager", requester_tokens_);
      server_manager_ = td::actor::create_actor<LifetimeTestManager>("server manager", server_tokens_);
      requester_ = add_node();
      answerer_ = add_node();
      buffered_ = add_node();
      full_node_ = add_node();
      for (auto &node : nodes_) {
        if (node.id != requester_) {
          td::actor::send_closure(adnl_, &adnl::Adnl::add_peer, requester_, node.full, address_);
        }
      }
    });
    run_for(0.2);
  }

  ~Harness() {
    scheduler_.run_in_context([&] {
      shard_.reset();
      overlays_.reset();
      dht_.reset();
      rldp_.reset();
      requester_manager_.reset();
      server_manager_.reset();
      adnl_.reset();
      net_.reset();
      keyring_.reset();
    });
    run_for(0.3);
    scheduler_.stop();
    td::rmrf(root_).ignore();
  }

  template <class F>
  void run(F &&f) {
    scheduler_.run_in_context(std::forward<F>(f));
  }

  void run_for(double seconds, const std::function<bool()> &done = {}) {
    auto deadline = td::Timestamp::in(seconds);
    while (!deadline.is_in_past() && !(done && done())) {
      scheduler_.run(0.001);
    }
  }
  void run_until(td::Timestamp at) {
    while (!at.is_in_past()) {
      scheduler_.run(0.001);
    }
  }
  void wait_for(const std::function<bool()> &done, const std::string &what, double limit = 10.0) {
    run_for(limit, done);
    require(done(), what);
  }

  rldp2::Rldp::OutboundTransferStats outbound(adnl::AdnlNodeIdShort local_id) {
    std::optional<rldp2::Rldp::OutboundTransferStats> stats;
    run([&] {
      td::actor::send_closure(rldp_, &rldp2::Rldp::get_outbound_transfer_stats, local_id,
                              [&](td::Result<rldp2::Rldp::OutboundTransferStats> R) { stats = R.move_as_ok(); });
    });
    run_for(2.0, [&] { return stats.has_value(); });
    require(stats.has_value(), "the transfer stats were never answered");
    return *stats;
  }

  // Whether the requester receives anything. Cut off, it still sends, so its
  // queries arrive, but no answer reaches it and it acknowledges none.
  void requester_receives(bool receives) {
    run([&] {
      td::actor::send_closure(net_, &adnl::TestLoopbackNetworkManager::add_node_id, requester_, true, receives);
    });
    run_for(0.01);
  }

  void subscribe(adnl::AdnlNodeIdShort id, std::string prefix, std::unique_ptr<adnl::Adnl::Callback> callback) {
    run([&] { td::actor::send_closure(adnl_, &adnl::Adnl::subscribe, id, prefix, std::move(callback)); });
    run_for(0.01);
  }

  void query(adnl::AdnlNodeIdShort dst, td::BufferSlice data, double timeout, td::uint64 max_answer_size,
             std::shared_ptr<std::optional<td::Result<td::BufferSlice>>> result) {
    run([&] {
      td::actor::send_closure(
          rldp_, &rldp2::Rldp::send_query_ex, requester_, dst, std::string("lifetime"),
          [result](td::Result<td::BufferSlice> R) { *result = std::move(R); }, td::Timestamp::in(timeout),
          std::move(data), max_answer_size);
    });
  }

  adnl::AdnlNodeIdShort requester_, answerer_, buffered_, full_node_;
  PublicKeyHash full_node_key_;
  std::shared_ptr<std::atomic<int>> requester_tokens_, server_tokens_;
  td::actor::ActorOwn<keyring::Keyring> keyring_;
  td::actor::ActorOwn<adnl::TestLoopbackNetworkManager> net_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<rldp2::Rldp> rldp_;
  td::actor::ActorOwn<dht::Dht> dht_;
  td::actor::ActorOwn<overlay::Overlays> overlays_;
  td::actor::ActorOwn<LifetimeTestManager> requester_manager_, server_manager_;
  td::actor::ActorOwn<FullNodeShard> shard_;

 private:
  struct Node {
    adnl::AdnlNodeIdShort id;
    adnl::AdnlNodeIdFull full;
  };

  adnl::AdnlNodeIdShort add_node() {
    auto key = PrivateKey{privkeys::Ed25519::random()};
    auto pub = key.compute_public_key();
    auto id = adnl::AdnlNodeIdShort{pub.compute_short_id()};
    if (nodes_.size() == 3) {
      full_node_key_ = pub.compute_short_id();
    }
    td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(key), true, [](td::Result<>) {});
    td::actor::send_closure(adnl_, &adnl::Adnl::add_id, adnl::AdnlNodeIdFull{pub}, address_, td::uint8(0));
    td::actor::send_closure(rldp_, &rldp2::Rldp::add_id, id);
    td::actor::send_closure(net_, &adnl::TestLoopbackNetworkManager::add_node_id, id, true, true);
    nodes_.push_back(Node{id, adnl::AdnlNodeIdFull{pub}});
    return id;
  }

  std::string root_;
  td::actor::Scheduler scheduler_;
  adnl::AdnlAddressList address_ = adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();
  std::vector<Node> nodes_;
};

// The answering side's live transfers, polled until `done` or the limit.
size_t live(Harness &h, adnl::AdnlNodeIdShort id) {
  return h.outbound(id).live;
}

// Starts with the answering side idle and the requester cut off.
void begin_case(Harness &h, adnl::AdnlNodeIdShort answerer) {
  h.requester_receives(true);
  h.wait_for([&] { return live(h, answerer) == 0; }, "the answering side did not settle before a case");
  // The requester's own earlier queries, unacknowledged while it was cut off,
  // must be settled too, or they hold its congestion window.
  h.wait_for([&] { return live(h, h.requester_) == 0; }, "the requester did not settle before a case");
  h.requester_receives(false);
}

// Holds the answering side's transfer at `present_at` and requires it gone by
// `gone_by`.
void expect_held_then_gone(Harness &h, adnl::AdnlNodeIdShort answerer, td::Timestamp present_at, td::Timestamp gone_by,
                           const std::string &what) {
  h.run_until(present_at);
  auto stats = h.outbound(answerer);
  require(stats.live == 1, what + ": the answer was not held while within its deadline (live " +
                               std::to_string(stats.live) + ", started " + std::to_string(stats.started) + ")");
  h.run_for(gone_by.at() - td::Timestamp::now().at(), [&] { return live(h, answerer) == 0; });
  require(!gone_by.is_in_past() || live(h, answerer) == 0, what + ": the answer outlived its deadline");
  require(live(h, answerer) == 0, what + ": the answer outlived its deadline");
  pass(what);
}

void rldp_cases(Harness &h) {
  auto held = std::make_shared<Held>();
  h.subscribe(h.answerer_, "hint", std::make_unique<AnnotatingSubscriber>(held));
  h.subscribe(h.answerer_, "plain", std::make_unique<PlainSubscriber>());
  const td::uint64 small = 4096;

  auto annotated = [&](double request, size_t answer_size, std::optional<double> deadline_in, td::Timestamp &released) {
    begin_case(h, h.answerer_);
    auto result = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
    auto before = held->count();
    // Each outstanding query reserves its declared answer size on the
    // requester, so declare only what the answer needs.
    h.query(h.answerer_, td::BufferSlice("hint-query"), request, answer_size + 1024, result);
    h.run_for(10.0, [&] { return held->count() == before + 1 || result->has_value(); });
    require(held->count() == before + 1,
            "the annotated subscriber did not get its query" +
                (result->has_value() && (*result)->is_error() ? ": " + (*result)->error().to_string() : std::string()));
    released = td::Timestamp::now();
    auto deadline = deadline_in ? td::Timestamp::in(*deadline_in) : td::Timestamp{};
    h.run([&] { held->release(td::BufferSlice(std::string(answer_size, 'a')), deadline); });
  };

  {
    td::Timestamp released;
    annotated(50.0, 64, 3.0, released);
    expect_held_then_gone(h, h.answerer_, td::Timestamp::at(released.at() + 2.0),
                          td::Timestamp::at(released.at() + 4.0),
                          "a 3 s answer deadline ends the transfer despite a 50 s request");
  }
  {
    td::Timestamp released;
    annotated(6.0, 64, std::nullopt, released);
    expect_held_then_gone(h, h.answerer_, td::Timestamp::at(released.at() + 4.5),
                          td::Timestamp::at(released.at() + 7.0),
                          "a small unannotated answer keeps the request's deadline");
  }
  {
    td::Timestamp released;
    annotated(6.0, 2500000, std::nullopt, released);
    expect_held_then_gone(h, h.answerer_, td::Timestamp::at(released.at() + 4.5),
                          td::Timestamp::at(released.at() + 7.0),
                          "a multi-part unannotated answer keeps the request's deadline");
  }
  {
    td::Timestamp released;
    annotated(1.5, 64, 3.0, released);
    expect_held_then_gone(h, h.answerer_, td::Timestamp::at(released.at() + 0.7),
                          td::Timestamp::at(released.at() + 2.2),
                          "a request deadline under 3 s stays in charge of an annotated answer");
  }
  {
    td::Timestamp released;
    annotated(2.0, 64, 10.0, released);
    expect_held_then_gone(h, h.answerer_, td::Timestamp::at(released.at() + 1.0),
                          td::Timestamp::at(released.at() + 3.0),
                          "an answer deadline later than the request's does not extend it");
  }
  {
    begin_case(h, h.answerer_);
    auto result = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
    auto before = held->count();
    h.query(h.answerer_, td::BufferSlice("hint-expired"), 50.0, small, result);
    h.wait_for([&] { return held->count() == before + 1; }, "the annotated subscriber did not get its query");
    auto started = h.outbound(h.answerer_).started;
    auto expired = td::Timestamp::in(-1.0);
    h.run([&] { held->release(td::BufferSlice("late"), expired); });
    h.run_for(0.5);
    auto after = h.outbound(h.answerer_);
    require(after.started == started && after.live == 0, "an answer past its deadline still opened a transfer");
    pass("an answer past its deadline opens no transfer");
  }
  {
    begin_case(h, h.answerer_);
    auto result = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
    auto started = h.outbound(h.answerer_).started;
    auto sent = td::Timestamp::now();
    h.query(h.answerer_, td::BufferSlice("plain-query"), 6.0, small, result);
    h.wait_for([&] { return h.outbound(h.answerer_).started == started + 1; },
               "the plain subscriber's answer was not sent");
    expect_held_then_gone(h, h.answerer_, td::Timestamp::at(sent.at() + 4.5), td::Timestamp::at(sent.at() + 7.0),
                          "a plain subscriber answers through the annotated path with the request's deadline");
  }
}

// A query that arrives before its overlay exists waits in the overlay
// manager's buffer, and is answered once the overlay is created.
void buffered_cases(Harness &h) {
  // The manager buffers queries only for a local id it already serves.
  auto anchor = overlay::OverlayIdFull{td::BufferSlice("refusal-lifetime-anchor")};
  h.run([&] {
    td::actor::send_closure(h.overlays_, &overlay::Overlays::create_public_overlay, h.buffered_, anchor.clone(),
                            std::make_unique<PlainOverlayCallback>(), overlay::OverlayPrivacyRules{1 << 20},
                            std::string("anchor"));
  });
  h.run_for(0.2);

  auto run_case = [&](std::string name, double deadline_after_start, double buffered_for,
                      const std::function<void(td::Timestamp)> &check) {
    auto overlay_id = overlay::OverlayIdFull{td::BufferSlice("refusal-lifetime-" + name)};
    auto held = std::make_shared<Held>();
    begin_case(h, h.buffered_);
    auto start = td::Timestamp::now();
    auto deadline = td::Timestamp::at(start.at() + deadline_after_start);
    auto query = create_serialize_tl_object_suffix<tos_api::overlay_query>(td::Slice("not a known function"),
                                                                           overlay_id.compute_short_id().tl());
    auto result = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
    h.query(h.buffered_, std::move(query), 50.0, 1 << 20, result);
    h.run_for(buffered_for);
    require(held->count() == 0 && h.outbound(h.buffered_).live == 0,
            name + ": the query was not waiting in the buffer");
    auto started = h.outbound(h.buffered_).started;
    h.run([&] {
      td::actor::send_closure(h.overlays_, &overlay::Overlays::create_public_overlay, h.buffered_, overlay_id.clone(),
                              std::make_unique<AnnotatingOverlayCallback>(held), overlay::OverlayPrivacyRules{1 << 20},
                              name);
    });
    h.wait_for([&] { return held->count() == 1; }, name + ": the buffered query never reached its overlay");
    h.run([&] { held->release(td::BufferSlice("buffered answer"), deadline); });
    check(deadline);
    (void)started;
  };

  run_case("preserved", 4.0, 1.5, [&](td::Timestamp deadline) {
    expect_held_then_gone(h, h.buffered_, td::Timestamp::at(deadline.at() - 1.0),
                          td::Timestamp::at(deadline.at() + 0.8),
                          "a buffered query's answer keeps the deadline its answerer set");
  });
  run_case("expired", 1.0, 2.0, [&](td::Timestamp) {
    auto started = h.outbound(h.buffered_).started;
    h.run_for(0.5);
    auto after = h.outbound(h.buffered_);
    require(after.started == started && after.live == 0,
            "a buffered query's answer past its deadline still opened a transfer");
    pass("a buffered query's answer past its deadline opens no transfer");
  });
}

// The production shard and its admission, queried by the production
// downloader over real RLDP.
void production_path(Harness &h) {
  const ShardIdFull shard{basechainId, shardIdAll};
  const FileHash zero_state_file_hash = td::sha256_bits256("refusal-lifetime-zero-state");
  auto limiter = make_full_node_rate_limiter(full_node_rate_limits(1.0, 96, 64, 72));
  auto budget = std::make_shared<RefusalAnswerBudget>();
  h.run([&] {
    h.shard_ =
        FullNodeShard::create(shard, h.full_node_key_, h.full_node_, zero_state_file_hash, FullNodeOptions{}, limiter,
                              budget, h.keyring_.get(), h.adnl_.get(), h.rldp_.get(),
                              td::actor::ActorId<quic::QuicSender>{}, h.overlays_.get(), h.server_manager_.get(),
                              td::actor::ActorId<adnl::AdnlExtClient>{}, td::actor::ActorId<FullNode>{}, true, false);
  });
  h.run_for(0.3);
  auto overlay_hash =
      create_hash_tl_object<tos_api::tosNode_shardPublicOverlayId>(shard.workchain, shard.shard, zero_state_file_hash);
  td::BufferSlice name{32};
  name.as_slice().copy_from(as_slice(overlay_hash));
  auto overlay_id = overlay::OverlayIdFull{std::move(name)}.compute_short_id();

  // Spend the requester's allowance for block downloads, so its next one is
  // refused for capacity.
  for (int i = 0; i < 1000 && limiter->check_in(tos_api::tosNode_downloadBlockFull::ID, 1, shard, h.requester_); i++) {
  }

  auto download = [&](double timeout) {
    auto outcome = std::make_shared<std::optional<td::Result<ReceivedBlock>>>();
    BlockIdExt block{basechainId, shardIdAll, 9, td::sha256_bits256("root"), td::sha256_bits256("file")};
    h.run([&] {
      td::actor::create_actor<DownloadBlockNew>(
          "download", block, h.requester_, overlay_id, h.full_node_, 1, td::Timestamp::in(timeout),
          h.requester_manager_.get(), td::actor::ActorId<adnl::AdnlSenderInterface>(h.rldp_.get()), h.overlays_.get(),
          h.adnl_.get(), td::actor::ActorId<adnl::AdnlExtClient>{},
          [outcome](td::Result<ReceivedBlock> R) { *outcome = std::move(R); })
          .release();
    });
    return outcome;
  };

  // Delivered: the refusal reaches the downloader as notready, well within its
  // timeout, and its token is given back.
  {
    begin_case(h, h.full_node_);
    h.requester_receives(true);
    auto start = td::Timestamp::now();
    auto outcome = download(20.0);
    h.wait_for([&] { return outcome->has_value(); }, "the refused download never ended", 10.0);
    require((*outcome)->is_error() && (*outcome)->error().code() == ErrorCode::notready,
            "a refused download did not end in notready: " +
                ((*outcome)->is_error() ? (*outcome)->error().to_string() : std::string("a block")));
    require(td::Timestamp::now().at() - start.at() < 5.0, "the refused download waited most of its timeout");
    h.wait_for([&] { return h.requester_tokens_->load() == 0; }, "the refused download kept its token", 5.0);
    require(budget->answered() == 1, "the refusal was not answered by the shard's budget");
    pass("a capacity refusal reaches the production downloader as notready, and its token is given back");
  }

  // Cut off: the shard's refusal answer is dropped after the refusal lifetime,
  // although the request allows it far longer.
  {
    begin_case(h, h.full_node_);
    auto started = h.outbound(h.full_node_).started;
    auto outcome = download(20.0);
    h.wait_for([&] { return h.outbound(h.full_node_).started == started + 1; }, "the refusal answer was not sent");
    auto sent = td::Timestamp::now();
    require(budget->answered() == 2, "the second refusal was not answered by the shard's budget");
    expect_held_then_gone(h, h.full_node_, td::Timestamp::at(sent.at() + 2.0),
                          // The agreed refusal lifetime is 3 s; the request
                          // itself allows 15 s.
                          td::Timestamp::at(sent.at() + 4.0),
                          "the shard's refusal answer is dropped after the refusal lifetime, over the production path");
    h.requester_receives(true);
    h.wait_for([&] { return outcome->has_value(); }, "the cut-off download never ended", 25.0);
    h.wait_for([&] { return h.requester_tokens_->load() == 0; }, "the cut-off download kept its token", 5.0);
  }
}

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::set_default_failure_signal_handler().ensure();
  adapters();
  Harness h;
  rldp_cases(h);
  buffered_cases(h);
  production_path(h);
  std::printf("RLDP_REFUSAL_LIFETIME_OK\n");
  return 0;
}
