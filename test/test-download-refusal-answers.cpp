/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// A requester's download actors against a server whose overlay admission
// refuses them for capacity.
//
// The production download actors (DownloadBlockNew, DownloadNextBlocks,
// DownloadProof, DownloadState) send their queries through a stand-in
// transport, over the overlay path and over the external-client path. The
// stand-in hands each query to the production ShardQueryAdmission of a
// server shard, with tight limits and the production refusal-answer budget,
// exactly as FullNodeShardImpl::receive_query does; admitted queries get a
// canned successful answer. The validator manager is the production one with
// its start-up suppressed and the few calls the actors make answered here; it
// counts the download tokens it hands out.
//
// For every answered refusal the requester must fail with `notready` well
// within its own timeout and give its download token back, and a later retry
// in a fresh admission window must succeed. Each query a download sends must
// not outlive the download's own deadline, on either path, and that deadline
// is a property of the transport query separate from the token, which the
// download releases when it gives up.

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#include "adnl/adnl-ext-client.h"
#include "auto/tl/tos_api.hpp"
#include "overlay/overlays.h"
#include "quic/quic-sender.h"
#include "td/actor/actor.h"
#include "td/utils/Time.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "tl-utils/tl-utils.hpp"
#include "tos/tos-tl.hpp"
#include "validator/fabric.h"
#include "validator/full-node-shard-admission.h"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager.hpp"
#include "validator/net/download-block-new.hpp"
#include "validator/net/download-deadline.h"
#include "validator/net/download-next-blocks.hpp"
#include "validator/net/download-proof.hpp"
#include "validator/net/download-state.hpp"

namespace {

using namespace tos;
using namespace tos::validator;
using namespace tos::validator::fullnode;

[[noreturn]] void fail(const std::string &message) {
  std::fprintf(stderr, "DOWNLOAD_REFUSAL_ANSWERS_FAILURE: %s\n", message.c_str());
  std::fflush(stderr);
  std::_Exit(1);
}

void require(bool condition, const std::string &message) {
  if (!condition) {
    fail(message);
  }
}

template <class T>
void require_ok(const td::Result<T> &result, const std::string &what) {
  if (result.is_error()) {
    fail(what + ": " + result.error().to_string());
  }
}

template <class T>
void require_error(const td::Result<T> &result, int code, const std::string &what) {
  if (result.is_ok()) {
    fail(what + ": got a result");
  }
  if (result.error().code() != code) {
    fail(what + ": got " + result.error().to_string());
  }
}

td::Bits256 fill(unsigned char byte) {
  td::Bits256 value;
  for (auto &b : value.as_array()) {
    b = byte;
  }
  return value;
}

adnl::AdnlNodeIdShort node_id(unsigned char byte) {
  return adnl::AdnlNodeIdShort{fill(byte)};
}

// The requester as the server sees it, and the peer it downloads from.
const adnl::AdnlNodeIdShort k_requester = node_id(0x11);
const adnl::AdnlNodeIdShort k_server = node_id(0x22);

td::BufferSlice block_bytes(unsigned char tag) {
  return td::BufferSlice(std::string(64, static_cast<char>(tag)));
}

BlockIdExt block_with_data(int workchain, BlockSeqno seqno, const td::BufferSlice &data) {
  return BlockIdExt{workchain, shardIdAll, seqno, fill(static_cast<unsigned char>(seqno)),
                    td::sha256_bits256(data.as_slice())};
}

td::int32 query_id(const td::BufferSlice &query) {
  require(query.size() >= 4, "query too short");
  return *reinterpret_cast<const td::int32 *>(query.as_slice().data());
}

enum class Path { overlay, ext_client };

const char *path_name(Path path) {
  return path == Path::overlay ? "overlay" : "external client";
}

// One shard of the server: production admission with tight limits and the
// production refusal-answer budget, a still clock the test advances, and the
// successful answers for admitted queries.
class Server {
 public:
  struct Sent {
    td::int32 id;
    td::Timestamp deadline;
    Path path;
  };

  Server()
      // Medium 8: each source may hold 2 a window, enough for a proof's
      // preparation and download in one window.
      : limiter_(make_full_node_rate_limiter(full_node_rate_limits(1.0, 96, 64, 8)))
      , budget_(std::make_shared<RefusalAnswerBudget>(default_refusal_answer_limits(), td::Timestamp::at(clock_)))
      , admission_(limiter_, ShardIdFull{basechainId, shardIdAll}, budget_) {
    admission_.start();
  }

  // Spends the requester's allowance for `query` at the current clock, so
  // the next one of its kind is refused for capacity.
  void exhaust(const td::BufferSlice &query) {
    std::unique_lock lock(mutex_);
    for (int i = 0; i < 1000; i++) {
      auto result = admission_.admit(k_requester, query.clone(), td::Timestamp::at(clock_));
      if (!result.is_admitted()) {
        require(result.outcome() == QueryAdmission::Outcome::refused_for_capacity, "exhaust: not a refusal");
        return;
      }
    }
    fail("exhaust: never refused");
  }

  // Moves into a fresh admission window.
  void next_window() {
    std::unique_lock lock(mutex_);
    clock_ += 1.5;
  }

  void answer(td::int32 query, td::BufferSlice answer) {
    std::unique_lock lock(mutex_);
    answers_[query] = std::move(answer);
  }

  // Admitted queries of this type are held unanswered instead.
  void hold(td::int32 query) {
    std::unique_lock lock(mutex_);
    held_types_.insert(query);
  }

  void serve(td::BufferSlice query, td::Timestamp deadline, Path path, td::Promise<td::BufferSlice> promise) {
    std::unique_lock lock(mutex_);
    sent_.push_back(Sent{query_id(query), deadline, path});
    auto function = admission_.admit_or_answer(k_requester, std::move(query), promise, td::Timestamp::at(clock_));
    if (!function) {
      return;
    }
    if (held_types_.count(function->get_id())) {
      held_.push_back(std::move(promise));
      return;
    }
    auto it = answers_.find(function->get_id());
    if (it == answers_.end()) {
      promise.set_error(td::Status::Error("no canned answer"));
      return;
    }
    promise.set_value(it->second.clone());
  }

  std::vector<Sent> sent() {
    std::unique_lock lock(mutex_);
    return sent_;
  }
  void clear_sent() {
    std::unique_lock lock(mutex_);
    sent_.clear();
  }
  size_t held() {
    std::unique_lock lock(mutex_);
    return held_.size();
  }
  void release_held() {
    std::unique_lock lock(mutex_);
    for (auto &promise : held_) {
      promise.set_error(td::Status::Error(ErrorCode::timeout, "released"));
    }
    held_.clear();
  }
  td::uint64 answered_refusals() const {
    return budget_->answered();
  }

 private:
  std::mutex mutex_;
  double clock_ = 1000.0;
  std::shared_ptr<FullNodeRateLimiter> limiter_;
  std::shared_ptr<RefusalAnswerBudget> budget_;
  ShardQueryAdmission admission_;
  std::map<td::int32, td::BufferSlice> answers_;
  std::set<td::int32> held_types_;
  std::vector<td::Promise<td::BufferSlice>> held_;
  std::vector<Sent> sent_;
};

class FakeExtClient : public adnl::AdnlExtClient {
 public:
  explicit FakeExtClient(std::shared_ptr<Server> server) : server_(std::move(server)) {
  }
  void check_ready(td::Promise<td::Unit> promise) override {
    promise.set_value(td::Unit());
  }
  void send_query(std::string name, td::BufferSlice data, td::Timestamp timeout,
                  td::Promise<td::BufferSlice> promise) override {
    // The external client wraps every query in tosNode.query.
    require(query_id(data) == tos_api::tosNode_query::ID, "external query without its wrapper");
    data.confirm_read(4);
    server_->serve(std::move(data), timeout, Path::ext_client, std::move(promise));
  }

 private:
  std::shared_ptr<Server> server_;
};

class FakeOverlays : public overlay::Overlays {
 public:
  explicit FakeOverlays(std::shared_ptr<Server> server) : server_(std::move(server)) {
  }
  void send_query(adnl::AdnlNodeIdShort dst, adnl::AdnlNodeIdShort src, overlay::OverlayIdShort overlay_id,
                  std::string name, td::Promise<td::BufferSlice> promise, td::Timestamp timeout,
                  td::BufferSlice query) override {
    require(dst == k_server, "overlay query to an unexpected peer");
    server_->serve(std::move(query), timeout, Path::overlay, std::move(promise));
  }
  void send_query_via(adnl::AdnlNodeIdShort dst, adnl::AdnlNodeIdShort src, overlay::OverlayIdShort overlay_id,
                      std::string name, td::Promise<td::BufferSlice> promise, td::Timestamp timeout,
                      td::BufferSlice query, td::uint64 max_answer_size,
                      td::actor::ActorId<adnl::AdnlSenderInterface> via) override {
    require(dst == k_server, "overlay query to an unexpected peer");
    server_->serve(std::move(query), timeout, Path::overlay, std::move(promise));
  }
  void get_overlay_random_peers(adnl::AdnlNodeIdShort local_id, overlay::OverlayIdShort overlay, td::uint32 max_peers,
                                td::Promise<std::vector<adnl::AdnlNodeIdShort>> promise) override {
    promise.set_value({k_server});
  }

  void update_dht_node(td::actor::ActorId<dht::Dht>) override {
  }
  void create_public_overlay(adnl::AdnlNodeIdShort, overlay::OverlayIdFull, std::unique_ptr<Callback>,
                             overlay::OverlayPrivacyRules, td::string) override {
  }
  void create_public_overlay_ex(adnl::AdnlNodeIdShort, overlay::OverlayIdFull, std::unique_ptr<Callback>,
                                overlay::OverlayPrivacyRules, td::string, overlay::OverlayOptions) override {
  }
  void create_semiprivate_overlay(adnl::AdnlNodeIdShort, overlay::OverlayIdFull, std::vector<adnl::AdnlNodeIdShort>,
                                  std::vector<PublicKeyHash>, overlay::OverlayMemberCertificate,
                                  std::unique_ptr<Callback>, overlay::OverlayPrivacyRules, td::string,
                                  overlay::OverlayOptions) override {
  }
  void create_private_overlay(adnl::AdnlNodeIdShort, overlay::OverlayIdFull, std::vector<adnl::AdnlNodeIdShort>,
                              std::unique_ptr<Callback>, overlay::OverlayPrivacyRules, std::string) override {
  }
  void create_private_overlay_ex(adnl::AdnlNodeIdShort, overlay::OverlayIdFull, std::vector<adnl::AdnlNodeIdShort>,
                                 std::unique_ptr<Callback>, overlay::OverlayPrivacyRules, std::string,
                                 overlay::OverlayOptions) override {
  }
  void delete_overlay(adnl::AdnlNodeIdShort, overlay::OverlayIdShort) override {
  }
  void send_message(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, overlay::OverlayIdShort, td::BufferSlice) override {
  }
  void send_message_via(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, overlay::OverlayIdShort, td::BufferSlice,
                        td::actor::ActorId<adnl::AdnlSenderInterface>) override {
  }
  void send_broadcast(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, td::BufferSlice) override {
  }
  void send_broadcast_ex(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, PublicKeyHash, td::uint32,
                         td::BufferSlice) override {
  }
  void send_broadcast_fec(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, td::BufferSlice) override {
  }
  void send_broadcast_fec_ex(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, PublicKeyHash, td::uint32,
                             td::BufferSlice) override {
  }
  void send_broadcast_fec_with_extra(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, PublicKeyHash, td::uint32,
                                     td::BufferSlice, td::BufferSlice) override {
  }
  void send_broadcast_plumtree_fec(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, PublicKeyHash, td::uint32,
                                   td::BufferSlice) override {
  }
  void send_broadcast_plumtree(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, PublicKeyHash, td::uint32, td::Bits256,
                               td::BufferSlice) override {
  }
  void get_plumtree_stats_records(
      adnl::AdnlNodeIdShort, overlay::OverlayIdShort,
      td::Promise<std::vector<tl_object_ptr<tos_api::overlay_plumtreeStatsRecord>>> promise) override {
    promise.set_value({});
  }
  void set_privacy_rules(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, overlay::OverlayPrivacyRules) override {
  }
  void update_certificate(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, PublicKeyHash,
                          std::shared_ptr<overlay::Certificate>) override {
  }
  void update_member_certificate(adnl::AdnlNodeIdShort, overlay::OverlayIdShort,
                                 overlay::OverlayMemberCertificate) override {
  }
  void update_root_member_list(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, std::vector<adnl::AdnlNodeIdShort>,
                               std::vector<PublicKeyHash>, overlay::OverlayMemberCertificate) override {
  }
  void get_stats(td::Promise<tl_object_ptr<tos_api::engine_validator_overlaysStats>> promise) override {
    promise.set_error(td::Status::Error("no stats"));
  }
  void forget_peer(adnl::AdnlNodeIdShort, overlay::OverlayIdShort, adnl::AdnlNodeIdShort) override {
  }

 private:
  std::shared_ptr<Server> server_;
};

// The production manager with its start-up suppressed. It answers the calls
// the download actors make and counts live download tokens.
class Manager : public ValidatorManagerImpl {
 public:
  Manager(BlockIdExt zero_id, std::string root, std::shared_ptr<std::atomic<int>> live_tokens)
      : ValidatorManagerImpl(ValidatorManagerOptions::create(zero_id, zero_id), std::move(root), {}, {}, {}, {}, {})
      , live_tokens_(std::move(live_tokens)) {
  }

  void start_up() override {
  }

  void get_block_handle(BlockIdExt id, bool force, td::Promise<BlockHandle> promise) override {
    promise.set_value(create_empty_block_handle(id));
  }
  void get_download_token(size_t download_size, td::uint32 priority, td::Timestamp timeout,
                          td::Promise<std::unique_ptr<ActionToken>> promise) override {
    promise.set_value(std::make_unique<Token>(live_tokens_));
  }
  void validate_block_proof(BlockIdExt, td::BufferSlice, td::Promise<td::Unit> promise) override {
    promise.set_value(td::Unit());
  }
  void validate_block_proof_link(BlockIdExt, td::BufferSlice, td::Promise<td::Unit> promise) override {
    promise.set_value(td::Unit());
  }
  void validate_block_is_next_proof(BlockIdExt, BlockIdExt, td::BufferSlice, td::Promise<td::Unit> promise) override {
    promise.set_value(td::Unit());
  }
  void validate_block(ReceivedBlock block, td::Promise<BlockHandle> promise) override {
    promise.set_value(create_empty_block_handle(block.id));
  }
  void get_key_block_proof(BlockIdExt, td::Promise<td::BufferSlice> promise) override {
    promise.set_error(td::Status::Error(ErrorCode::notready, "not stored"));
  }
  void get_key_block_proof_link(BlockIdExt, td::Promise<td::BufferSlice> promise) override {
    promise.set_error(td::Status::Error(ErrorCode::notready, "not stored"));
  }
  void get_zero_state(BlockIdExt, td::Promise<td::BufferSlice> promise) override {
    promise.set_error(td::Status::Error(ErrorCode::notready, "not stored"));
  }
  void get_persistent_state(BlockIdExt, BlockIdExt, PersistentStateType,
                            td::Promise<td::BufferSlice> promise) override {
    promise.set_error(td::Status::Error(ErrorCode::notready, "not stored"));
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

template <class T>
struct Outcome {
  std::mutex mutex;
  std::optional<td::Result<T>> result;
  td::Timestamp at;

  td::Promise<T> promise(std::shared_ptr<Outcome> self) {
    return td::PromiseCreator::lambda([self](td::Result<T> R) {
      std::unique_lock lock(self->mutex);
      self->result = std::move(R);
      self->at = td::Timestamp::now();
    });
  }
  bool done() {
    std::unique_lock lock(mutex);
    return result.has_value();
  }
};

class Harness {
 public:
  Harness() {
    root_ = "/tmp/tos-download-refusal-answers-" + std::to_string(::getpid());
    td::rmrf(root_).ignore();
    require(td::mkdir(root_).is_ok(), "cannot create the work directory");
    scheduler_ = std::make_unique<td::actor::Scheduler>(std::vector<td::actor::Scheduler::NodeInfo>{2});
    live_tokens_ = std::make_shared<std::atomic<int>>(0);
    BlockIdExt zero{masterchainId, shardIdAll, 0, fill(0x01), fill(0x02)};
    scheduler_->run_in_context(
        [&] { manager_ = td::actor::create_actor<Manager>("manager", zero, root_ + "/db", live_tokens_); });
  }

  ~Harness() {
    scheduler_->run_in_context([&] {
      clients_.clear();
      overlays_.clear();
      manager_.reset();
    });
    scheduler_->run(0.2);
    scheduler_->stop();
    td::rmrf(root_).ignore();
  }

  // A transport to `server` on `path`: the overlay to use and the external
  // client to use, one of them empty.
  std::pair<td::actor::ActorId<overlay::Overlays>, td::actor::ActorId<adnl::AdnlExtClient>> transport(
      std::shared_ptr<Server> server, Path path) {
    std::pair<td::actor::ActorId<overlay::Overlays>, td::actor::ActorId<adnl::AdnlExtClient>> result;
    scheduler_->run_in_context([&] {
      if (path == Path::overlay) {
        overlays_.push_back(td::actor::create_actor<FakeOverlays>("overlays", server));
        result.first = overlays_.back().get();
      } else {
        clients_.push_back(td::actor::create_actor<FakeExtClient>("client", server));
        result.second = clients_.back().get();
      }
    });
    return result;
  }

  template <class F>
  void run(F &&f) {
    scheduler_->run_in_context(std::forward<F>(f));
  }

  template <class F>
  void wait_until(F &&done, const std::string &what, double limit = 20.0) {
    auto deadline = td::Timestamp::in(limit);
    while (!done()) {
      scheduler_->run(0.005);
      if (deadline.is_in_past()) {
        fail(what);
      }
    }
  }

  void settle(double seconds) {
    auto until = td::Timestamp::in(seconds);
    while (!until.is_in_past()) {
      scheduler_->run(0.005);
    }
  }

  td::actor::ActorId<ValidatorManagerInterface> manager() {
    return manager_.get();
  }
  int live_tokens() const {
    return live_tokens_->load();
  }

 private:
  std::string root_;
  std::unique_ptr<td::actor::Scheduler> scheduler_;
  std::shared_ptr<std::atomic<int>> live_tokens_;
  td::actor::ActorOwn<Manager> manager_;
  std::vector<td::actor::ActorOwn<FakeOverlays>> overlays_;
  std::vector<td::actor::ActorOwn<FakeExtClient>> clients_;
};

const overlay::OverlayIdShort k_overlay{fill(0x33)};
const adnl::AdnlNodeIdShort k_local = node_id(0x44);

// The peer to download from: named for the overlay path, chosen by the
// external client otherwise.
adnl::AdnlNodeIdShort peer_for(Path path) {
  return path == Path::overlay ? k_server : adnl::AdnlNodeIdShort::zero();
}

template <class T>
void require_refusal_is_retryable(Harness &h, const std::shared_ptr<Outcome<T>> &outcome, td::Timestamp started,
                                  double operation_timeout, const std::string &what) {
  h.wait_until([&] { return outcome->done(); }, what + ": no result");
  std::unique_lock lock(outcome->mutex);
  require_error(*outcome->result, ErrorCode::notready, what + ": a refusal must end in notready");
  // Well within the requester's own timeout: the refusal was answered, not
  // waited out.
  require(outcome->at.at() - started.at() < operation_timeout / 4,
          what + ": the refusal took most of the requester's timeout");
}

void download_block_full(Harness &h, Path path) {
  auto server = std::make_shared<Server>();
  auto data = block_bytes(0x5a);
  auto id = block_with_data(basechainId, 7, data);
  auto query = create_serialize_tl_object<tos_api::tosNode_downloadBlockFull>(create_tl_block_id(id));
  server->answer(tos_api::tosNode_downloadBlockFull::ID,
                 create_serialize_tl_object<tos_api::tosNode_dataFull>(create_tl_block_id(id), td::BufferSlice("proof"),
                                                                       data.clone(), false));
  auto [overlays, client] = h.transport(server, path);
  const double timeout = 10.0;
  std::string what = std::string("downloadBlockFull over the ") + path_name(path);

  server->exhaust(query);
  auto refused = std::make_shared<Outcome<ReceivedBlock>>();
  auto started = td::Timestamp::now();
  h.run([&] {
    td::actor::create_actor<DownloadBlockNew>("download", id, k_local, k_overlay, peer_for(path), 1,
                                              td::Timestamp::in(timeout), h.manager(),
                                              td::actor::ActorId<adnl::AdnlSenderInterface>{}, overlays,
                                              td::actor::ActorId<adnl::Adnl>{}, client, refused->promise(refused))
        .release();
  });
  require_refusal_is_retryable(h, refused, started, timeout, what);
  require(server->answered_refusals() == 1, what + ": the refusal was not answered");
  h.wait_until([&] { return h.live_tokens() == 0; }, what + ": the download token was not given back", 5.0);

  server->next_window();
  auto retried = std::make_shared<Outcome<ReceivedBlock>>();
  h.run([&] {
    td::actor::create_actor<DownloadBlockNew>("download", id, k_local, k_overlay, peer_for(path), 1,
                                              td::Timestamp::in(timeout), h.manager(),
                                              td::actor::ActorId<adnl::AdnlSenderInterface>{}, overlays,
                                              td::actor::ActorId<adnl::Adnl>{}, client, retried->promise(retried))
        .release();
  });
  h.wait_until([&] { return retried->done(); }, what + ": retry has no result");
  require_ok(*retried->result, what + ": retry failed");
  require(retried->result->ok().data.as_slice() == data.as_slice(), what + ": retry returned other data");
  h.wait_until([&] { return h.live_tokens() == 0; }, what + ": token kept after the retry", 5.0);
  std::printf("  ok: %s\n", what.c_str());
}

void download_next_blocks(Harness &h, Path path, bool allow_many) {
  auto server = std::make_shared<Server>();
  auto prev_data = block_bytes(0x10);
  auto prev = block_with_data(masterchainId, 10, prev_data);
  auto next_data = block_bytes(0x11);
  auto next = block_with_data(masterchainId, 11, next_data);
  auto full = [&] {
    return create_tl_object<tos_api::tosNode_dataFull>(create_tl_block_id(next), td::BufferSlice("proof"),
                                                       next_data.clone(), false);
  };
  td::BufferSlice query;
  td::int32 type;
  if (allow_many) {
    type = tos_api::tosNode_downloadNextBlocksFull::ID;
    query = create_serialize_tl_object<tos_api::tosNode_downloadNextBlocksFull>(create_tl_block_id(prev), 10);
    std::vector<tos_api::object_ptr<tos_api::tosNode_DataFull>> blocks;
    blocks.push_back(full());
    server->answer(type, create_serialize_tl_object<tos_api::tosNode_nextBlocksFull>(std::move(blocks)));
  } else {
    type = tos_api::tosNode_downloadNextBlockFull::ID;
    query = create_serialize_tl_object<tos_api::tosNode_downloadNextBlockFull>(create_tl_block_id(prev));
    server->answer(type, serialize_tl_object(full(), true));
  }
  auto [overlays, client] = h.transport(server, path);
  std::string what =
      std::string(allow_many ? "downloadNextBlocksFull" : "downloadNextBlockFull") + " over the " + path_name(path);

  server->exhaust(query);
  auto refused = std::make_shared<Outcome<BlockHandle>>();
  auto started = td::Timestamp::now();
  h.run([&] {
    td::actor::create_actor<DownloadNextBlocks>(
        "next", k_local, k_overlay, create_empty_block_handle(prev), peer_for(path), 1, allow_many, h.manager(),
        td::actor::ActorId<adnl::AdnlSenderInterface>{}, overlays, client, refused->promise(refused))
        .release();
  });
  // This download has no deadline of its own; its query is bounded at 5 s.
  require_refusal_is_retryable(h, refused, started, 5.0, what);
  require(server->answered_refusals() == 1, what + ": the refusal was not answered");

  server->next_window();
  auto retried = std::make_shared<Outcome<BlockHandle>>();
  h.run([&] {
    td::actor::create_actor<DownloadNextBlocks>(
        "next", k_local, k_overlay, create_empty_block_handle(prev), peer_for(path), 1, allow_many, h.manager(),
        td::actor::ActorId<adnl::AdnlSenderInterface>{}, overlays, client, retried->promise(retried))
        .release();
  });
  h.wait_until([&] { return retried->done(); }, what + ": retry has no result");
  require_ok(*retried->result, what + ": retry failed");
  require(retried->result->ok()->id() == next, what + ": retry downloaded another block");
  std::printf("  ok: %s\n", what.c_str());
}

void download_proof(Harness &h, Path path, bool key_block) {
  auto server = std::make_shared<Server>();
  auto id = key_block ? block_with_data(masterchainId, 20, block_bytes(0x20))
                      : block_with_data(basechainId, 21, block_bytes(0x21));
  td::BufferSlice query;
  if (key_block) {
    query = create_serialize_tl_object<tos_api::tosNode_prepareKeyBlockProof>(create_tl_block_id(id), false);
    server->answer(tos_api::tosNode_prepareKeyBlockProof::ID,
                   create_serialize_tl_object<tos_api::tosNode_preparedProof>());
    server->answer(tos_api::tosNode_downloadKeyBlockProof::ID, td::BufferSlice("the proof"));
  } else {
    query = create_serialize_tl_object<tos_api::tosNode_prepareBlockProof>(create_tl_block_id(id), false);
    server->answer(tos_api::tosNode_prepareBlockProof::ID,
                   create_serialize_tl_object<tos_api::tosNode_preparedProof>());
    server->answer(tos_api::tosNode_downloadBlockProof::ID, td::BufferSlice("the proof"));
  }
  auto [overlays, client] = h.transport(server, path);
  const double timeout = 10.0;
  std::string what =
      std::string(key_block ? "prepareKeyBlockProof" : "prepareBlockProof") + " over the " + path_name(path);

  server->exhaust(query);
  auto refused = std::make_shared<Outcome<td::BufferSlice>>();
  auto started = td::Timestamp::now();
  auto start = [&](std::shared_ptr<Outcome<td::BufferSlice>> outcome) {
    h.run([&] {
      td::actor::create_actor<DownloadProof>("proof", id, false, key_block, k_local, k_overlay, peer_for(path), 1,
                                             td::Timestamp::in(timeout), h.manager(),
                                             td::actor::ActorId<adnl::AdnlSenderInterface>{}, overlays,
                                             td::actor::ActorId<adnl::Adnl>{}, client, outcome->promise(outcome))
          .release();
    });
  };
  start(refused);
  require_refusal_is_retryable(h, refused, started, timeout, what);
  require(server->answered_refusals() == 1, what + ": the refusal was not answered");
  h.wait_until([&] { return h.live_tokens() == 0; }, what + ": the download token was not given back", 5.0);

  server->next_window();
  auto retried = std::make_shared<Outcome<td::BufferSlice>>();
  start(retried);
  h.wait_until([&] { return retried->done(); }, what + ": retry has no result");
  require_ok(*retried->result, what + ": retry failed");
  require(retried->result->ok().as_slice() == "the proof", what + ": retry returned another proof");
  h.wait_until([&] { return h.live_tokens() == 0; }, what + ": token kept after the retry", 5.0);
  std::printf("  ok: %s\n", what.c_str());
}

void download_state(Harness &h, Path path, bool zero_state) {
  auto server = std::make_shared<Server>();
  auto state = td::BufferSlice(std::string(1000, 's'));
  BlockIdExt id = zero_state ? BlockIdExt{basechainId, shardIdAll, 0, fill(0x30), fill(0x31)}
                             : BlockIdExt{basechainId, shardIdAll, 30, fill(0x32), fill(0x33)};
  BlockIdExt masterchain_id =
      zero_state ? BlockIdExt{} : BlockIdExt{masterchainId, shardIdAll, 40, fill(0x34), fill(0x35)};
  td::BufferSlice query;
  if (zero_state) {
    query = create_serialize_tl_object<tos_api::tosNode_prepareZeroState>(create_tl_block_id(id));
    server->answer(tos_api::tosNode_prepareZeroState::ID, create_serialize_tl_object<tos_api::tosNode_preparedState>());
    server->answer(tos_api::tosNode_downloadZeroState::ID, state.clone());
  } else {
    query = create_serialize_tl_object<tos_api::tosNode_preparePersistentState>(create_tl_block_id(id),
                                                                                create_tl_block_id(masterchain_id));
    server->answer(tos_api::tosNode_preparePersistentState::ID,
                   create_serialize_tl_object<tos_api::tosNode_preparedState>());
    server->answer(
        tos_api::tosNode_getPersistentStateSizeV2::ID,
        create_serialize_tl_object<tos_api::tosNode_persistentStateSize>(static_cast<td::int64>(state.size())));
    server->answer(tos_api::tosNode_downloadPersistentStateSliceV2::ID, state.clone());
  }
  auto [overlays, client] = h.transport(server, path);
  const double timeout = 10.0;
  std::string what =
      std::string(zero_state ? "prepareZeroState" : "preparePersistentState") + " over the " + path_name(path);

  server->exhaust(query);
  auto refused = std::make_shared<Outcome<DownloadedPersistentState>>();
  auto started = td::Timestamp::now();
  auto start = [&](std::shared_ptr<Outcome<DownloadedPersistentState>> outcome) {
    h.run([&] {
      td::actor::create_actor<DownloadState>("state", id, masterchain_id, UnsplitStateType{}, k_local, k_overlay,
                                             peer_for(path), 1, td::Timestamp::in(timeout), h.manager(),
                                             td::actor::ActorId<adnl::AdnlSenderInterface>{}, overlays,
                                             td::actor::ActorId<adnl::Adnl>{}, client, outcome->promise(outcome))
          .release();
    });
  };
  start(refused);
  require_refusal_is_retryable(h, refused, started, timeout, what);
  require(server->answered_refusals() == 1, what + ": the refusal was not answered");

  server->next_window();
  auto retried = std::make_shared<Outcome<DownloadedPersistentState>>();
  start(retried);
  h.wait_until([&] { return retried->done(); }, what + ": retry has no result");
  require_ok(*retried->result, what + ": retry failed");
  std::printf("  ok: %s\n", what.c_str());
}

// Each query a download sends is bounded by the download's own deadline, not
// only by the query's: on both paths, for the first query and the later
// ones. The token is given back when the download gives up, while the held
// transport query lives on until its own, capped, deadline.
void query_deadlines(Harness &h, Path path) {
  std::string where = std::string(" over the ") + path_name(path);
  const double tolerance = 1e-6;

  {
    auto server = std::make_shared<Server>();
    auto id = block_with_data(basechainId, 50, block_bytes(0x50));
    server->hold(tos_api::tosNode_downloadBlockFull::ID);
    auto [overlays, client] = h.transport(server, path);
    auto outcome = std::make_shared<Outcome<ReceivedBlock>>();
    td::Timestamp deadline;
    h.run([&] {
      deadline = td::Timestamp::in(1.0);
      td::actor::create_actor<DownloadBlockNew>("download", id, k_local, k_overlay, peer_for(path), 1, deadline,
                                                h.manager(), td::actor::ActorId<adnl::AdnlSenderInterface>{}, overlays,
                                                td::actor::ActorId<adnl::Adnl>{}, client, outcome->promise(outcome))
          .release();
    });
    h.wait_until([&] { return server->held() == 1; }, "block query was not sent" + where);
    auto sent = server->sent();
    require(sent.size() == 1 && sent[0].path == path, "block query took another path" + where);
    require(sent[0].deadline.at() <= deadline.at() + tolerance,
            "block query outlives its download (15 s bound not capped)" + where);
    // The download gives up at its deadline and gives its token back, while
    // the transport still holds the query.
    h.wait_until([&] { return outcome->done(); }, "block download did not give up" + where);
    require_error(*outcome->result, ErrorCode::timeout, "block download did not time out" + where);
    h.wait_until([&] { return h.live_tokens() == 0; }, "block download kept its token" + where, 5.0);
    require(server->held() == 1, "the held query disappeared" + where);
    server->release_held();
  }

  {
    auto server = std::make_shared<Server>();
    auto id = block_with_data(basechainId, 51, block_bytes(0x51));
    server->answer(tos_api::tosNode_prepareBlockProof::ID,
                   create_serialize_tl_object<tos_api::tosNode_preparedProof>());
    server->hold(tos_api::tosNode_downloadBlockProof::ID);
    auto [overlays, client] = h.transport(server, path);
    auto outcome = std::make_shared<Outcome<td::BufferSlice>>();
    td::Timestamp deadline;
    h.run([&] {
      deadline = td::Timestamp::in(0.8);
      td::actor::create_actor<DownloadProof>("proof", id, false, false, k_local, k_overlay, peer_for(path), 1, deadline,
                                             h.manager(), td::actor::ActorId<adnl::AdnlSenderInterface>{}, overlays,
                                             td::actor::ActorId<adnl::Adnl>{}, client, outcome->promise(outcome))
          .release();
    });
    h.wait_until([&] { return server->held() == 1 || outcome->done(); }, "proof queries were not sent" + where);
    auto sent = server->sent();
    require(!sent.empty(), "no proof query was sent" + where);
    for (auto &s : sent) {
      require(s.deadline.at() <= deadline.at() + tolerance, "a proof query outlives its download" + where);
    }
    h.wait_until([&] { return outcome->done(); }, "proof download did not end" + where);
    h.wait_until([&] { return h.live_tokens() == 0; }, "proof download kept its token" + where, 5.0);
    server->release_held();
  }

  {
    auto server = std::make_shared<Server>();
    BlockIdExt id{basechainId, shardIdAll, 0, fill(0x52), fill(0x53)};
    server->answer(tos_api::tosNode_prepareZeroState::ID, create_serialize_tl_object<tos_api::tosNode_preparedState>());
    server->hold(tos_api::tosNode_downloadZeroState::ID);
    auto [overlays, client] = h.transport(server, path);
    auto outcome = std::make_shared<Outcome<DownloadedPersistentState>>();
    td::Timestamp deadline;
    h.run([&] {
      deadline = td::Timestamp::in(0.8);
      td::actor::create_actor<DownloadState>("state", id, BlockIdExt{}, UnsplitStateType{}, k_local, k_overlay,
                                             peer_for(path), 1, deadline, h.manager(),
                                             td::actor::ActorId<adnl::AdnlSenderInterface>{}, overlays,
                                             td::actor::ActorId<adnl::Adnl>{}, client, outcome->promise(outcome))
          .release();
    });
    h.wait_until([&] { return server->held() == 1 || outcome->done(); }, "state queries were not sent" + where);
    auto sent = server->sent();
    require(!sent.empty(), "no state query was sent" + where);
    for (auto &s : sent) {
      require(s.deadline.at() <= deadline.at() + tolerance, "a state query outlives its download" + where);
    }
    h.wait_until([&] { return outcome->done(); }, "state download did not end" + where);
    server->release_held();
  }

  {
    // A download whose deadline has passed sends nothing at all.
    auto server = std::make_shared<Server>();
    auto id = block_with_data(basechainId, 54, block_bytes(0x54));
    auto [overlays, client] = h.transport(server, path);
    auto outcome = std::make_shared<Outcome<ReceivedBlock>>();
    h.run([&] {
      td::actor::create_actor<DownloadBlockNew>("download", id, k_local, k_overlay, peer_for(path), 1,
                                                td::Timestamp::in(-1.0), h.manager(),
                                                td::actor::ActorId<adnl::AdnlSenderInterface>{}, overlays,
                                                td::actor::ActorId<adnl::Adnl>{}, client, outcome->promise(outcome))
          .release();
    });
    h.wait_until([&] { return outcome->done(); }, "expired download did not end" + where);
    h.settle(0.1);
    require(server->sent().empty(), "an expired download sent a query" + where);
    require_error(*outcome->result, ErrorCode::timeout, "an expired download did not time out" + where);
  }
  std::printf("  ok: query deadlines%s\n", where.c_str());
}

void deadline_rule() {
  auto now = td::Timestamp::at(500.0);
  // Capped by the download's deadline.
  auto capped = download_query_deadline(td::Timestamp::at(502.0), 15.0, now);
  require(capped.is_ok() && capped.ok().at() == 502.0, "query deadline not capped by the download");
  // The query's own bound when it is the earlier one.
  auto own = download_query_deadline(td::Timestamp::at(600.0), 3.0, now);
  require(own.is_ok() && own.ok().at() == 503.0, "query deadline not its own bound");
  // A download without a deadline keeps the query's bound.
  auto unbounded = download_query_deadline(td::Timestamp::never(), 20.0, now);
  require(unbounded.is_ok() && unbounded.ok().at() == 520.0, "unbounded download changed the query deadline");
  // A download at or past its deadline sends nothing.
  auto at_deadline = download_query_deadline(td::Timestamp::at(500.0), 15.0, now);
  require(at_deadline.is_error() && at_deadline.error().code() == ErrorCode::timeout,
          "a download at its deadline may still send");
  auto expired = download_query_deadline(td::Timestamp::at(499.0), 15.0, now);
  require(expired.is_error() && expired.error().code() == ErrorCode::timeout, "an expired download may still send");
  std::printf("  ok: query deadline rule\n");
}

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  deadline_rule();
  Harness harness;
  for (auto path : {Path::overlay, Path::ext_client}) {
    download_block_full(harness, path);
    download_next_blocks(harness, path, false);
    download_next_blocks(harness, path, true);
    download_proof(harness, path, false);
    download_proof(harness, path, true);
    download_state(harness, path, true);
    download_state(harness, path, false);
    query_deadlines(harness, path);
  }
  std::printf("DOWNLOAD_REFUSAL_ANSWERS_OK\n");
  return 0;
}
