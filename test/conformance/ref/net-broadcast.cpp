// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// net harness, overlay broadcasts: the node's own overlay manager and overlay actors (simple, FEC and
// two-step broadcasts) for a fixed-member overlay whose members all run in-process on one single-threaded
// scheduler. The only stand-ins are at the network edge: an ADNL that records what an overlay sends and
// hands it to the subscribed overlay manager of its destination, and the two-step sender. The node's
// wall clock is fixed at the context's `now` (net-node.h), so dates, broadcast ids and signatures are
// functions of the context.
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "adnl/adnl-sender-ex.h"
#include "adnl/adnl.h"
#include "auto/tl/tos_api.hpp"
#include "keyring/keyring.h"
#include "keys/keys.hpp"
#include "overlay/overlay-manager.h"
#include "overlay/overlay.hpp"
#include "td/actor/actor.h"
#include "td/utils/crypto.h"
#include "tl-utils/tl-utils.hpp"

#include "net-common.h"
#include "net-node.h"

namespace conformance::net {

namespace adnl = tos::adnl;
namespace overlay = tos::overlay;
namespace tos_api = tos::tos_api;

namespace {

constexpr std::size_t kMinMembers = 2;
constexpr std::size_t kMaxMembers = 8;
constexpr std::size_t kMaxInbound = 64;
// Messages the members may emit before a context is cut off as not settling.
constexpr std::size_t kMaxEmitted = 1024;
constexpr int kMaxRounds = 20000;
// Rounds without a new emitted message or delivery after which the members are taken to be idle.
constexpr int kIdleRounds = 64;
// The FEC sender emits four symbols at once and the rest on a 10 ms timer; below this size the first
// four are all it sends (BroadcastFecActor: (size / 768 + 1) * 2 symbols), so the context does not depend
// on how fast it runs.
constexpr std::size_t kMaxFecData = 1535;

std::string bits(const td::Bits256 &value) {
  return hex(value.as_slice());
}

// What the edge and the members' callbacks saw, read by the caller between scheduler rounds.
struct Emitted {
  adnl::AdnlNodeIdShort src;
  adnl::AdnlNodeIdShort dst;
  std::string via;
  std::string data;
};
struct Delivered {
  std::size_t member;
  std::string kind;  // "broadcast" or "message"
  td::Bits256 source;
  std::string data;
  std::string extra;
};
struct Record {
  std::vector<Emitted> emitted;
  std::vector<Delivered> delivered;
};

// The ADNL below the overlay manager: subscriptions per local id, messages recorded and handed to the
// destination's subscriber with the longest matching prefix, as AdnlLocalId::deliver does. Queries are
// refused: no context needs an answer from a peer.
class EdgeAdnl final : public adnl::Adnl {
 public:
  explicit EdgeAdnl(std::shared_ptr<Record> record) : record_(std::move(record)) {
  }

  void send_message(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data) override {
    record_->emitted.push_back(Emitted{src, dst, "adnl", data.as_slice().str()});
  }
  void send_message_ex(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data,
                       td::uint32) override {
    send_message(src, dst, std::move(data));
  }
  void send_query(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, std::string, td::Promise<td::BufferSlice> promise,
                  td::Timestamp, td::BufferSlice) override {
    promise.set_error(td::Status::Error(tos::ErrorCode::notready, "queries are not served at the network edge"));
  }
  void send_query_ex(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, std::string, td::Promise<td::BufferSlice> promise,
                     td::Timestamp, td::BufferSlice, td::uint64) override {
    promise.set_error(td::Status::Error(tos::ErrorCode::notready, "queries are not served at the network edge"));
  }
  void get_conn_ip_str(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::Promise<td::string> promise) override {
    promise.set_value("network edge");
  }
  void add_peer(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdFull, adnl::AdnlAddressList) override {
  }
  void add_static_nodes_from_config(adnl::AdnlNodesList) override {
  }
  void add_id_ex(adnl::AdnlNodeIdFull, adnl::AdnlAddressList, td::uint8, td::uint32) override {
  }
  void del_id(adnl::AdnlNodeIdShort, td::Promise<td::Unit> promise) override {
    promise.set_value(td::Unit());
  }
  void check_id_exists(adnl::AdnlNodeIdShort id, td::Promise<bool> promise) override {
    promise.set_value(subscribers_.count(id) != 0);
  }
  void subscribe(adnl::AdnlNodeIdShort dst, std::string prefix, std::unique_ptr<Callback> callback) override {
    subscribers_[dst].emplace_back(std::move(prefix), std::move(callback));
  }
  void unsubscribe(adnl::AdnlNodeIdShort dst, std::string prefix) override {
    auto it = subscribers_.find(dst);
    if (it == subscribers_.end()) {
      return;
    }
    std::erase_if(it->second, [&](const auto &entry) { return entry.first == prefix; });
  }
  void register_dht_node(td::actor::ActorId<tos::dht::Dht>) override {
  }
  void register_network_manager(td::actor::ActorId<adnl::AdnlNetworkManager>) override {
  }
  void get_addr_list(adnl::AdnlNodeIdShort, td::Promise<adnl::AdnlAddressList> promise) override {
    promise.set_value(adnl::AdnlAddressList{});
  }
  void get_self_node(adnl::AdnlNodeIdShort, td::Promise<adnl::AdnlNode> promise) override {
    promise.set_error(td::Status::Error(tos::ErrorCode::notready, "not served at the network edge"));
  }
  void get_peer_node(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::Promise<adnl::AdnlNode> promise) override {
    promise.set_error(td::Status::Error(tos::ErrorCode::notready, "not served at the network edge"));
  }
  void create_ext_server(std::vector<adnl::AdnlNodeIdShort>, std::vector<td::uint16>,
                         td::Promise<td::actor::ActorOwn<adnl::AdnlExtServer>> promise) override {
    promise.set_error(td::Status::Error(tos::ErrorCode::notready, "not served at the network edge"));
  }
  void create_tunnel(
      adnl::AdnlNodeIdShort, td::uint32,
      td::Promise<std::pair<td::actor::ActorOwn<adnl::AdnlTunnel>, adnl::AdnlAddress>> promise) override {
    promise.set_error(td::Status::Error(tos::ErrorCode::notready, "not served at the network edge"));
  }
  void get_stats(bool, td::Promise<tos::tl_object_ptr<tos_api::adnl_stats>> promise) override {
    promise.set_error(td::Status::Error(tos::ErrorCode::notready, "not served at the network edge"));
  }

  // One message as the destination's ADNL hands it to its subscriber (AdnlLocalId::deliver).
  void deliver(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data) {
    auto it = subscribers_.find(dst);
    if (it == subscribers_.end()) {
      return;
    }
    for (auto &[prefix, callback] : it->second) {
      if (prefix.size() <= data.size() && data.as_slice().substr(0, prefix.size()) == prefix) {
        callback->receive_message(src, dst, std::move(data));
        return;
      }
    }
  }

 protected:
  void add_protected_peers(adnl::AdnlNodeIdShort, std::vector<adnl::AdnlNodeIdShort>) override {
  }
  void remove_protected_peers(adnl::AdnlNodeIdShort, std::vector<adnl::AdnlNodeIdShort>) override {
  }

 private:
  std::shared_ptr<Record> record_;
  std::map<adnl::AdnlNodeIdShort, std::vector<std::pair<std::string, std::unique_ptr<Callback>>>> subscribers_;
};

// The transport a two-step broadcast is sent through (an RLDP-style sender in a node): recorded the same
// way, and delivered through the destination's ADNL subscription like every other message.
class EdgeSender final : public adnl::AdnlSenderEx {
 public:
  explicit EdgeSender(std::shared_ptr<Record> record) : record_(std::move(record)) {
  }
  void add_id(adnl::AdnlNodeIdShort) override {
  }
  void send_message(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data) override {
    record_->emitted.push_back(Emitted{src, dst, "sender", data.as_slice().str()});
  }
  void send_query(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, std::string, td::Promise<td::BufferSlice> promise,
                  td::Timestamp, td::BufferSlice) override {
    promise.set_error(td::Status::Error(tos::ErrorCode::notready, "queries are not served at the network edge"));
  }
  void send_query_ex(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, std::string, td::Promise<td::BufferSlice> promise,
                     td::Timestamp, td::BufferSlice, td::uint64) override {
    promise.set_error(td::Status::Error(tos::ErrorCode::notready, "queries are not served at the network edge"));
  }
  void get_conn_ip_str(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::Promise<td::string> promise) override {
    promise.set_value("network edge");
  }

 protected:
  void on_mtu_updated(td::optional<adnl::AdnlNodeIdShort>, td::optional<adnl::AdnlNodeIdShort>) override {
  }

 private:
  std::shared_ptr<Record> record_;
};

// The application above one member's overlay: records what it is given and accepts every broadcast it is
// asked to check (the overlay asks when the source is not allowed outright by the privacy rules).
class MemberCallback final : public overlay::Overlays::Callback {
 public:
  MemberCallback(std::shared_ptr<Record> record, std::size_t member) : record_(std::move(record)), member_(member) {
  }
  void receive_message(adnl::AdnlNodeIdShort src, overlay::OverlayIdShort, td::BufferSlice data) override {
    record_->delivered.push_back(Delivered{member_, "message", src.bits256_value(), data.as_slice().str(), {}});
  }
  void receive_broadcast_with_extra(tos::PublicKeyHash src, overlay::OverlayIdShort, td::BufferSlice data,
                                    td::BufferSlice extra) override {
    record_->delivered.push_back(
        Delivered{member_, "broadcast", src.bits256_value(), data.as_slice().str(), extra.as_slice().str()});
  }

 private:
  std::shared_ptr<Record> record_;
  std::size_t member_;
};

// The name of a TL constructor the overlay sends, for the effect; any other is its id.
std::string message_type(td::Slice data) {
  auto body = data;
  if (tos::fetch_tl_prefix<tos_api::overlay_messageWithExtra>(body, true).is_error()) {
    body = data;
    if (tos::fetch_tl_prefix<tos_api::overlay_message>(body, true).is_error()) {
      return "not_overlay";
    }
  }
  if (body.size() < 4) {
    return "short";
  }
  td::int32 id = 0;
  std::memcpy(&id, body.data(), 4);
  switch (id) {
    case tos_api::overlay_broadcast::ID:
      return "overlay.broadcast";
    case tos_api::overlay_broadcastFec::ID:
      return "overlay.broadcastFec";
    case tos_api::overlay_broadcastFecShort::ID:
      return "overlay.broadcastFecShort";
    case tos_api::overlay_fec_received::ID:
      return "overlay.fec.received";
    case tos_api::overlay_fec_completed::ID:
      return "overlay.fec.completed";
    case tos_api::overlay_broadcastTwostepSimple::ID:
      return "overlay.broadcastTwostepSimple";
    case tos_api::overlay_broadcastTwostepFec::ID:
      return "overlay.broadcastTwostepFec";
    case tos_api::overlay_unicast::ID:
      return "overlay.unicast";
    case tos_api::overlay_broadcastNotFound::ID:
      return "overlay.broadcastNotFound";
    case tos_api::overlay_broadcastPlumtreeSimple::ID:
      return "overlay.broadcastPlumtreeSimple";
    case tos_api::overlay_broadcastPlumtreeFec::ID:
      return "overlay.broadcastPlumtreeFec";
    case tos_api::overlay_broadcastPlumtreeIHave::ID:
      return "overlay.broadcastPlumtreeIHave";
    case tos_api::overlay_broadcastPlumtreePrune::ID:
      return "overlay.broadcastPlumtreePrune";
    case tos_api::overlay_broadcastPlumtreeUseful::ID:
      return "overlay.broadcastPlumtreeUseful";
    default:
      return PSTRING() << "id:" << static_cast<td::uint32>(id);
  }
}

// Texts that open the overlay's log line for a message or broadcast it drops.
constexpr td::Slice kDropMarkers[] = {
    "Failed to process broadcast",          "received message in private overlay from unknown source",
    "can not parse overlay message",        "message to unknown overlay",
    "message to localid is not in overlay", "dropping certificate from",
    "received message from banned peer",
};

struct Member {
  tos::PrivateKey key;
  adnl::AdnlNodeIdShort id;
};

td::Result<std::vector<Member>> members_field(td::JsonObject &ctx) {
  TRY_RESULT(value, array_field(ctx, "members", kMaxMembers));
  auto &items = value.get_array();
  if (items.size() < kMinMembers) {
    return td::Status::Error("members: two to eight Ed25519 private keys required");
  }
  std::vector<Member> members;
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (items[i].type() != td::JsonValue::Type::String) {
      return td::Status::Error(PSLICE() << "members[" << i << "]: hex required");
    }
    auto bytes = td::hex_decode(items[i].get_string());
    if (bytes.is_error() || bytes.ok().size() > 4096) {
      return td::Status::Error(PSLICE() << "members[" << i << "]: hex of at most 4096 bytes required");
    }
    auto tl = tos::fetch_tl_object<tos_api::PrivateKey>(td::Slice(bytes.ok()), true);
    if (tl.is_error()) {
      return td::Status::Error(PSLICE() << "members[" << i << "]: not a TL PrivateKey: " << tl.error().message());
    }
    tos::PrivateKey key{tl.ok()};
    auto public_key = key.compute_public_key();
    if (!public_key.is_ed25519()) {
      return td::Status::Error(PSLICE() << "members[" << i << "]: an Ed25519 key required");
    }
    adnl::AdnlNodeIdShort id{public_key.compute_short_id()};
    for (const auto &other : members) {
      if (other.id == id) {
        return td::Status::Error(PSLICE() << "members[" << i << "]: repeated key");
      }
    }
    members.push_back(Member{std::move(key), id});
  }
  return members;
}

struct Inbound {
  adnl::AdnlNodeIdShort src;
  std::size_t dst;
  std::string data;
};

td::Result<std::vector<Inbound>> inbound_field(td::JsonObject &ctx, std::size_t members) {
  std::vector<Inbound> inbound;
  if (!ctx.has_field("inbound")) {
    return inbound;
  }
  TRY_RESULT(value, array_field(ctx, "inbound", kMaxInbound));
  for (auto &item : value.get_array()) {
    if (item.type() != td::JsonValue::Type::Object) {
      return td::Status::Error("inbound: objects required");
    }
    auto &entry = item.get_object();
    TRY_RESULT(src, bits256_field(entry, "src"));
    TRY_RESULT(dst, uint32_field(entry, "dst"));
    TRY_RESULT(data, hex_field(entry, "message"));
    if (dst >= members) {
      return td::Status::Error("inbound.dst: a member index required");
    }
    inbound.push_back(Inbound{adnl::AdnlNodeIdShort{src}, dst, std::move(data)});
  }
  return inbound;
}

std::string member_text(const std::vector<Member> &members, const adnl::AdnlNodeIdShort &id) {
  for (std::size_t i = 0; i < members.size(); ++i) {
    if (members[i].id == id) {
      return std::to_string(i);
    }
  }
  return quote(bits(id.bits256_value()));
}

}  // namespace

// One broadcast scenario on a fixed-member overlay: optionally member 0 sends a broadcast through the
// overlay manager (send_broadcast_ex, or send_broadcast_fec_ex when `broadcast.fec`), and optionally
// messages arrive at members from given ADNL ids. Every message a member emits is recorded and handed to
// its destination member, until every member is idle. The effect lists what was emitted (in order, with
// its bytes), what each member's application received, and the overlay's drops with their classes.
td::Result<std::string> op_overlay_broadcast(td::JsonObject &ctx) {
  TRY_RESULT(now, int32_field(ctx, "now"));
  // The node converts the clock to an unsigned date; a time before 1970 has no defined conversion.
  if (now < 1) {
    return td::Status::Error("now: a positive unix time required");
  }
  TRY_RESULT(name, hex_field(ctx, "name"));
  TRY_RESULT(members, members_field(ctx));
  TRY_RESULT(mode, ctx.get_required_string_field("mode"));
  if (mode != "simple" && mode != "fec" && mode != "twostep" && mode != "plumtree") {
    return td::Status::Error("mode: simple, fec, twostep or plumtree required");
  }
  TRY_RESULT(max_unauth_size, uint32_field(ctx, "max_unauth_size"));
  TRY_RESULT(rule_flags, uint32_field(ctx, "flags"));
  TRY_RESULT(keys_value, array_field(ctx, "authorized_keys", 1024));
  std::map<tos::PublicKeyHash, td::uint32> authorized;
  for (auto &item : keys_value.get_array()) {
    if (item.type() != td::JsonValue::Type::Object) {
      return td::Status::Error("authorized_keys: objects required");
    }
    auto &entry = item.get_object();
    TRY_RESULT(key, bits256_field(entry, "key"));
    TRY_RESULT(limit, uint32_field(entry, "max_size"));
    if (!authorized.emplace(tos::PublicKeyHash{key}, limit).second) {
      return td::Status::Error("authorized_keys: repeated key");
    }
  }
  bool send = ctx.has_field("broadcast");
  std::string send_data;
  td::uint32 send_flags = 0;
  bool send_fec = false;
  if (send) {
    td::JsonValue holder;
    TRY_RESULT_ASSIGN(holder, ctx.extract_required_field("broadcast", td::JsonValue::Type::Object));
    auto &spec = holder.get_object();
    TRY_RESULT_ASSIGN(send_data, hex_field(spec, "data"));
    TRY_RESULT_ASSIGN(send_flags, uint32_field(spec, "flags"));
    TRY_RESULT_ASSIGN(send_fec, bool_field(spec, "fec"));
    // OverlayManager::send_broadcast_ex requires a simple broadcast to fit (a CHECK: its callers choose
    // the FEC path above that size), so a larger one is the local caller's error, not a node verdict.
    if (!send_fec && send_data.size() > overlay::Overlays::max_simple_broadcast_size()) {
      return td::Status::Error(PSLICE() << "broadcast.data: at most " << overlay::Overlays::max_simple_broadcast_size()
                                        << " bytes for a simple broadcast");
    }
  }
  // The path the node takes for the send, as OverlayImpl dispatches it: a simple send is always the
  // simple path; a FEC send is two-step only when two-step sending is on and BroadcastFlagNoTwostep is
  // clear, and the old FEC path otherwise. The limits below follow that path, not the declared mode.
  const bool twostep_path =
      send && mode == "twostep" && send_fec && (send_flags & overlay::Overlays::BroadcastFlagNoTwostep()) == 0;
  const bool old_fec_path = send && mode != "plumtree" && send_fec && !twostep_path;
  if (old_fec_path && send_data.size() > kMaxFecData) {
    return td::Status::Error(PSLICE() << "broadcast.data: at most " << kMaxFecData
                                      << " bytes for a broadcast on the old FEC path");
  }
  TRY_RESULT(inbound, inbound_field(ctx, members.size()));
  // With more than one neighbour the simple, old FEC and Plumtree paths pick neighbours at random (also
  // when relaying a received broadcast); two members leave each one exactly one. Only a two-step send,
  // with nothing received, goes to every member in a fixed order.
  if (members.size() != kMinMembers && !(twostep_path && inbound.empty())) {
    return td::Status::Error("members: exactly two unless the context sends a two-step broadcast and receives nothing");
  }

  overlay::OverlayIdFull overlay_full{td::BufferSlice(name)};
  const auto overlay_id = overlay_full.compute_short_id();
  std::vector<adnl::AdnlNodeIdShort> ids;
  for (const auto &member : members) {
    ids.push_back(member.id);
  }

  FixedClock clock(static_cast<double>(now));
  NodeLog log;
  auto record = std::make_shared<Record>();
  td::Status setup_error;
  bool settled = false;
  {
    td::actor::Scheduler scheduler({0});
    td::actor::ActorOwn<tos::keyring::Keyring> keyring;
    td::actor::ActorOwn<EdgeAdnl> edge;
    td::actor::ActorOwn<EdgeSender> sender;
    td::actor::ActorOwn<overlay::OverlayManager> manager;
    scheduler.run_in_context([&] {
      keyring = tos::keyring::Keyring::create("");
      edge = td::actor::create_actor<EdgeAdnl>("edge", record);
      sender = td::actor::create_actor<EdgeSender>("edge-sender", record);
      manager = td::actor::create_actor<overlay::OverlayManager>("overlays", "", keyring.get(),
                                                                 td::actor::actor_dynamic_cast<adnl::Adnl>(edge.get()),
                                                                 td::actor::ActorId<tos::dht::Dht>{});
      for (std::size_t i = 0; i < members.size(); ++i) {
        td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key, members[i].key, true,
                                [&](td::Result<td::Unit> added) {
                                  if (added.is_error()) {
                                    setup_error = added.move_as_error_prefix("keyring: ");
                                  }
                                });
        overlay::OverlayOptions options;
        if (mode == "twostep") {
          options.twostep_broadcast_sender_ = sender.get();
          options.send_twostep_broadcast_ = true;
        }
        if (mode == "plumtree") {
          options.enable_plumtree_broadcast_ = true;
          options.plumtree_broadcast_sender_ = sender.get();
        }
        auto actor = td::actor::create_actor<overlay::OverlayImpl>(
            "overlay", keyring.get(), td::actor::actor_dynamic_cast<adnl::Adnl>(edge.get()), manager.get(),
            td::actor::ActorId<tos::dht::Dht>{}, members[i].id, overlay::OverlayIdFull{overlay_full.clone()},
            overlay::OverlayType::FixedMemberList, ids, std::vector<tos::PublicKeyHash>{},
            overlay::OverlayMemberCertificate{}, std::make_unique<MemberCallback>(record, i),
            overlay::OverlayPrivacyRules{max_unauth_size, rule_flags, authorized}, "conformance", std::move(options));
        td::actor::send_closure(manager, &overlay::OverlayManager::register_overlay, members[i].id, overlay_id,
                                overlay::OverlayMemberCertificate{}, std::move(actor));
      }
    });
    bool started = false;
    std::size_t handed = 0;
    int idle = 0;
    std::size_t seen_emitted = 0;
    std::size_t seen_delivered = 0;
    for (int round = 0; round < kMaxRounds && setup_error.is_ok(); ++round) {
      scheduler.run(0);
      if (!started && round >= kIdleRounds) {
        // Every overlay is registered and idle: the scenario starts.
        started = true;
        scheduler.run_in_context([&] {
          for (auto &message : inbound) {
            td::actor::send_closure(edge, &EdgeAdnl::deliver, message.src, members[message.dst].id,
                                    td::BufferSlice(message.data));
          }
          if (send && mode == "plumtree") {
            if (send_fec) {
              td::actor::send_closure(manager, &overlay::OverlayManager::send_broadcast_plumtree_fec, members[0].id,
                                      overlay_id, members[0].id.pubkey_hash(), send_flags, td::BufferSlice(send_data));
            } else {
              td::actor::send_closure(manager, &overlay::OverlayManager::send_broadcast_plumtree, members[0].id,
                                      overlay_id, members[0].id.pubkey_hash(), send_flags,
                                      td::sha256_bits256(send_data), td::BufferSlice(send_data));
            }
          } else if (send) {
            if (send_fec) {
              td::actor::send_closure(manager, &overlay::OverlayManager::send_broadcast_fec_ex, members[0].id,
                                      overlay_id, members[0].id.pubkey_hash(), send_flags, td::BufferSlice(send_data));
            } else {
              td::actor::send_closure(manager, &overlay::OverlayManager::send_broadcast_ex, members[0].id, overlay_id,
                                      members[0].id.pubkey_hash(), send_flags, td::BufferSlice(send_data));
            }
          }
        });
        continue;
      }
      if (!started) {
        continue;
      }
      // Hand every newly emitted message to its destination, in the order it was emitted.
      if (handed < record->emitted.size()) {
        if (record->emitted.size() > kMaxEmitted) {
          setup_error = td::Status::Error("the members emitted more messages than a context may");
          break;
        }
        std::vector<Emitted> batch(record->emitted.begin() + static_cast<std::ptrdiff_t>(handed),
                                   record->emitted.end());
        handed = record->emitted.size();
        scheduler.run_in_context([&] {
          for (auto &message : batch) {
            td::actor::send_closure(edge, &EdgeAdnl::deliver, message.src, message.dst, td::BufferSlice(message.data));
          }
        });
      }
      if (record->emitted.size() != seen_emitted || record->delivered.size() != seen_delivered) {
        seen_emitted = record->emitted.size();
        seen_delivered = record->delivered.size();
        idle = 0;
      } else if (++idle >= kIdleRounds) {
        settled = true;
        break;
      }
    }
    scheduler.run_in_context([&] {
      manager.reset();
      sender.reset();
      edge.reset();
      keyring.reset();
    });
    scheduler.run(0);
  }
  if (setup_error.is_error()) {
    return setup_error;
  }
  if (!settled) {
    return td::Status::Error("the overlay members did not settle");
  }

  std::string emitted = "[";
  for (const auto &message : record->emitted) {
    emitted += (emitted.size() > 1 ? "," : "") + std::string("{\"src\":") + member_text(members, message.src) +
               ",\"dst\":" + member_text(members, message.dst) + ",\"via\":" + quote(message.via) +
               ",\"type\":" + quote(message_type(message.data)) + ",\"canonical\":" + quote(hex(message.data)) + "}";
  }
  emitted += "]";
  std::string delivered = "[";
  for (const auto &item : record->delivered) {
    delivered += (delivered.size() > 1 ? "," : "") + std::string("{\"member\":") + std::to_string(item.member) +
                 ",\"kind\":" + quote(item.kind) + ",\"from_key\":" + quote(bits(item.source)) +
                 ",\"data_sha256\":" + quote(bits(td::sha256_bits256(item.data))) +
                 ",\"extra\":" + quote(hex(item.extra)) + "}";
  }
  delivered += "]";
  std::string drops = "[";
  for (const auto &line : log.lines()) {
    for (const auto &marker : kDropMarkers) {
      auto at = line.find(marker.str());
      if (at != std::string::npos) {
        drops += (drops.size() > 1 ? "," : "") + quote(reason_class(td::Slice(line).substr(at)));
        break;
      }
    }
  }
  drops += "]";
  return "{\"outcome\":\"broadcast\",\"emitted\":" + emitted + ",\"delivered\":" + delivered + ",\"drops\":" + drops +
         "}";
}

}  // namespace conformance::net
