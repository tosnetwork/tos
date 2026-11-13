// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// net harness, ADNL operations: address lists, messages, packets, datagrams to a local id, channels, and
// the pre-authentication admission gate, each through the node's own adnl/ code.
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "adnl/adnl-address-list.hpp"
#include "adnl/adnl-channel.hpp"
#include "adnl/adnl-message.h"
#include "adnl/adnl-network-manager.h"
#include "adnl/adnl-node-id.hpp"
#include "adnl/adnl-packet.h"
#include "adnl/adnl-peer.h"
#include "adnl/decrypt-admission.h"
#include "auto/tl/tos_api.hpp"
#include "keys/encryptor.h"
#include "keys/keys.hpp"
#include "td/actor/actor.h"
#include "td/utils/overloaded.h"
#include "td/utils/port/IPAddress.h"
#include "tl-utils/tl-utils.hpp"

#include "net-common.h"

namespace conformance::net {

namespace adnl = tos::adnl;
namespace tos_api = tos::tos_api;

namespace {

constexpr std::size_t kMaxSources = 1024;
constexpr double kMinGatePeriod = 60.0;

std::string bits(const td::Bits256 &value) {
  return hex(value.as_slice());
}

std::string serialized_hex(const tos::tl_object_ptr<tos_api::Object> &object) {
  return hex(tos::serialize_tl_object(object, true).as_slice());
}

// Decodes a boxed TL object of type T from the bytes of a context field; a TL refusal is returned inside the
// result, a field that is not bounded hex is a harness error.
template <class T>
td::Result<td::Result<tos::tl_object_ptr<T>>> wire_object(td::JsonObject &ctx, td::Slice field) {
  TRY_RESULT(bytes, hex_field(ctx, field));
  auto parsed = tos::fetch_tl_object<T>(td::BufferSlice(bytes), true);
  if (parsed.is_error()) {
    return td::Result<tos::tl_object_ptr<T>>(tl_error(parsed.error()));
  }
  return td::Result<tos::tl_object_ptr<T>>(parsed.move_as_ok());
}

td::Result<td::IPAddress> ip_field(td::JsonObject &obj) {
  TRY_RESULT(ip, obj.get_required_string_field("ip"));
  TRY_RESULT(port, obj.get_required_int_field("port"));
  if (port < 1 || port > 65535) {
    return td::Status::Error("port: 1..65535 required");
  }
  if (ip.size() > 64) {
    return td::Status::Error("ip: at most 64 characters");
  }
  td::IPAddress addr;
  if (ip.find(':') != std::string::npos) {
    TRY_STATUS_PREFIX(addr.init_ipv6_port(ip, port), "ip: ");
  } else {
    TRY_STATUS_PREFIX(addr.init_ipv4_port(ip, port), "ip: ");
  }
  return addr;
}

std::string ip_json(const td::IPAddress &addr) {
  return "{\"ip\":" + quote(addr.get_ip_str()) + ",\"port\":" + std::to_string(addr.get_port()) + "}";
}

}  // namespace

std::string message_json(const adnl::AdnlMessage &message) {
  std::string fields;
  message.visit(td::overloaded(
      [&](const adnl::AdnlMessage::Empty &) { fields = "\"type\":\"empty\""; },
      [&](const adnl::adnlmessage::AdnlMessageCreateChannel &m) {
        fields = "\"type\":\"create_channel\",\"key\":" + quote(bits(m.key().raw())) +
                 ",\"date\":" + std::to_string(m.date()) + ",\"size\":" + std::to_string(m.size());
      },
      [&](const adnl::adnlmessage::AdnlMessageConfirmChannel &m) {
        fields = "\"type\":\"confirm_channel\",\"key\":" + quote(bits(m.key().raw())) +
                 ",\"peer_key\":" + quote(bits(m.peer_key().raw())) + ",\"date\":" + std::to_string(m.date()) +
                 ",\"size\":" + std::to_string(m.size());
      },
      [&](const adnl::adnlmessage::AdnlMessageCustom &m) {
        fields =
            "\"type\":\"custom\",\"data\":" + quote(hex(m.data().as_slice())) + ",\"size\":" + std::to_string(m.size());
      },
      [&](const adnl::adnlmessage::AdnlMessageNop &m) {
        fields = "\"type\":\"nop\",\"size\":" + std::to_string(m.size());
      },
      [&](const adnl::adnlmessage::AdnlMessageReinit &m) {
        fields = "\"type\":\"reinit\",\"date\":" + std::to_string(m.date()) + ",\"size\":" + std::to_string(m.size());
      },
      [&](const adnl::adnlmessage::AdnlMessageQuery &m) {
        fields = "\"type\":\"query\",\"query_id\":" + quote(bits(m.query_id())) +
                 ",\"data\":" + quote(hex(m.data().as_slice())) + ",\"size\":" + std::to_string(m.size());
      },
      [&](const adnl::adnlmessage::AdnlMessageAnswer &m) {
        fields = "\"type\":\"answer\",\"query_id\":" + quote(bits(m.query_id())) +
                 ",\"data\":" + quote(hex(m.data().as_slice())) + ",\"size\":" + std::to_string(m.size());
      },
      [&](const adnl::adnlmessage::AdnlMessagePart &m) {
        fields = "\"type\":\"part\",\"hash\":" + quote(bits(m.hash())) +
                 ",\"total_size\":" + std::to_string(m.total_size()) + ",\"offset\":" + std::to_string(m.offset()) +
                 ",\"data\":" + quote(hex(m.data().as_slice())) + ",\"size\":" + std::to_string(m.size());
      }));
  return "{" + fields + "}";
}

std::string address_list_json(const adnl::AdnlAddressList &list) {
  std::string addrs = "[";
  for (const auto &addr : list.adnl_addrs()) {
    addrs += (addrs.size() > 1 ? "," : "") + quote(serialized_hex(addr->tl()));
  }
  addrs += "]";
  std::string quic = "[";
  for (const auto &addr : list.quic_addrs()) {
    quic += (quic.size() > 1 ? "," : "") + ip_json(addr);
  }
  quic += "]";
  return "{\"version\":" + std::to_string(list.version()) + ",\"reinit_date\":" + std::to_string(list.reinit_date()) +
         ",\"priority\":" + std::to_string(list.priority()) + ",\"expire_at\":" + std::to_string(list.expire_at()) +
         ",\"empty\":" + json_bool(list.empty()) + ",\"public_only\":" + json_bool(list.public_only()) +
         ",\"has_reverse\":" + json_bool(list.has_reverse()) + ",\"addresses\":" + addrs + ",\"quic\":" + quic +
         ",\"serialized_size\":" + std::to_string(list.serialized_size()) +
         ",\"canonical\":" + quote(hex(tos::serialize_tl_object(list.tl(), true).as_slice())) + "}";
}

std::string packet_signature_check(const adnl::AdnlPacket &packet) {
  if (!packet.inited_from()) {
    return "null";
  }
  auto encryptor = packet.from().pubkey().create_encryptor();
  if (encryptor.is_error()) {
    return quote(reason_class(encryptor.error().message()));
  }
  auto status = encryptor.ok()->check_signature(packet.to_sign().as_slice(), packet.signature().as_slice());
  if (status.is_error()) {
    return quote(reason_class(status.message()));
  }
  return "\"valid\"";
}

std::string packet_json(const adnl::AdnlPacket &packet, const std::string &signature_check) {
  constexpr td::uint32 kPriorityAddress = 0x20;
  std::string messages = "[";
  for (const auto &message : const_cast<adnl::AdnlPacket &>(packet).messages().vector()) {
    messages += (messages.size() > 1 ? "," : "") + message_json(message);
  }
  messages += "]";
  const bool has_priority_list = (packet.flags() & kPriorityAddress) != 0;
  return "{\"flags\":" + std::to_string(packet.flags()) + ",\"priority\":" + json_bool(packet.priority()) +
         ",\"from\":" +
         (packet.inited_from() ? quote(hex(tos::serialize_tl_object(packet.from().tl(), true).as_slice()))
                               : std::string("null")) +
         ",\"from_short\":" +
         (packet.inited_from_short() ? quote(bits(packet.from_short().bits256_value())) : std::string("null")) +
         ",\"messages\":" + messages + ",\"address_list\":" +
         (packet.inited_addr_list() ? address_list_json(packet.addr_list()) : std::string("null")) +
         ",\"priority_address_list\":" +
         (has_priority_list ? address_list_json(packet.priority_addr_list()) : std::string("null")) +
         ",\"seqno\":" + decimal_text(packet.seqno()) + ",\"confirm_seqno\":" + decimal_text(packet.confirm_seqno()) +
         ",\"recv_addr_list_version\":" + std::to_string(packet.recv_addr_list_version()) +
         ",\"recv_priority_addr_list_version\":" + std::to_string(packet.recv_priority_addr_list_version()) +
         ",\"reinit_date\":" + std::to_string(packet.reinit_date()) +
         ",\"dst_reinit_date\":" + std::to_string(packet.dst_reinit_date()) +
         ",\"signature\":" + quote(hex(packet.signature().as_slice())) +
         ",\"to_sign\":" + quote(hex(packet.to_sign().as_slice())) +
         ",\"canonical\":" + quote(hex(tos::serialize_tl_object(packet.tl(), true).as_slice())) +
         ",\"signature_check\":" + signature_check + "}";
}

namespace {

// AdnlPacket::create on decoded packet contents, as every receive path calls it.
td::Result<adnl::AdnlPacket> packet_from_bytes(td::Slice bytes) {
  auto tl = tos::fetch_tl_object<tos_api::adnl_packetContents>(td::BufferSlice(bytes), true);
  if (tl.is_error()) {
    return tl_error(tl.error());
  }
  return adnl::AdnlPacket::create(tl.move_as_ok());
}

}  // namespace

td::Result<std::string> op_adnl_address_list(td::JsonObject &ctx) {
  TRY_RESULT(tl, wire_object<tos_api::adnl_addressList>(ctx, "address_list"));
  if (tl.is_error()) {
    return refused(tl.error());
  }
  auto list = adnl::AdnlAddressList::create(tl.ok());
  if (list.is_error()) {
    return refused(list.error());
  }
  return "{\"outcome\":\"address_list\",\"address_list\":" + address_list_json(list.ok()) + "}";
}

td::Result<std::string> op_adnl_message(td::JsonObject &ctx) {
  TRY_RESULT(tl, wire_object<tos_api::adnl_Message>(ctx, "message"));
  if (tl.is_error()) {
    return refused(tl.error());
  }
  adnl::AdnlMessage message{tl.move_as_ok()};
  return "{\"outcome\":\"message\",\"message\":" + message_json(message) +
         ",\"canonical\":" + quote(hex(tos::serialize_tl_object(message.tl(), true).as_slice())) + "}";
}

td::Result<std::string> op_adnl_packet(td::JsonObject &ctx) {
  TRY_RESULT(bytes, hex_field(ctx, "contents"));
  auto packet = packet_from_bytes(bytes);
  if (packet.is_error()) {
    return refused(packet.error());
  }
  return "{\"outcome\":\"packet\",\"packet\":" + packet_json(packet.ok(), packet_signature_check(packet.ok())) + "}";
}

// A datagram addressed to a local id of a receiver that knows no peer yet: the steps of
// AdnlPeerTableImpl::receive_packet, AdnlLocalId::receive, receive_decrypted_packet and
// AdnlPeerPairImpl::receive_packet up to the signature check, in their order.
td::Result<std::string> op_adnl_datagram(td::JsonObject &ctx) {
  TRY_RESULT(key_bytes, hex_field(ctx, "private_key", 4096));
  TRY_RESULT(datagram, hex_field(ctx, "datagram"));
  auto key_tl = tos::fetch_tl_object<tos_api::PrivateKey>(td::Slice(key_bytes), true);
  if (key_tl.is_error()) {
    return td::Status::Error(PSLICE() << "private_key: not a TL PrivateKey: " << key_tl.error().message());
  }
  tos::PrivateKey key{key_tl.ok()};
  if (datagram.size() < 32) {
    return refused_text("message too short");
  }
  const td::Slice dst = td::Slice(datagram).truncate(32);
  if (dst != key.compute_short_id().as_slice()) {
    return refused_text("unknown dst");
  }
  TRY_RESULT(decryptor, key.create_decryptor());
  auto plain = decryptor->decrypt(td::Slice(datagram).substr(32));
  if (plain.is_error()) {
    return refused(plain.error());
  }
  auto packet = packet_from_bytes(plain.ok().as_slice());
  if (packet.is_error()) {
    return refused(packet.error());
  }
  if (auto status = packet.ok().run_basic_checks(); status.is_error()) {
    return refused(status);
  }
  if (!packet.ok().inited_from_short()) {
    return refused_text("src not set");
  }
  if (!packet.ok().inited_from()) {
    return refused_text("unknown peer and no full src in packet");
  }
  TRY_RESULT(encryptor, packet.ok().from().pubkey().create_encryptor());
  auto status = encryptor->check_signature(packet.ok().to_sign().as_slice(), packet.ok().signature().as_slice());
  if (status.is_error()) {
    return refused(status);
  }
  return "{\"outcome\":\"received\",\"from_short\":" + quote(bits(packet.ok().from_short().bits256_value())) +
         ",\"packet\":" + packet_json(packet.ok(), "\"valid\"") + "}";
}

namespace {

// What the test doubles below observed.
struct ChannelRecord {
  bool decrypted = false;
  std::string received;
  bool sent = false;
  std::string sent_bytes;
};

// The channel hands decrypted packets to its peer pair and encrypted datagrams to a connection; these
// doubles stand in for both and only record what they were given.
class RecordingPeerPair : public adnl::AdnlPeerPair {
 public:
  explicit RecordingPeerPair(std::shared_ptr<ChannelRecord> record) : record_(std::move(record)) {
  }
  void receive_packet_from_channel(adnl::AdnlChannelIdShort, adnl::AdnlPacket, td::uint64) override {
  }
  void receive_packet_checked(adnl::AdnlPacket) override {
  }
  void receive_packet(adnl::AdnlPacket, td::uint64) override {
  }
  void send_messages(std::vector<adnl::OutboundAdnlMessage>) override {
  }
  void get_peer_node(td::Promise<adnl::AdnlNode> promise) override {
    promise.set_error(td::Status::Error("not available in the test double"));
  }
  void send_query(std::string, td::Promise<td::BufferSlice> promise, td::Timestamp, td::BufferSlice,
                  td::uint32) override {
    promise.set_error(td::Status::Error("not available in the test double"));
  }
  void reset_channel(td::Promise<td::Unit> promise) override {
    promise.set_error(td::Status::Error("not available in the test double"));
  }
  void alarm_query(adnl::AdnlQueryId) override {
  }
  void update_dht_node(td::actor::ActorId<tos::dht::Dht>) override {
  }
  void update_peer_id(adnl::AdnlNodeIdFull) override {
  }
  void update_addr_list(adnl::AdnlAddressList) override {
  }
  void get_conn_ip_str(td::Promise<td::string> promise) override {
    promise.set_error(td::Status::Error("not available in the test double"));
  }
  void get_stats(bool, td::Promise<tos::tl_object_ptr<tos_api::adnl_stats_peerPair>> promise) override {
    promise.set_error(td::Status::Error("not available in the test double"));
  }

 private:
  std::shared_ptr<ChannelRecord> record_;
};

class RecordingConnection : public adnl::AdnlNetworkConnection {
 public:
  explicit RecordingConnection(std::shared_ptr<ChannelRecord> record) : record_(std::move(record)) {
  }
  void send(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::uint32, td::BufferSlice message) override {
    record_->sent = true;
    record_->sent_bytes = hex(message.as_slice());
  }
  bool is_alive() const override {
    return true;
  }
  bool is_active() const override {
    return true;
  }
  void get_ip_str(td::Promise<td::string> promise) override {
    promise.set_value("test double");
  }

 private:
  std::shared_ptr<ChannelRecord> record_;
};

}  // namespace

// AdnlChannel::create from the local and peer channel keys and ids: the channel ids, and optionally one
// inbound datagram decrypted by the channel (AdnlChannelImpl::decrypt) and one packet encrypted by it
// (AdnlChannelImpl::send_message), on a single-threaded scheduler.
td::Result<std::string> op_adnl_channel(td::JsonObject &ctx) {
  TRY_RESULT(local_key, bits256_field(ctx, "local_channel_key"));
  TRY_RESULT(peer_key, bits256_field(ctx, "peer_channel_key"));
  TRY_RESULT(local_id, bits256_field(ctx, "local_id"));
  TRY_RESULT(peer_id, bits256_field(ctx, "peer_id"));
  std::string datagram;
  bool has_datagram = ctx.has_field("datagram");
  if (has_datagram) {
    TRY_RESULT_ASSIGN(datagram, hex_field(ctx, "datagram"));
  }
  std::string to_send;
  bool has_send = ctx.has_field("send");
  if (has_send) {
    TRY_RESULT_ASSIGN(to_send, hex_field(ctx, "send"));
  }

  auto record = std::make_shared<ChannelRecord>();
  adnl::AdnlChannelIdShort out_id;
  adnl::AdnlChannelIdShort in_id;
  td::Status create_error;
  std::string received = "null";
  {
    td::actor::Scheduler scheduler({0});
    td::actor::ActorOwn<RecordingPeerPair> pair;
    td::actor::ActorOwn<RecordingConnection> conn;
    td::actor::ActorOwn<adnl::AdnlChannel> channel;
    scheduler.run_in_context([&] {
      pair = td::actor::create_actor<RecordingPeerPair>("pair", record);
      conn = td::actor::create_actor<RecordingConnection>("conn", record);
      auto created = adnl::AdnlChannel::create(tos::privkeys::Ed25519{local_key}, tos::pubkeys::Ed25519{peer_key},
                                               adnl::AdnlNodeIdShort{local_id}, adnl::AdnlNodeIdShort{peer_id}, out_id,
                                               in_id, pair.get());
      if (created.is_error()) {
        create_error = created.move_as_error();
        return;
      }
      channel = created.move_as_ok();
      auto &impl = static_cast<adnl::AdnlChannelImpl &>(channel.get().get_actor_unsafe());
      if (has_datagram) {
        // AdnlPeerTableImpl::receive_packet routes by the first 32 bytes before the channel sees the rest.
        if (datagram.size() < 32) {
          received = "{\"reason\":" + quote(reason_class("message too short")) + "}";
        } else if (td::Slice(datagram).truncate(32) != in_id.as_slice()) {
          received = "{\"reason\":" + quote(reason_class("unknown channel")) + "}";
        } else {
          impl.decrypt(td::BufferSlice(td::Slice(datagram).substr(32)),
                       td::PromiseCreator::lambda([&](td::Result<adnl::AdnlPacket> packet) {
                         record->decrypted = true;
                         if (packet.is_error()) {
                           received = "{\"reason\":" + quote(reason_class(packet.error().message())) + "}";
                           return;
                         }
                         // A channel packet is authenticated by the channel key, not by a packet signature.
                         received = "{\"packet\":" + packet_json(packet.ok(), "null") + "}";
                       }));
          if (!record->decrypted) {
            received = "{\"reason\":\"unclassified\"}";
          }
        }
      }
      if (has_send) {
        impl.send_message(0, conn.get(), td::BufferSlice(to_send));
      }
    });
    for (int i = 0; i < 100 && has_send && !record->sent && create_error.is_ok(); i++) {
      scheduler.run(0);
    }
    scheduler.run_in_context([&] {
      channel.reset();
      conn.reset();
      pair.reset();
    });
    scheduler.run(0);
  }
  if (create_error.is_error()) {
    return refused(create_error);
  }
  if (has_send && !record->sent) {
    return td::Status::Error("the channel did not hand the encrypted datagram to its connection");
  }
  return "{\"outcome\":\"channel\",\"in_id\":" + quote(hex(in_id.as_slice())) +
         ",\"out_id\":" + quote(hex(out_id.as_slice())) + ",\"received\":" + received +
         ",\"sent\":" + (has_send ? quote(record->sent_bytes) : std::string("null")) + "}";
}

td::Result<std::string> op_preauth_source(td::JsonObject &ctx) {
  td::JsonValue holder;
  TRY_RESULT_ASSIGN(holder, ctx.extract_required_field("address", td::JsonValue::Type::Object));
  TRY_RESULT(addr, ip_field(holder.get_object()));
  return "{\"outcome\":\"source\",\"source\":" + ip_json(adnl::preauth_source(addr)) + "}";
}

namespace {

struct BudgetSpec {
  td::uint32 burst;
  double period;
  std::size_t limit;
};

td::Result<BudgetSpec> budget_field(td::JsonObject &ctx, td::Slice field) {
  td::JsonValue holder;
  TRY_RESULT_ASSIGN(holder, ctx.extract_required_field(field, td::JsonValue::Type::Object));
  auto &obj = holder.get_object();
  TRY_RESULT(burst, uint32_field(obj, "burst"));
  TRY_RESULT(period, number_field(obj, "period"));
  TRY_RESULT(limit, uint32_field(obj, "in_flight_limit"));
  if (burst == 0 || burst > 4096) {
    return td::Status::Error(PSLICE() << field << ".burst: 1..4096 required");
  }
  // The gate's rate limiters read the clock. With a period this long no token can be refilled while the
  // events of one context run, so the outcome does not depend on how fast they run.
  if (!(period >= kMinGatePeriod && period <= 1e9)) {
    return td::Status::Error(PSLICE() << field << ".period: 60..1e9 seconds required");
  }
  return BudgetSpec{burst, period, limit};
}

}  // namespace

// A sequence of admissions and releases on one PreauthGate with explicit budgets.
td::Result<std::string> op_preauth_gate(td::JsonObject &ctx) {
  TRY_RESULT(max_sources, uint32_field(ctx, "max_sources"));
  TRY_RESULT(source, budget_field(ctx, "source"));
  TRY_RESULT(process_spec, budget_field(ctx, "process"));
  TRY_RESULT(local_spec, budget_field(ctx, "local"));
  TRY_RESULT(events_value, array_field(ctx, "events", kMaxItems));
  if (max_sources == 0 || max_sources > kMaxSources) {
    return td::Status::Error("max_sources: 1..1024 required");
  }
  adnl::DecryptBudget process(process_spec.burst, process_spec.period, process_spec.limit);
  adnl::DecryptBudget local(local_spec.burst, local_spec.period, local_spec.limit);
  using Gate = adnl::PreauthGate<int>;
  Gate gate(max_sources, source.burst, source.period);
  // Declared after the gate and the budgets, so every ticket is released before they go away.
  std::map<std::size_t, std::unique_ptr<Gate::Ticket>> tickets;
  std::string results = "[";
  auto &events = events_value.get_array();
  for (std::size_t i = 0; i < events.size(); i++) {
    if (events[i].type() != td::JsonValue::Type::Object) {
      return td::Status::Error("events: objects required");
    }
    auto &event = events[i].get_object();
    std::string result;
    if (event.has_field("admit")) {
      td::JsonValue holder;
      TRY_RESULT_ASSIGN(holder, event.extract_required_field("admit", td::JsonValue::Type::Object));
      TRY_RESULT(addr, ip_field(holder.get_object()));
      auto ticket = gate.admit(addr, process, local);
      if (ticket.is_error()) {
        result = quote(reason_class(ticket.error().message()));
      } else {
        tickets.emplace(i, std::make_unique<Gate::Ticket>(ticket.move_as_ok()));
        result = "\"admitted\"";
      }
    } else if (event.has_field("release")) {
      TRY_RESULT(index, event.get_required_long_field("release"));
      auto it = index < 0 ? tickets.end() : tickets.find(static_cast<std::size_t>(index));
      if (it == tickets.end()) {
        return td::Status::Error(PSLICE() << "events[" << i << "]: release of an event that holds no ticket");
      }
      tickets.erase(it);
      result = "\"released\"";
    } else {
      return td::Status::Error(PSLICE() << "events[" << i << "]: admit or release required");
    }
    results += (results.size() > 1 ? "," : "") + result;
  }
  results += "]";
  const auto held = tickets.size();
  tickets.clear();
  return "{\"outcome\":\"gate\",\"results\":" + results + ",\"sources\":" + std::to_string(gate.size()) +
         ",\"held\":" + std::to_string(held) + "}";
}

}  // namespace conformance::net
