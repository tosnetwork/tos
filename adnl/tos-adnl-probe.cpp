/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give permission
    to link the code of portions of this program with the OpenSSL library.
    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the file(s),
    but you are not obligated to do so. If you do not wish to do so, delete this
    exception statement from your version. If you delete this exception statement
    from all source files in the program, then also delete it here.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// tos-adnl-probe: measurement sidecar for cross-implementation ADNL
// reachability testing. Speaks the line-delimited JSON protocol
// "tos-adnl-probe/1" on stdin/stdout; see PROTOCOL.md next to this file.

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <deque>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "adnl/adnl-address-list.h"
#include "adnl/adnl-network-manager.h"
#include "adnl/adnl.h"
#include "auto/tl/tos_api.h"
#include "common/checksum.h"
#include "common/errorcode.h"
#include "keys/keys.hpp"
#include "rldp2/rldp.h"
#include "td/actor/actor.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/Random.h"
#include "td/utils/misc.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/port/UdpSocketFd.h"
#include "td/utils/port/signals.h"
#include "td/utils/port/sleep.h"

#include "git.h"

namespace tos {

namespace probe {

constexpr td::Slice kProtocol = "tos-adnl-probe/1";
constexpr td::Slice kEchoPrefix = "tosprobe-echo/1\n";  // 16 bytes
constexpr td::Slice kRldpPrefix = "tosprobe-rldp/1\n";  // 16 bytes
constexpr char kRldpPayloadDomain[] = "tos.messaging.reachability-rldp-payload.v1";
// The native stack refuses queries whose payload exceeds
// Adnl::huge_packet_max_size(); larger echo requests are reported as
// unsupported instead of being sent (see PROTOCOL.md).
constexpr size_t kMaxQueryPayload = Adnl::huge_packet_max_size();
constexpr td::uint32 kRldpPartSize = 2000000;
constexpr td::uint32 kMaxRldpPayload = 16 << 20;

std::mutex &stdout_mutex() {
  static std::mutex mutex;
  return mutex;
}

void emit_line(td::Slice line) {
  std::lock_guard<std::mutex> guard(stdout_mutex());
  std::fwrite(line.begin(), 1, line.size(), stdout);
  std::fputc('\n', stdout);
  std::fflush(stdout);
}

std::atomic<bool> g_stop{false};

struct LineQueue {
  std::mutex mutex;
  std::deque<std::string> lines;
  bool eof{false};
};

class ProbeCore;

class ProbeCallback : public adnl::Adnl::Callback {
 public:
  explicit ProbeCallback(std::function<void(adnl::AdnlNodeIdShort)> note_inbound)
      : note_inbound_(std::move(note_inbound)) {
  }
  void receive_message(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data) override {
    note_inbound_(src);
  }
  void receive_query(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    note_inbound_(src);
    auto payload = data.as_slice();
    if (payload.size() < kEchoPrefix.size() || payload.substr(0, kEchoPrefix.size()) != kEchoPrefix) {
      promise.set_error(td::Status::Error(ErrorCode::protoviolation, "bad echo query prefix"));
      return;
    }
    payload.remove_prefix(kEchoPrefix.size());
    auto hash = td::sha256_bits256(payload);
    promise.set_value(td::BufferSlice{hash.as_slice()});
  }

 private:
  std::function<void(adnl::AdnlNodeIdShort)> note_inbound_;
};

class RldpProbeCallback : public adnl::Adnl::Callback {
 public:
  using QueryHandler =
      std::function<void(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice, td::Promise<td::BufferSlice>)>;

  explicit RldpProbeCallback(QueryHandler handler) : handler_(std::move(handler)) {
  }
  void receive_message(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice) override {
  }
  void receive_query(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data,
                     td::Promise<td::BufferSlice> promise) override {
    handler_(src, dst, std::move(data), std::move(promise));
  }

 private:
  QueryHandler handler_;
};

class ProbeCore : public td::actor::Actor {
 public:
  explicit ProbeCore(std::shared_ptr<LineQueue> queue) : queue_(std::move(queue)) {
  }

  void start_up() override {
    alarm_timestamp() = td::Timestamp::in(0.005);
  }

  void alarm() override {
    drain_lines();
    process_timers();
    if (!stopping_) {
      alarm_timestamp() = td::Timestamp::in(0.005);
    }
  }

  void note_inbound(adnl::AdnlNodeIdShort src) {
    seen_inbound_.insert(src);
    if (confirm_.kind == ConfirmKind::await_peer && confirm_.waiting_inbound && src == peer_id_) {
      confirm_.waiting_inbound = false;
      start_confirm_attempt();
    }
  }

 private:
  enum class ConfirmKind { none, dial, await_peer, reconnect };

  struct ConfirmOp {
    ConfirmKind kind{ConfirmKind::none};
    td::int64 cmd_id{0};
    td::Timestamp started;
    td::Timestamp deadline;
    td::Timestamp retry_at = td::Timestamp::never();
    bool waiting_inbound{false};
    bool resolving_addr{false};        // confirmed; resolving the peer address
    td::int64 established_millis{0};   // millis measured at confirmation time
    td::uint64 seq{0};
  };

  struct PunchOp {
    bool active{false};
    td::int64 cmd_id{0};
    std::vector<td::IPAddress> targets;
    td::int64 rounds_left{0};
    double interval{0.1};
    td::Timestamp next_at;
  };

  struct HoldOp {
    bool active{false};
    td::int64 cmd_id{0};
    td::int64 window_ms{0};
    td::Timestamp started;
    td::Timestamp window_end;
    double interval{2.0};
    int consecutive_failures{0};
    double last_success_span{0.0};
    bool in_flight{false};
    bool closing_probe{false};
    td::Timestamp next_at;
    td::uint64 seq{0};
  };

  struct EchoOp {
    bool active{false};
    td::int64 cmd_id{0};
    td::Timestamp started;
    td::Bits256 expected;
    td::uint64 seq{0};
  };

  struct RldpOp {
    bool active{false};
    td::int64 cmd_id{0};
    td::Timestamp started;
    td::Timestamp interruption_started;
    td::Timestamp interruption_deadline;
    td::Timestamp query_completed_at;
    td::uint32 payload_bytes{0};
    td::uint32 interrupt_after_bytes{0};
    td::int64 planned_interruption_ms{0};
    td::Bits256 seed;
    td::Bits256 expected_payload_hash;
    td::Bits256 expected_response_transfer_id;
    td::uint64 seq{0};
    td::uint64 decoded_bytes{0};
    td::uint64 suppressed_messages{0};
    td::int64 actual_interruption_ms{0};
    bool interruption_attempted{false};
    bool suppression_done{false};
    bool query_done{false};
    bool query_ok{false};
    std::string failure;
  };

  std::shared_ptr<LineQueue> queue_;
  bool stopping_{false};
  bool eof_handled_{false};

  td::actor::ActorOwn<keyring::Keyring> keyring_;
  td::actor::ActorOwn<adnl::Adnl> adnl_;
  td::actor::ActorOwn<adnl::AdnlNetworkManager> network_manager_;
  td::actor::ActorOwn<rldp2::Rldp> rldp2_;

  bool listening_{false};
  bool have_identity_{false};
  PrivateKey local_pk_;  // held from identity/listen until listen hands it to the keyring
  PublicKey local_pub_;
  adnl::AdnlNodeIdShort local_id_;

  bool have_peer_{false};       // peer identity known (dial/await issued)
  bool peer_confirmed_{false};  // a round trip has been confirmed
  adnl::AdnlNodeIdFull peer_full_;
  adnl::AdnlNodeIdShort peer_id_;

  std::set<adnl::AdnlNodeIdShort> seen_inbound_;

  ConfirmOp confirm_;
  PunchOp punch_;
  HoldOp hold_;
  EchoOp echo_;
  RldpOp rldp_op_;
  td::Timestamp next_rldp_answer_at_;

  // shared monotone counter so a stale in-flight completion of one operation
  // can never be mistaken for a fresh attempt of a later operation
  td::uint64 op_seq_counter_{0};

  // session-operation lease: at most one of {dial, await, hold, reconnect,
  // echo} may be active at a time, so one operation's channel reset or peer
  // replacement can never be recorded as another operation's network
  // behavior. returns the name of the operation holding the lease, if any
  td::Slice busy_session_operation() const {
    switch (confirm_.kind) {
      case ConfirmKind::dial:
        return "dial";
      case ConfirmKind::await_peer:
        return "await";
      case ConfirmKind::reconnect:
        return "reconnect";
      case ConfirmKind::none:
        break;
    }
    if (hold_.active) {
      return "hold";
    }
    if (echo_.active) {
      return "echo";
    }
    if (rldp_op_.active) {
      return "rldp";
    }
    return td::Slice();
  }

  // fail-closed: a session command arriving while another holds the lease is
  // answered immediately with an error naming the busy operation, never
  // queued silently
  bool acquire_session_lease(td::int64 id) {
    auto busy = busy_session_operation();
    if (!busy.empty()) {
      emit_error(id, PSTRING() << "busy: " << busy << " in progress");
      return false;
    }
    return true;
  }

  // answers every in-flight command id with an error completion so that the
  // exactly-one-completion rule survives shutdown; with the session lease at
  // most one session operation plus one punch can be outstanding
  void cancel_outstanding(td::Slice reason) {
    if (punch_.active) {
      emit_error(punch_.cmd_id, reason);
      punch_ = PunchOp{};
    }
    if (confirm_.kind != ConfirmKind::none) {
      emit_error(confirm_.cmd_id, reason);
      confirm_ = ConfirmOp{};
    }
    if (hold_.active) {
      emit_error(hold_.cmd_id, reason);
      hold_ = HoldOp{};
    }
    if (echo_.active) {
      emit_error(echo_.cmd_id, reason);
      echo_ = EchoOp{};
    }
    if (rldp_op_.active) {
      emit_error(rldp_op_.cmd_id, reason);
      rldp_op_ = RldpOp{};
    }
  }

  // reads an optional integer field; emits a protocol error and returns false
  // when the field is present but not an integer
  bool read_long_field(td::int64 id, td::JsonObject &obj, td::Slice name, td::int64 default_value, td::int64 &out) {
    auto r_value = obj.get_optional_long_field(name, default_value);
    if (r_value.is_error()) {
      emit_error(id, PSTRING() << "field \"" << name << "\" must be an integer");
      return false;
    }
    out = r_value.move_as_ok();
    return true;
  }

  // frozen protocol bounds for the numeric command parameters; the
  // orchestrator enforces the identical limits (see PROTOCOL.md)
  static constexpr td::int64 kMinTimeoutMs = 1;
  static constexpr td::int64 kMaxTimeoutMs = 120000;
  static constexpr td::int64 kMinWindowMs = 1;
  static constexpr td::int64 kMaxWindowMs = 600000;
  static constexpr td::int64 kMinKeepaliveMs = 1;
  static constexpr td::int64 kMaxKeepaliveMs = 120000;
  static constexpr td::int64 kMinPunchRounds = 1;
  static constexpr td::int64 kMaxPunchRounds = 100;
  static constexpr td::int64 kMinPunchIntervalMs = 1;
  static constexpr td::int64 kMaxPunchIntervalMs = 10000;

  // accepts only a canonical JSON integer token: digits only, no sign, no
  // leading zero, no decimal point or exponent (the shared rule for the
  // command id and every numeric parameter)
  static td::Result<td::int64> parse_canonical_integer(td::Slice token) {
    if (token.empty() || (token.size() > 1 && token[0] == '0')) {
      return td::Status::Error("not a canonical integer token");
    }
    for (auto c : token) {
      if (c < '0' || c > '9') {
        return td::Status::Error("not a canonical integer token");
      }
    }
    return td::to_integer_safe<td::int64>(token);
  }

  // reads a required numeric parameter with the same canonical-token rules
  // as the id, enforcing its frozen protocol bound. called BEFORE any
  // session/peer mutation or lease acquisition, so an out-of-range value
  // produces an error completion and nothing changes — a control-plane
  // mistake must never be recorded as network behavior
  bool read_bounded_param(td::int64 id, td::JsonObject &obj, td::Slice name, td::int64 min_value, td::int64 max_value,
                          td::int64 &out) {
    auto field = obj.extract_field(name);
    if (field.type() != td::JsonValue::Type::Number) {
      emit_error(id, PSTRING() << "field \"" << name << "\" is required and must be a JSON integer in [" << min_value
                               << ", " << max_value << "]");
      return false;
    }
    auto token = field.get_number();
    auto r_value = parse_canonical_integer(token);
    if (r_value.is_error() || r_value.ok() < min_value || r_value.ok() > max_value) {
      emit_error(id, PSTRING() << "field \"" << name << "\" must be a JSON integer in [" << min_value << ", "
                               << max_value << "], got \"" << token << "\"");
      return false;
    }
    out = r_value.move_as_ok();
    return true;
  }

  static td::int64 elapsed_ms(td::Timestamp since) {
    auto ms = static_cast<td::int64>((td::Timestamp::now().at() - since.at()) * 1000.0 + 0.5);
    return ms < 0 ? 0 : ms;
  }

  static void emit_error(td::int64 id, td::Slice message) {
    td::JsonBuilder jb;
    {
      auto obj = jb.enter_object();
      obj("id", id);
      obj("event", "error");
      obj("message", message);
    }
    emit_line(jb.string_builder().as_cslice());
  }

  void drain_lines() {
    std::vector<std::string> lines;
    bool eof = false;
    {
      std::lock_guard<std::mutex> guard(queue_->mutex);
      while (!queue_->lines.empty()) {
        lines.push_back(std::move(queue_->lines.front()));
        queue_->lines.pop_front();
      }
      eof = queue_->eof;
    }
    for (auto &line : lines) {
      if (stopping_) {
        return;
      }
      handle_line(std::move(line));
    }
    if (eof && !eof_handled_ && !stopping_) {
      eof_handled_ = true;
      LOG(INFO) << "stdin EOF, shutting down";
      shutdown();
    }
  }

  void handle_line(std::string line) {
    if (td::trim(td::Slice(line)).empty()) {
      return;
    }
    auto r_value = td::json_decode(td::MutableSlice(line));
    if (r_value.is_error()) {
      emit_error(0, PSTRING() << "malformed JSON line: " << r_value.error().message());
      return;
    }
    auto value = r_value.move_as_ok();
    if (value.type() != td::JsonValue::Type::Object) {
      emit_error(0, "expected a JSON object");
      return;
    }
    auto &obj = value.get_object();
    // the id is required and validated before anything is dispatched or
    // mutated. it must be a JSON Number carrying a canonical integer token:
    // strings ("1"), booleans, null, floats (1.0) and exponent forms (1e0)
    // are all rejected — the generic field helpers would happily parse a
    // string, which the protocol forbids
    auto id_value = obj.extract_field("id");
    if (id_value.type() != td::JsonValue::Type::Number) {
      emit_error(0, "field \"id\" is required and must be a JSON integer");
      return;
    }
    auto id_token = id_value.get_number();
    constexpr td::int64 kMaxCommandId = (td::int64{1} << 53) - 1;
    td::int64 id = 0;
    auto r_id = parse_canonical_integer(id_token);
    if (r_id.is_ok()) {
      id = r_id.move_as_ok();
    }
    if (id < 1 || id > kMaxCommandId) {
      emit_error(0, PSTRING() << "field \"id\" must be a JSON integer in [1, 2^53-1], got \"" << id_token << "\"");
      return;
    }
    auto r_cmd = obj.get_required_string_field("cmd");
    if (r_cmd.is_error()) {
      emit_error(id, "field \"cmd\" must be a string");
      return;
    }
    auto cmd = r_cmd.move_as_ok();
    if (cmd == "identity") {
      cmd_identity(id);
    } else if (cmd == "listen") {
      cmd_listen(id, obj);
    } else if (cmd == "punch") {
      cmd_punch(id, obj);
    } else if (cmd == "dial") {
      cmd_dial(id, obj);
    } else if (cmd == "await") {
      cmd_await(id, obj);
    } else if (cmd == "hold") {
      cmd_hold(id, obj);
    } else if (cmd == "reconnect") {
      cmd_reconnect(id, obj);
    } else if (cmd == "echo") {
      cmd_echo(id, obj);
    } else if (cmd == "rldp") {
      cmd_rldp(id, obj);
    } else if (cmd == "close") {
      cmd_close(id);
    } else {
      emit_error(id, PSTRING() << "unknown cmd \"" << cmd << "\"");
    }
  }

  void process_timers() {
    if (stopping_) {
      return;
    }
    if (punch_.active && punch_.next_at.is_in_past()) {
      punch_round();
    }
    if (confirm_.kind != ConfirmKind::none) {
      if (confirm_.waiting_inbound && confirm_.deadline.is_in_past()) {
        finish_confirm_failure();
      } else if (confirm_.retry_at && confirm_.retry_at.is_in_past()) {
        confirm_.retry_at = td::Timestamp::never();
        start_confirm_attempt();
      }
    }
    if (hold_.active) {
      if (hold_.window_end.is_in_past()) {
        // the verdict must always rest on a round trip that completed at or
        // after window close. a keepalive still in flight fills that role
        // (keepalive_result finishes the hold with its result); with none
        // outstanding, a dedicated closing round trip is launched exactly
        // once — a success proven only early in the window must not credit
        // the whole window
        if (!hold_.in_flight && !hold_.closing_probe) {
          hold_.closing_probe = true;
          send_keepalive();
        }
      } else if (!hold_.in_flight && hold_.next_at.is_in_past()) {
        send_keepalive();
      }
    }
  }

  // ---- identity ----

  void ensure_identity() {
    if (have_identity_) {
      return;
    }
    local_pk_ = PrivateKey{privkeys::Ed25519::random()};
    local_pub_ = local_pk_.compute_public_key();
    local_id_ = adnl::AdnlNodeIdShort{local_pub_.compute_short_id()};
    have_identity_ = true;
  }

  void cmd_identity(td::int64 id) {
    // generates (or returns the already-generated) ephemeral transport
    // keypair without binding any socket; a subsequent listen reuses it.
    // lets an orchestrator hand the pubkey to the peer during rendezvous on
    // its own socket before the sidecar takes over the same port
    ensure_identity();
    td::JsonBuilder jb;
    {
      auto e = jb.enter_object();
      e("id", id);
      e("event", "identity");
      e("adnl_pubkey_hex", td::hex_encode(local_pub_.ed25519_value().raw().as_slice()));
      e("adnl_id_hex", td::hex_encode(local_id_.as_slice()));
    }
    emit_line(jb.string_builder().as_cslice());
  }

  // ---- listen ----

  // waits (bounded) until the requested UDP port can be bound; covers the
  // handoff where the caller closed its rendezvous socket on this port just
  // before issuing listen. the probe bind is released again immediately, so
  // a tiny re-bind race remains, but the transport bind follows right after
  td::Status wait_port_bindable(td::uint16 port) {
    td::IPAddress check;
    TRY_STATUS(check.init_ipv4_port("0.0.0.0", port));
    td::Status last_error;
    for (int attempt = 0; attempt < 20; attempt++) {
      auto r_fd = td::UdpSocketFd::open(check);
      if (r_fd.is_ok()) {
        r_fd.move_as_ok().close();
        return td::Status::OK();
      }
      last_error = r_fd.move_as_error();
      td::usleep_for(50000);  // 50 ms; worst case 1 s in total
    }
    return last_error;
  }

  void cmd_listen(td::int64 id, td::JsonObject &obj) {
    if (listening_) {
      emit_error(id, "already listening");
      return;
    }
    auto r_bind = obj.get_optional_string_field("bind", "0.0.0.0:0");
    if (r_bind.is_error()) {
      emit_error(id, "field \"bind\" must be a string");
      return;
    }
    auto bind = r_bind.move_as_ok();
    td::IPAddress bind_addr;
    auto S = bind_addr.init_host_port(bind);
    if (S.is_error()) {
      emit_error(id, PSTRING() << "cannot parse bind address \"" << bind << "\": " << S.message());
      return;
    }
    if (!bind_addr.is_ipv4()) {
      // The native UDP transport (td::UdpServer::create) binds an IPv4
      // 0.0.0.0 socket unconditionally; there is no IPv6 listener.
      emit_error(id, PSTRING() << "cannot bind \"" << bind
                               << "\": the native adnl transport only binds an IPv4 0.0.0.0 UDP socket");
      return;
    }

    auto port = static_cast<td::uint16>(bind_addr.get_port());
    if (port == 0) {
      // discover a free ephemeral port; the transport rebinds it right after.
      // init_ipv4_port refuses port 0, so craft the wildcard sockaddr directly
      sockaddr_in any{};
      any.sin_family = AF_INET;
      any.sin_port = 0;
      any.sin_addr.s_addr = INADDR_ANY;
      td::IPAddress ephemeral;
      auto S2 = ephemeral.init_sockaddr(reinterpret_cast<sockaddr *>(&any), sizeof(any));
      if (S2.is_error()) {
        emit_error(id, PSTRING() << "internal address error: " << S2.message());
        return;
      }
      auto r_fd = td::UdpSocketFd::open(ephemeral);
      if (r_fd.is_error()) {
        emit_error(id, PSTRING() << "cannot bind UDP socket: " << r_fd.error().message());
        return;
      }
      auto fd = r_fd.move_as_ok();
      auto r_local = fd.get_local_address();
      if (r_local.is_error()) {
        emit_error(id, PSTRING() << "cannot resolve bound address: " << r_local.error().message());
        return;
      }
      port = static_cast<td::uint16>(r_local.ok().get_port());
      fd.close();
    } else {
      auto S3 = wait_port_bindable(port);
      if (S3.is_error()) {
        emit_error(id, PSTRING() << "cannot bind UDP port " << port << ": " << S3.message());
        return;
      }
    }

    ensure_identity();

    keyring_ = keyring::Keyring::create("");
    td::actor::send_closure(keyring_, &keyring::Keyring::add_key, std::move(local_pk_), true, [](td::Result<> R) {
      if (R.is_error()) {
        LOG(ERROR) << "failed to add key to keyring: " << R.move_as_error();
      }
    });

    adnl_ = adnl::Adnl::create("", keyring_.get());
    network_manager_ = adnl::AdnlNetworkManager::create(port);
    td::actor::send_closure(adnl_, &adnl::Adnl::register_network_manager, network_manager_.get());
    rldp2_ = rldp2::Rldp::create(adnl_.get());

    td::IPAddress self_addr;
    self_addr.init_ipv4_port("0.0.0.0", port).ensure();
    adnl::AdnlCategoryMask cat_mask;
    cat_mask[0] = true;
    td::actor::send_closure(network_manager_, &adnl::AdnlNetworkManager::add_self_addr, self_addr, std::move(cat_mask),
                            static_cast<td::uint32>(0));

    // publish a versioned address list with zero addresses: peers then reply
    // to the observed source address (implicit address), which is what a
    // reachability probe wants both on loopback and behind NAT
    auto tladdrlist = create_tl_object<tos_api::adnl_addressList>(
        std::vector<tl_object_ptr<tos_api::adnl_Address>>{}, adnl::Adnl::adnl_start_time(),
        adnl::Adnl::adnl_start_time(), 0, 0);
    auto r_addrlist = adnl::AdnlAddressList::create(tladdrlist);
    if (r_addrlist.is_error()) {
      emit_error(id, PSTRING() << "cannot build address list: " << r_addrlist.error().message());
      return;
    }

    td::actor::send_closure(adnl_, &adnl::Adnl::add_id, adnl::AdnlNodeIdFull{local_pub_}, r_addrlist.move_as_ok(),
                            static_cast<td::uint8>(0));

    auto self = actor_id(this);
    td::actor::send_closure(rldp2_, &rldp2::Rldp::set_default_mtu, static_cast<td::uint64>(kMaxRldpPayload + 4096));
    td::actor::send_closure(rldp2_, &rldp2::Rldp::set_part_completed_callback,
                            [self](adnl::AdnlNodeIdShort local_id, adnl::AdnlNodeIdShort peer_id,
                                   td::Bits256 transfer_id, td::uint32 part, td::uint64 decoded_bytes) {
                              td::actor::send_closure(self, &ProbeCore::rldp_part_completed, local_id, peer_id,
                                                      transfer_id, part, decoded_bytes);
                            });
    td::actor::send_closure(rldp2_, &rldp2::Rldp::add_id, local_id_);
    td::actor::send_closure(adnl_, &adnl::Adnl::subscribe, local_id_, kEchoPrefix.str(),
                            std::make_unique<ProbeCallback>([self](adnl::AdnlNodeIdShort src) {
                              td::actor::send_closure(self, &ProbeCore::note_inbound, src);
                            }));
    td::actor::send_closure(
        adnl_, &adnl::Adnl::subscribe, local_id_, kRldpPrefix.str(),
        std::make_unique<RldpProbeCallback>([self](adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst,
                                                   td::BufferSlice data, td::Promise<td::BufferSlice> promise) mutable {
          td::actor::send_closure(self, &ProbeCore::handle_rldp_probe_query, src, dst, std::move(data),
                                  std::move(promise));
        }));

    listening_ = true;

    td::JsonBuilder jb;
    {
      auto e = jb.enter_object();
      e("id", id);
      e("event", "listening");
      e("addr", PSTRING() << "0.0.0.0:" << port);
      e("adnl_pubkey_hex", td::hex_encode(local_pub_.ed25519_value().raw().as_slice()));
      e("adnl_id_hex", td::hex_encode(local_id_.as_slice()));
    }
    emit_line(jb.string_builder().as_cslice());
  }

  // ---- punch ----

  void cmd_punch(td::int64 id, td::JsonObject &obj) {
    if (!listening_) {
      emit_error(id, "not listening");
      return;
    }
    if (punch_.active) {
      emit_error(id, "punch already in progress");
      return;
    }
    auto targets_value = obj.extract_field("targets");
    if (targets_value.type() != td::JsonValue::Type::Array) {
      emit_error(id, "field \"targets\" must be an array of \"ip:port\" strings");
      return;
    }
    std::vector<td::IPAddress> targets;
    for (auto &el : targets_value.get_array()) {
      if (el.type() != td::JsonValue::Type::String) {
        emit_error(id, "field \"targets\" must be an array of \"ip:port\" strings");
        return;
      }
      td::IPAddress target;
      auto S = target.init_host_port(el.get_string().str());
      if (S.is_error()) {
        emit_error(id, PSTRING() << "cannot parse target \"" << el.get_string() << "\": " << S.message());
        return;
      }
      if (!target.is_ipv4()) {
        // the native transport socket is IPv4-only; sending to an IPv6
        // destination through it aborts deep inside the UDP server, so
        // non-IPv4 targets are skipped up front (see PROTOCOL.md)
        LOG(WARNING) << "punch: skipping non-IPv4 target " << el.get_string();
        continue;
      }
      if (target.get_port() == 0) {
        // sending to port 0 aborts on the same unsurvivable send-error path
        // (sendmmsg EINVAL), so such targets are skipped up front too
        LOG(WARNING) << "punch: skipping port-0 target " << el.get_string();
        continue;
      }
      targets.push_back(target);
    }
    td::int64 rounds;
    td::int64 interval_ms;
    if (!read_bounded_param(id, obj, "rounds", kMinPunchRounds, kMaxPunchRounds, rounds) ||
        !read_bounded_param(id, obj, "interval_ms", kMinPunchIntervalMs, kMaxPunchIntervalMs, interval_ms)) {
      return;
    }
    punch_.active = true;
    punch_.cmd_id = id;
    punch_.targets = std::move(targets);
    punch_.rounds_left = rounds;
    punch_.interval = static_cast<double>(interval_ms) / 1000.0;
    punch_.next_at = td::Timestamp::now();
    punch_round();
  }

  void punch_round() {
    for (auto &target : punch_.targets) {
      td::BufferSlice data{64};
      td::Random::secure_bytes(data.as_slice());
      td::actor::send_closure(network_manager_, &adnl::AdnlNetworkManager::send_udp_packet, local_id_,
                              adnl::AdnlNodeIdShort::zero(), target, static_cast<td::uint32>(0), std::move(data));
    }
    punch_.rounds_left--;
    if (punch_.rounds_left <= 0) {
      punch_.active = false;
      td::JsonBuilder jb;
      {
        auto e = jb.enter_object();
        e("id", punch_.cmd_id);
        e("event", "punched");
      }
      emit_line(jb.string_builder().as_cslice());
      return;
    }
    punch_.next_at = td::Timestamp::in(punch_.interval);
  }

  // ---- dial / await / reconnect: confirmed round trips ----

  // parses the peer key into the caller's temporaries only: session state
  // (peer_full_/peer_id_/have_peer_/peer_confirmed_) is committed by the
  // command handlers in one place, after ALL validation has passed, so a
  // rejected dial/await leaves an existing established session untouched
  bool parse_peer_pubkey(td::int64 id, td::JsonObject &obj, adnl::AdnlNodeIdFull &peer_full,
                         adnl::AdnlNodeIdShort &peer_id) {
    auto r_hex = obj.get_required_string_field("peer_pubkey_hex");
    if (r_hex.is_error()) {
      emit_error(id, "field \"peer_pubkey_hex\" must be a string");
      return false;
    }
    auto r_raw = td::hex_decode(r_hex.ok());
    if (r_raw.is_error() || r_raw.ok().size() != 32) {
      emit_error(id, "field \"peer_pubkey_hex\" must be 64 hex chars of an ed25519 public key");
      return false;
    }
    td::Bits256 raw;
    raw.as_slice().copy_from(r_raw.ok());
    peer_full = adnl::AdnlNodeIdFull{pubkeys::Ed25519{raw}};
    peer_id = peer_full.compute_short_id();
    return true;
  }

  void commit_session_peer(adnl::AdnlNodeIdFull peer_full, adnl::AdnlNodeIdShort peer_id) {
    peer_full_ = std::move(peer_full);
    peer_id_ = peer_id;
    have_peer_ = true;
    peer_confirmed_ = false;
  }

  void cmd_dial(td::int64 id, td::JsonObject &obj) {
    if (!listening_) {
      emit_error(id, "not listening");
      return;
    }
    // every parameter is validated before the lease is taken and before any
    // session/peer mutation: an invalid command must change nothing
    adnl::AdnlNodeIdFull new_peer_full;
    adnl::AdnlNodeIdShort new_peer_id;
    if (!parse_peer_pubkey(id, obj, new_peer_full, new_peer_id)) {
      return;
    }
    td::int64 timeout_ms;
    if (!read_bounded_param(id, obj, "timeout_ms", kMinTimeoutMs, kMaxTimeoutMs, timeout_ms)) {
      return;
    }
    if (!acquire_session_lease(id)) {
      return;
    }

    auto candidates_value = obj.extract_field("candidates");
    std::vector<td::IPAddress> candidates;
    size_t dropped_unsupported = 0;
    if (candidates_value.type() == td::JsonValue::Type::Array) {
      for (auto &el : candidates_value.get_array()) {
        if (el.type() != td::JsonValue::Type::String) {
          continue;
        }
        td::IPAddress candidate;
        if (candidate.init_host_port(el.get_string().str()).is_ok()) {
          if (!candidate.is_ipv4()) {
            // the native transport socket is IPv4-only; handing an IPv6
            // address to the connection layer aborts inside the UDP server
            // on send, so such candidates are unusable (see PROTOCOL.md)
            LOG(WARNING) << "dial: skipping non-IPv4 candidate " << el.get_string();
            dropped_unsupported++;
          } else if (candidate.get_port() == 0) {
            // sending to port 0 aborts on the same unsurvivable send-error
            // path (sendmmsg EINVAL), so such candidates are unusable too
            LOG(WARNING) << "dial: skipping port-0 candidate " << el.get_string();
            dropped_unsupported++;
          } else {
            candidates.push_back(candidate);
          }
        }
      }
    }
    if (candidates.empty()) {
      // implementation limits must stay distinguishable from a genuinely
      // empty candidate set, so no network evidence gets filed from them
      if (dropped_unsupported > 0) {
        emit_failed(id, "unsupported-candidate");
      } else {
        emit_failed(id, "no-candidate");
      }
      return;
    }

    std::vector<tl_object_ptr<tos_api::adnl_Address>> addrs;
    for (auto &candidate : candidates) {
      addrs.push_back(create_tl_object<tos_api::adnl_address_udp>(candidate.get_ipv4(), candidate.get_port()));
    }
    auto tladdrlist = create_tl_object<tos_api::adnl_addressList>(
        std::move(addrs), static_cast<td::int32>(td::Clocks::system()), 0, 0, 0);
    auto r_addrlist = adnl::AdnlAddressList::create(tladdrlist);
    if (r_addrlist.is_error()) {
      emit_error(id, PSTRING() << "cannot build candidate address list: " << r_addrlist.error().message());
      return;
    }

    // every validation has passed: only now replace the session peer state
    commit_session_peer(std::move(new_peer_full), new_peer_id);
    td::actor::send_closure(adnl_, &adnl::Adnl::add_peer, local_id_, peer_full_, r_addrlist.move_as_ok());

    confirm_ = ConfirmOp{};
    confirm_.kind = ConfirmKind::dial;
    confirm_.cmd_id = id;
    confirm_.started = td::Timestamp::now();
    confirm_.deadline = td::Timestamp::in(static_cast<double>(timeout_ms) / 1000.0);
    start_confirm_attempt();
  }

  void cmd_await(td::int64 id, td::JsonObject &obj) {
    if (!listening_) {
      emit_error(id, "not listening");
      return;
    }
    // every parameter is validated before the lease is taken and before any
    // session/peer mutation: an invalid command must change nothing
    adnl::AdnlNodeIdFull new_peer_full;
    adnl::AdnlNodeIdShort new_peer_id;
    if (!parse_peer_pubkey(id, obj, new_peer_full, new_peer_id)) {
      return;
    }
    td::int64 timeout_ms;
    if (!read_bounded_param(id, obj, "timeout_ms", kMinTimeoutMs, kMaxTimeoutMs, timeout_ms)) {
      return;
    }
    if (!acquire_session_lease(id)) {
      return;
    }

    // every validation has passed: only now replace the session peer state.
    // never dials: register the peer identity with no addresses; the peer
    // pair learns the return path from the inbound session
    commit_session_peer(std::move(new_peer_full), new_peer_id);
    td::actor::send_closure(adnl_, &adnl::Adnl::add_peer, local_id_, peer_full_, adnl::AdnlAddressList{});

    confirm_ = ConfirmOp{};
    confirm_.kind = ConfirmKind::await_peer;
    confirm_.cmd_id = id;
    confirm_.started = td::Timestamp::now();
    confirm_.deadline = td::Timestamp::in(static_cast<double>(timeout_ms) / 1000.0);
    if (seen_inbound_.count(peer_id_) > 0) {
      start_confirm_attempt();
    } else {
      confirm_.waiting_inbound = true;
    }
  }

  void cmd_reconnect(td::int64 id, td::JsonObject &obj) {
    if (!listening_ || !have_peer_ || !peer_confirmed_) {
      emit_error(id, "no confirmed peer to reconnect to");
      return;
    }
    // the timeout is validated BEFORE the channel reset: an invalid
    // reconnect must not reset the channel and then record the inevitable
    // instant failure as a network reconnect failure
    td::int64 timeout_ms;
    if (!read_bounded_param(id, obj, "timeout_ms", kMinTimeoutMs, kMaxTimeoutMs, timeout_ms)) {
      return;
    }
    if (!acquire_session_lease(id)) {
      return;
    }

    confirm_ = ConfirmOp{};
    confirm_.kind = ConfirmKind::reconnect;
    confirm_.cmd_id = id;
    confirm_.started = td::Timestamp::now();
    confirm_.deadline = td::Timestamp::in(static_cast<double>(timeout_ms) / 1000.0);
    confirm_.seq = ++op_seq_counter_;

    auto self = actor_id(this);
    auto seq = confirm_.seq;
    td::actor::send_closure(adnl_, &adnl::Adnl::reset_peer_channel, local_id_, peer_id_,
                            td::PromiseCreator::lambda([self, seq](td::Result<td::Unit> R) {
                              td::actor::send_closure(self, &ProbeCore::reconnect_reset_done, seq, std::move(R));
                            }));
  }

  void reconnect_reset_done(td::uint64 seq, td::Result<td::Unit> R) {
    if (confirm_.kind != ConfirmKind::reconnect || confirm_.seq != seq) {
      return;
    }
    if (R.is_error()) {
      auto id = confirm_.cmd_id;
      confirm_ = ConfirmOp{};
      emit_error(id, PSTRING() << "cannot reset channel: " << R.error().message());
      return;
    }
    start_confirm_attempt();
  }

  td::BufferSlice make_echo_payload(size_t bytes, td::Bits256 &expected) {
    td::BufferSlice data{kEchoPrefix.size() + bytes};
    td::MutableSlice S = data.as_slice();
    S.copy_from(kEchoPrefix);
    S.remove_prefix(kEchoPrefix.size());
    td::Random::secure_bytes(S);
    expected = td::sha256_bits256(S);
    return data;
  }

  void start_confirm_attempt() {
    confirm_.seq = ++op_seq_counter_;
    auto seq = confirm_.seq;
    td::Bits256 expected;
    auto payload = make_echo_payload(32, expected);
    auto attempt_timeout =
        td::Timestamp::at(std::min(confirm_.deadline.at(), td::Timestamp::in(1.0).at()));
    auto self = actor_id(this);
    auto P = td::PromiseCreator::lambda([self, seq, expected](td::Result<td::BufferSlice> R) {
      td::actor::send_closure(self, &ProbeCore::confirm_attempt_result, seq, expected, std::move(R));
    });
    td::actor::send_closure(adnl_, &adnl::Adnl::send_query, local_id_, peer_id_, "probe-confirm", std::move(P),
                            attempt_timeout, std::move(payload));
  }

  void confirm_attempt_result(td::uint64 seq, td::Bits256 expected, td::Result<td::BufferSlice> R) {
    if (confirm_.kind == ConfirmKind::none || confirm_.seq != seq) {
      return;
    }
    bool ok = false;
    if (R.is_ok()) {
      auto answer = R.move_as_ok();
      ok = answer.size() == 32 && answer.as_slice() == expected.as_slice();
    }
    if (ok) {
      finish_confirm_success();
      return;
    }
    if (confirm_.deadline.is_in_past()) {
      finish_confirm_failure();
      return;
    }
    confirm_.retry_at = td::Timestamp::in(0.15);
  }

  void finish_confirm_success() {
    auto millis = elapsed_ms(confirm_.started);
    if (confirm_.kind == ConfirmKind::reconnect) {
      auto id = confirm_.cmd_id;
      confirm_ = ConfirmOp{};
      peer_confirmed_ = true;
      td::JsonBuilder jb;
      {
        auto e = jb.enter_object();
        e("id", id);
        e("event", "reconnected");
        e("millis", millis);
        e("succeeded", td::JsonBool{true});
      }
      emit_line(jb.string_builder().as_cslice());
      return;
    }
    // hold the confirm state — and with it the session lease — until the
    // established event is actually emitted: a close racing this tail still
    // finds the operation outstanding and cancels it with a terminal error,
    // so exactly-one-completion holds and no other session command can
    // interleave with the address lookup
    confirm_.resolving_addr = true;
    confirm_.established_millis = millis;
    confirm_.seq = ++op_seq_counter_;
    auto seq = confirm_.seq;
    auto self = actor_id(this);
    td::actor::send_closure(adnl_, &adnl::Adnl::get_conn_ip_str, local_id_, peer_id_,
                            td::PromiseCreator::lambda([self, seq](td::Result<td::string> R) {
                              td::actor::send_closure(self, &ProbeCore::resolve_peer_addr_done, seq, std::move(R));
                            }));
  }

  void resolve_peer_addr_done(td::uint64 seq, td::Result<td::string> R) {
    if (confirm_.kind == ConfirmKind::none || !confirm_.resolving_addr || confirm_.seq != seq) {
      return;  // the operation was cancelled; its terminal event was already emitted
    }
    auto id = confirm_.cmd_id;
    auto millis = confirm_.established_millis;
    confirm_ = ConfirmOp{};
    peer_confirmed_ = true;
    std::string peer_addr = R.is_ok() ? R.move_as_ok() : "undefined";
    td::JsonBuilder jb;
    {
      auto e = jb.enter_object();
      e("id", id);
      e("event", "established");
      e("millis", millis);
      e("peer_addr", peer_addr);
    }
    emit_line(jb.string_builder().as_cslice());
  }

  void finish_confirm_failure() {
    auto kind = confirm_.kind;
    auto id = confirm_.cmd_id;
    auto millis = elapsed_ms(confirm_.started);
    confirm_ = ConfirmOp{};
    if (kind == ConfirmKind::reconnect) {
      td::JsonBuilder jb;
      {
        auto e = jb.enter_object();
        e("id", id);
        e("event", "reconnected");
        e("millis", millis);
        e("succeeded", td::JsonBool{false});
      }
      emit_line(jb.string_builder().as_cslice());
      return;
    }
    emit_failed(id, "handshake-timeout");
  }

  static void emit_failed(td::int64 id, td::Slice error_class) {
    td::JsonBuilder jb;
    {
      auto e = jb.enter_object();
      e("id", id);
      e("event", "failed");
      e("class", error_class);
    }
    emit_line(jb.string_builder().as_cslice());
  }

  // ---- hold ----

  void cmd_hold(td::int64 id, td::JsonObject &obj) {
    if (!listening_ || !have_peer_ || !peer_confirmed_) {
      emit_error(id, "no confirmed peer to hold");
      return;
    }
    td::int64 window_ms;
    td::int64 keepalive_ms;
    if (!read_bounded_param(id, obj, "window_ms", kMinWindowMs, kMaxWindowMs, window_ms) ||
        !read_bounded_param(id, obj, "keepalive_ms", kMinKeepaliveMs, kMaxKeepaliveMs, keepalive_ms)) {
      return;
    }
    if (!acquire_session_lease(id)) {
      return;
    }
    hold_ = HoldOp{};
    hold_.active = true;
    hold_.cmd_id = id;
    hold_.window_ms = window_ms;
    hold_.started = td::Timestamp::now();
    hold_.window_end = td::Timestamp::in(static_cast<double>(window_ms) / 1000.0);
    hold_.interval = static_cast<double>(keepalive_ms) / 1000.0;
    hold_.next_at = td::Timestamp::now();
    send_keepalive();
  }

  void send_keepalive() {
    hold_.in_flight = true;
    hold_.seq = ++op_seq_counter_;
    hold_.next_at = td::Timestamp::in(hold_.interval);
    auto seq = hold_.seq;
    td::Bits256 expected;
    auto payload = make_echo_payload(32, expected);
    double timeout = std::max(hold_.interval, 0.05);
    if (hold_.closing_probe) {
      // the closing round trip is bounded like a round trip, not like the
      // keepalive cadence: a 60 s keepalive interval must not stretch the
      // verdict of a 3 s window by a minute
      timeout = std::min(timeout, 5.0);
    }
    auto self = actor_id(this);
    auto P = td::PromiseCreator::lambda([self, seq, expected](td::Result<td::BufferSlice> R) {
      td::actor::send_closure(self, &ProbeCore::keepalive_result, seq, expected, std::move(R));
    });
    td::actor::send_closure(adnl_, &adnl::Adnl::send_query, local_id_, peer_id_, "probe-keepalive", std::move(P),
                            td::Timestamp::in(timeout), std::move(payload));
  }

  void keepalive_result(td::uint64 seq, td::Bits256 expected, td::Result<td::BufferSlice> R) {
    if (!hold_.active || hold_.seq != seq) {
      return;
    }
    hold_.in_flight = false;
    bool ok = false;
    if (R.is_ok()) {
      auto answer = R.move_as_ok();
      ok = answer.size() == 32 && answer.as_slice() == expected.as_slice();
    }
    if (ok) {
      hold_.consecutive_failures = 0;
      hold_.last_success_span = td::Timestamp::now().at() - hold_.started.at();
    } else {
      hold_.consecutive_failures++;
      if (hold_.consecutive_failures >= 3) {
        finish_hold(false);
        return;
      }
    }
    if (hold_.window_end.is_in_past()) {
      // the round trip that closed the window decides the verdict: a peer
      // that died just before a short window must not be reported as
      // having survived it
      finish_hold(ok);
    }
  }

  void finish_hold(bool completed) {
    auto id = hold_.cmd_id;
    // whole seconds by truncation with a floor of one, mirroring the
    // collector's clamped-seconds rule: zero means "not measured" in the
    // trial schema, so a measured hold always reports at least 1
    td::int64 survival;
    if (completed) {
      survival = hold_.window_ms / 1000;
    } else {
      survival = static_cast<td::int64>(hold_.last_success_span);
    }
    if (survival < 1) {
      survival = 1;
    }
    hold_ = HoldOp{};
    td::JsonBuilder jb;
    {
      auto e = jb.enter_object();
      e("id", id);
      e("event", "held");
      e("survival_seconds", survival);
      e("completed", td::JsonBool{completed});
    }
    emit_line(jb.string_builder().as_cslice());
  }

  // ---- RLDPv2 segmented transfer and same-query recovery ----

  static td::uint32 load_be32(td::Slice data) {
    return (static_cast<td::uint32>(static_cast<td::uint8>(data[0])) << 24) |
           (static_cast<td::uint32>(static_cast<td::uint8>(data[1])) << 16) |
           (static_cast<td::uint32>(static_cast<td::uint8>(data[2])) << 8) |
           static_cast<td::uint32>(static_cast<td::uint8>(data[3]));
  }

  static void store_be32(td::MutableSlice data, td::uint32 value) {
    data[0] = static_cast<char>(value >> 24);
    data[1] = static_cast<char>(value >> 16);
    data[2] = static_cast<char>(value >> 8);
    data[3] = static_cast<char>(value);
  }

  static td::BufferSlice deterministic_rldp_payload(td::Bits256 seed, td::uint32 size) {
    td::BufferSlice payload{size};
    auto output = payload.as_slice();
    td::uint64 counter = 0;
    while (!output.empty()) {
      td::BufferSlice input{sizeof(kRldpPayloadDomain) + 32 + 8};
      auto input_slice = input.as_slice();
      input_slice.copy_from(td::Slice{kRldpPayloadDomain, sizeof(kRldpPayloadDomain)});
      input_slice.remove_prefix(sizeof(kRldpPayloadDomain));
      input_slice.copy_from(seed.as_slice());
      input_slice.remove_prefix(32);
      for (size_t i = 0; i < 8; i++) {
        input_slice[i] = static_cast<char>(counter >> ((7 - i) * 8));
      }
      auto block = td::sha256_bits256(input.as_slice());
      auto take = std::min(output.size(), block.as_slice().size());
      output.copy_from(block.as_slice().truncate(take));
      output.remove_prefix(take);
      counter++;
    }
    return payload;
  }

  void handle_rldp_probe_query(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::BufferSlice data,
                               td::Promise<td::BufferSlice> promise) {
    auto request = data.as_slice();
    const size_t request_size = kRldpPrefix.size() + 4 + 32;
    if (!listening_ || !peer_confirmed_ || src != peer_id_ || dst != local_id_) {
      promise.set_error(td::Status::Error(ErrorCode::notready, "RLDP probe peer is not confirmed"));
      return;
    }
    if (request.size() != request_size || request.substr(0, kRldpPrefix.size()) != kRldpPrefix) {
      promise.set_error(td::Status::Error(ErrorCode::protoviolation, "bad RLDP probe request"));
      return;
    }
    if (next_rldp_answer_at_ && !next_rldp_answer_at_.is_in_past()) {
      promise.set_error(td::Status::Error(ErrorCode::notready, "RLDP probe response rate limit"));
      return;
    }
    request.remove_prefix(kRldpPrefix.size());
    auto payload_bytes = load_be32(request.substr(0, 4));
    request.remove_prefix(4);
    if (payload_bytes <= kRldpPartSize || payload_bytes > kMaxRldpPayload) {
      promise.set_error(td::Status::Error(ErrorCode::protoviolation, "RLDP probe payload is outside bounds"));
      return;
    }
    td::Bits256 seed;
    seed.as_slice().copy_from(request);
    auto payload = deterministic_rldp_payload(seed, payload_bytes);
    td::BufferSlice response{32 + payload.size()};
    auto response_slice = response.as_slice();
    response_slice.copy_from(seed.as_slice());
    response_slice.remove_prefix(32);
    response_slice.copy_from(payload.as_slice());
    next_rldp_answer_at_ = td::Timestamp::in(1.0);
    promise.set_value(std::move(response));
  }

  void cmd_rldp(td::int64 id, td::JsonObject &obj) {
    if (!listening_ || !have_peer_ || !peer_confirmed_) {
      emit_error(id, "no confirmed peer for an RLDP transfer");
      return;
    }
    td::int64 payload_bytes;
    td::int64 interrupt_after_bytes;
    td::int64 interruption_ms;
    td::int64 timeout_ms;
    if (!read_bounded_param(id, obj, "bytes", kRldpPartSize + 1, kMaxRldpPayload, payload_bytes) ||
        !read_bounded_param(id, obj, "interrupt_after_bytes", kRldpPartSize, kRldpPartSize, interrupt_after_bytes) ||
        !read_bounded_param(id, obj, "interruption_ms", 100, 10000, interruption_ms) ||
        !read_bounded_param(id, obj, "timeout_ms", kMinTimeoutMs, kMaxTimeoutMs, timeout_ms)) {
      return;
    }
    if (!acquire_session_lease(id)) {
      return;
    }

    rldp_op_ = RldpOp{};
    rldp_op_.active = true;
    rldp_op_.cmd_id = id;
    rldp_op_.started = td::Timestamp::now();
    rldp_op_.payload_bytes = static_cast<td::uint32>(payload_bytes);
    rldp_op_.interrupt_after_bytes = static_cast<td::uint32>(interrupt_after_bytes);
    rldp_op_.planned_interruption_ms = interruption_ms;
    rldp_op_.seq = ++op_seq_counter_;
    td::Random::secure_bytes(rldp_op_.seed.as_slice());
    td::Bits256 request_transfer_id;
    td::Random::secure_bytes(request_transfer_id.as_slice());
    if (request_transfer_id.is_zero()) {
      request_transfer_id.as_slice()[0] = 1;
    }
    rldp_op_.expected_response_transfer_id = request_transfer_id;
    for (auto &byte : rldp_op_.expected_response_transfer_id.as_slice()) {
      byte = static_cast<char>(static_cast<td::uint8>(byte) ^ 0xff);
    }
    auto expected = deterministic_rldp_payload(rldp_op_.seed, rldp_op_.payload_bytes);
    rldp_op_.expected_payload_hash = td::sha256_bits256(expected.as_slice());

    td::BufferSlice request{kRldpPrefix.size() + 4 + 32};
    auto request_slice = request.as_slice();
    request_slice.copy_from(kRldpPrefix);
    request_slice.remove_prefix(kRldpPrefix.size());
    store_be32(request_slice, rldp_op_.payload_bytes);
    request_slice.remove_prefix(4);
    request_slice.copy_from(rldp_op_.seed.as_slice());

    auto self = actor_id(this);
    auto seq = rldp_op_.seq;
    auto promise = td::PromiseCreator::lambda([self, seq](td::Result<td::BufferSlice> result) {
      td::actor::send_closure(self, &ProbeCore::rldp_query_result, seq, std::move(result));
    });
    td::actor::send_closure(rldp2_, &rldp2::Rldp::send_query_ex_with_transfer_id, local_id_, peer_id_, "probe-rldp",
                            std::move(promise), td::Timestamp::in(static_cast<double>(timeout_ms) / 1000.0),
                            std::move(request), static_cast<td::uint64>(payload_bytes + 1024), request_transfer_id);
  }

 public:
  void rldp_part_completed(adnl::AdnlNodeIdShort local_id, adnl::AdnlNodeIdShort peer_id, td::Bits256 transfer_id,
                           td::uint32, td::uint64 decoded_bytes) {
    if (!rldp_op_.active || rldp_op_.interruption_attempted || local_id != local_id_ || peer_id != peer_id_ ||
        transfer_id != rldp_op_.expected_response_transfer_id) {
      return;
    }
    rldp_op_.decoded_bytes += decoded_bytes;
    if (rldp_op_.decoded_bytes < rldp_op_.interrupt_after_bytes) {
      return;
    }
    rldp_op_.interruption_attempted = true;
    rldp_op_.interruption_started = td::Timestamp::now();
    rldp_op_.interruption_deadline = td::Timestamp::in(static_cast<double>(rldp_op_.planned_interruption_ms) / 1000.0);
    auto self = actor_id(this);
    auto seq = rldp_op_.seq;
    td::actor::send_closure(
        network_manager_, &adnl::AdnlNetworkManager::suppress_packets_until, rldp_op_.interruption_deadline,
        td::PromiseCreator::lambda([self, seq](td::Result<adnl::AdnlNetworkManager::PacketSuppressionStats> result) {
          td::actor::send_closure(self, &ProbeCore::rldp_suppression_result, seq, std::move(result));
        }));
  }

  void rldp_query_result(td::uint64 seq, td::Result<td::BufferSlice> result) {
    if (!rldp_op_.active || rldp_op_.seq != seq) {
      return;
    }
    rldp_op_.query_done = true;
    rldp_op_.query_completed_at = td::Timestamp::now();
    if (result.is_error()) {
      rldp_op_.failure = result.move_as_error().message().str();
      maybe_finish_rldp();
      return;
    }
    auto response = result.move_as_ok();
    if (response.size() != static_cast<size_t>(32 + rldp_op_.payload_bytes)) {
      rldp_op_.failure = "RLDP response size mismatch";
      maybe_finish_rldp();
      return;
    }
    auto response_slice = response.as_slice();
    if (response_slice.substr(0, 32) != rldp_op_.seed.as_slice()) {
      rldp_op_.failure = "RLDP response seed mismatch";
      maybe_finish_rldp();
      return;
    }
    response_slice.remove_prefix(32);
    if (td::sha256_bits256(response_slice) != rldp_op_.expected_payload_hash) {
      rldp_op_.failure = "RLDP response digest mismatch";
      maybe_finish_rldp();
      return;
    }
    rldp_op_.query_ok = true;
    maybe_finish_rldp();
  }

  void rldp_suppression_result(td::uint64 seq, td::Result<adnl::AdnlNetworkManager::PacketSuppressionStats> result) {
    if (!rldp_op_.active || rldp_op_.seq != seq) {
      return;
    }
    rldp_op_.suppression_done = true;
    rldp_op_.actual_interruption_ms = elapsed_ms(rldp_op_.interruption_started);
    if (result.is_error()) {
      rldp_op_.failure = result.move_as_error().message().str();
    } else {
      rldp_op_.suppressed_messages = result.move_as_ok().total();
    }
    maybe_finish_rldp();
  }

 private:
  void maybe_finish_rldp() {
    if (!rldp_op_.active || !rldp_op_.query_done || (rldp_op_.interruption_attempted && !rldp_op_.suppression_done)) {
      return;
    }
    if (!rldp_op_.interruption_attempted && rldp_op_.failure.empty()) {
      rldp_op_.failure = "RLDP transfer completed before the interruption point";
    }
    if (rldp_op_.suppression_done && rldp_op_.suppressed_messages == 0 && rldp_op_.failure.empty()) {
      rldp_op_.failure = "RLDP interruption suppressed no packets";
    }
    if (rldp_op_.suppression_done && rldp_op_.actual_interruption_ms < rldp_op_.planned_interruption_ms &&
        rldp_op_.failure.empty()) {
      rldp_op_.failure = "RLDP interruption ended before its planned duration";
    }
    if (rldp_op_.query_done && rldp_op_.interruption_attempted &&
        rldp_op_.query_completed_at.at() < rldp_op_.interruption_deadline.at() && rldp_op_.failure.empty()) {
      rldp_op_.failure = "RLDP query completed before the interruption window ended";
    }
    bool ok = rldp_op_.query_ok && rldp_op_.interruption_attempted && rldp_op_.suppression_done &&
              rldp_op_.suppressed_messages > 0 && rldp_op_.actual_interruption_ms >= rldp_op_.planned_interruption_ms &&
              rldp_op_.failure.empty();
    auto millis = elapsed_ms(rldp_op_.started);
    auto completed = std::move(rldp_op_);
    rldp_op_ = RldpOp{};
    td::JsonBuilder jb;
    {
      auto e = jb.enter_object();
      e("id", completed.cmd_id);
      e("event", "rldp_transferred");
      e("ok", td::JsonBool{ok});
      e("bytes", static_cast<td::int64>(completed.payload_bytes));
      e("part_size_bytes", static_cast<td::int64>(kRldpPartSize));
      e("expected_parts", static_cast<td::int64>((completed.payload_bytes + kRldpPartSize - 1) / kRldpPartSize));
      e("interrupt_after_bytes", static_cast<td::int64>(completed.interrupt_after_bytes));
      e("planned_interruption_ms", completed.planned_interruption_ms);
      e("interruption_attempted", td::JsonBool{completed.interruption_attempted});
      e("interruption_ms", completed.actual_interruption_ms);
      e("suppressed_messages", static_cast<td::int64>(completed.suppressed_messages));
      e("same_transfer_resumed", td::JsonBool{ok});
      e("sha256_hex", td::hex_encode(completed.expected_payload_hash.as_slice()));
      e("millis", millis);
      if (!completed.failure.empty()) {
        e("error", completed.failure);
      }
    }
    emit_line(jb.string_builder().as_cslice());
  }

  // ---- echo ----

  void cmd_echo(td::int64 id, td::JsonObject &obj) {
    if (!listening_ || !have_peer_ || !peer_confirmed_) {
      emit_error(id, "no confirmed peer to echo against");
      return;
    }
    td::int64 bytes;
    td::int64 timeout_ms;
    if (!read_long_field(id, obj, "bytes", 1024, bytes) ||
        !read_bounded_param(id, obj, "timeout_ms", kMinTimeoutMs, kMaxTimeoutMs, timeout_ms)) {
      return;
    }
    if (bytes <= 0) {
      emit_error(id, "\"bytes\" must be > 0");
      return;
    }
    if (!acquire_session_lease(id)) {
      return;
    }
    // validate the size BEFORE any allocation: the failure path must not
    // allocate or hash the requested payload (a huge bytes value would
    // otherwise be an out-of-memory crash vector), so it reports an empty
    // sha256_hex
    if (bytes > static_cast<td::int64>(kMaxQueryPayload - kEchoPrefix.size())) {
      td::JsonBuilder jb;
      {
        auto e = jb.enter_object();
        e("id", id);
        e("event", "echoed");
        e("ok", td::JsonBool{false});
        e("sha256_hex", "");
        e("millis", static_cast<td::int64>(0));
        e("error", PSTRING() << "payload of " << bytes << "+" << kEchoPrefix.size()
                             << " bytes exceeds the native adnl query cap huge_packet_max_size=" << kMaxQueryPayload
                             << " bytes");
      }
      emit_line(jb.string_builder().as_cslice());
      return;
    }
    echo_ = EchoOp{};
    echo_.active = true;
    echo_.cmd_id = id;
    echo_.started = td::Timestamp::now();
    echo_.seq = ++op_seq_counter_;
    auto payload = make_echo_payload(static_cast<size_t>(bytes), echo_.expected);
    auto self = actor_id(this);
    auto seq = echo_.seq;
    auto P = td::PromiseCreator::lambda([self, seq](td::Result<td::BufferSlice> R) {
      td::actor::send_closure(self, &ProbeCore::echo_result, seq, std::move(R));
    });
    td::actor::send_closure(adnl_, &adnl::Adnl::send_query, local_id_, peer_id_, "probe-echo", std::move(P),
                            td::Timestamp::in(static_cast<double>(timeout_ms) / 1000.0), std::move(payload));
  }

  void echo_result(td::uint64 seq, td::Result<td::BufferSlice> R) {
    if (!echo_.active || echo_.seq != seq) {
      return;
    }
    auto id = echo_.cmd_id;
    auto millis = elapsed_ms(echo_.started);
    auto expected = echo_.expected;
    echo_ = EchoOp{};
    bool ok = false;
    std::string error;
    if (R.is_ok()) {
      auto answer = R.move_as_ok();
      if (answer.size() == 32 && answer.as_slice() == expected.as_slice()) {
        ok = true;
      } else {
        error = PSTRING() << "answer hash mismatch (got " << answer.size() << " bytes)";
      }
    } else {
      error = R.error().message().str();
    }
    td::JsonBuilder jb;
    {
      auto e = jb.enter_object();
      e("id", id);
      e("event", "echoed");
      e("ok", td::JsonBool{ok});
      e("sha256_hex", td::hex_encode(expected.as_slice()));
      e("millis", millis);
      if (!ok) {
        e("error", error);
      }
    }
    emit_line(jb.string_builder().as_cslice());
  }

  // ---- close ----

  void cmd_close(td::int64 id) {
    // exactly-one-completion: any in-flight operation gets its terminal
    // error event before the closed event
    cancel_outstanding("cancelled by close");
    td::JsonBuilder jb;
    {
      auto e = jb.enter_object();
      e("id", id);
      e("event", "closed");
    }
    emit_line(jb.string_builder().as_cslice());
    shutdown();
  }

  void shutdown() {
    if (stopping_) {
      return;
    }
    cancel_outstanding("cancelled by shutdown");
    stopping_ = true;
    rldp2_.reset();
    adnl_.reset();
    network_manager_.reset();
    keyring_.reset();
    g_stop.store(true, std::memory_order_release);
    stop();
  }
};

}  // namespace probe

}  // namespace tos

static std::string detect_toolchain() {
#if defined(__clang__)
  return PSTRING() << "clang " << __clang_major__ << "." << __clang_minor__ << "." << __clang_patchlevel__;
#elif defined(__GNUC__)
  return PSTRING() << "gcc " << __GNUC__ << "." << __GNUC_MINOR__ << "." << __GNUC_PATCHLEVEL__;
#else
  return "unknown";
#endif
}

static std::string detect_target() {
  std::string os =
#if defined(__linux__)
      "linux";
#elif defined(__APPLE__)
      "darwin";
#elif defined(_WIN32)
      "windows";
#else
      "unknown";
#endif
  std::string arch =
#if defined(__x86_64__) || defined(_M_X64)
      "amd64";
#elif defined(__aarch64__)
      "arm64";
#elif defined(__riscv)
      "riscv64";
#else
      "unknown";
#endif
  return os + "/" + arch;
}

int main(int argc, char *argv[]) {
  SET_VERBOSITY_LEVEL(verbosity_WARNING);
  td::set_default_failure_signal_handler().ensure();

  for (int i = 1; i < argc; i++) {
    auto arg = td::Slice(argv[i]);
    if (arg == "-V" || arg == "--version") {
      std::cout << "tos-adnl-probe build information: [ Commit: " << GitMetadata::CommitSHA1()
                << ", Date: " << GitMetadata::CommitDate() << "]\n";
      return 0;
    }
    if (arg == "-v" || arg == "--verbosity") {
      if (i + 1 < argc) {
        SET_VERBOSITY_LEVEL(VERBOSITY_NAME(FATAL) + td::to_integer<int>(td::Slice(argv[++i])));
      }
      continue;
    }
  }

  {
    td::JsonBuilder jb;
    {
      auto e = jb.enter_object();
      e("event", "hello");
      e("protocol", tos::probe::kProtocol);
      e("implementation", "tos-native-adnl");
      e("implementation_commit", GitMetadata::CommitSHA1());
      e("toolchain", detect_toolchain());
      e("target", detect_target());
    }
    tos::probe::emit_line(jb.string_builder().as_cslice());
  }

  auto queue = std::make_shared<tos::probe::LineQueue>();

  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<tos::probe::ProbeCore> core;
  scheduler.run_in_context(
      [&] { core = td::actor::create_actor<tos::probe::ProbeCore>("probe-core", queue); });

  std::thread stdin_thread([queue] {
    std::string line;
    while (std::getline(std::cin, line)) {
      std::lock_guard<std::mutex> guard(queue->mutex);
      queue->lines.push_back(std::move(line));
    }
    std::lock_guard<std::mutex> guard(queue->mutex);
    queue->eof = true;
  });
  stdin_thread.detach();

  while (scheduler.run(0.1)) {
    if (tos::probe::g_stop.load(std::memory_order_acquire)) {
      break;
    }
  }
  return 0;
}
