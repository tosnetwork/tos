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

    Copyright 2019-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

// The site side of an HTTP CONNECT tunnel carried over RLDP: a remote peer
// asks the proxy to open a TCP connection to a configured backend, and the
// bytes of that connection travel as payload parts in both directions.
//
// Every tunnel holds a socket and an actor for as long as it lives, so the
// proxy admits a bounded number of them (in total and per peer), ends each
// one that moves no bytes for an idle timeout or outlives a maximum
// lifetime, and releases the socket and actor on every terminal path.

#include <atomic>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <mutex>

#include "adnl/adnl.h"
#include "auto/tl/tos_api.h"
#include "td/actor/actor.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/Observer.h"
#include "td/utils/Status.h"
#include "td/utils/Time.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/port/SocketFd.h"

namespace tos::rldp_http {

// Concurrent tunnels the proxy admits from all peers together. Each holds one
// TCP socket, so the default stays well inside the common 1024-descriptor
// soft limit and leaves room for the listener, the ADNL socket and ordinary
// forwarded requests.
constexpr std::size_t kDefaultMaxTunnels = 512;
// Concurrent tunnels from one ADNL peer. Browsers open about six connections
// per site, so a client with several tabs on a few sites fits; one peer
// cannot take the whole global allowance. ADNL ids are cheap to create, so
// this bounds a single well-behaved or careless client, not a peer that mints
// identities. Against identity spraying the global cap bounds only the
// resources tunnels hold (sockets, actors); it does not keep the proxy
// available: such a peer can hold every global slot, and other peers' CONNECTs
// are then refused until those tunnels end.
constexpr std::size_t kDefaultMaxTunnelsPerPeer = 16;
// A tunnel that moves no bytes in either direction for this long is closed.
// Ten minutes outlasts the keep-alive idle periods of browsers and TLS
// servers (tens of seconds to a few minutes), so live interactive sessions are
// not cut, while an abandoned tunnel gives its socket back in bounded time.
constexpr double kDefaultTunnelIdleTimeout = 600.0;
// A tunnel is closed this long after it opened, however busy it is: a day
// covers long downloads and long-lived streaming sessions, and guarantees
// that every socket is eventually reclaimed.
constexpr double kDefaultTunnelMaxLifetime = 86400.0;

// Longest delay, in seconds, accepted for any deadline here. The I/O worker
// turns the earliest pending deadline into an int32 millisecond wait, so a
// longer delay cannot be represented there (about 24.8 days). Values such as
// 1e300 or infinity are refused rather than turned into a deadline that
// never arrives.
constexpr double kMaxDeadlineSeconds = 2147483.0;

// Largest values the command-line options accept.
constexpr std::size_t kMaxTunnelLimit = 65536;
constexpr double kMaxTunnelIdleTimeout = 7 * 86400.0;
constexpr double kMaxTunnelLifetime = kMaxDeadlineSeconds;

struct TunnelTimeouts {
  double idle = kDefaultTunnelIdleTimeout;
  double max_lifetime = kDefaultTunnelMaxLifetime;
};

// Largest --forward-timeout (seconds a request forwarded to a local HTTP
// server may take in total, response included). Large downloads can
// legitimately take hours, so the only limit is that the deadline stays
// representable.
constexpr double kMaxHttpForwardTimeout = kMaxDeadlineSeconds;

// "<n>" with 1 <= n <= kMaxTunnelLimit, digits only.
td::Result<std::size_t> parse_tunnel_limit(td::Slice text);
// A number of seconds with 0 < value <= max, written as a plain decimal
// number (no leading space, no trailing text, finite).
td::Result<double> parse_positive_seconds(td::Slice text, double max);

// Counts admitted tunnels. Safe to use from any thread: a tunnel actor
// releases its admission when it is destroyed, on whatever scheduler thread
// that happens.
class TunnelAdmission : public std::enable_shared_from_this<TunnelAdmission> {
 public:
  // Held by an admitted tunnel; releases the admission when destroyed.
  class Ticket {
   public:
    Ticket() = default;
    Ticket(Ticket &&other) noexcept = default;
    Ticket &operator=(Ticket &&other) noexcept;
    Ticket(const Ticket &) = delete;
    Ticket &operator=(const Ticket &) = delete;
    ~Ticket();

   private:
    friend class TunnelAdmission;
    Ticket(std::shared_ptr<TunnelAdmission> owner, adnl::AdnlNodeIdShort peer);
    void release();

    std::shared_ptr<TunnelAdmission> owner_;
    adnl::AdnlNodeIdShort peer_;
  };

  TunnelAdmission(std::size_t max_tunnels, std::size_t max_tunnels_per_peer)
      : max_tunnels_(max_tunnels), max_tunnels_per_peer_(max_tunnels_per_peer) {
  }

  // Refuses when the global or the peer's limit is already reached.
  td::Result<Ticket> admit(adnl::AdnlNodeIdShort peer);

  std::size_t active() const;
  std::size_t active_for(adnl::AdnlNodeIdShort peer) const;

 private:
  void release(adnl::AdnlNodeIdShort peer);

  const std::size_t max_tunnels_;
  const std::size_t max_tunnels_per_peer_;
  mutable std::mutex mutex_;
  std::size_t active_ = 0;
  std::map<adnl::AdnlNodeIdShort, std::size_t> per_peer_;
};

// Releases a payload-part handler registration when destroyed.
class PayloadSenderRegistry;
using RegisteredPayloadSenderGuard =
    std::unique_ptr<std::pair<td::actor::ActorId<PayloadSenderRegistry>, td::Bits256>,
                    std::function<void(std::pair<td::actor::ActorId<PayloadSenderRegistry>, td::Bits256> *)>>;
using PayloadPartHandler =
    std::function<void(tl_object_ptr<tos_api::http_getNextPayloadPart>, td::Promise<td::BufferSlice>)>;

// Routes incoming payload-part queries to the actor serving that transfer id.
class PayloadSenderRegistry : public td::actor::Actor {
 public:
  virtual void register_payload_sender(td::Bits256 id, PayloadPartHandler handler,
                                       td::Promise<RegisteredPayloadSenderGuard> promise) = 0;
  virtual void unregister_payload_sender(td::Bits256 id) = 0;

 protected:
  RegisteredPayloadSenderGuard make_guard(td::Bits256 id);
};

class RldpTcpTunnel : public td::actor::Actor, private td::ObserverBase {
 public:
  RldpTcpTunnel(td::Bits256 transfer_id, adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort local_id,
                td::actor::ActorId<adnl::AdnlSenderInterface> rldp, td::actor::ActorId<PayloadSenderRegistry> registry,
                td::SocketFd fd, TunnelTimeouts timeouts, TunnelAdmission::Ticket ticket);
  ~RldpTcpTunnel() override;

  // Tunnel actors currently alive in this process.
  static std::size_t live_count() {
    return live_count_.load();
  }

  void start_up() override;
  void tear_down() override;
  void alarm() override;

  void registered_sender(td::Result<RegisteredPayloadSenderGuard> R);
  void receive_query(tl_object_ptr<tos_api::http_getNextPayloadPart> f, td::Promise<td::BufferSlice> promise);
  void got_data_from_rldp(td::Result<td::BufferSlice> R);
  void answer_query(bool allow_empty = false, bool from_timer = false);

 private:
  void notify() override;
  void process();
  void request_data();
  // The one way a tunnel ends: fails a pending peer query, then stops the
  // actor, which closes the socket and releases the registration and the
  // admission. Later calls do nothing.
  void finish(td::Status reason);
  void touch();
  void rearm();

  static std::atomic<std::size_t> live_count_;

  td::Bits256 id_;
  RegisteredPayloadSenderGuard guard_;

  adnl::AdnlNodeIdShort src_;
  adnl::AdnlNodeIdShort local_id_;
  td::actor::ActorId<adnl::AdnlSenderInterface> rldp_;
  td::actor::ActorId<PayloadSenderRegistry> registry_;

  td::BufferedFd<td::SocketFd> fd_;

  TunnelTimeouts timeouts_;
  TunnelAdmission::Ticket ticket_;
  td::Timestamp lifetime_deadline_;
  td::Timestamp idle_deadline_;
  // When a peer query held open for lack of data is answered empty, so the
  // peer's own query timeout does not end a quiet tunnel.
  td::Timestamp query_deadline_;

  td::actor::ActorId<RldpTcpTunnel> self_;

  td::int32 cur_seqno_ = 0, cur_max_chunk_size_ = 0;
  td::Promise<td::BufferSlice> cur_promise_;
  td::int32 out_seqno_ = 0;
  bool close_ = false, sent_request_ = false, got_last_part_ = false;
  bool active_timer_ = false;
  bool finished_ = false;
};

// What a tunnel needs from the proxy that starts it.
struct TunnelEnvironment {
  td::actor::ActorId<adnl::AdnlSenderInterface> rldp;
  td::actor::ActorId<PayloadSenderRegistry> registry;
  std::shared_ptr<TunnelAdmission> admission;
  TunnelTimeouts timeouts;
};

enum class TunnelStart { started, refused, unreachable };

// Admits a tunnel for `src`, opens a TCP connection to `backend` and starts
// the tunnel actor. A refused tunnel opens no socket.
TunnelStart start_tcp_tunnel(const TunnelEnvironment &env, td::Bits256 id, adnl::AdnlNodeIdShort src,
                             adnl::AdnlNodeIdShort local_id, td::IPAddress backend);

}  // namespace tos::rldp_http
