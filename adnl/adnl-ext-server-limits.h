/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <string>

#include "common/checksum.h"
#include "td/utils/RateLimiterWindow.h"
#include "td/utils/port/IPAddress.h"

#include "adnl-source-share.h"

namespace tos::adnl {

// Outcome of admitting one external query; every denial names the budget that refused it.
enum class ExtAdmission {
  Acquired,
  PerConnectionRateLimited,
  PerConnectionInflightLimited,
  PerIpInflightLimited,
  ServerInflightLimited,
};

inline td::Bits256 external_peer_ip_identity(td::Slice peer_ip) {
  std::string material = "tos-adnl-ext-ip:";
  material.append(peer_ip.data(), peer_ip.size());
  return td::sha256_bits256(material);
}

// The anonymous identity and the per-IP rate-limiting key must both be derived
// from the same peer address. Deriving them together here keeps that from
// depending on argument evaluation order at the call site: moving the address
// into one argument while another argument still reads it is unspecified
// order, and on a compiler that evaluates the move first every anonymous peer
// would receive the identity of the empty string and every per-IP bucket would
// collapse into one -- silently, with the limits still appearing to work.
struct ExtConnectionIdentity {
  td::Bits256 anonymous_id;
  std::string peer_ip;
};

inline ExtConnectionIdentity make_ext_connection_identity(std::string peer_ip) {
  ExtConnectionIdentity result;
  result.anonymous_id = external_peer_ip_identity(peer_ip);
  result.peer_ip = std::move(peer_ip);
  return result;
}

// Small value types kept separate from the socket actor so admission behavior
// can be tested without opening real TCP connections.
//
// Connections are counted per source, the same key the input-byte share uses
// (network_source_key: IPv4 address or IPv6 /64), not per exact address: a
// host free to send from any address of its /64 would otherwise hold a
// per-source allowance for each of them and could fill the server-wide table
// while staying under its byte share. Admission takes the peer address, not a
// string, so a caller cannot key it by the exact address by mistake; the exact
// address stays the connection's identity for logging and query limits.
class ExtServerConnectionLimits {
 public:
  ExtServerConnectionLimits(size_t max_connections, size_t max_connections_per_source)
      : max_connections_(max_connections), max_connections_per_source_(max_connections_per_source) {
  }

  // Admit a connection from `peer`; returns the source it was counted under,
  // which release() takes back, or nothing when a limit refused it.
  std::optional<std::string> try_acquire(const td::IPAddress &peer) {
    auto source = network_source_key(peer);
    auto it = connections_per_source_.find(source);
    size_t per_source = it == connections_per_source_.end() ? 0 : it->second;
    if (connections_ >= max_connections_ || per_source >= max_connections_per_source_) {
      return std::nullopt;
    }
    ++connections_;
    ++connections_per_source_[source];
    return source;
  }

  void release(const std::string &source) {
    auto it = connections_per_source_.find(source);
    if (it == connections_per_source_.end() || it->second == 0) {
      return;
    }
    --connections_;
    if (--it->second == 0) {
      connections_per_source_.erase(it);
    }
  }

  size_t connections() const {
    return connections_;
  }
  size_t connections_from(const std::string &source) const {
    auto it = connections_per_source_.find(source);
    return it == connections_per_source_.end() ? 0 : it->second;
  }
  // Sources holding a connection; an entry is erased when its last one closes.
  size_t sources() const {
    return connections_per_source_.size();
  }

 private:
  size_t max_connections_;
  size_t max_connections_per_source_;
  size_t connections_{0};
  std::map<std::string, size_t> connections_per_source_;
};

class ExtConnectionQueryLimits {
 public:
  ExtConnectionQueryLimits(double window, size_t max_queries_per_window, size_t max_inflight)
      : rate_(window, max_queries_per_window), max_inflight_(max_inflight) {
  }

  ExtAdmission try_acquire(td::Timestamp now = td::Timestamp::now()) {
    if (inflight_ >= max_inflight_) {
      return ExtAdmission::PerConnectionInflightLimited;
    }
    if (!rate_.check(now)) {
      return ExtAdmission::PerConnectionRateLimited;
    }
    rate_.insert(now);
    ++inflight_;
    return ExtAdmission::Acquired;
  }

  void release() {
    if (inflight_ != 0) {
      --inflight_;
    }
  }

  size_t inflight() const {
    return inflight_;
  }

 private:
  td::RateLimiterWindow rate_;
  size_t max_inflight_;
  size_t inflight_{0};
};

// The source a connection's server-wide query allowance is counted under:
// network_source_key of the peer address (IPv4 address or IPv6 /64), the same
// key as the connection and input-byte shares. Built only from an address, so
// a caller cannot count queries under the exact address by mistake; the exact
// address stays the connection's identity for logging.
class ExtSourceKey {
 public:
  explicit ExtSourceKey(const td::IPAddress &peer) : key_(network_source_key(peer)) {
  }
  const std::string &str() const {
    return key_;
  }

 private:
  std::string key_;
};

// Parked and executing queries across a server's connections: at most
// `max_inflight` in all and `max_inflight_per_source` for one source. Counting
// per source rather than per exact address keeps one IPv6 /64 from holding an
// allowance for every address it sends from.
class ExtServerQueryLimits {
 public:
  ExtServerQueryLimits(size_t max_inflight, size_t max_inflight_per_source)
      : max_inflight_(max_inflight), max_inflight_per_source_(max_inflight_per_source) {
  }

  ExtAdmission try_acquire(const ExtSourceKey &source) {
    std::lock_guard lock(mutex_);
    if (inflight_ >= max_inflight_) {
      return ExtAdmission::ServerInflightLimited;
    }
    auto it = inflight_per_source_.find(source.str());
    size_t per_source = it == inflight_per_source_.end() ? 0 : it->second;
    if (per_source >= max_inflight_per_source_) {
      return ExtAdmission::PerIpInflightLimited;
    }
    ++inflight_;
    ++inflight_per_source_[source.str()];
    return ExtAdmission::Acquired;
  }

  void release(const ExtSourceKey &source) {
    std::lock_guard lock(mutex_);
    auto it = inflight_per_source_.find(source.str());
    if (it == inflight_per_source_.end() || it->second == 0) {
      return;
    }
    --inflight_;
    if (--it->second == 0) {
      inflight_per_source_.erase(it);
    }
  }

  size_t inflight() const {
    std::lock_guard lock(mutex_);
    return inflight_;
  }
  size_t inflight_from(const ExtSourceKey &source) const {
    std::lock_guard lock(mutex_);
    auto it = inflight_per_source_.find(source.str());
    return it == inflight_per_source_.end() ? 0 : it->second;
  }
  // Sources with a query in flight; an entry is erased when its last one ends.
  size_t sources() const {
    std::lock_guard lock(mutex_);
    return inflight_per_source_.size();
  }

 private:
  size_t max_inflight_;
  size_t max_inflight_per_source_;
  mutable std::mutex mutex_;
  size_t inflight_{0};
  std::map<std::string, size_t> inflight_per_source_;
};

}  // namespace tos::adnl
