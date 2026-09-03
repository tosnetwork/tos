/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <map>
#include <mutex>
#include <string>

#include "common/checksum.h"
#include "td/utils/RateLimiterWindow.h"

namespace tos::adnl {

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
class ExtServerConnectionLimits {
 public:
  ExtServerConnectionLimits(size_t max_connections, size_t max_connections_per_ip)
      : max_connections_(max_connections), max_connections_per_ip_(max_connections_per_ip) {
  }

  bool try_acquire(const std::string &peer_ip) {
    auto it = connections_per_ip_.find(peer_ip);
    size_t per_ip = it == connections_per_ip_.end() ? 0 : it->second;
    if (connections_ >= max_connections_ || per_ip >= max_connections_per_ip_) {
      return false;
    }
    ++connections_;
    ++connections_per_ip_[peer_ip];
    return true;
  }

  void release(const std::string &peer_ip) {
    auto it = connections_per_ip_.find(peer_ip);
    if (it == connections_per_ip_.end() || it->second == 0) {
      return;
    }
    --connections_;
    if (--it->second == 0) {
      connections_per_ip_.erase(it);
    }
  }

  size_t connections() const {
    return connections_;
  }

 private:
  size_t max_connections_;
  size_t max_connections_per_ip_;
  size_t connections_{0};
  std::map<std::string, size_t> connections_per_ip_;
};

class ExtConnectionQueryLimits {
 public:
  ExtConnectionQueryLimits(double window, size_t max_queries_per_window, size_t max_inflight)
      : rate_(window, max_queries_per_window), max_inflight_(max_inflight) {
  }

  bool try_acquire(td::Timestamp now = td::Timestamp::now()) {
    if (inflight_ >= max_inflight_ || !rate_.check(now)) {
      return false;
    }
    rate_.insert(now);
    ++inflight_;
    return true;
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

class ExtServerQueryLimits {
 public:
  ExtServerQueryLimits(size_t max_inflight, size_t max_inflight_per_ip)
      : max_inflight_(max_inflight), max_inflight_per_ip_(max_inflight_per_ip) {
  }

  bool try_acquire(const std::string &peer_ip) {
    std::lock_guard lock(mutex_);
    auto it = inflight_per_ip_.find(peer_ip);
    size_t per_ip = it == inflight_per_ip_.end() ? 0 : it->second;
    if (inflight_ >= max_inflight_ || per_ip >= max_inflight_per_ip_) {
      return false;
    }
    ++inflight_;
    ++inflight_per_ip_[peer_ip];
    return true;
  }

  void release(const std::string &peer_ip) {
    std::lock_guard lock(mutex_);
    auto it = inflight_per_ip_.find(peer_ip);
    if (it == inflight_per_ip_.end() || it->second == 0) {
      return;
    }
    --inflight_;
    if (--it->second == 0) {
      inflight_per_ip_.erase(it);
    }
  }

  size_t inflight() const {
    std::lock_guard lock(mutex_);
    return inflight_;
  }

 private:
  size_t max_inflight_;
  size_t max_inflight_per_ip_;
  mutable std::mutex mutex_;
  size_t inflight_{0};
  std::map<std::string, size_t> inflight_per_ip_;
};

}  // namespace tos::adnl
