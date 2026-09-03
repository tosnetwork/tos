/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <map>
#include <string>

#include "td/utils/RateLimiterWindow.h"

namespace tos::adnl {

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

}  // namespace tos::adnl
