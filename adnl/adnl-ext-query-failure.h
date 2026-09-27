/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "td/utils/Status.h"
#include "td/utils/Time.h"
#include "td/utils/buffer.h"

namespace tos::adnl {

// Why an external query that already carries a parsed query ID could not be served.
enum class ExtQueryFailureKind {
  PerConnectionRateLimit,
  PerConnectionInflightLimit,
  ServerInflightLimit,
  PerIpInflightLimit,
  HandlerError,
  ResponseTooLarge,
};

inline const char *ext_query_failure_kind_name(ExtQueryFailureKind kind) {
  switch (kind) {
    case ExtQueryFailureKind::PerConnectionRateLimit:
      return "per_connection_rate";
    case ExtQueryFailureKind::PerConnectionInflightLimit:
      return "per_connection_inflight";
    case ExtQueryFailureKind::ServerInflightLimit:
      return "server";
    case ExtQueryFailureKind::PerIpInflightLimit:
      return "per_ip";
    case ExtQueryFailureKind::HandlerError:
      return "handler_error";
    case ExtQueryFailureKind::ResponseTooLarge:
      return "response_too_large";
  }
  return "unknown";
}

struct ExtQueryFailure {
  ExtQueryFailureKind kind;
  // The handler's error for HandlerError; OK otherwise. Encoders must not reflect
  // its text to the client unchecked.
  td::Status status;
};

// Turns a failure into the service's own answer bytes for the original query ID.
// The generic external server never guesses a service protocol: a service that
// installs no encoder gets its connection closed instead of a failure answer.
class ExtQueryFailureEncoder {
 public:
  virtual td::Result<td::BufferSlice> encode(const ExtQueryFailure &failure) const = 0;
  virtual ~ExtQueryFailureEncoder() = default;
};

// A failure answer is a small fixed message; anything larger is not sent.
constexpr size_t kMaxExtQueryFailurePayloadBytes = 1024;

// Independent budget for failure answers, so rejected queries cannot be turned
// into unbounded outbound work. Counts are per fixed one-second window, per IP and
// server-wide. A peer denied a failure answer gets its connection closed instead.
class ExtFailureReplyLimits {
 public:
  ExtFailureReplyLimits(double window, size_t max_per_ip, size_t max_global, size_t max_tracked_ips)
      : window_(window), max_per_ip_(max_per_ip), max_global_(max_global), max_tracked_ips_(max_tracked_ips) {
  }

  bool try_acquire(const std::string &peer_ip, td::Timestamp now = td::Timestamp::now()) {
    std::lock_guard lock(mutex_);
    roll(global_, now);
    if (global_.count >= max_global_) {
      return false;
    }
    auto it = per_ip_.find(peer_ip);
    if (it == per_ip_.end()) {
      if (per_ip_.size() >= max_tracked_ips_) {
        drop_expired(now);
      }
      if (per_ip_.size() >= max_tracked_ips_) {
        return false;
      }
      it = per_ip_.emplace(peer_ip, Window{now, 0}).first;
    }
    roll(it->second, now);
    if (it->second.count >= max_per_ip_) {
      return false;
    }
    ++it->second.count;
    ++global_.count;
    return true;
  }

  size_t tracked_ips() const {
    std::lock_guard lock(mutex_);
    return per_ip_.size();
  }

 private:
  struct Window {
    td::Timestamp start;
    size_t count{0};
  };

  void roll(Window &window, td::Timestamp now) const {
    if (!window.start || now.at() - window.start.at() >= window_) {
      window.start = now;
      window.count = 0;
    }
  }

  void drop_expired(td::Timestamp now) {
    for (auto it = per_ip_.begin(); it != per_ip_.end();) {
      if (now.at() - it->second.start.at() >= window_) {
        it = per_ip_.erase(it);
      } else {
        ++it;
      }
    }
  }

  double window_;
  size_t max_per_ip_;
  size_t max_global_;
  size_t max_tracked_ips_;
  mutable std::mutex mutex_;
  Window global_;
  std::map<std::string, Window> per_ip_;
};

// Shared by an external server and all its connections. The encoder may be
// installed after the server starts; until then every failure closes the connection.
class ExtQueryFailurePolicy {
 public:
  static constexpr double kReplyWindowSeconds = 1.0;
  static constexpr size_t kMaxRepliesPerConnection = 16;
  static constexpr size_t kMaxRepliesPerIp = 32;
  static constexpr size_t kMaxRepliesGlobal = 256;
  static constexpr size_t kMaxTrackedIps = 4096;

  void set_encoder(std::shared_ptr<const ExtQueryFailureEncoder> encoder) {
    std::lock_guard lock(mutex_);
    encoder_ = std::move(encoder);
  }

  std::shared_ptr<const ExtQueryFailureEncoder> encoder() const {
    std::lock_guard lock(mutex_);
    return encoder_;
  }

  ExtFailureReplyLimits &reply_limits() {
    return reply_limits_;
  }

 private:
  mutable std::mutex mutex_;
  std::shared_ptr<const ExtQueryFailureEncoder> encoder_;
  ExtFailureReplyLimits reply_limits_{kReplyWindowSeconds, kMaxRepliesPerIp, kMaxRepliesGlobal, kMaxTrackedIps};
};

}  // namespace tos::adnl
