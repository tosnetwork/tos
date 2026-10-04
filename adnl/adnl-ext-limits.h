/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <atomic>
#include <cstddef>

#include "common/errorcode.h"
#include "td/utils/Status.h"

namespace tos::adnl {

inline constexpr std::size_t adnl_ext_max_packet_bytes = 1U << 24;
inline constexpr std::size_t adnl_ext_packet_framing_bytes = 64;
// A packet on the wire: its 4-byte length prefix plus the packet itself.
inline constexpr std::size_t adnl_ext_max_frame_bytes = 4 + adnl_ext_max_packet_bytes;
// Encrypted bytes one connection may hold for a peer that has not read them.
// Two full frames: a maximal reply can always queue behind one in flight.
// Query admission is released when a reply is queued, not when it is read,
// so without this bound a peer that keeps asking and never reads grows the
// queue without limit.
inline constexpr std::size_t adnl_ext_max_pending_output_bytes = 2 * adnl_ext_max_frame_bytes;

// Unread output all of one server's external connections may hold together.
// The per-connection bound times the connection limit would be tens of GiB.
inline constexpr std::size_t adnl_ext_max_server_pending_output_bytes = std::size_t{256} << 20;

// Unread output shared by a server's connections. A connection reserves a
// frame's bytes before queuing it and releases them as they are written, so
// connections on different threads cannot together pass the bound.
class AdnlExtOutputBudget {
 public:
  explicit AdnlExtOutputBudget(std::size_t limit = adnl_ext_max_server_pending_output_bytes) : limit_(limit) {
  }
  // Take `bytes` if they fit under the limit; all or nothing.
  bool try_reserve(std::size_t bytes) {
    auto used = used_.load();
    do {
      if (used > limit_ || bytes > limit_ - used) {
        return false;
      }
    } while (!used_.compare_exchange_weak(used, used + bytes));
    return true;
  }
  // Give back bytes this connection reserved. False if more is given back
  // than is held, which is an accounting error; nothing is then released.
  bool release(std::size_t bytes) {
    auto used = used_.load();
    do {
      if (bytes > used) {
        return false;
      }
    } while (!used_.compare_exchange_weak(used, used - bytes));
    return true;
  }
  std::size_t used() const {
    return used_.load();
  }

 private:
  const std::size_t limit_;
  std::atomic<std::size_t> used_{0};
};

// Whether a frame of `frame_bytes` may join `pending_bytes` already queued.
inline bool adnl_ext_output_fits(std::size_t pending_bytes, std::size_t frame_bytes,
                                 std::size_t maximum_pending_bytes = adnl_ext_max_pending_output_bytes) {
  return frame_bytes <= maximum_pending_bytes && pending_bytes <= maximum_pending_bytes - frame_bytes;
}

inline td::Status check_adnl_ext_payload_size(std::size_t payload_bytes,
                                              std::size_t maximum_packet_bytes = adnl_ext_max_packet_bytes) {
  if (maximum_packet_bytes < adnl_ext_packet_framing_bytes ||
      payload_bytes > maximum_packet_bytes - adnl_ext_packet_framing_bytes) {
    return td::Status::Error(ErrorCode::protoviolation, "ADNL external payload exceeds packet limit");
  }
  return td::Status::OK();
}

inline td::Status check_adnl_ext_framed_size(std::size_t packet_bytes,
                                             std::size_t maximum_packet_bytes = adnl_ext_max_packet_bytes) {
  if (packet_bytes < adnl_ext_packet_framing_bytes || packet_bytes > maximum_packet_bytes) {
    return td::Status::Error(ErrorCode::protoviolation, "bad ADNL external packet size");
  }
  return td::Status::OK();
}

}  // namespace tos::adnl
