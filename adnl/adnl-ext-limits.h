/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>

#include "common/errorcode.h"
#include "td/utils/Status.h"

#include "adnl-source-share.h"

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

// Received bytes one server connection may hold before they form a frame.
// One maximal frame: a peer that has sent a frame's length may send the frame,
// and nothing past it is read until that frame has been taken off the buffer.
inline constexpr std::size_t adnl_ext_max_pending_input_bytes = adnl_ext_max_frame_bytes;

// Received bytes all of one server's external connections may hold together
// before they form frames. This is a budget of pending input bytes, not a
// ceiling on process memory: buffer blocks, the decrypted copy of a frame being
// dispatched and everything downstream of dispatch are outside it. Held bytes sit in 4 KiB chain-buffer blocks: the
// input budget test measures 53664 buffer bytes for 49996 held (1.07x), and a
// connection holding a single byte still has one 4 KiB block, at most 4 MiB
// across the 1024-connection limit. Sixteen maximal frames at once,
// matching the output side, keeps the external port's worst case at 512 MiB in
// both directions, inside the 4 GB testnet minimum host. Legitimate external
// traffic is small queries; the bound only bites when many peers hold large
// unfinished frames, and the partial-frame lifetime below ends those.
inline constexpr std::size_t adnl_ext_max_server_pending_input_bytes = std::size_t{256} << 20;

// The part of the server's input budget one source may hold, summed across all
// of that source's connections: one eighth, 32 MiB, which is two maximal frames.
// A source that asks for more has the connection that asked closed; no other
// connection is touched. Without it, one address within its 64-connection limit
// could hold the whole budget with sixteen unfinished frames, and every other
// external connection that needed to read would be closed. Sources are keyed by
// IPv4 address or IPv6 /64 (see network_source_key). This isolates sources; it
// is not a Sybil-resistant availability guarantee: eight sources can still
// together hold the whole budget.
inline constexpr std::size_t adnl_ext_max_source_pending_input_bytes =
    default_source_share(adnl_ext_max_server_pending_input_bytes);

// Bytes reserved from the shared input budget per read. Reads never take more
// than they reserved, so the budget is charged before the buffer grows.
inline constexpr std::size_t adnl_ext_input_read_chunk_bytes = std::size_t{64} << 10;

// How long a server connection may hold an unfinished frame, measured from the
// first byte of that frame it holds, however steadily bytes keep arriving. A
// maximal frame at the 10 Mbit/s testnet minimum bandwidth takes about 13.4 s;
// twice that leaves margin without letting a trickle keep 16 MiB pinned for the
// whole idle timeout.
inline constexpr double adnl_ext_partial_frame_lifetime_seconds = 30.0;

// Bytes shared by a server's connections. A connection reserves bytes before it
// holds them and releases them when it stops holding them, so connections on
// different threads cannot together pass the bound.
class AdnlExtByteBudget {
 public:
  explicit AdnlExtByteBudget(std::size_t limit = adnl_ext_max_server_pending_output_bytes) : limit_(limit) {
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
  // Take as much of `bytes` as fits under the limit; returns what was taken,
  // which is zero when the budget is spent.
  std::size_t try_reserve_up_to(std::size_t bytes) {
    auto used = used_.load();
    std::size_t taken = 0;
    do {
      if (used >= limit_) {
        return 0;
      }
      taken = std::min(bytes, limit_ - used);
    } while (!used_.compare_exchange_weak(used, used + taken));
    return taken;
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
  std::size_t limit() const {
    return limit_;
  }

 private:
  const std::size_t limit_;
  std::atomic<std::size_t> used_{0};
};

// Unread output shared by a server's connections.
using AdnlExtOutputBudget = AdnlExtByteBudget;

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
