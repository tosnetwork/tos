/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <cstddef>

#include "common/errorcode.h"
#include "td/utils/Status.h"

namespace tos::adnl {

inline constexpr std::size_t adnl_ext_max_packet_bytes = 1U << 24;
inline constexpr std::size_t adnl_ext_packet_framing_bytes = 64;

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
