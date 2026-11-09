/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <string>

#include "common/checksum.h"
#include "td/utils/port/IPAddress.h"

#include "adnl-source-share.h"

namespace tos::adnl {

inline td::Bits256 external_peer_ip_identity(td::Slice peer_ip) {
  std::string material = "tos-adnl-ext-ip:";
  material.append(peer_ip.data(), peer_ip.size());
  return td::sha256_bits256(material);
}

// The anonymous identity and the per-IP logging key must both be derived from
// the same peer address. Deriving them together here keeps that from depending
// on argument evaluation order at the call site: moving the address into one
// argument while another argument still reads it is unspecified order, and on a
// compiler that evaluates the move first every anonymous peer would receive the
// identity of the empty string -- silently.
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

// The source a connection's input and output byte shares are counted under:
// network_source_key of the peer address (IPv4 address or IPv6 /64). Built only
// from an address, so a caller cannot count bytes under the exact address by
// mistake; the exact address stays the connection's identity for logging.
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

}  // namespace tos::adnl
