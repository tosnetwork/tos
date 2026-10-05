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

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

// Where the native JSON-RPC listener may bind.
//
// The listener speaks plaintext HTTP. With write methods enabled, anything
// that can read the traffic between a remote client and a non-loopback
// listener can read the X-API-Key header and replay it, so an API key does
// not make a remote plaintext write listener safe. A write-enabled listener
// therefore binds a loopback address only; remote writes go through an
// authenticated TLS reverse proxy that forwards to that loopback listener.
// Only a read-only listener may bind a non-loopback address.
//
// The decision depends only on the bound address and the read-only flag. It
// deliberately ignores the API key and every proxy header (X-Forwarded-Proto
// and the like): a client controls those headers, and the listener cannot
// tell whether a hop it does not terminate was encrypted.

#include <cstddef>
#include <string>

#include "td/utils/Status.h"
#include "td/utils/logging.h"
#include "td/utils/port/IPAddress.h"

namespace tos::json_rpc {

enum class ListenDecision {
  Accept,
  RefuseWriteNonLoopback,
};

// True only for an address on the loopback interface: 127.0.0.0/8 or ::1.
// Every other address, including the unspecified ones (0.0.0.0, ::) and
// IPv4-mapped IPv6 forms, is treated as reachable from outside the host.
inline bool is_loopback_bind_address(const td::IPAddress& addr) {
  if (!addr.is_valid()) {
    return false;
  }
  if (addr.is_ipv4()) {
    // get_ipv4() returns the address in host byte order, so the first octet
    // is the most significant byte.
    const td::uint32 raw = addr.get_ipv4();
    return (raw >> 24) == 127u;
  }
  if (addr.is_ipv6()) {
    const std::string bytes = addr.get_ipv6();
    if (bytes.size() != 16) {
      return false;
    }
    for (std::size_t i = 0; i + 1 < bytes.size(); i++) {
      if (bytes[i] != 0) {
        return false;
      }
    }
    return static_cast<unsigned char>(bytes[15]) == 1u;
  }
  return false;
}

inline ListenDecision decide_listen_admission(bool is_loopback, bool readonly) {
  if (!is_loopback && !readonly) {
    return ListenDecision::RefuseWriteNonLoopback;
  }
  return ListenDecision::Accept;
}

// The startup check. An error here must stop the process before it serves
// anything: a node that silently runs without the RPC its operator asked for
// is a misconfiguration nobody notices, and one that serves it on the wrong
// boundary is the problem this check exists to prevent.
inline td::Status check_listen_admission(const td::IPAddress& addr, bool readonly) {
  switch (decide_listen_admission(is_loopback_bind_address(addr), readonly)) {
    case ListenDecision::Accept:
      return td::Status::OK();
    case ListenDecision::RefuseWriteNonLoopback:
      return td::Status::Error(
          PSLICE() << "JSON-RPC: refusing to bind write-enabled plaintext listener to non-loopback address " << addr
                   << ". Bind --json-rpc-address to 127.0.0.1 or [::1] and put an authenticated TLS reverse proxy in "
                      "front of it for remote writes, or pass --json-rpc-readonly. An API key does not make a "
                      "remote plaintext write listener acceptable.");
  }
  return td::Status::Error("JSON-RPC: unknown listen decision");
}

}  // namespace tos::json_rpc
