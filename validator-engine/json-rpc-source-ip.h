/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <string>
#include <vector>

namespace tos {

// Trim ASCII whitespace from both ends of a string.
inline std::string source_ip_trim_ws(std::string s) {
  size_t start = 0;
  while (start < s.size() && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n')) {
    ++start;
  }
  size_t end = s.size();
  while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r' || s[end - 1] == '\n')) {
    --end;
  }
  if (start == 0 && end == s.size()) {
    return s;
  }
  return s.substr(start, end - start);
}

// True when `peer` is on the loopback interface (127.0.0.0/8, ::1, or the
// canonical-uncompressed IPv6 loopback). Loopback peers are implicit trust
// anchors for proxy headers.
inline bool source_ip_is_loopback(const std::string& peer) {
  if (peer == "127.0.0.1") {
    return true;
  }
  if (peer == "::1") {
    return true;
  }
  if (peer == "0:0:0:0:0:0:0:1") {
    return true;
  }
  if (peer.size() >= 4 && peer.compare(0, 4, "127.") == 0) {
    return true;
  }
  return false;
}

// True when `addr` is a configured trusted proxy (verbatim textual match, no
// CIDR / DNS).
inline bool source_ip_is_trusted_proxy(const std::string& addr, const std::vector<std::string>& trusted_proxies) {
  for (const auto& p : trusted_proxies) {
    if (p == addr) {
      return true;
    }
  }
  return false;
}

// True when `peer` is loopback or a configured trusted proxy.
inline bool source_ip_is_loopback_or_trusted(const std::string& peer, const std::vector<std::string>& trusted_proxies) {
  return source_ip_is_loopback(peer) || source_ip_is_trusted_proxy(peer, trusted_proxies);
}

// Resolve the originating client IP for the per-IP rate limiter.
//
// Attribution starts from the real TCP peer IP captured at accept time. Only
// when `trust_proxy_headers` is set AND the peer is loopback or a configured
// trusted proxy are forwarding headers honoured.
//
// X-Forwarded-For is a comma-separated proxy chain appended left-to-right: the
// leftmost entry is whatever the ORIGINAL client sent (forgeable), and each
// proxy appends the address it observed. A common edge-proxy config (e.g.
// nginx `$proxy_add_x_forwarded_for`) appends rather than replaces, so trusting
// the leftmost entry would let a caller spoof its source IP. The real client as
// seen by our trusted edge is the RIGHTMOST entry that is not itself one of our
// configured trusted proxies: walk from the right, peel known trusted-proxy
// hops, and take the first untrusted entry. This is correct whether the edge
// proxy appends or replaces the header, and for single- and multi-hop chains
// (each intermediary proxy must be listed as trusted for multi-hop peeling).
//
// An empty result is bucketed into a shared "unknown" slot so an unattributed
// caller still throttles rather than bypassing the per-IP gate.
inline std::string resolve_client_source_ip(const std::string& peer_ip, const std::string& forwarded_for,
                                            const std::string& real_ip, bool trust_proxy_headers,
                                            const std::vector<std::string>& trusted_proxies) {
  std::string source = peer_ip;
  if (trust_proxy_headers && source_ip_is_loopback_or_trusted(peer_ip, trusted_proxies)) {
    if (!forwarded_for.empty()) {
      std::vector<std::string> hops;
      size_t start = 0;
      while (true) {
        auto comma = forwarded_for.find(',', start);
        auto end = (comma == std::string::npos) ? forwarded_for.size() : comma;
        std::string hop = source_ip_trim_ws(forwarded_for.substr(start, end - start));
        if (!hop.empty()) {
          hops.push_back(std::move(hop));
        }
        if (comma == std::string::npos) {
          break;
        }
        start = comma + 1;
      }
      bool found_client = false;
      for (auto it = hops.rbegin(); it != hops.rend(); ++it) {
        if (!source_ip_is_trusted_proxy(*it, trusted_proxies)) {
          source = *it;
          found_client = true;
          break;
        }
      }
      // Every hop is a configured trusted proxy (no client hop present): fall
      // back to the leftmost entry rather than attributing to a proxy.
      if (!found_client && !hops.empty()) {
        source = hops.front();
      }
    } else if (!real_ip.empty()) {
      std::string xri = source_ip_trim_ws(real_ip);
      if (!xri.empty()) {
        source = std::move(xri);
      }
    }
  }
  if (source.empty()) {
    source = "unknown";
  }
  return source;
}

}  // namespace tos
