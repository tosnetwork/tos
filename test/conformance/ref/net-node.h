// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// In-process node pieces for the net harness: the node's own ADNL peer table, keyring and overlay actors
// run on a single-threaded scheduler (every actor on the calling thread, in message order), with
// recording stand-ins only at the network edge. A refusal on these paths is a dropped datagram or
// message that the node reports only in its log, so the log is captured while a context runs and the
// node's text is classified by the same table as every other refusal.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "adnl/adnl-network-manager.h"
#include "td/utils/logging.h"
#include "td/utils/port/IPAddress.h"

namespace conformance::net {

// The address every inbound datagram of a context comes from (TEST-NET-1, RFC 5737); it is what the
// receiver's pre-authentication gate keys its budgets on.
td::Result<td::IPAddress> datagram_source();

// The node's log lines while it is alive, at every ADNL and overlay verbosity. Restores the previous
// log interface and verbosity when destroyed. One per context; not reentrant.
class NodeLog final : public td::LogInterface {
 public:
  NodeLog();
  ~NodeLog() override;
  NodeLog(const NodeLog &) = delete;
  NodeLog &operator=(const NodeLog &) = delete;
  NodeLog(NodeLog &&) = delete;
  NodeLog &operator=(NodeLog &&) = delete;

  void append(td::CSlice slice, int log_level) override;

  // The text after `marker` in the first line that contains it, or empty: the node's own words for
  // the first drop it reported.
  std::string first_after(td::Slice marker) const;
  bool contains(td::Slice text) const;

 private:
  std::vector<std::string> lines_;
  td::LogInterface *saved_interface_;
  int saved_level_;
};

// The network edge of a node: what a UDP socket would deliver to the peer table, and what the node
// would put on the wire, recorded instead of sent.
class EdgeNetworkManager final : public tos::adnl::AdnlNetworkManager {
 public:
  struct Sent {
    tos::adnl::AdnlNodeIdShort src;
    tos::adnl::AdnlNodeIdShort dst;
    std::string data;
  };
  // What the edge saw, read by the caller between scheduler rounds (one thread throughout).
  struct Record {
    bool installed = false;  // the peer table has installed its callback: datagrams can be delivered
    std::vector<Sent> sent;
  };
  explicit EdgeNetworkManager(std::shared_ptr<Record> record);

  void install_callback(std::unique_ptr<Callback> callback) override;
  void add_self_addr(td::IPAddress addr, tos::adnl::AdnlCategoryMask cat_mask, td::uint32 priority) override;
  void add_proxy_addr(td::IPAddress addr, td::uint16 local_port, std::shared_ptr<tos::adnl::AdnlProxy> proxy,
                      tos::adnl::AdnlCategoryMask cat_mask, td::uint32 priority) override;
  void send_udp_packet(tos::adnl::AdnlNodeIdShort src_id, tos::adnl::AdnlNodeIdShort dst_id, td::IPAddress dst_addr,
                       td::uint32 priority, td::BufferSlice data) override;
  void set_local_id_category(tos::adnl::AdnlNodeIdShort id, td::uint8 cat) override;

  // One inbound datagram, as the socket of every category hands it to the peer table.
  void deliver(td::IPAddress from, td::BufferSlice data);

 private:
  std::unique_ptr<Callback> callback_;
  std::shared_ptr<Record> record_;
};

}  // namespace conformance::net
