// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// In-process node pieces of the net harness (net-node.h).
#include <utility>

#include "adnl/adnl-peer-table.h"

#include "net-node.h"

namespace {

bool clock_fixed = false;
double fixed_now = 0;

}  // namespace

// The linker resolves every reference to td::Clocks::system() in the reference library to this wrapper
// (--wrap=_ZN2td6Clocks6systemEv); the real function stays reachable as __real_.
extern "C" double __real__ZN2td6Clocks6systemEv();
extern "C" double __wrap__ZN2td6Clocks6systemEv() {
  return clock_fixed ? fixed_now : __real__ZN2td6Clocks6systemEv();
}

namespace conformance::net {

FixedClock::FixedClock(double now) {
  clock_fixed = true;
  fixed_now = now;
}

FixedClock::~FixedClock() {
  clock_fixed = false;
}

td::Result<td::IPAddress> datagram_source() {
  td::IPAddress addr;
  TRY_STATUS(addr.init_ipv4_port("192.0.2.1", 3000));
  return addr;
}

NodeLog::NodeLog() : saved_interface_(td::log_interface), saved_level_(GET_VERBOSITY_LEVEL()) {
  td::log_interface = this;
  // Every drop on the inbound ADNL and overlay paths is logged at ADNL_DEBUG (= OVERLAY_DEBUG) or a lower
  // level.
  SET_VERBOSITY_LEVEL(tos::adnl::VERBOSITY_NAME(ADNL_DEBUG));
}

NodeLog::~NodeLog() {
  td::log_interface = saved_interface_;
  SET_VERBOSITY_LEVEL(saved_level_);
}

void NodeLog::append(td::CSlice slice, int log_level) {
  // A fatal record is the node aborting (LOG(FATAL), a failed ensure()): the interface it goes to is what
  // aborts, so it is handed to the interface this one replaced, never kept as a line.
  if (log_level == VERBOSITY_NAME(FATAL)) {
    saved_interface_->append(slice, log_level);
    return;
  }
  lines_.emplace_back(slice.str());
}

std::string NodeLog::first_after(td::Slice marker) const {
  for (const auto &line : lines_) {
    auto at = line.find(marker.str());
    if (at != std::string::npos) {
      return line.substr(at + marker.size());
    }
  }
  return {};
}

bool NodeLog::contains(td::Slice text) const {
  for (const auto &line : lines_) {
    if (line.find(text.str()) != std::string::npos) {
      return true;
    }
  }
  return false;
}

EdgeNetworkManager::EdgeNetworkManager(std::shared_ptr<Record> record) : record_(std::move(record)) {
}

void EdgeNetworkManager::install_callback(std::unique_ptr<Callback> callback) {
  callback_ = std::move(callback);
  record_->installed = true;
}

void EdgeNetworkManager::add_self_addr(td::IPAddress, tos::adnl::AdnlCategoryMask, td::uint32) {
}

void EdgeNetworkManager::add_proxy_addr(td::IPAddress, td::uint16, std::shared_ptr<tos::adnl::AdnlProxy>,
                                        tos::adnl::AdnlCategoryMask, td::uint32) {
}

void EdgeNetworkManager::send_udp_packet(tos::adnl::AdnlNodeIdShort src_id, tos::adnl::AdnlNodeIdShort dst_id,
                                         td::IPAddress, td::uint32, td::BufferSlice data) {
  record_->sent.push_back(Sent{src_id, dst_id, data.as_slice().str()});
}

void EdgeNetworkManager::set_local_id_category(tos::adnl::AdnlNodeIdShort, td::uint8) {
}

void EdgeNetworkManager::deliver(td::IPAddress from, td::BufferSlice data) {
  if (!callback_) {
    LOG(ERROR) << "conformance network edge: no peer table installed";
    return;
  }
  tos::adnl::AdnlCategoryMask every_category;
  every_category.set();
  callback_->receive_packet(from, std::move(every_category), std::move(data));
}

}  // namespace conformance::net
