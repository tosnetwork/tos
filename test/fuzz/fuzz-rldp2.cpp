/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// RLDP inbound datagrams, as an authenticated peer sends them on one connection: message
// parts carrying FEC symbols, completions and confirmations, in any order and any number
// (RldpConnection::receive_raw, then the connection's run loop). This is the network path
// into the C++ FEC decoder.
//
// Input layout: any number of datagrams, each a little-endian u16 length and that many
// bytes; the connection runs after every datagram.
//
// The connection draws decoders from a budget of its own here, and once the connection is
// gone every decoder and byte it reserved must be back. An unsolicited transfer it
// completes is never larger than the connection's limit for one.
//
// Run:
//   build-fuzz/fuzz/fuzz-rldp2 -max_total_time=300 -max_len=65536 fuzz-work/fuzz-rldp2 test/fuzz/corpus/fuzz-rldp2

#include <memory>

#include "rldp2/RldpConnection.h"

#include "fuzz-common.h"

namespace {

constexpr int kMaxDatagrams = 256;

class Sink final : public tos::rldp2::ConnectionCallback {
 public:
  explicit Sink(td::uint64 max_unsolicited) : max_unsolicited_(max_unsolicited) {
  }
  void send_raw(td::BufferSlice) override {
  }
  void receive(tos::rldp2::TransferId, td::Result<td::BufferSlice> r_data) override {
    if (r_data.is_ok()) {
      TOS_FUZZ_INVARIANT(r_data.ok().size() <= max_unsolicited_);
    }
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {
  }

 private:
  td::uint64 max_unsolicited_;
};

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  tos::fuzz::quiet_logging();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  auto budget = std::make_shared<tos::rldp2::RldpInboundBudget>(64, 64 << 20);
  {
    tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
    connection.set_inbound_budget(budget);
    Sink sink(connection.default_mtu());
    tos::fuzz::Reader in(data, size);
    for (int i = 0; i < kMaxDatagrams && !in.empty(); i++) {
      auto length = in.u16();
      connection.receive_raw(td::BufferSlice(in.bytes(length)));
      connection.run(sink);
    }
    TOS_FUZZ_INVARIANT(connection.inbound_transfer_count() <= tos::rldp2::RldpConnection::MAX_INBOUND_TRANSFERS);
    TOS_FUZZ_INVARIANT(budget->active_decoders() <= budget->max_decoders());
    TOS_FUZZ_INVARIANT(budget->reserved_bytes() <= budget->max_bytes());
  }
  TOS_FUZZ_INVARIANT(budget->active_decoders() == 0);
  TOS_FUZZ_INVARIANT(budget->reserved_bytes() == 0);
  return 0;
}
