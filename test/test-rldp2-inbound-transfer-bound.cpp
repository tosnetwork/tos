/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// How much of the node's memory one peer can claim on a single connection.
//
// A transfer id is chosen by the sender, and an unseen one makes the receiver
// allocate decoder state, a reassembly buffer and a timeout entry. Nothing
// about that is bounded by the connection cap, which counts peers: this is one
// peer, on one connection. Left open, an authenticated peer -- and identities
// are free to generate -- names as many transfers as it can send parts for and
// holds them all until they expire.
//
// So a connection accepts a bounded number of concurrent inbound transfers and
// drops parts opening any more. The peer pays a retransmit; the node does not
// pay a peer-chosen amount of heap.

#include "rldp2/RldpConnection.h"

#include "td/utils/Random.h"
#include "td/utils/tests.h"

#include <vector>

namespace tos::rldp2 {
namespace {

class Sink : public ConnectionCallback {
 public:
  void send_raw(td::BufferSlice datagram) override {
    outbox.push_back(std::move(datagram));
  }
  void receive(TransferId transfer_id, td::Result<td::BufferSlice> r_data) override {
    if (r_data.is_ok()) {
      completed.push_back(transfer_id);
    }
  }
  void on_sent(TransferId, td::Result<td::Unit>) override {
  }

  std::vector<td::BufferSlice> outbox;
  std::vector<TransferId> completed;
};

TransferId transfer(td::uint32 n) {
  TransferId id;
  id.set_zero();
  id.as_slice().copy_from(td::Slice{reinterpret_cast<const td::uint8 *>(&n), sizeof(n)});
  return id;
}

td::BufferSlice payload(size_t size) {
  td::BufferSlice data{size};
  td::Random::secure_bytes(data.as_slice());
  return data;
}

// Hand one transfer to a fresh sender and return the datagrams it produces.
std::vector<td::BufferSlice> datagrams_for(TransferId id, size_t size) {
  RldpConnection sender;
  Sink sink;
  sender.send(id, payload(size), td::Timestamp::in(60.0));
  for (int i = 0; i < 64 && sink.outbox.empty(); i++) {
    sender.run(sink);
  }
  return std::move(sink.outbox);
}

// Open a transfer on the receiver without finishing it: one part of something
// far larger than a part, so reassembly stays pending.
void open_transfer(RldpConnection &receiver, Sink &sink, TransferId id) {
  // As large as an unsolicited transfer may declare -- anything more is
  // refused for a different reason -- so one datagram is far from enough to
  // reassemble it and the transfer stays open.
  auto parts = datagrams_for(id, RldpConnection::DEFAULT_MTU);
  CHECK(!parts.empty());
  receiver.receive_raw(parts[0].clone());
  receiver.run(sink);
}

// Deliver a transfer small enough to complete from the parts produced.
void deliver_whole_transfer(RldpConnection &receiver, Sink &sink, TransferId id) {
  auto parts = datagrams_for(id, 64);
  CHECK(!parts.empty());
  for (auto &part : parts) {
    receiver.receive_raw(part.clone());
    receiver.run(sink);
  }
}

TEST(Rldp2InboundTransferBound, ATransferCompletesWhenTheConnectionHasRoom) {
  RldpConnection receiver;
  Sink sink;
  // The control: with nothing else open, a whole transfer arrives. Without
  // this the test below could pass because delivery never works at all.
  deliver_whole_transfer(receiver, sink, transfer(1));
  ASSERT_EQ(1u, sink.completed.size());
  ASSERT_TRUE(sink.completed[0] == transfer(1));
}

TEST(Rldp2InboundTransferBound, TransfersPastTheLimitAreRefusedNotAllocated) {
  RldpConnection receiver;
  Sink sink;

  // Fill the connection with transfers the peer opens and never finishes,
  // which is what the attack looks like: one part each, nothing completed.
  for (size_t i = 0; i < RldpConnection::MAX_INBOUND_TRANSFERS; i++) {
    open_transfer(receiver, sink, transfer(static_cast<td::uint32>(1000 + i)));
  }
  ASSERT_TRUE(sink.completed.empty());
  LOG(ERROR) << "open inbound transfers after filling: " << receiver.inbound_transfer_count();
  ASSERT_EQ(RldpConnection::MAX_INBOUND_TRANSFERS, receiver.inbound_transfer_count());

  // One more transfer, small enough to complete in the parts delivered. It
  // must not: accepting it would mean the peer, not the node, decides how many
  // of these exist.
  deliver_whole_transfer(receiver, sink, transfer(9999));
  ASSERT_TRUE(sink.completed.empty());
}

}  // namespace
}  // namespace tos::rldp2
