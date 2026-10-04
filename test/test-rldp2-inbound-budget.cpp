/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// How many decoders, and how many bytes of reassembly, all RLDP2 connections
// of a process may hold together.
//
// Each connection bounds the transfers one peer may open, but thousands of
// connections times that bound is over a million decoders. A budget shared by
// every connection is reserved before a decoder is created, around each decode
// attempt for the solver's working memory, and given back when the transfer
// finishes, expires or its connection goes away. These tests drive real
// connections with real FEC datagrams against small injected budgets.

#include <limits>
#include <memory>
#include <vector>

#include "fec/fec.h"
#include "rldp2/InboundTransfer.h"
#include "rldp2/RldpConnection.h"
#include "rldp2/rldp-inbound-budget.h"
#include "td/fec/fec.h"
#include "td/utils/Random.h"
#include "td/utils/Time.h"
#include "td/utils/tests.h"

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

// The datagrams a fresh sender produces for one transfer in its first runs.
std::vector<td::BufferSlice> datagrams_for(TransferId id, size_t size) {
  RldpConnection sender;
  Sink sink;
  sender.send(id, payload(size), td::Timestamp::in(60.0));
  for (int i = 0; i < 64 && sink.outbox.empty(); i++) {
    sender.run(sink);
  }
  return std::move(sink.outbox);
}

std::unique_ptr<RldpConnection> receiver_with(std::shared_ptr<RldpInboundBudget> budget) {
  auto receiver = std::make_unique<RldpConnection>();
  receiver->set_inbound_budget(std::move(budget));
  return receiver;
}

// One part of an unsolicited-size transfer: the transfer opens a decoder and
// stays open, since one datagram is far from enough to reassemble it.
void open_transfer(RldpConnection &receiver, Sink &sink, TransferId id) {
  auto parts = datagrams_for(id, RldpConnection::DEFAULT_MTU);
  CHECK(!parts.empty());
  receiver.receive_raw(parts[0].clone());
  receiver.run(sink);
}

// A transfer small enough to complete from its first datagram.
void deliver_whole_transfer(RldpConnection &receiver, Sink &sink, TransferId id) {
  auto parts = datagrams_for(id, 64);
  CHECK(!parts.empty());
  for (auto &part : parts) {
    receiver.receive_raw(part.clone());
    receiver.run(sink);
  }
}

size_t open_part_cost() {
  // An unsolicited transfer is one part of at most DEFAULT_MTU bytes.
  auto symbols = (RldpConnection::DEFAULT_MTU + 767) / 768;
  return rldp_decoder_reservation_bytes(RldpConnection::DEFAULT_MTU, 768, symbols).value();
}

TEST(Rldp2InboundBudget, CostsMatchTheDocumentedMeasurements) {
  ASSERT_EQ(38656u, open_part_cost());
  ASSERT_EQ(6681216u, rldp_decoder_reservation_bytes(2000000, 768, 2605).value());
  ASSERT_EQ(12134912u, rldp_solver_working_bytes(768, 2605).value());
  // A size that cannot be represented is refused, never wrapped.
  ASSERT_TRUE(!rldp_decoder_reservation_bytes(0, 768, std::numeric_limits<size_t>::max() / 2));
  ASSERT_TRUE(!rldp_decoder_reservation_bytes(std::numeric_limits<size_t>::max(), 768, 1));
  ASSERT_TRUE(!rldp_solver_working_bytes(std::numeric_limits<size_t>::max(), 2));
  // The production defaults are finite and hold at least one maximal part.
  auto budget = RldpInboundBudget::process_default();
  ASSERT_TRUE(budget->max_decoders() < RldpConnection::MAX_INBOUND_TRANSFERS * 4096);
  ASSERT_TRUE(budget->max_bytes() >= rldp_decoder_reservation_bytes(2000000, 768, 2605).value() +
                                         rldp_solver_working_bytes(768, 2605).value());
}

TEST(Rldp2InboundBudget, DecodersAreBoundedAcrossConnections) {
  auto budget = std::make_shared<RldpInboundBudget>(2, 64 << 20);
  auto first = receiver_with(budget);
  auto second = receiver_with(budget);
  auto third = receiver_with(budget);
  Sink sink;

  open_transfer(*first, sink, transfer(1));
  open_transfer(*second, sink, transfer(2));
  ASSERT_EQ(2u, budget->active_decoders());
  ASSERT_EQ(2 * open_part_cost(), budget->reserved_bytes());

  // Each connection is far below its own limit; the process is at its own.
  open_transfer(*third, sink, transfer(3));
  ASSERT_EQ(0u, third->inbound_transfer_count());
  ASSERT_EQ(2u, budget->active_decoders());
  deliver_whole_transfer(*third, sink, transfer(4));
  ASSERT_TRUE(sink.completed.empty());
  ASSERT_EQ(0u, third->inbound_transfer_count());

  // A connection going away gives back everything it held, and another
  // connection can use it.
  first.reset();
  ASSERT_EQ(1u, budget->active_decoders());
  ASSERT_EQ(open_part_cost(), budget->reserved_bytes());
  deliver_whole_transfer(*third, sink, transfer(5));
  ASSERT_EQ(1u, sink.completed.size());
  ASSERT_TRUE(sink.completed[0] == transfer(5));
  // A finished transfer holds nothing.
  ASSERT_EQ(1u, budget->active_decoders());
  ASSERT_EQ(open_part_cost(), budget->reserved_bytes());
}

TEST(Rldp2InboundBudget, BytesAreBoundedAcrossConnections) {
  // Room for two open decoders' bytes but not three; the count is no limit.
  auto budget = std::make_shared<RldpInboundBudget>(1000, 2 * open_part_cost() + 1000);
  auto first = receiver_with(budget);
  auto second = receiver_with(budget);
  Sink sink;
  open_transfer(*first, sink, transfer(10));
  open_transfer(*first, sink, transfer(11));
  ASSERT_EQ(2u, first->inbound_transfer_count());
  open_transfer(*second, sink, transfer(12));
  ASSERT_EQ(0u, second->inbound_transfer_count());
  ASSERT_TRUE(budget->reserved_bytes() <= budget->max_bytes());
  first.reset();
  ASSERT_EQ(0u, budget->active_decoders());
  ASSERT_EQ(0u, budget->reserved_bytes());
  open_transfer(*second, sink, transfer(12));
  ASSERT_EQ(1u, second->inbound_transfer_count());
}

TEST(Rldp2InboundBudget, ExpiredTransfersGiveBackTheirReservation) {
  auto budget = std::make_shared<RldpInboundBudget>(10, 64 << 20);
  auto receiver = receiver_with(budget);
  Sink sink;
  open_transfer(*receiver, sink, transfer(20));
  ASSERT_EQ(1u, budget->active_decoders());
  // An unsolicited transfer lives ten seconds.
  td::Time::jump_in_future(td::Time::now() + 11.0);
  receiver->run(sink);
  ASSERT_EQ(0u, receiver->inbound_transfer_count());
  ASSERT_EQ(0u, budget->active_decoders());
  ASSERT_EQ(0u, budget->reserved_bytes());
}

TEST(Rldp2InboundBudget, DecodingWaitsForSolverMemory) {
  auto budget = std::make_shared<RldpInboundBudget>(10, 64 << 20);
  auto receiver = receiver_with(budget);
  Sink sink;
  // Leave room for the decoder but not for a decode attempt.
  auto symbols = static_cast<size_t>(1);
  auto decoder_cost = rldp_decoder_reservation_bytes(64, 768, symbols).value();
  auto solver_cost = rldp_solver_working_bytes(768, symbols).value();
  auto held = RldpInboundReservation::acquire(budget, 0, budget->max_bytes() - decoder_cost - solver_cost + 1);
  ASSERT_TRUE(held.has_value());
  deliver_whole_transfer(*receiver, sink, transfer(30));
  ASSERT_TRUE(sink.completed.empty());
  ASSERT_EQ(1u, receiver->inbound_transfer_count());
  ASSERT_EQ(1u, budget->active_decoders());
  ASSERT_TRUE(budget->reserved_bytes() <= budget->max_bytes());
  held.reset();
}

// Finished parts keep only their decoded bytes charged; the transfer going
// away returns those too. Driven on the reassembly state directly so that a
// transfer of several parts can be finished part by part.
TEST(Rldp2InboundBudget, FinishedPartsKeepOnlyTheirBytes) {
  const size_t part_size = 7680;
  auto budget = std::make_shared<RldpInboundBudget>(1, 64 << 20);
  auto data = payload(2 * part_size);
  auto encode = [&](size_t index) {
    return td::fec::RaptorQEncoder::create(td::BufferSlice(data.as_slice().substr(index * part_size, part_size)), 768);
  };
  auto first_encoder = encode(0);
  auto second_encoder = encode(1);
  first_encoder->prepare_more_symbols();
  second_encoder->prepare_more_symbols();
  fec::FecType first_type{first_encoder->get_parameters()};
  fec::FecType second_type{second_encoder->get_parameters()};
  auto cost = rldp_decoder_reservation_bytes(part_size, 768, first_type.symbols_count()).value();

  auto finish = [&](InboundTransfer &inbound, td::uint32 index, td::fec::Encoder &encoder) {
    auto part = inbound.get_part(index, index == 0 ? first_type : second_type).move_as_ok();
    CHECK(part != nullptr);
    for (td::uint32 i = 0; !part->decoder->may_try_decode(); i++) {
      part->decoder->add_symbol(encoder.gen_symbol(i)).ensure();
    }
    inbound.finish_part(index, part->decoder->try_decode(false).move_as_ok().data);
  };
  {
    InboundTransfer inbound(2 * part_size, budget);
    finish(inbound, 0, *first_encoder);
    ASSERT_EQ(0u, budget->active_decoders());
    ASSERT_EQ(part_size, budget->reserved_bytes());

    // The second part waits for room when the budget has none.
    bool refused = false;
    {
      auto held = RldpInboundReservation::acquire(budget, 1, 0);
      ASSERT_TRUE(held.has_value());
      auto part = inbound.get_part(1, second_type, &refused).move_as_ok();
      ASSERT_TRUE(part == nullptr);
      ASSERT_TRUE(refused);
    }
    // Refusal took nothing, so the same part can be opened once there is room.
    ASSERT_EQ(part_size, budget->reserved_bytes());
    auto part = inbound.get_part(1, second_type, &refused).move_as_ok();
    ASSERT_TRUE(part != nullptr);
    ASSERT_TRUE(!refused);
    ASSERT_EQ(1u, budget->active_decoders());
    ASSERT_EQ(part_size + cost, budget->reserved_bytes());
    finish(inbound, 1, *second_encoder);
    ASSERT_EQ(0u, budget->active_decoders());
    ASSERT_EQ(2 * part_size, budget->reserved_bytes());
    auto whole = inbound.try_finish();
    ASSERT_TRUE(bool(whole));
    ASSERT_TRUE(whole.value().as_slice() == data.as_slice());
  }
  ASSERT_EQ(0u, budget->active_decoders());
  ASSERT_EQ(0u, budget->reserved_bytes());
}

}  // namespace
}  // namespace tos::rldp2
