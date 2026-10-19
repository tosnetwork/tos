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
//
// Half of the budget is a reserve for transfers answering the node's own
// requests, and one peer identity may hold only a share of the other half.
// The tests for that division run a saturating identity beside an unrelated
// one, and check that a peer cannot reach the reserve by any claim of its own.
// They do not show, and the division does not give, availability against many
// identities: generating identities costs nothing.

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include "fec/fec.h"
#include "rldp2/InboundTransfer.h"
#include "rldp2/RldpConnection.h"
#include "rldp2/rldp-in.hpp"
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
      payloads.emplace(transfer_id, r_data.move_as_ok());
    } else {
      failed.push_back(transfer_id);
    }
  }
  void on_sent(TransferId, td::Result<td::Unit>) override {
  }

  std::vector<td::BufferSlice> outbox;
  std::vector<TransferId> completed;
  std::vector<TransferId> failed;
  std::map<TransferId, td::BufferSlice> payloads;
};

RldpPeerIdentity identity(td::uint32 n) {
  RldpPeerIdentity id{};
  std::memcpy(id.data(), &n, sizeof(n));
  return id;
}

// A budget whose unsolicited half and per-identity share are the whole of it,
// for the tests of the overall bound.
std::shared_ptr<RldpInboundBudget> undivided(size_t decoders, size_t bytes) {
  RldpInboundLimits limits;
  limits.max_decoders = decoders;
  limits.max_bytes = bytes;
  limits.unsolicited_decoders = decoders;
  limits.unsolicited_bytes = bytes;
  limits.per_identity_decoders = decoders;
  limits.per_identity_bytes = bytes;
  limits.max_identities = decoders;
  return std::make_shared<RldpInboundBudget>(limits);
}

// Capacity taken outside any transfer, from the solicited side so that it
// counts against the total only.
std::optional<RldpInboundReservation> hold(std::shared_ptr<RldpInboundBudget> budget, size_t decoders, size_t bytes) {
  return RldpInboundReservation::acquire(std::move(budget), RldpInboundKind::solicited, identity(0), decoders, bytes);
}

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
  RldpConnection sender{identity(0)};
  Sink sink;
  sender.send(id, payload(size), td::Timestamp::in(60.0));
  for (int i = 0; i < 64 && sink.outbox.empty(); i++) {
    sender.run(sink);
  }
  return std::move(sink.outbox);
}

std::unique_ptr<RldpConnection> receiver_with(std::shared_ptr<RldpInboundBudget> budget,
                                              RldpPeerIdentity peer = identity(0)) {
  auto receiver = std::make_unique<RldpConnection>(peer);
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

size_t open_part_symbols() {
  return (RldpConnection::DEFAULT_MTU + 767) / 768;
}

size_t open_part_cost() {
  // An unsolicited transfer is one part of at most DEFAULT_MTU bytes.
  return rldp_decoder_reservation_bytes(RldpConnection::DEFAULT_MTU, 768, open_part_symbols()).value();
}

// The working memory of one decode attempt of such a part, which must still
// fit when its decoder is reserved.
size_t open_part_solver() {
  return rldp_solver_working_bytes(768, open_part_symbols()).value();
}

// The largest transfer at the supported overlay limit: overlays with the
// fixed limit raise a peer's allowance to 16 MiB plus an envelope, at most
// 4096 bytes. Overlays that derive their limit from network configuration can
// produce other sizes; see RldpInboundLimits.
size_t largest_unsolicited_transfer() {
  return (size_t{16} << 20) + 4096;
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
  // Half is kept for solicited transfers. One identity's share of the rest is
  // an eighth of the decoders and half of the bytes: 1024 decoders and
  // 128 MiB -- room for a full connection of default-size transfers, and for
  // the largest transfer at the supported overlay limit with every part open.
  auto &limits = budget->limits();
  ASSERT_EQ(rldp_max_active_decoders / 2, limits.unsolicited_decoders);
  ASSERT_EQ(rldp_max_inbound_bytes / 2, limits.unsolicited_bytes);
  ASSERT_EQ(1024u, limits.per_identity_decoders);
  ASSERT_EQ(size_t{128} << 20, limits.per_identity_bytes);
  // The largest transfer at the supported overlay limit, charged with every
  // part open, its assembly buffer and one decode attempt: about 81 MiB, which
  // leaves the share more than 40 MiB of margin. The same function decides
  // whether RLDP2 accepts an allowance.
  ASSERT_EQ(84984576u, rldp_transfer_peak_bytes(largest_unsolicited_transfer()).value());
  ASSERT_TRUE(rldp_transfer_peak_bytes(largest_unsolicited_transfer()).value() + (size_t{40} << 20) <=
              limits.per_identity_bytes);
  ASSERT_EQ(rldp_identity_byte_share, limits.per_identity_bytes);
  // It cuts transfers as the sender does.
  ASSERT_EQ(OutboundTransfer::part_size(), rldp_part_size);
  ASSERT_EQ(OutboundTransfer::symbol_size(), rldp_symbol_size);
  ASSERT_EQ(rldp_decoder_reservation_bytes(2000000, 768, 2605).value() + rldp_solver_working_bytes(768, 2605).value(),
            rldp_transfer_peak_bytes(2000000).value());
  ASSERT_TRUE(!rldp_transfer_peak_bytes(std::numeric_limits<size_t>::max()));
  ASSERT_TRUE(limits.per_identity_decoders >= RldpConnection::MAX_INBOUND_TRANSFERS);
  ASSERT_TRUE(limits.per_identity_bytes >= RldpConnection::MAX_INBOUND_TRANSFERS * open_part_cost());
  ASSERT_TRUE(limits.per_identity_bytes >= rldp_decoder_reservation_bytes(2000000, 768, 2605).value() +
                                               rldp_solver_working_bytes(768, 2605).value());
}

TEST(Rldp2InboundBudget, DecodersAreBoundedAcrossConnections) {
  auto budget = undivided(2, 64 << 20);
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
  // Room for two open decoders' bytes and a decode attempt, but not three
  // decoders and an attempt; the count is no limit.
  auto budget = undivided(1000, 2 * open_part_cost() + open_part_solver() + 1000);
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
  auto budget = undivided(10, 64 << 20);
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
  ASSERT_EQ(0u, budget->unsolicited_decoders());
  ASSERT_EQ(0u, budget->tracked_identities());
}

TEST(Rldp2InboundBudget, DecodingWaitsForSolverMemory) {
  auto budget = undivided(10, 64 << 20);
  auto receiver = receiver_with(budget);
  Sink sink;
  auto id = transfer(30);
  auto parts = datagrams_for(id, RldpConnection::DEFAULT_MTU);
  ASSERT_TRUE(parts.size() > open_part_symbols() + 1);
  // The decoder is reserved while its decode attempt still fits...
  receiver->receive_raw(parts[0].clone());
  receiver->run(sink);
  ASSERT_EQ(1u, budget->active_decoders());
  // ...and something else then takes that room.
  auto held = hold(budget, 0, budget->max_bytes() - budget->reserved_bytes() - open_part_solver() + 1);
  ASSERT_TRUE(held.has_value());
  for (size_t i = 1; i + 1 < parts.size(); i++) {
    receiver->receive_raw(parts[i].clone());
    receiver->run(sink);
  }
  // Enough symbols to decode, but no room to: the symbols are kept.
  ASSERT_TRUE(sink.completed.empty());
  ASSERT_EQ(1u, receiver->inbound_transfer_count());
  ASSERT_TRUE(budget->reserved_bytes() <= budget->max_bytes());
  // Once there is room, the next symbol decodes.
  held.reset();
  receiver->receive_raw(parts.back().clone());
  receiver->run(sink);
  ASSERT_EQ(1u, sink.completed.size());
  ASSERT_EQ(0u, budget->active_decoders());
}

// A decoder is reserved only while its decode attempt would still fit, so a
// share cannot fill with decoders none of which has room to decode. Without
// that, these three transfers would hold the share between them and never
// complete.
TEST(Rldp2InboundBudget, AShareFullOfDecodersStillDecodes) {
  RldpInboundLimits limits = RldpInboundLimits::split(64, 64 << 20);
  limits.per_identity_bytes = 2 * open_part_cost() + open_part_solver();
  auto budget = std::make_shared<RldpInboundBudget>(limits);
  auto receiver = receiver_with(budget, identity(1));
  Sink sink;
  std::vector<std::vector<td::BufferSlice>> transfers;
  for (td::uint32 i = 0; i < 3; i++) {
    transfers.push_back(datagrams_for(transfer(40 + i), RldpConnection::DEFAULT_MTU));
    receiver->receive_raw(transfers.back()[0].clone());
    receiver->run(sink);
  }
  ASSERT_EQ(2u, receiver->inbound_transfer_count());
  for (auto &datagrams : transfers) {
    for (auto &datagram : datagrams) {
      receiver->receive_raw(datagram.clone());
      receiver->run(sink);
    }
  }
  ASSERT_EQ(3u, sink.completed.size());
  ASSERT_EQ(0u, budget->identity_bytes(identity(1)));
}

// A decode attempt of an unsolicited transfer is charged to its identity's
// share like the decoder itself, so one identity cannot use decode attempts to
// reach past its share.
TEST(Rldp2InboundBudget, DecodeAttemptsCountAgainstTheIdentityShare) {
  auto budget = std::make_shared<RldpInboundBudget>(64, 64 << 20);
  auto peer = identity(1);
  auto receiver = receiver_with(budget, peer);
  Sink sink;
  auto id = transfer(31);
  auto parts = datagrams_for(id, RldpConnection::DEFAULT_MTU);
  ASSERT_TRUE(parts.size() > open_part_symbols() + 1);
  receiver->receive_raw(parts[0].clone());
  receiver->run(sink);
  ASSERT_EQ(open_part_cost(), budget->identity_bytes(peer));
  // The same identity's other unsolicited use takes the room its decode
  // attempt needs; the total and the unsolicited half still have plenty.
  auto share = budget->limits().per_identity_bytes;
  auto held = RldpInboundReservation::acquire(budget, RldpInboundKind::unsolicited, peer, 0,
                                              share - open_part_cost() - open_part_solver() + 1);
  ASSERT_TRUE(held.has_value());
  for (size_t i = 1; i + 1 < parts.size(); i++) {
    receiver->receive_raw(parts[i].clone());
    receiver->run(sink);
  }
  ASSERT_TRUE(sink.completed.empty());
  held.reset();
  receiver->receive_raw(parts.back().clone());
  receiver->run(sink);
  ASSERT_EQ(1u, sink.completed.size());
  ASSERT_EQ(0u, budget->identity_bytes(peer));
}

// Finished parts keep only their decoded bytes charged; the transfer going
// away returns those too. Driven on the reassembly state directly so that a
// transfer of several parts can be finished part by part.
TEST(Rldp2InboundBudget, FinishedPartsKeepOnlyTheirBytes) {
  const size_t part_size = 7680;
  auto budget = undivided(1, 64 << 20);
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
    InboundTransfer inbound(2 * part_size, budget, RldpInboundKind::unsolicited, identity(1));
    finish(inbound, 0, *first_encoder);
    ASSERT_EQ(0u, budget->active_decoders());
    ASSERT_EQ(part_size, budget->reserved_bytes());

    // The second part waits for room when the budget has none.
    bool refused = false;
    {
      auto held = hold(budget, 1, 0);
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
    // The last part also holds the buffer the two are assembled into.
    ASSERT_EQ(part_size + cost + 2 * part_size, budget->reserved_bytes());
    finish(inbound, 1, *second_encoder);
    ASSERT_EQ(0u, budget->active_decoders());
    ASSERT_EQ(2 * part_size + 2 * part_size, budget->reserved_bytes());
    auto whole = inbound.try_finish();
    ASSERT_TRUE(bool(whole));
    ASSERT_TRUE(whole.value().as_slice() == data.as_slice());
  }
  ASSERT_EQ(0u, budget->active_decoders());
  ASSERT_EQ(0u, budget->reserved_bytes());
}

// The buffer a transfer of several parts is assembled into is reserved before
// the last part's decoder is created. When the decoded parts fit but the
// assembly does not, the last part is refused and nothing is allocated; once
// capacity frees, the same part opens and the transfer completes.
TEST(Rldp2InboundBudget, AssemblyIsReservedBeforeTheLastPartOpens) {
  const size_t part_size = 7680;
  auto budget = undivided(10, 64 << 20);
  auto data = payload(2 * part_size);
  auto first_encoder = td::fec::RaptorQEncoder::create(td::BufferSlice(data.as_slice().substr(0, part_size)), 768);
  auto second_encoder =
      td::fec::RaptorQEncoder::create(td::BufferSlice(data.as_slice().substr(part_size, part_size)), 768);
  first_encoder->prepare_more_symbols();
  second_encoder->prepare_more_symbols();
  fec::FecType first_type{first_encoder->get_parameters()};
  fec::FecType second_type{second_encoder->get_parameters()};
  auto cost = rldp_decoder_reservation_bytes(part_size, 768, first_type.symbols_count()).value();
  auto decode = [](InboundTransfer::Part &part, td::fec::Encoder &encoder) {
    for (td::uint32 i = 0; !part.decoder->may_try_decode(); i++) {
      part.decoder->add_symbol(encoder.gen_symbol(i)).ensure();
    }
    return part.decoder->try_decode(false).move_as_ok().data;
  };

  InboundTransfer inbound(2 * part_size, budget, RldpInboundKind::unsolicited, identity(1));
  auto first = inbound.get_part(0, first_type).move_as_ok();
  CHECK(first != nullptr);
  inbound.finish_part(0, decode(*first, *first_encoder));
  ASSERT_EQ(part_size, budget->reserved_bytes());

  // Leave room for the last part's decoder, its decoded bytes and its decode
  // attempt, but not for the assembly buffer on top.
  auto solver = rldp_solver_working_bytes(768, second_type.symbols_count()).value();
  auto room = cost + 2 * part_size + solver - 1;
  auto held = hold(budget, 0, budget->max_bytes() - part_size - room);
  ASSERT_TRUE(held.has_value());
  bool refused = false;
  auto second = inbound.get_part(1, second_type, &refused).move_as_ok();
  ASSERT_TRUE(second == nullptr);
  ASSERT_TRUE(refused);
  ASSERT_EQ(0u, budget->active_decoders());
  ASSERT_TRUE(!inbound.try_finish());

  held.reset();
  second = inbound.get_part(1, second_type, &refused).move_as_ok();
  ASSERT_TRUE(second != nullptr);
  inbound.finish_part(1, decode(*second, *second_encoder));
  auto whole = inbound.try_finish();
  ASSERT_TRUE(bool(whole));
  ASSERT_TRUE(whole.value().as_slice() == data.as_slice());
}

// Runs a sender and a receiver against each other, delivering every datagram
// both ways, until the receiver completes the transfer or `rounds` pass.
bool run_loopback(RldpConnection &sender, Sink &sender_sink, RldpConnection &receiver, Sink &receiver_sink,
                  size_t rounds) {
  for (size_t round = 0; round < rounds && receiver_sink.completed.empty(); round++) {
    sender.run(sender_sink);
    auto to_receiver = std::move(sender_sink.outbox);
    sender_sink.outbox.clear();
    for (auto &datagram : to_receiver) {
      receiver.receive_raw(std::move(datagram));
    }
    receiver.run(receiver_sink);
    auto to_sender = std::move(receiver_sink.outbox);
    receiver_sink.outbox.clear();
    for (auto &datagram : to_sender) {
      sender.receive_raw(std::move(datagram));
    }
    if (to_receiver.empty() && to_sender.empty()) {
      // Nothing moved: let the pacer and the acknowledgement timers run.
      td::Time::jump_in_future(td::Time::now() + 0.01);
    }
  }
  return !receiver_sink.completed.empty();
}

// A transfer of two parts, through real connections, completes under the
// budget and leaves nothing reserved.
TEST(Rldp2InboundBudget, TransferOfSeveralPartsCompletesAndReturnsEverything) {
  const size_t size = 2000000 + 100000;
  auto budget = undivided(10, 64 << 20);
  RldpConnection sender{identity(0)};
  auto receiver = receiver_with(budget);
  Sink sender_sink;
  Sink receiver_sink;
  auto id = transfer(40);
  receiver->set_receive_limits(id, td::Timestamp::in(600.0), size);
  sender.send(id, payload(size), td::Timestamp::in(600.0));
  ASSERT_TRUE(run_loopback(sender, sender_sink, *receiver, receiver_sink, 200000));
  ASSERT_EQ(0u, receiver->inbound_transfer_count());
  ASSERT_EQ(0u, budget->active_decoders());
  ASSERT_EQ(0u, budget->reserved_bytes());
}

// The division of the budget, on the budget alone. Each check is reached with
// the others holding room, so each refusal below has exactly one cause.
TEST(Rldp2InboundBudget, UnsolicitedIsHeldToItsHalfAndEachIdentityToItsShare) {
  // 64 decoders and 64 MiB: the unsolicited half is 32 decoders and 32 MiB,
  // and one identity's share is 4 decoders and 16 MiB.
  const size_t mib = size_t{1} << 20;
  RldpInboundBudget budget(64, 64 * mib);
  auto unsolicited = RldpInboundKind::unsolicited;
  auto solicited = RldpInboundKind::solicited;
  ASSERT_EQ(32u, budget.limits().unsolicited_decoders);
  ASSERT_EQ(4u, budget.limits().per_identity_decoders);
  ASSERT_EQ(16 * mib, budget.limits().per_identity_bytes);

  // One identity's decoder share.
  for (int i = 0; i < 4; i++) {
    ASSERT_TRUE(budget.try_acquire(unsolicited, identity(1), 1, 1));
  }
  ASSERT_TRUE(!budget.try_acquire(unsolicited, identity(1), 1, 1));
  // Another identity is not affected by it.
  ASSERT_TRUE(budget.try_acquire(unsolicited, identity(2), 1, 1));
  ASSERT_TRUE(budget.release(unsolicited, identity(2), 1, 1));

  // One identity's byte share.
  ASSERT_TRUE(budget.try_acquire(unsolicited, identity(3), 1, 16 * mib));
  ASSERT_TRUE(!budget.try_acquire(unsolicited, identity(3), 0, 1));
  ASSERT_TRUE(budget.release(unsolicited, identity(3), 1, 16 * mib));

  // The unsolicited half's decoders: eight identities at their share fill it,
  // and a ninth is refused although the total and its own share have room.
  for (td::uint32 peer = 10; peer < 17; peer++) {
    for (int i = 0; i < 4; i++) {
      ASSERT_TRUE(budget.try_acquire(unsolicited, identity(peer), 1, 1));
    }
  }
  ASSERT_EQ(32u, budget.unsolicited_decoders());
  ASSERT_TRUE(!budget.try_acquire(unsolicited, identity(17), 1, 1));
  // The reserve is still there for solicited transfers, all of it.
  ASSERT_TRUE(budget.try_acquire(solicited, identity(17), 32, 1));
  ASSERT_TRUE(!budget.try_acquire(solicited, identity(17), 1, 1));
  ASSERT_TRUE(budget.release(solicited, identity(17), 32, 1));
  for (td::uint32 peer = 10; peer < 17; peer++) {
    ASSERT_TRUE(budget.release(unsolicited, identity(peer), 4, 4));
  }
  ASSERT_TRUE(budget.release(unsolicited, identity(1), 4, 4));

  // The unsolicited half's bytes: two identities at their byte share fill
  // it, and a third is refused although decoders and its share have room.
  for (td::uint32 peer = 20; peer < 22; peer++) {
    ASSERT_TRUE(budget.try_acquire(unsolicited, identity(peer), 1, 16 * mib));
  }
  ASSERT_EQ(32 * mib, budget.unsolicited_bytes());
  ASSERT_TRUE(!budget.try_acquire(unsolicited, identity(22), 0, 1));
  ASSERT_TRUE(budget.try_acquire(solicited, identity(22), 0, 32 * mib));
  ASSERT_TRUE(budget.release(solicited, identity(22), 0, 32 * mib));
  for (td::uint32 peer = 20; peer < 22; peer++) {
    ASSERT_TRUE(budget.release(unsolicited, identity(peer), 1, 16 * mib));
  }

  // Solicited transfers may use the whole budget, not only the reserve, and
  // then nothing else fits.
  ASSERT_TRUE(budget.try_acquire(solicited, identity(1), 64, 64 * mib));
  ASSERT_TRUE(!budget.try_acquire(unsolicited, identity(2), 1, 1));
  ASSERT_TRUE(budget.release(solicited, identity(1), 64, 64 * mib));

  // Giving back what an identity does not hold is refused and changes nothing.
  ASSERT_TRUE(budget.try_acquire(unsolicited, identity(1), 1, 1));
  ASSERT_TRUE(!budget.release(unsolicited, identity(2), 1, 1));
  ASSERT_TRUE(!budget.release(unsolicited, identity(1), 2, 1));
  ASSERT_EQ(1u, budget.identity_decoders(identity(1)));
  ASSERT_TRUE(budget.release(unsolicited, identity(1), 1, 1));

  ASSERT_EQ(0u, budget.active_decoders());
  ASSERT_EQ(0u, budget.reserved_bytes());
  ASSERT_EQ(0u, budget.unsolicited_decoders());
  ASSERT_EQ(0u, budget.unsolicited_bytes());
  ASSERT_EQ(0u, budget.tracked_identities());
}

// Headroom must fit under each limit that applies, and is not taken.
TEST(Rldp2InboundBudget, HeadroomMustFitButIsNotTaken) {
  const size_t mib = size_t{1} << 20;
  auto unsolicited = RldpInboundKind::unsolicited;
  auto solicited = RldpInboundKind::solicited;
  {
    // The identity's share: 16 MiB.
    RldpInboundBudget budget(64, 64 * mib);
    ASSERT_TRUE(!budget.try_acquire(unsolicited, identity(1), 1, 8 * mib, 8 * mib + 1));
    ASSERT_TRUE(budget.try_acquire(unsolicited, identity(1), 1, 8 * mib, 8 * mib));
    ASSERT_EQ(8 * mib, budget.identity_bytes(identity(1)));
    ASSERT_EQ(8 * mib, budget.reserved_bytes());
  }
  {
    // The unsolicited half: 32 MiB, of which 30 MiB are held by others.
    RldpInboundBudget budget(64, 64 * mib);
    ASSERT_TRUE(budget.try_acquire(unsolicited, identity(10), 1, 16 * mib));
    ASSERT_TRUE(budget.try_acquire(unsolicited, identity(17), 1, 14 * mib));
    ASSERT_TRUE(!budget.try_acquire(unsolicited, identity(18), 1, mib, mib + 1));
    ASSERT_TRUE(budget.try_acquire(unsolicited, identity(18), 1, mib, mib));
    ASSERT_EQ(31 * mib, budget.unsolicited_bytes());
  }
  {
    // The total: 64 MiB, of which 60 MiB are held.
    RldpInboundBudget budget(64, 64 * mib);
    ASSERT_TRUE(budget.try_acquire(solicited, identity(1), 0, 60 * mib));
    ASSERT_TRUE(!budget.try_acquire(solicited, identity(1), 1, mib, 3 * mib + 1));
    ASSERT_TRUE(budget.try_acquire(solicited, identity(1), 1, mib, 3 * mib));
    ASSERT_EQ(61 * mib, budget.reserved_bytes());
  }
}

// The ledger of identities is bounded, and an identity leaves it once it
// holds nothing.
TEST(Rldp2InboundBudget, IdentityLedgerIsBounded) {
  RldpInboundLimits limits = RldpInboundLimits::split(64, 64 << 20);
  limits.max_identities = 2;
  RldpInboundBudget budget(limits);
  auto unsolicited = RldpInboundKind::unsolicited;
  ASSERT_TRUE(budget.try_acquire(unsolicited, identity(1), 1, 1));
  ASSERT_TRUE(budget.try_acquire(unsolicited, identity(2), 1, 1));
  ASSERT_TRUE(!budget.try_acquire(unsolicited, identity(3), 1, 1));
  ASSERT_EQ(2u, budget.tracked_identities());
  // A known identity can still grow within its share.
  ASSERT_TRUE(budget.try_acquire(unsolicited, identity(1), 1, 1));
  ASSERT_TRUE(budget.release(unsolicited, identity(2), 1, 1));
  ASSERT_EQ(1u, budget.tracked_identities());
  ASSERT_TRUE(budget.try_acquire(unsolicited, identity(3), 1, 1));
  ASSERT_TRUE(budget.release(unsolicited, identity(1), 2, 2));
  ASSERT_TRUE(budget.release(unsolicited, identity(3), 1, 1));
  ASSERT_EQ(0u, budget.tracked_identities());
}

// An identity opening as many unsolicited transfers as it can is stopped at
// its share, across every connection it holds, while an unrelated identity's
// transfers still open and complete. Closing the saturating connections gives
// everything back, and the identity can reconnect and use its share again.
TEST(Rldp2InboundBudget, SaturatingIdentityLeavesOthersProgressing) {
  // A per-identity share of 4 decoders.
  auto budget = std::make_shared<RldpInboundBudget>(64, 64 << 20);
  ASSERT_EQ(4u, budget->limits().per_identity_decoders);
  auto flooder = identity(1);
  auto flooder_first = receiver_with(budget, flooder);
  auto flooder_second = receiver_with(budget, flooder);
  auto honest = receiver_with(budget, identity(2));
  Sink sink;

  for (td::uint32 i = 0; i < 3; i++) {
    open_transfer(*flooder_first, sink, transfer(100 + i));
  }
  // The same identity on a second connection, as through another local id,
  // shares the one share.
  for (td::uint32 i = 0; i < 3; i++) {
    open_transfer(*flooder_second, sink, transfer(200 + i));
  }
  ASSERT_EQ(3u, flooder_first->inbound_transfer_count());
  ASSERT_EQ(1u, flooder_second->inbound_transfer_count());
  ASSERT_EQ(4u, budget->identity_decoders(flooder));
  ASSERT_EQ(4 * open_part_cost(), budget->identity_bytes(flooder));

  // The unrelated identity both opens a transfer and completes one.
  open_transfer(*honest, sink, transfer(300));
  ASSERT_EQ(1u, honest->inbound_transfer_count());
  deliver_whole_transfer(*honest, sink, transfer(301));
  ASSERT_EQ(1u, sink.completed.size());
  ASSERT_TRUE(sink.completed[0] == transfer(301));

  // Release: closing the flooder's connections returns its usage to zero and
  // it leaves the ledger; the honest identity's transfer is untouched.
  flooder_first.reset();
  flooder_second.reset();
  ASSERT_EQ(0u, budget->identity_decoders(flooder));
  ASSERT_EQ(0u, budget->identity_bytes(flooder));
  ASSERT_EQ(1u, budget->tracked_identities());
  ASSERT_EQ(1u, budget->active_decoders());

  // Reconnect: the same identity gets its whole share back, and no more.
  auto flooder_again = receiver_with(budget, flooder);
  for (td::uint32 i = 0; i < 6; i++) {
    open_transfer(*flooder_again, sink, transfer(400 + i));
  }
  ASSERT_EQ(4u, flooder_again->inbound_transfer_count());
  flooder_again.reset();
  honest.reset();
  ASSERT_EQ(0u, budget->active_decoders());
  ASSERT_EQ(0u, budget->reserved_bytes());
  ASSERT_EQ(0u, budget->tracked_identities());
}

// Has `identities` identities try to open `each` unsolicited transfers.
// Returns the connections, which hold whatever they opened.
std::vector<std::unique_ptr<RldpConnection>> fill_unsolicited(std::shared_ptr<RldpInboundBudget> budget, Sink &sink,
                                                              td::uint32 identities, td::uint32 each) {
  std::vector<std::unique_ptr<RldpConnection>> peers;
  for (td::uint32 i = 0; i < identities; i++) {
    peers.push_back(receiver_with(budget, identity(1000 + i)));
    for (td::uint32 j = 0; j < each; j++) {
      open_transfer(*peers.back(), sink, transfer(1000 + i * each + j));
    }
  }
  return peers;
}

// However many identities open unsolicited transfers, an answer to a local
// request completes.
TEST(Rldp2InboundBudget, SolicitedAnswerCompletesWhenUnsolicitedHalfIsFull) {
  // 64 decoders: 32 unsolicited, at most 4 per identity; 32 reserved.
  auto budget = std::make_shared<RldpInboundBudget>(64, 64 << 20);
  Sink sink;
  // Each identity at its share, and twice as many identities as the
  // unsolicited half admits: together they would take every decoder.
  auto peers = fill_unsolicited(budget, sink, 16, 4);
  ASSERT_EQ(32u, budget->unsolicited_decoders());
  ASSERT_EQ(32u, budget->active_decoders());

  auto requester = receiver_with(budget, identity(1));
  auto answer = transfer(500);
  ASSERT_TRUE(requester->set_receive_limits(answer, td::Timestamp::in(60.0), 64));
  ASSERT_EQ(1u, requester->outstanding_request_count());
  deliver_whole_transfer(*requester, sink, answer);
  ASSERT_EQ(1u, sink.completed.size());
  ASSERT_TRUE(sink.completed[0] == answer);
  // The request ended with its answer.
  ASSERT_EQ(0u, requester->outstanding_request_count());
  ASSERT_EQ(32u, budget->active_decoders());
}

// A peer cannot reach the reserve by sending under an id no local request
// expects, by answering a request made to another peer, or by answering a
// request with more than it asked for.
TEST(Rldp2InboundBudget, PeerCannotClaimTheReserve) {
  auto budget = std::make_shared<RldpInboundBudget>(64, 64 << 20);
  Sink sink;
  auto peers = fill_unsolicited(budget, sink, 8, 4);
  ASSERT_EQ(32u, budget->unsolicited_decoders());

  auto requested_peer = receiver_with(budget, identity(1));
  auto other_peer = receiver_with(budget, identity(2));
  auto answer = transfer(600);
  ASSERT_TRUE(requested_peer->set_receive_limits(answer, td::Timestamp::in(60.0), 64));

  // An id no local request expects.
  deliver_whole_transfer(*requested_peer, sink, transfer(601));
  // The expected id, from a peer the request did not go to.
  deliver_whole_transfer(*other_peer, sink, answer);
  // The expected id from the expected peer, but larger than was asked for.
  for (auto &part : datagrams_for(answer, 1000)) {
    requested_peer->receive_raw(part.clone());
    requested_peer->run(sink);
  }
  ASSERT_TRUE(sink.completed.empty());
  ASSERT_EQ(0u, requested_peer->inbound_transfer_count());
  ASSERT_EQ(0u, other_peer->inbound_transfer_count());
  ASSERT_EQ(32u, budget->active_decoders());

  // The request is still outstanding, and its real answer completes.
  ASSERT_EQ(1u, requested_peer->outstanding_request_count());
  deliver_whole_transfer(*requested_peer, sink, answer);
  ASSERT_EQ(1u, sink.completed.size());
  ASSERT_TRUE(sink.completed[0] == answer);
}

// A transfer the peer opened under an id before a local request expected it
// was unsolicited; the request does not adopt it. It is dropped, and its
// identity's usage with it, and the answer is reassembled under the request.
TEST(Rldp2InboundBudget, RequestDoesNotAdoptATransferThePeerOpenedFirst) {
  auto budget = std::make_shared<RldpInboundBudget>(64, 64 << 20);
  auto peer = identity(1);
  auto receiver = receiver_with(budget, peer);
  Sink sink;
  auto id = transfer(700);
  open_transfer(*receiver, sink, id);
  ASSERT_EQ(1u, budget->identity_decoders(peer));
  ASSERT_TRUE(receiver->set_receive_limits(id, td::Timestamp::in(60.0), RldpConnection::DEFAULT_MTU));
  ASSERT_EQ(0u, receiver->inbound_transfer_count());
  ASSERT_EQ(0u, budget->identity_decoders(peer));
  ASSERT_EQ(0u, budget->active_decoders());
  open_transfer(*receiver, sink, id);
  ASSERT_EQ(1u, budget->active_decoders());
  ASSERT_EQ(0u, budget->unsolicited_decoders());
}

// Local requests outstanding on one connection are bounded; one beyond the
// bound is reported as failed rather than left waiting. Requests end when
// answered or expired.
TEST(Rldp2InboundBudget, OutstandingRequestsAreBounded) {
  auto budget = std::make_shared<RldpInboundBudget>(64, 64 << 20);
  auto receiver = receiver_with(budget, identity(1));
  Sink sink;
  for (td::uint32 i = 0; i < RldpConnection::MAX_OUTSTANDING_REQUESTS; i++) {
    ASSERT_TRUE(receiver->set_receive_limits(transfer(10000 + i), td::Timestamp::in(30.0), 64));
  }
  ASSERT_EQ(RldpConnection::MAX_OUTSTANDING_REQUESTS, receiver->outstanding_request_count());
  auto refused = transfer(20000);
  ASSERT_TRUE(!receiver->set_receive_limits(refused, td::Timestamp::in(30.0), 64));
  receiver->run(sink);
  ASSERT_EQ(1u, sink.failed.size());
  ASSERT_TRUE(sink.failed[0] == refused);
  ASSERT_EQ(RldpConnection::MAX_OUTSTANDING_REQUESTS, receiver->outstanding_request_count());

  // A second request under an outstanding id is refused without failing the
  // first.
  ASSERT_TRUE(!receiver->set_receive_limits(transfer(10000), td::Timestamp::in(30.0), 64));
  receiver->run(sink);
  ASSERT_EQ(1u, sink.failed.size());

  // An answer ends its request and makes room for another.
  deliver_whole_transfer(*receiver, sink, transfer(10000));
  ASSERT_EQ(1u, sink.completed.size());
  ASSERT_EQ(RldpConnection::MAX_OUTSTANDING_REQUESTS - 1, receiver->outstanding_request_count());
  ASSERT_TRUE(receiver->set_receive_limits(refused, td::Timestamp::in(30.0), 64));

  // Expiry ends the rest.
  td::Time::jump_in_future(td::Time::now() + 31.0);
  receiver->run(sink);
  ASSERT_EQ(0u, receiver->outstanding_request_count());
  ASSERT_EQ(0u, budget->active_decoders());
}

// One sender and one receiving connection, carried to each other in memory
// with nothing lost.
struct Link {
  Link(std::shared_ptr<RldpInboundBudget> budget, RldpPeerIdentity peer, td::uint64 receiver_mtu)
      : sender(identity(0)), receiver(receiver_with(std::move(budget), peer)) {
    receiver->set_default_mtu(receiver_mtu);
  }
  // Moves one round of datagrams both ways. True if anything moved.
  bool step() {
    sender.run(sender_sink);
    auto to_receiver = std::move(sender_sink.outbox);
    sender_sink.outbox.clear();
    for (auto &datagram : to_receiver) {
      receiver->receive_raw(std::move(datagram));
    }
    receiver->run(receiver_sink);
    auto to_sender = std::move(receiver_sink.outbox);
    receiver_sink.outbox.clear();
    for (auto &datagram : to_sender) {
      sender.receive_raw(std::move(datagram));
    }
    return !to_receiver.empty() || !to_sender.empty();
  }
  size_t finished() const {
    return receiver_sink.completed.size() + receiver_sink.failed.size();
  }

  RldpConnection sender;
  Sink sender_sink;
  std::unique_ptr<RldpConnection> receiver;
  Sink receiver_sink;
};

struct UnsolicitedRun {
  bool largest_completed{false};
  bool everything_completed{false};
  bool payloads_match{false};
  size_t failed{0};
  double seconds{0};
};

// The largest transfer at the supported overlay limit, two smaller ones from
// the same peer overlapping it, and an unrelated peer's transfer at the same
// time, all through real connections against `budget`. Runs until every
// transfer has finished one way or the other, or well past the unsolicited
// lifetime.
UnsolicitedRun run_largest_unsolicited(std::shared_ptr<RldpInboundBudget> budget) {
  const size_t small = size_t{1} << 20;
  Link raised(budget, identity(1), largest_unsolicited_transfer());
  Link unrelated(budget, identity(2), small + 4096);
  std::map<TransferId, td::BufferSlice> sent;
  auto send = [&](Link &link, TransferId id, size_t size) {
    auto data = payload(size);
    sent.emplace(id, data.clone());
    // The sender's own timeout is far beyond the receiver's lifetime, so only
    // the receiver decides whether the transfer made it in time.
    link.sender.send(id, std::move(data), td::Timestamp::in(600.0));
  };
  send(raised, transfer(900), largest_unsolicited_transfer());
  send(raised, transfer(901), small);
  send(raised, transfer(902), small);
  send(unrelated, transfer(903), small);

  UnsolicitedRun run;
  auto start = td::Time::now();
  while ((raised.finished() < 3 || unrelated.finished() < 1) && td::Time::now() - start < 15.0) {
    bool moved = raised.step();
    moved = unrelated.step() || moved;
    if (!moved) {
      td::Time::jump_in_future(td::Time::now() + 0.01);
    }
  }
  run.seconds = td::Time::now() - start;
  run.failed = raised.receiver_sink.failed.size() + unrelated.receiver_sink.failed.size();
  run.largest_completed = raised.receiver_sink.payloads.count(transfer(900)) > 0;
  run.everything_completed =
      raised.receiver_sink.completed.size() == 3 && unrelated.receiver_sink.completed.size() == 1;
  run.payloads_match = run.everything_completed;
  for (auto *link : {&raised, &unrelated}) {
    for (auto &[id, data] : link->receiver_sink.payloads) {
      auto it = sent.find(id);
      if (it == sent.end() || it->second.as_slice() != data.as_slice()) {
        run.payloads_match = false;
      }
    }
  }
  return run;
}

// Production budgets carry the largest transfer at the supported overlay
// limit, beside smaller ones from the same peer and an unrelated peer's,
// within the unsolicited lifetime, and give back everything afterwards.
// Overlays that size their limit from network configuration can allow larger
// transfers; RLDP2 refuses those it cannot hold when the allowance is
// installed (RldpRefusesAnAllowanceItCannotHold).
TEST(Rldp2InboundBudget, LargestUnsolicitedTransferCompletesUnderProductionBudgets) {
  auto budget = std::make_shared<RldpInboundBudget>(rldp_max_active_decoders, rldp_max_inbound_bytes);
  ASSERT_EQ(size_t{128} << 20, budget->limits().per_identity_bytes);
  auto run = run_largest_unsolicited(budget);
  LOG(ERROR) << "production share: completed=" << run.everything_completed << " failed=" << run.failed << " in "
             << run.seconds << "s";
  ASSERT_EQ(0u, run.failed);
  ASSERT_TRUE(run.everything_completed);
  ASSERT_TRUE(run.payloads_match);
  ASSERT_TRUE(run.seconds < 10.0);
  ASSERT_EQ(0u, budget->active_decoders());
  ASSERT_EQ(0u, budget->reserved_bytes());
  ASSERT_EQ(0u, budget->unsolicited_decoders());
  ASSERT_EQ(0u, budget->unsolicited_bytes());
  ASSERT_EQ(0u, budget->tracked_identities());
}

// The control: the same run with the share of 32 MiB this replaced. The
// largest transfer cannot be held and outlives its lifetime; if this ever
// completes, the test above no longer shows anything about the share.
TEST(Rldp2InboundBudget, LargestUnsolicitedTransferFailsAtTheOldShare) {
  auto limits = RldpInboundLimits::split(rldp_max_active_decoders, rldp_max_inbound_bytes);
  limits.per_identity_bytes = size_t{32} << 20;
  auto budget = std::make_shared<RldpInboundBudget>(limits);
  auto run = run_largest_unsolicited(budget);
  LOG(ERROR) << "32 MiB share: largest completed=" << run.largest_completed << " failed=" << run.failed << " in "
             << run.seconds << "s";
  ASSERT_TRUE(!run.largest_completed);
  ASSERT_TRUE(run.failed >= 1);
  ASSERT_EQ(0u, budget->active_decoders());
  ASSERT_EQ(0u, budget->reserved_bytes());
}

// RLDP2 as the transport an overlay raises a peer's allowance on. Its
// allowance setters are the ones a node calls; the probe only reads the
// allowance back.
class AllowanceProbe : public RldpIn {
 public:
  AllowanceProbe() : RldpIn(td::actor::ActorId<adnl::AdnlPeerTable>{}) {
  }
  td::uint64 allowance(adnl::AdnlNodeIdShort local_id, adnl::AdnlNodeIdShort peer_id) {
    return get_peer_mtu(local_id, peer_id);
  }
};

// A transport with no inbound budget of this kind accepts any allowance.
class UnbudgetedSender : public adnl::AdnlSenderEx {
 public:
  void add_id(adnl::AdnlNodeIdShort) override {
  }
  void send_message(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice) override {
  }
  void send_query(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, std::string, td::Promise<td::BufferSlice>,
                  td::Timestamp, td::BufferSlice) override {
  }
  void send_query_ex(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, std::string, td::Promise<td::BufferSlice>,
                     td::Timestamp, td::BufferSlice, td::uint64) override {
  }
  void get_conn_ip_str(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::Promise<td::string>) override {
  }
  td::uint64 allowance(adnl::AdnlNodeIdShort local_id, adnl::AdnlNodeIdShort peer_id) {
    return get_peer_mtu(local_id, peer_id);
  }

 protected:
  void on_mtu_updated(td::optional<adnl::AdnlNodeIdShort>, td::optional<adnl::AdnlNodeIdShort>) override {
  }
};

adnl::AdnlNodeIdShort node(td::uint32 n) {
  td::Bits256 bits;
  bits.set_zero();
  bits.as_slice().copy_from(td::Slice{reinterpret_cast<const td::uint8 *>(&n), sizeof(n)});
  return adnl::AdnlNodeIdShort{bits};
}

// An allowance is installed on RLDP2 only if its largest transfer fits one
// identity's share: the fixed overlay limit and a configuration above 16 MiB
// whose cost still fits are installed; one whose cost does not is refused, with
// the sizes, and the peer keeps the allowance it had.
TEST(Rldp2InboundBudget, RldpRefusesAnAllowanceItCannotHold) {
  const td::uint64 fixed_limit = (td::uint64{16} << 20) + 1024;
  // A configuration-derived limit above 16 MiB that still fits: about 116 MiB.
  const td::uint64 larger_fitting = (td::uint64{26} << 20) + 1024;
  // One that does not: about 150 MiB.
  const td::uint64 over_budget = (td::uint64{32} << 20) + 1024;
  ASSERT_TRUE(rldp_transfer_peak_bytes(larger_fitting).value() <= rldp_identity_byte_share);
  ASSERT_TRUE(rldp_transfer_peak_bytes(over_budget).value() > rldp_identity_byte_share);

  AllowanceProbe rldp;
  auto local = node(1);
  auto default_allowance = rldp.allowance(local, node(2));

  rldp.add_peer_mtu(local, node(2), fixed_limit);
  ASSERT_EQ(fixed_limit, rldp.allowance(local, node(2)));
  rldp.add_peer_mtu(local, node(3), larger_fitting);
  ASSERT_EQ(larger_fitting, rldp.allowance(local, node(3)));

  rldp.add_peer_mtu(local, node(4), over_budget);
  ASSERT_EQ(default_allowance, rldp.allowance(local, node(4)));
  // A peer that already had an allowance keeps it, unenlarged and unshrunk.
  rldp.add_peer_mtu(local, node(2), over_budget);
  ASSERT_EQ(fixed_limit, rldp.allowance(local, node(2)));
  // Removing what was refused leaves what was installed.
  rldp.remove_peer_mtu(local, node(2), over_budget);
  ASSERT_EQ(fixed_limit, rldp.allowance(local, node(2)));
  rldp.remove_peer_mtu(local, node(2), fixed_limit);
  ASSERT_EQ(default_allowance, rldp.allowance(local, node(2)));
  // The same holds for the allowances that apply to every peer.
  rldp.set_local_id_mtu(local, over_budget);
  ASSERT_EQ(default_allowance, rldp.allowance(local, node(5)));
  rldp.set_default_mtu(over_budget);
  ASSERT_EQ(default_allowance, rldp.allowance(node(9), node(5)));
  rldp.set_local_id_mtu(local, larger_fitting);
  ASSERT_EQ(larger_fitting, rldp.allowance(local, node(5)));

  // The refusal names the allowance, what it needs and what is available.
  auto refused = rldp_check_transfer_allowance(over_budget);
  ASSERT_TRUE(refused.is_error());
  auto message = refused.message().str();
  ASSERT_TRUE(message.find(std::to_string(over_budget)) != std::string::npos);
  ASSERT_TRUE(message.find(std::to_string(rldp_transfer_peak_bytes(over_budget).value())) != std::string::npos);
  ASSERT_TRUE(message.find(std::to_string(rldp_identity_byte_share)) != std::string::npos);
  ASSERT_TRUE(rldp_check_transfer_allowance(larger_fitting).is_ok());

  // A transport without this budget, such as the one the consensus overlays
  // use, carries the same allowance.
  UnbudgetedSender other;
  other.add_peer_mtu(local, node(4), over_budget);
  ASSERT_EQ(over_budget, other.allowance(local, node(4)));
}

}  // namespace
}  // namespace tos::rldp2
