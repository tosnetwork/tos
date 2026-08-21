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
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <functional>

#include "adnl/adnl-sender-ex.h"
#include "td/actor/PromiseFuture.h"
#include "td/utils/buffer.h"

namespace tos {

namespace rldp2 {

namespace detail {

// Completes an outbound query's promise against a received answer, enforcing
// the max_answer_size the caller originally declared to send_query_ex.
//
// This is only ever called from RldpIn::process_message(rldp_answer&) in
// rldp.cpp, where it is provably unreachable via any RLDP2-wire-protocol-
// compliant sender: RldpConnection::receive_raw_obj (RldpConnection.cpp)
// checks the sender-declared total_size against this same max_answer_size
// before accepting any part of a transfer, and InboundTransfer::try_finish
// only ever completes with exactly total_size_ bytes, so a reassembled
// message.data_ can never exceed max_answer_size in practice -- a malicious
// peer that tries to answer bigger just gets that part dropped before
// reassembly. Exposed here as a free function (rather than kept private to
// RldpIn) purely so its boundary behavior can still be unit-tested directly,
// without needing to fabricate a wire-level scenario the transport layer's
// own accounting makes impossible. Lives in `detail` since it is an
// implementation aid for tests, not part of the Rldp public interface.
void complete_out_query(td::Promise<td::BufferSlice> promise, td::uint64 max_answer_size, td::BufferSlice data);

}  // namespace detail

class Rldp : public adnl::AdnlSenderEx {
 public:
  using PartCompletedCallback =
      std::function<void(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::Bits256, td::uint32, td::uint64)>;

  Rldp() : AdnlSenderEx(default_mtu()) {
  }
  ~Rldp() override = default;

  static constexpr td::uint64 default_mtu() {
    return 7680;  // See RldpConnection::DEFAULT_MTU
  }

  virtual void send_message_ex(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, td::Timestamp timeout,
                               td::BufferSlice data) = 0;

  // Measurement and diagnostics may bind decoded-part observations to one
  // exact query by choosing its request transfer id. Normal callers should
  // continue using send_query_ex, which chooses a cryptographically random id.
  // Explicit ids must be nonzero and cannot reuse an active complementary
  // response id; violations fail the promise before anything is sent.
  virtual void send_query_ex_with_transfer_id(adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort dst, std::string name,
                                              td::Promise<td::BufferSlice> promise, td::Timestamp timeout,
                                              td::BufferSlice data, td::uint64 max_answer_size,
                                              td::Bits256 request_transfer_id) = 0;

  // An observer sees completed inbound FEC parts after successful decode. It
  // cannot alter transfer validity; measurement tools use it to place an
  // independently counted network-loss window after real progress.
  virtual void set_part_completed_callback(PartCompletedCallback callback) = 0;

  static td::actor::ActorOwn<Rldp> create(td::actor::ActorId<adnl::Adnl> adnl);
};

}  // namespace rldp2

}  // namespace tos
