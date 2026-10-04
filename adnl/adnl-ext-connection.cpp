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
#include <algorithm>

#include "adnl-ext-connection.hpp"

namespace tos {

namespace adnl {

void AdnlExtConnection::send_uninit(td::BufferSlice data) {
  buffered_fd_.output_buffer().append(std::move(data));
  yield();
}

bool AdnlExtConnection::send(td::BufferSlice data) {
  LOG(DEBUG) << "sending packet of size " << data.size();
  if (output_overflowed_) {
    return false;
  }
  auto size_status = check_adnl_ext_payload_size(data.size());
  if (size_status.is_error()) {
    LOG(WARNING) << size_status;
    return false;
  }
  auto data_size = td::narrow_cast<td::uint32>(data.size() + adnl_ext_packet_framing_bytes);
  auto frame_bytes = data.size() + 4 + 32 + 32;
  auto pending = buffered_fd_.ready_for_flush_write();
  bool fits = adnl_ext_output_fits(pending, frame_bytes, pending_output_limit_);
  // Reserve the frame in the server's budget before it is queued, so
  // connections on other threads cannot pass the bound together.
  std::size_t reserved = 0;
  if (fits && server_output_budget_) {
    auto held = pending + frame_bytes;
    reserved = held > output_accounted_ ? held - output_accounted_ : 0;
    fits = server_output_budget_->try_reserve(reserved);
    if (!fits) {
      reserved = 0;
    }
  }
  if (!fits) {
    // The peer is not reading what it asked for, or the server's connections
    // together hold too much unread. Queuing more would grow memory without
    // bound, and dropping a frame would corrupt the stream.
    LOG(INFO) << "ADNL external peer left " << pending << " bytes unread; closing connection";
    output_overflowed_ = true;
    stop();
    return false;
  }

  td::BufferSlice d{frame_bytes};
  auto S = d.as_slice();

  S.copy_from(td::Slice(reinterpret_cast<const td::uint8 *>(&data_size), 4));
  S.remove_prefix(4);
  auto Sc = S;
  td::Random::secure_bytes(S.copy().truncate(32));
  S.remove_prefix(32);
  S.copy_from(data.as_slice());
  S.remove_prefix(data.size());

  td::sha256(Sc.truncate(32 + data.size()), S);

  td::BufferSlice e{d.size()};

  out_ctr_.encrypt(d.as_slice(), e.as_slice());

  buffered_fd_.output_buffer().append(std::move(e));
  output_accounted_ += reserved;
  account_output();
  yield();
  return true;
}

td::Status AdnlExtConnection::receive(td::ChainBufferReader &input, bool &exit_loop) {
  // Once closing for unread output, take no further queries from the buffer.
  if (stop_read_ || output_overflowed_) {
    exit_loop = true;
    return td::Status::OK();
  }
  if (input.size() > 0) {
    received_bytes_ = 1;
  }
  if (inited_) {
    if (!read_len_) {
      if (input.size() < 4) {
        exit_loop = true;
        return td::Status::OK();
      }

      char x[4];
      td::MutableSlice s{x, 4};
      input.advance(4, s);

      td::MutableSlice e{reinterpret_cast<td::uint8 *>(&len_), 4};
      in_ctr_.encrypt(s, e);
      LOG(DEBUG) << "len=" << len_;
      // Packet layout after decrypt:
      //   [32 bytes random prefix] [payload bytes (may be empty)] [32 bytes sha256]
      // So minimal valid length is 64 bytes (keepalive has empty payload).
      // A server connection holds at most its pending-input bound, so a frame
      // that could not fit is refused here, before any of it is read.
      auto max_packet_bytes = adnl_ext_max_packet_bytes;
      if (input_budget_) {
        max_packet_bytes = max_pending_input_ > 4 ? std::min(max_packet_bytes, max_pending_input_ - 4) : 0;
      }
      if (check_adnl_ext_framed_size(len_, max_packet_bytes).is_error()) {
        return td::Status::Error(ErrorCode::protoviolation, PSTRING() << "bad packet size: size=" << len_);
      }
      read_len_ = true;
    }
    if (input.size() < len_) {
      exit_loop = true;
      return td::Status::OK();
    }
    auto data = input.cut_head(len_).move_as_buffer_slice();
    update_timer();
    partial_frame_deadline_ = {};

    td::BufferSlice dec_data{data.size()};
    in_ctr_.encrypt(data.as_slice(), dec_data.as_slice());

    exit_loop = false;
    read_len_ = false;
    len_ = 0;
    return receive_packet(std::move(dec_data));
  } else {
    if (input.size() < 256) {
      exit_loop = true;
      return td::Status::OK();
    }

    auto data = input.cut_head(256).move_as_buffer_slice();
    update_timer();
    partial_frame_deadline_ = {};

    exit_loop = false;
    return process_init_packet(std::move(data));
  }
}

td::Result<std::size_t> AdnlExtConnection::read_input_within_budget() {
  if (!input_budget_) {
    TRY_STATUS(buffered_fd_.flush_read());
    return 0;
  }
  if (!td::can_read(buffered_fd_)) {
    return 0;
  }
  auto held = buffered_fd_.input_buffer().size();
  if (held >= max_pending_input_) {
    // Only reachable while reading is paused: a full buffer otherwise holds a
    // complete frame, which receive() has already taken. The socket stays
    // readable, so the next loop() resumes here.
    return 0;
  }
  auto wanted = held + std::min(adnl_ext_input_read_chunk_bytes, max_pending_input_ - held);
  if (wanted > input_accounted_) {
    input_accounted_ += input_budget_->try_reserve_up_to(wanted - input_accounted_);
  }
  if (input_accounted_ <= held) {
    // The server's connections together hold as much unfinished input as they
    // may. Reading on would grow memory past the bound; leaving bytes in the
    // socket would stall this peer with no end. Closing releases everything
    // this connection holds.
    return td::Status::Error(ErrorCode::notready, PSTRING() << "external connections hold their whole input budget ("
                                                            << input_budget_->limit() << " bytes)");
  }
  // Never read more than is reserved: the budget is charged before the buffer grows.
  TRY_RESULT(read, buffered_fd_.flush_read(input_accounted_ - held));
  return read;
}

void AdnlExtConnection::account_input() {
  if (!input_budget_) {
    return;
  }
  auto held = buffered_fd_.input_buffer().size();
  if (held < input_accounted_) {
    if (!input_budget_->release(input_accounted_ - held)) {
      LOG(ERROR) << "ADNL external input budget: released more than was reserved";
    }
    input_accounted_ = held;
  }
}

void AdnlExtConnection::update_partial_frame_deadline() {
  if (!input_budget_) {
    return;
  }
  bool holds_partial_frame = read_len_ || buffered_fd_.input_buffer().size() > 0;
  if (!holds_partial_frame) {
    partial_frame_deadline_ = {};
    return;
  }
  if (!partial_frame_deadline_) {
    partial_frame_deadline_ = td::Timestamp::in(partial_frame_lifetime_);
  }
  // Re-armed every time: update_timer() resets the alarm to the idle timeout.
  alarm_timestamp().relax(partial_frame_deadline_);
}

void AdnlExtConnection::loop() {
  auto status = [&] {
    auto &input = buffered_fd_.input_buffer();
    // Read a reserved chunk, take every complete frame off the buffer, and
    // repeat while the socket has more, so what is held between reads is at
    // most one unfinished frame.
    while (true) {
      TRY_RESULT(read, read_input_within_budget());
      bool exit_loop = false;
      while (!exit_loop) {
        TRY_STATUS(receive(input, exit_loop));
      }
      account_input();
      if (read == 0) {
        break;
      }
    }
    update_partial_frame_deadline();
    TRY_STATUS(buffered_fd_.flush_write());
    account_output();
    if (td::can_close(buffered_fd_)) {
      stop();
    }
    return td::Status::OK();
  }();
  if (status.is_error()) {
    // Answers already queued while this batch was processed still go out before
    // the socket closes. A refusal that ends in a close is an intended terminal
    // state for the peer's queries, not a fault of this side, so it is not an error.
    buffered_fd_.flush_write().ignore();
    if (status.code() == ErrorCode::notready) {
      LOG(INFO) << "Closing external connection: " << status;
    } else {
      LOG(ERROR) << "Client got error " << status;
    }
    stop();
  } else {
    send_ready();
  }
}

td::Status AdnlExtConnection::init_crypto(td::Slice S) {
  if (S.size() < 96) {
    return td::Status::Error(ErrorCode::protoviolation, "too small enc data");
  }
  CHECK(S.size() >= 96);
  td::SecureString s1(32), s2(32);
  td::SecureString v1(16), v2(16);
  s1.as_mutable_slice().copy_from(S.copy().truncate(32));
  S.remove_prefix(32);
  s2.as_mutable_slice().copy_from(S.copy().truncate(32));
  S.remove_prefix(32);
  v1.as_mutable_slice().copy_from(S.copy().truncate(16));
  S.remove_prefix(16);
  v2.as_mutable_slice().copy_from(S.copy().truncate(16));
  S.remove_prefix(16);
  if (is_client_) {
    in_ctr_.init(s1, v1);
    out_ctr_.init(s2, v2);
  } else {
    in_ctr_.init(s2, v2);
    out_ctr_.init(s1, v1);
  }
  inited_ = true;
  return td::Status::OK();
}

td::Status AdnlExtConnection::receive_packet(td::BufferSlice data) {
  LOG(DEBUG) << "received packet of size " << data.size();
  if (data.size() < adnl_ext_packet_framing_bytes) {
    return td::Status::Error(ErrorCode::protoviolation, "too small packet");
  }
  auto S = data.as_slice();
  S.truncate(data.size() - 32);
  auto D = data.as_slice();
  D.remove_prefix(data.size() - 32);

  if (td::sha256(S) != D) {
    return td::Status::Error(ErrorCode::protoviolation, "sha256 mismatch");
  }

  data.truncate(data.size() - 32);
  data.confirm_read(32);

  if (data.size() == 0) {
    // keepalive
    return td::Status::OK();
  }

  bool processed = false;
  TRY_STATUS(process_custom_packet(data, processed));
  if (processed) {
    return td::Status::OK();
  }

  return process_packet(std::move(data));
}

}  // namespace adnl

}  // namespace tos
