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

    Copyright 2019-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#include <algorithm>

#include "auto/tl/tos_api.hpp"
#include "common/delay.h"
#include "http/http.h"
#include "rldp-http-proxy/tcp-tunnel.h"
#include "td/utils/misc.h"
#include "tl-utils/tl-utils.hpp"
#include "validator-engine/json-rpc-http-policy.h"

namespace tos::rldp_http {

td::Result<std::size_t> parse_tunnel_limit(td::Slice text) {
  // to_integer_safe refuses signs, spaces and trailing text; leading zeros
  // are refused here so that a value reads one way only.
  if (text.size() > 1 && text[0] == '0') {
    return td::Status::Error("tunnel limit must be a plain number from 1 to 65536");
  }
  auto R = td::to_integer_safe<td::uint32>(text);
  if (R.is_error() || R.ok() == 0 || R.ok() > kMaxTunnelLimit) {
    return td::Status::Error("tunnel limit must be a plain number from 1 to 65536");
  }
  return static_cast<std::size_t>(R.ok());
}

td::Result<double> parse_positive_seconds(td::Slice text, double max) {
  // Decimal notation only: strtod would also read hexadecimal ("0x10"),
  // "inf" and "nan".
  for (char c : text) {
    if (!(td::is_digit(c) || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-')) {
      return td::Status::Error("expected a decimal number of seconds");
    }
  }
  TRY_RESULT(seconds, json_rpc::parse_timeout_seconds(text));
  if (!(seconds > 0) || seconds > max) {
    return td::Status::Error(PSLICE() << "expected a number of seconds greater than 0 and at most " << max);
  }
  return seconds;
}

TunnelAdmission::Ticket::Ticket(std::shared_ptr<TunnelAdmission> owner, adnl::AdnlNodeIdShort peer)
    : owner_(std::move(owner)), peer_(peer) {
}

TunnelAdmission::Ticket &TunnelAdmission::Ticket::operator=(Ticket &&other) noexcept {
  if (this != &other) {
    release();
    owner_ = std::move(other.owner_);
    peer_ = other.peer_;
  }
  return *this;
}

TunnelAdmission::Ticket::~Ticket() {
  release();
}

void TunnelAdmission::Ticket::release() {
  if (owner_) {
    owner_->release(peer_);
    owner_.reset();
  }
}

td::Result<TunnelAdmission::Ticket> TunnelAdmission::admit(adnl::AdnlNodeIdShort peer) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (active_ >= max_tunnels_) {
    return td::Status::Error("too many tunnels");
  }
  auto it = per_peer_.find(peer);
  if (it != per_peer_.end() && it->second >= max_tunnels_per_peer_) {
    return td::Status::Error("too many tunnels from this peer");
  }
  // Both counts are below limits that fit in size_t, so neither increment
  // can wrap.
  ++per_peer_[peer];
  ++active_;
  return Ticket(shared_from_this(), peer);
}

std::size_t TunnelAdmission::active() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return active_;
}

std::size_t TunnelAdmission::active_for(adnl::AdnlNodeIdShort peer) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = per_peer_.find(peer);
  return it == per_peer_.end() ? 0 : it->second;
}

void TunnelAdmission::release(adnl::AdnlNodeIdShort peer) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = per_peer_.find(peer);
  if (it == per_peer_.end() || it->second == 0 || active_ == 0) {
    LOG(ERROR) << "tunnel admission released that was never taken";
    return;
  }
  if (--it->second == 0) {
    per_peer_.erase(it);
  }
  --active_;
}

RegisteredPayloadSenderGuard PayloadSenderRegistry::make_guard(td::Bits256 id) {
  return RegisteredPayloadSenderGuard(
      new std::pair<td::actor::ActorId<PayloadSenderRegistry>, td::Bits256>(actor_id(this), id),
      [](std::pair<td::actor::ActorId<PayloadSenderRegistry>, td::Bits256> *x) {
        td::actor::send_closure(x->first, &PayloadSenderRegistry::unregister_payload_sender, x->second);
        delete x;
      });
}

std::atomic<std::size_t> RldpTcpTunnel::live_count_{0};

RldpTcpTunnel::RldpTcpTunnel(td::Bits256 transfer_id, adnl::AdnlNodeIdShort src, adnl::AdnlNodeIdShort local_id,
                             td::actor::ActorId<adnl::AdnlSenderInterface> rldp,
                             td::actor::ActorId<PayloadSenderRegistry> registry, td::SocketFd fd,
                             TunnelTimeouts timeouts, TunnelAdmission::Ticket ticket)
    : id_(transfer_id)
    , src_(src)
    , local_id_(local_id)
    , rldp_(std::move(rldp))
    , registry_(std::move(registry))
    , fd_(std::move(fd))
    , timeouts_(timeouts)
    , ticket_(std::move(ticket)) {
  live_count_++;
}

RldpTcpTunnel::~RldpTcpTunnel() {
  live_count_--;
}

void RldpTcpTunnel::start_up() {
  self_ = actor_id(this);
  lifetime_deadline_ = td::Timestamp::in(timeouts_.max_lifetime);
  touch();
  td::actor::SchedulerContext::get().get_poll().subscribe(fd_.get_poll_info().extract_pollable_fd(this),
                                                          td::PollFlags::ReadWrite());
  td::actor::send_closure(
      registry_, &PayloadSenderRegistry::register_payload_sender, id_,
      [SelfId = actor_id(this)](tl_object_ptr<tos_api::http_getNextPayloadPart> f,
                                td::Promise<td::BufferSlice> promise) {
        td::actor::send_closure(SelfId, &RldpTcpTunnel::receive_query, std::move(f), std::move(promise));
      },
      [SelfId = actor_id(this)](td::Result<RegisteredPayloadSenderGuard> R) {
        td::actor::send_closure(SelfId, &RldpTcpTunnel::registered_sender, std::move(R));
      });
  process();
}

void RldpTcpTunnel::tear_down() {
  LOG(INFO) << "RldpTcpTunnel: tear_down";
  td::actor::SchedulerContext::get().get_poll().unsubscribe(fd_.get_poll_info().get_pollable_fd_ref());
  // The socket itself closes when the actor is destroyed, right after this.
}

void RldpTcpTunnel::registered_sender(td::Result<RegisteredPayloadSenderGuard> R) {
  if (R.is_error()) {
    // Without a registration the peer's queries never reach this tunnel, so
    // it could only sit on its socket.
    finish(R.move_as_error_prefix("failed to register tunnel: "));
    return;
  }
  guard_ = R.move_as_ok();
}

void RldpTcpTunnel::notify() {
  td::actor::send_closure(self_, &RldpTcpTunnel::process);
}

void RldpTcpTunnel::touch() {
  idle_deadline_ = td::Timestamp::in(timeouts_.idle);
  rearm();
}

void RldpTcpTunnel::rearm() {
  alarm_timestamp() = lifetime_deadline_;
  alarm_timestamp().relax(idle_deadline_);
  if (cur_promise_) {
    alarm_timestamp().relax(query_deadline_);
  }
}

void RldpTcpTunnel::alarm() {
  if (lifetime_deadline_.is_in_past()) {
    finish(td::Status::Error("tunnel reached its maximum lifetime"));
    return;
  }
  if (idle_deadline_.is_in_past()) {
    finish(td::Status::Error("tunnel was idle too long"));
    return;
  }
  if (cur_promise_ && query_deadline_.is_in_past()) {
    answer_query(true, false);
    if (finished_) {
      return;
    }
  }
  rearm();
}

void RldpTcpTunnel::request_data() {
  // One bounded part at a time. A completed RLDP response no longer consumes
  // the transport's reassembly budget, so queued socket writes need their own
  // backpressure before another response is admitted.
  if (finished_ || close_ || got_last_part_ || sent_request_ || fd_.ready_for_flush_write() != 0) {
    return;
  }
  sent_request_ = true;
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::BufferSlice> R) {
    td::actor::send_closure(SelfId, &RldpTcpTunnel::got_data_from_rldp, std::move(R));
  });

  auto f = create_serialize_tl_object<tos_api::http_getNextPayloadPart>(id_, out_seqno_++,
                                                                        static_cast<td::int32>(max_buffer_bytes));
  td::actor::send_closure(rldp_, &adnl::AdnlSenderInterface::send_query_ex, local_id_, src_, "payload part",
                          std::move(P), td::Timestamp::in(60.0), std::move(f), max_buffer_bytes + 1024);
}

void RldpTcpTunnel::receive_query(tl_object_ptr<tos_api::http_getNextPayloadPart> f,
                                  td::Promise<td::BufferSlice> promise) {
  if (finished_) {
    promise.set_error(td::Status::Error("tunnel is closed"));
    return;
  }
  if (cur_promise_) {
    LOG(INFO) << "failed to process query: previous query is active";
    promise.set_error(td::Status::Error("previous query is active"));
    return;
  }
  if (f->seqno_ != cur_seqno_) {
    LOG(INFO) << "failed to process query: seqno mismatch";
    promise.set_error(td::Status::Error("seqno mismatch"));
    return;
  }
  if (f->max_chunk_size_ <= 0) {
    promise.set_error(td::Status::Error("payload chunk size must be positive"));
    return;
  }
  LOG(INFO) << "RldpTcpTunnel: received query, seqno=" << cur_seqno_;
  cur_promise_ = std::move(promise);
  cur_max_chunk_size_ = f->max_chunk_size_;
  query_deadline_ = td::Timestamp::in(50.0);
  rearm();
  process();
}

void RldpTcpTunnel::got_data_from_rldp(td::Result<td::BufferSlice> R) {
  if (finished_) {
    return;
  }
  if (R.is_error()) {
    finish(R.move_as_error_prefix("payload part from peer failed: "));
    return;
  }
  td::BufferSlice data = R.move_as_ok();
  LOG(INFO) << "RldpTcpTunnel: received data from rldp: size=" << data.size();
  sent_request_ = false;
  auto F = fetch_tl_object<tos_api::http_payloadPart>(data, true);
  if (F.is_error()) {
    finish(F.move_as_error());
    return;
  }
  auto f = F.move_as_ok();
  if (f->data_.size() > max_buffer_bytes) {
    finish(td::Status::Error("payload part exceeds requested chunk size"));
    return;
  }
  if (!f->data_.empty()) {
    touch();
  }
  fd_.output_buffer().append(std::move(f->data_));
  if (f->last_) {
    got_last_part_ = true;
  }
  process();
}

void RldpTcpTunnel::process() {
  if (finished_) {
    return;
  }
  auto status = [&] {
    if (!close_) {
      auto remaining = max_buffer_bytes - fd_.input_buffer().size();
      TRY_RESULT(read, fd_.flush_read(remaining));
      // A hangup can arrive with unread socket data. Only mark EOF after
      // reading less than our allowance, so a full application buffer does
      // not discard the bytes still waiting in the kernel.
      close_ = read < remaining && td::can_close(fd_);
      if (read != 0) {
        touch();
      }
    }
    // Even after the peer's final part, drain bytes already accepted for the
    // backend. A temporarily unwritable socket is not a completed transfer.
    TRY_RESULT(written, fd_.flush_write());
    if (written != 0) {
      touch();
    }
    return td::Status::OK();
  }();
  if (status.is_error()) {
    finish(std::move(status));
    return;
  }
  if (got_last_part_) {
    close_ = true;
  }
  answer_query();
  request_data();
}

void RldpTcpTunnel::answer_query(bool allow_empty, bool from_timer) {
  if (finished_) {
    return;
  }
  if (from_timer) {
    active_timer_ = false;
  }
  auto &input = fd_.input_buffer();
  bool writes_drained = fd_.ready_for_flush_write() == 0;
  if (cur_promise_ && (!input.empty() || (close_ && writes_drained) || allow_empty)) {
    if (!from_timer && !close_ && !allow_empty && input.size() < http::HttpRequest::low_watermark()) {
      if (!active_timer_) {
        active_timer_ = true;
        delay_action(
            [SelfId = actor_id(this)]() { td::actor::send_closure(SelfId, &RldpTcpTunnel::answer_query, false, true); },
            td::Timestamp::in(0.001));
      }
      return;
    }
    size_t s = std::min<size_t>(input.size(), static_cast<size_t>(std::max<td::int32>(cur_max_chunk_size_, 0)));
    if (s != 0) {
      touch();
    }
    td::BufferSlice data(s);
    LOG(INFO) << "RldpTcpTunnel: sending data to rldp: size=" << data.size();
    input.advance(s, td::as_mutable_slice(data));
    bool last = close_ && input.empty() && writes_drained;
    cur_promise_.set_result(create_serialize_tl_object<tos_api::http_payloadPart>(
        std::move(data), std::vector<tl_object_ptr<tos_api::http_header>>(), last));
    ++cur_seqno_;
    cur_promise_.reset();
    rearm();
    if (last) {
      finish(td::Status::OK());
      return;
    }
  }
}

void RldpTcpTunnel::finish(td::Status reason) {
  if (finished_) {
    return;
  }
  finished_ = true;
  if (reason.is_error()) {
    LOG(INFO) << "RldpTcpTunnel closed: " << reason;
  } else {
    LOG(INFO) << "RldpTcpTunnel closed";
  }
  if (cur_promise_) {
    cur_promise_.set_error(reason.is_error() ? std::move(reason) : td::Status::Error("tunnel closed"));
  }
  stop();
}

TunnelStart start_tcp_tunnel(const TunnelEnvironment &env, td::Bits256 id, adnl::AdnlNodeIdShort src,
                             adnl::AdnlNodeIdShort local_id, td::IPAddress backend) {
  auto ticket = env.admission->admit(src);
  if (ticket.is_error()) {
    LOG(INFO) << "refusing HTTP tunnel from " << src << ": " << ticket.error();
    return TunnelStart::refused;
  }
  auto fd = td::SocketFd::open(backend);
  if (fd.is_error()) {
    LOG(INFO) << "failed to open HTTP tunnel to " << backend << ": " << fd.error();
    return TunnelStart::unreachable;
  }
  td::actor::create_actor<RldpTcpTunnel>(td::actor::ActorOptions().with_name("tunnel").with_poll(), id, src, local_id,
                                         env.rldp, env.registry, fd.move_as_ok(), env.timeouts, ticket.move_as_ok())
      .release();
  return TunnelStart::started;
}

}  // namespace tos::rldp_http
