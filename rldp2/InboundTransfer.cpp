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

#include "common/errorcode.h"

#include "InboundTransfer.h"

namespace tos {
namespace rldp2 {
size_t InboundTransfer::total_size() const {
  return total_size_;
}

std::map<td::uint32, InboundTransfer::Part> &InboundTransfer::parts() {
  return parts_;
}

bool InboundTransfer::is_part_completed(td::uint32 part_i) {
  return !parts_.contains(part_i) && part_i < next_part_;
}

td::Result<InboundTransfer::Part *> InboundTransfer::get_part(td::uint32 part_i, const tos::fec::FecType &fec_type,
                                                              bool *refused_by_budget) {
  if (refused_by_budget) {
    *refused_by_budget = false;
  }
  auto it = parts_.find(part_i);
  if (it != parts_.end()) {
    return &it->second;
  }
  //TODO: pass offset off and process even newer parts.
  //LOG_CHECK(next_part_ >= part_i) << next_part_ << " >= " << part_i;
  if (next_part_ == part_i && parts_.size() < 20) {
    auto offset = offset_;
    if (fec_type.size() > total_size() - offset) {
      return td::Status::Error(ErrorCode::protoviolation,
                               PSTRING() << "too big part: offset=" << offset << " part_size=" << fec_type.size()
                                         << " total_size=" << total_size() << " part=" << part_i);
    }
    auto cost = rldp_decoder_reservation_bytes(fec_type.size(), fec_type.symbol_size(), fec_type.symbols_count());
    auto solver_bytes = rldp_solver_working_bytes(fec_type.symbol_size(), fec_type.symbols_count());
    if (!cost || !solver_bytes) {
      return td::Status::Error(ErrorCode::protoviolation, "part decoder size overflows");
    }
    // The last part of a transfer of several parts also needs the buffer the
    // parts are copied into while all of them are still held.
    bool assembles = part_i > 0 && fec_type.size() == total_size() - offset;
    size_t assembly_bytes = assembles ? total_size() : 0;
    auto charge = detail::checked_add(cost.value(), assembly_bytes);
    if (!charge) {
      return td::Status::Error(ErrorCode::protoviolation, "part decoder size overflows");
    }
    // Reserved before the decoder exists, so the budget bounds what is
    // allocated rather than what was already allocated; and only if its decode
    // attempt would still fit, so open decoders cannot crowd out every decode.
    auto reservation = RldpInboundReservation::acquire(budget_, kind_, peer_, 1, charge.value(), solver_bytes.value());
    if (!reservation) {
      if (refused_by_budget) {
        *refused_by_budget = true;
      }
      return nullptr;
    }
    offset_ = offset + fec_type.size();

    TRY_RESULT(decoder, fec_type.create_decoder());
    auto it = parts_.emplace(part_i, Part{std::move(decoder), RldpReceiver(RldpSender::Config()), offset,
                                          std::move(reservation.value()), solver_bytes.value(), assembly_bytes});
    data_parts_.emplace_back();
    next_part_++;
    return &it.first->second;
  }
  return nullptr;
}

void InboundTransfer::finish_part(td::uint32 part_i, td::BufferSlice data) {
  auto it = parts_.find(part_i);
  CHECK(it != parts_.end());
  CHECK(part_i < data_parts_.size());
  // The decoder goes away; its decoded bytes stay until the transfer ends.
  auto &reservation = it->second.reservation;
  // Never more than was reserved, which was representable.
  auto keep = detail::checked_add(data.size(), it->second.assembly_bytes);
  reservation.shrink_to(0, keep ? keep.value() : reservation.bytes());
  finished_reservations_.push_back(std::move(reservation));
  data_parts_[part_i] = std::move(data);
  parts_.erase(it);
}

td::optional<td::BufferSlice> InboundTransfer::try_finish() {
  if (parts_.empty() && offset_ == total_size_) {
    if (data_parts_.size() == 1) {
      return data_parts_[0].clone();
    }
    // Reserved with the last part's decoder: see get_part().
    td::BufferSlice data(total_size_);
    td::MutableSlice s = data.as_slice();
    for (const auto &part : data_parts_) {
      s.copy_from(part);
      s.remove_prefix(part.size());
    }
    CHECK(s.empty());
    return data;
  }
  return {};
}

}  // namespace rldp2
}  // namespace tos
