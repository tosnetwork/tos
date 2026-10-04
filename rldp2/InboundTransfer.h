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

#include <map>
#include <memory>
#include <vector>

#include "fec/fec.h"
#include "td/utils/optional.h"

#include "RldpReceiver.h"
#include "rldp-inbound-budget.h"

namespace tos {
namespace rldp2 {
struct InboundTransfer {
  struct Part {
    std::unique_ptr<td::fec::Decoder> decoder;
    RldpReceiver receiver;
    size_t offset;
    // The decoder slot and bytes this part may hold, taken before the decoder
    // was created.
    RldpInboundReservation reservation;
    // Working memory a decode attempt of this part may take, reserved around
    // each attempt.
    size_t solver_bytes;
  };

  // Every part's decoder is reserved from `budget` before it is created; a
  // part the budget cannot hold is not created.
  InboundTransfer(size_t total_size, std::shared_ptr<RldpInboundBudget> budget)
      : total_size_(total_size), budget_(std::move(budget)) {
  }

  size_t total_size() const;
  std::map<td::uint32, Part> &parts();
  bool is_part_completed(td::uint32 part_i);
  // The part's state, created if `part_i` is the next part. Null if it is not
  // the next part, too many parts are open, or the budget cannot hold it; then
  // `refused_by_budget` says which.
  td::Result<Part *> get_part(td::uint32 part_i, const fec::FecType &fec_type, bool *refused_by_budget = nullptr);
  void finish_part(td::uint32 part_i, td::BufferSlice data);
  td::optional<td::BufferSlice> try_finish();

 private:
  std::map<td::uint32, Part> parts_;
  td::uint32 next_part_{0};
  size_t offset_{0};
  size_t total_size_;
  std::vector<td::BufferSlice> data_parts_;
  std::shared_ptr<RldpInboundBudget> budget_;
  // Bytes still held by finished parts, kept charged until the transfer ends.
  std::vector<RldpInboundReservation> finished_reservations_;
};
}  // namespace rldp2
}  // namespace tos
