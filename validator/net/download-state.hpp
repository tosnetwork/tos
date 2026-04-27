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

#include <memory>

#include <stats-provider.h>

#include "adnl/adnl-ext-client.h"
#include "overlay/overlays.h"
#include "tos/tos-types.h"
#include "validator/validator.h"

namespace tos {

namespace validator {

namespace fullnode {

// RAII reservation against the global persistent-state download memory
// budget. The reservation is held by a shared_ptr alongside the downloaded
// buffer; the underlying bytes are returned to the global budget only when
// the last reference is dropped (i.e., when downstream consumers have
// finished processing the buffer).
struct PersistentStateDownloadReservation {
  td::uint64 bytes{0};

  PersistentStateDownloadReservation() = default;
  explicit PersistentStateDownloadReservation(td::uint64 b) : bytes(b) {
  }
  PersistentStateDownloadReservation(const PersistentStateDownloadReservation &) = delete;
  PersistentStateDownloadReservation &operator=(const PersistentStateDownloadReservation &) = delete;
  PersistentStateDownloadReservation(PersistentStateDownloadReservation &&) = delete;
  PersistentStateDownloadReservation &operator=(PersistentStateDownloadReservation &&) = delete;
  ~PersistentStateDownloadReservation();
};

// Pairs a downloaded persistent-state buffer with its budget reservation.
// As long as a BudgetedBufferSlice (or any copy of `reservation`) is held,
// the corresponding bytes remain accounted against the global budget. The
// reservation is released exactly once when the last shared_ptr ref is
// dropped.
struct BudgetedBufferSlice {
  td::BufferSlice data;
  std::shared_ptr<PersistentStateDownloadReservation> reservation;
};

namespace testing {

// Test-only handle to the global persistent-state download budget. These
// helpers exist so a unit test can exercise the reservation lifetime
// invariant without bringing up the full DownloadState actor stack.
td::uint64 test_get_persistent_state_download_bytes();
bool test_try_reserve_persistent_state_download_memory(td::uint64 size);

}  // namespace testing

class DownloadState : public td::actor::Actor {
 public:
  DownloadState(BlockIdExt block_id, BlockIdExt masterchain_block_id, PersistentStateType type,
                adnl::AdnlNodeIdShort local_id, overlay::OverlayIdShort overlay_id, adnl::AdnlNodeIdShort download_from,
                td::uint32 priority, td::Timestamp timeout,
                td::actor::ActorId<ValidatorManagerInterface> validator_manager,
                td::actor::ActorId<adnl::AdnlSenderInterface> rldp, td::actor::ActorId<overlay::Overlays> overlays,
                td::actor::ActorId<adnl::Adnl> adnl, td::actor::ActorId<adnl::AdnlExtClient> client,
                td::Promise<BudgetedBufferSlice> promise);

  void abort_query(td::Status reason);
  void alarm() override;
  void finish_query();

  void start_up() override;
  void get_block_handle();
  void got_block_handle(BlockHandle handle);
  void got_node_to_download(adnl::AdnlNodeIdShort node);
  void got_block_state_description(td::BufferSlice data_description);
  void got_state_size(td::BufferSlice size_or_not_found);
  void request_total_size();
  void got_total_size(td::uint64 size);
  void got_block_state_part(td::BufferSlice data, td::uint32 requested_size);
  void got_block_state(td::BufferSlice data);

 private:
  td::Status prepare_download_buffer(td::uint64 size);

  BlockIdExt block_id_;
  BlockIdExt masterchain_block_id_;
  PersistentStateType type_;
  ShardId effective_shard_;
  adnl::AdnlNodeIdShort local_id_;
  overlay::OverlayIdShort overlay_id_;

  adnl::AdnlNodeIdShort download_from_ = adnl::AdnlNodeIdShort::zero();

  td::uint32 priority_;

  td::Timestamp timeout_;
  td::actor::ActorId<ValidatorManagerInterface> validator_manager_;
  td::actor::ActorId<adnl::AdnlSenderInterface> rldp_;
  td::actor::ActorId<overlay::Overlays> overlays_;
  td::actor::ActorId<adnl::Adnl> adnl_;
  td::actor::ActorId<adnl::AdnlExtClient> client_;
  td::Promise<BudgetedBufferSlice> promise_;

  BlockHandle handle_;
  td::BufferSlice state_;
  td::uint64 sum_ = 0;

  td::uint64 prev_logged_sum_ = 0;
  td::Timer prev_logged_timer_;
  td::uint64 total_size_ = 0;
  bool download_started_ = false;
  // RAII handle for the reserved download bytes. Set after the global
  // budget reserve succeeds in prepare_download_buffer(). Bytes are
  // released only when the last shared_ptr reference is dropped — which
  // covers the lifetime of any BudgetedBufferSlice handed to downstream.
  std::shared_ptr<PersistentStateDownloadReservation> reservation_;

  ProcessStatus status_;
};

}  // namespace fullnode

}  // namespace validator

}  // namespace tos
