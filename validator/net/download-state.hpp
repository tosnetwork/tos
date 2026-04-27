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
#include <string>

#include <stats-provider.h>

#include "adnl/adnl-ext-client.h"
#include "overlay/overlays.h"
#include "td/utils/port/FileFd.h"
#include "tos/tos-types.h"
#include "validator/state-download-buffer.h"
#include "validator/validator.h"

namespace tos {

namespace validator {

namespace fullnode {

class DownloadState : public td::actor::Actor {
 public:
  DownloadState(BlockIdExt block_id, BlockIdExt masterchain_block_id, PersistentStateType type,
                adnl::AdnlNodeIdShort local_id, overlay::OverlayIdShort overlay_id, adnl::AdnlNodeIdShort download_from,
                td::uint32 priority, td::Timestamp timeout,
                td::actor::ActorId<ValidatorManagerInterface> validator_manager,
                td::actor::ActorId<adnl::AdnlSenderInterface> rldp, td::actor::ActorId<overlay::Overlays> overlays,
                td::actor::ActorId<adnl::Adnl> adnl, td::actor::ActorId<adnl::AdnlExtClient> client,
                td::Promise<DownloadedPersistentState> promise);

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
  // Storage mode is decided in prepare_download_buffer() based on the
  // peer-advertised total size. Heap mode preserves the small-state
  // cheap path; File mode streams chunks into a tempfile via pwrite.
  enum class StorageMode { Heap, File };

  td::Status prepare_download_buffer(td::uint64 size);
  td::Status open_tempfile(td::uint64 size);
  td::Status write_chunk_to_tempfile(td::Slice chunk);
  td::Status finalize_tempfile();
  void cleanup_tempfile();

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
  td::Promise<DownloadedPersistentState> promise_;

  BlockHandle handle_;
  // Heap-path storage. Allocated only when StorageMode::Heap was chosen.
  td::BufferSlice state_;

  // File-path storage. Allocated only when StorageMode::File was chosen.
  td::FileFd file_fd_;
  std::string tempfile_path_;

  StorageMode mode_{StorageMode::Heap};

  td::uint64 sum_ = 0;

  td::uint64 prev_logged_sum_ = 0;
  td::Timer prev_logged_timer_;
  td::uint64 total_size_ = 0;
  bool download_started_ = false;
  // RAII handle for the reserved download bytes. Set after the global
  // budget reserve succeeds in prepare_download_buffer(). Bytes are
  // released only when the last shared_ptr reference is dropped — which
  // covers the lifetime of any DownloadedPersistentState handed to
  // downstream.
  std::shared_ptr<PersistentStateDownloadReservation> reservation_;

  ProcessStatus status_;
};

}  // namespace fullnode

}  // namespace validator

}  // namespace tos
