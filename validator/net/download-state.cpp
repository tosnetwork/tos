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
#include "td/utils/overloaded.h"
#include "td/utils/port/path.h"
#include "tos/tos-io.hpp"
#include "tos/tos-tl.hpp"

#include "download-state.hpp"
#include "full-node.h"

#include <algorithm>
#include <limits>

namespace tos {

namespace validator {

namespace fullnode {

namespace {

constexpr td::uint64 kPersistentStatePartSize = 1ULL << 21;

}  // namespace

DownloadState::DownloadState(BlockIdExt block_id, BlockIdExt masterchain_block_id, PersistentStateType type,
                             adnl::AdnlNodeIdShort local_id, overlay::OverlayIdShort overlay_id,
                             adnl::AdnlNodeIdShort download_from, td::uint32 priority, td::Timestamp timeout,
                             td::actor::ActorId<ValidatorManagerInterface> validator_manager,
                             td::actor::ActorId<adnl::AdnlSenderInterface> rldp,
                             td::actor::ActorId<overlay::Overlays> overlays, td::actor::ActorId<adnl::Adnl> adnl,
                             td::actor::ActorId<adnl::AdnlExtClient> client,
                             td::Promise<DownloadedPersistentState> promise)
    : block_id_(block_id)
    , masterchain_block_id_(masterchain_block_id)
    , type_(type)
    , effective_shard_(persistent_state_to_effective_shard(block_id_.shard_full(), type))
    , local_id_(local_id)
    , overlay_id_(overlay_id)
    , download_from_(download_from)
    , priority_(priority)
    , timeout_(timeout)
    , validator_manager_(validator_manager)
    , rldp_(rldp)
    , overlays_(overlays)
    , adnl_(adnl)
    , client_(client)
    , promise_(std::move(promise)) {
  CHECK(masterchain_block_id_.is_valid() || effective_shard_ == 0);
}

void DownloadState::cleanup_tempfile() {
  if (!file_fd_.empty()) {
    file_fd_.close();
  }
  if (!tempfile_path_.empty()) {
    auto status = td::unlink(tempfile_path_);
    if (status.is_error()) {
      LOG(WARNING) << "failed to remove partial tempfile " << tempfile_path_ << ": " << status;
    }
    tempfile_path_.clear();
  }
}

void DownloadState::abort_query(td::Status reason) {
  // Drop the RAII reservation here: its destructor is the single source of
  // budget release. If `reservation_` is null (e.g., we never reserved or
  // the buffer was already handed off), this is a no-op.
  reservation_.reset();
  // Tear down any pending tempfile in case we aborted mid-stream so the
  // partial file does not survive the actor.
  cleanup_tempfile();
  if (promise_) {
    LOG(WARNING) << "failed to download state " << block_id_.to_str() << " from " << download_from_ << ": " << reason;
    promise_.set_error(std::move(reason));
  }
  stop();
}

void DownloadState::alarm() {
  abort_query(td::Status::Error(ErrorCode::timeout, "timeout"));
}

void DownloadState::finish_query() {
  if (!promise_) {
    // Promise was already settled (e.g., disk path delivered an error
    // before us); drop the reservation locally so the destructor releases
    // the budget exactly once.
    reservation_.reset();
    cleanup_tempfile();
    stop();
    return;
  }
  if (mode_ == StorageMode::Heap) {
    // Hand both the buffer and the reservation downstream. The reservation
    // shared_ptr keeps the bytes accounted against the global budget for as
    // long as any caller holds the BudgetedBufferSlice (or any copy of the
    // shared_ptr). DO NOT release the budget here: that would prematurely
    // free the accounting while downstream is still holding the buffer.
    promise_.set_value(DownloadedPersistentState::memory(
        BudgetedBufferSlice{std::move(state_), std::move(reservation_)}));
    stop();
    return;
  }

  // File mode: fsync, rename .partial -> final, then hand the path
  // (still owned via BudgetedStateFile.is_temp = true so the consumer's
  // destructor cleans up after parse).
  auto status = finalize_tempfile();
  if (status.is_error()) {
    cleanup_tempfile();
    promise_.set_error(std::move(status));
    reservation_.reset();
    stop();
    return;
  }

  BudgetedStateFile bsf{std::move(tempfile_path_), sum_, std::move(reservation_), /*temp=*/true};
  tempfile_path_.clear();
  promise_.set_value(DownloadedPersistentState::file(std::move(bsf)));
  stop();
}

td::Status DownloadState::open_tempfile(td::uint64 size) {
  auto root = get_persistent_state_tempfile_dir();
  if (root.empty()) {
    return td::Status::Error("persistent state tempfile directory not registered");
  }
  // Best-effort: ensure the directory exists.
  auto mk = td::mkpath(root + "/persistent-state/", 0700);
  if (mk.is_error()) {
    return td::Status::Error(PSTRING() << "cannot create tempfile dir " << root << "/persistent-state/: "
                                       << mk.error());
  }
  // Filename pattern: persistent-state/<block_id>.<ptr>.partial
  // The pid+ptr disambiguator avoids collisions if two downloads target the
  // same block id concurrently. The .partial suffix is what
  // cleanup_persistent_state_tempfiles() looks for to sweep residue at
  // startup.
  std::string path = PSTRING() << root << "/persistent-state/" << block_id_.id.to_str() << "."
                               << static_cast<td::uint64>(reinterpret_cast<std::uintptr_t>(this))
                               << ".partial";
  auto r_fd = td::FileFd::open(
      path,
      td::FileFd::Flags::Write | td::FileFd::Flags::Read | td::FileFd::Flags::Create | td::FileFd::Flags::Truncate);
  if (r_fd.is_error()) {
    return td::Status::Error(PSTRING() << "cannot open tempfile " << path << ": " << r_fd.error());
  }
  file_fd_ = r_fd.move_as_ok();
  tempfile_path_ = std::move(path);

  // Pre-size the file so any pwrite at offset < size is well-defined and
  // we fail early if disk space is unavailable. Achieved via seek + write
  // of a single zero byte at the end (portable equivalent of ftruncate via
  // the FileFd API surface).
  if (size > 0) {
    auto seek_status = file_fd_.seek(static_cast<td::int64>(size) - 1);
    if (seek_status.is_error()) {
      return td::Status::Error(PSTRING() << "cannot seek tempfile to " << size << ": " << seek_status);
    }
    char zero = 0;
    auto write_res = file_fd_.write(td::Slice(&zero, 1));
    if (write_res.is_error()) {
      return td::Status::Error(PSTRING() << "cannot pre-extend tempfile to " << size << ": "
                                         << write_res.error());
    }
    if (write_res.ok() != 1) {
      return td::Status::Error(PSTRING() << "short pre-extend write: " << write_res.ok() << " of 1");
    }
  }

  return td::Status::OK();
}

td::Status DownloadState::write_chunk_to_tempfile(td::Slice chunk) {
  if (chunk.empty()) {
    return td::Status::OK();
  }
  // Defensive overflow check. sum_ is tracked elsewhere but we never
  // pwrite past total_size_; if math somehow lands wrong we error out.
  td::uint64 offset = sum_;
  if (chunk.size() > total_size_ || offset > total_size_ - chunk.size()) {
    return td::Status::Error("tempfile write would exceed advertised size");
  }
  auto r_written = file_fd_.pwrite(chunk, static_cast<td::int64>(offset));
  if (r_written.is_error()) {
    return td::Status::Error(PSTRING() << "tempfile pwrite failed: " << r_written.error());
  }
  if (r_written.ok() != chunk.size()) {
    // Partial pwrite: fail closed rather than retry. RLDP delivers full
    // chunks so a partial write here means the FS or disk is in trouble.
    return td::Status::Error(PSTRING() << "short tempfile pwrite: " << r_written.ok() << " of "
                                       << chunk.size());
  }
  return td::Status::OK();
}

td::Status DownloadState::finalize_tempfile() {
  if (file_fd_.empty()) {
    return td::Status::Error("tempfile already closed");
  }
  auto sync_status = file_fd_.sync();
  if (sync_status.is_error()) {
    return td::Status::Error(PSTRING() << "tempfile fsync failed: " << sync_status);
  }
  file_fd_.close();
  // Rename .partial -> final.
  std::string final_path = tempfile_path_;
  constexpr auto suffix = ".partial";
  constexpr std::size_t suffix_len = sizeof(".partial") - 1;
  if (final_path.size() >= suffix_len &&
      final_path.compare(final_path.size() - suffix_len, suffix_len, suffix) == 0) {
    final_path.resize(final_path.size() - suffix_len);
  }
  auto rename_status = td::rename(tempfile_path_, final_path);
  if (rename_status.is_error()) {
    return td::Status::Error(PSTRING() << "tempfile rename failed: " << rename_status);
  }
  tempfile_path_ = std::move(final_path);
  return td::Status::OK();
}

td::Status DownloadState::prepare_download_buffer(td::uint64 size) {
  auto status = validate_persistent_state_size(size);
  if (status.is_error()) {
    return status;
  }
  if (reservation_) {
    return td::Status::Error("persistent state download size announced twice");
  }
  if (!try_reserve_persistent_state_download_memory(size)) {
    return td::Status::Error(PSTRING() << "persistent state download memory budget exceeded: "
                                       << size << " requested");
  }
  // Wrap the reserved bytes in a shared RAII handle. From this point the
  // ONLY way the budget is released is via this shared_ptr's destructor.
  // If make_shared throws (allocation failure), the reservation handle is
  // never constructed, so the dtor never runs and the bytes we just CAS'd
  // into the global counter would leak. Release them explicitly on failure
  // via a stack-allocated reservation whose destructor returns the bytes.
  std::shared_ptr<PersistentStateDownloadReservation> reservation;
  try {
    reservation = std::make_shared<PersistentStateDownloadReservation>(size);
  } catch (...) {
    PersistentStateDownloadReservation rollback{size};
    (void)rollback;
    return td::Status::Error("cannot allocate persistent state download reservation");
  }

  total_size_ = size;
  // Pick storage mode based on the heap threshold. Anything larger than
  // the threshold bypasses the BufferSlice path entirely so a 1 GiB
  // state cannot induce a 1 GiB heap allocation.
  if (size <= persistent_state_heap_threshold_bytes()) {
    mode_ = StorageMode::Heap;
    try {
      state_ = td::BufferSlice{td::narrow_cast<std::size_t>(total_size_)};
    } catch (...) {
      // reservation goes out of scope here; its dtor releases the bytes.
      total_size_ = 0;
      return td::Status::Error("cannot allocate persistent state download buffer");
    }
  } else {
    mode_ = StorageMode::File;
    auto file_status = open_tempfile(size);
    if (file_status.is_error()) {
      // reservation goes out of scope here; its dtor releases the bytes.
      cleanup_tempfile();
      total_size_ = 0;
      return file_status;
    }
  }

  reservation_ = std::move(reservation);
  sum_ = 0;
  return td::Status::OK();
}

void DownloadState::start_up() {
  status_ = ProcessStatus(validator_manager_, "process.download_state_net");
  alarm_timestamp() = timeout_;

  td::Promise<td::BufferSlice> P = [SelfId = actor_id(this), block_id = block_id_](td::Result<td::BufferSlice> R) {
    if (R.is_error()) {
      td::actor::send_closure(SelfId, &DownloadState::get_block_handle);
    } else {
      LOG(WARNING) << "got block state from disk: " << block_id.to_str();
      td::actor::send_closure(SelfId, &DownloadState::got_block_state, R.move_as_ok());
    }
  };
  if (block_id_.seqno() == 0) {
    td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_zero_state, block_id_, std::move(P));
  } else {
    td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_persistent_state, block_id_,
                            masterchain_block_id_, type_, std::move(P));
  }
}

void DownloadState::get_block_handle() {
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<BlockHandle> R) {
    if (R.is_error()) {
      td::actor::send_closure(SelfId, &DownloadState::abort_query, R.move_as_error());
    } else {
      td::actor::send_closure(SelfId, &DownloadState::got_block_handle, R.move_as_ok());
    }
  });

  td::actor::send_closure(validator_manager_, &ValidatorManagerInterface::get_block_handle, block_id_, true,
                          std::move(P));
}

void DownloadState::got_block_handle(BlockHandle handle) {
  handle_ = std::move(handle);
  if (!download_from_.is_zero() || !client_.empty()) {
    got_node_to_download(download_from_);
  } else {
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<std::vector<adnl::AdnlNodeIdShort>> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &DownloadState::abort_query, R.move_as_error());
      } else {
        auto vec = R.move_as_ok();
        if (vec.size() == 0) {
          td::actor::send_closure(SelfId, &DownloadState::abort_query,
                                  td::Status::Error(ErrorCode::notready, "no nodes"));
        } else {
          td::actor::send_closure(SelfId, &DownloadState::got_node_to_download, vec[0]);
        }
      }
    });

    td::actor::send_closure(overlays_, &overlay::Overlays::get_overlay_random_peers, local_id_, overlay_id_, 1,
                            std::move(P));
  }
}

void DownloadState::got_node_to_download(adnl::AdnlNodeIdShort node) {
  download_from_ = node;
  LOG(WARNING) << "downloading state " << block_id_.to_str() << " ("
               << persistent_state_type_to_string(block_id_.shard_full(), type_) << ") from " << download_from_;

  td::Promise<td::BufferSlice> P;
  td::BufferSlice query;

  if (effective_shard_ == 0) {
    P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &DownloadState::abort_query, R.move_as_error());
      } else {
        td::actor::send_closure(SelfId, &DownloadState::got_block_state_description, R.move_as_ok());
      }
    });

    if (masterchain_block_id_.is_valid()) {
      query = create_serialize_tl_object<tos_api::tosNode_preparePersistentState>(
          create_tl_block_id(block_id_), create_tl_block_id(masterchain_block_id_));
    } else {
      query = create_serialize_tl_object<tos_api::tosNode_prepareZeroState>(create_tl_block_id(block_id_));
    }
  } else {
    P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::BufferSlice> R) mutable {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &DownloadState::abort_query, R.move_as_error());
      } else {
        td::actor::send_closure(SelfId, &DownloadState::got_state_size, R.move_as_ok());
      }
    });

    query = create_serialize_tl_object<tos_api::tosNode_getPersistentStateSizeV2>(
        create_tl_object<tos_api::tosNode_persistentStateIdV2>(
            create_tl_block_id(block_id_), create_tl_block_id(masterchain_block_id_), effective_shard_));
  }

  if (client_.empty()) {
    td::actor::send_closure(overlays_, &overlay::Overlays::send_query, download_from_, local_id_, overlay_id_,
                            "get_prepare", std::move(P), td::Timestamp::in(1.0), std::move(query));
  } else {
    td::actor::send_closure(client_, &adnl::AdnlExtClient::send_query, "get_prepare",
                            create_serialize_tl_object_suffix<tos_api::tosNode_query>(std::move(query)),
                            td::Timestamp::in(1.0), std::move(P));
  }
}

void DownloadState::got_block_state_description(td::BufferSlice data) {
  auto F = fetch_tl_object<tos_api::tosNode_PreparedState>(std::move(data), true);
  if (F.is_error()) {
    abort_query(F.move_as_error());
    return;
  }
  prev_logged_timer_ = td::Timer();

  tos_api::downcast_call(
      *F.move_as_ok().get(),
      td::overloaded(
          [&](tos_api::tosNode_notFoundState &f) {
            abort_query(td::Status::Error(ErrorCode::notready, "state not found"));
          },
          [&, self = this](tos_api::tosNode_preparedState &f) {
            if (masterchain_block_id_.is_valid()) {
              // Downloading a prepared persistent state must be bounded by
              // the peer-advertised total size first. Starting slices before
              // this response lets a faulty peer stream chunks indefinitely.
              request_total_size();
              return;
            }
            auto P = td::PromiseCreator::lambda([SelfId = actor_id(self)](td::Result<td::BufferSlice> R) {
              if (R.is_error()) {
                td::actor::send_closure(SelfId, &DownloadState::abort_query, R.move_as_error());
              } else {
                td::actor::send_closure(SelfId, &DownloadState::got_block_state, R.move_as_ok());
              }
            });

            td::BufferSlice query =
                create_serialize_tl_object<tos_api::tosNode_downloadZeroState>(create_tl_block_id(block_id_));
            if (client_.empty()) {
              td::actor::send_closure(overlays_, &overlay::Overlays::send_query_via, download_from_, local_id_,
                                      overlay_id_, "download state", std::move(P), td::Timestamp::in(3.0),
                                      std::move(query), FullNode::max_zerostate_size(), rldp_);
            } else {
              td::actor::send_closure(client_, &adnl::AdnlExtClient::send_query, "download state",
                                      create_serialize_tl_object_suffix<tos_api::tosNode_query>(std::move(query)),
                                      td::Timestamp::in(3.0), std::move(P));
            }
            status_.set_status(PSTRING() << block_id_.id.to_str() << " : download started");
          }));
}

void DownloadState::got_state_size(td::BufferSlice size_or_not_found) {
  auto F = fetch_tl_object<tos_api::tosNode_PersistentStateSize>(std::move(size_or_not_found), true);
  if (F.is_error()) {
    abort_query(F.move_as_error());
    return;
  }
  prev_logged_timer_ = td::Timer();

  tos_api::downcast_call(*F.move_as_ok().get(),
                         td::overloaded(
                             [&](tos_api::tosNode_persistentStateSizeNotFound &f) {
                               abort_query(td::Status::Error(ErrorCode::notready, "state not found"));
                             },
                             [&](tos_api::tosNode_persistentStateSize &f) {
                               auto status = prepare_download_buffer(f.size_);
                               if (status.is_error()) {
                                 abort_query(std::move(status));
                                 return;
                               }
                               got_block_state_part(td::BufferSlice{}, 0);
                             }));
}

void DownloadState::request_total_size() {
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::BufferSlice> R) {
    if (R.is_error()) {
      td::actor::send_closure(SelfId, &DownloadState::abort_query, R.move_as_error());
      return;
    }
    auto res = fetch_tl_object<tos_api::tosNode_persistentStateSize>(R.move_as_ok(), true);
    if (res.is_error()) {
      td::actor::send_closure(SelfId, &DownloadState::abort_query, res.move_as_error());
      return;
    }
    td::actor::send_closure(SelfId, &DownloadState::got_total_size, res.ok()->size_);
  });

  td::BufferSlice query = create_serialize_tl_object<tos_api::tosNode_getPersistentStateSizeV2>(
      create_tl_object<tos_api::tosNode_persistentStateIdV2>(
          create_tl_block_id(block_id_), create_tl_block_id(masterchain_block_id_), effective_shard_));
  if (client_.empty()) {
    td::actor::send_closure(overlays_, &overlay::Overlays::send_query_via, download_from_, local_id_, overlay_id_,
                            "get size", std::move(P), td::Timestamp::in(3.0), std::move(query), 1024, rldp_);
  } else {
    td::actor::send_closure(client_, &adnl::AdnlExtClient::send_query, "get size",
                            create_serialize_tl_object_suffix<tos_api::tosNode_query>(std::move(query)),
                            td::Timestamp::in(3.0), std::move(P));
  }
}

void DownloadState::got_total_size(td::uint64 size) {
  auto status = prepare_download_buffer(size);
  if (status.is_error()) {
    abort_query(std::move(status));
    return;
  }
  if (!download_started_) {
    got_block_state_part(td::BufferSlice{}, 0);
  }
}

void DownloadState::got_block_state_part(td::BufferSlice data, td::uint32 requested_size) {
  if (total_size_ == 0) {
    abort_query(td::Status::Error(ErrorCode::protoviolation,
                                  "persistent state size is not known"));
    return;
  }
  download_started_ = true;

  if (requested_size != 0 && data.size() > requested_size) {
    abort_query(td::Status::Error(ErrorCode::protoviolation,
                                  PSTRING() << "persistent state part too large: "
                                            << data.size() << " > " << requested_size));
    return;
  }
  if (data.size() > total_size_ || sum_ > total_size_ - data.size()) {
    abort_query(td::Status::Error(ErrorCode::protoviolation,
                                  "persistent state stream exceeds advertised size"));
    return;
  }
  if (data.size() > persistent_state_max_file_bytes() ||
      sum_ > persistent_state_max_file_bytes() - data.size()) {
    abort_query(td::Status::Error(ErrorCode::protoviolation,
                                  "persistent state stream exceeds local size limit"));
    return;
  }

  bool short_part = requested_size != 0 && data.size() < requested_size;
  if (data.size() != 0) {
    if (mode_ == StorageMode::Heap) {
      auto dst = state_.as_slice();
      dst.remove_prefix(td::narrow_cast<std::size_t>(sum_));
      dst.copy_from(data.as_slice());
    } else {
      auto write_status = write_chunk_to_tempfile(data.as_slice());
      if (write_status.is_error()) {
        abort_query(std::move(write_status));
        return;
      }
    }
  }
  // Defense in depth: data.size() is bounded by total_size_ - sum_ above,
  // so the add never overflows. Re-check explicitly.
  if (data.size() > std::numeric_limits<td::uint64>::max() - sum_) {
    abort_query(td::Status::Error("byte counter overflow"));
    return;
  }
  sum_ += data.size();

  double elapsed = prev_logged_timer_.elapsed();
  if (elapsed > 5.0) {
    prev_logged_timer_ = td::Timer();
    auto speed = (td::uint64)((double)(sum_ - prev_logged_sum_) / elapsed);
    td::StringBuilder sb;
    sb << td::format::as_size(sum_);
    if (total_size_) {
      sb << "/" << td::format::as_size(total_size_);
    }
    sb << " (" << td::format::as_size(speed) << "/s";
    if (total_size_) {
      sb << ", " << td::StringBuilder::FixedDouble((double)sum_ / (double)total_size_ * 100.0, 2) << "%";
      if (speed > 0 && total_size_ >= sum_) {
        td::uint64 rem = (total_size_ - sum_) / speed;
        sb << ", " << rem << "s remaining";
      }
    }
    sb << ")";
    LOG(WARNING) << "downloading state " << block_id_.to_str() << " : " << sb.as_cslice();
    status_.set_status(PSTRING() << block_id_.id.to_str() << " : " << sb.as_cslice());
    prev_logged_sum_ = sum_;
  }

  if (short_part && sum_ != total_size_) {
    abort_query(td::Status::Error(ErrorCode::protoviolation,
                                  "persistent state stream ended before advertised size"));
    return;
  }

  if (sum_ == total_size_) {
    status_.set_status(PSTRING() << block_id_.id.to_str() << " : " << sum_ << " bytes, finishing");
    if (mode_ == StorageMode::Heap) {
      got_block_state(std::move(state_));
    } else {
      LOG(WARNING) << "finished downloading state " << block_id_.to_str() << ": "
                   << td::format::as_size(sum_) << " (file)";
      finish_query();
    }
    return;
  }

  td::uint32 part_size = static_cast<td::uint32>(
      std::min<td::uint64>(kPersistentStatePartSize, total_size_ - sum_));
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), part_size](td::Result<td::BufferSlice> R) {
    if (R.is_error()) {
      td::actor::send_closure(SelfId, &DownloadState::abort_query, R.move_as_error());
    } else {
      td::actor::send_closure(SelfId, &DownloadState::got_block_state_part, R.move_as_ok(), part_size);
    }
  });

  td::BufferSlice query = create_serialize_tl_object<tos_api::tosNode_downloadPersistentStateSliceV2>(
      create_tl_object<tos_api::tosNode_persistentStateIdV2>(
          create_tl_block_id(block_id_), create_tl_block_id(masterchain_block_id_), effective_shard_),
      sum_, part_size);
  if (client_.empty()) {
    td::actor::send_closure(overlays_, &overlay::Overlays::send_query_via, download_from_, local_id_, overlay_id_,
                            "download state", std::move(P), td::Timestamp::in(20.0), std::move(query), part_size + 1024,
                            rldp_);
  } else {
    td::actor::send_closure(client_, &adnl::AdnlExtClient::send_query, "download state",
                            create_serialize_tl_object_suffix<tos_api::tosNode_query>(std::move(query)),
                            td::Timestamp::in(20.0), std::move(P));
  }
}

void DownloadState::got_block_state(td::BufferSlice data) {
  // Monolithic delivery path used by zero-state and the local DB
  // short-circuit. Data arrives in one chunk, no total_size announced.
  // Use heap mode unconditionally here.
  if (data.size() > persistent_state_max_file_bytes()) {
    abort_query(td::Status::Error(ErrorCode::protoviolation,
                                  PSTRING() << "monolithic state too large: " << data.size() << " > "
                                            << persistent_state_max_file_bytes()));
    return;
  }
  if (!reservation_) {
    if (!try_reserve_persistent_state_download_memory(data.size())) {
      abort_query(td::Status::Error("download budget exceeded for monolithic state"));
      return;
    }
    try {
      reservation_ = std::make_shared<PersistentStateDownloadReservation>(data.size());
    } catch (...) {
      PersistentStateDownloadReservation rollback{data.size()};
      (void)rollback;
      abort_query(td::Status::Error("cannot allocate reservation for monolithic state"));
      return;
    }
    mode_ = StorageMode::Heap;
    total_size_ = data.size();
    sum_ = data.size();
  }
  state_ = std::move(data);
  LOG(WARNING) << "finished downloading state " << block_id_.to_str() << ": " << td::format::as_size(state_.size());
  finish_query();
}

}  // namespace fullnode

}  // namespace validator

}  // namespace tos
