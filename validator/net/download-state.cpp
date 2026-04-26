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
#include "tos/tos-io.hpp"
#include "tos/tos-tl.hpp"

#include "download-state.hpp"
#include "full-node.h"

#include <algorithm>
#include <atomic>

namespace tos {

namespace validator {

namespace fullnode {

namespace {

constexpr td::uint64 kPersistentStatePartSize = 1ULL << 21;
constexpr td::uint64 kMaxPersistentStateDownloadBytes = 1ULL << 30;
constexpr td::uint64 kMaxPersistentStateHeapBufferBytes = 256ULL << 20;
constexpr td::uint64 kMaxTotalPersistentStateDownloadBytes = 512ULL << 20;

std::atomic<td::uint64> g_persistent_state_download_bytes{0};

td::Status validate_persistent_state_size(td::uint64 size) {
  if (size == 0) {
    return td::Status::Error(ErrorCode::protoviolation, "persistent state has zero size");
  }
  if (size > kMaxPersistentStateDownloadBytes) {
    return td::Status::Error(ErrorCode::protoviolation,
                             PSTRING() << "persistent state too large: " << size << " > "
                                       << kMaxPersistentStateDownloadBytes);
  }
  if (size > kMaxPersistentStateHeapBufferBytes) {
    return td::Status::Error(ErrorCode::notready,
                             PSTRING() << "persistent state too large for heap downloader: " << size << " > "
                                       << kMaxPersistentStateHeapBufferBytes
                                       << " (streaming persistent-state downloader required)");
  }
  return td::Status::OK();
}

bool try_reserve_persistent_state_download_memory(td::uint64 size) {
  auto current = g_persistent_state_download_bytes.load(std::memory_order_relaxed);
  for (;;) {
    if (size > kMaxTotalPersistentStateDownloadBytes ||
        current > kMaxTotalPersistentStateDownloadBytes - size) {
      return false;
    }
    if (g_persistent_state_download_bytes.compare_exchange_weak(
            current, current + size, std::memory_order_acq_rel, std::memory_order_relaxed)) {
      return true;
    }
  }
}

void release_persistent_state_download_memory(td::uint64 size) {
  if (size == 0) {
    return;
  }
  auto previous = g_persistent_state_download_bytes.fetch_sub(size, std::memory_order_acq_rel);
  CHECK(previous >= size);
}

}  // namespace

DownloadState::DownloadState(BlockIdExt block_id, BlockIdExt masterchain_block_id, PersistentStateType type,
                             adnl::AdnlNodeIdShort local_id, overlay::OverlayIdShort overlay_id,
                             adnl::AdnlNodeIdShort download_from, td::uint32 priority, td::Timestamp timeout,
                             td::actor::ActorId<ValidatorManagerInterface> validator_manager,
                             td::actor::ActorId<adnl::AdnlSenderInterface> rldp,
                             td::actor::ActorId<overlay::Overlays> overlays, td::actor::ActorId<adnl::Adnl> adnl,
                             td::actor::ActorId<adnl::AdnlExtClient> client, td::Promise<td::BufferSlice> promise)
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

void DownloadState::abort_query(td::Status reason) {
  release_download_memory();
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
  if (promise_) {
    promise_.set_value(std::move(state_));
  }
  release_download_memory();
  stop();
}

void DownloadState::release_download_memory() {
  release_persistent_state_download_memory(reserved_download_bytes_);
  reserved_download_bytes_ = 0;
}

td::Status DownloadState::prepare_download_buffer(td::uint64 size) {
  auto status = validate_persistent_state_size(size);
  if (status.is_error()) {
    return status;
  }
  if (reserved_download_bytes_ != 0) {
    return td::Status::Error(ErrorCode::protoviolation,
                             "persistent state download size announced twice");
  }
  if (!try_reserve_persistent_state_download_memory(size)) {
    return td::Status::Error(ErrorCode::notready,
                             PSTRING() << "persistent state download memory budget exceeded: "
                                       << size << " requested, "
                                       << kMaxTotalPersistentStateDownloadBytes << " total budget");
  }
  reserved_download_bytes_ = size;
  total_size_ = size;
  try {
    state_ = td::BufferSlice{td::narrow_cast<std::size_t>(total_size_)};
  } catch (...) {
    release_download_memory();
    total_size_ = 0;
    return td::Status::Error(ErrorCode::notready,
                             "cannot allocate persistent state download buffer");
  }
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
  if (data.size() > kMaxPersistentStateDownloadBytes ||
      sum_ > kMaxPersistentStateDownloadBytes - data.size()) {
    abort_query(td::Status::Error(ErrorCode::protoviolation,
                                  "persistent state stream exceeds local size limit"));
    return;
  }

  bool short_part = requested_size != 0 && data.size() < requested_size;
  if (data.size() != 0) {
    auto dst = state_.as_slice();
    dst.remove_prefix(td::narrow_cast<std::size_t>(sum_));
    dst.copy_from(data.as_slice());
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
    got_block_state(std::move(state_));
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
  state_ = std::move(data);
  LOG(WARNING) << "finished downloading state " << block_id_.to_str() << ": " << td::format::as_size(state_.size());
  finish_query();
}

}  // namespace fullnode

}  // namespace validator

}  // namespace tos
