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
#include "common/checksum.h"
#include "common/delay.h"
#include "crypto/block/block-auto.h"
#include "crypto/block/block-parse.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/path.h"
#include "tos/tos-io.hpp"
#include "validator/fabric.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"

#include "download-state.hpp"

#include <functional>
#include <utility>

namespace tos {

namespace validator {

// Stream the contents of a tempfile into the destination FileFd that
// the archive manager handed us via store_persistent_state_file_gen or
// store_zero_state_file_gen. 1 MiB pread/write loop bounds peak resident
// memory by the chunk size, regardless of the underlying state size. No
// BufferSlice of size == state size is ever allocated.
// OnDisk parse pipeline factored out of DownloadShardState::downloaded_shard_state
// so the same code path can be exercised from a regression test that
// constructs a corrupted tempfile and asserts that each layer of
// defense (BoC deserializer, root-hash compare) catches the corruption.
//
// Returns the deserialized cell tree on success. Any failure is
// surfaced as a descriptive Status::Error: BoC failures propagate the
// vm::std_boc_deserialize message, root-hash mismatches return the
// hex-encoded expected and observed hashes so an audit log can
// distinguish "BoC structurally valid but wrong content" from "BoC
// trailer corrupt".
//
// The helper does NOT call validate_deep(): the BoC deserializer plus
// the explicit root-hash compare against `expected_root_hash` is the
// same invariant validate_deep() enforces, so a second pass is
// structurally redundant. The regression test
// (test_h02_ondisk_corrupt_tempfile_rejected_by_boc_or_root_hash)
// pins this claim by feeding three corruption variants to this
// function and asserting all three are rejected here.
td::Result<td::Ref<vm::Cell>> parse_ondisk_state_for_test(fullnode::BudgetedStateFile &file,
                                                          const RootHash &expected_root_hash) {
  if (file.path.empty() || file.size == 0) {
    return td::Status::Error("parse_ondisk_state_for_test: empty BudgetedStateFile");
  }
  // Layer 1: mmap the tempfile. mmap_persistent_state_file already
  // validates the on-disk size against the announced size, so a
  // truncated or padded tempfile is rejected here before any parsing.
  TRY_RESULT(mapped, fullnode::mmap_persistent_state_file(file));
  // Layer 2: BoC deserialize. We deliberately keep the slice-based
  // deserialize here instead of the streaming-from-file variant: the
  // helper exists so corruption-rejection tests can drive the same
  // BoC layer + root-hash compare end-to-end without standing up the
  // streaming importer's per-cell persist callback. A flipped byte
  // anywhere in the BoC payload either fails CRC32C validation or
  // produces a different root hash than `expected_root_hash`.
  TRY_RESULT(root, vm::std_boc_deserialize(mapped));
  if (root.is_null()) {
    return td::Status::Error("parse_ondisk_state_for_test: BoC deserialize returned null root");
  }
  // Layer 3: root-hash compare against the BFT-attested expected root.
  // The BoC may deserialize cleanly into a structurally valid cell
  // tree whose root nonetheless does not match the block handle's
  // attested root_hash — that is the case the test exercises by
  // mutating cell content while keeping the BoC envelope intact.
  if (RootHash{root->get_hash().bits()} != expected_root_hash) {
    return td::Status::Error(PSTRING() << "parse_ondisk_state_for_test: root hash mismatch: expected "
                                       << expected_root_hash.to_hex() << " got "
                                       << RootHash{root->get_hash().bits()}.to_hex());
  }
  return root;
}

// Streaming variant of the OnDisk parse path: opens `file` for read,
// runs the bounded BoC importer, and verifies the root hash against
// the BFT-attested `expected_root_hash`. Peak resident memory is
// bounded by `opts.max_resident_bytes` regardless of the on-disk file
// size — the on-disk parse path is no longer constrained by the legacy
// 512 MiB processing cap.
//
// The `persist_cell` callback is invoked once per unique cell as the
// importer completes its deserialization. The DownloadShardState actor
// supplies an empty callback today: cells are persisted as a side
// effect of the downstream archive store / set_block_state path. A
// future refactor that lands the cells directly into the cell DB can
// pass a real callback here without changing the streaming contract.
td::Result<td::Ref<vm::Cell>> parse_ondisk_state_streaming(fullnode::BudgetedStateFile &file,
                                                           const RootHash &expected_root_hash,
                                                           td::uint64 max_resident_bytes,
                                                           vm::StreamingPersistCellFn persist_cell) {
  if (file.path.empty() || file.size == 0) {
    return td::Status::Error("parse_ondisk_state_streaming: empty BudgetedStateFile");
  }
  TRY_RESULT(fd, td::FileFd::open(file.path, td::FileFd::Flags::Read));
  vm::StreamingBocImportOptions opts;
  if (max_resident_bytes > 0) {
    opts.max_resident_bytes = max_resident_bytes;
  }
  TRY_RESULT(root, vm::std_boc_deserialize_from_file_bounded(fd, file.size, opts, std::move(persist_cell)));
  fd.close();
  if (root.is_null()) {
    return td::Status::Error("parse_ondisk_state_streaming: BoC deserialize returned null root");
  }
  if (RootHash{root->get_hash().bits()} != expected_root_hash) {
    return td::Status::Error(PSTRING() << "parse_ondisk_state_streaming: root hash mismatch: expected "
                                       << expected_root_hash.to_hex() << " got "
                                       << RootHash{root->get_hash().bits()}.to_hex());
  }
  return root;
}

td::Result<td::Ref<vm::Cell>> parse_ondisk_state_streaming(fullnode::BudgetedStateFile &file,
                                                           const RootHash &expected_root_hash,
                                                           td::uint64 max_resident_bytes,
                                                           vm::StreamingCellSink *sink) {
  if (file.path.empty() || file.size == 0) {
    return td::Status::Error("parse_ondisk_state_streaming: empty BudgetedStateFile");
  }
  TRY_RESULT(fd, td::FileFd::open(file.path, td::FileFd::Flags::Read));
  vm::StreamingBocImportOptions opts;
  if (max_resident_bytes > 0) {
    opts.max_resident_bytes = max_resident_bytes;
  }
  TRY_RESULT(root, vm::std_boc_deserialize_from_file_bounded(fd, file.size, opts, sink));
  fd.close();
  if (root.is_null()) {
    return td::Status::Error("parse_ondisk_state_streaming: BoC deserialize returned null root");
  }
  if (RootHash{root->get_hash().bits()} != expected_root_hash) {
    return td::Status::Error(PSTRING() << "parse_ondisk_state_streaming: root hash mismatch: expected "
                                       << expected_root_hash.to_hex() << " got "
                                       << RootHash{root->get_hash().bits()}.to_hex());
  }
  return root;
}

// H-02 / H-03 full-options overload. Lets the caller forward every
// `vm::StreamingBocImportOptions` field (max_resident_bytes,
// max_cells, max_scaffolding_bytes, max_total_cell_bytes,
// max_roots) verbatim. Used by the actor wiring so a single budget
// configuration object drives every BoC import in the persistent-state
// path.
td::Result<td::Ref<vm::Cell>> parse_ondisk_state_streaming(fullnode::BudgetedStateFile &file,
                                                           const RootHash &expected_root_hash,
                                                           const vm::StreamingBocImportOptions &opts,
                                                           vm::StreamingCellSink *sink) {
  if (file.path.empty() || file.size == 0) {
    return td::Status::Error("parse_ondisk_state_streaming: empty BudgetedStateFile");
  }
  TRY_RESULT(fd, td::FileFd::open(file.path, td::FileFd::Flags::Read));
  TRY_RESULT(root, vm::std_boc_deserialize_from_file_bounded(fd, file.size, opts, sink));
  fd.close();
  if (root.is_null()) {
    return td::Status::Error("parse_ondisk_state_streaming: BoC deserialize returned null root");
  }
  if (RootHash{root->get_hash().bits()} != expected_root_hash) {
    return td::Status::Error(PSTRING() << "parse_ondisk_state_streaming: root hash mismatch: expected "
                                       << expected_root_hash.to_hex() << " got "
                                       << RootHash{root->get_hash().bits()}.to_hex());
  }
  return root;
}

td::Status copy_tempfile_to_writer(const std::string &src_path, td::uint64 size, td::FileFd &dst) {
  TRY_RESULT(src_fd, td::FileFd::open(src_path, td::FileFd::Read));
  constexpr td::uint64 kChunkBytes = 1ULL << 20;  // 1 MiB
  td::BufferSlice scratch{td::narrow_cast<std::size_t>(kChunkBytes)};
  td::uint64 copied = 0;
  while (copied < size) {
    auto remaining = size - copied;
    auto want = remaining < kChunkBytes ? remaining : kChunkBytes;
    auto chunk = scratch.as_slice();
    chunk.truncate(td::narrow_cast<std::size_t>(want));
    auto r_n = src_fd.pread(chunk, static_cast<td::int64>(copied));
    if (r_n.is_error()) {
      return r_n.move_as_error();
    }
    auto n = r_n.move_as_ok();
    if (n == 0) {
      return td::Status::Error("short read while copying persistent state tempfile");
    }
    if (n > want) {
      return td::Status::Error("read past expected length while copying persistent state tempfile");
    }
    auto chunk_to_write = scratch.as_slice();
    chunk_to_write.truncate(n);
    auto r_w = dst.write(chunk_to_write);
    if (r_w.is_error()) {
      return r_w.move_as_error();
    }
    if (r_w.ok() != n) {
      return td::Status::Error(PSTRING() << "short write while copying persistent state tempfile: "
                                         << r_w.ok() << " of " << n);
    }
    copied += n;
  }
  return td::Status::OK();
}

class SplitStateDeserializer {
 public:
  td::Result<std::vector<SplitStatePart>> get_effective_shards_from_header(ShardId shard_id, RootHash root_hash,
                                                                           td::Ref<vm::Cell> wrapped_header,
                                                                           td::uint32 split_depth) {
    int shard_prefix_length = shard_pfx_len(shard_id);
    CHECK(split_depth <= 63 && shard_prefix_length < static_cast<int>(split_depth));

    try {
      TRY_RESULT(header, vm::MerkleProof::virtualize(wrapped_header));

      if (RootHash{header->get_hash().bits()} != root_hash) {
        return td::Status::Error("Hash mismatch in split state header");
      }

      auto shard_state_cs = vm::load_cell_slice(header);
      bool rc = block::gen::t_ShardStateUnsplit.unpack(shard_state_cs, shard_state_);
      if (!rc) {
        return td::Status::Error("Cannot deserialize ShardStateUnsplit");
      }

      vm::AugmentedDictionary accounts{
          vm::load_cell_slice_ref(shard_state_.accounts),
          256,
          block::tlb::aug_ShardAccounts,
          false,
      };

      std::vector<SplitStatePart> parts;

      // The following loop is the same as in state-serializer.cpp.
      ShardId effective_shard = shard_id ^ (1ULL << (63 - shard_prefix_length)) ^ (1ULL << (63 - split_depth));
      ShardId increment = 1ULL << (64 - split_depth);

      for (int i = 0; i < (1 << (split_depth - shard_prefix_length)); ++i, effective_shard += increment) {
        td::BitArray<64> prefix;
        prefix.store_ulong(effective_shard);
        auto account_dict_part = accounts;
        account_dict_part.cut_prefix_subdict(prefix.bits(), split_depth);

        if (!account_dict_part.is_empty()) {
          parts.push_back({effective_shard, account_dict_part.get_wrapped_dict_root()->get_hash()});
        }
      }

      // Now check that header does not contain pruned cells outside of accounts dict. For that, we
      // just replace account dict with an empty cell and see if header remains virtualized or not.
      shard_state_.accounts = vm::DataCell::create("", 0, {}, false).move_as_ok();

      vm::CellBuilder cb;
      block::gen::t_ShardStateUnsplit.pack(cb, shard_state_);
      if (cb.finalize()->is_virtualized()) {
        return td::Status::Error("State headers is pruned outside of account dict");
      }

      return parts;
    } catch (const vm::VmError &e) {
      return e.as_status();
    } catch (const vm::VmVirtError &) {
      return td::Status::Error("Insufficient number of cells in split state header");
    }
  }

  td::Ref<vm::Cell> merge(const std::vector<td::Ref<vm::Cell>> &parts) {
    try {
      vm::AugmentedDictionary accounts{256, block::tlb::aug_ShardAccounts};
      for (const auto &part_root : parts) {
        vm::AugmentedDictionary part{
            vm::load_cell_slice_ref(part_root),
            256,
            block::tlb::aug_ShardAccounts,
            false,
        };
        bool rc = accounts.combine_with(part);
        LOG_CHECK(rc) << "Split state parts have been validated but merging them still resulted in a conflict";
      }

      CHECK(accounts.is_valid());

      shard_state_.accounts = accounts.get_wrapped_dict_root();

      vm::CellBuilder cb;
      block::gen::t_ShardStateUnsplit.pack(cb, shard_state_);
      auto state_root = cb.finalize();
      CHECK(!state_root->is_virtualized());
      return state_root;
    } catch (const vm::VmError &e) {
      LOG(FATAL) << "Unexpected VmError: " << e.as_status();
    } catch (const vm::VmVirtError &) {
      LOG(FATAL) << "Unexpected VmVirtError";
    }
    UNREACHABLE();
  }

 private:
  block::gen::ShardStateUnsplit::Record shard_state_;
};

DownloadShardState::DownloadShardState(BlockIdExt block_id, BlockIdExt masterchain_block_id, td::uint32 split_depth,
                                       td::uint32 priority, td::actor::ActorId<ValidatorManager> manager,
                                       td::Timestamp timeout, td::Promise<td::Ref<ShardState>> promise)
    : block_id_(block_id)
    , masterchain_block_id_(masterchain_block_id)
    , split_depth_(split_depth)
    , priority_(priority)
    , manager_(manager)
    , timeout_(timeout)
    , promise_(std::move(promise)) {
  CHECK(masterchain_block_id_.is_valid() || split_depth_ == 0);

  int shard_prefix_length = shard_pfx_len(block_id_.shard_full().shard);
  if (shard_prefix_length >= static_cast<int>(split_depth_)) {
    split_depth_ = 0;
  }

  LOG(INFO) << "requested to download state of " << block_id.to_str() << " referenced by "
            << masterchain_block_id.to_str() << " with split depth " << split_depth;
}

DownloadShardState::~DownloadShardState() = default;

void DownloadShardState::start_up() {
  status_ = ProcessStatus(manager_, "process.download_state");
  alarm_timestamp() = timeout_;

  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<BlockHandle> R) {
    R.ensure();
    td::actor::send_closure(SelfId, &DownloadShardState::got_block_handle, R.move_as_ok());
  });
  td::actor::send_closure(manager_, &ValidatorManager::get_block_handle, block_id_, true, std::move(P));
}

void DownloadShardState::got_block_handle(BlockHandle handle) {
  handle_ = std::move(handle);

  if (handle_->received_state()) {
    LOG(WARNING) << "shard state " << block_id_.to_str() << " already stored in db";
    td::actor::send_closure(manager_, &ValidatorManagerInterface::get_shard_state_from_db, handle_,
                            [SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
                              R.ensure();
                              td::actor::send_closure(SelfId, &DownloadShardState::written_shard_state, R.move_as_ok());
                            });
  } else {
    download_state();
  }
}

void DownloadShardState::retry() {
  deserializer_ = {};
  parts_.clear();
  download_state();
}

void DownloadShardState::download_state() {
  if (handle_->id().seqno() == 0 || handle_->inited_proof() || handle_->inited_proof_link()) {
    checked_proof_link();
    return;
  }
  status_.set_status(PSTRING() << block_id_.id.to_str() << " : downloading proof");

  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), block_id = block_id_](td::Result<td::BufferSlice> R) {
    if (R.is_error()) {
      LOG(DEBUG) << "Cannot get proof link from import: " << R.move_as_error();
      td::actor::send_closure(SelfId, &DownloadShardState::download_proof_link);
    } else {
      LOG(INFO) << "Got proof link for " << block_id.to_str() << " from import";
      td::actor::send_closure(SelfId, &DownloadShardState::downloaded_proof_link, R.move_as_ok());
    }
  });
  td::actor::send_closure(manager_, &ValidatorManager::get_block_proof_link_from_import, block_id_,
                          masterchain_block_id_, std::move(P));
}

void DownloadShardState::download_proof_link() {
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::BufferSlice> R) {
    if (R.is_error()) {
      fail_handler(SelfId, R.move_as_error());
    } else {
      td::actor::send_closure(SelfId, &DownloadShardState::downloaded_proof_link, R.move_as_ok());
    }
  });
  td::actor::send_closure(manager_, &ValidatorManager::send_get_block_proof_link_request, block_id_, priority_,
                          std::move(P));
}

void DownloadShardState::downloaded_proof_link(td::BufferSlice data) {
  auto pp = create_proof_link(block_id_, std::move(data));
  if (pp.is_error()) {
    fail_handler(actor_id(this), pp.move_as_error());
    return;
  }

  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<BlockHandle> R) {
    if (R.is_error()) {
      fail_handler(SelfId, R.move_as_error());
    } else {
      td::actor::send_closure(SelfId, &DownloadShardState::checked_proof_link);
    }
  });
  run_check_proof_link_query(block_id_, pp.move_as_ok(), manager_, td::Timestamp::in(60.0), std::move(P));
}

void DownloadShardState::checked_proof_link() {
  if (block_id_.seqno() == 0) {
    // try_get_static_file returns a plain BufferSlice (no download budget
    // is involved — it is read straight from disk). Wrap it as a
    // DownloadedPersistentState::memory with a null reservation so
    // downstream paths share the same handler signature.
    auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::BufferSlice> R) {
      if (R.is_error()) {
        td::actor::send_closure(SelfId, &DownloadShardState::download_zero_state);
      } else {
        td::actor::send_closure(SelfId, &DownloadShardState::downloaded_zero_state,
                                fullnode::DownloadedPersistentState::memory(
                                    fullnode::BudgetedBufferSlice{R.move_as_ok(), {}}));
      }
    });
    td::actor::send_closure(manager_, &ValidatorManager::try_get_static_file, block_id_.file_hash, std::move(P));
    status_.set_status(PSTRING() << block_id_.id.to_str() << " : downloading zero state");
  } else {
    CHECK(masterchain_block_id_.is_valid());
    CHECK(masterchain_block_id_.is_masterchain());

    if (split_depth_ == 0) {
      auto P = td::PromiseCreator::lambda(
          [SelfId = actor_id(this)](td::Result<fullnode::DownloadedPersistentState> R) {
            if (R.is_error()) {
              fail_handler(SelfId, R.move_as_error());
            } else {
              td::actor::send_closure(SelfId, &DownloadShardState::downloaded_shard_state, R.move_as_ok());
            }
          });
      td::actor::send_closure(manager_, &ValidatorManager::send_get_persistent_state_request, block_id_,
                              masterchain_block_id_, UnsplitStateType{}, priority_, std::move(P));
      status_.set_status(PSTRING() << block_id_.id.to_str() << " : downloading state");
    } else {
      auto P = td::PromiseCreator::lambda(
          [SelfId = actor_id(this)](td::Result<fullnode::DownloadedPersistentState> R) {
            if (R.is_error()) {
              fail_handler(SelfId, R.move_as_error());
            } else {
              td::actor::send_closure(SelfId, &DownloadShardState::downloaded_split_state_header, R.move_as_ok());
            }
          });
      td::actor::send_closure(manager_, &ValidatorManager::send_get_persistent_state_request, block_id_,
                              masterchain_block_id_, SplitPersistentStateType{}, priority_, std::move(P));
      status_.set_status(PSTRING() << block_id_.id.to_str() << " : downloading state header");
    }
  }
}

void DownloadShardState::download_zero_state() {
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this)](td::Result<fullnode::DownloadedPersistentState> R) {
        if (R.is_error()) {
          fail_handler(SelfId, R.move_as_error());
        } else {
          td::actor::send_closure(SelfId, &DownloadShardState::downloaded_zero_state, R.move_as_ok());
        }
      });
  td::actor::send_closure(manager_, &ValidatorManager::send_get_zero_state_request, block_id_, priority_, std::move(P));
}

void DownloadShardState::downloaded_zero_state(fullnode::DownloadedPersistentState downloaded) {
  // Two paths:
  //   InMemory: existing flow — hash check + clone-based parse, then
  //             persist via store_zero_state_file (BufferSlice).
  //   OnDisk:   mmap the tempfile, hash-check + deserialize from the
  //             mmap'd Slice (no full-state heap allocation). `data_`
  //             stays empty and `data_file_` retains the tempfile;
  //             checked_shard_state() then routes to
  //             store_zero_state_file_gen with a streaming 1 MiB-chunk
  //             writer so no BufferSlice of state size is ever
  //             allocated, regardless of state size.
  if (downloaded.is_memory()) {
    auto incoming = std::move(downloaded.memory().data);
    auto download_reservation = std::move(downloaded.memory().reservation);
    if (sha256_bits256(incoming.as_slice()) != block_id_.file_hash) {
      fail_handler(actor_id(this), td::Status::Error(ErrorCode::protoviolation, "bad zero state: file hash mismatch"));
      return;
    }
    data_ = std::move(incoming);
    // Hold the reservation in actor state so the global download budget
    // stays charged for as long as data_ is being processed and persisted.
    data_reservation_ = std::move(download_reservation);

    // Reserve a separate processing slice that accounts for the parse clone
    // fed into create_shard_state().
    const auto data_size = data_.size();
    std::shared_ptr<fullnode::PersistentStateProcessingReservation> processing_reservation;
    if (data_size > 0) {
      if (!fullnode::try_reserve_persistent_state_processing_memory(data_size)) {
        data_ = td::BufferSlice{};
        data_reservation_.reset();
        fail_handler(actor_id(this),
                     td::Status::Error(ErrorCode::notready,
                                       "persistent state processing memory budget exceeded"));
        return;
      }
      try {
        processing_reservation = std::make_shared<fullnode::PersistentStateProcessingReservation>(data_size);
      } catch (...) {
        fullnode::PersistentStateProcessingReservation rollback{data_size};
        (void)rollback;
        data_ = td::BufferSlice{};
        data_reservation_.reset();
        fail_handler(actor_id(this),
                     td::Status::Error(ErrorCode::notready,
                                       "cannot allocate processing reservation"));
        return;
      }
    }

    auto S = create_shard_state(block_id_, data_.clone());
    processing_reservation.reset();
    S.ensure();
    state_ = S.move_as_ok();

    CHECK(state_->root_hash() == block_id_.root_hash);
    checked_shard_state();
    return;
  }

  // OnDisk parse path for zero state.
  data_file_ = std::move(downloaded.file());
  data_reservation_ = data_file_.reservation;

  auto r_slice = fullnode::mmap_persistent_state_file(data_file_);
  if (r_slice.is_error()) {
    data_file_ = fullnode::BudgetedStateFile{};
    data_reservation_.reset();
    fail_handler(actor_id(this), r_slice.move_as_error());
    return;
  }
  td::Slice mapped = r_slice.move_as_ok();

  if (sha256_bits256(mapped) != block_id_.file_hash) {
    data_file_ = fullnode::BudgetedStateFile{};
    data_reservation_.reset();
    fail_handler(actor_id(this), td::Status::Error(ErrorCode::protoviolation, "bad zero state: file hash mismatch"));
    return;
  }

  // Reserve a processing slice covering the mmap view; matches the
  // InMemory accounting so the global processing counter is consistent
  // across both paths.
  std::shared_ptr<fullnode::PersistentStateProcessingReservation> processing_reservation;
  if (mapped.size() > 0) {
    if (!fullnode::try_reserve_persistent_state_processing_memory(mapped.size())) {
      data_file_ = fullnode::BudgetedStateFile{};
      data_reservation_.reset();
      fail_handler(actor_id(this),
                   td::Status::Error(ErrorCode::notready,
                                     "persistent state processing memory budget exceeded for OnDisk zero-state"));
      return;
    }
    try {
      processing_reservation =
          std::make_shared<fullnode::PersistentStateProcessingReservation>(mapped.size());
    } catch (...) {
      fullnode::PersistentStateProcessingReservation rollback{mapped.size()};
      (void)rollback;
      data_file_ = fullnode::BudgetedStateFile{};
      data_reservation_.reset();
      fail_handler(actor_id(this),
                   td::Status::Error(ErrorCode::notready,
                                     "cannot allocate processing reservation for OnDisk zero-state"));
      return;
    }
  }

  auto r_root = vm::std_boc_deserialize(mapped);
  processing_reservation.reset();
  if (r_root.is_error()) {
    data_file_ = fullnode::BudgetedStateFile{};
    data_reservation_.reset();
    fail_handler(actor_id(this), r_root.move_as_error());
    return;
  }
  auto root = r_root.move_as_ok();
  auto S = create_shard_state(block_id_, std::move(root));
  S.ensure();
  state_ = S.move_as_ok();
  CHECK(state_->root_hash() == block_id_.root_hash);

  // data_ stays empty; data_file_ carries the tempfile through to
  // checked_shard_state(), which routes the OnDisk branch through
  // store_zero_state_file_gen with a streaming writer. No BufferSlice
  // of state size is ever allocated.
  checked_shard_state();
}

void DownloadShardState::downloaded_shard_state(fullnode::DownloadedPersistentState downloaded) {
  status_.set_status(PSTRING() << block_id_.id.to_str() << " : processing downloaded state");

  // Two parse paths, sharing the same downstream `state_` / `data_` /
  // `data_reservation_` invariants:
  //
  //   InMemory: hand off the BufferSlice to the existing
  //             create_shard_state(BlockIdExt, td::BufferSlice) path,
  //             which clones once for the parser. The processing
  //             budget covers that clone.
  //   OnDisk:   mmap the tempfile (zero heap allocation of file size),
  //             vm::std_boc_deserialize() the mmap'd Slice, then call
  //             the create_shard_state(BlockIdExt, td::Ref<vm::Cell>)
  //             overload. No BufferSlice of file size is ever
  //             allocated, satisfying the H-02 invariant.
  if (downloaded.is_memory()) {
    auto incoming = std::move(downloaded.memory().data);
    auto download_reservation = std::move(downloaded.memory().reservation);
    // Move the original buffer (and its download-budget reservation) into
    // actor state up front. Previously this method cloned the buffer
    // twice — once for the parser and once into `data_` — so a 256 MiB
    // advertised state could resident-peak at ~768 MiB (original + parse
    // clone + persist clone). Moving here means peak = original + ONE
    // parse clone, and the parse clone is accounted by the processing
    // budget below.
    data_ = std::move(incoming);
    data_reservation_ = std::move(download_reservation);

    // Reserve a separate processing slice that tracks the single parse
    // clone fed into create_shard_state(). The reservation is local to
    // this method scope: as soon as the parser returns (success OR
    // failure) the cloned BufferSlice has been consumed and the
    // processing budget is released.
    const auto data_size = data_.size();
    std::shared_ptr<fullnode::PersistentStateProcessingReservation> processing_reservation;
    if (data_size > 0) {
      if (!fullnode::try_reserve_persistent_state_processing_memory(data_size)) {
        data_ = td::BufferSlice{};
        data_reservation_.reset();
        fail_handler(actor_id(this),
                     td::Status::Error(ErrorCode::notready,
                                       "persistent state processing memory budget exceeded"));
        return;
      }
      try {
        processing_reservation = std::make_shared<fullnode::PersistentStateProcessingReservation>(data_size);
      } catch (...) {
        // Roll back the global processing counter via a local RAII
        // reservation: its destructor returns the bytes to the global
        // counter exactly once.
        fullnode::PersistentStateProcessingReservation rollback{data_size};
        (void)rollback;
        data_ = td::BufferSlice{};
        data_reservation_.reset();
        fail_handler(actor_id(this),
                     td::Status::Error(ErrorCode::notready,
                                       "cannot allocate processing reservation"));
        return;
      }
    }

    auto S = create_shard_state(block_id_, data_.clone());
    // Release the processing reservation before any branching: regardless
    // of success or error, the parse clone has been consumed by the call
    // above and the bytes should return to the global counter immediately.
    processing_reservation.reset();
    if (S.is_error()) {
      data_ = td::BufferSlice{};
      data_reservation_.reset();
      fail_handler(actor_id(this), S.move_as_error());
      return;
    }
    auto state = S.move_as_ok();
    if (state->root_hash() != handle_->state()) {
      data_ = td::BufferSlice{};
      data_reservation_.reset();
      fail_handler(actor_id(this),
                   td::Status::Error(ErrorCode::protoviolation, "bad persistent state: root hash mismatch"));
      return;
    }
    auto St = state->validate_deep();
    if (St.is_error()) {
      data_ = td::BufferSlice{};
      data_reservation_.reset();
      fail_handler(actor_id(this), St.move_as_error());
      return;
    }
    state_ = std::move(state);
    // data_ and data_reservation_ remain populated: checked_shard_state()
    // will consume them by handing data_ to store_*_state_file and
    // capturing data_reservation_ into the disk-write completion lambda
    // (it covers the on-disk write window).
    checked_shard_state();
    return;
  }

  // OnDisk parse path. The download budget reservation is currently
  // owned by `downloaded.file().reservation`; move the entire
  // BudgetedStateFile into actor state so its lifetime (and the
  // download-budget charge) covers parse + persist. The InMemory
  // counterpart of `data_reservation_` is taken from the same field so
  // the rest of the actor's lifecycle bookkeeping is identical.
  data_file_ = std::move(downloaded.file());
  data_reservation_ = data_file_.reservation;

  // M-01: reserve a processing slice that will be HELD ACROSS the
  // entire parse → create_shard_state → archive store handoff. The
  // legacy code released the reservation right after deserialize
  // returned, but the resident DataCell tree + ShardState object
  // continue to occupy memory through checked_shard_state() and
  // beyond; under-accounting that window is the M-01 hazard.
  //
  // The reservation is bounded by the streaming importer's
  // max_resident_bytes (NOT by the file size): the streaming pass
  // peaks at the dependency-chain depth, not at the full BoC
  // materialization. We charge that smaller number against the
  // processing budget so concurrent imports stack correctly.
  auto budget_cfg = fullnode::persistent_state_budget_config();
  // H-02 short-term cap. The streaming importer still returns the full
  // root cell DAG, so resident bytes for the returned tree can exceed
  // the per-cell residency budget. Charge against the conservative
  // returned-DAG cap (file.size, capped at max_returned_dag_bytes_per_parse)
  // and fail closed when the file is larger than that cap unless the
  // future ExtCell-backed importer is enabled.
  if (data_file_.size > budget_cfg.max_returned_dag_bytes_per_parse &&
      !budget_cfg.enable_true_cell_db_streaming_import) {
    auto rejected_size = data_file_.size;
    data_file_ = fullnode::BudgetedStateFile{};
    data_reservation_.reset();
    fail_handler(
        actor_id(this),
        td::Status::Error(
            ErrorCode::notready,
            PSTRING()
                << "persistent-state download rejected: file size " << rejected_size
                << " exceeds max_returned_dag_bytes_per_parse="
                << budget_cfg.max_returned_dag_bytes_per_parse
                << ". This is a known liveness ceiling pending Phase B (true ExtCell-backed "
                   "CellDb-streaming importer). Operator options: (a) raise "
                   "max_returned_dag_bytes_per_parse if you accept the OOM risk for this state, "
                   "(b) bootstrap from a smaller checkpoint, (c) wait for Phase B which will "
                   "remove this ceiling."));
    return;
  }
  td::uint64 processing_charge = data_file_.size;
  if (processing_charge > budget_cfg.max_returned_dag_bytes_per_parse) {
    processing_charge = budget_cfg.max_returned_dag_bytes_per_parse;
  }
  if (processing_charge > 0) {
    if (!fullnode::try_reserve_persistent_state_processing_memory(processing_charge)) {
      data_file_ = fullnode::BudgetedStateFile{};
      data_reservation_.reset();
      fail_handler(actor_id(this),
                   td::Status::Error(ErrorCode::notready,
                                     "persistent state processing memory budget exceeded for OnDisk parse"));
      return;
    }
    try {
      state_processing_reservation_ =
          std::make_shared<fullnode::PersistentStateProcessingReservation>(processing_charge);
    } catch (...) {
      fullnode::PersistentStateProcessingReservation rollback{processing_charge};
      (void)rollback;
      data_file_ = fullnode::BudgetedStateFile{};
      data_reservation_.reset();
      fail_handler(actor_id(this),
                   td::Status::Error(ErrorCode::notready,
                                     "cannot allocate processing reservation for OnDisk parse"));
      return;
    }
  }

  // H-03: streaming OnDisk parse. Replaces the legacy mmap +
  // vm::std_boc_deserialize one-shot materialization with a chunked
  // pread + per-cell deserialize that bounds peak resident memory at
  // budget_cfg.max_resident_bytes_per_parse. The same root-hash
  // compare against handle_->state() that
  // parse_ondisk_state_for_test() does still runs at the end, so the
  // existing "validate_deep skipped here is OK because BoC + root-hash
  // is the same invariant" reasoning still applies.
  //
  // K3 (this round): wire a real CellDbStreamingSink. The sink runs
  // begin/persist/finish/abort around the importer; today its body is
  // a counting + per-cell-validation pass (defense-in-depth against a
  // null cell or descriptor corruption surfacing late). The
  // downstream checked_shard_state() still routes through
  // store_persistent_state_file (which copies the tempfile into the
  // archive) and set_block_state (which lands the cell tree into the
  // cell DB). True streaming-into-CellDb-without-DAG-residency is a
  // follow-up that requires a deeper refactor of DataCell to use
  // hash-only references for children — out of scope for this commit.
  // The sink interface is the load-bearing extension point that lets
  // that future commit land without changing this actor wiring.
  fullnode::CellDbStreamingSink streaming_sink;
  vm::StreamingBocImportOptions opts;
  opts.max_resident_bytes = budget_cfg.max_resident_bytes_per_parse;
  opts.max_cells = budget_cfg.max_cells_per_parse;
  opts.max_scaffolding_bytes = budget_cfg.max_scaffolding_bytes_per_parse;
  opts.max_total_cell_bytes =
      std::min(data_file_.size, budget_cfg.max_total_cell_bytes_per_parse);
  auto r_root = parse_ondisk_state_streaming(data_file_, handle_->state(), opts, &streaming_sink);
  if (r_root.is_error()) {
    LOG(WARNING) << "OnDisk streaming parse failed for " << block_id_.to_str()
                 << " after " << streaming_sink.cell_count() << " cells: "
                 << r_root.error();
    data_file_ = fullnode::BudgetedStateFile{};
    data_reservation_.reset();
    state_processing_reservation_.reset();
    fail_handler(actor_id(this), r_root.move_as_error());
    return;
  }
  if (!streaming_sink.finished()) {
    // Defense in depth: the importer's contract guarantees finish runs
    // on the success path. If the sink reports otherwise we treat it
    // as a programming bug and fail closed rather than silently
    // committing a half-validated state.
    data_file_ = fullnode::BudgetedStateFile{};
    data_reservation_.reset();
    state_processing_reservation_.reset();
    fail_handler(actor_id(this),
                 td::Status::Error("OnDisk streaming sink finished=false on success path"));
    return;
  }
  LOG(INFO) << "OnDisk streaming parse for " << block_id_.to_str() << " imported "
            << streaming_sink.cell_count() << " cells";
  auto root = r_root.move_as_ok();

  auto S = create_shard_state(block_id_, std::move(root));
  if (S.is_error()) {
    data_file_ = fullnode::BudgetedStateFile{};
    data_reservation_.reset();
    state_processing_reservation_.reset();
    fail_handler(actor_id(this), S.move_as_error());
    return;
  }
  auto state = S.move_as_ok();
  // The root-hash compare above already verified the equivalent of the
  // legacy `state->root_hash() != handle_->state()` check; the
  // create_shard_state() output preserves that hash.
  state_ = std::move(state);

  // data_ stays empty in the OnDisk branch — checked_shard_state()
  // detects this and routes to store_persistent_state_file_gen, which
  // copies the tempfile directly into the archive without ever
  // materializing a BufferSlice of file size. state_processing_reservation_
  // remains charged across this handoff and is released by
  // checked_shard_state() once the archive write completes.
  checked_shard_state();
}

void DownloadShardState::checked_shard_state() {
  status_.set_status(PSTRING() << block_id_.id.to_str() << " : storing state file");
  LOG(WARNING) << "checked shard state " << block_id_.to_str();

  // Three handoff paths:
  //   InMemory:  the actor still holds `data_` (BufferSlice) and the
  //              download-budget reservation. Pass both to
  //              store_persistent_state_file (or store_zero_state_file
  //              for seqno=0) and release the reservation when the disk
  //              write completes.
  //   OnDisk:    `data_` is empty and `data_file_` holds the tempfile.
  //              Use store_persistent_state_file_gen (or
  //              store_zero_state_file_gen for seqno=0) with a callable
  //              that copies the tempfile straight into the archive
  //              FileFd in 1 MiB chunks — no BufferSlice of file size
  //              is allocated. The download reservation rides along in
  //              the completion lambda and is released when the archive
  //              write fsync's.
  if (data_.empty() && !data_file_.path.empty()) {
    auto src_path = data_file_.path;
    auto src_size = data_file_.size;
    auto write_data = [src_path, src_size](td::FileFd &dst) -> td::Status {
      return copy_tempfile_to_writer(src_path, src_size, dst);
    };
    // M-01: pin state_processing_reservation_ into the completion
    // lambda alongside the download-budget reservation so the
    // processing budget stays charged through the archive write.
    // Both reservations are released exactly once when the lambda
    // runs to completion, AFTER the archive store fsync's.
    auto P = td::PromiseCreator::lambda(
        [SelfId = actor_id(this), reservation = std::move(data_reservation_),
         processing_reservation = std::move(state_processing_reservation_),
         file = std::move(data_file_)](td::Result<td::Unit> R) mutable {
          R.ensure();
          // The BudgetedStateFile destructor unmaps + unlinks the
          // tempfile when `file` goes out of scope; both reservations
          // return their bytes to the respective global counters.
          (void)file;
          reservation.reset();
          processing_reservation.reset();
          td::actor::send_closure(SelfId, &DownloadShardState::written_shard_state_file);
        });
    if (block_id_.seqno() == 0) {
      td::actor::send_closure(manager_, &ValidatorManager::store_zero_state_file_gen, block_id_,
                              std::move(write_data), std::move(P));
    } else {
      td::actor::send_closure(manager_, &ValidatorManager::store_persistent_state_file_gen, block_id_,
                              masterchain_block_id_, UnsplitStateType{}, std::move(write_data),
                              std::move(P));
    }
    return;
  }

  // InMemory path: hand the BufferSlice to the existing store API. The
  // reservation rides along in the completion lambda and releases when
  // the disk write is durable. The processing reservation (if held;
  // the InMemory branch may not have taken one) follows the same
  // lifetime.
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), reservation = std::move(data_reservation_),
       processing_reservation = std::move(state_processing_reservation_)](td::Result<td::Unit> R) mutable {
        R.ensure();
        reservation.reset();
        processing_reservation.reset();
        td::actor::send_closure(SelfId, &DownloadShardState::written_shard_state_file);
      });
  if (block_id_.seqno() == 0) {
    td::actor::send_closure(manager_, &ValidatorManager::store_zero_state_file, block_id_, std::move(data_),
                            std::move(P));
  } else {
    td::actor::send_closure(manager_, &ValidatorManager::store_persistent_state_file, block_id_, masterchain_block_id_,
                            UnsplitStateType{}, std::move(data_), std::move(P));
  }
}

void DownloadShardState::downloaded_split_state_header(fullnode::DownloadedPersistentState downloaded) {
  LOG(INFO) << "processing state header";
  status_.set_status(PSTRING() << block_id_.id.to_str() << " : processing state header");

  deserializer_ = std::make_unique<SplitStateDeserializer>();

  if (downloaded.is_memory()) {
    auto data = std::move(downloaded.memory().data);
    auto reservation = std::move(downloaded.memory().reservation);

    auto maybe_header = vm::std_boc_deserialize(data.as_slice());
    if (maybe_header.is_error()) {
      fail_handler(actor_id(this), maybe_header.move_as_error());
      return;
    }
    auto maybe_parts = deserializer_->get_effective_shards_from_header(block_id_.shard_full().shard, handle_->state(),
                                                                        maybe_header.move_as_ok(), split_depth_);
    if (maybe_parts.is_error()) {
      fail_handler(actor_id(this), maybe_parts.move_as_error());
      return;
    }
    parts_ = maybe_parts.move_as_ok();

    auto P = td::PromiseCreator::lambda(
        [SelfId = actor_id(this), reservation = std::move(reservation)](td::Result<td::Unit> R) mutable {
          R.ensure();
          reservation.reset();
          td::actor::send_closure(SelfId, &DownloadShardState::download_next_part_or_finish);
        });
    td::actor::send_closure(manager_, &ValidatorManager::store_persistent_state_file, block_id_, masterchain_block_id_,
                            SplitPersistentStateType{}, std::move(data), std::move(P));
    return;
  }

  // OnDisk: streaming BoC deserialize → effective shards. Pass the
  // tempfile straight into store_persistent_state_file_gen to avoid a
  // heap BufferSlice of file size; the streaming importer further
  // bounds peak resident memory at the configured per-parse cap so
  // even a multi-GiB split-state header parses without mmap-resident
  // peaks.
  auto file = std::move(downloaded.file());
  auto reservation = file.reservation;

  // H-03: split-state header OnDisk parse must take its own processing
  // reservation. Before this change the split-header path was
  // unaccounted: a hostile peer could announce a multi-GiB header and
  // burn unbounded resident memory while the streaming-tempfile
  // download budget was happy. Charge the per-parse cap (NOT the file
  // size) since the streaming importer peaks at that smaller number.
  auto budget_cfg = fullnode::persistent_state_budget_config();
  // H-02 short-term cap, mirrored on the split-state header path.
  if (file.size > budget_cfg.max_returned_dag_bytes_per_parse &&
      !budget_cfg.enable_true_cell_db_streaming_import) {
    fail_handler(
        actor_id(this),
        td::Status::Error(
            ErrorCode::notready,
            PSTRING()
                << "persistent-state download rejected: split header file size " << file.size
                << " exceeds max_returned_dag_bytes_per_parse="
                << budget_cfg.max_returned_dag_bytes_per_parse
                << ". This is a known liveness ceiling pending Phase B (true ExtCell-backed "
                   "CellDb-streaming importer). Operator options: (a) raise "
                   "max_returned_dag_bytes_per_parse if you accept the OOM risk for this state, "
                   "(b) bootstrap from a smaller checkpoint, (c) wait for Phase B which will "
                   "remove this ceiling."));
    return;
  }
  td::uint64 processing_charge = file.size;
  if (processing_charge > budget_cfg.max_returned_dag_bytes_per_parse) {
    processing_charge = budget_cfg.max_returned_dag_bytes_per_parse;
  }
  std::shared_ptr<fullnode::PersistentStateProcessingReservation> split_processing_reservation;
  if (processing_charge > 0) {
    if (!fullnode::try_reserve_persistent_state_processing_memory(processing_charge)) {
      fail_handler(
          actor_id(this),
          td::Status::Error(ErrorCode::notready,
                            "persistent state processing memory budget exceeded for split OnDisk header parse"));
      return;
    }
    try {
      split_processing_reservation =
          std::make_shared<fullnode::PersistentStateProcessingReservation>(processing_charge);
    } catch (...) {
      fullnode::PersistentStateProcessingReservation rollback{processing_charge};
      (void)rollback;
      fail_handler(actor_id(this),
                   td::Status::Error(ErrorCode::notready,
                                     "cannot allocate processing reservation for split OnDisk header parse"));
      return;
    }
  }

  td::Ref<vm::Cell> header_root;
  {
    auto r_fd = td::FileFd::open(file.path, td::FileFd::Flags::Read);
    if (r_fd.is_error()) {
      fail_handler(actor_id(this), r_fd.move_as_error());
      return;
    }
    auto fd = r_fd.move_as_ok();
    vm::StreamingBocImportOptions opts;
    opts.max_resident_bytes = budget_cfg.max_resident_bytes_per_parse;
    opts.max_cells = budget_cfg.max_cells_per_parse;
    opts.max_scaffolding_bytes = budget_cfg.max_scaffolding_bytes_per_parse;
    opts.max_total_cell_bytes = std::min(file.size, budget_cfg.max_total_cell_bytes_per_parse);
    // K3: wire the real CellDbStreamingSink so split-state header
    // imports get the same per-cell validation + counter that the
    // unsplit OnDisk parse uses. The downstream archive store still
    // owns the actual CellDb commit.
    fullnode::CellDbStreamingSink streaming_sink;
    auto r_root = vm::std_boc_deserialize_from_file_bounded(fd, file.size, opts, &streaming_sink);
    fd.close();
    if (r_root.is_error()) {
      LOG(WARNING) << "OnDisk streaming split-state header parse failed for " << block_id_.to_str()
                   << " after " << streaming_sink.cell_count() << " cells: "
                   << r_root.error();
      fail_handler(actor_id(this), r_root.move_as_error());
      return;
    }
    if (!streaming_sink.finished()) {
      fail_handler(actor_id(this),
                   td::Status::Error("OnDisk streaming sink finished=false on split-header success path"));
      return;
    }
    LOG(INFO) << "OnDisk streaming split-state header parse for " << block_id_.to_str()
              << " imported " << streaming_sink.cell_count() << " cells";
    header_root = r_root.move_as_ok();
  }

  auto maybe_parts = deserializer_->get_effective_shards_from_header(block_id_.shard_full().shard, handle_->state(),
                                                                      std::move(header_root), split_depth_);
  if (maybe_parts.is_error()) {
    fail_handler(actor_id(this), maybe_parts.move_as_error());
    return;
  }
  parts_ = maybe_parts.move_as_ok();

  auto src_path = file.path;
  auto src_size = file.size;
  auto write_data = [src_path, src_size](td::FileFd &dst) -> td::Status {
    return copy_tempfile_to_writer(src_path, src_size, dst);
  };
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), reservation = std::move(reservation),
       processing_reservation = std::move(split_processing_reservation),
       file = std::move(file)](td::Result<td::Unit> R) mutable {
        R.ensure();
        (void)file;
        reservation.reset();
        processing_reservation.reset();
        td::actor::send_closure(SelfId, &DownloadShardState::download_next_part_or_finish);
      });
  td::actor::send_closure(manager_, &ValidatorManager::store_persistent_state_file_gen, block_id_,
                          masterchain_block_id_, SplitPersistentStateType{}, std::move(write_data),
                          std::move(P));
}

namespace {

void retry_part_download(td::actor::ActorId<DownloadShardState> SelfId, td::Status error) {
  LOG(WARNING) << "failed to download state part : " << error;
  delay_action([=]() { td::actor::send_closure(SelfId, &DownloadShardState::download_next_part_or_finish); },
               td::Timestamp::in(1.0));
}

}  // namespace

void DownloadShardState::download_next_part_or_finish() {
  if (stored_parts_.size() == parts_.size()) {
    auto state_root = deserializer_->merge(stored_parts_);
    auto maybe_state = create_shard_state(block_id_, state_root);

    // We cannot rollback database changes here without significant elbow grease.
    maybe_state.ensure();
    state_ = maybe_state.move_as_ok();
    CHECK(state_->root_hash() == handle_->state());

    written_shard_state_file();
    return;
  }

  size_t idx = stored_parts_.size();

  LOG(INFO) << "downloading state part " << idx + 1 << " out of " << parts_.size();
  status_.set_status(PSTRING() << block_id_.id.to_str() << " : downloading state part (part " << idx + 1 << " out of "
                               << parts_.size() << ")");

  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this)](td::Result<fullnode::DownloadedPersistentState> R) {
        if (R.is_error()) {
          retry_part_download(SelfId, R.move_as_error());
        } else {
          td::actor::send_closure(SelfId, &DownloadShardState::downloaded_state_part, R.move_as_ok());
        }
      });
  td::actor::send_closure(manager_, &ValidatorManager::send_get_persistent_state_request, block_id_,
                          masterchain_block_id_, SplitAccountStateType{parts_[idx].effective_shard}, priority_,
                          std::move(P));
}

void DownloadShardState::downloaded_state_part(fullnode::DownloadedPersistentState downloaded) {
  size_t idx = stored_parts_.size();

  LOG(INFO) << "processing state part " << idx + 1 << " out of " << parts_.size();
  status_.set_status(PSTRING() << block_id_.id.to_str() << " : processing state part (part " << idx + 1 << " out of "
                               << parts_.size() << ")");

  if (downloaded.is_memory()) {
    auto data = std::move(downloaded.memory().data);
    auto reservation = std::move(downloaded.memory().reservation);

    auto maybe_part = vm::std_boc_deserialize(data.as_slice());
    if (maybe_part.is_error()) {
      retry_part_download(actor_id(this), maybe_part.move_as_error());
      return;
    }
    auto root = maybe_part.move_as_ok();
    if (root->get_hash() != parts_[idx].root_hash) {
      auto error_message =
          "Hash mismatch for part " +
          persistent_state_type_to_string(block_id_.shard_full(), SplitAccountStateType{parts_[idx].effective_shard});
      retry_part_download(actor_id(this), td::Status::Error(error_message));
      return;
    }
    stored_parts_.push_back(root);

    auto P = td::PromiseCreator::lambda(
        [SelfId = actor_id(this), reservation = std::move(reservation)](td::Result<td::Unit> R) mutable {
          R.ensure();
          reservation.reset();
          td::actor::send_closure(SelfId, &DownloadShardState::written_state_part_file);
        });
    td::actor::send_closure(manager_, &ValidatorManager::store_persistent_state_file, block_id_, masterchain_block_id_,
                            SplitAccountStateType{parts_[idx].effective_shard}, std::move(data), std::move(P));

    LOG(INFO) << "storing state part to file " << idx + 1 << " out of " << parts_.size();
    status_.set_status(PSTRING() << block_id_.id.to_str() << " : storing state part to file (part " << idx + 1
                                 << " out of " << parts_.size() << ")");
    return;
  }

  // OnDisk: streaming deserialize → store via _gen. The split-state
  // part path is the second of the two split-state branches H-03
  // calls out as needing its own processing reservation; without it,
  // a hostile peer could ship many large parts in succession and
  // burn unbounded resident memory while the streaming-tempfile
  // download budget tracks only the on-disk bytes.
  auto file = std::move(downloaded.file());
  auto reservation = file.reservation;

  auto budget_cfg = fullnode::persistent_state_budget_config();
  // H-02 short-term cap, mirrored on the split-state part path.
  if (file.size > budget_cfg.max_returned_dag_bytes_per_parse &&
      !budget_cfg.enable_true_cell_db_streaming_import) {
    retry_part_download(
        actor_id(this),
        td::Status::Error(
            ErrorCode::notready,
            PSTRING()
                << "persistent-state download rejected: split part file size " << file.size
                << " exceeds max_returned_dag_bytes_per_parse="
                << budget_cfg.max_returned_dag_bytes_per_parse
                << ". This is a known liveness ceiling pending Phase B (true ExtCell-backed "
                   "CellDb-streaming importer). Operator options: (a) raise "
                   "max_returned_dag_bytes_per_parse if you accept the OOM risk for this state, "
                   "(b) bootstrap from a smaller checkpoint, (c) wait for Phase B which will "
                   "remove this ceiling."));
    return;
  }
  td::uint64 processing_charge = file.size;
  if (processing_charge > budget_cfg.max_returned_dag_bytes_per_parse) {
    processing_charge = budget_cfg.max_returned_dag_bytes_per_parse;
  }
  std::shared_ptr<fullnode::PersistentStateProcessingReservation> split_processing_reservation;
  if (processing_charge > 0) {
    if (!fullnode::try_reserve_persistent_state_processing_memory(processing_charge)) {
      retry_part_download(
          actor_id(this),
          td::Status::Error(ErrorCode::notready,
                            "persistent state processing memory budget exceeded for split OnDisk part parse"));
      return;
    }
    try {
      split_processing_reservation =
          std::make_shared<fullnode::PersistentStateProcessingReservation>(processing_charge);
    } catch (...) {
      fullnode::PersistentStateProcessingReservation rollback{processing_charge};
      (void)rollback;
      retry_part_download(actor_id(this),
                          td::Status::Error(ErrorCode::notready,
                                            "cannot allocate processing reservation for split OnDisk part parse"));
      return;
    }
  }

  td::Ref<vm::Cell> root;
  {
    auto r_fd = td::FileFd::open(file.path, td::FileFd::Flags::Read);
    if (r_fd.is_error()) {
      retry_part_download(actor_id(this), r_fd.move_as_error());
      return;
    }
    auto fd = r_fd.move_as_ok();
    vm::StreamingBocImportOptions opts;
    opts.max_resident_bytes = budget_cfg.max_resident_bytes_per_parse;
    opts.max_cells = budget_cfg.max_cells_per_parse;
    opts.max_scaffolding_bytes = budget_cfg.max_scaffolding_bytes_per_parse;
    opts.max_total_cell_bytes = std::min(file.size, budget_cfg.max_total_cell_bytes_per_parse);
    // K3: wire the real CellDbStreamingSink for the split-state part
    // OnDisk parse. Same pattern as the header path.
    fullnode::CellDbStreamingSink streaming_sink;
    auto r_root = vm::std_boc_deserialize_from_file_bounded(fd, file.size, opts, &streaming_sink);
    fd.close();
    if (r_root.is_error()) {
      LOG(WARNING) << "OnDisk streaming split-state part parse failed for " << block_id_.to_str()
                   << " part " << idx << " after " << streaming_sink.cell_count() << " cells: "
                   << r_root.error();
      retry_part_download(actor_id(this), r_root.move_as_error());
      return;
    }
    if (!streaming_sink.finished()) {
      retry_part_download(actor_id(this),
                          td::Status::Error("OnDisk streaming sink finished=false on split-part success path"));
      return;
    }
    LOG(INFO) << "OnDisk streaming split-state part parse for " << block_id_.to_str()
              << " part " << idx << " imported " << streaming_sink.cell_count() << " cells";
    root = r_root.move_as_ok();
  }
  if (root->get_hash() != parts_[idx].root_hash) {
    auto error_message =
        "Hash mismatch for part " +
        persistent_state_type_to_string(block_id_.shard_full(), SplitAccountStateType{parts_[idx].effective_shard});
    retry_part_download(actor_id(this), td::Status::Error(error_message));
    return;
  }
  stored_parts_.push_back(root);

  auto src_path = file.path;
  auto src_size = file.size;
  auto write_data = [src_path, src_size](td::FileFd &dst) -> td::Status {
    return copy_tempfile_to_writer(src_path, src_size, dst);
  };
  auto P = td::PromiseCreator::lambda(
      [SelfId = actor_id(this), reservation = std::move(reservation),
       processing_reservation = std::move(split_processing_reservation),
       file = std::move(file)](td::Result<td::Unit> R) mutable {
        R.ensure();
        (void)file;
        reservation.reset();
        processing_reservation.reset();
        td::actor::send_closure(SelfId, &DownloadShardState::written_state_part_file);
      });
  td::actor::send_closure(manager_, &ValidatorManager::store_persistent_state_file_gen, block_id_,
                          masterchain_block_id_, SplitAccountStateType{parts_[idx].effective_shard},
                          std::move(write_data), std::move(P));

  LOG(INFO) << "storing state part to file " << idx + 1 << " out of " << parts_.size();
  status_.set_status(PSTRING() << block_id_.id.to_str() << " : storing state part to file (part " << idx + 1
                               << " out of " << parts_.size() << ")");
}

void DownloadShardState::written_state_part_file() {
  size_t idx = stored_parts_.size() - 1;

  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Ref<vm::DataCell>> R) {
    R.ensure();
    td::actor::send_closure(SelfId, &DownloadShardState::saved_state_part_into_celldb, R.move_as_ok());
  });
  td::actor::send_closure(manager_, &ValidatorManager::store_block_state_part,
                          BlockId{block_id_.shard_full().workchain, parts_[idx].effective_shard, block_id_.seqno()},
                          stored_parts_.back(), std::move(P));
  LOG(INFO) << "saving to celldb state part " << idx + 1 << " out of " << parts_.size();
  status_.set_status(PSTRING() << block_id_.id.to_str() << " : saving state part to celldb (part " << idx + 1
                               << " out of " << parts_.size() << ")");
}

void DownloadShardState::saved_state_part_into_celldb(td::Ref<vm::DataCell> cell) {
  stored_parts_.back() = cell;
  download_next_part_or_finish();
}

void DownloadShardState::written_shard_state_file() {
  status_.set_status(PSTRING() << block_id_.id.to_str() << " : storing state to celldb");
  LOG(WARNING) << "written shard state file " << block_id_.to_str();
  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this)](td::Result<td::Ref<ShardState>> R) {
    R.ensure();
    td::actor::send_closure(SelfId, &DownloadShardState::written_shard_state, R.move_as_ok());
  });
  td::actor::send_closure(manager_, &ValidatorManager::set_block_state, handle_, std::move(state_), vm::StoreCellHint{},
                          std::move(P));
}

void DownloadShardState::written_shard_state(td::Ref<ShardState> state) {
  status_.set_status(PSTRING() << block_id_.id.to_str() << " : finishing");
  state_ = std::move(state);
  handle_->set_unix_time(state_->get_unix_time());
  handle_->set_is_key_block(block_id_.is_masterchain());
  handle_->set_logical_time(state_->get_logical_time());
  handle_->set_applied();
  handle_->set_split(state_->before_split());
  if (!block_id_.is_masterchain()) {
    handle_->set_masterchain_ref_block(masterchain_block_id_.seqno());
  }

  auto P = td::PromiseCreator::lambda([SelfId = actor_id(this), handle = handle_](td::Result<td::Unit> R) {
    CHECK(handle->handle_moved_to_archive());
    CHECK(handle->moved_to_archive())
    R.ensure();
    td::actor::send_closure(SelfId, &DownloadShardState::written_block_handle);
  });
  td::actor::send_closure(manager_, &ValidatorManager::archive, handle_, std::move(P));
}

void DownloadShardState::written_block_handle() {
  LOG(WARNING) << "finished downloading and storing shard state " << block_id_.to_str();
  finish_query();
}

void DownloadShardState::finish_query() {
  if (promise_) {
    promise_.set_value(std::move(state_));
  }
  stop();
}

void DownloadShardState::alarm() {
  abort_query(td::Status::Error(ErrorCode::timeout, "timeout"));
}

void DownloadShardState::abort_query(td::Status reason) {
  if (promise_) {
    promise_.set_error(std::move(reason));
  }
  stop();
}

void DownloadShardState::fail_handler(td::actor::ActorId<DownloadShardState> SelfId, td::Status error) {
  LOG(WARNING) << "failed to download state : " << error;
  delay_action([=]() { td::actor::send_closure(SelfId, &DownloadShardState::retry); }, td::Timestamp::in(1.0));
}

}  // namespace validator

}  // namespace tos
