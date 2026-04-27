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

#include "td/utils/Status.h"
#include "td/utils/port/FileFd.h"
#include "validator/interfaces/validator-manager.h"
#include "validator/state-download-buffer.h"
#include "vm/boc.h"
#include "vm/cells/Cell.h"

#include "stats-provider.h"

#include <functional>
#include <string>

namespace tos {

namespace validator {

// Stream the contents of a tempfile into the destination FileFd that the
// archive manager opens for store_persistent_state_file_gen and
// store_zero_state_file_gen. The implementation copies in 1 MiB chunks so
// peak resident memory is bounded by the chunk size, regardless of the
// underlying state size. No BufferSlice of size == state size is ever
// allocated. Returns Status::OK on a complete copy, or an Error on read /
// write / short-IO failures.
td::Status copy_tempfile_to_writer(const std::string &src_path, td::uint64 size, td::FileFd &dst);

// Run the OnDisk parse pipeline that DownloadShardState::downloaded_shard_state
// uses for the OnDisk branch: mmap → BoC deserialize → compare root hash
// against the BFT-attested expected root. Returns the deserialized cell
// tree on success.
//
// Exposed so a regression test can pin the claim "validate_deep() is
// skipped on the OnDisk path because the BoC deserializer + root-hash
// check is the same invariant validate_deep() enforces": the test feeds
// a corrupted tempfile to this function and asserts the corruption is
// rejected with a descriptive Status::Error.
//
// NOT a public API surface — the function is on the `validator::` (NOT
// `validator::fullnode::`) namespace and the only call site outside
// downloaded_shard_state is the regression test.
td::Result<td::Ref<vm::Cell>> parse_ondisk_state_for_test(fullnode::BudgetedStateFile &file,
                                                          const RootHash &expected_root_hash);

// H-03 streaming OnDisk parse path. Opens the BudgetedStateFile for
// read, drives the bounded streaming BoC importer with the supplied
// resident-bytes cap (0 = use the importer's built-in default), and
// validates the resulting root hash against the BFT-attested
// `expected_root_hash`. Peak resident memory is bounded by
// `max_resident_bytes`, NOT by the file size; this is the load-bearing
// primitive that lets a 600 MiB+ catch-up state parse without hitting
// the 512 MiB processing cap.
//
// `persist_cell` is invoked once per unique cell in topological order
// (leaves first). The current actor wires a CellDbStreamingSink that
// counts cells and surfaces per-cell errors; the downstream
// set_block_state still does the CellDb commit. See the sink-overload
// (below) for the load-bearing extension point a future commit can
// use to land cells directly through the importer.
td::Result<td::Ref<vm::Cell>> parse_ondisk_state_streaming(fullnode::BudgetedStateFile &file,
                                                           const RootHash &expected_root_hash,
                                                           td::uint64 max_resident_bytes,
                                                           vm::StreamingPersistCellFn persist_cell);

// Sink-based variant. Identical to the std::function overload except
// that the caller drives the importer with a vm::StreamingCellSink
// instance — exposing the begin/persist/finish/abort state machine
// without the std::function wrapper. The actor uses this overload so
// the sink's accumulated counters / observed root hash are available
// after the parse returns.
//
// `sink` may be nullptr — in that case the importer behaves like the
// legacy empty-callback path (cells live only through the returned
// root cell's DAG). The sink, if non-null, MUST outlive the call.
td::Result<td::Ref<vm::Cell>> parse_ondisk_state_streaming(fullnode::BudgetedStateFile &file,
                                                           const RootHash &expected_root_hash,
                                                           td::uint64 max_resident_bytes,
                                                           vm::StreamingCellSink *sink);

class SplitStateDeserializer;

struct SplitStatePart {
  ShardId effective_shard;
  vm::CellHash root_hash;
};

class DownloadShardState : public td::actor::Actor {
 public:
  DownloadShardState(BlockIdExt block_id, BlockIdExt masterchain_block_id, td::uint32 split_depth, td::uint32 priority,
                     td::actor::ActorId<ValidatorManager> manager, td::Timestamp timeout,
                     td::Promise<td::Ref<ShardState>> promise);
  ~DownloadShardState();

  void start_up() override;
  void got_block_handle(BlockHandle handle);
  void retry();
  void downloaded_proof_link(td::BufferSlice data);
  void checked_proof_link();

  void download_state();
  void download_proof_link();

  void download_zero_state();
  void downloaded_zero_state(fullnode::DownloadedPersistentState downloaded);

  void downloaded_shard_state(fullnode::DownloadedPersistentState downloaded);
  void checked_shard_state();

  void downloaded_split_state_header(fullnode::DownloadedPersistentState downloaded);
  void download_next_part_or_finish();
  void downloaded_state_part(fullnode::DownloadedPersistentState downloaded);
  void written_state_part_file();
  void saved_state_part_into_celldb(td::Ref<vm::DataCell> cell);

  void written_shard_state_file();
  void written_shard_state(td::Ref<ShardState> state);
  void written_block_handle();

  void finish_query();
  void alarm() override;
  void abort_query(td::Status reason);

  static void fail_handler(td::actor::ActorId<DownloadShardState> SelfId, td::Status error);

 private:
  BlockIdExt block_id_;
  BlockIdExt masterchain_block_id_;
  td::uint32 split_depth_;

  BlockHandle handle_;
  td::uint32 priority_;

  td::actor::ActorId<ValidatorManager> manager_;
  td::Timestamp timeout_;
  td::Promise<td::Ref<ShardState>> promise_;

  std::unique_ptr<SplitStateDeserializer> deserializer_;
  std::vector<SplitStatePart> parts_;
  std::vector<Ref<vm::Cell>> stored_parts_;

  td::BufferSlice data_;
  // Reservation tied to the buffer/file above. Held in the actor state
  // so the global persistent-state download budget stays charged for as
  // long as the downloaded buffer is being processed (deserialize,
  // validate, write to disk). Released exactly once when this shared_ptr
  // is dropped.
  std::shared_ptr<fullnode::PersistentStateDownloadReservation> data_reservation_;
  // Set when the downloaded state arrived as an on-disk tempfile
  // (DownloadedPersistentState::Kind::OnDisk). The actor reads from this
  // file to deserialize/persist; on success the downstream
  // store_persistent_state_file consumes the file, on abort the
  // BudgetedStateFile destructor unlinks the tempfile.
  fullnode::BudgetedStateFile data_file_;
  // M-01: processing-budget reservation held across parse + create
  // shard state + archive store. Released exactly once when the archive
  // handoff finishes (success path) or when the failure branch resets
  // actor state. Held as a shared_ptr so completion lambdas can extend
  // its lifetime past `this` without copying the reservation bytes.
  std::shared_ptr<fullnode::PersistentStateProcessingReservation> state_processing_reservation_;
  td::Ref<ShardState> state_;

  ProcessStatus status_;
};

}  // namespace validator

}  // namespace tos
