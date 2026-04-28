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
#include "validator/db/celldb.hpp"
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

// H-02 / H-03 full-options overload. Lets the caller forward every
// `vm::StreamingBocImportOptions` field (max_resident_bytes,
// max_cells, max_scaffolding_bytes, max_total_cell_bytes,
// max_roots) verbatim. The actor uses this overload so a single
// PersistentStateBudgetConfig snapshot drives every BoC import.
td::Result<td::Ref<vm::Cell>> parse_ondisk_state_streaming(fullnode::BudgetedStateFile &file,
                                                           const RootHash &expected_root_hash,
                                                           const vm::StreamingBocImportOptions &opts,
                                                           vm::StreamingCellSink *sink);

// Phase B "true streaming" parse path.
//
// tos26 P1-4 NOTE: this overload is RETAINED for direct-driver callers
// that already have (reader, writer) in hand — primarily the
// CellDbIn-internal import path and the regression tests in
// test/test-celldb-streaming-import.cpp. Production downloader code
// MUST go through `ValidatorManager::import_persistent_state_streaming`
// so the whole begin/parse/verify-root/commit lifecycle runs inside
// CellDbIn's serialized actor loop. Calling this overload from the
// downloader actor would re-introduce the actor-serialization hazard
// the audit's P1-4 closes.
//
// Identical surface to the
// (file, expected_root_hash, opts, sink*) overload above, except this
// helper OWNS the sink lifecycle: it constructs a `CellDbStreamingSink`
// from the supplied (`reader`, `writer`) pair, drives the
// begin/persist/finish/abort state machine around the bounded BoC
// importer, and returns a hash-only ExtCell-backed root whose child
// DAG lives durably in CellDb rather than in process memory.
//
// Reservation-lifecycle contract:
//   The caller must hold the persistent-state processing reservation
//   for the duration of this call. The reservation MUST stay alive
//   until AFTER this function returns; the sink's `finish()` (which
//   commits the CellDb batch) runs before the function returns.
//   The acceptance criterion in the Phase B spec ("Do not release
//   processing reservation until: BoC parse completed; CellDb batch
//   committed; root hash verified; downstream manager has either
//   accepted lazy root or failed; temporary file cleanup is complete")
//   bottoms out at this function for the first three clauses; the
//   caller still owns the manager-handoff and tempfile-cleanup
//   clauses.
//
// Failure-mode contract:
//   On any internal error (file open, importer rejection, root-hash
//   mismatch, sink finish failure) the function calls `sink.abort()`
//   before returning so the CellDb write batch is rolled back; the
//   caller observes the error verbatim and SHOULD release its
//   reservation as part of its normal failure-cleanup path.
//
// Concurrency contract:
//   `CellDbIn::create_streaming_writer()` is import-only; the validator
//   manager that constructs the writer must serialize concurrent
//   imports (Wave 4 of the broader Phase B plan owns that surface).
//   This helper assumes the caller has already claimed the import slot
//   and does NOT add its own per-CellDb lock.
//
// The function logs `cells_persisted` on success at INFO level so
// operators can confirm the Phase B path was taken; Wave 6 tests
// observe `sink.is_true_streaming()` / `sink.cells_persisted()` via
// the (file, opts, sink*) overload directly.
td::Result<td::Ref<vm::Cell>> parse_ondisk_state_streaming(
    fullnode::BudgetedStateFile &file, const RootHash &expected_root_hash,
    const vm::StreamingBocImportOptions &opts, std::shared_ptr<vm::CellDbReader> reader,
    std::unique_ptr<CellDbStreamingWriter> writer);

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
  // tos26 P1-4: completion callback for the actor-local persistent-state
  // import message. The downloader hands the entire (file, expected
  // root, options) request to `ValidatorManager::import_persistent_state_streaming`;
  // this method is invoked when CellDbIn finishes the begin / parse /
  // verify-root / commit lifecycle. On success the lazy ExtCell-backed
  // root flows into checked_shard_state() exactly like the legacy path.
  void on_streaming_import_done(td::Result<PersistentStateImportResult> r_result);
  void checked_shard_state();

  void downloaded_split_state_header(fullnode::DownloadedPersistentState downloaded);
  // tos27 P1-3: completion callback for the actor-local split-state-header
  // streaming-import message. The OnDisk header parse now flows through
  // `ValidatorManager::import_persistent_state_streaming` so it gets the
  // same root-mismatch / commit-after-verify / GC-pause-lease guarantees
  // as the unsplit-state path; this method receives the lazy
  // ExtCell-backed root and proceeds with `get_effective_shards_from_header`
  // exactly like the legacy local-sink path did.
  void on_split_state_header_imported(fullnode::BudgetedStateFile file,
                                      std::shared_ptr<fullnode::PersistentStateDownloadReservation> reservation,
                                      std::shared_ptr<fullnode::PersistentStateProcessingReservation> processing,
                                      td::Result<PersistentStateImportResult> r_result);
  void download_next_part_or_finish();
  void downloaded_state_part(fullnode::DownloadedPersistentState downloaded);
  // tos27 P1-3: completion callback for the actor-local split-state-part
  // streaming-import message. Same lifecycle as
  // `on_split_state_header_imported` but for an individual split-state
  // part: the lazy root is hash-checked against `parts_[idx].root_hash`,
  // pushed into `stored_parts_`, and the tempfile flows into
  // `store_persistent_state_file_gen` for archive durability.
  void on_split_state_part_imported(size_t part_idx, fullnode::BudgetedStateFile file,
                                    std::shared_ptr<fullnode::PersistentStateDownloadReservation> reservation,
                                    std::shared_ptr<fullnode::PersistentStateProcessingReservation> processing,
                                    td::Result<PersistentStateImportResult> r_result);
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
  // tos27 P0-1 / P1-3: GC-pause lease taken out by CellDbIn on the
  // streaming-import success path and held by this actor across
  // `create_shard_state` -> `set_block_state`. Released exactly once
  // when `set_block_state` resolves successfully (in
  // `written_shard_state`). If the actor is destroyed before
  // `set_block_state` resolves (cancel / shutdown / abort_query) the
  // lease's destructor releases the pause as a fallback so GC always
  // resumes — there is no fixed-timer fallback in the importer
  // anymore. Held by std::unique_ptr because `CellDbGcPauseLease` is
  // move-only and the present `gc_lease_` slot must be both
  // default-constructible (empty before the import resolves) and
  // assign-from-empty-able (release path) without exposing the
  // lease's full type to users of the actor's public surface.
  //
  // Lease lifecycle for split-state imports (tos27 P1-3):
  //   Each Phase B import (header + every part) issues its own lease.
  //   We keep only the latest lease in this slot — when a new part's
  //   lease arrives we drop the previous one. Earlier leases would
  //   technically extend GC pause for a few extra milliseconds; the
  //   importer's watchdog logs lingering leases so an operator can
  //   observe the leak path. This trade follows the audit's
  //   "easiest correct" recommendation: simpler than a vector-of-leases
  //   release scheme and still bounded by per-part `store_block_state_part`
  //   completion (which adds a canonical reference each part import).
  //   Final release happens in `written_shard_state`, after the
  //   merged `set_block_state` commits the canonical block-state root.
  std::unique_ptr<CellDbGcPauseLease> gc_lease_;
  td::Ref<ShardState> state_;

  ProcessStatus status_;
};

}  // namespace validator

}  // namespace tos
