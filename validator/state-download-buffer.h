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

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <memory>
#include <string>
#include <utility>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "td/utils/buffer.h"
#include "td/utils/int_types.h"

namespace tos {
namespace validator {
namespace fullnode {

// Forward declaration of the platform-specific mmap holder. Owns the file
// descriptor, the page-aligned mapped pointer, and the data offset within
// the mapping. Defined in state-download-buffer.cpp.
class MmapHandle;

// RAII reservation against the global persistent-state download memory
// budget. The reservation is held by a shared_ptr alongside the downloaded
// buffer; the underlying bytes are returned to the global budget only when
// the last reference is dropped (i.e., when downstream consumers have
// finished processing the buffer).
//
// Declared here in a public header (independent of the DownloadState actor
// implementation) so that both the network-side producer and every
// manager/full-node interface boundary can carry the reservation through
// without breaking the reservation lifetime invariant.
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

// On-disk variant of a downloaded persistent state. The downloader writes
// chunked rldp slices via pwrite into a tempfile and renames it to a
// content-addressed final path on success. The reservation accounts the
// full file size against the download budget for as long as any consumer
// keeps a reference to this struct alive (i.e., until the final state is
// parsed and persisted to celldb).
//
// `path` is the path the consumer should read for parsing. If `is_temp`
// is true, the destructor unlinks the file on drop (used for the partial
// tempfile during transit and on the abort path); the producer flips
// `is_temp` to false once a successful rename to the final path has been
// performed and ownership is transferred to the consumer.
struct BudgetedStateFile {
  std::string path;
  td::uint64 size{0};
  std::shared_ptr<PersistentStateDownloadReservation> reservation;
  // If true, the file at `path` is owned by the consumer and should be
  // unlinked when the BudgetedStateFile is dropped (e.g. an abort path or
  // after parsing finishes consuming the file). Default true so an
  // accidentally-leaked struct does not leave residue on disk; producers
  // explicitly set false when they want the file to outlive this handle.
  bool is_temp{true};

  // The default ctor and the (path,size,reservation,temp) ctor are
  // implementable inline because the unique_ptr<MmapHandle> default-
  // constructs to nullptr — no destruction of an incomplete type. The
  // copy/move/destructor that need to interact with the unique_ptr's
  // destructor (which instantiates default_delete<MmapHandle>) are
  // declared inline only and DEFINED out-of-line in the .cpp where the
  // MmapHandle class is complete.
  BudgetedStateFile() noexcept;
  BudgetedStateFile(std::string p, td::uint64 s,
                    std::shared_ptr<PersistentStateDownloadReservation> r,
                    bool temp = true) noexcept;
  BudgetedStateFile(const BudgetedStateFile &) = delete;
  BudgetedStateFile &operator=(const BudgetedStateFile &) = delete;
  BudgetedStateFile(BudgetedStateFile &&other) noexcept;
  BudgetedStateFile &operator=(BudgetedStateFile &&other) noexcept;
  ~BudgetedStateFile();

  // mmap the on-disk file as PROT_READ / MAP_PRIVATE and return a
  // non-owning td::Slice that points into kernel-mapped memory. The
  // returned slice is valid only while *this BudgetedStateFile is alive
  // (the mmap handle is owned by *this). NEVER allocates a heap buffer of
  // size == file size: this is the load-bearing zero-copy entry point
  // that lets the OnDisk parse path avoid the read_full_file heap peak.
  //
  // Calling this twice on the same instance returns the same mapping; the
  // mapping is created lazily on the first call and reused on subsequent
  // calls (so callers can pass the slice to multiple downstream functions
  // without re-mapping). The mapping is dropped together with the temp
  // file when reset() runs.
  td::Result<td::Slice> mmap_view() noexcept;

 private:
  void reset() noexcept;

  // Lazily-created mmap holder. unique_ptr keeps this header free of
  // platform-specific includes and lets the destructor unmap (and close
  // the fd) exactly once when the BudgetedStateFile is dropped.
  std::unique_ptr<MmapHandle> mmap_;
};

// Buffer-or-file variant produced by DownloadState. Small states (<=
// kHeapThreshold) take the InMemory branch and ride the existing heap
// path; large states take the OnDisk branch where the downloader streams
// chunks into a tempfile via pwrite without any single full-state heap
// allocation.
class DownloadedPersistentState {
 public:
  enum class Kind { InMemory, OnDisk };

  DownloadedPersistentState() = default;

  static DownloadedPersistentState memory(BudgetedBufferSlice mem) {
    DownloadedPersistentState r;
    r.kind_ = Kind::InMemory;
    r.memory_ = std::move(mem);
    return r;
  }

  static DownloadedPersistentState file(BudgetedStateFile f) {
    DownloadedPersistentState r;
    r.kind_ = Kind::OnDisk;
    r.file_ = std::move(f);
    return r;
  }

  Kind kind() const {
    return kind_;
  }
  bool is_memory() const {
    return kind_ == Kind::InMemory;
  }
  bool is_file() const {
    return kind_ == Kind::OnDisk;
  }

  BudgetedBufferSlice &memory() {
    return memory_;
  }
  const BudgetedBufferSlice &memory() const {
    return memory_;
  }
  BudgetedStateFile &file() {
    return file_;
  }
  const BudgetedStateFile &file() const {
    return file_;
  }

  td::uint64 size() const {
    if (kind_ == Kind::InMemory) {
      return memory_.data.size();
    }
    return file_.size;
  }

 private:
  Kind kind_{Kind::InMemory};
  BudgetedBufferSlice memory_;
  BudgetedStateFile file_;
};

// RAII reservation against the global persistent-state PROCESSING memory
// budget. This budget is separate from the download budget: it accounts the
// transient extra memory required while parsing/persisting a downloaded
// state buffer (e.g. the BufferSlice clone fed to `create_shard_state`).
//
// The two budgets must be tracked separately because the download budget
// covers the resident original buffer while it is held alive across the
// network -> manager -> disk-write pipeline; the processing budget covers
// the additional clone(s) that exist only during deserialize/validate.
// Mixing them would either over-restrict downloads (counting transient
// peaks against the download cap) or under-account the actual peak
// resident bytes.
struct PersistentStateProcessingReservation {
  td::uint64 bytes{0};

  PersistentStateProcessingReservation() = default;
  explicit PersistentStateProcessingReservation(td::uint64 b) : bytes(b) {
  }
  PersistentStateProcessingReservation(const PersistentStateProcessingReservation &) = delete;
  PersistentStateProcessingReservation &operator=(const PersistentStateProcessingReservation &) = delete;
  PersistentStateProcessingReservation(PersistentStateProcessingReservation &&) = delete;
  PersistentStateProcessingReservation &operator=(PersistentStateProcessingReservation &&) = delete;
  ~PersistentStateProcessingReservation();
};

// Public reservation API for the download budget. Returns true iff `size`
// bytes were CAS'd into the global counter; in that case the caller MUST
// own a `PersistentStateDownloadReservation{size}` (or wrap one in a
// shared_ptr) whose destructor will release the bytes exactly once.
bool try_reserve_persistent_state_download_memory(td::uint64 size);

// Mirror of the download API for the processing budget.
bool try_reserve_persistent_state_processing_memory(td::uint64 size);

// Validate the peer-advertised total persistent-state size against the
// hard download cap. Used by DownloadState before reserving the budget so
// a hostile peer cannot induce an unbounded heap allocation.
td::Status validate_persistent_state_size(td::uint64 size);

// Threshold above which the streaming-tempfile downloader is used.
td::uint64 persistent_state_heap_threshold_bytes();

// Hard upper bound on a single persistent-state download.
td::uint64 persistent_state_max_file_bytes();

// Hard upper bound on the cumulative outstanding persistent-state download
// budget. Exposed so tests pin the value and so the OnDisk parse path can
// reason about whether a single state can occupy the full budget transiently.
td::uint64 persistent_state_total_download_budget_bytes();

// Map an on-disk persistent-state tempfile (the file referenced by the
// BudgetedStateFile produced by the streaming downloader) into the
// process via PROT_READ / MAP_PRIVATE and return a non-owning td::Slice
// view of its bytes. The mapping is owned by `f` for the rest of its
// lifetime; the caller MUST keep the BudgetedStateFile (or the
// DownloadedPersistentState that wraps it) alive until it stops using
// the returned slice.
//
// On error, returns a Status whose message includes the platform error.
// The OnDisk parse path uses this to feed `vm::std_boc_deserialize`
// without ever allocating a BufferSlice of size == file size.
td::Result<td::Slice> mmap_persistent_state_file(BudgetedStateFile &f);

// Helper used by manager/disk recovery: scan the given tempfile root
// directory and remove any *.partial files that look like residue from
// a prior crash.
//
// Race-safety contract:
//   The validator manager calls this function exactly once during
//   start_up(), BEFORE any DownloadState actor is spawned (DownloadState
//   is the only writer of *.partial files in this process). At that
//   point no in-process writer can exist, so concurrent writers are
//   impossible by construction. The mtime guard below is defense-in-depth
//   against (a) a future caller that invokes cleanup at runtime, and (b)
//   a co-located process (e.g. an admin running a maintenance tool) that
//   shares the same tempfile root and is mid-write when cleanup runs.
//   Files younger than `min_age_seconds` are skipped; files older are
//   unlinked. The default age threshold is 60 seconds, well below any
//   realistic startup -> first-download latency.
//
// `min_age_seconds == 0` disables the age guard entirely; reserved for
// situations where the caller has already proved no concurrent writer
// exists.
td::Status cleanup_persistent_state_tempfiles(td::CSlice tempfile_root,
                                              td::uint64 min_age_seconds = 60);

// Register / retrieve the persistent-state tempfile directory. Called
// once by the validator manager during start_up(); read by DownloadState
// when it decides to switch from heap mode to file mode.
void set_persistent_state_tempfile_dir(std::string dir);
std::string get_persistent_state_tempfile_dir();

namespace testing {

// Test-only handle to the global persistent-state download budget. These
// helpers exist so a unit test can exercise the reservation lifetime
// invariant without bringing up the full DownloadState actor stack.
td::uint64 test_get_persistent_state_download_bytes();
bool test_try_reserve_persistent_state_download_memory(td::uint64 size);

// Test-only handle to the global persistent-state processing budget.
// Mirrors the download counterpart so the parse/persist clone accounting
// can be validated without standing up the DownloadShardState actor.
td::uint64 test_get_persistent_state_processing_bytes();
bool test_try_reserve_persistent_state_processing_memory(td::uint64 size);

}  // namespace testing

}  // namespace fullnode
}  // namespace validator
}  // namespace tos
