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
#include "validator/state-download-buffer.h"

#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "td/utils/format.h"
#include "td/utils/logging.h"
#include "td/utils/port/Clocks.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/path.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace tos {
namespace validator {
namespace fullnode {

namespace {

// Threshold above which the downloader streams chunks into a tempfile
// instead of allocating a single contiguous BufferSlice. Sized so typical
// shard/zero states still take the cheap heap path while the large MC
// state path is forced onto disk where RSS is bounded.
constexpr td::uint64 kHeapThreshold = 64ULL << 20;  // 64 MiB

// Live budget configuration. The processing/download caps are generous
// aggregate budgets, while the default single-file / returned-DAG caps stay
// fail-closed at 512 MiB until the true CellDb-backed importer lands. The
// peak resident memory budget per parse is forwarded to the streaming BoC
// importer. All fields are mutated together via
// configure_persistent_state_budgets so
// the reservation hot path can take a single snapshot under a mutex.
//
// Defaults:
//   max_download_bytes               16 GiB
//   max_processing_bytes             16 GiB (raised from the legacy 512 MiB)
//   max_single_file_bytes            512 MiB (matches returned-DAG cap)
//   max_resident_bytes_per_parse     256 MiB
//   max_returned_dag_bytes_per_parse  512 MiB
//   max_total_cell_bytes_per_parse    512 MiB
std::mutex g_budget_config_mu;
PersistentStateBudgetConfig g_budget_config;

PersistentStateBudgetConfig load_budget_config_locked() {
  std::lock_guard<std::mutex> g(g_budget_config_mu);
  return g_budget_config;
}

std::atomic<td::uint64> g_persistent_state_download_bytes{0};
std::atomic<td::uint64> g_persistent_state_processing_bytes{0};

// Single registered tempfile directory. Set once by the validator manager
// at start_up; read many times from the actor thread that drives
// DownloadState. Guarded by a mutex so a concurrent set/get pair from
// distinct threads is well-defined; in practice the set happens before
// any download starts.
std::mutex g_tempfile_dir_mu;
std::string g_tempfile_dir;

void release_persistent_state_download_memory(td::uint64 size) {
  if (size == 0) {
    return;
  }
  auto previous = g_persistent_state_download_bytes.fetch_sub(size, std::memory_order_acq_rel);
  // Every successful try_reserve_persistent_state_download_memory MUST
  // be paired with exactly one release. If we observe a smaller previous
  // value, a release is being driven without a matching reserve and the
  // counter would underflow; that is a programming bug, but in production
  // we clamp to zero to stay liveness-safe.
  if (previous < size) {
    LOG(ERROR) << "persistent state download budget underflow: prev=" << previous << " size=" << size;
    g_persistent_state_download_bytes.store(0, std::memory_order_release);
  }
}

// Validate a configured budget. Each cap must be positive and large
// enough to support at least the heap-threshold path; an obviously-
// undersized cap is refused so a misconfigured operator does not
// silently disable persistent-state downloads.
td::Status validate_budget_config(const PersistentStateBudgetConfig& cfg) {
  if (cfg.max_download_bytes < kHeapThreshold) {
    return td::Status::Error(PSTRING() << "max_download_bytes " << cfg.max_download_bytes
                                       << " < kHeapThreshold " << kHeapThreshold);
  }
  if (cfg.max_processing_bytes < kHeapThreshold) {
    return td::Status::Error(PSTRING() << "max_processing_bytes " << cfg.max_processing_bytes
                                       << " < kHeapThreshold " << kHeapThreshold);
  }
  if (cfg.max_single_file_bytes < kHeapThreshold) {
    return td::Status::Error(PSTRING() << "max_single_file_bytes " << cfg.max_single_file_bytes
                                       << " < kHeapThreshold " << kHeapThreshold);
  }
  if (cfg.max_resident_bytes_per_parse < (16ULL << 20)) {
    return td::Status::Error(PSTRING() << "max_resident_bytes_per_parse "
                                       << cfg.max_resident_bytes_per_parse << " < 16 MiB minimum");
  }
  if (cfg.max_single_file_bytes > cfg.max_download_bytes) {
    return td::Status::Error(PSTRING() << "max_single_file_bytes " << cfg.max_single_file_bytes
                                       << " > max_download_bytes " << cfg.max_download_bytes);
  }
  // H-02: the per-parse returned-DAG cap must be at least the resident
  // budget — anything smaller would refuse parses that the streaming
  // importer can already complete inside its resident window.
  if (cfg.max_returned_dag_bytes_per_parse < cfg.max_resident_bytes_per_parse) {
    return td::Status::Error(PSTRING() << "max_returned_dag_bytes_per_parse "
                                       << cfg.max_returned_dag_bytes_per_parse
                                       << " < max_resident_bytes_per_parse "
                                       << cfg.max_resident_bytes_per_parse);
  }
  // H-03: the cell-count, scaffolding and total-cell-bytes per-parse
  // caps must all be positive. Zero would defer to the streaming
  // importer's built-in defaults; we enforce the explicit-non-zero
  // contract here so an operator who opts in to budget overrides has
  // no way to accidentally request "unlimited".
  if (cfg.max_cells_per_parse == 0) {
    return td::Status::Error("max_cells_per_parse must be > 0");
  }
  if (cfg.max_scaffolding_bytes_per_parse == 0) {
    return td::Status::Error("max_scaffolding_bytes_per_parse must be > 0");
  }
  if (cfg.max_total_cell_bytes_per_parse == 0) {
    return td::Status::Error("max_total_cell_bytes_per_parse must be > 0");
  }
  if (cfg.max_total_cell_bytes_per_parse < cfg.max_returned_dag_bytes_per_parse) {
    return td::Status::Error(PSTRING() << "max_total_cell_bytes_per_parse "
                                       << cfg.max_total_cell_bytes_per_parse
                                       << " < max_returned_dag_bytes_per_parse "
                                       << cfg.max_returned_dag_bytes_per_parse);
  }
  // Phase A hard-block: the true CellDb-backed streaming importer
  // (Phase B) is not yet implemented. Flipping this flag would silently
  // re-enable the OOM-prone full-DAG parse path because the parser still
  // returns a complete DataCell DAG. Refuse the configuration so a
  // misconfigured operator cannot bypass max_returned_dag_bytes_per_parse
  // by toggling a flag that has no implementation behind it.
  if (cfg.enable_true_cell_db_streaming_import) {
    return td::Status::Error(
        "enable_true_cell_db_streaming_import is reserved for Phase B "
        "(true ExtCell-backed CellDb streaming importer). The current "
        "tos18 build only ships the fail-closed importer; setting this "
        "flag would silently re-enable the OOM-prone full-DAG path. "
        "Refusing.");
  }
  return td::Status::OK();
}

void release_persistent_state_processing_memory(td::uint64 size) {
  if (size == 0) {
    return;
  }
  auto previous = g_persistent_state_processing_bytes.fetch_sub(size, std::memory_order_acq_rel);
  if (previous < size) {
    LOG(ERROR) << "persistent state processing budget underflow: prev=" << previous << " size=" << size;
    g_persistent_state_processing_bytes.store(0, std::memory_order_release);
  }
}

}  // namespace

// MmapHandle: cross-platform read-only mmap holder.
//
// POSIX: owns the file descriptor and the page-aligned mapped pointer
// returned by mmap(2). The destructor calls munmap and close.
//
// Windows: owns the file HANDLE, the file-mapping HANDLE, and the
// MapViewOfFile pointer. The destructor calls UnmapViewOfFile,
// CloseHandle on the mapping, and CloseHandle on the file. This matches
// the POSIX path: read-only, fail-closed on size mismatch, RAII
// teardown. The file is opened with FILE_SHARE_READ so concurrent
// readers (e.g. archive ingest reading while parse is in flight) do
// not contend, and FILE_SHARE_DELETE is intentionally NOT requested so
// the underlying file cannot be unlinked while we hold the mapping.
//
// `data_` points at byte 0 of the requested range (which equals byte 0
// of the file in our usage), so callers receive a tight Slice without a
// separate offset accounting.
//
// Default-constructed (never opened) instances are safely destructible:
// reset() observes the sentinel handle values and skips system calls.
class MmapHandle {
 public:
  MmapHandle() = default;
  MmapHandle(const MmapHandle &) = delete;
  MmapHandle &operator=(const MmapHandle &) = delete;
  MmapHandle(MmapHandle &&other) noexcept
      : data_(other.data_),
        data_size_(other.data_size_),
#if defined(_WIN32)
        view_(other.view_),
        mapping_(other.mapping_),
        file_(other.file_)
#else
        addr_(other.addr_),
        length_(other.length_),
        fd_(other.fd_)
#endif
  {
    other.data_ = nullptr;
    other.data_size_ = 0;
#if defined(_WIN32)
    other.view_ = nullptr;
    other.mapping_ = nullptr;
    other.file_ = INVALID_HANDLE_VALUE;
#else
    other.addr_ = nullptr;
    other.length_ = 0;
    other.fd_ = -1;
#endif
  }
  MmapHandle &operator=(MmapHandle &&other) noexcept {
    if (this != &other) {
      reset();
      data_ = other.data_;
      data_size_ = other.data_size_;
#if defined(_WIN32)
      view_ = other.view_;
      mapping_ = other.mapping_;
      file_ = other.file_;
      other.view_ = nullptr;
      other.mapping_ = nullptr;
      other.file_ = INVALID_HANDLE_VALUE;
#else
      addr_ = other.addr_;
      length_ = other.length_;
      fd_ = other.fd_;
      other.addr_ = nullptr;
      other.length_ = 0;
      other.fd_ = -1;
#endif
      other.data_ = nullptr;
      other.data_size_ = 0;
    }
    return *this;
  }
  ~MmapHandle() {
    reset();
  }

  td::Slice as_slice() const noexcept {
    if (data_ == nullptr) {
      return td::Slice{};
    }
    return td::Slice(data_, data_size_);
  }

  bool is_open() const noexcept {
    return data_ != nullptr;
  }

#if defined(_WIN32)
  // Windows entry point: CreateFileW (read-only) + CreateFileMappingW
  // (PAGE_READONLY) + MapViewOfFile (FILE_MAP_READ). The file is opened
  // with FILE_SHARE_READ so other readers can co-open; FILE_SHARE_DELETE
  // is omitted so the file cannot be unlinked while we hold the mapping
  // (the POSIX path keeps the fd open for the same reason). On any
  // failure the partial state (file/mapping) is rolled back via
  // CloseHandle so an error path leaves no leaked handles.
  static td::Result<MmapHandle> open_readonly(const std::string &path, td::uint64 expected_size) {
    if (expected_size == 0) {
      return td::Status::Error("cannot mmap zero-byte persistent state file");
    }
    // UTF-8 -> UTF-16 conversion via MultiByteToWideChar. Persistent-state
    // tempfile paths are produced internally and contain only ASCII, but
    // we use the wide API so a future relocation of the tempfile root
    // under a non-ASCII user directory still works.
    int wlen = ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (wlen <= 0) {
      auto err = ::GetLastError();
      return td::Status::Error(PSTRING() << "mmap path UTF-8 conversion failed for " << path
                                         << ": GetLastError=" << err);
    }
    std::wstring wpath(static_cast<std::size_t>(wlen), L'\0');
    int conv = ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), wlen);
    if (conv <= 0) {
      auto err = ::GetLastError();
      return td::Status::Error(PSTRING() << "mmap path UTF-8 conversion failed for " << path
                                         << ": GetLastError=" << err);
    }
    // wpath now ends in a null from the conversion; strip it from the
    // logical length so size() reflects the path bytes. CreateFileW does
    // not care either way, but a clean wstring is easier to debug.
    if (!wpath.empty() && wpath.back() == L'\0') {
      wpath.pop_back();
    }

    HANDLE file = ::CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
      auto err = ::GetLastError();
      return td::Status::Error(PSTRING() << "mmap CreateFileW failed for " << path
                                         << ": GetLastError=" << err);
    }
    LARGE_INTEGER fsize;
    fsize.QuadPart = 0;
    if (!::GetFileSizeEx(file, &fsize)) {
      auto err = ::GetLastError();
      ::CloseHandle(file);
      return td::Status::Error(PSTRING() << "mmap GetFileSizeEx failed for " << path
                                         << ": GetLastError=" << err);
    }
    if (fsize.QuadPart < 0 || static_cast<td::uint64>(fsize.QuadPart) != expected_size) {
      ::CloseHandle(file);
      return td::Status::Error(PSTRING() << "mmap size mismatch for " << path << ": expected "
                                         << expected_size << " got " << fsize.QuadPart);
    }
    // Pass the size explicitly to CreateFileMappingW: passing 0 would
    // ask Windows to use the current file size at call time, which is
    // racy if the file is resized concurrently. We have already verified
    // size == expected_size above, so freeze that value.
    DWORD size_hi = static_cast<DWORD>((expected_size >> 32) & 0xFFFFFFFFULL);
    DWORD size_lo = static_cast<DWORD>(expected_size & 0xFFFFFFFFULL);
    HANDLE mapping = ::CreateFileMappingW(file, nullptr, PAGE_READONLY, size_hi, size_lo, nullptr);
    if (mapping == nullptr) {
      auto err = ::GetLastError();
      ::CloseHandle(file);
      return td::Status::Error(PSTRING() << "mmap CreateFileMappingW failed for " << path
                                         << ": GetLastError=" << err);
    }
    LPVOID view = ::MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(expected_size));
    if (view == nullptr) {
      auto err = ::GetLastError();
      ::CloseHandle(mapping);
      ::CloseHandle(file);
      return td::Status::Error(PSTRING() << "mmap MapViewOfFile failed for " << path
                                         << ": GetLastError=" << err);
    }
    MmapHandle h;
    h.view_ = view;
    h.mapping_ = mapping;
    h.file_ = file;
    h.data_ = static_cast<const char *>(view);
    h.data_size_ = static_cast<std::size_t>(expected_size);
    return h;
  }
#else
  // POSIX entry point: open `path`, mmap PROT_READ + MAP_PRIVATE for the
  // full file, return the handle on success. The file descriptor is held
  // for the lifetime of the mapping; closing it does not invalidate the
  // mapping (POSIX semantics) but we keep it open as a defensive measure
  // so the underlying inode cannot be reaped by the filesystem while we
  // are still reading from the mapped pages.
  static td::Result<MmapHandle> open_readonly(const std::string &path, td::uint64 expected_size) {
    if (expected_size == 0) {
      return td::Status::Error("cannot mmap zero-byte persistent state file");
    }
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      auto err = errno;
      return td::Status::Error(PSTRING() << "mmap open() failed for " << path << ": "
                                         << std::strerror(err) << " (errno=" << err << ")");
    }
    struct stat st;
    if (::fstat(fd, &st) != 0) {
      auto err = errno;
      ::close(fd);
      return td::Status::Error(PSTRING() << "mmap fstat() failed for " << path << ": "
                                         << std::strerror(err) << " (errno=" << err << ")");
    }
    if (st.st_size < 0 || static_cast<td::uint64>(st.st_size) != expected_size) {
      ::close(fd);
      return td::Status::Error(PSTRING() << "mmap size mismatch for " << path << ": expected "
                                         << expected_size << " got " << st.st_size);
    }
    // map the full file.
    void *addr = ::mmap(nullptr, static_cast<std::size_t>(expected_size), PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
    if (addr == MAP_FAILED) {
      auto err = errno;
      ::close(fd);
      return td::Status::Error(PSTRING() << "mmap() failed for " << path << ": "
                                         << std::strerror(err) << " (errno=" << err << ")");
    }
    MmapHandle h;
    h.addr_ = addr;
    h.length_ = static_cast<std::size_t>(expected_size);
    h.data_ = static_cast<const char *>(addr);
    h.data_size_ = static_cast<std::size_t>(expected_size);
    h.fd_ = fd;
    return h;
  }
#endif

 private:
  void reset() noexcept {
#if defined(_WIN32)
    if (view_ != nullptr) {
      if (!::UnmapViewOfFile(view_)) {
        auto err = ::GetLastError();
        LOG(WARNING) << "UnmapViewOfFile failed: GetLastError=" << err;
      }
      view_ = nullptr;
    }
    if (mapping_ != nullptr) {
      if (!::CloseHandle(mapping_)) {
        auto err = ::GetLastError();
        LOG(WARNING) << "CloseHandle on mmap mapping failed: GetLastError=" << err;
      }
      mapping_ = nullptr;
    }
    if (file_ != INVALID_HANDLE_VALUE) {
      if (!::CloseHandle(file_)) {
        auto err = ::GetLastError();
        LOG(WARNING) << "CloseHandle on mmap file failed: GetLastError=" << err;
      }
      file_ = INVALID_HANDLE_VALUE;
    }
#else
    if (addr_ != nullptr && length_ > 0) {
      auto rc = ::munmap(addr_, length_);
      if (rc != 0) {
        auto err = errno;
        LOG(WARNING) << "munmap failed: " << std::strerror(err) << " (errno=" << err << ")";
      }
    }
    if (fd_ >= 0) {
      auto rc = ::close(fd_);
      if (rc != 0) {
        auto err = errno;
        LOG(WARNING) << "close on mmap fd failed: " << std::strerror(err) << " (errno=" << err << ")";
      }
    }
    addr_ = nullptr;
    length_ = 0;
    fd_ = -1;
#endif
    data_ = nullptr;
    data_size_ = 0;
  }

  const char *data_{nullptr};
  std::size_t data_size_{0};
#if defined(_WIN32)
  // INVALID_HANDLE_VALUE is the OS sentinel for "no file handle"; using
  // it for default-constructed instances lets ~reset() distinguish
  // "never opened" from "opened then moved-from" without an extra flag.
  void *view_{nullptr};
  void *mapping_{nullptr};
  void *file_{INVALID_HANDLE_VALUE};
#else
  void *addr_{nullptr};
  std::size_t length_{0};
  int fd_{-1};
#endif
};

td::Result<td::Slice> mmap_persistent_state_file(BudgetedStateFile &f) {
  return f.mmap_view();
}

// Out-of-line BudgetedStateFile special-member functions. Required so the
// unique_ptr<MmapHandle> destructor sees a complete MmapHandle type at
// the point std::default_delete is instantiated (the class is defined
// above in this TU).
BudgetedStateFile::BudgetedStateFile() noexcept = default;

BudgetedStateFile::BudgetedStateFile(std::string p, td::uint64 s,
                                     std::shared_ptr<PersistentStateDownloadReservation> r,
                                     bool temp) noexcept
    : path(std::move(p)), size(s), reservation(std::move(r)), is_temp(temp) {
}

BudgetedStateFile::BudgetedStateFile(BudgetedStateFile &&other) noexcept
    : path(std::move(other.path)),
      size(other.size),
      reservation(std::move(other.reservation)),
      is_temp(other.is_temp),
      mmap_(std::move(other.mmap_)) {
  other.size = 0;
  other.is_temp = false;
}

BudgetedStateFile &BudgetedStateFile::operator=(BudgetedStateFile &&other) noexcept {
  if (this != &other) {
    reset();
    path = std::move(other.path);
    size = other.size;
    reservation = std::move(other.reservation);
    is_temp = other.is_temp;
    mmap_ = std::move(other.mmap_);
    other.size = 0;
    other.is_temp = false;
  }
  return *this;
}

BudgetedStateFile::~BudgetedStateFile() {
  reset();
}

td::Result<td::Slice> BudgetedStateFile::mmap_view() noexcept {
  if (path.empty() || size == 0) {
    return td::Status::Error("BudgetedStateFile is empty: cannot mmap");
  }
  if (mmap_ && mmap_->is_open()) {
    return mmap_->as_slice();
  }
  // Cross-platform: MmapHandle::open_readonly is implemented for both
  // POSIX (mmap(2)) and Windows (CreateFileMappingW + MapViewOfFile).
  // The path is identical from the caller's perspective: a successful
  // open returns a held handle whose as_slice() is valid until the
  // BudgetedStateFile is reset.
  TRY_RESULT(handle, MmapHandle::open_readonly(path, size));
  std::unique_ptr<MmapHandle> holder;
  try {
    holder = std::make_unique<MmapHandle>(std::move(handle));
  } catch (...) {
    // make_unique failure: handle is moved-from at this point; its dtor
    // runs at scope-exit and is a no-op (state was reset by the move).
    return td::Status::Error("cannot allocate mmap handle holder");
  }
  mmap_ = std::move(holder);
  return mmap_->as_slice();
}

bool try_reserve_persistent_state_download_memory(td::uint64 size) {
  // Zero-sized reservations are admissible no-ops. They keep callers simple
  // (e.g. an empty zero-state-from-disk fast path) without contending on
  // the global CAS.
  if (size == 0) {
    return true;
  }
  auto cap = load_budget_config_locked().max_download_bytes;
  auto current = g_persistent_state_download_bytes.load(std::memory_order_relaxed);
  for (;;) {
    // Defensive: refuse single reservations larger than the total cap and
    // any reservation that would overflow the running counter. The check
    // is written so cap - size never underflows.
    if (size > cap || current > cap - size) {
      return false;
    }
    if (g_persistent_state_download_bytes.compare_exchange_weak(
            current, current + size, std::memory_order_acq_rel, std::memory_order_relaxed)) {
      return true;
    }
  }
}

bool try_reserve_persistent_state_processing_memory(td::uint64 size) {
  if (size == 0) {
    return true;
  }
  auto cap = load_budget_config_locked().max_processing_bytes;
  auto current = g_persistent_state_processing_bytes.load(std::memory_order_relaxed);
  for (;;) {
    if (size > cap || current > cap - size) {
      return false;
    }
    if (g_persistent_state_processing_bytes.compare_exchange_weak(
            current, current + size, std::memory_order_acq_rel, std::memory_order_relaxed)) {
      return true;
    }
  }
}

td::Status validate_persistent_state_size(td::uint64 size) {
  if (size == 0) {
    return td::Status::Error("persistent state has zero size");
  }
  auto cap = load_budget_config_locked().max_single_file_bytes;
  if (size > cap) {
    return td::Status::Error(PSTRING() << "persistent state too large: " << size << " > " << cap);
  }
  return td::Status::OK();
}

td::uint64 persistent_state_heap_threshold_bytes() {
  return kHeapThreshold;
}

td::uint64 persistent_state_max_file_bytes() {
  return load_budget_config_locked().max_single_file_bytes;
}

td::uint64 persistent_state_total_download_budget_bytes() {
  return load_budget_config_locked().max_download_bytes;
}

td::Status configure_persistent_state_budgets(PersistentStateBudgetConfig cfg) {
  auto status = validate_budget_config(cfg);
  if (status.is_error()) {
    // Preserve the previous configuration on rejection. The caller is
    // expected to surface this Status (e.g. fail node startup); we still
    // log it here as a defense-in-depth backstop for any caller that
    // accidentally drops the return value.
    LOG(ERROR) << "rejecting invalid PersistentStateBudgetConfig: " << status
               << "; keeping previous configuration";
    return status;
  }
  std::lock_guard<std::mutex> g(g_budget_config_mu);
  g_budget_config = cfg;
  return td::Status::OK();
}

PersistentStateBudgetConfig persistent_state_budget_config() {
  return load_budget_config_locked();
}

void set_persistent_state_tempfile_dir(std::string dir) {
  std::lock_guard<std::mutex> g(g_tempfile_dir_mu);
  g_tempfile_dir = std::move(dir);
}

std::string get_persistent_state_tempfile_dir() {
  std::lock_guard<std::mutex> g(g_tempfile_dir_mu);
  return g_tempfile_dir;
}

// The reservation destructor is the single point of budget release: it runs
// exactly once when the last shared_ptr<PersistentStateDownloadReservation>
// reference is dropped (downstream may keep the buffer alive past the
// DownloadState actor's lifetime).
PersistentStateDownloadReservation::~PersistentStateDownloadReservation() {
  release_persistent_state_download_memory(bytes);
}

// Mirror destructor for the processing budget. The processing reservation
// is a separate budget covering transient parse/persist clones; releasing
// it here is the single point that returns those bytes to the global
// processing counter, regardless of whether the parse succeeded or failed.
PersistentStateProcessingReservation::~PersistentStateProcessingReservation() {
  release_persistent_state_processing_memory(bytes);
}

// BudgetedStateFile cleanup: unlinks the on-disk tempfile if `is_temp` is
// still set when the struct is dropped. This covers both the producer's
// abort path (drop the partial tempfile) and the consumer's "I'm done
// reading" path. The reservation drop is implicit via the shared_ptr
// destructor.
//
// Order matters: drop the mmap first (munmap) so the kernel releases
// its hold on the file; then unlink, so the inode is reaped immediately
// rather than lingering as a deleted-but-mapped file. Finally drop the
// reservation, which returns the bytes to the global download budget.
void BudgetedStateFile::reset() noexcept {
  // Drop the mmap (munmap + close fd) before unlink: on some platforms
  // ‹unlink while mapped› is fine but produces a deleted-but-still-open
  // inode; we explicitly serialize munmap → unlink to keep cleanup
  // observable.
  mmap_.reset();
  if (is_temp && !path.empty()) {
    auto status = td::unlink(path);
    if (status.is_error()) {
      // Not fatal: at worst we leave residue that the startup
      // cleanup_persistent_state_tempfiles() helper will sweep on
      // the next process start.
      LOG(WARNING) << "failed to unlink partial persistent state file " << path << ": "
                   << status;
    }
  }
  is_temp = false;
  path.clear();
  size = 0;
  reservation.reset();
}

// Defense-in-depth implementation. See the contract documented in the
// header above the prototype. The function:
//   1. Walks `tempfile_root` for *.partial files (recursively).
//   2. Stats each candidate and skips files whose mtime is newer than
//      `now - min_age_seconds`. The skip is logged at DEBUG level so a
//      future maintainer can see why a file survived.
//   3. Unlinks every other *.partial file and logs the action with the
//      file age (so an operator can sanity-check what was swept).
//
// Race-safety reasoning: when called at validator-engine startup, no
// in-process writer can exist. The mtime guard is a backstop for
// (a) concurrent maintenance tools and (b) future runtime callers
// that the audit explicitly flagged as a hazard. Setting
// `min_age_seconds == 0` opts out of the guard for callers that have
// proved no concurrent writer exists.
td::Status cleanup_persistent_state_tempfiles(td::CSlice tempfile_root, td::uint64 min_age_seconds) {
  if (tempfile_root.empty()) {
    return td::Status::OK();
  }
  auto stat = td::stat(tempfile_root);
  if (stat.is_error()) {
    // No tempfile root yet: nothing to clean. Treat as success so the
    // caller does not log a startup error on a fresh DB.
    return td::Status::OK();
  }
  // Snapshot the wall-clock once per cleanup so all per-file age checks
  // use the same reference point. td::Clocks::system() returns seconds
  // as a double; we work in 64-bit nanoseconds to match the resolution
  // of td::Stat::mtime_nsec_ exactly.
  const double now_seconds = td::Clocks::system();
  // Negative wall-clock (host clock pre-epoch / unset) is implausible
  // on a real validator host, but it would underflow the conversion to
  // uint64. Clamp at 0 in that case so the age guard simply reduces to
  // "skip everything not strictly older than min_age_seconds, treating
  // the world as if it just started".
  const td::uint64 now_nsec = now_seconds < 0.0
                                  ? 0ULL
                                  : static_cast<td::uint64>(now_seconds * 1e9);
  // Convert min_age_seconds to nanoseconds with a saturating multiply
  // so a pathological caller passing UINT64_MAX cannot overflow.
  td::uint64 min_age_nsec = 0;
  if (min_age_seconds > 0) {
    constexpr td::uint64 kNsecPerSec = 1000000000ULL;
    if (min_age_seconds > std::numeric_limits<td::uint64>::max() / kNsecPerSec) {
      min_age_nsec = std::numeric_limits<td::uint64>::max();
    } else {
      min_age_nsec = min_age_seconds * kNsecPerSec;
    }
  }
  return td::walk_path(tempfile_root, [now_nsec, min_age_nsec](td::CSlice path, td::WalkPath::Type type) {
    if (type != td::WalkPath::Type::RegularFile) {
      return td::WalkPath::Action::Continue;
    }
    auto str = path.str();
    constexpr auto suffix = ".partial";
    constexpr std::size_t suffix_len = sizeof(".partial") - 1;
    if (str.size() < suffix_len) {
      return td::WalkPath::Action::Continue;
    }
    if (std::memcmp(str.data() + str.size() - suffix_len, suffix, suffix_len) != 0) {
      return td::WalkPath::Action::Continue;
    }

    // Age guard: skip files younger than the configured threshold.
    // Statting before unlinking is also a cheap sanity check that the
    // file still exists (another caller may have raced ahead).
    if (min_age_nsec > 0) {
      auto file_stat = td::stat(str);
      if (file_stat.is_error()) {
        // File vanished between walk and stat — nothing to do.
        return td::WalkPath::Action::Continue;
      }
      td::uint64 mtime_nsec = file_stat.ok().mtime_nsec_;
      // age_nsec computed via saturating subtraction so a clock skew
      // (file mtime > now) does not wrap around and accidentally
      // unlink an in-progress file.
      td::uint64 age_nsec = mtime_nsec > now_nsec ? 0 : (now_nsec - mtime_nsec);
      if (age_nsec < min_age_nsec) {
        LOG(INFO) << "skipping recent persistent state tempfile " << str << " (age "
                  << (age_nsec / 1000000000ULL) << "s < threshold "
                  << (min_age_nsec / 1000000000ULL) << "s)";
        return td::WalkPath::Action::Continue;
      }
    }

    // Final pre-unlink stat for the age log line. If the prior stat
    // already ran (min_age_nsec > 0) we re-stat here for the log; the
    // duplicate IO is irrelevant on the cleanup path which runs once
    // at startup.
    td::uint64 age_seconds = 0;
    if (auto file_stat = td::stat(str); file_stat.is_ok()) {
      td::uint64 mtime_nsec = file_stat.ok().mtime_nsec_;
      td::uint64 age_nsec = mtime_nsec > now_nsec ? 0 : (now_nsec - mtime_nsec);
      age_seconds = age_nsec / 1000000000ULL;
    }
    auto unlink_status = td::unlink(str);
    if (unlink_status.is_error()) {
      LOG(WARNING) << "failed to remove residual persistent state tempfile " << str << ": "
                   << unlink_status;
    } else {
      LOG(WARNING) << "removed residual persistent state tempfile " << str << " (age "
                   << age_seconds << "s)";
    }
    return td::WalkPath::Action::Continue;
  });
}

// CellDbStreamingSink: minimal counting / per-cell-validation sink that
// flows behind vm::std_boc_deserialize_from_file_bounded. The sink is
// the load-bearing extension point that lets the OnDisk parse path
// surface per-cell errors (currently: null cells, sub-callback
// rejection) BEFORE the streaming importer returns the root. The
// downstream archive store + set_block_state still owns the actual
// CellDb commit; see comment in state-download-buffer.h for the full
// memory contract.
td::Status CellDbStreamingSink::begin() {
  if (begun_) {
    return td::Status::Error("CellDbStreamingSink::begin called twice on same sink");
  }
  if (finished_ || aborted_) {
    return td::Status::Error("CellDbStreamingSink::begin called after finish/abort");
  }
  begun_ = true;
  cell_count_.store(0, std::memory_order_release);
  return td::Status::OK();
}

td::Status CellDbStreamingSink::persist(td::Ref<vm::Cell> cell) {
  if (!begun_) {
    return td::Status::Error("CellDbStreamingSink::persist called before begin");
  }
  if (finished_ || aborted_) {
    return td::Status::Error("CellDbStreamingSink::persist called after finish/abort");
  }
  if (cell.is_null()) {
    return td::Status::Error("CellDbStreamingSink::persist received null cell");
  }
  cell_count_.fetch_add(1, std::memory_order_acq_rel);
  if (on_cell_) {
    auto status = on_cell_(std::move(cell));
    if (status.is_error()) {
      return status;
    }
  }
  return td::Status::OK();
}

td::Status CellDbStreamingSink::finish(const vm::Cell::Hash &root_hash) {
  if (!begun_) {
    return td::Status::Error("CellDbStreamingSink::finish called before begin");
  }
  if (finished_) {
    return td::Status::Error("CellDbStreamingSink::finish called twice");
  }
  if (aborted_) {
    return td::Status::Error("CellDbStreamingSink::finish called after abort");
  }
  finished_ = true;
  root_hash_ = root_hash;
  return td::Status::OK();
}

void CellDbStreamingSink::abort() {
  // Idempotent. The importer's abort guard guarantees a single call,
  // but we defend in depth in case a future caller wires a path that
  // could trigger a second abort (e.g. a wrapper sink).
  if (aborted_ || finished_) {
    return;
  }
  aborted_ = true;
}

namespace testing {

td::uint64 test_get_persistent_state_download_bytes() {
  return g_persistent_state_download_bytes.load(std::memory_order_acquire);
}

bool test_try_reserve_persistent_state_download_memory(td::uint64 size) {
  return try_reserve_persistent_state_download_memory(size);
}

td::uint64 test_get_persistent_state_processing_bytes() {
  return g_persistent_state_processing_bytes.load(std::memory_order_acquire);
}

bool test_try_reserve_persistent_state_processing_memory(td::uint64 size) {
  return try_reserve_persistent_state_processing_memory(size);
}

}  // namespace testing

}  // namespace fullnode
}  // namespace validator
}  // namespace tos
