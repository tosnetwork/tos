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
#include <atomic>
#include <cerrno>
#include <limits>

#include "td/utils/FileLog.h"
#include "td/utils/Slice.h"
#include "td/utils/common.h"
#include "td/utils/logging.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/StdStreams.h"
#include "td/utils/port/config.h"
#include "td/utils/port/path.h"

namespace td {

namespace {

std::atomic<uint64> rotation_failure_count{0};
std::atomic<uint64> prune_failure_count{0};

// The log cannot log through itself while it rotates, so a failure goes to the
// process stderr as one line, written straight to the fd.
void report_to_stderr(Slice what, const Status &error) {
  auto &fd = Stderr();
  if (fd.empty()) {
    return;
  }
  string line = PSTRING() << "log rotation: " << what << ": " << error << '\n';
  // NOLINTNEXTLINE(bugprone-unused-return-value): this is the last resort for reporting; a failed write has nowhere left to go, and the counter already holds the failure
  fd.write(line).ignore();
}

}  // namespace

uint64 FileLog::rotation_failures() {
  return rotation_failure_count.load(std::memory_order_relaxed);
}

uint64 FileLog::prune_failures() {
  return prune_failure_count.load(std::memory_order_relaxed);
}

void FileLog::report_prune_failure(const Status &error) {
  prune_failure_count.fetch_add(1, std::memory_order_relaxed);
  report_to_stderr("stale rotated files not removed", error);
}

bool FileLog::is_missing_file_error(const Status &error) {
  if (error.is_ok()) {
    return false;
  }
#if TD_PORT_POSIX
  return error.code() == ENOENT;
#elif TD_PORT_WINDOWS
  return error.code() == ERROR_FILE_NOT_FOUND || error.code() == ERROR_PATH_NOT_FOUND;
#else
  return false;
#endif
}

Status FileLog::init(string path, int64 rotate_threshold, bool redirect_stderr, int32 keep_rotated) {
  if (path.empty()) {
    return Status::Error("Log file path can't be empty");
  }
  if (path == path_) {
    set_rotate_threshold(rotate_threshold);
    set_keep_rotated(keep_rotated);
    // A smaller kept number takes effect now, not at the next rotation, which
    // a quiet log may never reach.
    prune_rotated();
    return Status::OK();
  }

  TRY_RESULT(fd, FileFd::open(path, FileFd::Create | FileFd::Write | FileFd::Append));

  fd_.close();
  fd_ = std::move(fd);
  if (!Stderr().empty() && redirect_stderr) {
    fd_.get_native_fd().duplicate(Stderr().get_native_fd()).ignore();
  }

  auto r_path = realpath(path, true);
  if (r_path.is_error()) {
    path_ = std::move(path);
  } else {
    path_ = r_path.move_as_ok();
  }
  TRY_RESULT_ASSIGN(size_, fd_.get_size());
  rotate_threshold_ = rotate_threshold;
  set_keep_rotated(keep_rotated);
  redirect_stderr_ = redirect_stderr;
  prune_rotated();
  return Status::OK();
}

Slice FileLog::get_path() const {
  return path_;
}

vector<string> FileLog::get_file_paths() {
  vector<string> result;
  if (!path_.empty()) {
    result.push_back(path_);
    result.push_back(PSTRING() << path_ << ".old");
    for (int32 i = 1; i < keep_rotated_; i++) {
      result.push_back(PSTRING() << path_ << ".old." << i);
    }
  }
  return result;
}

void FileLog::set_rotate_threshold(int64 rotate_threshold) {
  rotate_threshold_ = rotate_threshold;
}

int64 FileLog::get_rotate_threshold() const {
  return rotate_threshold_;
}

void FileLog::set_keep_rotated(int32 keep_rotated) {
  keep_rotated_ = keep_rotated < 1 ? 1 : keep_rotated;
}

int32 FileLog::get_keep_rotated() const {
  return keep_rotated_;
}

// Removes rotated files beyond the kept number (<path>.old.<keep_rotated_> and
// up), left behind by a run that kept more. Every index up to the largest
// number an engine accepts is tried: a run interrupted mid-shift, or files
// removed by hand, can leave gaps, so a missing index does not end the scan.
// It runs at start and once per rotation, so the unlinks of absent files cost
// nothing that matters. A missing file is the normal case; any other failure
// is counted and reported, and the scan goes on, since each index is
// independent.
void FileLog::prune_rotated() {
  if (path_.empty()) {
    return;
  }
  for (int32 k = keep_rotated_; k <= kMaxKeepRotated; k++) {
    auto status = unlink(PSLICE() << path_ << ".old." << k);
    if (status.is_error() && !is_missing_file_error(status)) {
      report_prune_failure(status);
    }
  }
}

// Makes room for a new <path>.old: <path>.old.<k-1> becomes <path>.old.<k>
// for the kept files, oldest first, and <path>.old becomes <path>.old.1. A
// file that does not exist yet (the first rotations) is skipped, and the
// oldest kept file is overwritten by the rename, so at most keep_rotated_
// rotated files remain.
//
// Any other rename failure stops the shift there. Going on would let the
// remaining renames move newer generations over files that were never moved
// out of the way, so the archive would silently hold the wrong generations.
// The caller still renames the current file onto <path>.old, overwriting the
// newest rotated generation, which the stopped shift left in place: losing
// that one generation is the price of keeping the disk bounded, which matters
// more than any single archive, because an unbounded log can fill the disk a
// validator needs to run.
void FileLog::shift_rotated() {
  prune_rotated();
  // Returns whether the shift may go on.
  auto shift = [](CSlice from, CSlice to) {
    auto status = rename(from, to);
    if (status.is_ok() || is_missing_file_error(status)) {
      return true;
    }
    rotation_failure_count.fetch_add(1, std::memory_order_relaxed);
    report_to_stderr("rotated files not shifted, the newest rotated file is overwritten", status);
    return false;
  };
  for (int32 k = keep_rotated_ - 1; k >= 2; k--) {
    if (!shift(PSLICE() << path_ << ".old." << (k - 1), PSLICE() << path_ << ".old." << k)) {
      return;
    }
  }
  if (keep_rotated_ >= 2) {
    // The last shift: a failure is counted and reported inside, and nothing
    // follows that it would have to stop.
    shift(PSLICE() << path_ << ".old", PSLICE() << path_ << ".old.1");
  }
}

void FileLog::append(CSlice cslice, int log_level) {
  Slice slice = cslice;
  while (!slice.empty()) {
    auto r_size = fd_.write(slice);
    if (r_size.is_error()) {
      process_fatal_error(PSLICE() << r_size.error() << " in " << __FILE__ << " at " << __LINE__);
    }
    auto written = r_size.ok();
    size_ += static_cast<int64>(written);
    slice.remove_prefix(written);
  }
  if (log_level == VERBOSITY_NAME(FATAL)) {
    process_fatal_error(cslice);
  }

  if (size_ > rotate_threshold_ || want_rotate_.load(std::memory_order_relaxed)) {
    shift_rotated();
    auto status = rename(path_, PSLICE() << path_ << ".old");
    if (status.is_error()) {
      process_fatal_error(PSLICE() << status.error() << " in " << __FILE__ << " at " << __LINE__);
    }
    do_rotate();
  }
}

void FileLog::rotate() {
  if (path_.empty()) {
    return;
  }
  do_rotate();
}

void FileLog::lazy_rotate() {
  want_rotate_ = true;
}

void FileLog::do_rotate() {
  want_rotate_ = false;
  td::ScopedDisableLog disable_log;  // to ensure that nothing will be printed to the closed log
  CHECK(!path_.empty());
  fd_.close();
  auto r_fd = FileFd::open(path_, FileFd::Create | FileFd::Truncate | FileFd::Write);
  if (r_fd.is_error()) {
    process_fatal_error(PSLICE() << r_fd.error() << " in " << __FILE__ << " at " << __LINE__);
  }
  fd_ = r_fd.move_as_ok();
  if (!Stderr().empty() && redirect_stderr_) {
    fd_.get_native_fd().duplicate(Stderr().get_native_fd()).ignore();
  }
  size_ = 0;
}

Result<td::unique_ptr<LogInterface>> FileLog::create(string path, int64 rotate_threshold, bool redirect_stderr,
                                                     int32 keep_rotated) {
  auto l = make_unique<FileLog>();
  TRY_STATUS(l->init(std::move(path), rotate_threshold, redirect_stderr, keep_rotated));
  return std::move(l);
}

}  // namespace td
