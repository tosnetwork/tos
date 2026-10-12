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
#include <limits>

#include "td/utils/FileLog.h"
#include "td/utils/Slice.h"
#include "td/utils/common.h"
#include "td/utils/logging.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/StdStreams.h"
#include "td/utils/port/path.h"

namespace td {

Status FileLog::init(string path, int64 rotate_threshold, bool redirect_stderr, int32 keep_rotated) {
  if (path.empty()) {
    return Status::Error("Log file path can't be empty");
  }
  if (path == path_) {
    set_rotate_threshold(rotate_threshold);
    set_keep_rotated(keep_rotated);
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
// nothing that matters.
void FileLog::prune_rotated() {
  if (path_.empty()) {
    return;
  }
  for (int32 k = keep_rotated_; k <= kMaxKeepRotated; k++) {
    unlink(PSLICE() << path_ << ".old." << k).ignore();
  }
}

// Makes room for a new <path>.old: <path>.old.<k-1> becomes <path>.old.<k>
// for the kept files, oldest first, and <path>.old becomes <path>.old.1. A
// file that does not exist yet (the first rotations) is skipped, and the
// oldest kept file is overwritten by the rename, so at most keep_rotated_
// rotated files remain.
void FileLog::shift_rotated() {
  prune_rotated();
  for (int32 k = keep_rotated_ - 1; k >= 2; k--) {
    rename(PSLICE() << path_ << ".old." << (k - 1), PSLICE() << path_ << ".old." << k).ignore();
  }
  if (keep_rotated_ >= 2) {
    rename(PSLICE() << path_ << ".old", PSLICE() << path_ << ".old.1").ignore();
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
