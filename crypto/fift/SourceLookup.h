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
#include <cstdlib>
#include <iostream>

#include "td/utils/Status.h"
#include "td/utils/Time.h"

namespace fift {
class FileLoader {
 public:
  virtual ~FileLoader() = default;
  struct File {
    std::string data;
    std::string path;
  };
  virtual td::Result<File> read_file(td::CSlice filename) = 0;
  virtual td::Status write_file(td::CSlice filename, td::Slice data) = 0;
  virtual td::Result<File> read_file_part(td::CSlice filename, td::int64 size, td::int64 offset) = 0;
  virtual bool is_file_exists(td::CSlice filename) = 0;
};

class OsFileLoader : public FileLoader {
 public:
  td::Result<File> read_file(td::CSlice filename) override;
  td::Status write_file(td::CSlice filename, td::Slice data) override;
  td::Result<File> read_file_part(td::CSlice filename, td::int64 size, td::int64 offset) override;
  bool is_file_exists(td::CSlice filename) override;
};

class OsTime {
 public:
  virtual ~OsTime() = default;
  virtual td::uint32 now() = 0;
};

//TODO: rename SourceLookup
class SourceLookup {
 public:
  SourceLookup() = default;
  explicit SourceLookup(std::unique_ptr<FileLoader> file_loader, std::unique_ptr<OsTime> os_time = {})
      : file_loader_(std::move(file_loader)), os_time_(std::move(os_time)) {
  }
  void set_os_time(std::unique_ptr<OsTime> os_time) {
    os_time_ = std::move(os_time);
  }
  void add_include_path(td::string path);
  td::Result<FileLoader::File> lookup_source(std::string filename, std::string current_dir);

  td::Result<FileLoader::File> read_file(td::CSlice path) {
    return file_loader_->read_file(path);
  }
  td::Status write_file(td::CSlice path, td::Slice data) {
    return file_loader_->write_file(path, data);
  }
  td::Result<FileLoader::File> read_file_part(td::CSlice filename, td::int64 size, td::int64 offset) {
    return file_loader_->read_file_part(filename, size, offset);
  }
  bool is_file_exists(td::CSlice filename) {
    return file_loader_->is_file_exists(filename);
  }
  td::uint32 now() {
    if (os_time_) {
      return os_time_->now();
    }
    // Reproducible-build override: when SOURCE_DATE_EPOCH is set (e.g. by the
    // zerostate regression harness, which shells out to create-state and so
    // cannot inject an OsTime), use it so genesis `now`/gen_utime is
    // deterministic. Production runs leave it unset → wall-clock as before.
    if (const char* sde = std::getenv("SOURCE_DATE_EPOCH")) {
      char* end = nullptr;
      unsigned long long v = std::strtoull(sde, &end, 10);
      if (end != sde && *end == '\0') {
        return static_cast<td::uint32>(v);
      }
    }
    return static_cast<td::uint32>(td::Clocks::system());
  }

 protected:
  std::unique_ptr<FileLoader> file_loader_;
  std::unique_ptr<OsTime> os_time_;
  std::vector<std::string> source_include_path_;
};
}  // namespace fift
