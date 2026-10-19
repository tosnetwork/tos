/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <optional>
#include <string>
#include <sys/stat.h>

#include "td/utils/Status.h"

namespace tos::validator::consensus {

// A resumable, one-entry-at-a-time listing of one directory. Unlike a recursive
// walk with a callback, the caller can stop between entries, wait for
// asynchronous work, and continue later, while holding only the cursor: the
// listing itself is never collected. Entries are reported with whether they are
// real directories (a symlink to a directory is not one).
class DirectoryCursor {
 public:
  struct Entry {
    std::string name;
    bool is_directory = false;
  };
  // The metadata lookup of an entry; fstatat(2) unless a test substitutes it.
  using StatFn = int (*)(int dirfd, const char* name, struct stat* st, int flags);

  DirectoryCursor() = default;
  DirectoryCursor(const DirectoryCursor&) = delete;
  DirectoryCursor& operator=(const DirectoryCursor&) = delete;
  DirectoryCursor(DirectoryCursor&& other) noexcept : dir_(other.dir_), stat_(other.stat_) {
    other.dir_ = nullptr;
  }
  DirectoryCursor& operator=(DirectoryCursor&& other) noexcept {
    if (this != &other) {
      close();
      dir_ = other.dir_;
      stat_ = other.stat_;
      other.dir_ = nullptr;
    }
    return *this;
  }
  ~DirectoryCursor() {
    close();
  }

  // Opens `path`. A missing directory is an empty listing, not an error.
  static td::Result<DirectoryCursor> open(const std::string& path, StatFn stat_fn = &::fstatat) {
    DirectoryCursor cursor;
    cursor.stat_ = stat_fn;
    cursor.dir_ = ::opendir(path.c_str());
    if (cursor.dir_ == nullptr) {
      int err = errno;
      if (err == ENOENT) {
        return cursor;
      }
      return td::Status::Error(PSLICE() << "cannot open directory " << path << ": " << std::strerror(err));
    }
    return cursor;
  }

  // The next entry, nothing at the end of the listing, or an error. An entry that
  // disappeared between the listing and its metadata lookup is skipped; any other
  // failure to read an entry's metadata is a listing failure, because the entry can
  // be neither classified nor ignored.
  td::Result<std::optional<Entry>> next() {
    if (dir_ == nullptr) {
      return std::optional<Entry>{};
    }
    while (true) {
      errno = 0;
      struct dirent* ent = ::readdir(dir_);
      if (ent == nullptr) {
        int err = errno;
        close();
        if (err != 0) {
          return td::Status::Error(PSLICE() << "directory listing failed: " << std::strerror(err));
        }
        return std::optional<Entry>{};
      }
      std::string name = ent->d_name;
      if (name == "." || name == "..") {
        continue;
      }
      struct stat st;
      if (stat_(::dirfd(dir_), ent->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        int err = errno;
        if (err == ENOENT) {
          continue;
        }
        return td::Status::Error(PSLICE() << "cannot read the metadata of " << name << ": " << std::strerror(err));
      }
      return std::optional<Entry>{Entry{std::move(name), S_ISDIR(st.st_mode)}};
    }
  }

  bool at_end() const {
    return dir_ == nullptr;
  }

 private:
  void close() {
    if (dir_ != nullptr) {
      ::closedir(dir_);
      dir_ = nullptr;
    }
  }

  DIR* dir_ = nullptr;
  StatFn stat_ = &::fstatat;
};

// Whether `path` is a real directory (not a symlink to one).
inline bool is_real_directory(const std::string& path) {
  struct stat st;
  if (::lstat(path.c_str(), &st) != 0) {
    return false;
  }
  return S_ISDIR(st.st_mode);
}

}  // namespace tos::validator::consensus
