/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// Reading a 32-byte post-quantum seed off the local disk, and the conditions under which
// this machine refuses to.
//
// Two different secrets are kept this way and must never be kept the same place: the hot
// consensus key a validator signs with, and the offline controller root that authorises
// the stake and replaces that key. What makes each of them safe on disk is the same list
// of local facts -- a regular file this process owns, no group or world bits, a directory
// nobody else can write, exactly 32 bytes, and a path that is read rather than followed.
//
// The list lives here once. Two copies would be two sets of rules, and the one that
// drifted would be the one nobody read until a key was readable by somebody else.

#include <array>
#include <cstddef>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

namespace tos::pq::detail {

// The whole content of a key file. A key is a seed, not a container: no header to get
// wrong, no version to disagree about.
inline constexpr std::size_t seed_file_bytes = 32;

// Closes on every path out, including the ones that throw nothing and return early.
class Descriptor {
 public:
  explicit Descriptor(int fd) noexcept : fd_(fd) {
  }
  ~Descriptor() {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }
  Descriptor(const Descriptor&) = delete;
  Descriptor& operator=(const Descriptor&) = delete;
  int get() const noexcept {
    return fd_;
  }
  bool valid() const noexcept {
    return fd_ >= 0;
  }

 private:
  int fd_;
};

// A buffer that is wiped when it goes out of scope, however it goes out of scope.
class SeedBuffer {
 public:
  ~SeedBuffer() {
    OPENSSL_cleanse(bytes.data(), bytes.size());
  }
  std::array<unsigned char, seed_file_bytes> bytes{};
};

inline std::string parent_directory(std::string_view path) {
  const auto slash = path.find_last_of('/');
  if (slash == std::string_view::npos) {
    return ".";
  }
  if (slash == 0) {
    return "/";
  }
  return std::string(path.substr(0, slash));
}

// Anyone who can write the directory can replace the key in it, so the directory is part
// of what protects the key and is checked with it.
inline bool directory_is_private(std::string_view path) noexcept {
  struct stat st{};
  if (::stat(parent_directory(path).c_str(), &st) != 0) {
    return false;
  }
  return (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

// Which protection a file failed. The caller maps these onto its own error type, so the
// words an operator reads stay with the key they are about.
enum class SeedFileRefusal {
  cannot_open,
  not_a_regular_file,
  wrong_owner,
  readable_by_others,
  directory_writable,
  wrong_size,
  read_failed,
};

// Read the seed at `path`, or say which protection refused it. A symlink is refused
// rather than followed: the path an operator configured is the file that is read.
inline std::optional<SeedFileRefusal> read_protected_seed(std::string_view path, SeedBuffer& seed) noexcept {
  const std::string name(path);
  Descriptor fd(::open(name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (!fd.valid()) {
    return SeedFileRefusal::cannot_open;
  }
  struct stat st{};
  if (::fstat(fd.get(), &st) != 0) {
    return SeedFileRefusal::cannot_open;
  }
  if (!S_ISREG(st.st_mode)) {
    return SeedFileRefusal::not_a_regular_file;
  }
  if (st.st_uid != ::geteuid()) {
    return SeedFileRefusal::wrong_owner;
  }
  if ((st.st_mode & 077) != 0) {
    return SeedFileRefusal::readable_by_others;
  }
  if (!directory_is_private(path)) {
    return SeedFileRefusal::directory_writable;
  }
  if (st.st_size != static_cast<off_t>(seed_file_bytes)) {
    return SeedFileRefusal::wrong_size;
  }

  std::size_t read_so_far = 0;
  while (read_so_far < seed.bytes.size()) {
    const auto n = ::read(fd.get(), seed.bytes.data() + read_so_far, seed.bytes.size() - read_so_far);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return SeedFileRefusal::read_failed;
    }
    read_so_far += static_cast<std::size_t>(n);
  }
  return std::nullopt;
}

}  // namespace tos::pq::detail
