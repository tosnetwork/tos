/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Shared helpers for the coverage-guided fuzz targets in this directory.
//
// A target refuses malformed input the way the node does, through td::Status, and treats
// that refusal as an ordinary outcome. What it must never do is hide a failure: a broken
// invariant on input the code accepted ends the process at once, with the reason on
// stderr, so libFuzzer records the input as a crash. Nothing here catches a signal, an
// exception or a sanitizer report.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "td/utils/Slice.h"
#include "td/utils/logging.h"

namespace tos::fuzz {

// Ends the run when an invariant the code under test promises does not hold.
[[noreturn]] inline void invariant_failed(const char *what) {
  std::fprintf(stderr, "FUZZ INVARIANT VIOLATED: %s\n", what);
  std::fflush(stderr);
  std::abort();
}

#define TOS_FUZZ_INVARIANT(condition)            \
  do {                                           \
    if (!(condition)) {                          \
      ::tos::fuzz::invariant_failed(#condition); \
    }                                            \
  } while (false)

// The libraries log every refusal; at fuzzing rates that is all the run would do.
inline void quiet_logging() {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(FATAL));
}

// Splits an input into fields without copying. Every read is bounded by what is left; a
// short input yields short or empty fields rather than reading past the end.
class Reader {
 public:
  Reader(const std::uint8_t *data, std::size_t size) : data_(data), size_(size) {
  }

  bool empty() const {
    return size_ == 0;
  }
  std::size_t left() const {
    return size_;
  }

  std::uint8_t u8() {
    if (size_ == 0) {
      return 0;
    }
    auto value = data_[0];
    advance(1);
    return value;
  }

  std::uint16_t u16() {
    return static_cast<std::uint16_t>(u8() | (static_cast<std::uint16_t>(u8()) << 8));
  }

  std::uint32_t u32() {
    std::uint32_t value = u16();
    return value | (static_cast<std::uint32_t>(u16()) << 16);
  }

  // At most `n` bytes; fewer when the input ends first.
  td::Slice bytes(std::size_t n) {
    if (n > size_) {
      n = size_;
    }
    td::Slice result(reinterpret_cast<const char *>(data_), n);
    advance(n);
    return result;
  }

  td::Slice rest() {
    return bytes(size_);
  }

 private:
  void advance(std::size_t n) {
    data_ += n;
    size_ -= n;
  }

  const std::uint8_t *data_;
  std::size_t size_;
};

}  // namespace tos::fuzz
