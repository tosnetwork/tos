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

#include <algorithm>
#include <new>

#include "td/utils/format.h"
#include "td/utils/port/FileFd.h"
#include "vm/boc.h"

namespace vm::detail {

// Bounded read buffer for the streaming BoC importer. Owns a single
// fixed-capacity scratch BufferSlice and refills it from `file` on demand.
// Provides a logical absolute offset interface so the caller can think
// in BoC-file coordinates rather than buffer-relative coordinates.
//
// Direction-aware refill policy: BoC v1 layout places the root cell at
// the file start (index 0) and the leaves at the file end (max index).
// The parent-walk pass scans cells forward (0 → cell_count-1). The
// cell-build pass scans backward (cell_count-1 → 0) so each child has
// already been built when its parent is assembled. A purely forward-
// prefetch chunk is a perfect fit for the parent walk but a worst-case
// thrash for the build loop: every cell read lands BEFORE the cached
// chunk and forces a fresh pread (~100-250 µs/cell on a page-cached
// file, dominating the 1 GiB / 16 GiB import wall time).
//
// Fix: track the last access offset; on a miss, when the new request
// is BEFORE the previous request, anchor the refilled chunk so its
// END aligns with the request end rather than its START with the
// request start. The next backward access then lands inside the same
// chunk. Forward-walk callers see no behavior change because the
// "previous offset < current offset" branch keeps the legacy anchoring.
//
// Peak resident memory is unchanged: the reader still owns exactly one
// scratch buffer of size `chunk_bytes_`, regardless of direction.
class StreamingFileReader {
 public:
  StreamingFileReader(td::FileFd& file, td::uint64 file_size, std::size_t chunk_bytes, StreamingBocImportStats* stats)
      : file_(&file)
      , file_size_(file_size)
      , chunk_bytes_(std::clamp(chunk_bytes, std::size_t{256}, kStreamingBocScratchBytes))
      , stats_(stats) {
  }

  // Return a Slice covering [offset, offset+len). Performs a pread when
  // the requested range is not entirely contained in the current scratch
  // buffer. The returned slice is invalidated by the next call to read();
  // callers must consume it before requesting more bytes.
  td::Result<td::Slice> read(td::uint64 offset, std::size_t len) {
    if (len == 0) {
      // Track even zero-length reads so a zero-byte probe between two
      // backward scans does not flip direction detection.
      return td::Slice{};
    }
    if (offset > file_size_ || len > file_size_ - offset) {
      return td::Status::Error(PSLICE() << "streaming BoC reader: out-of-range read offset=" << offset << " len=" << len
                                        << " file_size=" << file_size_);
    }
    if (len > chunk_bytes_) {
      return td::Status::Error("streaming BoC reader: read exceeds scratch limit");
    }
    if (!cached_in_range(offset, len)) {
      if (scratch_.empty()) {
        try {
          scratch_ = td::BufferSlice{chunk_bytes_};
        } catch (const std::bad_alloc&) {
          return td::Status::Error("streaming BoC reader: cannot allocate scratch buffer");
        }
        if (stats_ != nullptr) {
          stats_->peak_scratch_bytes = scratch_.size();
        }
      }
      // A descriptor probe and its validated full read have the same offset.
      // Preserve direction across that pair so backward imports keep their
      // cache window instead of refilling forward for every cell.
      bool backward = last_request_seen_ &&
                      (offset < last_request_offset_ || (offset == last_request_offset_ && last_request_backward_));
      td::uint64 chunk_start;
      td::uint64 want;
      if (backward) {
        // Anchor so the chunk ends at offset + len. If the requested
        // range sits less than chunk_bytes_ from the file start, clamp
        // chunk_start to 0 and shrink `want` accordingly. This makes
        // each backward step move the cache window backward by one full
        // chunk, reducing the number of preads on a backward scan from
        // O(cell_count) to O(file_size / chunk_bytes_).
        td::uint64 end = offset + len;
        if (end > chunk_bytes_) {
          chunk_start = end - chunk_bytes_;
        } else {
          chunk_start = 0;
        }
        want = end - chunk_start;
        if (want > chunk_bytes_) {
          want = chunk_bytes_;  // defensive; should be unreachable
        }
      } else {
        chunk_start = offset;
        want = chunk_bytes_;
        if (want > file_size_ - chunk_start) {
          want = file_size_ - chunk_start;
        }
      }
      auto dst = scratch_.as_slice().truncate(static_cast<std::size_t>(want));
      // pread may overwrite a prefix of the scratch before it reports an error
      // or a short read. Retire the old window first, so a later read cannot
      // take those bytes for the previous offset; publish the new window only
      // after a complete read.
      cache_offset_ = 0;
      cache_len_ = 0;
      auto status = file_->pread(dst, static_cast<td::int64>(chunk_start));
      if (status.is_error()) {
        return td::Status::Error(PSLICE() << "streaming BoC reader: pread failed at offset=" << chunk_start << ": "
                                          << status.error());
      }
      auto got = status.move_as_ok();
      if (got != static_cast<std::size_t>(want)) {
        return td::Status::Error(PSLICE() << "streaming BoC reader: short pread got=" << got << " want=" << want
                                          << " at offset=" << chunk_start);
      }
      if (stats_ != nullptr) {
        ++stats_->file_read_calls;
        stats_->file_read_bytes += got;
      }
      cache_offset_ = chunk_start;
      cache_len_ = static_cast<std::size_t>(want);
    }
    if (last_request_seen_ && offset != last_request_offset_) {
      last_request_backward_ = offset < last_request_offset_;
    }
    last_request_offset_ = offset;
    last_request_seen_ = true;
    auto buf = scratch_.as_slice();
    auto local = static_cast<std::size_t>(offset - cache_offset_);
    return buf.substr(local, len);
  }

  // Index offsets are untrusted. Read only the descriptor until its exact
  // serialized size agrees with the span; both importer passes use this gate.
  td::Result<td::Slice> read_cell(td::uint64 base, td::uint64 data_size, td::uint64 start, td::uint64 end,
                                  int ref_byte_size) {
    if (start > end || end > data_size) {
      return td::Status::Error("streaming BoC reader: corrupt cell offsets");
    }
    if (base > file_size_ || data_size > file_size_ - base) {
      return td::Status::Error("streaming BoC reader: cell data outside file");
    }
    if (ref_byte_size < 1 || ref_byte_size > 4) {
      return td::Status::Error("streaming BoC reader: invalid reference width");
    }
    const td::uint64 span = end - start;
    if (span < 2) {
      return td::Status::Error("streaming BoC reader: truncated cell descriptor");
    }
    TRY_RESULT(descriptor, read(base + start, 2));
    CellSerializationInfo cell_info;
    TRY_STATUS(cell_info.init(descriptor.ubegin()[0], descriptor.ubegin()[1], ref_byte_size));
    if (span != cell_info.end_offset) {
      return td::Status::Error(PSLICE() << "streaming BoC reader: cell span does not match descriptor: span=" << span
                                        << " expected=" << cell_info.end_offset);
    }
    // end_offset is bounded by the two descriptor bytes and ref_byte_size
    // (validated by the header), so no index-controlled narrowing occurs.
    if (stats_ != nullptr) {
      ++stats_->cell_read_calls;
    }
    return read(base + start, cell_info.end_offset);
  }

  // Stream `len` bytes starting at `offset` into the supplied callable
  // in chunk-sized pieces. Used for incremental CRC32C validation over
  // the BoC body without a full materialization.
  template <class Fn>
  td::Status stream(td::uint64 offset, td::uint64 len, Fn&& fn) {
    while (len > 0) {
      std::size_t want = static_cast<std::size_t>(std::min<td::uint64>(len, chunk_bytes_));
      TRY_RESULT(slice, read(offset, want));
      auto status = fn(slice);
      if (status.is_error()) {
        return status;
      }
      offset += want;
      len -= want;
    }
    return td::Status::OK();
  }

  td::uint64 file_size() const {
    return file_size_;
  }

 private:
  bool cached_in_range(td::uint64 offset, std::size_t len) const {
    if (cache_len_ == 0) {
      return false;
    }
    if (offset < cache_offset_) {
      return false;
    }
    if (offset - cache_offset_ + len > cache_len_) {
      return false;
    }
    return true;
  }

  td::FileFd* file_;
  td::uint64 file_size_;
  const std::size_t chunk_bytes_;
  StreamingBocImportStats* stats_;
  td::BufferSlice scratch_;
  td::uint64 cache_offset_{0};
  std::size_t cache_len_{0};
  // Direction-detection state. `last_request_offset_` records the start
  // offset of the most recent successful read; `last_request_seen_` is
  // false until the first read completes so the very first call cannot
  // be misclassified as backward.
  td::uint64 last_request_offset_{0};
  bool last_request_seen_{false};
  bool last_request_backward_{false};
};

}  // namespace vm::detail
