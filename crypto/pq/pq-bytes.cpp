/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>

#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

#include "pq-bytes.h"

namespace tos::pq {

td::Result<td::Ref<vm::Cell>> pack_pq_bytes(td::Slice data, std::size_t max_bytes) {
  const std::size_t len = data.size();
  // Both bounds apply: the caller's limit and the absolute ceiling. Never just the caller's.
  if (len > max_bytes || len > pq_bytes_hard_max || max_bytes > 0xffffffffULL) {
    return td::Status::Error("pq-bytes: oversize");
  }
  vm::Ref<vm::Cell> next;  // null tail
  if (len > 0) {
    const std::size_t nchunks = (len + pq_bytes_chunk - 1) / pq_bytes_chunk;
    for (std::size_t i = nchunks; i-- > 0;) {  // build the snake from the tail back
      const std::size_t off = i * pq_bytes_chunk;
      const std::size_t n = std::min(pq_bytes_chunk, len - off);
      vm::CellBuilder cb;
      if (!cb.store_bytes_bool(data.substr(off, n))) {
        return td::Status::Error("pq-bytes: store");
      }
      if (next.not_null()) {
        cb.store_ref(next);
      }
      next = cb.finalize();
    }
  }
  vm::CellBuilder root;
  root.store_long(static_cast<long long>(len), 32);
  if (next.not_null()) {
    root.store_ref(next);
  }
  return root.finalize();
}

td::Result<td::BufferSlice> unpack_pq_bytes(td::Ref<vm::Cell> root, std::size_t max_bytes) {
  if (root.is_null()) {
    return td::Status::Error("pq-bytes: null root");
  }
  vm::CellSlice cs(vm::NoVm(), root);
  if (cs.size() != 32) {
    return td::Status::Error("pq-bytes: root bits");
  }
  // The declared length is attacker-controlled: bound it against BOTH the caller limit
  // and the absolute ceiling before allocating or walking a single cell.
  const std::size_t len = static_cast<std::size_t>(cs.fetch_ulong(32));
  if (len > max_bytes || len > pq_bytes_hard_max) {
    return td::Status::Error("pq-bytes: oversize");
  }
  if (len == 0) {
    if (cs.size_refs() != 0) {
      return td::Status::Error("pq-bytes: empty with ref");
    }
    return td::BufferSlice();
  }
  if (cs.size_refs() != 1) {
    return td::Status::Error("pq-bytes: root ref count");
  }
  td::BufferSlice out(len);
  std::size_t got = 0;
  vm::Ref<vm::Cell> cur = cs.fetch_ref();
  while (true) {
    vm::CellSlice dc(vm::NoVm(), cur);
    const std::size_t n = std::min(pq_bytes_chunk, len - got);
    if (dc.size() != n * 8) {  // exact chunk, no stray bits -> canonical
      return td::Status::Error("pq-bytes: chunk bits");
    }
    if (!dc.fetch_bytes(reinterpret_cast<unsigned char*>(out.data()) + got, static_cast<unsigned>(n))) {
      return td::Status::Error("pq-bytes: fetch");
    }
    got += n;
    if (got == len) {
      if (dc.size_refs() != 0) {
        return td::Status::Error("pq-bytes: trailing ref");
      }
      break;
    }
    if (dc.size_refs() != 1) {
      return td::Status::Error("pq-bytes: chunk ref count");
    }
    cur = dc.fetch_ref();
  }
  return std::move(out);
}

}  // namespace tos::pq
