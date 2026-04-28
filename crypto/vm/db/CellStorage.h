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
#include "td/db/KeyValue.h"
#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "vm/cells.h"
#include "vm/db/DynamicBagOfCellsDb.h"

namespace vm {
using KeyValue = td::KeyValue;
using KeyValueReader = td::KeyValueReader;

class CellLoader {
 public:
  struct LoadResult {
   public:
    enum { Ok, NotFound } status{NotFound};

    Ref<DataCell> &cell() {
      DCHECK(status == Ok);
      return cell_;
    }

    td::int32 refcnt() const {
      return refcnt_;
    }

    Ref<DataCell> cell_;
    td::int32 refcnt_{0};
    bool stored_boc_{false};
  };
  CellLoader(std::shared_ptr<KeyValueReader> reader, std::function<void(const LoadResult &)> on_load_callback = {});
  td::Result<LoadResult> load(td::Slice hash, bool need_data, ExtCellCreator &ext_cell_creator);
  td::Result<std::vector<LoadResult>> load_bulk(td::Span<td::Slice> hashes, bool need_data,
                                                ExtCellCreator &ext_cell_creator);
  static td::Result<LoadResult> load(td::Slice hash, td::Slice value, bool need_data, ExtCellCreator &ext_cell_creator);
  td::Result<LoadResult> load_refcnt(td::Slice hash);  // This only loads refcnt_, cell_ == null
  KeyValueReader &key_value_reader() const {
    return *reader_;
  }

 private:
  std::shared_ptr<KeyValueReader> reader_;
  std::function<void(const LoadResult &)> on_load_callback_;
};

class CellStorer {
 public:
  CellStorer(KeyValue &kv);
  td::Status erase(td::Slice hash);
  td::Status set(td::int32 refcnt, const td::Ref<DataCell> &cell, bool as_boc);
  td::Status merge(td::Slice hash, td::int32 refcnt_diff);

  // Per-cell streaming write entry used by import-only paths (state-sync
  // streaming sink). Unlike `set` / `merge`, this method does NOT walk
  // children and does NOT touch refcount accounting beyond writing a
  // refcount-1 record for the cell itself. It is intended to be batched
  // by the caller via `KeyValue::begin_write_batch` /
  // `commit_write_batch` and is safe to call from a single-threaded
  // parser.
  //
  // Idempotency / collision semantics:
  //   - If the same hash is already present with the same serialized
  //     bytes, the call returns OK and performs no write.
  //   - If the same hash is already present with DIFFERENT bytes, the
  //     call returns an Error. This is the fail-closed behavior the
  //     streaming importer relies on to detect a corrupt source.
  //   - Otherwise the (hash -> bytes) mapping is appended to the
  //     current write batch.
  //
  // The slice overload assumes the caller has already serialized the
  // cell into the on-disk RefcntCell value format (see
  // `serialize_value` above); the DataCell overload is a convenience
  // wrapper that does the serialization internally.
  //
  // TODO(tos25 W6): regression tests for store_cell_streaming
  //   - same hash + same bytes -> OK (idempotent)
  //   - same hash + different bytes -> Error
  //   - 1M cells streaming write does not OOM
  //   - abort_batch leaves no partial state visible to a fresh CellDbReader
  td::Status store_cell_streaming(td::Slice hash, td::Slice serialized_cell_bytes);
  td::Status store_cell_streaming(const td::Ref<DataCell> &cell);

  static void merge_value_and_refcnt_diff(std::string &value, td::Slice right);
  static void merge_refcnt_diffs(std::string &left, td::Slice right);
  static std::string serialize_refcnt_diffs(td::int32 refcnt_diff);

  static std::string serialize_value(td::int32 refcnt, const td::Ref<DataCell> &cell, bool as_boc,
                                     int max_level = vm::Cell::max_level);

  struct Diff {
    enum Type { Set, Erase, Merge } type{Set};
    CellHash key;
    std::string value{};
  };
  td::Status apply_diff(const Diff &diff);

  struct MetaDiff {
    enum Type { Set, Erase } type{Set};
    std::string key;
    std::string value{};
  };
  td::Status apply_meta_diff(const MetaDiff &diff);

 private:
  KeyValue &kv_;
};
}  // namespace vm
