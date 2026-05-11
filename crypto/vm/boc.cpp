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
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <limits>
#include <new>

#include "td/utils/Slice-decl.h"
#include "td/utils/bits.h"
#include "td/utils/crypto.h"
#include "td/utils/format.h"
#include "td/utils/misc.h"
#include "vm/boc-writers.h"
#include "vm/boc.h"
#include "vm/cells.h"
#include "vm/cellslice.h"

namespace vm {
using td::Ref;

td::Status CellSerializationInfo::init(td::Slice data, int ref_byte_size) {
  if (data.size() < 2) {
    return td::Status::Error(PSLICE() << "Not enough bytes " << td::tag("got", data.size())
                                      << td::tag("expected", "at least 2"));
  }
  TRY_STATUS(init(data.ubegin()[0], data.ubegin()[1], ref_byte_size));
  if (data.size() < end_offset) {
    return td::Status::Error(PSLICE() << "Not enough bytes " << td::tag("got", data.size())
                                      << td::tag("expected", end_offset));
  }
  return td::Status::OK();
}

td::Status CellSerializationInfo::init(td::uint8 d1, td::uint8 d2, int ref_byte_size) {
  refs_cnt = d1 & 7;
  level_mask = Cell::LevelMask(d1 >> 5);
  special = (d1 & 8) != 0;
  with_hashes = (d1 & 16) != 0;

  if (refs_cnt > 4) {
    if (refs_cnt != 7 || !with_hashes) {
      return td::Status::Error("Invalid first byte");
    }
    refs_cnt = 0;
    // ...
    // do not deserialize absent cells!
    return td::Status::Error("TODO: absent cells");
  }

  hashes_offset = 2;
  auto n = level_mask.get_hashes_count();
  depth_offset = hashes_offset + (with_hashes ? n * Cell::hash_bytes : 0);
  data_offset = depth_offset + (with_hashes ? n * Cell::depth_bytes : 0);
  data_len = (d2 >> 1) + (d2 & 1);
  data_with_bits = (d2 & 1) != 0;
  refs_offset = data_offset + data_len;
  end_offset = refs_offset + refs_cnt * ref_byte_size;

  return td::Status::OK();
}

td::Result<int> CellSerializationInfo::get_bits(td::Slice cell) const {
  if (data_with_bits) {
    DCHECK(data_len != 0);
    int last = cell[data_offset + data_len - 1];
    if (!(last & 0x7f)) {
      return td::Status::Error("overlong encoding");
    }
    return td::narrow_cast<int>((data_len - 1) * 8 + 7 - td::count_trailing_zeroes_non_zero32(last));
  } else {
    return td::narrow_cast<int>(data_len * 8);
  }
}

// TODO: check usage when result is empty
td::Result<Ref<DataCell>> CellSerializationInfo::create_data_cell(td::Slice cell_slice,
                                                                  td::Span<Ref<Cell>> refs) const {
  DCHECK(refs_cnt == (td::int64)refs.size());
  TRY_RESULT(bits, get_bits(cell_slice));
  TRY_RESULT(res, DataCell::create(cell_slice.substr(data_offset), bits, refs, special));
  CHECK(!res.is_null());
  if (res->is_special() != special) {
    return td::Status::Error("is_special mismatch");
  }
  if (res->get_level_mask() != level_mask) {
    return td::Status::Error("level mask mismatch");
  }
  //return res;
  if (with_hashes) {
    auto hash_n = level_mask.get_hashes_count();
    if (res->get_hash().as_slice() !=
        cell_slice.substr(hashes_offset + Cell::hash_bytes * (hash_n - 1), Cell::hash_bytes)) {
      return td::Status::Error("representation hash mismatch");
    }
    if (res->get_depth() !=
        DataCell::load_depth(
            cell_slice.substr(depth_offset + Cell::depth_bytes * (hash_n - 1), Cell::depth_bytes).ubegin())) {
      return td::Status::Error("depth mismatch");
    }

    bool check_all_hashes = true;
    for (unsigned level_i = 0, hash_i = 0, level = level_mask.get_level(); check_all_hashes && level_i < level;
         level_i++) {
      if (!level_mask.is_significant(level_i)) {
        continue;
      }
      if (cell_slice.substr(hashes_offset + Cell::hash_bytes * hash_i, Cell::hash_bytes) !=
          res->get_hash(level_i).as_slice()) {
        // hash mismatch
        return td::Status::Error("lower hash mismatch");
      }
      if (res->get_depth(level_i) !=
          DataCell::load_depth(
              cell_slice.substr(depth_offset + Cell::depth_bytes * hash_i, Cell::depth_bytes).ubegin())) {
        return td::Status::Error("lower depth mismatch");
      }
      hash_i++;
    }
  }
  return res;
}

void BagOfCells::clear() {
  cells_clear();
  roots.clear();
  root_count = 0;
  serialized.clear();
}

int BagOfCells::set_roots(const std::vector<td::Ref<vm::Cell>>& new_roots) {
  clear();
  return add_roots(new_roots);
}

int BagOfCells::set_root(td::Ref<vm::Cell> new_root) {
  clear();
  return add_root(std::move(new_root));
}

int BagOfCells::add_roots(const std::vector<td::Ref<vm::Cell>>& add_roots) {
  int res = 0;
  for (td::Ref<vm::Cell> root : add_roots) {
    res += add_root(std::move(root));
  }
  return res;
}

int BagOfCells::add_root(td::Ref<vm::Cell> add_root) {
  if (add_root.is_null()) {
    return 0;
  }
  LOG_CHECK(!add_root->is_virtualized()) << "TODO: support serialization of virtualized cells";
  //const Cell::Hash& hash = add_root->get_hash();
  //for (const auto& root_info : roots) {
  //if (root_info.cell->get_hash() == hash) {
  //return 0;
  //}
  //}
  roots.emplace_back(std::move(add_root), -1);
  ++root_count;
  cells_clear();
  return 1;
}

// Changes in this function may require corresponding changes in crypto/vm/large-boc-serializer.cpp
td::Status BagOfCells::import_cells() {
  if (logger_ptr_) {
    logger_ptr_->start_stage("import_cells");
  }
  cells_clear();
  for (auto& root : roots) {
    auto res = import_cell(root.cell, 0);
    if (res.is_error()) {
      return res.move_as_error();
    }
    root.idx = res.move_as_ok();
  }
  //LOG(INFO) << "[cells: " << cell_count << ", refs: " << int_refs << ", bytes: " << data_bytes << "]";
  reorder_cells();
  //LOG(INFO) << "[cells: " << cell_count << ", refs: " << int_refs << ", bytes: " << data_bytes
  //<< ", internal hashes: " << int_hashes << ", top hashes: " << top_hashes << "]";
  CHECK(cell_count != 0);
  if (logger_ptr_) {
    logger_ptr_->finish_stage(PSLICE() << cell_count << " cells");
  }
  return td::Status::OK();
}

// Changes in this function may require corresponding changes in crypto/vm/large-boc-serializer.cpp
td::Result<int> BagOfCells::import_cell(td::Ref<vm::Cell> cell, int depth) {
  if (depth > max_depth) {
    return td::Status::Error("error while importing a cell into a bag of cells: cell depth too large");
  }
  if (cell.is_null()) {
    return td::Status::Error("error while importing a cell into a bag of cells: cell is null");
  }
  if (logger_ptr_) {
    TRY_STATUS(logger_ptr_->on_cells_processed(1));
  }
  auto it = cells.find(cell->get_hash());
  if (it != cells.end()) {
    auto pos = it->second;
    cell_list_[pos].should_cache = true;
    return pos;
  }
  if (cell->is_virtualized()) {
    return td::Status::Error(
        "error while importing a cell into a bag of cells: cell has non-zero virtualization level");
  }
  auto r_loaded_dc = cell->load_cell();
  if (r_loaded_dc.is_error()) {
    return td::Status::Error("error while importing a cell into a bag of cells: " +
                             r_loaded_dc.move_as_error().to_string());
  }
  auto loaded_dc = r_loaded_dc.move_as_ok();
  CellSlice cs(std::move(loaded_dc));
  std::array<int, 4> refs{-1};
  DCHECK(cs.size_refs() <= 4);
  unsigned sum_child_wt = 1;
  for (unsigned i = 0; i < cs.size_refs(); i++) {
    auto ref = import_cell(cs.prefetch_ref(i), depth + 1);
    if (ref.is_error()) {
      return ref.move_as_error();
    }
    refs[i] = ref.move_as_ok();
    sum_child_wt += cell_list_[refs[i]].wt;
    ++int_refs;
  }
  DCHECK(cell_list_.size() == static_cast<std::size_t>(cell_count));
  auto dc = cs.move_as_loaded_cell().data_cell;
  auto res = cells.emplace(dc->get_hash(), cell_count);
  DCHECK(res.second);
  cell_list_.emplace_back(dc, dc->size_refs(), refs);
  CellInfo& dc_info = cell_list_.back();
  dc_info.hcnt = static_cast<unsigned char>(dc->get_level_mask().get_hashes_count());
  dc_info.wt = static_cast<unsigned char>(std::min(0xffU, sum_child_wt));
  dc_info.new_idx = -1;
  data_bytes += dc->get_serialized_size();
  return cell_count++;
}

// Changes in this function may require corresponding changes in crypto/vm/large-boc-serializer.cpp
void BagOfCells::reorder_cells() {
  int_hashes = 0;
  for (int i = cell_count - 1; i >= 0; --i) {
    CellInfo& dci = cell_list_[i];
    int s = dci.ref_num, c = s, sum = max_cell_whs - 1, mask = 0;
    for (int j = 0; j < s; ++j) {
      CellInfo& dcj = cell_list_[dci.ref_idx[j]];
      int limit = (max_cell_whs - 1 + j) / s;
      if (dcj.wt <= limit) {
        sum -= dcj.wt;
        --c;
        mask |= (1 << j);
      }
    }
    if (c) {
      for (int j = 0; j < s; ++j) {
        if (!(mask & (1 << j))) {
          CellInfo& dcj = cell_list_[dci.ref_idx[j]];
          int limit = sum++ / c;
          if (dcj.wt > limit) {
            dcj.wt = static_cast<unsigned char>(limit);
          }
        }
      }
    }
  }
  for (int i = 0; i < cell_count; i++) {
    CellInfo& dci = cell_list_[i];
    int s = dci.ref_num, sum = 1;
    for (int j = 0; j < s; ++j) {
      sum += cell_list_[dci.ref_idx[j]].wt;
    }
    DCHECK(sum <= max_cell_whs);
    if (sum <= dci.wt) {
      dci.wt = static_cast<unsigned char>(sum);
    } else {
      dci.wt = 0;
      int_hashes += dci.hcnt;
    }
  }
  top_hashes = 0;
  for (auto& root_info : roots) {
    auto& cell_info = cell_list_[root_info.idx];
    if (cell_info.is_root_cell) {
      cell_info.is_root_cell = true;
      if (cell_info.wt) {
        top_hashes += cell_info.hcnt;
      }
    }
  }
  if (cell_count > 0) {
    rv_idx = 0;
    cell_list_tmp.clear();
    cell_list_tmp.reserve(cell_count);

    for (const auto& root_info : roots) {
      revisit(root_info.idx, 0);
      revisit(root_info.idx, 1);
    }
    for (const auto& root_info : roots) {
      revisit(root_info.idx, 2);
    }
    for (auto& root_info : roots) {
      root_info.idx = cell_list_[root_info.idx].new_idx;
    }

    DCHECK(rv_idx == cell_count);
    //DCHECK(cell_list.back().new_idx == cell_count - 1);
    DCHECK(cell_list_.size() == cell_list_tmp.size());
    cell_list_ = std::move(cell_list_tmp);
    cell_list_tmp.clear();
  }
}

// force=0 : previsit (recursively until special cells are found; then visit them)
// force=1 : visit (allocate and process all children)
// force=2 : allocate (assign a new index; can be run only after visiting)
// Changes in this function may require corresponding changes in crypto/vm/large-boc-serializer.cpp
int BagOfCells::revisit(int cell_idx, int force) {
  DCHECK(cell_idx >= 0 && cell_idx < cell_count);
  CellInfo& dci = cell_list_[cell_idx];
  if (dci.new_idx >= 0) {
    return dci.new_idx;
  }
  if (!force) {
    // previsit
    if (dci.new_idx != -1) {
      // already previsited or visited
      return dci.new_idx;
    }
    int n = dci.ref_num;
    for (int j = n - 1; j >= 0; --j) {
      int child_idx = dci.ref_idx[j];
      // either previsit or visit child, depending on whether it is special
      revisit(dci.ref_idx[j], cell_list_[child_idx].is_special());
    }
    return dci.new_idx = -2;  // mark as previsited
  }
  if (force > 1) {
    // time to allocate
    auto i = dci.new_idx = rv_idx++;
    cell_list_tmp.emplace_back(std::move(dci));
    return i;
  }
  if (dci.new_idx == -3) {
    // already visited
    return dci.new_idx;
  }
  if (dci.is_special()) {
    // if current cell is special, previsit it first
    revisit(cell_idx, 0);
  }
  // visit children
  int n = dci.ref_num;
  for (int j = n - 1; j >= 0; --j) {
    revisit(dci.ref_idx[j], 1);
  }
  // allocate children
  for (int j = n - 1; j >= 0; --j) {
    dci.ref_idx[j] = revisit(dci.ref_idx[j], 2);
  }
  return dci.new_idx = -3;  // mark as visited (and all children processed)
}

// Changes in this function may require corresponding changes in crypto/vm/large-boc-serializer.cpp
td::uint64 BagOfCells::compute_sizes(int mode, int& r_size, int& o_size) {
  int rs = 0, os = 0;
  if (!root_count || !data_bytes) {
    r_size = o_size = 0;
    return 0;
  }
  while (cell_count >= (1LL << (rs << 3))) {
    rs++;
  }
  td::uint64 hashes =
      (((mode & Mode::WithTopHash) ? top_hashes : 0) + ((mode & Mode::WithIntHashes) ? int_hashes : 0)) *
      (Cell::hash_bytes + Cell::depth_bytes);
  td::uint64 data_bytes_adj = data_bytes + (unsigned long long)int_refs * rs + hashes;
  td::uint64 max_offset = (mode & Mode::WithCacheBits) ? data_bytes_adj * 2 : data_bytes_adj;
  while (max_offset >= (1ULL << (os << 3))) {
    os++;
  }
  if (rs > 4 || os > 8) {
    r_size = o_size = 0;
    return 0;
  }
  r_size = rs;
  o_size = os;
  return data_bytes_adj;
}

// Changes in this function may require corresponding changes in crypto/vm/large-boc-serializer.cpp
std::size_t BagOfCells::estimate_serialized_size(int mode) {
  if ((mode & Mode::WithCacheBits) && !(mode & Mode::WithIndex)) {
    info.invalidate();
    return 0;
  }
  auto data_bytes_adj = compute_sizes(mode, info.ref_byte_size, info.offset_byte_size);
  if (!data_bytes_adj) {
    info.invalidate();
    return 0;
  }
  info.valid = true;
  info.has_crc32c = mode & Mode::WithCRC32C;
  info.has_index = mode & Mode::WithIndex;
  info.has_cache_bits = mode & Mode::WithCacheBits;
  info.root_count = root_count;
  info.cell_count = cell_count;
  info.absent_count = dangle_count;
  int crc_size = info.has_crc32c ? 4 : 0;
  info.roots_offset = 4 + 1 + 1 + 3 * info.ref_byte_size + info.offset_byte_size;
  info.index_offset = info.roots_offset + info.root_count * info.ref_byte_size;
  info.data_offset = info.index_offset;
  if (info.has_index) {
    info.data_offset += (long long)cell_count * info.offset_byte_size;
  }
  info.magic = Info::boc_generic;
  info.data_size = data_bytes_adj;
  info.total_size = info.data_offset + data_bytes_adj + crc_size;
  auto res = td::narrow_cast_safe<size_t>(info.total_size);
  if (res.is_error()) {
    return 0;
  }
  return res.ok();
}

td::Status BagOfCells::serialize(int mode) {
  std::size_t size_est = estimate_serialized_size(mode);
  if (!size_est) {
    serialized.clear();
    return td::Status::OK();
  }
  serialized.resize(size_est);
  TRY_RESULT(size, serialize_to(const_cast<unsigned char*>(serialized.data()), serialized.size(), mode));
  if (size != size_est) {
    serialized.clear();
    return td::Status::Error("serialization failed");
  }
  return td::Status::OK();
}

std::string BagOfCells::serialize_to_string(int mode) {
  std::size_t size_est = estimate_serialized_size(mode);
  if (!size_est) {
    return {};
  }
  std::string res;
  res.resize(size_est, 0);
  if (serialize_to(const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(res.data())), res.size(), mode)
          .move_as_ok() == res.size()) {
    return res;
  } else {
    return {};
  }
}

td::Result<td::BufferSlice> BagOfCells::serialize_to_slice(int mode) {
  std::size_t size_est = estimate_serialized_size(mode);
  if (!size_est) {
    return td::Status::Error("no cells to serialize to this bag of cells");
  }
  td::BufferSlice res(size_est);
  TRY_RESULT(size, serialize_to(const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(res.data())),
                                res.size(), mode));
  if (size == res.size()) {
    return std::move(res);
  } else {
    return td::Status::Error("error while serializing a bag of cells: actual serialized size differs from estimated");
  }
}

std::string BagOfCells::extract_string() const {
  return std::string{serialized.data(), serialized.data() + serialized.size()};
}

//serialized_boc#672fb0ac has_idx:(## 1) has_crc32c:(## 1)
//  has_cache_bits:(## 1) flags:(## 2) { flags = 0 }
//  size:(## 3) { size <= 4 }
//  off_bytes:(## 8) { off_bytes <= 8 }
//  cells:(##(size * 8))
//  roots:(##(size * 8))
//  absent:(##(size * 8)) { roots + absent <= cells }
//  tot_cells_size:(##(off_bytes * 8))
//  index:(cells * ##(off_bytes * 8))
//  cell_data:(tot_cells_size * [ uint8 ])
//  = BagOfCells;
// Changes in this function may require corresponding changes in crypto/vm/large-boc-serializer.cpp
template <typename WriterT>
td::Result<std::size_t> BagOfCells::serialize_to_impl(WriterT& writer, int mode) {
  auto store_ref = [&](unsigned long long value) { writer.store_uint(value, info.ref_byte_size); };
  auto store_offset = [&](unsigned long long value) { writer.store_uint(value, info.offset_byte_size); };

  writer.store_uint(info.magic, 4);

  td::uint8 byte{0};
  if (info.has_index) {
    byte |= 1 << 7;
  }
  if (info.has_crc32c) {
    byte |= 1 << 6;
  }
  if (info.has_cache_bits) {
    byte |= 1 << 5;
  }
  // 3, 4 - flags
  if (info.ref_byte_size < 1 || info.ref_byte_size > 7) {
    return 0;
  }
  byte |= static_cast<td::uint8>(info.ref_byte_size);
  writer.store_uint(byte, 1);

  writer.store_uint(info.offset_byte_size, 1);
  store_ref(cell_count);
  store_ref(root_count);
  store_ref(0);
  store_offset(info.data_size);
  for (const auto& root_info : roots) {
    int k = cell_count - 1 - root_info.idx;
    DCHECK(k >= 0 && k < cell_count);
    store_ref(k);
  }
  DCHECK(writer.position() == info.index_offset);
  DCHECK((unsigned)cell_count == cell_list_.size());
  if (info.has_index) {
    std::size_t offs = 0;
    if (logger_ptr_) {
      logger_ptr_->start_stage("generate_index");
    }
    for (int i = cell_count - 1; i >= 0; --i) {
      const Ref<DataCell>& dc = cell_list_[i].dc_ref;
      bool with_hash = (mode & Mode::WithIntHashes) && !cell_list_[i].wt;
      if (cell_list_[i].is_root_cell && (mode & Mode::WithTopHash)) {
        with_hash = true;
      }
      offs += dc->get_serialized_size(with_hash) + dc->size_refs() * info.ref_byte_size;
      auto fixed_offset = offs;
      if (info.has_cache_bits) {
        fixed_offset = offs * 2 + cell_list_[i].should_cache;
      }
      store_offset(fixed_offset);
      if (logger_ptr_) {
        TRY_STATUS(logger_ptr_->on_cells_processed(1));
      }
    }
    if (logger_ptr_) {
      logger_ptr_->finish_stage("");
    }
    DCHECK(offs == info.data_size);
  }
  DCHECK(writer.position() == info.data_offset);
  size_t keep_position = writer.position();
  if (logger_ptr_) {
    logger_ptr_->start_stage("serialize");
  }
  for (int i = 0; i < cell_count; ++i) {
    const auto& dc_info = cell_list_[cell_count - 1 - i];
    const Ref<DataCell>& dc = dc_info.dc_ref;
    bool with_hash = (mode & Mode::WithIntHashes) && !dc_info.wt;
    if (dc_info.is_root_cell && (mode & Mode::WithTopHash)) {
      with_hash = true;
    }
    unsigned char buf[Cell::max_serialized_bytes];
    int s = dc->serialize(buf, Cell::max_serialized_bytes, with_hash);
    writer.store_bytes(buf, s);
    DCHECK(dc->size_refs() == dc_info.ref_num);
    // std::cerr << (dc_info.is_special() ? '*' : ' ') << i << '<' << (int)dc_info.wt << ">:";
    for (unsigned j = 0; j < dc_info.ref_num; ++j) {
      int k = cell_count - 1 - dc_info.ref_idx[j];
      DCHECK(k > i && k < cell_count);
      store_ref(k);
      // std::cerr << ' ' << k;
    }
    // std::cerr << std::endl;
    if (logger_ptr_) {
      TRY_STATUS(logger_ptr_->on_cells_processed(1));
    }
  }
  writer.chk();
  DCHECK(writer.position() - keep_position == info.data_size);
  DCHECK(writer.remaining() == (info.has_crc32c ? 4 : 0));
  if (info.has_crc32c) {
    unsigned crc = writer.get_crc32();
    writer.store_uint(td::bswap32(crc), 4);
  }
  if (logger_ptr_) {
    logger_ptr_->finish_stage(PSLICE() << cell_count << " cells, " << writer.position() << " bytes");
  }
  DCHECK(writer.empty());
  return writer.position();
}

td::Result<std::size_t> BagOfCells::serialize_to(unsigned char* buffer, std::size_t buff_size, int mode) {
  std::size_t size_est = estimate_serialized_size(mode);
  if (!size_est || size_est > buff_size) {
    return 0;
  }
  boc_writers::BufferWriter writer{buffer, buffer + size_est};
  return serialize_to_impl(writer, mode);
}

td::Status BagOfCells::serialize_to_file(td::FileFd& fd, int mode) {
  std::size_t size_est = estimate_serialized_size(mode);
  if (!size_est) {
    return td::Status::Error("no cells to serialize to this bag of cells");
  }
  boc_writers::FileWriter writer{fd, size_est};
  TRY_RESULT(s, serialize_to_impl(writer, mode));
  TRY_STATUS(writer.finalize());
  if (s != size_est) {
    return td::Status::Error("error while serializing a bag of cells: actual serialized size differs from estimated");
  }
  return td::Status::OK();
}

unsigned long long BagOfCells::Info::read_int(const unsigned char* ptr, unsigned bytes) {
  unsigned long long res = 0;
  while (bytes > 0) {
    res = (res << 8) + *ptr++;
    --bytes;
  }
  return res;
}

void BagOfCells::Info::write_int(unsigned char* ptr, unsigned long long value, int bytes) {
  ptr += bytes;
  while (bytes) {
    *--ptr = value & 0xff;
    value >>= 8;
    --bytes;
  }
  DCHECK(!bytes);
}

long long BagOfCells::Info::parse_serialized_header(const td::Slice& slice) {
  invalidate();
  int sz = static_cast<int>(std::min(slice.size(), static_cast<std::size_t>(0xffff)));
  if (sz < 4) {
    return -10;  // want at least 10 bytes
  }
  const unsigned char* ptr = slice.ubegin();
  magic = (unsigned)read_int(ptr, 4);
  has_crc32c = false;
  has_index = false;
  has_cache_bits = false;
  ref_byte_size = 0;
  offset_byte_size = 0;
  root_count = cell_count = absent_count = -1;
  index_offset = data_offset = data_size = total_size = 0;
  if (magic != boc_generic && magic != boc_idx && magic != boc_idx_crc32c) {
    magic = 0;
    return 0;
  }
  if (sz < 5) {
    return -10;
  }
  td::uint8 byte = ptr[4];
  if (magic == boc_generic) {
    has_index = (byte >> 7) % 2 == 1;
    has_crc32c = (byte >> 6) % 2 == 1;
    has_cache_bits = (byte >> 5) % 2 == 1;
  } else {
    has_index = true;
    has_crc32c = magic == boc_idx_crc32c;
  }
  if (has_cache_bits && !has_index) {
    return 0;
  }
  ref_byte_size = byte & 7;
  if (ref_byte_size > 4 || ref_byte_size < 1) {
    return 0;
  }
  if (sz < 6) {
    return -7 - 3 * ref_byte_size;
  }
  offset_byte_size = ptr[5];
  if (offset_byte_size > 8 || offset_byte_size < 1) {
    return 0;
  }
  roots_offset = 6 + 3 * ref_byte_size + offset_byte_size;
  ptr += 6;
  sz -= 6;
  if (sz < ref_byte_size) {
    return -static_cast<int>(roots_offset);
  }
  cell_count = (int)read_ref(ptr);
  if (cell_count <= 0) {
    cell_count = -1;
    return 0;
  }
  if (sz < 2 * ref_byte_size) {
    return -static_cast<int>(roots_offset);
  }
  root_count = (int)read_ref(ptr + ref_byte_size);
  if (root_count <= 0) {
    root_count = -1;
    return 0;
  }
  index_offset = roots_offset;
  if (magic == boc_generic) {
    index_offset += (long long)root_count * ref_byte_size;
    has_roots = true;
  } else {
    if (root_count != 1) {
      return 0;
    }
  }
  data_offset = index_offset;
  if (has_index) {
    data_offset += (long long)cell_count * offset_byte_size;
  }
  if (sz < 3 * ref_byte_size) {
    return -static_cast<int>(roots_offset);
  }
  absent_count = (int)read_ref(ptr + 2 * ref_byte_size);
  if (absent_count < 0 || absent_count > cell_count) {
    return 0;
  }
  if (sz < 3 * ref_byte_size + offset_byte_size) {
    return -static_cast<int>(roots_offset);
  }
  data_size = read_offset(ptr + 3 * ref_byte_size);
  if (data_size > ((unsigned long long)cell_count << 10)) {
    return 0;
  }
  if (data_size > (1ull << 40)) {
    return 0;  // bag of cells with more than 1TiB data is unlikely
  }
  if (data_size < cell_count * (2ull + ref_byte_size) - ref_byte_size) {
    return 0;  // invalid header, too many cells for this amount of data bytes
  }
  valid = true;
  total_size = data_offset + data_size + (has_crc32c ? 4 : 0);
  return total_size;
}

td::Result<td::Slice> BagOfCells::get_cell_slice(int idx, td::Slice data) {
  unsigned long long offs = get_idx_entry(idx - 1);
  unsigned long long offs_end = get_idx_entry(idx);
  if (offs > offs_end || offs_end > data.size()) {
    return td::Status::Error(PSLICE() << "invalid index entry [" << offs << "; " << offs_end << "], "
                                      << td::tag("data.size()", data.size()));
  }
  return data.substr(offs, td::narrow_cast<size_t>(offs_end - offs));
}

td::Result<td::Ref<vm::DataCell>> BagOfCells::deserialize_cell(int idx, td::Slice cells_slice,
                                                               td::Span<td::Ref<DataCell>> cells_span,
                                                               std::vector<td::uint8>* cell_should_cache) {
  TRY_RESULT(cell_slice, get_cell_slice(idx, cells_slice));
  std::array<td::Ref<Cell>, 4> refs_buf;

  CellSerializationInfo cell_info;
  TRY_STATUS(cell_info.init(cell_slice, info.ref_byte_size));
  if (cell_info.end_offset != cell_slice.size()) {
    return td::Status::Error("unused space in cell serialization");
  }

  auto refs = td::MutableSpan<td::Ref<Cell>>(refs_buf).substr(0, cell_info.refs_cnt);
  for (int k = 0; k < cell_info.refs_cnt; k++) {
    int ref_idx = (int)info.read_ref(cell_slice.ubegin() + cell_info.refs_offset + k * info.ref_byte_size);
    if (ref_idx <= idx) {
      return td::Status::Error(PSLICE() << "bag-of-cells error: reference #" << k << " of cell #" << idx
                                        << " is to cell #" << ref_idx << " with smaller index");
    }
    if (ref_idx >= cell_count) {
      return td::Status::Error(PSLICE() << "bag-of-cells error: reference #" << k << " of cell #" << idx
                                        << " is to non-existent cell #" << ref_idx << ", only " << cell_count
                                        << " cells are defined");
    }
    refs[k] = cells_span[cell_count - ref_idx - 1];
    if (cell_should_cache) {
      auto& cnt = (*cell_should_cache)[ref_idx];
      if (cnt < 2) {
        cnt++;
      }
    }
  }

  return cell_info.create_data_cell(cell_slice, refs);
}

td::Result<long long> BagOfCells::deserialize(const td::Slice& data, int max_roots) {
  clear();
  long long size_est = info.parse_serialized_header(data);
  if (size_est == 0) {
    return td::Status::Error(PSLICE() << "cannot deserialize bag-of-cells: invalid header, error " << size_est);
  }
  if (size_est < 0) {
    return td::Status::Error(PSLICE() << "cannot deserialize bag-of-cells: not enough bytes (" << data.size()
                                      << " present, " << -size_est << " required)");
  }

  if (size_est > (long long)data.size()) {
    return td::Status::Error(PSLICE() << "cannot deserialize bag-of-cells: not enough bytes (" << data.size()
                                      << " present, " << size_est << " required)");
  }
  if (info.root_count > max_roots) {
    return td::Status::Error("Bag-of-cells has more root cells than expected");
  }
  if (info.has_crc32c) {
    unsigned crc_computed = td::crc32c(td::Slice{data.ubegin(), data.uend() - 4});
    unsigned crc_stored = td::as<unsigned>(data.uend() - 4);
    if (crc_computed != crc_stored) {
      return td::Status::Error(PSLICE() << "bag-of-cells CRC32C mismatch: expected " << td::format::as_hex(crc_computed)
                                        << ", found " << td::format::as_hex(crc_stored));
    }
  }

  cell_count = info.cell_count;
  std::vector<td::uint8> cell_should_cache;
  if (info.has_cache_bits) {
    cell_should_cache.resize(cell_count, 0);
  }
  roots.clear();
  roots.resize(info.root_count);
  auto* roots_ptr = data.substr(info.roots_offset).ubegin();
  for (int i = 0; i < info.root_count; i++) {
    int idx = 0;
    if (info.has_roots) {
      idx = (int)info.read_ref(roots_ptr + i * info.ref_byte_size);
    }
    if (idx < 0 || idx >= info.cell_count) {
      return td::Status::Error(PSLICE() << "bag-of-cells invalid root index " << idx);
    }
    roots[i].idx = info.cell_count - idx - 1;
    if (info.has_cache_bits) {
      auto& cnt = cell_should_cache[idx];
      if (cnt < 2) {
        cnt++;
      }
    }
  }
  if (info.has_index) {
    index_ptr = data.substr(info.index_offset).ubegin();
    // Round 160 LOW fix: validate that the last cell's end offset
    // equals info.data_size, matching the canonical-form check
    // the non-indexed parser performs below.  Pre-fix, an indexed
    // BoC could declare data_size larger than the actual
    // cumulative cell-end offsets, leaving trailing bytes in the
    // data area that the parser ignored — yielding multiple
    // valid BoC encodings of the same cell tree (BoC malleability
    // for evidence systems / consensus paths that require
    // canonical bytes).  When info.has_cache_bits, the cache
    // flag is packed into the offset's LSB; mask it out.
    if (info.cell_count > 0) {
      unsigned long long last_offset = info.read_offset(
          index_ptr +
          static_cast<long>(info.cell_count - 1) * info.offset_byte_size);
      if (info.has_cache_bits) {
        last_offset >>= 1;
      }
      if (last_offset != info.data_size) {
        return td::Status::Error(
            PSLICE() << "invalid bag-of-cells: indexed last cell end offset "
                     << last_offset << " differs from declared data_size "
                     << info.data_size);
      }
    } else if (info.data_size != 0) {
      // Round 162 (claude review) follow-up: cell_count == 0 with
      // non-zero data_size is also non-canonical — the non-indexed
      // branch below would reject this same shape because its
      // cells_slice would be non-empty.  Keep the two parser paths
      // symmetric.
      return td::Status::Error(
          PSLICE() << "invalid bag-of-cells: indexed cell_count is 0 but "
                      "declared data_size is "
                   << info.data_size);
    }
  } else {
    index_ptr = nullptr;
    unsigned long long cur = 0;
    custom_index.reserve(info.cell_count);

    auto cells_slice = data.substr(info.data_offset, info.data_size);

    for (int i = 0; i < info.cell_count; i++) {
      CellSerializationInfo cell_info;
      auto status = cell_info.init(cells_slice, info.ref_byte_size);
      if (status.is_error()) {
        return td::Status::Error(PSLICE()
                                 << "invalid bag-of-cells failed to deserialize cell #" << i << " " << status.error());
      }
      cells_slice = cells_slice.substr(cell_info.end_offset);
      cur += cell_info.end_offset;
      custom_index.push_back(cur);
    }
    if (!cells_slice.empty()) {
      return td::Status::Error(PSLICE() << "invalid bag-of-cells last cell #" << info.cell_count - 1 << ": end offset "
                                        << cur << " is different from total data size " << info.data_size);
    }
  }
  auto cells_slice = data.substr(info.data_offset, info.data_size);
  std::vector<Ref<DataCell>> cell_list;
  cell_list.reserve(cell_count);
  std::array<td::Ref<Cell>, 4> refs_buf;
  for (int i = 0; i < cell_count; i++) {
    // reconstruct cell with index cell_count - 1 - i
    int idx = cell_count - 1 - i;
    auto r_cell = deserialize_cell(idx, cells_slice, cell_list, info.has_cache_bits ? &cell_should_cache : nullptr);
    if (r_cell.is_error()) {
      return td::Status::Error(PSLICE() << "invalid bag-of-cells failed to deserialize cell #" << idx << " "
                                        << r_cell.error());
    }
    cell_list.push_back(r_cell.move_as_ok());
    DCHECK(cell_list.back().not_null());
  }
  if (info.has_cache_bits) {
    for (int idx = 0; idx < cell_count; idx++) {
      auto should_cache = cell_should_cache[idx] > 1;
      auto stored_should_cache = get_cache_entry(idx);
      if (should_cache != stored_should_cache) {
        return td::Status::Error(PSLICE() << "invalid bag-of-cells cell #" << idx << " has wrong cache flag "
                                          << stored_should_cache);
      }
    }
  }
  custom_index.clear();
  index_ptr = nullptr;
  root_count = info.root_count;
  dangle_count = info.absent_count;
  for (auto& root_info : roots) {
    root_info.cell = cell_list[root_info.idx];
  }
  cell_list.clear();
  return size_est;
}

unsigned long long BagOfCells::get_idx_entry(int index) {
  auto raw = get_idx_entry_raw(index);
  if (info.has_cache_bits) {
    raw /= 2;
  }
  return raw;
}

bool BagOfCells::get_cache_entry(int index) {
  if (!info.has_cache_bits) {
    return true;
  }
  if (!info.has_index) {
    return true;
  }
  auto raw = get_idx_entry_raw(index);
  return raw % 2 == 1;
}

unsigned long long BagOfCells::get_idx_entry_raw(int index) {
  if (index < 0) {
    return 0;
  }
  if (!info.has_index) {
    return custom_index.at(index);
  } else if (index < info.cell_count && index_ptr) {
    return info.read_offset(index_ptr + (long)index * info.offset_byte_size);
  } else {
    // throw ?
    return 0;
  }
}

/*
 *
 *  Simple BoC serialization/deserialization functions
 *
 */

td::Result<Ref<Cell>> std_boc_deserialize(td::Slice data, bool can_be_empty, bool allow_nonzero_level) {
  if (data.empty() && can_be_empty) {
    return Ref<Cell>();
  }
  BagOfCells boc;
  auto res = boc.deserialize(data, 1);
  if (res.is_error()) {
    return res.move_as_error();
  }
  if (boc.get_root_count() != 1) {
    return td::Status::Error("bag of cells is expected to have exactly one root");
  }
  auto root = boc.get_root_cell();
  if (root.is_null()) {
    return td::Status::Error("bag of cells has null root cell (?)");
  }
  if (!allow_nonzero_level && root->get_level() != 0) {
    return td::Status::Error("bag of cells has a root with non-zero level");
  }
  return std::move(root);
}

td::Result<std::vector<Ref<Cell>>> std_boc_deserialize_multi(td::Slice data, int max_roots) {
  if (data.empty()) {
    return std::vector<Ref<Cell>>{};
  }
  BagOfCells boc;
  auto res = boc.deserialize(data, max_roots);
  if (res.is_error()) {
    return res.move_as_error();
  }
  int n = boc.get_root_count();
  std::vector<Ref<Cell>> roots;
  for (int i = 0; i < n; i++) {
    auto root = boc.get_root_cell(i);
    if (root.is_null()) {
      return td::Status::Error("bag of cells has a null root cell (?)");
    }
    if (root->get_level() != 0) {
      return td::Status::Error("bag of cells has a root with non-zero level");
    }
    roots.emplace_back(std::move(root));
  }
  return std::move(roots);
}

td::Result<td::BufferSlice> std_boc_serialize(Ref<Cell> root, int mode) {
  if (root.is_null()) {
    return td::Status::Error("cannot serialize a null cell reference into a bag of cells");
  }
  BagOfCells boc;
  boc.add_root(std::move(root));
  auto res = boc.import_cells();
  if (res.is_error()) {
    return res.move_as_error();
  }
  return boc.serialize_to_slice(mode);
}

td::Result<td::BufferSlice> std_boc_serialize_multi(std::vector<Ref<Cell>> roots, int mode) {
  if (roots.empty()) {
    return td::BufferSlice{};
  }
  BagOfCells boc;
  boc.add_roots(std::move(roots));
  auto res = boc.import_cells();
  if (res.is_error()) {
    return res.move_as_error();
  }
  return boc.serialize_to_slice(mode);
}
td::Status std_boc_serialize_to_file(Ref<Cell> root, td::FileFd& fd, int mode,
                                     td::CancellationToken cancellation_token) {
  if (root.is_null()) {
    return td::Status::Error("cannot serialize a null cell reference into a bag of cells");
  }
  td::Timer timer;
  BagOfCellsLogger logger(std::move(cancellation_token));
  BagOfCells boc;
  boc.set_logger(&logger);
  boc.add_root(std::move(root));
  TRY_STATUS(boc.import_cells());
  TRY_STATUS(boc.serialize_to_file(fd, mode));
  LOG(ERROR) << "serialization took " << timer.elapsed() << "s";
  return td::Status::OK();
}

namespace {

// Bounded read buffer for the streaming BoC importer. Owns a single
// resizeable scratch BufferSlice and refills it from `file` on demand.
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
  StreamingFileReader(td::FileFd& file, td::uint64 file_size, td::uint64 chunk_bytes)
      : file_(&file), file_size_(file_size), chunk_bytes_(chunk_bytes) {
  }

  // Return a Slice covering [offset, offset+len). Performs a pread when
  // the requested range is not entirely contained in the current scratch
  // buffer. The returned slice is invalidated by the next call to read()
  // or read_into(); callers must consume it before requesting more bytes.
  td::Result<td::Slice> read(td::uint64 offset, std::size_t len) {
    if (len == 0) {
      // Track even zero-length reads so a zero-byte probe between two
      // backward scans does not flip direction detection.
      return td::Slice{};
    }
    if (offset > file_size_ || len > file_size_ - offset) {
      return td::Status::Error(PSLICE() << "streaming BoC reader: out-of-range read offset=" << offset
                                        << " len=" << len << " file_size=" << file_size_);
    }
    if (len > chunk_bytes_) {
      // Caller asked for more than our scratch size; grow the scratch
      // buffer to fit this request. The growth is a single allocation
      // (no fragmentation) and is bounded by the per-cell size limit
      // imposed elsewhere in the caller, so a hostile peer cannot grow
      // the scratch arbitrarily.
      chunk_bytes_ = len;
      scratch_ = td::BufferSlice{};  // force a re-fill below
      cache_len_ = 0;
    }
    if (!cached_in_range(offset, len)) {
      if (scratch_.size() < chunk_bytes_) {
        scratch_ = td::BufferSlice{chunk_bytes_};
      }
      // Decide where to anchor the chunk window. The default is forward
      // (anchor at `offset`); we switch to backward (anchor so the chunk
      // ENDS at `offset + len`) when the access pattern shows the caller
      // is moving toward smaller offsets. We require the previous
      // request to be observed (last_request_seen_) before we trust the
      // direction signal — the very first read must always anchor
      // forward so the header probe at offset 0 stays valid.
      bool backward = false;
      if (last_request_seen_ && offset + len <= last_request_offset_) {
        backward = true;
      }
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
      auto status = file_->pread(dst, static_cast<td::int64>(chunk_start));
      if (status.is_error()) {
        return td::Status::Error(PSLICE() << "streaming BoC reader: pread failed at offset=" << chunk_start
                                          << ": " << status.error());
      }
      auto got = status.move_as_ok();
      if (got != static_cast<std::size_t>(want)) {
        return td::Status::Error(PSLICE() << "streaming BoC reader: short pread got=" << got << " want="
                                          << want << " at offset=" << chunk_start);
      }
      cache_offset_ = chunk_start;
      cache_len_ = static_cast<std::size_t>(want);
    }
    last_request_offset_ = offset;
    last_request_seen_ = true;
    auto buf = scratch_.as_slice();
    auto local = static_cast<std::size_t>(offset - cache_offset_);
    return buf.substr(local, len);
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
  td::uint64 chunk_bytes_;
  td::BufferSlice scratch_;
  td::uint64 cache_offset_{0};
  std::size_t cache_len_{0};
  // Direction-detection state. `last_request_offset_` records the start
  // offset of the most recent successful read; `last_request_seen_` is
  // false until the first read completes so the very first call cannot
  // be misclassified as backward.
  td::uint64 last_request_offset_{0};
  bool last_request_seen_{false};
};

}  // namespace

namespace {

// Adapter so the std::function-based public API delegates to the same
// sink-driven core implementation. begin/finish are no-ops; abort is a
// no-op. persist forwards each Ref<Cell> to the wrapped functor.
class FunctionStreamingCellSink final : public StreamingCellSink {
 public:
  explicit FunctionStreamingCellSink(StreamingPersistCellFn fn) : fn_(std::move(fn)) {
  }
  td::Status persist(td::Ref<Cell> cell) override {
    if (!fn_) {
      return td::Status::OK();
    }
    return fn_(std::move(cell));
  }

 private:
  StreamingPersistCellFn fn_;
};

// Core implementation. The two public overloads delegate here so the
// streaming pipeline lives in exactly one place. `sink` may be nullptr.
td::Result<td::Ref<Cell>> std_boc_deserialize_from_file_bounded_impl(td::FileFd& file, td::uint64 size,
                                                                     const StreamingBocImportOptions& opts,
                                                                     StreamingCellSink* sink);

}  // namespace

td::Result<td::Ref<Cell>> std_boc_deserialize_from_file_bounded(td::FileFd& file, td::uint64 size,
                                                                const StreamingBocImportOptions& opts,
                                                                StreamingPersistCellFn persist_cell) {
  if (!persist_cell) {
    return std_boc_deserialize_from_file_bounded_impl(file, size, opts, /*sink=*/nullptr);
  }
  FunctionStreamingCellSink adapter{std::move(persist_cell)};
  return std_boc_deserialize_from_file_bounded_impl(file, size, opts, &adapter);
}

td::Result<td::Ref<Cell>> std_boc_deserialize_from_file_bounded(td::FileFd& file, td::uint64 size,
                                                                const StreamingBocImportOptions& opts,
                                                                StreamingCellSink* sink) {
  return std_boc_deserialize_from_file_bounded_impl(file, size, opts, sink);
}

namespace {

// RAII guard: when the impl returns an error after the sink has been
// begun but before finish, call sink->abort() exactly once. The success
// path explicitly arms `disarm_` before the guard goes out of scope so
// no spurious abort is delivered after a clean finish.
class StreamingSinkAbortGuard {
 public:
  explicit StreamingSinkAbortGuard(StreamingCellSink* sink) : sink_(sink) {
  }
  StreamingSinkAbortGuard(const StreamingSinkAbortGuard&) = delete;
  StreamingSinkAbortGuard& operator=(const StreamingSinkAbortGuard&) = delete;
  ~StreamingSinkAbortGuard() {
    if (sink_ && armed_) {
      sink_->abort();
    }
  }
  void arm() {
    armed_ = true;
  }
  void disarm() {
    armed_ = false;
  }

 private:
  StreamingCellSink* sink_;
  bool armed_ = false;
};

td::Result<td::Ref<Cell>> std_boc_deserialize_from_file_bounded_impl(td::FileFd& file, td::uint64 size,
                                                                     const StreamingBocImportOptions& opts,
                                                                     StreamingCellSink* sink) {
  // Sink lifecycle: begin() is invoked exactly once after every header
  // validation has succeeded (right before the cell-build loop). If
  // begin succeeds the abort guard is armed; any error return from
  // here on triggers abort exactly once. The success path explicitly
  // calls finish + disarms the guard before returning the root cell.
  StreamingSinkAbortGuard abort_guard{sink};
  auto check_cancelled = [&opts]() -> td::Status {
    if (opts.is_cancelled && opts.is_cancelled()) {
      return td::Status::Error("std_boc_deserialize_from_file_bounded: import cancelled");
    }
    return td::Status::OK();
  };

  TRY_STATUS(check_cancelled());
  if (size == 0) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: zero-sized file");
  }
  // Layer 1: validate the announced size against the actual fd size.
  // The caller must own `file`; we only fstat it for the cross-check.
  TRY_RESULT(stat, file.stat());
  if (static_cast<td::uint64>(stat.size_) != size) {
    return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: file size mismatch: announced "
                                      << size << " observed " << stat.size_);
  }
  TRY_STATUS(check_cancelled());

  // The streaming reader buffers reads in 4 MiB chunks by default. The
  // chunk size is intentionally larger than the per-cell ceiling
  // (~64 KiB after data + refs + hash bytes) so a typical cell is
  // satisfied from the cached chunk without an extra pread.
  constexpr td::uint64 kStreamingChunkBytes = 4ULL << 20;
  StreamingFileReader reader(file, size, kStreamingChunkBytes);

  // Layer 2: read the BoC header. The header is a small fixed prefix
  // followed by ref-byte-sized metadata; we read up to 256 bytes which
  // is comfortably more than any valid header layout.
  constexpr std::size_t kHeaderProbe = 256;
  std::size_t probe_len = static_cast<std::size_t>(std::min<td::uint64>(size, kHeaderProbe));
  TRY_RESULT(header_probe, reader.read(0, probe_len));
  TRY_STATUS(check_cancelled());

  BagOfCells::Info info;
  long long size_est = info.parse_serialized_header(header_probe);
  if (size_est == 0) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: invalid BoC header");
  }
  if (size_est < 0) {
    // The header parser reports a negative estimate when it needs more
    // bytes; we already provided up to 256 which covers all valid BoC
    // header layouts.
    return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: header truncated, need "
                                      << -size_est << " bytes");
  }
  if (static_cast<td::uint64>(size_est) > size) {
    return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: declared total size "
                                      << size_est << " exceeds file size " << size);
  }
  if (info.cell_count <= 0 || info.root_count <= 0) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: empty BoC");
  }
  if (static_cast<td::uint64>(info.root_count) > opts.max_roots) {
    return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: too many roots "
                                      << info.root_count << " > " << opts.max_roots);
  }
  // H-03: a `max_cells == 0` request maps to `kDefaultStreamingBocMaxCells`,
  // never to "unlimited". The same rule applies to max_total_cell_bytes
  // and max_scaffolding_bytes below. A caller that omits these fields
  // gets the safe default; a caller that explicitly sets a non-zero
  // value gets that value verbatim.
  const td::uint64 effective_max_cells =
      opts.max_cells != 0 ? opts.max_cells : kDefaultStreamingBocMaxCells;
  if (static_cast<td::uint64>(info.cell_count) > effective_max_cells) {
    return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell count "
                                      << info.cell_count << " > max_cells " << effective_max_cells);
  }
  const td::uint64 effective_max_total_cell_bytes =
      opts.max_total_cell_bytes != 0 ? opts.max_total_cell_bytes : kDefaultStreamingBocMaxTotalCellBytes;
  if (info.data_size > effective_max_total_cell_bytes) {
    return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: declared data_size "
                                      << info.data_size << " > max_total_cell_bytes "
                                      << effective_max_total_cell_bytes);
  }
  TRY_STATUS(check_cancelled());

  // H-03 scaffolding budget. Compute the upper-bound bytes that would be
  // pulled into RAM for the importer's three O(cell_count) tables BEFORE
  // any of the four vectors is allocated. The arithmetic uses a manual
  // overflow check (no implicit reliance on wraparound) so a malicious
  // header announcing a `cell_count` near 2^64 / sizeof(Ref<Cell>) is
  // rejected here rather than after a partial allocation. Zero in the
  // option means "use default cap"; a non-zero value is honoured
  // verbatim.
  const td::uint64 effective_max_scaffolding_bytes =
      opts.max_scaffolding_bytes != 0 ? opts.max_scaffolding_bytes : kDefaultStreamingBocMaxScaffoldingBytes;
  {
    auto safe_add = [](td::uint64& acc, td::uint64 v) -> bool {
      if (v > std::numeric_limits<td::uint64>::max() - acc) {
        return false;
      }
      acc += v;
      return true;
    };
    auto safe_mul = [](td::uint64 a, td::uint64 b, td::uint64& out) -> bool {
      if (a == 0 || b == 0) {
        out = 0;
        return true;
      }
      if (a > std::numeric_limits<td::uint64>::max() / b) {
        return false;
      }
      out = a * b;
      return true;
    };
    const td::uint64 cell_count_u64 = static_cast<td::uint64>(info.cell_count);
    td::uint64 scaffolding = 0;
    td::uint64 product = 0;
    // offset_table: (cell_count + 1) * sizeof(td::uint64). The +1 must
    // not overflow either, hence the explicit check.
    if (cell_count_u64 == std::numeric_limits<td::uint64>::max() ||
        !safe_mul(cell_count_u64 + 1, sizeof(td::uint64), product) ||
        !safe_add(scaffolding, product) ||
        !safe_mul(cell_count_u64, sizeof(td::uint32), product) ||
        !safe_add(scaffolding, product) ||
        !safe_mul(cell_count_u64, sizeof(td::Ref<vm::Cell>), product) ||
        !safe_add(scaffolding, product)) {
      return td::Status::Error(PSLICE()
                               << "std_boc_deserialize_from_file_bounded: BoC scaffolding size overflow for "
                               << info.cell_count << " cells");
    }
    if (scaffolding > effective_max_scaffolding_bytes) {
      return td::Status::Error(PSLICE()
                               << "std_boc_deserialize_from_file_bounded: BoC scaffolding budget exceeded: "
                               << scaffolding << " > " << effective_max_scaffolding_bytes);
    }
  }
  TRY_STATUS(check_cancelled());

  // Layer 3: optional CRC32C trailer. For a streaming reader we can
  // validate it incrementally by streaming the body in chunks; this
  // keeps peak resident memory at the chunk size while preserving the
  // fail-closed guarantee a one-shot deserialize provides.
  if (info.has_crc32c) {
    if (size < 4) {
      return td::Status::Error("std_boc_deserialize_from_file_bounded: CRC32C trailer missing");
    }
    td::uint32 crc_computed = 0;
    auto status = reader.stream(0, size - 4, [&](td::Slice chunk) -> td::Status {
      TRY_STATUS(check_cancelled());
      crc_computed = td::crc32c_extend(crc_computed, chunk);
      return check_cancelled();
    });
    if (status.is_error()) {
      return std::move(status);
    }
    TRY_STATUS(check_cancelled());
    TRY_RESULT(trailer, reader.read(size - 4, 4));
    td::uint32 crc_stored = td::as<td::uint32>(trailer.ubegin());
    if (crc_computed != crc_stored) {
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: CRC32C mismatch: expected "
                                        << td::format::as_hex(crc_computed) << " found "
                                        << td::format::as_hex(crc_stored));
    }
  }

  // Layer 4: read root indices. Stored at info.roots_offset, root_count
  // entries, ref_byte_size each. Total size is bounded by max_roots.
  // The vector is tiny (max_roots is 1 by default), but H-03 still
  // requires every BoC import vector to fail closed on bad_alloc — a
  // hostile thread allocator can starve any allocation, however small.
  std::vector<int> root_indices;
  try {
    root_indices.assign(static_cast<std::size_t>(info.root_count), 0);
  } catch (const std::bad_alloc&) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: cannot allocate BoC import scaffolding");
  } catch (...) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: cannot allocate BoC import scaffolding");
  }
  if (info.has_roots) {
    td::uint64 roots_bytes = static_cast<td::uint64>(info.root_count) * info.ref_byte_size;
    TRY_RESULT(roots_slice, reader.read(info.roots_offset, static_cast<std::size_t>(roots_bytes)));
    for (int i = 0; i < info.root_count; ++i) {
      int idx = static_cast<int>(info.read_ref(roots_slice.ubegin() + i * info.ref_byte_size));
      if (idx < 0 || idx >= info.cell_count) {
        return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: invalid root index "
                                          << idx);
      }
      root_indices[i] = idx;
      TRY_STATUS(check_cancelled());
    }
  }
  TRY_STATUS(check_cancelled());

  // Layer 5: build the cell offset table. With `has_index=true` the
  // index lives in the file at info.index_offset (cell_count *
  // offset_byte_size bytes). With `has_index=false` we synthesize the
  // table by scanning the cell descriptors. Either way the resulting
  // table is O(cell_count * 8) bytes — bounded but still the largest
  // scaffolding in this function. For 16 GiB BoC at typical cell sizes
  // (~100 bytes/cell) this is ~1.3 GiB; for a 600 MiB BoC at the same
  // density it is ~50 MiB. The spec tolerates this because the
  // scaffolding lives only for the duration of the streaming pass.
  std::vector<td::uint64> offset_table;
  try {
    offset_table.assign(static_cast<std::size_t>(info.cell_count) + 1, 0);
  } catch (const std::bad_alloc&) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: cannot allocate BoC import scaffolding");
  } catch (...) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: cannot allocate BoC import scaffolding");
  }
  if (info.has_index) {
    td::uint64 index_bytes = static_cast<td::uint64>(info.cell_count) * info.offset_byte_size;
    // Read the index in chunks to keep the scratch reader usable; copy
    // each entry into offset_table.
    td::uint64 done = 0;
    constexpr td::uint64 kIndexChunkBytes = 1ULL << 20;
    while (done < index_bytes) {
      TRY_STATUS(check_cancelled());
      td::uint64 want = std::min<td::uint64>(index_bytes - done, kIndexChunkBytes);
      // Round to a multiple of offset_byte_size so we never split an entry.
      td::uint64 want_aligned = (want / info.offset_byte_size) * info.offset_byte_size;
      if (want_aligned == 0) {
        want_aligned = info.offset_byte_size;
      }
      TRY_RESULT(slice, reader.read(info.index_offset + done, static_cast<std::size_t>(want_aligned)));
      std::size_t entries = static_cast<std::size_t>(want_aligned / info.offset_byte_size);
      std::size_t start = static_cast<std::size_t>(done / info.offset_byte_size);
      for (std::size_t i = 0; i < entries; ++i) {
        td::uint64 raw = info.read_offset(slice.ubegin() + i * info.offset_byte_size);
        if (info.has_cache_bits) {
          raw /= 2;
        }
        offset_table[start + i + 1] = raw;
      }
      done += want_aligned;
    }
    // Round 160 LOW fix: validate that the indexed offset table
    // ends at info.data_size, mirroring the non-indexed walk's
    // cur-vs-data_size check below.  Same canonical-form gap as
    // in the one-shot deserialize path.
    if (info.cell_count > 0 &&
        offset_table[static_cast<std::size_t>(info.cell_count)] !=
            info.data_size) {
      return td::Status::Error(
          PSLICE() << "std_boc_deserialize_from_file_bounded: indexed last "
                      "cell end offset "
                   << offset_table[static_cast<std::size_t>(info.cell_count)]
                   << " != declared data_size " << info.data_size);
    }
  } else {
    // Synthesize the offset table by scanning cell descriptors. Each
    // cell starts at cumulative offset `cur`; reading the first two
    // descriptor bytes is enough to compute its end_offset. We pull
    // every descriptor through the streaming reader so peak resident
    // memory stays bounded by the chunk buffer.
    td::uint64 cur = 0;
    td::uint64 cells_base = info.data_offset;
    for (int i = 0; i < info.cell_count; ++i) {
      TRY_STATUS(check_cancelled());
      // Need at least the descriptor (2 bytes) and the trailing data +
      // ref bytes. Read up to 64 bytes to cover any descriptor + small
      // payload; if the descriptor declares more, re-read with the exact
      // length below.
      td::uint64 absolute = cells_base + cur;
      if (absolute + 2 > size) {
        return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << i
                                          << " descriptor truncated at offset " << absolute);
      }
      TRY_RESULT(probe, reader.read(absolute, 2));
      td::uint8 d1 = probe.ubegin()[0];
      td::uint8 d2 = probe.ubegin()[1];
      CellSerializationInfo cs_info;
      auto status = cs_info.init(d1, d2, info.ref_byte_size);
      if (status.is_error()) {
        return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << i
                                          << " descriptor invalid: " << status.error());
      }
      cur += cs_info.end_offset;
      offset_table[static_cast<std::size_t>(i) + 1] = cur;
    }
    if (cur != info.data_size) {
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell-walk size "
                                        << cur << " != declared data_size " << info.data_size);
    }
  }
  TRY_STATUS(check_cancelled());

  // Layer 5b: count parent references per child index. A cell at
  // index `idx` is held resident in `cells` only as long as it has at
  // least one outstanding parent that has not yet been deserialized.
  // We compute the total parent count up front by scanning each cell's
  // descriptor once. The scan is O(cell_count) reads through the
  // streaming reader; each read hits the per-chunk cache so a typical
  // BoC requires only ceil(file_size / chunk_bytes) preads total.
  //
  // Roots are explicitly counted as "parents" so the root cell is not
  // dropped by the residency tracker before the function returns it.
  std::vector<td::uint32> parent_refcount;
  try {
    parent_refcount.assign(static_cast<std::size_t>(info.cell_count), 0);
  } catch (const std::bad_alloc&) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: cannot allocate BoC import scaffolding");
  } catch (...) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: cannot allocate BoC import scaffolding");
  }
  for (int idx : root_indices) {
    parent_refcount[static_cast<std::size_t>(idx)] += 1;
  }
  for (int i = 0; i < info.cell_count; ++i) {
    TRY_STATUS(check_cancelled());
    td::uint64 cell_offset = offset_table[static_cast<std::size_t>(i)];
    td::uint64 cell_end = offset_table[static_cast<std::size_t>(i) + 1];
    if (cell_offset > cell_end || cell_end > info.data_size) {
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << i
                                        << " offset table corrupt during parent walk");
    }
    std::size_t cell_len = static_cast<std::size_t>(cell_end - cell_offset);
    if (cell_len < 2) {
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << i
                                        << " too small during parent walk");
    }
    TRY_RESULT(cs_slice, reader.read(info.data_offset + cell_offset, cell_len));
    CellSerializationInfo cs_info;
    auto status = cs_info.init(cs_slice, info.ref_byte_size);
    if (status.is_error()) {
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << i
                                        << " descriptor invalid in parent walk: " << status.error());
    }
    for (int k = 0; k < cs_info.refs_cnt; ++k) {
      int ref_idx = static_cast<int>(
          info.read_ref(cs_slice.ubegin() + cs_info.refs_offset + k * info.ref_byte_size));
      if (ref_idx <= i || ref_idx >= info.cell_count) {
        return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << i
                                          << " ref #" << k << " has invalid target " << ref_idx);
      }
      auto& rc = parent_refcount[static_cast<std::size_t>(ref_idx)];
      if (rc == std::numeric_limits<td::uint32>::max()) {
        return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: parent refcount "
                                             "overflow at cell #"
                                          << ref_idx);
      }
      rc += 1;
    }
  }
  TRY_STATUS(check_cancelled());

  // Sink begin: every header invariant has been validated and the
  // offset table + parent_refcount scaffolding is built. The sink may
  // now allocate per-import resources (write batches, accumulators);
  // the abort guard ensures abort() runs on any error after this point.
  if (sink) {
    TRY_STATUS(check_cancelled());
    auto begin_status = sink->begin();
    if (begin_status.is_error()) {
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: sink begin rejected: "
                                        << begin_status.error());
    }
    abort_guard.arm();
  }

  // Layer 6: streaming deserialize. Iterate cells from leaves to root
  // (highest BoC index first) and build each one. The parent_refcount
  // array drives residency: each time a parent claims a child the
  // count is decremented, and the child slot in `cells` is dropped
  // when the count hits zero. Resident memory peaks at the longest
  // dependency chain rather than the full cell count.
  std::vector<td::Ref<Cell>> cells;
  try {
    cells.assign(static_cast<std::size_t>(info.cell_count), td::Ref<Cell>{});
  } catch (const std::bad_alloc&) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: cannot allocate BoC import scaffolding");
  } catch (...) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: cannot allocate BoC import scaffolding");
  }

  // Resident-byte tracker. Each cell's contribution is its serialized
  // payload size, which is a tight overestimate of the DataCell heap
  // footprint. We charge against `opts.max_resident_bytes` whenever a
  // cell enters the residency window and credit it back when the slot
  // is released. The budget is fail-closed: once the cap is exceeded,
  // abort immediately instead of parsing the rest of an attacker-controlled
  // BoC and only returning an error at the end.
  td::uint64 resident_bytes = 0;
  td::uint64 peak_resident_bytes = 0;
  bool resident_cap_exceeded = false;

  // Per-cell scratch buffer for descriptor + data + refs. Sized at the
  // max possible cell length (max_cell_whs is 64 hashes * (32 + 2)
  // bytes plus the 4 ref slots and data).
  for (int i = 0; i < info.cell_count; ++i) {
    TRY_STATUS(check_cancelled());
    int idx = info.cell_count - 1 - i;
    td::uint64 cell_offset = offset_table[static_cast<std::size_t>(idx)];
    td::uint64 cell_end = offset_table[static_cast<std::size_t>(idx) + 1];
    if (cell_offset > cell_end || cell_end > info.data_size) {
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << idx
                                        << " offset table corrupt [" << cell_offset << "," << cell_end
                                        << "]");
    }
    std::size_t cell_len = static_cast<std::size_t>(cell_end - cell_offset);
    if (cell_len < 2) {
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << idx
                                        << " too small");
    }
    TRY_RESULT(cell_slice, reader.read(info.data_offset + cell_offset, cell_len));
    CellSerializationInfo cs_info;
    auto status = cs_info.init(cell_slice, info.ref_byte_size);
    if (status.is_error()) {
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: failed to deserialize cell #"
                                        << idx << ": " << status.error());
    }
    if (cs_info.end_offset != cell_slice.size()) {
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << idx
                                        << " has unused trailing bytes");
    }

    std::array<td::Ref<Cell>, 4> refs_buf;
    auto refs = td::MutableSpan<td::Ref<Cell>>(refs_buf).substr(0, cs_info.refs_cnt);
    for (int k = 0; k < cs_info.refs_cnt; ++k) {
      int ref_idx = static_cast<int>(
          info.read_ref(cell_slice.ubegin() + cs_info.refs_offset + k * info.ref_byte_size));
      if (ref_idx <= idx) {
        return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << idx
                                          << " ref #" << k << " points to cell #" << ref_idx
                                          << " with smaller-or-equal index");
      }
      if (ref_idx >= info.cell_count) {
        return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << idx
                                          << " ref #" << k << " points to non-existent cell #" << ref_idx);
      }
      auto& slot = cells[static_cast<std::size_t>(ref_idx)];
      if (slot.is_null()) {
        return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << idx
                                          << " ref #" << k << " (cell #" << ref_idx
                                          << ") was already released");
      }
      refs[k] = slot;
      // Decrement refcount; if this was the final outstanding parent,
      // free our copy. The DataCell will live on via the parent's ref.
      auto& rc = parent_refcount[static_cast<std::size_t>(ref_idx)];
      if (rc == 0) {
        return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: parent refcount "
                                             "underflow at cell #"
                                          << ref_idx);
      }
      rc -= 1;
      if (rc == 0) {
        // Charge back the residency contribution of the released cell
        // using the offset table (cell N's serialized size is
        // offset_table[N+1] - offset_table[N], which is a tight
        // overestimate of the DataCell heap footprint).
        td::uint64 freed = offset_table[static_cast<std::size_t>(ref_idx) + 1] -
                           offset_table[static_cast<std::size_t>(ref_idx)];
        if (resident_bytes >= freed) {
          resident_bytes -= freed;
        } else {
          resident_bytes = 0;
        }
        cells[static_cast<std::size_t>(ref_idx)] = td::Ref<Cell>{};
      }
    }

    auto r_data_cell = cs_info.create_data_cell(cell_slice, refs);
    if (r_data_cell.is_error()) {
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: cell #" << idx
                                        << " create_data_cell failed: " << r_data_cell.error());
    }
    auto data_cell = r_data_cell.move_as_ok();
    // Count this cell's parent expectations: every cell that arrives
    // later in iteration with a ref to `idx` will decrement this
    // counter. The lookup is done through cells[idx]; `idx` is fixed
    // for the lifetime of the loop entry.
    // (We pre-seeded root contributions above so the actual parent walk
    //  is sufficient; siblings that share a child are handled because
    //  every parent decrements once.)

    // Peer-friendly residency accounting: we charge the BoC-declared
    // cell size (offset_table delta), which is what the caller is
    // being asked to keep resident.
    td::uint64 cost = offset_table[static_cast<std::size_t>(idx) + 1] -
                      offset_table[static_cast<std::size_t>(idx)];
    resident_bytes += cost;
    if (resident_bytes > peak_resident_bytes) {
      peak_resident_bytes = resident_bytes;
    }
    if (opts.max_resident_bytes > 0 && resident_bytes > opts.max_resident_bytes) {
      resident_cap_exceeded = true;
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: peak resident bytes "
                                        << peak_resident_bytes << " exceeded cap "
                                        << opts.max_resident_bytes
                                        << "; aborting import immediately");
    }

    auto cell_ref = td::Ref<Cell>{std::move(data_cell)};
    if (sink) {
      auto original_hash = cell_ref->get_hash();
      TRY_STATUS(check_cancelled());
      auto replacement = sink->persist_and_replace(cell_ref);
      if (replacement.is_error()) {
        return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: persist_cell rejected "
                                             "cell #"
                                          << idx << ": " << replacement.error());
      }
      cell_ref = replacement.move_as_ok();
      if (cell_ref.is_null()) {
        return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: persist_cell returned "
                                             "null replacement for cell #"
                                          << idx);
      }
      if (cell_ref->get_hash() != original_hash) {
        return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: persist_cell returned "
                                             "replacement with different hash for cell #"
                                          << idx);
      }
    }
    cells[static_cast<std::size_t>(idx)] = std::move(cell_ref);

    // Walk this cell's refs again purely to account parent counts for
    // the *remaining* descendants. (Each child has already had its
    // refcount decremented above to model parent consumption; here we
    // attribute the reverse direction so each parent counts exactly
    // once toward each child.)
    // The loop above already handled both directions; nothing else is
    // needed here.
  }

  if (resident_cap_exceeded) {
    return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: peak resident bytes "
                                      << peak_resident_bytes << " exceeded cap " << opts.max_resident_bytes
                                      << "; raise StreamingBocImportOptions::max_resident_bytes "
                                         "or split the import");
  }

  // Layer 7: assemble the root cell. Single-root contract: the API
  // returns the first declared root; if the BoC has multiple roots a
  // separate multi-root entry point would be required.
  if (root_indices.empty()) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: BoC has no roots");
  }
  TRY_STATUS(check_cancelled());
  auto root_idx = root_indices[0];
  auto root = cells[static_cast<std::size_t>(root_idx)];
  if (root.is_null()) {
    return td::Status::Error("std_boc_deserialize_from_file_bounded: root cell missing after import");
  }
  // Release any other live entries (multi-root case): the caller only
  // sees the first root, but all roots' cells must persist long enough
  // for the caller's persist_cell callback to have observed them. We
  // already invoked persist_cell for every cell, so we can drop our
  // remaining refs here.
  cells.clear();
  parent_refcount.clear();

  // Sink finish: every cell has been persisted and the root is about
  // to be returned. The sink may now commit its write batch / close
  // its transaction. A finish error aborts the import (the abort guard
  // is still armed so abort() runs); a success path disarms the guard
  // so abort() does NOT run on the way out.
  if (sink) {
    TRY_STATUS(check_cancelled());
    auto finish_status = sink->finish(root->get_hash());
    if (finish_status.is_error()) {
      return td::Status::Error(PSLICE() << "std_boc_deserialize_from_file_bounded: sink finish rejected: "
                                        << finish_status.error());
    }
    abort_guard.disarm();
  }
  return root;
}

}  // namespace

/*
 *
 *  Cell storage statistics
 *
 */

td::Result<CellStorageStat::CellInfo> CellStorageStat::compute_used_storage(Ref<vm::CellSlice> cs_ref, bool kill_dup,
                                                                            unsigned skip_count_root) {
  clear();
  TRY_RESULT(res, add_used_storage(std::move(cs_ref), kill_dup, skip_count_root));
  clear_seen();
  return res;
}

td::Result<CellStorageStat::CellInfo> CellStorageStat::compute_used_storage(const CellSlice& cs, bool kill_dup,
                                                                            unsigned skip_count_root) {
  clear();
  TRY_RESULT(res, add_used_storage(cs, kill_dup, skip_count_root));
  clear_seen();
  return res;
}

td::Result<CellStorageStat::CellInfo> CellStorageStat::compute_used_storage(CellSlice&& cs, bool kill_dup,
                                                                            unsigned skip_count_root) {
  clear();
  TRY_RESULT(res, add_used_storage(std::move(cs), kill_dup, skip_count_root));
  clear_seen();
  return res;
}

td::Result<CellStorageStat::CellInfo> CellStorageStat::compute_used_storage(Ref<vm::Cell> cell, bool kill_dup,
                                                                            unsigned skip_count_root) {
  clear();
  TRY_RESULT(res, add_used_storage(std::move(cell), kill_dup, skip_count_root));
  clear_seen();
  return res;
}

td::Result<CellStorageStat::CellInfo> CellStorageStat::add_used_storage(Ref<vm::CellSlice> cs_ref, bool kill_dup,
                                                                        unsigned skip_count_root) {
  if (cs_ref->is_unique()) {
    return add_used_storage(std::move(cs_ref.unique_write()), kill_dup, skip_count_root);
  } else {
    return add_used_storage(*cs_ref, kill_dup, skip_count_root);
  }
}

td::Result<CellStorageStat::CellInfo> CellStorageStat::add_used_storage(const CellSlice& cs, bool kill_dup,
                                                                        unsigned skip_count_root) {
  if (!(skip_count_root & 1)) {
    ++cells;
    if (cells > limit_cells) {
      return td::Status::Error("too many cells");
    }
  }
  if (!(skip_count_root & 2)) {
    bits += cs.size();
    if (bits > limit_bits) {
      return td::Status::Error("too many bits");
    }
  }
  CellInfo res;
  for (unsigned i = 0; i < cs.size_refs(); i++) {
    TRY_RESULT(child, add_used_storage(cs.prefetch_ref(i), kill_dup));
    res.max_merkle_depth = std::max(res.max_merkle_depth, child.max_merkle_depth);
  }
  if (cs.special_type() == CellTraits::SpecialType::MerkleProof ||
      cs.special_type() == CellTraits::SpecialType::MerkleUpdate) {
    ++res.max_merkle_depth;
  }
  return res;
}

td::Result<CellStorageStat::CellInfo> CellStorageStat::add_used_storage(CellSlice&& cs, bool kill_dup,
                                                                        unsigned skip_count_root) {
  if (!(skip_count_root & 1)) {
    ++cells;
    if (cells > limit_cells) {
      return td::Status::Error("too many cells");
    }
  }
  if (!(skip_count_root & 2)) {
    bits += cs.size();
    if (bits > limit_bits) {
      return td::Status::Error("too many bits");
    }
  }
  CellInfo res;
  while (cs.size_refs()) {
    TRY_RESULT(child, add_used_storage(cs.fetch_ref(), kill_dup));
    res.max_merkle_depth = std::max(res.max_merkle_depth, child.max_merkle_depth);
  }
  if (cs.special_type() == CellTraits::SpecialType::MerkleProof ||
      cs.special_type() == CellTraits::SpecialType::MerkleUpdate) {
    ++res.max_merkle_depth;
  }
  return res;
}

td::Result<CellStorageStat::CellInfo> CellStorageStat::add_used_storage(Ref<vm::Cell> cell, bool kill_dup,
                                                                        unsigned skip_count_root) {
  if (cell.is_null()) {
    return td::Status::Error("cell is null");
  }
  if (kill_dup) {
    auto ins = seen.emplace(cell->get_hash(), CellInfo{});
    if (!ins.second) {
      return ins.first->second;
    }
  }
  vm::CellSlice cs{vm::NoVm{}, cell};
  TRY_RESULT(res, add_used_storage(std::move(cs), kill_dup, skip_count_root));
  if (kill_dup) {
    seen[cell->get_hash()] = res;
  }
  return res;
}

td::Result<CellStorageStat::CellInfo> CellStorageStat::add_used_storage(td::Span<Ref<Cell>> cells, bool kill_dup,
                                                                        unsigned skip_count_root) {
  CellInfo result;
  for (const auto& cell : cells) {
    TRY_RESULT(info, add_used_storage(cell, kill_dup, skip_count_root));
    result.max_merkle_depth = std::max(result.max_merkle_depth, info.max_merkle_depth);
  }
  return result;
}

void NewCellStorageStat::add_cell(Ref<Cell> cell) {
  dfs(std::move(cell), true, false);
}
void NewCellStorageStat::add_proof(Ref<Cell> cell, const CellUsageTree* usage_tree) {
  CHECK(usage_tree);
  usage_tree_ = usage_tree;
  dfs(std::move(cell), false, true);
}
void NewCellStorageStat::add_cell_and_proof(Ref<Cell> cell, const CellUsageTree* usage_tree) {
  CHECK(usage_tree);
  usage_tree_ = usage_tree;
  dfs(std::move(cell), true, true);
}

NewCellStorageStat::Stat NewCellStorageStat::tentative_add_cell(Ref<Cell> cell) const {
  NewCellStorageStat stat;
  stat.parent_ = this;
  stat.add_cell(std::move(cell));
  return stat.get_stat();
}

NewCellStorageStat::Stat NewCellStorageStat::tentative_add_proof(Ref<Cell> cell,
                                                                 const CellUsageTree* usage_tree) const {
  NewCellStorageStat stat;
  stat.parent_ = this;
  stat.add_proof(std::move(cell), usage_tree);
  return stat.get_proof_stat();
}

void NewCellStorageStat::dfs(Ref<Cell> cell, bool need_stat, bool need_proof_stat) {
  if (cell.is_null()) {
    // FIXME: save error flag?
    return;
  }
  if (need_stat) {
    stat_.internal_refs++;
    if ((parent_ && parent_->seen_.count(cell->get_hash()) != 0) || !seen_.insert(cell->get_hash()).second) {
      need_stat = false;
    } else {
      stat_.cells++;
    }
  }

  if (need_proof_stat) {
    auto tree_node = cell->get_tree_node();
    if (!tree_node.empty() && tree_node.is_from_tree(usage_tree_)) {
      proof_stat_.external_refs++;
      need_proof_stat = false;
    } else {
      proof_stat_.internal_refs++;
      if ((parent_ && parent_->proof_seen_.count(cell->get_hash()) != 0) ||
          !proof_seen_.insert(cell->get_hash()).second) {
        need_proof_stat = false;
      } else {
        proof_stat_.cells++;
      }
    }
  }

  if (!need_proof_stat && !need_stat) {
    return;
  }
  vm::CellSlice cs{vm::NoVm{}, std::move(cell)};
  if (need_stat) {
    stat_.bits += cs.size();
  }
  if (need_proof_stat) {
    proof_stat_.bits += cs.size();
  }
  while (cs.size_refs()) {
    dfs(cs.fetch_ref(), need_stat, need_proof_stat);
  }
}

bool VmStorageStat::add_storage(Ref<Cell> cell) {
  if (cell.is_null() || !check_visited(cell)) {
    return true;
  }
  if (cells >= limit) {
    return false;
  }
  ++cells;
  bool special;
  auto cs = load_cell_slice_special(std::move(cell), special);
  return cs.is_valid() && add_storage(std::move(cs));
}

bool VmStorageStat::add_storage(const CellSlice& cs) {
  bits += cs.size();
  refs += cs.size_refs();
  for (unsigned i = 0; i < cs.size_refs(); i++) {
    if (!add_storage(cs.prefetch_ref(i))) {
      return false;
    }
  }
  return true;
}

void ProofStorageStat::add_loaded_cell(const Ref<DataCell>& cell, td::uint8 max_level) {
  max_level = std::min<td::uint8>(max_level, Cell::max_level);
  auto& [status, size] = cells_[cell->get_hash(max_level)];
  if (status == c_loaded) {
    return;
  }
  proof_size_ -= size;
  status = c_loaded;
  proof_size_ += size = estimate_serialized_size(cell);
  max_level += (cell->special_type() == CellTraits::SpecialType::MerkleProof ||
                cell->special_type() == CellTraits::SpecialType::MerkleUpdate);
  for (unsigned i = 0; i < cell->size_refs(); ++i) {
    auto& [child_status, child_size] = cells_[cell->get_ref(i)->get_hash(max_level)];
    if (child_status == c_none) {
      child_status = c_prunned;
      proof_size_ += child_size = estimate_prunned_size();
    }
  }
}

void ProofStorageStat::add_loaded_cells(const ProofStorageStat& other) {
  for (const auto& [hash, x] : other.cells_) {
    const auto& [new_status, new_size] = x;
    auto& [old_status, old_size] = cells_[hash];
    if (old_status >= new_status) {
      continue;
    }
    proof_size_ -= old_size;
    old_status = new_status;
    proof_size_ += old_size = new_size;
  }
}

td::uint64 ProofStorageStat::estimate_proof_size() const {
  return proof_size_;
}

ProofStorageStat::CellStatus ProofStorageStat::get_cell_status(const Cell::Hash& hash) const {
  auto it = cells_.find(hash);
  return it == cells_.end() ? c_none : it->second.first;
}

td::uint64 ProofStorageStat::estimate_prunned_size() {
  return 41;
}

td::uint64 ProofStorageStat::estimate_serialized_size(const Ref<DataCell>& cell) {
  return cell->get_serialized_size() + cell->size_refs() * 3 + 3;
}

}  // namespace vm
