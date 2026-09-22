/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#ifdef NDEBUG
#undef NDEBUG  // test assertions must stay live even in Release (-DNDEBUG)
#endif
#include <cassert>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "crypto/pq/pq-bytes.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"

using namespace tos::pq;

static std::string roundtrip(const std::string& s, std::size_t max) {
  auto packed = pack_pq_bytes(td::Slice(s), max);
  assert(packed.is_ok());
  auto un = unpack_pq_bytes(packed.move_as_ok(), max);
  assert(un.is_ok());
  return un.move_as_ok().as_slice().str();
}

int main() {
  // round-trip across chunk boundaries + the real ML-DSA-44 sizes
  for (std::size_t n : {std::size_t(0), std::size_t(1), std::size_t(126), std::size_t(127), std::size_t(128),
                        std::size_t(254), std::size_t(1312), std::size_t(2420)}) {
    std::string s(n, '\0');
    for (std::size_t i = 0; i < n; i++)
      s[i] = char((i * 131 + 7) & 0xff);
    assert(roundtrip(s, 2420) == s);
  }
  // oversize refused on pack and on unpack
  assert(pack_pq_bytes(td::Slice(std::string(2421, 'x')), 2420).is_error());
  {
    auto p = pack_pq_bytes(td::Slice(std::string(2420, 'x')), 2420).move_as_ok();
    assert(unpack_pq_bytes(p, 1312).is_error());
  }
  // canonical negative: a non-last chunk holding 100 bytes instead of a full 127
  {
    std::string s(254, 'a');
    auto c3 = [&] {
      vm::CellBuilder cb;
      cb.store_bytes_bool(td::Slice(s).substr(227, 27));
      return cb.finalize();
    }();
    auto c2 = [&] {
      vm::CellBuilder cb;
      cb.store_bytes_bool(td::Slice(s).substr(100, 127));
      cb.store_ref(c3);
      return cb.finalize();
    }();
    auto c1 = [&] {
      vm::CellBuilder cb;
      cb.store_bytes_bool(td::Slice(s).substr(0, 100));
      cb.store_ref(c2);
      return cb.finalize();
    }();
    vm::CellBuilder root;
    root.store_long(254, 32);
    root.store_ref(c1);
    assert(unpack_pq_bytes(root.finalize(), 2420).is_error());
  }
  // canonical negative: length says 200 but the snake is shorter
  {
    auto data = [&] {
      vm::CellBuilder cb;
      cb.store_bytes_bool(td::Slice(std::string(50, 'q')));
      return cb.finalize();
    }();
    vm::CellBuilder root;
    root.store_long(200, 32);
    root.store_ref(data);
    assert(unpack_pq_bytes(root.finalize(), 2420).is_error());
  }
#ifdef PQ_BYTES_VECTORS
  {  // shared cross-language fixture: pack matches the recorded cell hash + BOC; BOC unpacks back
    std::ifstream f(PQ_BYTES_VECTORS);
    assert(f);
    std::string line;
    int seen = 0;
    while (std::getline(f, line)) {
      if (line.empty())
        continue;
      auto sp1 = line.find(' '), sp2 = line.find(' ', sp1 + 1);
      assert(sp1 != std::string::npos && sp2 != std::string::npos);
      auto input = td::hex_decode(line.substr(0, sp1)).move_as_ok();
      auto root_hex = line.substr(sp1 + 1, sp2 - sp1 - 1);
      auto boc = td::hex_decode(line.substr(sp2 + 1)).move_as_ok();
      auto cell = pack_pq_bytes(td::Slice(input), 2420).move_as_ok();
      assert(td::hex_encode(cell->get_hash().as_slice()) == root_hex);
      assert(td::hex_encode(vm::std_boc_serialize(cell, 31).move_as_ok().as_slice()) == td::hex_encode(td::Slice(boc)));
      auto decoded = vm::std_boc_deserialize(boc).move_as_ok();
      assert(unpack_pq_bytes(decoded, 2420).move_as_ok().as_slice().str() == input);
      seen++;
    }
    assert(seen >= 8);
  }
#endif
  {  // canonicality battery: every structural rule gets its own attacking tree.
     // A rule no test can break is not an enforced rule.
    auto data_cell = [](const std::string& bytes, std::vector<vm::Ref<vm::Cell>> refs) {
      vm::CellBuilder cb;
      cb.store_bytes_bool(td::Slice(bytes));
      for (auto& r : refs)
        cb.store_ref(r);
      return cb.finalize();
    };
    auto root_cell = [](unsigned long long len, int bits, std::vector<vm::Ref<vm::Cell>> refs) {
      vm::CellBuilder cb;
      cb.store_long(static_cast<long long>(len), bits);
      for (auto& r : refs)
        cb.store_ref(r);
      return cb.finalize();
    };
    const std::string b127(127, '\x01'), b100(100, '\x01'), b73(73, '\x01'), b10(10, '\x01');
    auto tail = data_cell(b73, {});

    // A well-formed snake of arbitrary length: otherwise perfectly canonical, so the
    // ONLY thing that can reject it is the absolute ceiling. Built here rather than via
    // pack_pq_bytes because pack itself refuses to exceed the ceiling.
    auto snake = [&](std::size_t len) {
      vm::Ref<vm::Cell> next;
      const std::size_t nchunks = (len + pq_bytes_chunk - 1) / pq_bytes_chunk;
      for (std::size_t i = nchunks; i-- > 0;) {
        const std::size_t off = i * pq_bytes_chunk;
        const std::size_t n = std::min(pq_bytes_chunk, len - off);
        vm::CellBuilder cb;
        cb.store_bytes_bool(td::Slice(std::string(n, '\x05')));
        if (next.not_null())
          cb.store_ref(next);
        next = cb.finalize();
      }
      vm::CellBuilder rb;
      rb.store_long(static_cast<long long>(len), 32);
      if (next.not_null())
        rb.store_ref(next);
      return rb.finalize();
    };
    // absolute ceiling: a permissive caller limit must NOT unlock it
    assert(pack_pq_bytes(td::Slice(std::string(pq_bytes_hard_max + 1, 'x')), 0xffffffffULL).is_error());
    assert(pack_pq_bytes(td::Slice(std::string(pq_bytes_hard_max, 'x')), 0xffffffffULL).is_ok());
    assert(unpack_pq_bytes(snake(pq_bytes_hard_max), 0xffffffffULL).is_ok());         // canonical at the ceiling
    assert(unpack_pq_bytes(snake(pq_bytes_hard_max + 1), 0xffffffffULL).is_error());  // only the ceiling rejects it
    // a 4 GiB declaration is refused by the same length gate, before any allocation
    assert(unpack_pq_bytes(root_cell(0xffffffffULL, 32, {}), 0xffffffffULL).is_error());

    // root bit-width: 31 and 33 are both non-canonical
    assert(unpack_pq_bytes(root_cell(0, 31, {}), 2420).is_error());
    assert(unpack_pq_bytes(root_cell(0, 33, {}), 2420).is_error());

    // zero length must carry no ref
    assert(unpack_pq_bytes(root_cell(0, 32, {data_cell(b10, {})}), 2420).is_error());
    assert(unpack_pq_bytes(root_cell(0, 32, {}), 2420).is_ok());

    // root ref count must be exactly 1 when len > 0
    assert(unpack_pq_bytes(root_cell(10, 32, {}), 2420).is_error());
    assert(unpack_pq_bytes(root_cell(10, 32, {data_cell(b10, {}), data_cell(b10, {})}), 2420).is_error());

    // middle cell must have exactly 1 ref (0 and 2 both rejected)
    assert(unpack_pq_bytes(root_cell(200, 32, {data_cell(b127, {})}), 2420).is_error());
    assert(unpack_pq_bytes(root_cell(200, 32, {data_cell(b127, {tail, tail})}), 2420).is_error());

    // final cell must carry no trailing ref
    assert(unpack_pq_bytes(root_cell(127, 32, {data_cell(b127, {tail})}), 2420).is_error());

    // non-full middle chunk (100 instead of 127)
    assert(unpack_pq_bytes(root_cell(227, 32, {data_cell(b100, {data_cell(b127, {})})}), 2420).is_error());

    // declared length > actual, and < actual
    assert(unpack_pq_bytes(root_cell(300, 32, {data_cell(b127, {tail})}), 2420).is_error());
    assert(unpack_pq_bytes(root_cell(100, 32, {data_cell(b127, {})}), 2420).is_error());

    // final chunk longer than the remaining declared bytes
    assert(unpack_pq_bytes(root_cell(130, 32, {data_cell(b127, {data_cell(b10, {})})}), 2420).is_error());

    // non-byte-aligned payload: 100 bits where 12 whole bytes are required
    vm::CellBuilder odd;
    odd.store_long(0, 100 - 64);
    odd.store_long(0, 64);
    assert(unpack_pq_bytes(root_cell(12, 32, {odd.finalize()}), 2420).is_error());
  }

  printf("PQ_BYTES_OK roundtrips+hard-max+canonicality-battery+shared-vectors\n");
  return 0;
}
