/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include "crypto/openssl/digest.hpp"
#include "td/utils/base64.h"

#include "getter-context-fixture.h"

namespace control_fixture {
using namespace getter_fixture;
using namespace vm;
inline Ref<Cell> current_code(bool elector) {
  Ref<Cell> code;
  auto with_tvm_code = [&](const char*, td::Slice encoded) {
    auto bytes = must(td::base64_decode(encoded), "fresh code base64");
    code = must(vm::std_boc_deserialize(bytes), "fresh code BOC");
  };
  if (elector) {
#include "smartcont/auto/elector-code.cpp"
  } else {
#include "smartcont/auto/config-code.cpp"
  }
  require(code.not_null(), "current compiled contract code");
  return code;
}

inline State production_build(const std::string& zero, const std::string& fixtures, const std::string& config,
                              int version = 17, bool libraries = true, Ref<Cell> elector = {}, Ref<Cell> proposals = {},
                              Ref<Cell> probe_code = {}, Ref<Cell> probe_data = {}) {
  return getter_fixture::build(zero, fixtures, config, version, libraries, elector, proposals, probe_code, probe_data,
                               current_code(true), current_code(false));
}

inline td::BitArray<256> hashed_key(const std::string& tag, int i) {
  td::BitArray<256> key;
  std::string seed = tag + std::to_string(i);
  digest::hash_str<digest::SHA256>(key.data(), seed.data(), seed.size());
  return key;
}

// A dictionary of n entries, each `value` under its own hashed 256-bit key.
inline Ref<Cell> filled(Ref<CellSlice> value, const std::string& tag, int n) {
  Dictionary d{256};
  for (int i = 0; i < n; ++i) {
    auto key = hashed_key(tag, i);
    require(d.set(key.bits(), 256, value), "insert");
  }
  return d.get_root_cell();
}

inline Ref<CellSlice> first_value(Ref<Cell> root, int key_bits) {
  require(root.not_null(), "dictionary is not empty");
  Dictionary d{root, key_bits};
  td::BitArray<256> key;
  auto v = d.get_minmax_key(key.bits(), key_bits);
  require(v.not_null(), "first entry");
  return v;
}

inline int vm_amount_skip(CellSlice& cs) {
  unsigned len = static_cast<unsigned>(cs.fetch_ulong(4));
  require(cs.advance(len * 8), "amount");
  return 0;
}

struct Elector {
  Ref<Cell> elect;  // maybe null
  Ref<Cell> credits;
  Ref<Cell> past;
  Ref<CellSlice> rest;
};

inline Elector split(Ref<Cell> data) {
  CellSlice ds = load_cell_slice(data);
  Elector e;
  require(ds.fetch_maybe_ref(e.elect) && ds.fetch_maybe_ref(e.credits) && ds.fetch_maybe_ref(e.past), "data layout");
  e.rest = td::make_ref<CellSlice>(ds);
  return e;
}

inline Ref<Cell> join(const Elector& e) {
  CellBuilder b;
  require(b.store_maybe_ref(e.elect) && b.store_maybe_ref(e.credits) && b.store_maybe_ref(e.past) &&
              b.append_cellslice_bool(*e.rest),
          "rebuild data");
  return b.finalize();
}

// The open election with its member book replaced by n copies of its first member.
enum class Book { Hashed, Deepest, DeepestMaxStake };

// i ones followed by zeros: keys 0..n-1 form one path of n levels, the deepest a
// 256-bit-key dictionary allows.
inline td::BitArray<256> chain_key(int i) {
  td::BitArray<256> key;
  key.set_zero();
  for (int b = 0; b < i; ++b) {
    key[b] = true;
  }
  return key;
}

// The member record with its stake (the record's only variable-width field) set to the
// largest Coins value, 2^120 - 1.
inline Ref<CellSlice> with_max_stake(Ref<CellSlice> member) {
  CellSlice ms = *member;
  vm_amount_skip(ms);
  CellBuilder b;
  require(b.store_long_bool(15, 4), "stake length");
  for (int k = 0; k < 15; ++k) {
    require(b.store_long_bool(0xff, 8), "stake byte");
  }
  require(b.append_cellslice_bool(ms), "rest of the member");
  return load_cell_slice_ref(b.finalize());
}

inline Ref<Cell> book_of(Ref<CellSlice> member, Book shape, int n) {
  if (shape == Book::Hashed) {
    return filled(member, "member-", n);
  }
  require(n <= 257, "a 256-bit key path holds at most 257 keys");
  auto value = shape == Book::DeepestMaxStake ? with_max_stake(member) : member;
  Dictionary d{256};
  for (int i = 0; i < n; ++i) {
    auto key = chain_key(i);
    require(d.set(key.bits(), 256, value), "insert member");
  }
  return d.get_root_cell();
}

inline Ref<Cell> grow_members(Ref<Cell> elect, int n, Book shape) {
  CellSlice es = load_cell_slice(elect);
  CellSlice orig = es;
  require(es.advance(64), "elect_at, elect_close");
  vm_amount_skip(es);
  vm_amount_skip(es);
  require(es.advance(2), "failed, finished");
  int prefix_bits = static_cast<int>(orig.size() - es.size());
  Ref<Cell> members;
  require(es.fetch_maybe_ref(members), "member book");
  auto member = first_value(members, 256);
  CellSlice prefix = orig;
  require(prefix.only_first(prefix_bits, 0), "prefix");
  CellBuilder b;
  require(
      b.append_cellslice_bool(prefix) && b.store_maybe_ref(book_of(member, shape, n)) && b.append_cellslice_bool(es),
      "rebuild election");
  return b.finalize();
}

// k past elections, each the saved past election with f frozen entries; election ids
// are the saved id minus 1..k so they stay distinct and ordered.
inline Ref<Cell> grow_past(Ref<Cell> past, int k, int f) {
  require(past.not_null(), "the saved state holds a past election");
  Dictionary saved{past, 32};
  td::BitArray<32> id_bits;
  auto entry = saved.get_minmax_key(id_bits.bits(), 32);
  require(entry.not_null(), "past election");
  unsigned long long saved_id = id_bits.bits().get_uint(32);

  CellSlice ps = *entry;
  CellSlice orig = ps;
  require(ps.advance(32 + 32 + 256), "unfreeze_at, stake_held, vset_hash");
  int prefix_bits = static_cast<int>(orig.size() - ps.size());
  Ref<Cell> frozen;
  require(ps.fetch_maybe_ref(frozen), "frozen dictionary");
  auto frozen_entry = first_value(frozen, 256);
  Ref<Cell> grown_frozen = filled(frozen_entry, "frozen-", f);
  CellSlice prefix = orig;
  require(prefix.only_first(prefix_bits, 0), "prefix");
  CellBuilder eb;
  require(eb.append_cellslice_bool(prefix) && eb.store_maybe_ref(grown_frozen) && eb.append_cellslice_bool(ps),
          "rebuild past election");
  auto value = load_cell_slice_ref(eb.finalize());

  Dictionary out{32};
  for (int i = 1; i <= k; ++i) {
    td::BitArray<32> key;
    key.bits().store_uint(saved_id - static_cast<unsigned long long>(i), 32);
    require(out.set(key.bits(), 32, value), "insert past election");
  }
  return out.get_root_cell();
}

inline Ref<Cell> grow_credits(int c) {
  CellBuilder vb;
  require(vb.store_long_bool(5, 4) && vb.store_long_bool(1000000000LL, 40), "credit amount");
  return filled(load_cell_slice_ref(vb.finalize()), "credit-", c);
}

// The deepest credits dictionary 256-bit keys allow: key i is i ones followed by zeros, so
// the all-ones key sits at the end of a 256-level path.
inline Ref<Cell> deepest_credits() {
  CellBuilder vb;
  require(vb.store_long_bool(5, 4) && vb.store_long_bool(1000000000LL, 40), "credit amount");
  auto value = load_cell_slice_ref(vb.finalize());
  Dictionary d{256};
  for (int i = 0; i <= 256; ++i) {
    td::BitArray<256> key;
    key.set_zero();
    for (int b = 0; b < i; ++b) {
      key[b] = true;
    }
    require(d.set(key.bits(), 256, value), "insert");
  }
  return d.get_root_cell();
}

inline Ref<Cell> past_shape(Ref<Cell> original, int count, int entries, bool deep) {
  auto value = first_value(grow_past(original, count, entries), 32);
  Dictionary dictionary{32};
  for (int index = 0; index < count; ++index) {
    td::BitArray<32> key;
    key.set_zero();
    if (deep) {
      for (int bit = 0; bit < index; ++bit) {
        key[bit] = true;
      }
    } else {
      auto hash = hashed_key("past-", index);
      key = td::ConstBitPtr{hash.data()};
    }
    require(dictionary.set(key.cbits(), 32, value), "past shape entry");
  }
  return dictionary.get_root_cell();
}

inline td::BitArray<256> proposal_key(int index, int count, bool deep) {
  if (!deep) {
    return hashed_key("proposal-", index);
  }
  if (index < 244) {
    return chain_key(index);
  }
  td::BitArray<256> key;
  key.set_ones();
  auto tail = key.bits();
  tail.advance(244);
  tail.store_uint(static_cast<unsigned>(index - 244), 12);
  require(count <= 4096, "proposal fixture count");
  return key;
}

inline Ref<Cell> config_proposals(int count, bool deep, int voters) {
  Dictionary book{256};
  Dictionary voter_book{16};
  for (int index = 0; index < voters; ++index) {
    td::BitArray<16> key;
    key.bits().store_uint(static_cast<unsigned>(index), 16);
    require(voter_book.set_builder(key.cbits(), 16, CellBuilder{}), "voter entry");
  }
  auto proposal = CellBuilder{}.store_long(0xf3, 8).store_long(1001, 32).store_long(0, 2).finalize_novm();
  CellBuilder value;
  require(value.store_long_bool(0xce, 8) && value.store_long_bool(1900000000, 32) && value.store_ref_bool(proposal) &&
              value.store_bool_bool(false) && value.store_maybe_ref(voter_book.get_root_cell()) &&
              value.store_long_bool(100, 64) && value.store_bits_bool(getter_fixture::filled(0x51).cbits(), 256) &&
              value.store_long_bool(3, 8) && value.store_long_bool(1, 8) && value.store_long_bool(2, 8),
          "proposal record");
  auto record = value.as_cellslice_ref();
  for (int index = 0; index < count; ++index) {
    auto key = proposal_key(index, count, deep);
    require(book.set(key.cbits(), 256, record), "proposal entry");
  }
  CellBuilder data;
  require(data.store_ref_bool(empty_dictionary()) && data.store_maybe_ref(book.get_root_cell()),
          "proposal account data");
  return data.finalize_novm();
}

}  // namespace control_fixture
