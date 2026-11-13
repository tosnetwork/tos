// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
#include <algorithm>
#include <array>
#include <exception>
#include <filesystem>
#include <fstream>
#include <optional>
#include <utility>

#include "block/block-parse.h"
#include "common/refint.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cellslice.h"

#include "generator.h"

namespace conformance::fuzz {
namespace {

using CellRef = td::Ref<vm::Cell>;

constexpr std::size_t kMaxSeedLineBytes = 64u << 20;
constexpr std::size_t kMaxSeeds = 1u << 20;
constexpr int kMaxCodeDepth = 3;
constexpr unsigned kCellBits = 1023;
constexpr unsigned kCellRefs = 4;
constexpr std::size_t kMaxStackItems = 24;
constexpr std::int64_t kMaxGas = 1000000;

// ---------------------------------------------------------------------------------------------
// Bits under construction: a code or data cell before it is finalized.

struct Bits {
  std::vector<unsigned char> bytes;
  unsigned size = 0;
  std::vector<CellRef> refs;

  void put_bit(bool bit) {
    if (size % 8 == 0) {
      bytes.push_back(0);
    }
    if (bit) {
      bytes[size / 8] = static_cast<unsigned char>(bytes[size / 8] | (0x80u >> (size % 8)));
    }
    ++size;
  }
  void put(std::uint64_t value, unsigned bits) {
    for (unsigned i = bits; i > 0; --i) {
      put_bit(((value >> (i - 1)) & 1) != 0);
    }
  }
  bool fits(const Bits &more) const {
    return size + more.size <= kCellBits && refs.size() + more.refs.size() <= kCellRefs;
  }
  void append(const Bits &more) {
    for (unsigned i = 0; i < more.size; ++i) {
      put_bit(((more.bytes[i / 8] >> (7 - i % 8)) & 1) != 0);
    }
    refs.insert(refs.end(), more.refs.begin(), more.refs.end());
  }
  void append_slice(const vm::CellSlice &cs, unsigned bits, unsigned refs_from, unsigned refs_to) {
    for (unsigned i = 0; i < bits; ++i) {
      put_bit(cs.bit_at(i) == 1);
    }
    for (unsigned i = refs_from; i < refs_to; ++i) {
      refs.push_back(cs.prefetch_ref(i));
    }
  }
  CellRef finalize() const {
    vm::CellBuilder cb;
    cb.store_bits(bytes.data(), size);
    for (const auto &ref : refs) {
      cb.store_ref(ref);
    }
    return cb.finalize();
  }
};

std::string to_base64(const CellRef &cell) {
  auto bytes = vm::std_boc_serialize(cell, 0);
  if (bytes.is_error()) {
    return {};
  }
  return td::base64_encode(bytes.ok().as_slice());
}

std::optional<CellRef> from_base64(const std::string &text) {
  auto bytes = td::base64_decode(text);
  if (bytes.is_error()) {
    return std::nullopt;
  }
  auto cell = vm::std_boc_deserialize(td::Slice(bytes.ok()), false, true);
  if (cell.is_error()) {
    return std::nullopt;
  }
  return cell.move_as_ok();
}

// An ordinary (not exotic) cell as a slice, or nothing.
std::optional<vm::CellSlice> ordinary_slice(const CellRef &cell) {
  bool special = false;
  auto cs = vm::load_cell_slice_special(cell, special);
  if (special) {
    return std::nullopt;
  }
  return cs;
}

// ---------------------------------------------------------------------------------------------
// Values

template <class T, std::size_t N>
const T &pick(Choices &c, const std::array<T, N> &values) {
  return values[c.below(N)];
}

std::string random_bits_int(Choices &c, unsigned bits, bool negative) {
  auto x = td::make_refint(0);
  for (unsigned done = 0; done < bits; done += 32) {
    const unsigned step = std::min(32u, bits - done);
    x <<= static_cast<int>(step);
    x += static_cast<long long>(c.next() & ((1ull << step) - 1));
  }
  if (negative) {
    x = -x;
  }
  return x->to_dec_string();
}

// Integers near the edges the VM treats specially: powers of two, the 257-bit range, small values.
std::string interesting_int(Choices &c) {
  static const std::array<int, 14> powers{1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 200, 255, 256};
  switch (c.below(5)) {
    case 0:
      return std::to_string(static_cast<long long>(c.below(21)) - 10);
    case 1: {
      auto x = td::make_refint(1) << pick(c, powers);
      x += static_cast<long long>(c.below(3)) - 1;
      if (c.chance(40)) {
        x = -x;
      }
      // Keep within the 257-bit signed range the harness accepts.
      if (!x->signed_fits_bits(257)) {
        x = (td::make_refint(1) << 256) - 1;
      }
      return x->to_dec_string();
    }
    case 2:
      return random_bits_int(c, 64, c.chance(30));
    case 3:
      return random_bits_int(c, 1 + static_cast<unsigned>(c.below(256)), c.chance(30));
    default:
      return c.chance(50) ? (-(td::make_refint(1) << 256))->to_dec_string()
                          : ((td::make_refint(1) << 256) - 1)->to_dec_string();
  }
}

Json int_item(const std::string &value) {
  Json item = Json::object();
  item.set("type", Json::string("int"));
  item.set("value", Json::string(value));
  return item;
}

Json typed(const char *type) {
  Json item = Json::object();
  item.set("type", Json::string(type));
  return item;
}

Json boc_item(const char *type, const CellRef &cell) {
  Json item = typed(type);
  item.set("boc", Json::string(to_base64(cell)));
  return item;
}

CellRef random_data_cell(Choices &c, int depth) {
  Bits bits;
  const unsigned size = static_cast<unsigned>(c.below(c.chance(70) ? 72 : 1024));
  for (unsigned i = 0; i < size; i += 8) {
    bits.put(c.next() & 0xFF, std::min(8u, size - i));
  }
  if (depth < 2) {
    const unsigned refs = static_cast<unsigned>(c.below(c.chance(70) ? 2 : 5));
    for (unsigned i = 0; i < refs; ++i) {
      bits.refs.push_back(random_data_cell(c, depth + 1));
    }
  }
  return bits.finalize();
}

Json stack_item(Choices &c, int depth) {
  switch (c.below(depth < 2 ? 8 : 7)) {
    case 0:
      return typed("null");
    case 1:
      return c.chance(30) ? typed("nan") : int_item(interesting_int(c));
    case 2:
    case 3:
      return int_item(interesting_int(c));
    case 4:
      return boc_item("cell", random_data_cell(c, 1));
    case 5:
    case 6:
      return boc_item("slice", random_data_cell(c, 1));
    default: {
      Json tuple = typed("tuple");
      Json items = Json::array();
      const auto n = c.below(c.chance(80) ? 4 : 16);
      for (std::uint64_t i = 0; i < n; ++i) {
        items.push(stack_item(c, depth + 1));
      }
      tuple.set("items", std::move(items));
      return tuple;
    }
  }
}

Json random_stack(Choices &c) {
  Json stack = Json::array();
  const auto n = c.below(c.chance(85) ? 6 : kMaxStackItems);
  for (std::uint64_t i = 0; i < n; ++i) {
    stack.push(stack_item(c, 0));
  }
  return stack;
}

Json random_gas(Choices &c) {
  static const std::array<std::int64_t, 12> limits{0, 1, 10, 18, 26, 50, 100, 500, 1000, 10000, 100000, kMaxGas};
  Json gas = Json::object();
  const std::int64_t limit = c.chance(80) ? pick(c, limits) : static_cast<std::int64_t>(c.below(kMaxGas + 1));
  std::int64_t max = limit;
  if (c.chance(30)) {
    max = c.chance(50) ? kMaxGas : static_cast<std::int64_t>(c.below(kMaxGas + 1));
  }
  gas.set("limit", Json::integer(limit));
  gas.set("max", Json::integer(max));
  if (c.chance(20)) {
    gas.set("credit", Json::integer(c.chance(50) ? 10000 : static_cast<std::int64_t>(c.below(100000))));
  }
  return gas;
}

CellRef std_address_cell(Choices &c) {
  Bits bits;
  bits.put(0b100, 3);  // addr_std, no anycast
  bits.put(c.chance(80) ? 0 : (c.chance(50) ? 0xFF : c.below(256)), 8);
  for (int i = 0; i < 4; ++i) {
    bits.put(c.next(), 64);
  }
  return bits.finalize();
}

// c7: the standard one-element tuple of smart-contract parameters, or one of several broken shapes.
Json random_c7(Choices &c) {
  Json params = Json::array();
  params.push(int_item("124711402"));  // the parameter tuple's magic, 0x076ef1ea
  params.push(int_item("0"));
  params.push(int_item("0"));
  params.push(int_item(std::to_string(c.below(1ull << 32))));
  params.push(int_item(std::to_string(c.below(1ull << 40))));
  params.push(int_item(std::to_string(c.below(1ull << 40))));
  params.push(int_item(random_bits_int(c, 256, false)));
  Json balance = typed("tuple");
  Json balance_items = Json::array();
  balance_items.push(int_item(c.chance(80) ? std::to_string(c.below(1ull << 50)) : interesting_int(c)));
  balance_items.push(typed("null"));
  balance.set("items", std::move(balance_items));
  params.push(std::move(balance));
  params.push(boc_item("slice", std_address_cell(c)));
  params.push(c.chance(70) ? typed("null") : boc_item("cell", random_data_cell(c, 1)));
  const auto extra = c.below(8);
  for (std::uint64_t i = 0; i < extra; ++i) {
    params.push(stack_item(c, 1));
  }
  auto &list = params.items();
  switch (c.below(6)) {
    case 0:  // truncated parameter tuple
      list.resize(c.below(list.size() + 1));
      break;
    case 1:  // one parameter of an unexpected type
      list[c.below(list.size())] = stack_item(c, 1);
      break;
    default:
      break;
  }
  Json inner = typed("tuple");
  inner.set("items", std::move(params));
  Json outer_items = Json::array();
  switch (c.below(10)) {
    case 0:  // empty outer tuple
      break;
    case 1:  // outer tuple whose first element is not a tuple
      outer_items.push(stack_item(c, 1));
      break;
    case 2:
      outer_items.push(std::move(inner));
      outer_items.push(stack_item(c, 1));
      break;
    default:
      outer_items.push(std::move(inner));
  }
  Json outer = typed("tuple");
  outer.set("items", std::move(outer_items));
  return outer;
}

// ---------------------------------------------------------------------------------------------
// TVM instruction grammar. Encodings follow the instruction table; a wrong or reserved encoding still
// gives a deterministic result (an invalid-opcode exception) and is part of the space being explored.

const std::array<unsigned, 96> kOps8{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23,
                                     0x25, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x3F, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x60,
                                     0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6D, 0x6E, 0xA0,
                                     0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA8, 0xAC, 0xAD, 0xAE, 0xB0, 0xB1, 0xB2, 0xB3, 0xB8,
                                     0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC4, 0xC5, 0xC8, 0xC9, 0xCC, 0xCD, 0xCE,
                                     0xD0, 0xD1, 0xD4, 0xD5, 0xD8, 0xD9, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE4,
                                     0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xC8, 0xA0, 0x20, 0x01, 0x30};

const std::array<unsigned, 112> kOps16{
    0x6F80, 0x6F81, 0x6F82, 0x6F88, 0x6F89, 0x6F8A, 0x6F8B, 0x6F8C, 0x6F8D, 0xA904, 0xA905, 0xA906, 0xA908, 0xA90C,
    0xA984, 0xA985, 0xA98C, 0xB600, 0xB601, 0xB602, 0xB603, 0xB608, 0xB609, 0xB60A, 0xB60B, 0xB7A0, 0xB7A1, 0xB7A8,
    0xC700, 0xC701, 0xC702, 0xC705, 0xCF00, 0xCF01, 0xCF31, 0xCF32, 0xCF33, 0xD700, 0xD701, 0xD718, 0xD720, 0xD721,
    0xD749, 0xD74A, 0xD74B, 0xDB30, 0xDB31, 0xDB32, 0xDB34, 0xE304, 0xE305, 0xE308, 0xED40, 0xED41, 0xED44, 0xED45,
    0xED47, 0xED54, 0xED55, 0xED57, 0xF400, 0xF401, 0xF402, 0xF404, 0xF800, 0xF801, 0xF807, 0xF80F, 0xF810, 0xF811,
    0xF814, 0xF820, 0xF821, 0xF822, 0xF823, 0xF824, 0xF825, 0xF826, 0xF827, 0xF828, 0xF829, 0xF82A, 0xF82B, 0xF82C,
    0xF82D, 0xF82E, 0xF82F, 0xF830, 0xF832, 0xF833, 0xF840, 0xF860, 0xF900, 0xF901, 0xF902, 0xF910, 0xF911, 0xF940,
    0xF941, 0xF942, 0xF943, 0xFA00, 0xFA01, 0xFA02, 0xFA03, 0xFA40, 0xFA41, 0xFA42, 0xFA44, 0xFB00, 0xFB02, 0xFB04};

// One-byte opcodes followed by an 8-bit argument (constants, bit widths, stack indices).
const std::array<unsigned, 26> kOps8Arg8{0x10, 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x5E, 0x5F, 0x6C, 0x80, 0x83,
                                         0x84, 0x85, 0xA6, 0xA7, 0xAA, 0xAB, 0xB4, 0xB5, 0xC0, 0xC1, 0xC2, 0xC3, 0xCA};
const std::array<unsigned, 4> kOps8Arg8Cells{0xCB, 0xD2, 0xD3, 0xD6};
// 12-bit prefixes with a 4-bit argument: TUPLE, INDEX, UNTUPLE, SETINDEX.
const std::array<unsigned, 4> kOps12Arg4{0x6F0, 0x6F1, 0x6F2, 0x6F5};
// Opcodes taking a code reference: PUSHREFCONT, IFREF, IFNOTREF, IFJMPREF, IFNOTJMPREF, CALLREF, JMPREF.
const std::array<std::pair<unsigned, unsigned>, 7> kCodeRefOps{
    {{0x8A, 8}, {0xE300, 16}, {0xE301, 16}, {0xE302, 16}, {0xE303, 16}, {0xDB3C, 16}, {0xDB3D, 16}}};

CellRef code_cell(Choices &c, int depth);

// Appends instructions until about `target_bits` are used; with `allow_refs` false no instruction takes a
// reference (the body of a short PUSHCONT has none of its own).
void emit_code(Choices &c, Bits &code, int depth, unsigned target_bits, bool allow_refs);

Bits instruction(Choices &c, int depth, bool allow_refs) {
  Bits op;
  const auto kind = c.below(100);
  if (kind < 30) {
    op.put(pick(c, kOps8), 8);
  } else if (kind < 44) {
    op.put(pick(c, kOps16), 16);
  } else if (kind < 56) {
    op.put(pick(c, kOps8Arg8), 8);
    op.put(c.next() & 0xFF, 8);
  } else if (kind < 60) {
    op.put(pick(c, kOps8Arg8Cells), 8);
    op.put(c.below(c.chance(80) ? 64 : 256), 8);
  } else if (kind < 64) {
    op.put(pick(c, kOps12Arg4), 12);
    op.put(c.below(16), 4);
  } else if (kind < 74) {  // PUSHINT in its several widths
    switch (c.below(4)) {
      case 0:
        op.put(0x70 | c.below(16), 8);
        break;
      case 1:
        op.put(0x80, 8);
        op.put(c.next() & 0xFF, 8);
        break;
      case 2:
        op.put(0x81, 8);
        op.put(c.next() & 0xFFFF, 16);
        break;
      default: {
        const unsigned l = static_cast<unsigned>(c.below(c.chance(80) ? 4 : 31));
        op.put(0x82, 8);
        op.put(l, 5);
        const unsigned bits = 8 * l + 19;
        for (unsigned i = 0; i < bits; i += 32) {
          op.put(c.next(), std::min(32u, bits - i));
        }
      }
    }
  } else if (kind < 78) {  // THROW, THROWIF, THROWIFNOT with a short code
    op.put(0xF2, 8);
    op.put((c.below(3) << 6) | c.below(64), 8);
  } else if (kind < 81) {  // PUSHSLICE with up to 15 data bytes
    const unsigned x = static_cast<unsigned>(c.below(16));
    op.put(0x8B, 8);
    op.put(x, 4);
    const unsigned bits = 8 * x + 4;
    for (unsigned i = 0; i < bits; i += 32) {
      op.put(c.next(), std::min(32u, bits - i));
    }
  } else if (kind < 87) {  // PUSHCONT with an inline body of x bytes
    const unsigned x = static_cast<unsigned>(c.below(16));
    Bits body;
    if (depth < kMaxCodeDepth) {
      emit_code(c, body, depth + 1, 8 * x, false);
    }
    while (body.size < 8 * x) {
      body.put(0, 8);  // NOP padding
    }
    op.put(0x90 | x, 8);
    for (unsigned i = 0; i < 8 * x; ++i) {
      op.put_bit(((body.bytes[i / 8] >> (7 - i % 8)) & 1) != 0);
    }
  } else if (kind < 95 && allow_refs) {  // instructions with a reference
    if (c.chance(35) || depth >= kMaxCodeDepth) {
      op.put(c.chance(50) ? 0x88 : 0x89, 8);  // PUSHREF, PUSHREFSLICE
      op.refs.push_back(random_data_cell(c, 1));
    } else {
      const auto &entry = kCodeRefOps[c.below(kCodeRefOps.size())];
      op.put(entry.first, entry.second);
      op.refs.push_back(code_cell(c, depth + 1));
    }
  } else {  // arbitrary bits, including fragments that misalign what follows
    if (c.chance(70)) {
      op.put(c.next() & 0xFF, 8);
    } else {
      op.put(c.next(), 1 + static_cast<unsigned>(c.below(16)));
    }
  }
  return op;
}

void emit_code(Choices &c, Bits &code, int depth, unsigned target_bits, bool allow_refs) {
  for (int guard = 0; guard < 256 && code.size < target_bits; ++guard) {
    Bits op = instruction(c, depth, allow_refs);
    if (!code.fits(op)) {
      if (code.size + 8 > kCellBits) {
        break;
      }
      continue;
    }
    code.append(op);
  }
}

CellRef code_cell(Choices &c, int depth) {
  Bits code;
  const unsigned target =
      c.chance(70) ? static_cast<unsigned>(8 * (1 + c.below(12))) : static_cast<unsigned>(c.below(kCellBits + 1));
  emit_code(c, code, depth, target, true);
  // A trailing reference no instruction consumes: execution falls into it with an implicit JMPREF.
  if (depth < kMaxCodeDepth && code.refs.size() < kCellRefs && c.chance(25)) {
    code.refs.push_back(code_cell(c, depth + 1));
  }
  return code.finalize();
}

// ---------------------------------------------------------------------------------------------
// vm contexts

// The global version of current networks; other versions are explored less often.
constexpr std::int64_t kCurrentVersion = 16;

Json grammar_vm(Choices &c) {
  Json ctx = Json::object();
  ctx.set("code", Json::string(to_base64(code_cell(c, 0))));
  ctx.set("global_version",
          Json::integer(c.chance(85) ? kCurrentVersion : static_cast<std::int64_t>(c.below(kCurrentVersion + 5))));
  ctx.set("gas", random_gas(c));
  ctx.set("stack", random_stack(c));
  if (c.chance(60)) {
    ctx.set("c7", random_c7(c));
  }
  if (c.chance(40)) {
    ctx.set("data", Json::string(to_base64(random_data_cell(c, 0))));
  }
  if (c.chance(15)) {
    ctx.set("flags", Json::integer(static_cast<std::int64_t>(c.below(4))));
  }
  return ctx;
}

std::optional<CellRef> mutate_code_cell(Choices &c, const CellRef &root) {
  auto slice = ordinary_slice(root);
  if (!slice) {
    return std::nullopt;
  }
  const vm::CellSlice &cs = *slice;
  const unsigned bits = cs.size();
  const unsigned refs = cs.size_refs();
  Bits out;
  switch (c.below(7)) {
    case 0: {  // flip one bit
      if (bits == 0) {
        return std::nullopt;
      }
      out.append_slice(cs, bits, 0, refs);
      const unsigned at = static_cast<unsigned>(c.below(bits));
      out.bytes[at / 8] = static_cast<unsigned char>(out.bytes[at / 8] ^ (0x80u >> (at % 8)));
      break;
    }
    case 1:  // keep a prefix of the data
      out.append_slice(cs, static_cast<unsigned>(c.below(bits + 1)), 0, refs);
      break;
    case 2: {  // append instructions
      out.append_slice(cs, bits, 0, refs);
      emit_code(c, out, 1, out.size + 8 * static_cast<unsigned>(1 + c.below(6)), true);
      break;
    }
    case 3: {  // insert instructions at a byte boundary
      const unsigned at = 8 * static_cast<unsigned>(c.below(bits / 8 + 1));
      Bits inserted;
      emit_code(c, inserted, 1, 8 * static_cast<unsigned>(1 + c.below(4)), false);
      out.append_slice(cs, at, 0, 0);
      if (out.size + inserted.size + (bits - at) > kCellBits) {
        return std::nullopt;
      }
      out.append(inserted);
      for (unsigned i = at; i < bits; ++i) {
        out.put_bit(cs.bit_at(i) == 1);
      }
      for (unsigned i = 0; i < refs; ++i) {
        out.refs.push_back(cs.prefetch_ref(i));
      }
      break;
    }
    case 4: {  // replace or add a reference
      out.append_slice(cs, bits, 0, refs);
      auto fresh = code_cell(c, 1);
      if (refs > 0 && c.chance(60)) {
        out.refs[c.below(refs)] = fresh;
      } else if (refs < kCellRefs) {
        out.refs.push_back(fresh);
      } else {
        return std::nullopt;
      }
      break;
    }
    case 5:  // drop the last reference
      if (refs == 0) {
        return std::nullopt;
      }
      out.append_slice(cs, bits, 0, refs - 1);
      break;
    default: {  // a generated prelude, then JMPREF into the original code
      emit_code(c, out, 1, 8 * static_cast<unsigned>(1 + c.below(8)), false);
      if (out.size + 16 > kCellBits) {
        return std::nullopt;
      }
      out.put(0xDB3D, 16);
      out.refs.push_back(root);
      break;
    }
  }
  return out.finalize();
}

void mutate_stack(Choices &c, Json &stack) {
  if (!stack.is(Json::Type::Array)) {
    stack = Json::array();
  }
  auto &items = stack.items();
  switch (c.below(5)) {
    case 0:
      if (items.size() < kMaxStackItems) {
        items.push_back(stack_item(c, 0));
      }
      break;
    case 1:
      if (!items.empty()) {
        items.erase(items.begin() + static_cast<std::ptrdiff_t>(c.below(items.size())));
      }
      break;
    case 2:
      if (!items.empty()) {
        items[c.below(items.size())] = stack_item(c, 0);
      }
      break;
    case 3:
      if (items.size() > 1) {
        std::swap(items[c.below(items.size())], items[c.below(items.size())]);
      }
      break;
    default:
      stack = random_stack(c);
  }
}

Json mutated_vm(Choices &c, const Json &seed) {
  Json ctx = seed;
  const auto rounds = 1 + c.below(3);
  for (std::uint64_t round = 0; round < rounds; ++round) {
    switch (c.below(8)) {
      case 0: {
        Json *stack = ctx.find("stack");
        mutate_stack(c, stack != nullptr ? *stack : ctx.set("stack", Json::array()));
        break;
      }
      case 1:
        ctx.set("gas", random_gas(c));
        break;
      case 2:
      case 3: {
        const Json *code = ctx.find("code");
        if (code != nullptr && code->is(Json::Type::String)) {
          if (auto root = from_base64(code->as_string())) {
            if (auto mutated = mutate_code_cell(c, *root)) {
              ctx.set("code", Json::string(to_base64(*mutated)));
            }
          }
        }
        break;
      }
      case 4:
        if (ctx.has("c7") && c.chance(30)) {
          ctx.erase("c7");
        } else {
          ctx.set("c7", random_c7(c));
        }
        break;
      case 5:
        ctx.set(
            "global_version",
            Json::integer(c.chance(60) ? kCurrentVersion : static_cast<std::int64_t>(c.below(kCurrentVersion + 5))));
        break;
      case 6:
        if (c.chance(50)) {
          ctx.erase("flags");
        } else {
          ctx.set("flags", Json::integer(static_cast<std::int64_t>(c.below(4))));
        }
        break;
      default:
        if (ctx.has("data") && c.chance(40)) {
          ctx.erase("data");
        } else {
          ctx.set("data", Json::string(to_base64(random_data_cell(c, 0))));
        }
    }
  }
  return ctx;
}

// ---------------------------------------------------------------------------------------------
// txn contexts: mutations that keep every cell decodable.

std::string random_seed_hex(Choices &c) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  for (int i = 0; i < 64; ++i) {
    out += digits[c.below(16)];
  }
  return out;
}

td::RefInt256 mutated_amount(Choices &c, const td::RefInt256 &amount) {
  switch (c.below(6)) {
    case 0:
      return td::make_refint(0);
    case 1:
      return td::make_refint(1);
    case 2:
      return amount + 1;
    case 3:
      return amount->sgn() > 0 ? amount - 1 : td::make_refint(0);
    case 4:
      return amount * 2;
    default:
      return td::make_refint(static_cast<long long>(c.below(1ull << 50)));
  }
}

// Rebuilds `whole` with the Tomis amount that starts at `at` (a position within `whole`) replaced.
std::optional<CellRef> replace_amount(Choices &c, const vm::CellSlice &whole, vm::CellSlice at) {
  const unsigned bit_pos = whole.size() - at.size();
  const unsigned ref_pos = whole.size_refs() - at.size_refs();
  auto amount = block::tlb::t_Tomis.as_integer_skip(at);
  if (amount.is_null()) {
    return std::nullopt;
  }
  const auto fresh = mutated_amount(c, amount);
  if (fresh.is_null() || fresh->sgn() < 0 || !fresh->unsigned_fits_bits(120)) {
    return std::nullopt;
  }
  vm::CellSlice prefix = whole;
  if (!prefix.only_first(bit_pos, ref_pos)) {
    return std::nullopt;
  }
  vm::CellBuilder cb;
  if (!cb.append_cellslice_bool(prefix) || !block::tlb::t_Tomis.store_integer_value(cb, *fresh) ||
      !cb.append_cellslice_bool(at)) {
    return std::nullopt;
  }
  return cb.finalize();
}

std::optional<CellRef> mutate_account_balance(Choices &c, const CellRef &account) {
  auto slice = ordinary_slice(account);
  if (!slice || slice->size() == 0) {
    return std::nullopt;
  }
  vm::CellSlice cs = *slice;
  if (cs.fetch_ulong(1) != 1 || !block::tlb::t_MsgAddressInt.skip(cs) || !block::tlb::t_StorageInfo.skip(cs) ||
      !cs.advance(64)) {
    return std::nullopt;
  }
  return replace_amount(c, *slice, cs);
}

std::optional<std::string> mutate_shard_account(Choices &c, const std::string &b64) {
  auto root = from_base64(b64);
  if (!root) {
    return std::nullopt;
  }
  auto slice = ordinary_slice(*root);
  if (!slice || slice->size_refs() < 1) {
    return std::nullopt;
  }
  auto account = mutate_account_balance(c, slice->prefetch_ref(0));
  if (!account) {
    return std::nullopt;
  }
  vm::CellSlice rest = *slice;
  rest.advance_refs(1);
  vm::CellBuilder cb;
  if (!cb.store_ref_bool(*account) || !cb.append_cellslice_bool(rest)) {
    return std::nullopt;
  }
  return to_base64(cb.finalize());
}

CellRef random_body(Choices &c, const vm::CellSlice *old_body) {
  Bits body;
  switch (c.below(4)) {
    case 0:  // empty body
      break;
    case 1:  // a 32-bit operation and a 64-bit query id
      body.put(c.next() & 0xFFFFFFFF, 32);
      body.put(c.next(), 64);
      break;
    case 2:  // prefix of the old body
      if (old_body != nullptr) {
        const unsigned keep = static_cast<unsigned>(c.below(old_body->size() + 1));
        body.append_slice(*old_body, keep, 0, std::min(old_body->size_refs(), static_cast<unsigned>(c.below(5))));
      }
      break;
    default:  // the old body with one bit flipped
      if (old_body != nullptr && old_body->size() > 0) {
        body.append_slice(*old_body, old_body->size(), 0, old_body->size_refs());
        const unsigned at = static_cast<unsigned>(c.below(old_body->size()));
        body.bytes[at / 8] = static_cast<unsigned char>(body.bytes[at / 8] ^ (0x80u >> (at % 8)));
      }
  }
  return body.finalize();
}

std::optional<std::string> mutate_message(Choices &c, const std::string &b64) {
  auto root = from_base64(b64);
  if (!root) {
    return std::nullopt;
  }
  auto slice = ordinary_slice(*root);
  if (!slice) {
    return std::nullopt;
  }
  const vm::CellSlice &whole = *slice;
  const bool internal = block::tlb::t_CommonMsgInfo.get_tag(whole) == block::tlb::CommonMsgInfo::int_msg_info;
  const auto kind = c.below(4);
  if (internal && kind == 0) {  // the attached value
    vm::CellSlice cs = whole;
    if (!cs.advance(4) || !block::tlb::t_MsgAddressInt.skip(cs) || !block::tlb::t_MsgAddressInt.skip(cs)) {
      return std::nullopt;
    }
    auto cell = replace_amount(c, whole, cs);
    return cell ? std::optional<std::string>(to_base64(*cell)) : std::nullopt;
  }
  if (internal && kind == 1) {  // flip ihr_disabled, bounce or bounced
    Bits out;
    out.append_slice(whole, whole.size(), 0, whole.size_refs());
    const unsigned at = 1 + static_cast<unsigned>(c.below(3));
    out.bytes[0] = static_cast<unsigned char>(out.bytes[0] ^ (0x80u >> at));
    return to_base64(out.finalize());
  }
  // The body: skip the header and the optional StateInit, then replace (Either X ^X).
  vm::CellSlice cs = whole;
  if (!block::tlb::t_CommonMsgInfo.skip(cs) || cs.size() < 1) {
    return std::nullopt;
  }
  if (cs.fetch_ulong(1) == 1) {
    if (cs.size() < 1) {
      return std::nullopt;
    }
    if (cs.fetch_ulong(1) == 0) {
      if (!block::tlb::t_StateInit.skip(cs)) {
        return std::nullopt;
      }
    } else if (!cs.advance_refs(1)) {
      return std::nullopt;
    }
  }
  if (cs.size() < 1) {
    return std::nullopt;
  }
  const unsigned bit_pos = whole.size() - cs.size();
  const unsigned ref_pos = whole.size_refs() - cs.size_refs();
  std::optional<vm::CellSlice> old_body;
  if (cs.fetch_ulong(1) == 0) {
    old_body = cs;
  } else if (cs.size_refs() >= 1) {
    old_body = ordinary_slice(cs.prefetch_ref(0));
  }
  CellRef body = random_body(c, old_body ? &*old_body : nullptr);
  vm::CellSlice prefix = whole;
  if (!prefix.only_first(bit_pos, ref_pos)) {
    return std::nullopt;
  }
  vm::CellBuilder cb;
  if (!cb.append_cellslice_bool(prefix)) {
    return std::nullopt;
  }
  auto body_slice = ordinary_slice(body);
  const bool inline_fits = body_slice && cb.can_extend_by(1 + body_slice->size(), body_slice->size_refs());
  if (inline_fits && c.chance(60)) {
    if (!cb.store_long_bool(0, 1) || !cb.append_cellslice_bool(*body_slice)) {
      return std::nullopt;
    }
  } else if (!cb.store_long_bool(1, 1) || !cb.store_ref_bool(body)) {
    return std::nullopt;
  }
  return to_base64(cb.finalize());
}

Json mutated_txn(Choices &c, const Json &seed) {
  Json ctx = seed;
  const auto rounds = 1 + c.below(2);
  for (std::uint64_t round = 0; round < rounds; ++round) {
    switch (c.below(8)) {
      case 0: {
        const Json *now = ctx.find("now");
        std::int64_t value = now != nullptr && now->is(Json::Type::Int) ? now->as_int() : 1;
        static const std::array<std::int64_t, 5> deltas{1, 60, 3600, 86400, 31536000};
        value += (c.chance(50) ? 1 : -1) * pick(c, deltas);
        if (c.chance(10)) {
          value = static_cast<std::int64_t>(1 + c.below(0xFFFFFFFFull));
        }
        ctx.set("now", Json::integer(std::clamp<std::int64_t>(value, 1, 0xFFFFFFFFLL)));
        break;
      }
      case 1: {
        const Json *lt = ctx.find("lt");
        std::int64_t value = lt != nullptr && lt->is(Json::Type::Int) ? lt->as_int() : 1;
        static const std::array<std::int64_t, 4> deltas{1, 1000, 1000000, 1000000000};
        const auto delta = pick(c, deltas);
        value = c.chance(50) ? (value > INT64_MAX - delta ? value : value + delta) : value - delta;
        ctx.set("lt", Json::integer(std::max<std::int64_t>(value, 1)));
        break;
      }
      case 2:
        ctx.set("rand_seed", Json::string(random_seed_hex(c)));
        break;
      case 3: {
        const Json *kind = ctx.find("tick_tock");
        if (kind != nullptr && kind->is(Json::Type::String)) {
          ctx.set("tick_tock", Json::string(kind->as_string() == "tick" ? "tock" : "tick"));
        }
        break;
      }
      case 4:
      case 5: {
        const Json *account = ctx.find("shard_account");
        if (account != nullptr && account->is(Json::Type::String)) {
          if (auto fresh = mutate_shard_account(c, account->as_string())) {
            ctx.set("shard_account", Json::string(*fresh));
          }
        }
        break;
      }
      case 6: {
        const Json *message = ctx.find("message");
        if (message != nullptr && message->is(Json::Type::String)) {
          if (auto fresh = mutate_message(c, message->as_string())) {
            ctx.set("message", Json::string(*fresh));
          }
        }
        break;
      }
      default:
        ctx.erase(c.chance(50) ? "libraries" : "prev_blocks");
    }
  }
  return ctx;
}

// ---------------------------------------------------------------------------------------------
// Seeds

std::string lineage_name(std::string text) {
  for (auto &ch : text) {
    if (ch >= 'A' && ch <= 'Z') {
      ch = static_cast<char>(ch - 'A' + 'a');
    } else if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')) {
      ch = '-';
    }
  }
  if (text.empty()) {
    text = "seed";
  }
  return text.substr(0, 64);
}

// Replaces every {"blob": "<digest>"} by the blob's base64 text.
bool resolve_blobs(Json &value, const Json &blobs, int depth) {
  if (depth > 64) {
    return false;
  }
  if (value.is(Json::Type::Object)) {
    if (value.fields().size() == 1) {
      const Json *ref = value.find("blob");
      if (ref != nullptr && ref->is(Json::Type::String)) {
        const Json *blob = blobs.find(ref->as_string());
        if (blob == nullptr || !blob->is(Json::Type::String)) {
          return false;
        }
        value = *blob;
        return true;
      }
    }
    for (auto &[key, item] : value.fields()) {
      if (!resolve_blobs(item, blobs, depth + 1)) {
        return false;
      }
    }
  } else if (value.is(Json::Type::Array)) {
    for (auto &item : value.items()) {
      if (!resolve_blobs(item, blobs, depth + 1)) {
        return false;
      }
    }
  }
  return true;
}

std::string load_file(const std::filesystem::path &path, const std::string &harness, std::vector<Seed> &out) {
  std::ifstream in(path);
  if (!in) {
    return "cannot read " + path.string();
  }
  Json blobs = Json::object();
  const auto blob_path = path.parent_path() / (path.stem().string() + ".blobs.json");
  if (std::filesystem::exists(blob_path)) {
    std::ifstream blob_in(blob_path);
    std::string text((std::istreambuf_iterator<char>(blob_in)), std::istreambuf_iterator<char>());
    auto parsed = parse_json(text);
    if (!parsed.value || !parsed.value->is(Json::Type::Object)) {
      return blob_path.string() + ": " + (parsed.error.empty() ? "object required" : parsed.error);
    }
    blobs = std::move(*parsed.value);
  }
  std::string line;
  std::size_t number = 0;
  while (std::getline(in, line)) {
    ++number;
    if (line.empty()) {
      continue;
    }
    if (line.size() > kMaxSeedLineBytes) {
      return path.string() + ":" + std::to_string(number) + ": line too long";
    }
    auto parsed = parse_json(line);
    if (!parsed.value) {
      return path.string() + ":" + std::to_string(number) + ": " + parsed.error;
    }
    Json &record = *parsed.value;
    Json *context = record.find("context");
    if (context == nullptr || !context->is(Json::Type::Object)) {
      continue;
    }
    std::string lineage = lineage_name(path.stem().string());
    if (const Json *meta = record.find("metadata")) {
      const Json *h = meta->find("harness");
      if (h == nullptr || !h->is(Json::Type::String) || h->as_string() != harness) {
        continue;
      }
      if (const Json *family = meta->find("family"); family != nullptr && family->is(Json::Type::String)) {
        lineage = lineage_name(family->as_string());
      }
    } else if (const Json *h = record.find("harness"); h != nullptr && h->is(Json::Type::String)) {
      if (h->as_string() != harness) {
        continue;
      }
    }
    Json ctx = std::move(*context);
    if (!resolve_blobs(ctx, blobs, 0)) {
      return path.string() + ":" + std::to_string(number) + ": unresolved blob";
    }
    if (out.size() >= kMaxSeeds) {
      return "too many seed contexts";
    }
    out.push_back(Seed{lineage, std::move(ctx)});
  }
  return {};
}

}  // namespace

std::uint64_t SeededChoices::next() {
  std::uint64_t z = (state_ += 0x9E3779B97F4A7C15ull);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

std::uint64_t ByteChoices::next() {
  std::uint64_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value <<= 8;
    if (pos_ < size_) {
      value |= data_[pos_++];
    }
  }
  return value;
}

std::uint64_t case_seed(std::uint64_t campaign_seed, std::uint64_t index) {
  SeededChoices mix(campaign_seed ^ (index * 0xD1B54A32D192ED03ull));
  return mix.next();
}

std::string SeedPool::load(const std::string &harness, const std::vector<std::string> &paths) {
  for (const auto &item : paths) {
    std::error_code ec;
    const std::filesystem::path path(item);
    if (std::filesystem::is_directory(path, ec)) {
      std::vector<std::filesystem::path> files;
      for (const auto &entry : std::filesystem::recursive_directory_iterator(path, ec)) {
        if (entry.is_regular_file() && entry.path().extension() == ".jsonl") {
          files.push_back(entry.path());
        }
      }
      std::sort(files.begin(), files.end());
      for (const auto &file : files) {
        if (auto error = load_file(file, harness, seeds_); !error.empty()) {
          return error;
        }
      }
    } else if (std::filesystem::is_regular_file(path, ec)) {
      if (auto error = load_file(path, harness, seeds_); !error.empty()) {
        return error;
      }
    } else {
      return item + ": no such file or directory";
    }
  }
  return {};
}

std::string check_generator(const std::string &harness, const SeedPool &pool) {
  if (harness == "vm") {
    return {};
  }
  if (harness == "txn") {
    return pool.seeds().empty() ? "txn generation needs seed contexts (--seeds)" : std::string();
  }
  return "no generator for harness " + harness;
}

std::string generate(const std::string &harness, Choices &choices, const SeedPool &pool, Case &out) {
  const auto &seeds = pool.seeds();
  try {
    if (harness == "vm") {
      if (seeds.empty() || choices.chance(40)) {
        out.lineage = "grammar";
        out.context = grammar_vm(choices);
      } else {
        const auto &seed = seeds[choices.below(seeds.size())];
        out.lineage = seed.lineage;
        out.context = mutated_vm(choices, seed.context);
      }
      return {};
    }
    if (harness == "txn") {
      if (seeds.empty()) {
        return "txn generation needs seed contexts (--seeds)";
      }
      const auto &seed = seeds[choices.below(seeds.size())];
      out.lineage = seed.lineage;
      out.context = mutated_txn(choices, seed.context);
      return {};
    }
  } catch (const std::exception &e) {
    return std::string("generator exception: ") + e.what();
  } catch (...) {
    // Cell operations report overflow and underflow by throwing; such a case is dropped by the caller.
    return "generator exception";
  }
  return "no generator for harness " + harness;
}

std::string context_digest(const std::string &canonical_context) {
  return td::hex_encode(td::sha256(canonical_context));
}

}  // namespace conformance::fuzz
