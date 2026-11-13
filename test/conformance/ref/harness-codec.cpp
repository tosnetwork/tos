// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// codec harness: decoding verdicts for bags of cells and TL-B types (schema/harness/codec-v1.schema.json).
//
// Every verdict comes from the decoders the node itself runs: vm::std_boc_deserialize_multi for the bag,
// the generated block::gen::* validators, the handwritten block::tlb::* validators where the node has one,
// and the node's semantic unpackers (block::Account::unpack, block::Config::unpack_validator_set,
// block::valid_config_data). Nothing here re-implements a decoder.
#include <algorithm>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "block/transaction.h"
#include "common/refint.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cellslice.h"
#include "vm/tosops.h"

#include "common.h"

namespace {

constexpr int kDefaultMaxCells = 1024;
constexpr int kMaxCellsLimit = 1 << 24;
constexpr int kMaxRoots = 1 << 14;
constexpr std::size_t kMaxBits = 1023;
constexpr std::size_t kMaxPath = 64;

// Facts of one verdict, in the order they were produced; rendered as a JSON object.
class Facts {
 public:
  void add_raw(const std::string &key, const std::string &json) {
    items_.emplace_back(key, json);
  }
  void add_bool(const std::string &key, bool value) {
    add_raw(key, conformance::json_bool(value));
  }
  void add_int(const std::string &key, long long value) {
    add_raw(key, std::to_string(value));
  }
  void add_text(const std::string &key, const std::string &value) {
    add_raw(key, conformance::json_quote(value));
  }
  void add_null(const std::string &key) {
    add_raw(key, "null");
  }
  std::string json() const {
    std::string out = "{";
    for (std::size_t i = 0; i < items_.size(); ++i) {
      out += (i ? "," : "") + conformance::json_quote(items_[i].first) + ":" + items_[i].second;
    }
    return out + "}";
  }

 private:
  std::vector<std::pair<std::string, std::string>> items_;
};

std::string hash_list(const std::vector<td::Ref<vm::Cell>> &roots) {
  std::string out = "[";
  for (std::size_t i = 0; i < roots.size(); ++i) {
    out += (i ? "," : "") + conformance::json_quote(conformance::hash_hex(roots[i]));
  }
  return out + "]";
}

std::string accepted(const std::vector<td::Ref<vm::Cell>> &roots, const std::string &reserialized_sha256,
                     const Facts &facts) {
  return "{\"outcome\":\"accepted\",\"root_hashes\":" + hash_list(roots) +
         ",\"reserialized_sha256\":" + conformance::json_quote(reserialized_sha256) + ",\"facts\":" + facts.json() +
         "}";
}

std::string rejected(const char *reason, const std::vector<td::Ref<vm::Cell>> &roots, const Facts &facts) {
  return "{\"outcome\":\"rejected\",\"reason\":" + conformance::json_quote(td::Slice(reason)) +
         ",\"root_hashes\":" + hash_list(roots) + ",\"facts\":" + facts.json() + "}";
}

std::string sha256_hex(td::Slice data) {
  unsigned char digest[32];
  td::sha256(data, td::MutableSlice(digest, sizeof digest));
  return td::hex_encode(td::Slice(digest, sizeof digest));
}

// A decoder may throw on malformed input (cell underflow, a special cell where an ordinary one is
// expected); the node treats that as a refusal, and so does the verdict.
template <class F>
bool guarded(F &&check) {
  try {
    return check();
  } catch (const vm::VmError &) {
    return false;
  } catch (const vm::VmVirtError &) {
    return false;
  } catch (const vm::CellBuilder::CellWriteError &) {
    return false;
  } catch (const vm::CellBuilder::CellCreateError &) {
    return false;
  } catch (const std::exception &) {
    return false;
  }
}

bool exact_validate(const tlb::TLB &type, const td::Ref<vm::Cell> &cell, int max_cells) {
  return guarded([&] {
    int ops = max_cells;
    return type.validate_ref(&ops, cell, false);
  });
}

struct TypedEntry {
  const char *name;
  const tlb::TLB *generated;
  const tlb::TLB *handwritten;
};

const std::vector<TypedEntry> &typed_entries() {
  static const std::vector<TypedEntry> entries{
      {"Account", &block::gen::t_Account, &block::tlb::t_AccountE},
      {"AccountStorage", &block::gen::t_AccountStorage, &block::tlb::t_AccountStorage},
      {"Block", &block::gen::t_Block, nullptr},
      {"BlockInfo", &block::gen::t_BlockInfo, nullptr},
      {"Coins", &block::gen::t_Coins, &block::tlb::t_Tomis},
      {"CurrencyCollection", &block::gen::t_CurrencyCollection, &block::tlb::t_CurrencyCollection},
      {"ExtraCurrencyCollection", &block::gen::t_ExtraCurrencyCollection, &block::tlb::t_ExtraCurrencyCollection},
      {"McStateExtra", &block::gen::t_McStateExtra, &block::tlb::t_McStateExtra},
      {"Message", &block::gen::t_Message_Any, &block::tlb::t_Message},
      {"MessageRelaxed", &block::gen::t_MessageRelaxed_Any, nullptr},
      {"MsgAddressInt", &block::gen::t_MsgAddressInt, &block::tlb::t_MsgAddressInt},
      {"ShardAccount", &block::gen::t_ShardAccount, &block::tlb::t_ShardAccount},
      {"ShardState", &block::gen::t_ShardState, &block::tlb::t_ShardState},
      {"ShardStateUnsplit", &block::gen::t_ShardStateUnsplit, nullptr},
      {"StateInit", &block::gen::t_StateInit, &block::tlb::t_StateInit},
      {"StorageUsed", &block::gen::t_StorageUsed, &block::tlb::t_StorageUsed},
      {"Transaction", &block::gen::t_Transaction, &block::tlb::t_Transaction},
      {"ValidatorDescr", &block::gen::t_ValidatorDescr, nullptr},
      {"ValidatorSet", &block::gen::t_ValidatorSet, nullptr},
  };
  return entries;
}

const TypedEntry *find_typed(td::Slice name) {
  for (const auto &entry : typed_entries()) {
    if (name == td::Slice(entry.name)) {
      return &entry;
    }
  }
  return nullptr;
}

td::Result<td::Ref<vm::Cell>> cell_from_bits(td::Slice bits) {
  if (bits.size() > kMaxBits) {
    return td::Status::Error("bits: more than 1023");
  }
  vm::CellBuilder cb;
  for (char c : bits) {
    if (c != '0' && c != '1') {
      return td::Status::Error("bits: only 0 and 1 allowed");
    }
    cb.store_long(c - '0', 1);
  }
  return cb.finalize_novm();
}

std::string bits_text(const td::Ref<vm::Cell> &cell) {
  vm::CellSlice cs{vm::NoVm(), cell};
  std::string out;
  out.reserve(cs.size());
  for (unsigned i = 0; i < cs.size(); ++i) {
    out += cs.data_bits()[i] ? '1' : '0';
  }
  return out;
}

// --- VarUInteger: every reader the node has for this encoding, on one cell of bits -----------------

void reader_bits(Facts &facts, const std::string &key, bool ok, const vm::CellSlice &cs, unsigned total) {
  if (ok) {
    facts.add_int(key, static_cast<long long>(total - cs.size()));
  } else {
    facts.add_null(key);
  }
}

void canonical_encoding(Facts &facts, const block::tlb::VarUInteger &type, const td::RefInt256 &value) {
  vm::CellBuilder cb;
  if (value.not_null() && type.store_integer_value(cb, *value)) {
    auto cell = cb.finalize_novm();
    facts.add_text("canonical_bits", bits_text(cell));
    facts.add_text("canonical_hash", conformance::hash_hex(cell));
  } else {
    facts.add_null("canonical_bits");
    facts.add_null("canonical_hash");
  }
}

td::Result<std::string> run_varuint(td::JsonObject &ctx, int n) {
  if (n < 1 || n > 32) {
    return td::Status::Error("n must be within 1..32 for VarUInteger");
  }
  const block::tlb::VarUInteger type(n);
  TRY_RESULT(op, ctx.get_optional_string_field("op", "read"));
  Facts facts;
  const std::vector<td::Ref<vm::Cell>> no_roots;
  if (op == "write") {
    TRY_RESULT(text, ctx.get_required_string_field("value"));
    if (text.size() > 90) {
      return td::Status::Error("value: too long");
    }
    auto value = td::dec_string_to_int256(text);
    if (value.is_null()) {
      return td::Status::Error("value: decimal integer required");
    }
    vm::CellBuilder cb;
    if (!type.store_integer_value(cb, *value)) {
      return rejected("range", no_roots, facts);
    }
    auto cell = cb.finalize_novm();
    facts.add_text("canonical_bits", bits_text(cell));
    facts.add_text("canonical_hash", conformance::hash_hex(cell));
    TRY_RESULT(boc, vm::std_boc_serialize(cell, 0));
    return accepted({cell}, sha256_hex(boc.as_slice()), facts);
  }
  if (op != "read") {
    return td::Status::Error("op must be read or write");
  }
  TRY_RESULT(bits, ctx.get_required_string_field("bits"));
  TRY_RESULT(cell, cell_from_bits(bits));
  const unsigned total = static_cast<unsigned>(bits.size());

  auto validate = vm::load_cell_slice(cell);
  int ops = kDefaultMaxCells;
  const bool validated = guarded([&] { return type.validate_skip(&ops, validate, false); });
  reader_bits(facts, "validate_bits", validated, validate, total);

  auto decode = vm::load_cell_slice(cell);
  td::RefInt256 value;
  guarded([&] {
    value = type.as_integer_skip(decode);
    return value.not_null();
  });
  facts.add_raw("value", value.not_null() ? conformance::json_quote(value->to_dec_string()) : "null");
  reader_bits(facts, "value_bits", value.not_null(), decode, total);

  auto skip = vm::load_cell_slice(cell);
  const bool skipped = guarded([&] { return type.skip(skip); });
  reader_bits(facts, "skip_bits", skipped, skip, total);

  auto as_uint = vm::load_cell_slice(cell);
  unsigned long long uint_value = 0;
  guarded([&] {
    uint_value = type.as_uint(as_uint);
    return true;
  });
  facts.add_text("as_uint", std::to_string(uint_value));

  const block::gen::VarUInteger generated(static_cast<unsigned>(n));
  auto gen_validate = vm::load_cell_slice(cell);
  ops = kDefaultMaxCells;
  const bool gen_ok = guarded([&] { return generated.validate_skip(&ops, gen_validate, false); });
  reader_bits(facts, "gen_validate_bits", gen_ok, gen_validate, total);
  auto gen_unpack = vm::load_cell_slice(cell);
  block::gen::VarUInteger::Record record;
  const bool unpacked = guarded([&] { return generated.unpack(gen_unpack, record); });
  facts.add_raw("gen_value",
                unpacked && record.value.not_null() ? conformance::json_quote(record.value->to_dec_string()) : "null");
  reader_bits(facts, "gen_value_bits", unpacked, gen_unpack, total);

  const block::tlb::VarUIntegerPos positive(n);
  auto pos_validate = vm::load_cell_slice(cell);
  ops = kDefaultMaxCells;
  const bool pos_ok = guarded([&] { return positive.validate_skip(&ops, pos_validate, false); });
  reader_bits(facts, "pos_validate_bits", pos_ok, pos_validate, total);
  auto pos_decode = vm::load_cell_slice(cell);
  td::RefInt256 pos_value;
  guarded([&] {
    pos_value = positive.as_integer_skip(pos_decode);
    return pos_value.not_null();
  });
  facts.add_raw("pos_value", pos_value.not_null() ? conformance::json_quote(pos_value->to_dec_string()) : "null");
  reader_bits(facts, "pos_value_bits", pos_value.not_null(), pos_decode, total);

  auto vm_load = vm::load_cell_slice(cell);
  td::RefInt256 vm_value;
  const int len_bits = 32 - td::count_leading_zeroes32(static_cast<unsigned>(n - 1));
  const bool vm_ok = guarded([&] { return vm::util::load_var_integer_q(vm_load, vm_value, len_bits, false, true); });
  facts.add_raw("vm_value", vm_ok && vm_value.not_null() ? conformance::json_quote(vm_value->to_dec_string()) : "null");
  reader_bits(facts, "vm_bits", vm_ok, vm_load, total);

  // StorageUsed is cells:(VarUInteger 7) bits:(VarUInteger 7): the encoding is given as both fields.
  if (n == 7 && 2 * total <= kMaxBits) {
    TRY_RESULT(twice, cell_from_bits(bits + bits));
    facts.add_bool("storage_used", exact_validate(block::tlb::t_StorageUsed, twice, kDefaultMaxCells));
  } else {
    facts.add_null("storage_used");
  }
  canonical_encoding(facts, type, value);

  const std::vector<td::Ref<vm::Cell>> roots{cell};
  if (!validated || validate.size() != 0 || validate.size_refs() != 0) {
    return rejected("tlb", roots, facts);
  }
  TRY_RESULT(boc, vm::std_boc_serialize(cell, 0));
  return accepted(roots, sha256_hex(boc.as_slice()), facts);
}

// --- Bag of cells input ---------------------------------------------------------------------------

struct Input {
  std::string bytes;
  bool from_bits = false;
};

td::Result<Input> read_input(td::JsonObject &ctx) {
  const bool has_boc = ctx.has_field("boc");
  const bool has_bits = ctx.has_field("bits");
  if (has_boc == has_bits) {
    return td::Status::Error("exactly one of boc and bits");
  }
  Input input;
  if (has_bits) {
    TRY_RESULT(bits, ctx.get_required_string_field("bits"));
    TRY_RESULT(cell, cell_from_bits(bits));
    TRY_RESULT(boc, vm::std_boc_serialize(cell, 0));
    input.bytes = boc.as_slice().str();
    input.from_bits = true;
    return input;
  }
  TRY_RESULT(b64, ctx.get_required_string_field("boc"));
  TRY_RESULT(bytes, td::base64_decode(b64));
  input.bytes = std::move(bytes);
  return input;
}

td::Result<td::Bits256> bits256_field(td::JsonObject &ctx, td::Slice field) {
  TRY_RESULT(text, ctx.get_required_string_field(field));
  if (text.size() != 64) {
    return td::Status::Error(PSLICE() << field << ": 64 hex digits required");
  }
  TRY_RESULT(raw, td::hex_decode(text));
  td::Bits256 out;
  out.as_slice().copy_from(raw);
  return out;
}

// The cell a typed verdict is about: the single root, or the child of a Merkle proof root when the
// context asks for it (a bag cannot hold a root of nonzero level, so cells with pruned branches travel
// under a proof), then the cell reached by following the reference indices of path.
td::Result<td::Ref<vm::Cell>> subject_cell(td::JsonObject &ctx, const td::Ref<vm::Cell> &root) {
  TRY_RESULT(proof_child, ctx.get_optional_bool_field("proof_child", false));
  td::Ref<vm::Cell> cell = root;
  if (proof_child) {
    bool is_special = false;
    auto cs = vm::load_cell_slice_special(cell, is_special);
    if (!is_special || cs.special_type() != vm::Cell::SpecialType::MerkleProof || cs.size_refs() != 1) {
      return td::Status::Error("proof_child: the root is not a Merkle proof");
    }
    cell = cs.prefetch_ref(0);
  }
  if (!ctx.has_field("path")) {
    return cell;
  }
  TRY_RESULT(path_value, ctx.extract_required_field("path", td::JsonValue::Type::Array));
  auto &path = path_value.get_array();
  if (path.size() > kMaxPath) {
    return td::Status::Error("path: too long");
  }
  for (auto &step : path) {
    if (step.type() != td::JsonValue::Type::Number) {
      return td::Status::Error("path: reference indices required");
    }
    TRY_RESULT(index, td::to_integer_safe<int>(step.get_number()));
    bool is_special = false;
    auto cs = vm::load_cell_slice_special(cell, is_special);
    if (index < 0 || static_cast<unsigned>(index) >= cs.size_refs()) {
      return td::Status::Error("path: no such reference");
    }
    cell = cs.prefetch_ref(index);
  }
  return cell;
}

td::Result<std::string> run_codec(td::JsonObject &ctx) {
  TRY_RESULT(type, ctx.get_required_string_field("type"));
  TRY_RESULT(max_cells, ctx.get_optional_int_field("max_cells", kDefaultMaxCells));
  if (max_cells < 1 || max_cells > kMaxCellsLimit) {
    return td::Status::Error("max_cells out of range");
  }
  TRY_RESULT(mode, ctx.get_optional_int_field("mode", 0));
  if (mode < 0 || mode > 31) {
    return td::Status::Error("mode must be within 0..31");
  }
  if (type == "VarUInteger") {
    TRY_RESULT(n, ctx.get_required_int_field("n"));
    return run_varuint(ctx, n);
  }

  TRY_RESULT(input, read_input(ctx));
  Facts facts;
  std::vector<td::Ref<vm::Cell>> roots;
  auto decoded = vm::std_boc_deserialize_multi(td::Slice(input.bytes), kMaxRoots);
  if (decoded.is_error()) {
    return rejected("boc", roots, facts);
  }
  roots = decoded.move_as_ok();
  auto reserialized = vm::std_boc_serialize_multi(roots, mode);
  if (reserialized.is_error()) {
    return td::Status::Error(PSLICE() << "re-serialization failed: " << reserialized.error().message());
  }
  const auto digest = sha256_hex(reserialized.ok().as_slice());
  const bool canonical = reserialized.ok().as_slice() == td::Slice(input.bytes);

  if (type == "cell") {
    facts.add_int("roots", static_cast<long long>(roots.size()));
    facts.add_bool("canonical", canonical);
    return accepted(roots, digest, facts);
  }
  if (roots.size() != 1) {
    facts.add_int("roots", static_cast<long long>(roots.size()));
    return rejected("roots", roots, facts);
  }
  TRY_RESULT(cell, subject_cell(ctx, roots[0]));

  if (type == "account_storage") {
    // The production account decoder on a ShardAccount, as emulator/test/storage-encoding.cpp runs it.
    TRY_RESULT(now, ctx.get_required_long_field("now"));
    TRY_RESULT(special, ctx.get_optional_bool_field("special", false));
    TRY_RESULT(workchain, ctx.get_optional_int_field("workchain", 0));
    if (now < 0 || now > 0xffffffffLL || workchain < -128 || workchain > 127) {
      return td::Status::Error("now or workchain out of range");
    }
    td::Bits256 address = td::Bits256::zero();
    if (ctx.has_field("address")) {
      TRY_RESULT(parsed, bits256_field(ctx, "address"));
      address = parsed;
    }
    block::Account account(workchain, address.bits());
    const bool ok = guarded([&] {
      return account.unpack(vm::load_cell_slice_ref(cell), static_cast<tos::UnixTime>(now), special) &&
             account.storage.not_null();
    });
    if (!ok) {
      return rejected("semantic", roots, facts);
    }
    auto storage = vm::CellBuilder{}.append_cellslice(*account.storage).finalize_novm();
    facts.add_int("storage_bits", static_cast<long long>(account.storage->size()));
    facts.add_text("storage_hash", conformance::hash_hex(storage));
    std::string refs = "[";
    for (unsigned i = 0; i < account.storage->size_refs(); ++i) {
      refs += (i ? "," : "") + conformance::json_quote(conformance::hash_hex(account.storage->prefetch_ref(i)));
    }
    facts.add_raw("storage_refs", refs + "]");
    return accepted(roots, digest, facts);
  }

  if (type == "config") {
    // The whole-configuration acceptance predicate the node applies to a new configuration.
    TRY_RESULT(address, bits256_field(ctx, "address"));
    TRY_RESULT(relax, ctx.get_optional_bool_field("relax", false));
    td::Ref<vm::Cell> old_mparams;
    if (ctx.has_field("old_mparams")) {
      TRY_RESULT(b64, ctx.get_required_string_field("old_mparams"));
      TRY_RESULT(bytes, td::base64_decode(b64));
      auto old = vm::std_boc_deserialize(td::Slice(bytes), false, true);
      if (old.is_error()) {
        return td::Status::Error(PSLICE() << "old_mparams: " << old.error().message());
      }
      old_mparams = old.move_as_ok();
      TRY_RESULT(old_proof_child, ctx.get_optional_bool_field("old_mparams_proof_child", false));
      if (old_proof_child) {
        bool is_special = false;
        auto cs = vm::load_cell_slice_special(old_mparams, is_special);
        if (!is_special || cs.special_type() != vm::Cell::SpecialType::MerkleProof || cs.size_refs() != 1) {
          return td::Status::Error("old_mparams_proof_child: not a Merkle proof");
        }
        old_mparams = cs.prefetch_ref(0);
      }
    }
    const bool valid = guarded([&] { return block::valid_config_data(cell, address, true, relax, old_mparams); });
    facts.add_bool("valid", valid);
    return valid ? accepted(roots, digest, facts) : rejected("semantic", roots, facts);
  }

  if (type == "ConfigParam") {
    TRY_RESULT(n, ctx.get_required_long_field("n"));
    if (n < 0 || n > 0xffffffffLL) {
      return td::Status::Error("n must be a 32-bit unsigned parameter index");
    }
    const block::gen::ConfigParam param(static_cast<unsigned>(n));
    const bool gen = exact_validate(param, cell, max_cells);
    facts.add_bool("gen", gen);
    return gen ? accepted(roots, digest, facts) : rejected("tlb", roots, facts);
  }

  if (type == "ConfigParams") {
    // With an address the input is the parameter dictionary root, stored with that address as
    // ConfigParams; without one it is a complete ConfigParams cell.
    td::Ref<vm::Cell> subject = cell;
    if (ctx.has_field("address")) {
      TRY_RESULT(address, bits256_field(ctx, "address"));
      vm::CellBuilder cb;
      if (!cb.store_bits_bool(address.cbits(), 256) || !cb.store_ref_bool(cell)) {
        return td::Status::Error("cannot store ConfigParams");
      }
      subject = cb.finalize_novm();
    }
    const bool gen = exact_validate(block::gen::t_ConfigParams, subject, max_cells);
    facts.add_bool("gen", gen);
    return gen ? accepted(roots, digest, facts) : rejected("tlb", roots, facts);
  }

  const auto *entry = find_typed(type);
  if (entry == nullptr) {
    return td::Status::Error("unknown type");
  }
  const bool gen = exact_validate(*entry->generated, cell, max_cells);
  facts.add_bool("gen", gen);
  bool handwritten = true;
  if (entry->handwritten != nullptr) {
    handwritten = exact_validate(*entry->handwritten, cell, max_cells);
    facts.add_bool("handwritten", handwritten);
  }
  if (type == "Coins") {
    td::RefInt256 value;
    guarded([&] {
      auto cs = vm::load_cell_slice(cell);
      value = block::tlb::t_Tomis.as_integer_skip(cs);
      return value.not_null() && cs.empty_ext();
    });
    facts.add_raw("value", value.not_null() ? conformance::json_quote(value->to_dec_string()) : "null");
  }
  bool semantic = true;
  if (type == "ValidatorSet") {
    // The node's own reading of a validator set: identity, key and weight rules on top of the schema.
    td::Result<std::shared_ptr<block::TotalValidatorSet>> set = td::Status::Error("not unpacked");
    semantic = guarded([&] {
      set = block::Config::unpack_validator_set(cell, false);
      return set.is_ok();
    });
    facts.add_bool("unpack", semantic);
    if (semantic) {
      const auto &value = *set.ok();
      facts.add_int("total", value.total);
      facts.add_int("main", value.main);
      facts.add_text("total_weight", std::to_string(value.total_weight));
    }
  }
  if (!gen) {
    return rejected("tlb", roots, facts);
  }
  if (!handwritten) {
    return rejected("handwritten", roots, facts);
  }
  if (!semantic) {
    return rejected("semantic", roots, facts);
  }
  return accepted(roots, digest, facts);
}

}  // namespace

CONFORMANCE_REGISTER_HARNESS(codec, run_codec);
