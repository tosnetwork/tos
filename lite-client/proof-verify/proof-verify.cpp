/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <set>
#include <unordered_set>

#include "block/block-auto.h"
#include "block/block-db.h"
#include "block/block-parse.h"
#include "block/check-proof.h"
#include "block/mc-config.h"
#include "block/signature-set.h"
#include "block/transaction.h"
#include "common/refint.h"
#include "lite-client/lite-client-common.h"
#include "smc-envelope/SmartContract.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/base64.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/dict.h"
#include "vm/memo.h"
#include "vm/vm.h"

#include "proof-verify.h"

namespace tos::proofverify {

namespace {

constexpr std::size_t kMaxScannedCells = 1u << 16;
constexpr int kMaxLibraryDepth = 512;
constexpr std::size_t kMaxJsonInput = 1u << 20;

std::string hex(const td::Bits256& value) {
  auto text = value.to_hex();
  for (auto& c : text) {
    c = static_cast<char>(td::to_lower(c));
  }
  return text;
}

// Minimal JSON writer: every string passes through escape(), every number is
// an integer the caller produced. No external text is ever emitted raw.
std::string escape(td::Slice text);
std::string escape(const char* text) {
  return escape(td::Slice(text, std::strlen(text)));
}
std::string escape(td::Slice text) {
  std::string out;
  out.reserve(text.size() + 2);
  out.push_back('"');
  for (unsigned char c : text) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20 || c >= 0x7f) {
          static const char digits[] = "0123456789abcdef";
          out += "\\u00";
          out.push_back(digits[c >> 4]);
          out.push_back(digits[c & 15]);
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out.push_back('"');
  return out;
}

class JsonObjectWriter {
 public:
  JsonObjectWriter& raw(const char* key, const std::string& value) {
    return raw(key, td::Slice(value));
  }
  JsonObjectWriter& raw(const char* key, td::Slice value) {
    out_ += first_ ? "" : ",";
    first_ = false;
    out_ += escape(key);
    out_ += ":";
    out_.append(value.data(), value.size());
    return *this;
  }
  JsonObjectWriter& str(const char* key, td::Slice value) {
    return raw(key, escape(value));
  }
  JsonObjectWriter& str(const char* key, const std::string& value) {
    return raw(key, escape(td::Slice(value)));
  }
  JsonObjectWriter& str(const char* key, const char* value) {
    return raw(key, escape(value));
  }
  template <class T>
  JsonObjectWriter& num(const char* key, T value) {
    return raw(key, std::to_string(value));
  }
  JsonObjectWriter& boolean(const char* key, bool value) {
    return raw(key, std::string(value ? "true" : "false"));
  }
  std::string finish() const {
    return "{" + out_ + "}";
  }

 private:
  std::string out_;
  bool first_{true};
};

std::string shard_hex(tos::ShardId shard) {
  static const char digits[] = "0123456789abcdef";
  std::string out(16, '0');
  for (int i = 15; i >= 0; --i) {
    out[i] = digits[shard & 15];
    shard >>= 4;
  }
  return out;
}

td::Result<td::Bits256> parse_digest(td::Slice text) {
  if (text.size() != 64) {
    return td::Status::Error("digest must be 64 hex characters");
  }
  auto decoded = td::hex_decode(text);
  if (decoded.is_error()) {
    return td::Status::Error("digest is not hex");
  }
  td::Bits256 result;
  result.as_slice().copy_from(decoded.ok());
  if (result.is_zero()) {
    return td::Status::Error("digest is zero");
  }
  return result;
}

td::Result<td::JsonValue> decode_json(td::Slice text, std::string& storage) {
  if (text.size() > kMaxJsonInput) {
    return td::Status::Error("JSON input exceeds size limit");
  }
  storage = text.str();
  TRY_RESULT(value, td::json_decode(td::MutableSlice(storage)));
  if (value.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("JSON input must be an object");
  }
  return std::move(value);
}

td::Status only_fields(const td::JsonObject& object, std::initializer_list<td::Slice> allowed, td::Slice what) {
  td::Status status;
  object.foreach ([&](td::Slice name, const td::JsonValue&) {
    if (status.is_error()) {
      return;
    }
    bool known = std::any_of(allowed.begin(), allowed.end(), [&](td::Slice candidate) { return candidate == name; });
    if (!known) {
      status = td::Status::Error(PSLICE() << what << " has unknown field " << name);
    }
  });
  return status;
}

const td::JsonValue* field(const td::JsonObject& object, td::Slice name) {
  const td::JsonValue* found = nullptr;
  object.foreach ([&](td::Slice key, const td::JsonValue& value) {
    if (key == name && found == nullptr) {
      found = &value;
    }
  });
  return found;
}

td::Result<std::int64_t> required_integer(const td::JsonObject& object, td::Slice name) {
  const auto* value = field(object, name);
  if (value == nullptr || value->type() != td::JsonValue::Type::Number) {
    return td::Status::Error(PSLICE() << "field " << name << " must be an integer");
  }
  auto parsed = td::to_integer_safe<std::int64_t>(value->get_number());
  if (parsed.is_error()) {
    return td::Status::Error(PSLICE() << "field " << name << " must be an integer");
  }
  return parsed.move_as_ok();
}

td::Result<std::string> required_string(const td::JsonObject& object, td::Slice name) {
  const auto* value = field(object, name);
  if (value == nullptr || value->type() != td::JsonValue::Type::String) {
    return td::Status::Error(PSLICE() << "field " << name << " must be a string");
  }
  return value->get_string().str();
}

td::Result<tos::BlockIdExt> parse_masterchain_id(const td::JsonObject& object, td::Slice what) {
  TRY_STATUS(only_fields(object, {"workchain", "shard", "seqno", "root_hash", "file_hash"}, what));
  if (field(object, "workchain") != nullptr) {
    TRY_RESULT(workchain, required_integer(object, "workchain"));
    if (workchain != tos::masterchainId) {
      return td::Status::Error(PSLICE() << what << " must be a masterchain block");
    }
  }
  if (field(object, "shard") != nullptr) {
    TRY_RESULT(shard, required_string(object, "shard"));
    if (shard != shard_hex(tos::shardIdAll)) {
      return td::Status::Error(PSLICE() << what << " must use masterchain shard 8000000000000000");
    }
  }
  TRY_RESULT(seqno, required_integer(object, "seqno"));
  if (seqno < 0 || seqno > std::numeric_limits<td::uint32>::max()) {
    return td::Status::Error(PSLICE() << what << " seqno is out of range");
  }
  TRY_RESULT(root_text, required_string(object, "root_hash"));
  TRY_RESULT(file_text, required_string(object, "file_hash"));
  TRY_RESULT(root, parse_digest(root_text));
  TRY_RESULT(file, parse_digest(file_text));
  return tos::BlockIdExt{tos::masterchainId, tos::shardIdAll, static_cast<td::uint32>(seqno), root, file};
}

td::Result<block::StdAddress> parse_address(td::Slice text) {
  auto colon = text.find(':');
  if (colon == td::Slice::npos) {
    return td::Status::Error("account must be <workchain>:<64 hex>");
  }
  auto workchain = td::to_integer_safe<td::int32>(text.substr(0, colon));
  if (workchain.is_error() || (workchain.ok() != tos::masterchainId && workchain.ok() != tos::basechainId)) {
    return td::Status::Error("account workchain must be -1 or 0");
  }
  TRY_RESULT(addr, parse_digest(text.substr(colon + 1)));
  return block::StdAddress{workchain.ok(), addr};
}

td::int32 method_id_of(td::Slice name) {
  return static_cast<td::int32>((td::crc16(name) & 0xffff) | 0x10000);
}

td::Result<td::Ref<vm::Cell>> boc_cell(td::Slice base64) {
  TRY_RESULT(raw, td::base64_decode(base64));
  if (raw.size() > kMaxJsonInput) {
    return td::Status::Error("argument BOC exceeds size limit");
  }
  return vm::std_boc_deserialize(raw);
}

td::Result<vm::StackEntry> parse_stack_entry(const td::JsonValue& value, std::size_t depth) {
  if (depth > kMaxStackDepth) {
    return td::Status::Error("argument nesting exceeds limit");
  }
  if (value.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("stack entry must be an object");
  }
  const auto& object = value.get_object();
  TRY_RESULT(type, required_string(object, "type"));
  if (type == "null") {
    TRY_STATUS(only_fields(object, {"type"}, "null entry"));
    return vm::StackEntry{};
  }
  if (type == "int") {
    TRY_STATUS(only_fields(object, {"type", "value"}, "int entry"));
    TRY_RESULT(text, required_string(object, "value"));
    auto parsed = td::dec_string_to_int256(td::Slice(text));
    if (parsed.is_null() || !parsed->is_valid()) {
      return td::Status::Error("int entry is not a 257-bit decimal integer");
    }
    return vm::StackEntry{std::move(parsed)};
  }
  if (type == "cell" || type == "slice") {
    TRY_STATUS(only_fields(object, {"type", "boc"}, "cell entry"));
    TRY_RESULT(text, required_string(object, "boc"));
    TRY_RESULT(cell, boc_cell(text));
    if (type == "cell") {
      return vm::StackEntry{std::move(cell)};
    }
    return vm::StackEntry{vm::load_cell_slice_ref(std::move(cell))};
  }
  if (type == "tuple") {
    TRY_STATUS(only_fields(object, {"type", "items"}, "tuple entry"));
    const auto* items = field(object, "items");
    if (items == nullptr || items->type() != td::JsonValue::Type::Array) {
      return td::Status::Error("tuple entry needs an items array");
    }
    if (items->get_array().size() > 255) {
      return td::Status::Error("tuple has too many items");
    }
    std::vector<vm::StackEntry> tuple;
    for (const auto& item : items->get_array()) {
      TRY_RESULT(entry, parse_stack_entry(item, depth + 1));
      tuple.push_back(std::move(entry));
    }
    return vm::StackEntry{vm::make_tuple_ref(std::move(tuple))};
  }
  return td::Status::Error(PSLICE() << "unsupported stack entry type " << type);
}

td::Result<std::string> render_cell_boc(const td::Ref<vm::Cell>& cell) {
  TRY_RESULT(raw, vm::std_boc_serialize(cell, 31));
  return td::base64_encode(raw.as_slice());
}

td::Result<std::string> render_stack_entry(const vm::StackEntry& entry, std::size_t depth) {
  if (depth > kMaxStackDepth) {
    return td::Status::Error("result nesting exceeds limit");
  }
  switch (entry.type()) {
    case vm::StackEntry::t_null:
      return std::string{R"({"type":"null"})"};
    case vm::StackEntry::t_int: {
      auto value = entry.as_int();
      if (value.is_null() || !value->is_valid()) {
        return std::string{R"({"type":"nan"})"};
      }
      return JsonObjectWriter{}.str("type", "int").str("value", value->to_dec_string()).finish();
    }
    case vm::StackEntry::t_cell: {
      TRY_RESULT(boc, render_cell_boc(entry.as_cell()));
      return JsonObjectWriter{}.str("type", "cell").str("boc", boc).finish();
    }
    case vm::StackEntry::t_slice: {
      vm::CellBuilder builder;
      if (!builder.append_cellslice_bool(entry.as_slice())) {
        return td::Status::Error("result slice cannot be rendered");
      }
      TRY_RESULT(boc, render_cell_boc(builder.finalize_novm()));
      return JsonObjectWriter{}.str("type", "slice").str("boc", boc).finish();
    }
    case vm::StackEntry::t_builder: {
      auto copy = entry.as_builder()->finalize_copy();
      TRY_RESULT(boc, render_cell_boc(copy));
      return JsonObjectWriter{}.str("type", "builder").str("boc", boc).finish();
    }
    case vm::StackEntry::t_tuple: {
      std::string items = "[";
      bool first = true;
      for (const auto& item : *entry.as_tuple()) {
        TRY_RESULT(rendered, render_stack_entry(item, depth + 1));
        items += first ? "" : ",";
        items += rendered;
        first = false;
      }
      items += "]";
      return JsonObjectWriter{}.str("type", "tuple").raw("items", items).finish();
    }
    default:
      return td::Status::Error("get-method returned a value that cannot be rendered");
  }
}

template <class T>
td::Result<tos::lite_api::object_ptr<T>> fetch(const td::BufferSlice& raw, td::Slice what) {
  if (raw.size() > kMaxFileBytes) {
    return td::Status::Error(PSLICE() << what << " exceeds size limit");
  }
  auto object = tos::fetch_tl_object<T>(raw.clone(), true);
  if (object.is_error()) {
    return td::Status::Error(PSLICE() << what << " is not the expected lite API answer: " << object.error().message());
  }
  return object.move_as_ok();
}

struct ChainOutcome {
  std::size_t links{0};
  std::vector<VerifiedBlock> key_blocks;
  td::uint32 utime{0};
  bool is_key{false};
};

// Reads the generation time from a link's destination header proof. Only
// called after the link validated, so the header is bound to `link.to`.
td::Result<td::uint32> destination_utime(const block::BlockProofLink& link) {
  TRY_RESULT(root, vm::MerkleProof::virtualize(link.dest_proof));
  block::gen::Block::Record block_record;
  block::gen::BlockInfo::Record info;
  if (!(tlb::unpack_cell(root, block_record) && tlb::unpack_cell(block_record.info, info))) {
    return td::Status::Error("key block header cannot be parsed");
  }
  return info.gen_utime;
}

td::Result<ChainOutcome> verify_forward_chain(const tos::BlockIdExt& start, const tos::BlockIdExt& target,
                                              const std::vector<td::BufferSlice>& responses) {
  if (responses.empty()) {
    return td::Status::Error("no proof chain reaches the target");
  }
  if (responses.size() > kMaxChainResponses) {
    return td::Status::Error("proof chain has too many responses");
  }
  ChainOutcome outcome;
  auto current = start;
  for (std::size_t index = 0; index < responses.size(); ++index) {
    TRY_RESULT(object, fetch<tos::lite_api::liteServer_partialBlockProof>(responses[index], "proof chain response"));
    TRY_RESULT_PREFIX(chain, liteclient::deserialize_proof_chain(std::move(object)), "proof chain is malformed: ");
    if (chain->from != current) {
      return td::Status::Error("proof chain does not start at the authenticated block");
    }
    if (!chain->link_count()) {
      return td::Status::Error("proof chain response has no links");
    }
    for (const auto& link : chain->links) {
      if (!link.is_fwd) {
        return td::Status::Error("proof chain contains a backward link");
      }
      if (link.sig_set.is_null() || !link.sig_set->is_pq()) {
        return td::Status::Error("proof chain link does not carry a post-quantum finality signature set");
      }
    }
    if (chain->to.seqno() > target.seqno()) {
      return td::Status::Error("proof chain passes the target height");
    }
    const bool last = index + 1 == responses.size();
    if (chain->complete != last) {
      return td::Status::Error("proof chain completion flag differs from its position");
    }
    if (last && chain->to != target) {
      return td::Status::Error("proof chain does not end at the exact target block");
    }
    if (outcome.links > kMaxChainLinks - chain->link_count()) {
      return td::Status::Error("proof chain has too many links");
    }
    auto status = chain->validate();
    if (status.is_error()) {
      return status.move_as_error_prefix("proof chain validation failed: ");
    }
    for (const auto& link : chain->links) {
      if (link.is_key) {
        TRY_RESULT(utime, destination_utime(link));
        outcome.key_blocks.push_back(VerifiedBlock{link.to, utime});
      }
    }
    outcome.links += chain->link_count();
    outcome.utime = chain->last_utime;
    outcome.is_key = chain->last_link().is_key;
    current = chain->to;
  }
  if (current != target || outcome.utime == 0) {
    return td::Status::Error("proof chain does not reach the target");
  }
  return outcome;
}

td::Status verify_descent(const tos::BlockIdExt& target, const tos::BlockIdExt& head,
                          const std::vector<td::BufferSlice>& responses) {
  if (responses.size() != 1) {
    return td::Status::Error("descent from the verified head needs exactly one backward proof");
  }
  TRY_RESULT(object, fetch<tos::lite_api::liteServer_partialBlockProof>(responses[0], "descent proof"));
  TRY_RESULT_PREFIX(chain, liteclient::deserialize_proof_chain(std::move(object)), "descent proof is malformed: ");
  if (chain->from != target || chain->to != head || !chain->complete || !chain->link_count()) {
    return td::Status::Error("descent proof does not connect the target to the verified head");
  }
  for (const auto& link : chain->links) {
    if (link.is_fwd) {
      return td::Status::Error("descent proof contains a forward link");
    }
  }
  auto status = chain->validate();
  if (status.is_error()) {
    return status.move_as_error_prefix("descent proof validation failed: ");
  }
  return td::Status::OK();
}

td::Result<td::Ref<vm::Cell>> proven_state(const tos::BlockIdExt& target, const tos::BlockIdExt& answered,
                                           td::Slice state_proof, td::Slice data_proof, td::Slice what) {
  if (answered != target) {
    return td::Status::Error(PSLICE() << what << " answers for another block");
  }
  if (state_proof.empty() || data_proof.empty()) {
    return td::Status::Error(PSLICE() << what << " omits its proof");
  }
  auto root = block::check_extract_state_proof(target, state_proof, data_proof);
  if (root.is_error()) {
    return root.move_as_error_prefix(PSLICE() << what << " is not proven from the target: ");
  }
  return root.move_as_ok();
}

td::Result<std::vector<ProvenParam>> verify_params(const tos::BlockIdExt& target, const std::vector<int>& indexes,
                                                   const std::optional<td::BufferSlice>& raw) {
  if (!raw) {
    return td::Status::Error("configuration proof is missing");
  }
  TRY_RESULT(info, fetch<tos::lite_api::liteServer_configInfo>(*raw, "configuration proof"));
  TRY_RESULT(state_root, proven_state(target, tos::create_block_id(info->id_), info->state_proof_.as_slice(),
                                      info->config_proof_.as_slice(), "configuration proof"));
  TRY_RESULT_PREFIX(config, block::Config::extract_from_state(state_root, 0), "proven state has no configuration: ");
  std::vector<ProvenParam> result;
  for (int index : indexes) {
    td::Ref<vm::Cell> cell = config->get_config_param(index);
    if (cell.is_null()) {
      return td::Status::Error(PSLICE() << "ConfigParam " << index << " is absent from the proven configuration");
    }
    auto boc = vm::std_boc_serialize(cell, 31);
    if (boc.is_error()) {
      return td::Status::Error(PSLICE() << "ConfigParam " << index << " is not fully contained in the proof");
    }
    auto reparsed = vm::std_boc_deserialize(boc.ok().as_slice());
    if (reparsed.is_error() || reparsed.ok()->get_hash() != cell->get_hash()) {
      return td::Status::Error(PSLICE() << "ConfigParam " << index << " does not round-trip");
    }
    result.push_back(ProvenParam{index, td::Bits256{cell->get_hash().bits()}, boc.ok().as_slice().str()});
  }
  return result;
}

struct AccountRecord {
  ProvenAccount public_view;
  td::Ref<vm::Cell> code;
  td::Ref<vm::Cell> data;
  td::Ref<vm::Cell> account_libraries;
  block::CurrencyCollection balance;
  td::Ref<vm::CellSlice> address_slice;
  td::RefInt256 due_payment;
};

td::Result<AccountRecord> verify_account(const tos::BlockIdExt& target, const block::StdAddress& address,
                                         const std::optional<td::BufferSlice>& raw) {
  if (!raw) {
    return td::Status::Error("account proof is missing");
  }
  TRY_RESULT(answer, fetch<tos::lite_api::liteServer_accountState>(*raw, "account proof"));
  block::AccountState state;
  state.blk = tos::create_block_id(answer->id_);
  state.shard_blk = tos::create_block_id(answer->shardblk_);
  state.shard_proof = std::move(answer->shard_proof_);
  state.proof = std::move(answer->proof_);
  state.state = std::move(answer->state_);
  if (state.blk != target) {
    return td::Status::Error("account proof answers for another block");
  }
  if (state.proof.empty()) {
    return td::Status::Error("account proof omits its state proof");
  }
  if (state.shard_blk != target && state.shard_proof.empty()) {
    return td::Status::Error("account proof omits its shard proof");
  }
  TRY_RESULT_PREFIX(info, state.validate(target, address), "account is not proven at the target: ");

  AccountRecord record;
  auto& view = record.public_view;
  view.address = address;
  view.shard_block = state.shard_blk;
  view.gen_utime = info.gen_utime;
  view.gen_lt = info.gen_lt;
  view.last_trans_lt = info.last_trans_lt;
  view.last_trans_hash = info.last_trans_hash;
  if (info.true_root.is_null()) {
    view.exists = false;
    return record;
  }
  view.exists = true;
  view.state_hash = td::Bits256{info.true_root->get_hash().bits()};
  TRY_RESULT(serialized, vm::std_boc_serialize(info.true_root, 31));
  view.state_boc = serialized.as_slice().str();

  block::gen::Account::Record_account account;
  if (!tlb::unpack_cell(info.true_root, account)) {
    return td::Status::Error("proven account cell cannot be parsed");
  }
  block::StdAddress embedded;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(account.addr, embedded) ||
      embedded.workchain != address.workchain || embedded.addr != address.addr) {
    return td::Status::Error("proven account cell names another address");
  }
  record.address_slice = account.addr;
  block::gen::StorageInfo::Record storage_info;
  if (!tlb::csr_unpack(account.storage_stat, storage_info)) {
    return td::Status::Error("proven account storage information cannot be parsed");
  }
  record.due_payment = td::zero_refint();
  auto due = storage_info.due_payment;
  if (due.write().fetch_long(1)) {
    record.due_payment = block::tlb::t_Tomis.as_integer(due);
    if (record.due_payment.is_null()) {
      return td::Status::Error("proven account due payment cannot be parsed");
    }
  }
  block::gen::AccountStorage::Record storage;
  if (!tlb::csr_unpack(account.storage, storage) || !record.balance.validate_unpack(storage.balance)) {
    return td::Status::Error("proven account storage cannot be parsed");
  }
  view.balance = record.balance.tomis->to_dec_string();
  auto account_state = storage.state;
  if (account_state->prefetch_ulong(1) == 1) {
    block::gen::StateInit::Record state_init;
    if (!(account_state.write().advance(1) && tlb::csr_unpack(std::move(account_state), state_init))) {
      return td::Status::Error("proven active account state cannot be parsed");
    }
    view.active = true;
    record.code = state_init.code->prefetch_ref();
    record.data = state_init.data->prefetch_ref();
    record.account_libraries = state_init.library->prefetch_ref();
    if (record.code.not_null()) {
      view.code_hash = td::Bits256{record.code->get_hash().bits()};
    }
    if (record.data.not_null()) {
      view.data_hash = td::Bits256{record.data->get_hash().bits()};
    }
  }
  return record;
}

td::Status collect_libraries(const td::Ref<vm::Cell>& root, std::set<td::Bits256>& out,
                             std::unordered_set<vm::CellHash>& visited) {
  if (root.is_null()) {
    return td::Status::OK();
  }
  std::vector<td::Ref<vm::Cell>> pending{root};
  while (!pending.empty()) {
    auto cell = std::move(pending.back());
    pending.pop_back();
    if (!visited.insert(cell->get_hash()).second) {
      continue;
    }
    if (visited.size() > kMaxScannedCells) {
      return td::Status::Error("account code and data are too large to scan for libraries");
    }
    TRY_RESULT(loaded, cell->load_cell());
    const auto& data_cell = loaded.data_cell;
    if (data_cell->special_type() == vm::Cell::SpecialType::Library) {
      if (data_cell->size() != 8 + 256) {
        return td::Status::Error("library reference cell is malformed");
      }
      td::Bits256 hash;
      hash.as_slice().copy_from(td::Slice(data_cell->get_data() + 1, 32));
      out.insert(hash);
      continue;
    }
    if (data_cell->special_type() != vm::Cell::SpecialType::Ordinary) {
      return td::Status::Error("account code or data contains an unexpected exotic cell");
    }
    for (unsigned i = 0; i < data_cell->size_refs(); ++i) {
      pending.push_back(data_cell->get_ref(i));
    }
  }
  return td::Status::OK();
}

td::Result<vm::Dictionary> verify_libraries(const tos::BlockIdExt& target, std::set<td::Bits256> required,
                                            const std::optional<td::BufferSlice>& raw,
                                            std::vector<td::Bits256>& registered) {
  vm::Dictionary libraries{256};
  if (required.empty()) {
    return std::move(libraries);
  }
  if (!raw) {
    return td::Status::Error("a required library is referenced but no library proof was supplied");
  }
  TRY_RESULT(answer, fetch<tos::lite_api::liteServer_libraryResultWithProof>(*raw, "library proof"));
  TRY_RESULT(state_root, proven_state(target, tos::create_block_id(answer->id_), answer->state_proof_.as_slice(),
                                      answer->data_proof_.as_slice(), "library proof"));
  block::gen::ShardStateUnsplit::Record state;
  if (!tlb::unpack_cell(state_root, state)) {
    return td::Status::Error("library proof state cannot be parsed");
  }
  vm::Dictionary proven{state.r1.libraries->prefetch_ref(), 256};
  std::unordered_set<vm::CellHash> visited;
  std::set<td::Bits256> done;
  while (!required.empty()) {
    auto hash = *required.begin();
    required.erase(required.begin());
    if (!done.insert(hash).second) {
      continue;
    }
    if (done.size() > kMaxLibraries) {
      return td::Status::Error("too many required libraries");
    }
    auto descriptor = proven.lookup(hash.bits(), 256);
    if (descriptor.is_null()) {
      return td::Status::Error(PSLICE() << "required library " << hash.to_hex() << " is not in the proven state");
    }
    block::gen::LibDescr::Record record;
    if (!tlb::csr_unpack(descriptor, record)) {
      return td::Status::Error("proven library descriptor cannot be parsed");
    }
    const tos::lite_api::liteServer_libraryEntry* entry = nullptr;
    for (const auto& candidate : answer->result_) {
      if (candidate->hash_ == hash) {
        if (entry != nullptr) {
          return td::Status::Error("library proof repeats a library");
        }
        entry = candidate.get();
      }
    }
    if (entry == nullptr) {
      return td::Status::Error(PSLICE() << "library proof omits required library " << hash.to_hex());
    }
    TRY_RESULT_PREFIX(content, vm::std_boc_deserialize(entry->data_.as_slice()), "library content is malformed: ");
    if (td::Bits256{content->get_hash().bits()} != hash || content->get_hash() != record.lib->get_hash()) {
      return td::Status::Error("library content differs from the proven library");
    }
    if (content->get_depth() > kMaxLibraryDepth) {
      return td::Status::Error("library depth exceeds limit");
    }
    std::set<td::Bits256> nested;
    TRY_STATUS(collect_libraries(content, nested, visited));
    for (const auto& next : nested) {
      if (!done.count(next)) {
        required.insert(next);
      }
    }
    if (!libraries.set_ref(hash.bits(), 256, content)) {
      return td::Status::Error("library dictionary cannot be built");
    }
    registered.push_back(hash);
  }
  return std::move(libraries);
}

td::Bits256 derive_rand_seed(const tos::BlockIdExt& target, const block::StdAddress& address) {
  std::string preimage = "tos-proof-verify/rand-seed/1";
  preimage.append(target.root_hash.as_slice().data(), 32);
  preimage.append(target.file_hash.as_slice().data(), 32);
  const auto workchain = static_cast<td::uint32>(address.workchain);
  for (int shift = 24; shift >= 0; shift -= 8) {
    preimage.push_back(static_cast<char>((workchain >> shift) & 0xff));
  }
  preimage.append(address.addr.as_slice().data(), 32);
  td::Bits256 seed;
  td::sha256(preimage, seed.as_slice());
  return seed;
}

// SmartContractInfo for a get-method, built only from proven inputs. The field
// layout follows the transaction executor for the proven global version.
td::Result<td::Ref<vm::Tuple>> proven_c7(const block::ConfigInfo& config, const AccountRecord& account,
                                         const ExecutionContext& context) {
  std::vector<vm::StackEntry> tuple = {
      td::make_refint(0x076ef1ea),
      td::make_refint(0),
      td::make_refint(0),
      td::make_refint(context.unixtime),
      td::make_refint(context.block_lt),
      td::make_refint(context.block_lt),
      td::bits_to_refint(context.rand_seed.cbits(), 256, false),
      account.balance.as_vm_tuple(),
      account.address_slice,
      config.get_root_cell(),
  };
  const int version = config.get_global_version();
  if (version >= 4) {
    tuple.push_back(vm::StackEntry::maybe(account.code));
    tuple.push_back(block::CurrencyCollection::zero().as_vm_tuple());
    tuple.push_back(td::zero_refint());
    TRY_RESULT_PREFIX(previous, config.get_prev_blocks_info(), "previous block information is not proven: ");
    tuple.push_back(std::move(previous));
  }
  if (version >= 6) {
    auto unpacked = config.get_unpacked_config_tuple(context.unixtime);
    if (unpacked.is_null()) {
      return td::Status::Error("unpacked configuration is not available from the proof");
    }
    tuple.push_back(std::move(unpacked));
    tuple.push_back(account.due_payment);
    td::optional<block::PrecompiledContractsConfig::Contract> precompiled;
    if (account.code.not_null()) {
      precompiled = config.get_precompiled_contracts_config().get_contract(account.code->get_hash().bits());
    }
    tuple.push_back(precompiled ? td::make_refint(precompiled.value().gas_usage) : vm::StackEntry());
  }
  if (version >= 11) {
    tuple.push_back(block::transaction::Transaction::prepare_in_msg_params_tuple(nullptr, {}, {}));
  }
  return vm::make_tuple_ref(td::make_cnt_ref<std::vector<vm::StackEntry>>(std::move(tuple)));
}

td::Result<std::string> serialize_stack(const td::Ref<vm::Stack>& stack) {
  vm::FakeVmStateLimits limits(1000);
  vm::VmStateInterface::Guard guard(&limits);
  vm::CellBuilder builder;
  td::Ref<vm::Cell> cell;
  if (!(stack->serialize(builder) && builder.finalize_to(cell))) {
    return td::Status::Error("get-method result stack cannot be serialized");
  }
  TRY_RESULT(raw, vm::std_boc_serialize(cell, 31));
  return td::base64_encode(raw.as_slice());
}

td::Status run_get_methods(const Request& request, const tos::BlockIdExt& target, const AccountRecord& account,
                           const Material& material, Verified& verified) {
  if (!account.public_view.exists || !account.public_view.active || account.code.is_null()) {
    return td::Status::Error("get-methods need an active account with code");
  }
  if (!material.exec_config) {
    return td::Status::Error("execution configuration proof is missing");
  }
  TRY_RESULT(info, fetch<tos::lite_api::liteServer_configInfo>(*material.exec_config, "execution configuration"));
  TRY_RESULT(state_root, proven_state(target, tos::create_block_id(info->id_), info->state_proof_.as_slice(),
                                      info->config_proof_.as_slice(), "execution configuration"));
  const int mode = block::ConfigInfo::needCapabilities | block::ConfigInfo::needPrevBlocks;
  TRY_RESULT_PREFIX(config_info, block::ConfigInfo::extract_config(state_root, target, mode),
                    "execution configuration is not usable: ");
  std::shared_ptr<const block::ConfigInfo> config{std::move(config_info)};
  if (config->get_global_version() < 15 && account.account_libraries.not_null()) {
    return td::Status::Error("account-local libraries are not supported below global version 15");
  }

  std::set<td::Bits256> required;
  std::unordered_set<vm::CellHash> visited;
  TRY_STATUS(collect_libraries(account.code, required, visited));
  TRY_STATUS(collect_libraries(account.data, required, visited));
  ExecutionContext context;
  TRY_RESULT(libraries, verify_libraries(target, std::move(required), material.libraries, context.libraries));

  context.unixtime = account.public_view.gen_utime;
  context.block_lt = account.public_view.gen_lt;
  context.rand_seed = derive_rand_seed(target, request.account.value());
  context.config_root_hash = td::Bits256{config->get_root_cell()->get_hash().bits()};
  context.global_version = config->get_global_version();
  TRY_RESULT(c7, proven_c7(*config, account, context));

  for (const auto& method : request.get_methods) {
    tos::SmartContract contract{tos::SmartContract::State{account.code, account.data}};
    tos::SmartContract::Args args;
    args.set_c7(c7);
    args.set_config(std::shared_ptr<const block::Config>(config));
    args.set_libraries(libraries);
    args.set_limits(vm::GasLimits{kGetMethodGasLimit, kGetMethodGasLimit});
    args.set_stack(method.args);
    args.set_method_id(method.method_id);
    auto answer = contract.run_get_method(std::move(args));
    if (answer.missing_library) {
      return td::Status::Error(PSLICE() << "get-method " << method.method << " needs unproven library "
                                        << answer.missing_library.value().to_hex());
    }
    if (!answer.success || (answer.code != 0 && answer.code != 1)) {
      return td::Status::Error(PSLICE() << "get-method " << method.method << " failed with exit code " << answer.code);
    }
    GetMethodResult result;
    result.method = method.method;
    result.method_id = method.method_id;
    result.args_json = method.args_json;
    result.exit_code = answer.code;
    result.gas_used = answer.gas_used;
    TRY_RESULT(stack_boc, serialize_stack(answer.stack));
    result.stack_boc = std::move(stack_boc);
    std::string entries = "[";
    const int depth = answer.stack->depth();
    for (int i = 0; i < depth; ++i) {
      // Bottom first: entry 0 is the first value the method returned.
      TRY_RESULT(rendered, render_stack_entry(answer.stack->at(depth - 1 - i), 0));
      entries += i ? "," : "";
      entries += rendered;
    }
    entries += "]";
    result.stack_json = std::move(entries);
    verified.get_methods.push_back(std::move(result));
  }
  verified.context = std::move(context);
  return td::Status::OK();
}

td::Status check_live(const Request& request, const tos::BlockIdExt& target, td::uint32 utime,
                      const ChainOutcome& outcome, const std::optional<LiveState>& state, const Material& material,
                      const Policy& policy, Verified& verified) {
  if (static_cast<std::int64_t>(utime) > policy.now + kMaxFutureSkewSeconds) {
    return td::Status::Error("target block is dated in the future of the local clock");
  }
  const auto age = policy.now - static_cast<std::int64_t>(utime);
  if (age > request.max_age_seconds) {
    return td::Status::Error(PSLICE() << "target block is " << age << " s old, above the maximum age of "
                                      << request.max_age_seconds << " s");
  }
  if (state && state->head) {
    const auto& head = state->head->id;
    if (target.seqno() < head.seqno()) {
      return td::Status::Error("target is below the verified head: rollback refused");
    }
    if (target.seqno() == head.seqno() && target != head) {
      return td::Status::Error("target conflicts with the verified head at the same height");
    }
    for (const auto& key : outcome.key_blocks) {
      if (key.id.seqno() == head.seqno() && key.id != head) {
        return td::Status::Error("proof chain conflicts with the verified head at the same height");
      }
    }
    if (target.seqno() > head.seqno()) {
      TRY_STATUS(verify_descent(target, head, material.descent));
      verified.descends_from = head;
    }
  }
  if (state && state->key_block) {
    for (const auto& key : outcome.key_blocks) {
      if (key.id.seqno() == state->key_block->id.seqno() && key.id != state->key_block->id) {
        return td::Status::Error("proof chain conflicts with the verified key block at the same height");
      }
    }
  }
  LiveState next;
  next.anchor = verified.anchor;
  next.head = VerifiedBlock{target, utime};
  if (state) {
    next.key_block = state->key_block;
  }
  if (!outcome.key_blocks.empty()) {
    next.key_block = outcome.key_blocks.back();
  }
  verified.next_state = std::move(next);
  return td::Status::OK();
}

std::string anchor_kind_name(AnchorKind kind) {
  return kind == AnchorKind::Zerostate ? "zerostate" : "key_block";
}

td::Result<Verified> verify_impl(const Anchor& anchor, const Request& request, td::Slice request_bytes,
                                 const Material& material, const std::optional<LiveState>& state,
                                 const Policy& policy) {
  Verified verified;
  verified.mode = request.mode;
  verified.anchor = anchor;
  verified.now = policy.now;
  verified.max_age_seconds = request.max_age_seconds;
  {
    td::Bits256 digest;
    td::sha256(request_bytes, digest.as_slice());
    verified.request_sha256 = digest.to_hex();
  }
  if (request.mode == Mode::Historical && state) {
    return td::Status::Error("historical mode does not use live state");
  }
  if (request.mode == Mode::Live && !state) {
    return td::Status::Error("live mode requires a local live state record");
  }
  if (state && (state->anchor.id != anchor.id || state->anchor.kind != anchor.kind)) {
    return td::Status::Error("live state record belongs to another anchor");
  }

  tos::BlockIdExt target;
  if (request.target) {
    target = *request.target;
  } else {
    if (request.mode != Mode::Live || !material.masterchain_info) {
      return td::Status::Error("target block is not specified");
    }
    TRY_RESULT(info, fetch<tos::lite_api::liteServer_masterchainInfo>(*material.masterchain_info, "latest block"));
    target = tos::create_block_id(info->last_);
    if (!target.is_masterchain_ext() || !target.is_valid_full() || target.id.shard != tos::shardIdAll) {
      return td::Status::Error("latest block answer is not a masterchain block");
    }
  }
  if (target.seqno() <= anchor.id.seqno()) {
    return td::Status::Error("target must be after the anchor");
  }

  const auto start = chain_start(
      anchor, request.mode == Mode::Live ? std::optional<tos::BlockIdExt>{target} : std::optional<tos::BlockIdExt>{},
      request, state);
  verified.start = start;
  verified.target = target;
  ChainOutcome outcome;
  if (start == target) {
    if (!material.chain.empty()) {
      return td::Status::Error("proof chain supplied for an already verified target");
    }
    if (!(state && state->key_block && state->key_block->id == target && state->key_block->gen_utime)) {
      return td::Status::Error("target is not authenticated");
    }
    outcome.utime = state->key_block->gen_utime;
    outcome.is_key = true;
  } else {
    TRY_RESULT_ASSIGN(outcome, verify_forward_chain(start, target, material.chain));
  }
  verified.links = outcome.links;
  for (const auto& key : outcome.key_blocks) {
    verified.key_blocks.push_back(key.id);
  }
  verified.target_gen_utime = outcome.utime;
  verified.target_is_key_block = outcome.is_key;

  if (request.mode == Mode::Live) {
    TRY_STATUS(check_live(request, target, outcome.utime, outcome, state, material, policy, verified));
  } else if (!material.descent.empty() || material.masterchain_info) {
    return td::Status::Error("historical mode does not accept live material");
  }

  if (!request.config_params.empty()) {
    TRY_RESULT_ASSIGN(verified.params, verify_params(target, request.config_params, material.config));
  } else if (material.config) {
    return td::Status::Error("configuration proof supplied without a configuration request");
  }

  if (request.account) {
    TRY_RESULT(account, verify_account(target, *request.account, material.account));
    if (!request.get_methods.empty()) {
      TRY_STATUS(run_get_methods(request, target, account, material, verified));
    } else if (material.exec_config || material.libraries) {
      return td::Status::Error("execution material supplied without a get-method request");
    }
    verified.account = std::move(account.public_view);
  } else if (material.account || material.exec_config || material.libraries) {
    return td::Status::Error("account material supplied without an account request");
  }
  return verified;
}

std::string verified_block_json(const VerifiedBlock& block) {
  auto id = block_id_json(block.id);
  id.pop_back();
  return id + ",\"gen_utime\":" + std::to_string(block.gen_utime) + "}";
}

td::Result<VerifiedBlock> parse_verified_block(const td::JsonValue& value) {
  if (value.type() != td::JsonValue::Type::Object) {
    return td::Status::Error("state entry must be an object");
  }
  const auto& object = value.get_object();
  TRY_STATUS(
      only_fields(object, {"workchain", "shard", "seqno", "root_hash", "file_hash", "gen_utime"}, "state entry"));
  TRY_RESULT(utime, required_integer(object, "gen_utime"));
  if (utime < 0 || utime > std::numeric_limits<td::uint32>::max()) {
    return td::Status::Error("state entry utime is out of range");
  }
  // Reuse the id parser on a copy without the utime field.
  td::int64 seqno = 0;
  TRY_RESULT_ASSIGN(seqno, required_integer(object, "seqno"));
  TRY_RESULT(root_text, required_string(object, "root_hash"));
  TRY_RESULT(file_text, required_string(object, "file_hash"));
  TRY_RESULT(root, parse_digest(root_text));
  TRY_RESULT(file, parse_digest(file_text));
  TRY_RESULT(workchain, required_integer(object, "workchain"));
  TRY_RESULT(shard, required_string(object, "shard"));
  if (workchain != tos::masterchainId || shard != shard_hex(tos::shardIdAll) || seqno <= 0 ||
      seqno > std::numeric_limits<td::uint32>::max()) {
    return td::Status::Error("state entry is not a masterchain block after the anchor");
  }
  return VerifiedBlock{tos::BlockIdExt{tos::masterchainId, tos::shardIdAll, static_cast<td::uint32>(seqno), root, file},
                       static_cast<td::uint32>(utime)};
}

}  // namespace

std::string block_id_json(const tos::BlockIdExt& id) {
  return JsonObjectWriter{}
      .num("workchain", id.id.workchain)
      .str("shard", shard_hex(id.id.shard))
      .num("seqno", id.id.seqno)
      .str("root_hash", hex(id.root_hash))
      .str("file_hash", hex(id.file_hash))
      .finish();
}

td::Result<Anchor> parse_anchor(td::Slice json) {
  std::string storage;
  TRY_RESULT(value, decode_json(json, storage));
  auto& object = value.get_object();
  TRY_STATUS(only_fields(object, {"kind", "workchain", "shard", "seqno", "root_hash", "file_hash"}, "anchor"));
  TRY_RESULT(kind, required_string(object, "kind"));
  if (field(object, "workchain") == nullptr || field(object, "shard") == nullptr) {
    return td::Status::Error("anchor must state its workchain and shard");
  }
  Anchor anchor;
  if (kind == "zerostate") {
    anchor.kind = AnchorKind::Zerostate;
  } else if (kind == "key_block") {
    anchor.kind = AnchorKind::KeyBlock;
  } else {
    return td::Status::Error("anchor kind must be zerostate or key_block");
  }
  // parse_masterchain_id rejects unknown fields; strip "kind" by checking it separately.
  TRY_RESULT(workchain, required_integer(object, "workchain"));
  TRY_RESULT(shard, required_string(object, "shard"));
  TRY_RESULT(seqno, required_integer(object, "seqno"));
  TRY_RESULT(root_text, required_string(object, "root_hash"));
  TRY_RESULT(file_text, required_string(object, "file_hash"));
  if (workchain != tos::masterchainId || shard != shard_hex(tos::shardIdAll)) {
    return td::Status::Error("anchor must be a masterchain block");
  }
  if (seqno < 0 || seqno > std::numeric_limits<td::uint32>::max()) {
    return td::Status::Error("anchor seqno is out of range");
  }
  if ((anchor.kind == AnchorKind::Zerostate) != (seqno == 0)) {
    return td::Status::Error("a zerostate anchor has seqno 0 and a key-block anchor does not");
  }
  TRY_RESULT(root, parse_digest(root_text));
  TRY_RESULT(file, parse_digest(file_text));
  anchor.id = tos::BlockIdExt{tos::masterchainId, tos::shardIdAll, static_cast<td::uint32>(seqno), root, file};
  return anchor;
}

std::string render_anchor(const Anchor& anchor) {
  auto id = block_id_json(anchor.id);
  return "{\"kind\":" + escape(anchor_kind_name(anchor.kind)) + "," + id.substr(1);
}

td::Result<Anchor> anchor_from_zerostate(td::Slice zerostate_boc) {
  if (zerostate_boc.empty() || zerostate_boc.size() > kMaxFileBytes) {
    return td::Status::Error("zerostate file is empty or exceeds size limit");
  }
  TRY_RESULT(root, vm::std_boc_deserialize(zerostate_boc));
  block::gen::ShardStateUnsplit::Record state;
  if (!tlb::unpack_cell(root, state)) {
    return td::Status::Error("zerostate is not a shard state");
  }
  block::ShardId shard;
  if (!shard.deserialize(state.shard_id.write()) || shard.workchain_id != tos::masterchainId || state.seq_no != 0) {
    return td::Status::Error("zerostate is not the masterchain zerostate");
  }
  Anchor anchor;
  anchor.kind = AnchorKind::Zerostate;
  anchor.id = tos::BlockIdExt{tos::masterchainId, tos::shardIdAll, 0, td::Bits256{root->get_hash().bits()},
                              block::compute_file_hash(zerostate_boc)};
  return anchor;
}

td::Result<Request> parse_request(td::Slice json) {
  std::string storage;
  TRY_RESULT(value, decode_json(json, storage));
  auto& object = value.get_object();
  TRY_STATUS(
      only_fields(object, {"mode", "target", "max_age_seconds", "config_params", "account", "get_methods"}, "request"));
  Request request;
  TRY_RESULT(mode, required_string(object, "mode"));
  if (mode == "live") {
    request.mode = Mode::Live;
  } else if (mode == "historical") {
    request.mode = Mode::Historical;
  } else {
    return td::Status::Error("request mode must be live or historical");
  }
  if (const auto* target = field(object, "target")) {
    if (target->type() != td::JsonValue::Type::Object) {
      return td::Status::Error("target must be an object");
    }
    TRY_RESULT(id, parse_masterchain_id(target->get_object(), "target"));
    if (id.seqno() == 0) {
      return td::Status::Error("target must be after the zerostate");
    }
    request.target = id;
  }
  if (request.mode == Mode::Historical) {
    if (!request.target) {
      return td::Status::Error("historical mode requires an exact target block");
    }
    if (field(object, "max_age_seconds") != nullptr) {
      return td::Status::Error("historical mode has no maximum age");
    }
  } else {
    TRY_RESULT(max_age, required_integer(object, "max_age_seconds"));
    if (max_age <= 0 || max_age > kMaxAgeLimitSeconds) {
      return td::Status::Error("live mode requires a finite positive maximum age");
    }
    request.max_age_seconds = max_age;
  }
  if (const auto* params = field(object, "config_params")) {
    if (params->type() != td::JsonValue::Type::Array || params->get_array().empty() ||
        params->get_array().size() > kMaxConfigParams) {
      return td::Status::Error("config_params must be a non-empty bounded array");
    }
    std::set<int> seen;
    for (const auto& item : params->get_array()) {
      if (item.type() != td::JsonValue::Type::Number) {
        return td::Status::Error("config_params entries must be integers");
      }
      auto index = td::to_integer_safe<td::int32>(item.get_number());
      if (index.is_error() || index.ok() < 0 || !seen.insert(index.ok()).second) {
        return td::Status::Error("config_params entries must be distinct non-negative integers");
      }
      request.config_params.push_back(index.ok());
    }
  }
  if (field(object, "account") != nullptr) {
    TRY_RESULT(text, required_string(object, "account"));
    TRY_RESULT(address, parse_address(text));
    request.account = address;
  }
  if (const auto* methods = field(object, "get_methods")) {
    if (!request.account) {
      return td::Status::Error("get_methods require an account");
    }
    if (methods->type() != td::JsonValue::Type::Array || methods->get_array().empty() ||
        methods->get_array().size() > kMaxGetMethods) {
      return td::Status::Error("get_methods must be a non-empty bounded array");
    }
    for (const auto& item : methods->get_array()) {
      if (item.type() != td::JsonValue::Type::Object) {
        return td::Status::Error("get_methods entries must be objects");
      }
      const auto& entry = item.get_object();
      TRY_STATUS(only_fields(entry, {"method", "args"}, "get-method"));
      GetMethodRequest method;
      TRY_RESULT_ASSIGN(method.method, required_string(entry, "method"));
      if (method.method.empty() || method.method.size() > 128) {
        return td::Status::Error("get-method name is empty or too long");
      }
      for (unsigned char c : method.method) {
        if (!(std::isalnum(c) || c == '_')) {
          return td::Status::Error("get-method name must be an identifier");
        }
      }
      method.method_id = method_id_of(method.method);
      std::string args_json = "[";
      if (const auto* args = field(entry, "args")) {
        if (args->type() != td::JsonValue::Type::Array || args->get_array().size() > kMaxGetMethodArgs) {
          return td::Status::Error("get-method args must be a bounded array");
        }
        bool first = true;
        for (const auto& arg : args->get_array()) {
          TRY_RESULT(entry_value, parse_stack_entry(arg, 0));
          TRY_RESULT(rendered, render_stack_entry(entry_value, 0));
          args_json += first ? "" : ",";
          args_json += rendered;
          first = false;
          method.args.push_back(std::move(entry_value));
        }
      }
      args_json += "]";
      method.args_json = std::move(args_json);
      request.get_methods.push_back(std::move(method));
    }
  }
  return request;
}

td::Result<LiveState> parse_state(td::Slice json) {
  std::string storage;
  TRY_RESULT(value, decode_json(json, storage));
  auto& object = value.get_object();
  TRY_STATUS(only_fields(object, {"interface", "anchor", "head", "key_block"}, "live state"));
  TRY_RESULT(interface, required_string(object, "interface"));
  if (interface != kStateInterface) {
    return td::Status::Error("live state record has another interface version");
  }
  const auto* anchor_value = field(object, "anchor");
  if (anchor_value == nullptr || anchor_value->type() != td::JsonValue::Type::Object) {
    return td::Status::Error("live state record has no anchor");
  }
  LiveState state;
  {
    const auto& anchor_object = anchor_value->get_object();
    TRY_STATUS(only_fields(anchor_object, {"kind", "workchain", "shard", "seqno", "root_hash", "file_hash"},
                           "live state anchor"));
    TRY_RESULT(kind, required_string(anchor_object, "kind"));
    TRY_RESULT(seqno, required_integer(anchor_object, "seqno"));
    TRY_RESULT(root_text, required_string(anchor_object, "root_hash"));
    TRY_RESULT(file_text, required_string(anchor_object, "file_hash"));
    TRY_RESULT(root, parse_digest(root_text));
    TRY_RESULT(file, parse_digest(file_text));
    if ((kind != "zerostate" && kind != "key_block") || seqno < 0 || seqno > std::numeric_limits<td::uint32>::max()) {
      return td::Status::Error("live state anchor is malformed");
    }
    state.anchor.kind = kind == "zerostate" ? AnchorKind::Zerostate : AnchorKind::KeyBlock;
    state.anchor.id = tos::BlockIdExt{tos::masterchainId, tos::shardIdAll, static_cast<td::uint32>(seqno), root, file};
  }
  if (const auto* head = field(object, "head")) {
    TRY_RESULT(parsed, parse_verified_block(*head));
    state.head = parsed;
  }
  if (const auto* key = field(object, "key_block")) {
    TRY_RESULT(parsed, parse_verified_block(*key));
    state.key_block = parsed;
  }
  if (state.key_block && (!state.head || state.key_block->id.seqno() > state.head->id.seqno())) {
    return td::Status::Error("live state key block is not at or below its head");
  }
  return state;
}

std::string render_state(const LiveState& state) {
  JsonObjectWriter writer;
  writer.str("interface", kStateInterface).raw("anchor", render_anchor(state.anchor));
  if (state.head) {
    writer.raw("head", verified_block_json(*state.head));
  }
  if (state.key_block) {
    writer.raw("key_block", verified_block_json(*state.key_block));
  }
  return writer.finish();
}

tos::BlockIdExt chain_start(const Anchor& anchor, std::optional<tos::BlockIdExt> target, const Request& request,
                            const std::optional<LiveState>& state) {
  if (request.mode == Mode::Live && state && state->key_block && target &&
      state->key_block->id.seqno() <= target->seqno() && state->anchor.id == anchor.id) {
    return state->key_block->id;
  }
  return anchor.id;
}

td::Result<Verified> verify(const Anchor& anchor, const Request& request, td::Slice request_bytes,
                            const Material& material, const std::optional<LiveState>& state, const Policy& policy) {
  try {
    return verify_impl(anchor, request, request_bytes, material, state, policy);
  } catch (vm::VmError& error) {
    return td::Status::Error(PSLICE() << "proof traversal error: " << error.get_msg());
  } catch (vm::VmVirtError& error) {
    return td::Status::Error(PSLICE() << "proof is missing required cells: " << error.get_msg());
  } catch (vm::CellBuilder::CellWriteError&) {
    return td::Status::Error("cell construction error");
  } catch (vm::CellBuilder::CellCreateError&) {
    return td::Status::Error("cell construction error");
  } catch (std::exception& error) {
    return td::Status::Error(PSLICE() << "verification error: " << error.what());
  }
}

td::Result<std::vector<td::Bits256>> required_libraries(td::Slice account_state_boc) {
  try {
    TRY_RESULT(root, vm::std_boc_deserialize(account_state_boc));
    block::gen::Account::Record_account account;
    if (!tlb::unpack_cell(root, account)) {
      return std::vector<td::Bits256>{};
    }
    block::gen::AccountStorage::Record storage;
    if (!tlb::csr_unpack(account.storage, storage)) {
      return td::Status::Error("account storage cannot be parsed");
    }
    std::set<td::Bits256> required;
    std::unordered_set<vm::CellHash> visited;
    auto state = storage.state;
    if (state->prefetch_ulong(1) == 1) {
      block::gen::StateInit::Record state_init;
      if (!(state.write().advance(1) && tlb::csr_unpack(std::move(state), state_init))) {
        return td::Status::Error("account state cannot be parsed");
      }
      TRY_STATUS(collect_libraries(state_init.code->prefetch_ref(), required, visited));
      TRY_STATUS(collect_libraries(state_init.data->prefetch_ref(), required, visited));
    }
    return std::vector<td::Bits256>(required.begin(), required.end());
  } catch (vm::VmError& error) {
    return td::Status::Error(PSLICE() << "account scan error: " << error.get_msg());
  } catch (vm::VmVirtError& error) {
    return td::Status::Error(PSLICE() << "account scan error: " << error.get_msg());
  }
}

std::string render_verified(const Verified& verified) {
  JsonObjectWriter out;
  out.str("status", "verified").str("interface", kInterface);
  out.str("mode", verified.mode == Mode::Live ? "live" : "historical");
  out.raw("anchor", render_anchor(verified.anchor));
  out.raw("start", block_id_json(verified.start));
  {
    auto target = block_id_json(verified.target);
    target.pop_back();
    target += ",\"gen_utime\":" + std::to_string(verified.target_gen_utime) +
              ",\"is_key_block\":" + (verified.target_is_key_block ? "true" : "false") + "}";
    out.raw("target", target);
  }
  {
    std::string keys = "[";
    for (std::size_t i = 0; i < verified.key_blocks.size(); ++i) {
      keys += (i ? "," : "") + block_id_json(verified.key_blocks[i]);
    }
    keys += "]";
    out.raw("chain", JsonObjectWriter{}.num("links", verified.links).raw("key_blocks", keys).finish());
  }
  if (verified.mode == Mode::Live) {
    JsonObjectWriter freshness;
    freshness.num("now", verified.now)
        .num("age_seconds", verified.now - static_cast<std::int64_t>(verified.target_gen_utime))
        .num("max_age_seconds", verified.max_age_seconds);
    if (verified.descends_from) {
      freshness.raw("descends_from", block_id_json(*verified.descends_from));
    }
    out.raw("live", freshness.finish());
  }
  out.str("request_sha256", verified.request_sha256);
  if (!verified.params.empty()) {
    std::string params = "[";
    for (std::size_t i = 0; i < verified.params.size(); ++i) {
      const auto& param = verified.params[i];
      params += (i ? "," : "") + JsonObjectWriter{}
                                     .num("index", param.index)
                                     .str("cell_hash", hex(param.cell_hash))
                                     .str("boc", td::base64_encode(param.boc))
                                     .finish();
    }
    params += "]";
    out.raw("config_params", params);
  }
  if (verified.account) {
    const auto& account = *verified.account;
    JsonObjectWriter writer;
    writer.str("address", PSLICE() << account.address.workchain << ":" << account.address.addr.to_hex())
        .raw("shard_block", block_id_json(account.shard_block))
        .boolean("exists", account.exists)
        .num("gen_utime", account.gen_utime)
        .num("gen_lt", account.gen_lt)
        .num("last_trans_lt", account.last_trans_lt)
        .str("last_trans_hash", hex(account.last_trans_hash));
    if (account.exists) {
      writer.str("state_hash", hex(account.state_hash))
          .str("state_boc", td::base64_encode(account.state_boc))
          .str("balance", account.balance)
          .boolean("active", account.active);
      if (account.active) {
        writer.str("code_hash", hex(account.code_hash)).str("data_hash", hex(account.data_hash));
      }
    }
    out.raw("account", writer.finish());
  }
  if (verified.context) {
    const auto& context = *verified.context;
    std::string libraries = "[";
    for (std::size_t i = 0; i < context.libraries.size(); ++i) {
      libraries += (i ? "," : "") + escape(hex(context.libraries[i]));
    }
    libraries += "]";
    out.raw("execution_context", JsonObjectWriter{}
                                     .num("unixtime", context.unixtime)
                                     .num("block_lt", context.block_lt)
                                     .str("rand_seed", hex(context.rand_seed))
                                     .str("config_root_hash", hex(context.config_root_hash))
                                     .num("global_version", context.global_version)
                                     .num("gas_limit", kGetMethodGasLimit)
                                     .raw("libraries", libraries)
                                     .finish());
    std::string methods = "[";
    for (std::size_t i = 0; i < verified.get_methods.size(); ++i) {
      const auto& method = verified.get_methods[i];
      methods += (i ? "," : "") + JsonObjectWriter{}
                                      .str("method", method.method)
                                      .num("method_id", method.method_id)
                                      .raw("args", method.args_json)
                                      .num("exit_code", method.exit_code)
                                      .num("gas_used", method.gas_used)
                                      .raw("stack", method.stack_json)
                                      .str("stack_boc", method.stack_boc)
                                      .finish();
    }
    methods += "]";
    out.raw("get_methods", methods);
  }
  return out.finish();
}

std::string render_refusal(td::Slice reason) {
  return JsonObjectWriter{}.str("status", "refused").str("interface", kInterface).str("reason", reason).finish();
}

}  // namespace tos::proofverify
