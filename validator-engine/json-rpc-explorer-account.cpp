/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstring>

#include "crypto/pq/pq-bytes.h"
#include "crypto/pq/pq-consensus.h"
#include "td/utils/base64.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/dict.h"

#include "json-rpc-explorer.h"

namespace tos::explorer {
namespace {
#include "explorer-pq-registry.inc"
struct InvalidState {};
void require(bool value) {
  if (!value)
    throw InvalidState{};
}
struct Reader {
  vm::CellSlice slice;
  explicit Reader(td::Ref<vm::Cell> cell) : slice(vm::load_cell_slice(cell)) {
    require(cell.not_null() && cell->get_level() == 0);
  }
  td::uint64 u(unsigned bits) {
    require(slice.size() >= bits);
    return slice.fetch_ulong(bits);
  }
  td::int32 i32() {
    require(slice.size() >= 32);
    return static_cast<td::int32>(slice.fetch_long(32));
  }
  td::Bits256 hash() {
    td::Bits256 value;
    require(slice.fetch_bits_to(value));
    return value;
  }
  td::Ref<vm::Cell> ref() {
    require(slice.size_refs() > 0);
    return slice.fetch_ref();
  }
  void end() {
    require(slice.empty_ext());
  }
};
std::string b64(td::Slice bytes) {
  return td::base64_encode(bytes);
}
std::string hash_b64(const td::Bits256& hash) {
  return b64(hash.as_slice());
}
std::string raw_key(td::Ref<vm::Cell> cell, std::size_t length) {
  std::string bytes(length, '\0');
  std::size_t offset = 0;
  while (offset < length) {
    Reader r(cell);
    auto count = std::min<std::size_t>(127, length - offset);
    require(r.slice.size() == count * 8 && r.slice.size_refs() == (offset + count < length ? 1u : 0u));
    require(r.slice.fetch_bytes(td::MutableSlice(bytes.data() + offset, count)));
    offset += count;
    if (offset < length)
      cell = r.ref();
    r.end();
  }
  return bytes;
}
std::string fee_key(td::Ref<vm::Cell> cell) {
  auto bytes = raw_key(cell, 60);
  require(bytes.substr(0, 12) == std::string("\0\0\0\1\0\0\0\10\0\0\0\3", 12));
  return bytes;
}
td::Bits256 address_hash(Reader& reader) {
  require(reader.u(3) == 4 && reader.u(8) == 0);
  return reader.hash();
}
struct Module {
  td::int32 global;
  td::Bits256 network, rescue;
  td::uint8 policy;
  std::string primary, json;
};
Module module_state(td::Ref<vm::Cell> data) {
  Reader r(data);
  require(r.u(8) == 1);
  Module result;
  result.global = r.i32();
  result.network = r.hash();
  require(r.u(8) == 1);
  result.primary = raw_key(r.ref(), 1312);
  result.rescue = r.hash();
  auto policy = r.u(8);
  r.end();
  require(policy == 1 || policy == 2);
  result.policy = static_cast<td::uint8>(policy);
  td::StringBuilder out;
  out << "{\"kind\":\"quantum_module_v1\",\"global_id\":" << result.global << ",\"network_tag\":\""
      << hash_b64(result.network) << "\",\"primary\":{\"algorithm_id\":1,\"public_key\":\"" << b64(result.primary)
      << "\"},\"rescue\":{\"algorithm_id\":3,\"public_key\":\"" << hash_b64(result.rescue) << "\",\"policy\":\""
      << (policy == 1 ? "ready" : "required") << "\"}}";
  result.json = out.as_cslice().str();
  return result;
}
std::string fee_metadata(td::Ref<vm::Cell> data) {
  Reader r(data);
  require(r.u(8) == 1 && r.u(8) == 1);
  auto tree = r.hash();
  auto epoch = r.u(32);
  require(r.u(32) == 3600 && r.u(16) == 4);
  auto key = fee_key(r.ref());
  r.end();
  td::StringBuilder out;
  out << "{\"schema_version\":1,\"profile\":\"hss-lms-sha256-h20-lmots-sha256-w4\",\"algorithm_id\":4,\"fee_tree_id\":"
         "\""
      << hash_b64(tree) << "\",\"epoch0\":" << epoch
      << ",\"epoch_seconds\":3600,\"opening_horizon\":4,\"public_key\":\"" << b64(key) << "\"}";
  return out.as_cslice().str();
}
const RegistryEntry* find_family(td::Slice family) {
  for (const auto& entry : registry())
    if (entry.family == family)
      return &entry;
  return nullptr;
}
}  // namespace
const std::vector<RegistryEntry>& registry() {
  static auto entries = [] {
    std::vector<RegistryEntry> values;
    for (const auto& raw : kRegistryCode) {
      auto bytes = td::base64_decode(td::Slice(raw.boc));
      CHECK(bytes.is_ok());
      auto cell = vm::std_boc_deserialize(bytes.ok());
      CHECK(cell.is_ok());
      values.push_back({raw.family, cell.move_as_ok()});
    }
    return values;
  }();
  return entries;
}
const char* registry_revision() {
  return kRegistryRevision;
}
td::Bits256 registry_network_tag() {
  auto value = td::hex_decode(kQuantumNetwork);
  CHECK(value.is_ok() && value.ok().size() == 32);
  td::Bits256 result;
  result.as_slice().copy_from(value.ok());
  return result;
}
td::Result<PublicState> decode_public_state(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data,
                                            std::optional<td::int32> observation_global_id) {
  try {
    TRY_STATUS(inspect_cells(code, data));
    PublicState result;
    if (code.is_null())
      return result;
    for (const auto& entry : registry())
      if (entry.code->get_hash() == code->get_hash()) {
        result.family = entry.family;
        break;
      }
    if (result.family.empty())
      return result;
    require(data.not_null());
    Reader r(data);
    td::StringBuilder out;
    if (result.family == "pq_highload_mldsa44_v1") {
      auto key_cell = r.ref();
      auto subwallet = r.u(32);
      for (unsigned i = 0; i < 2; ++i) {
        auto root = r.u(1) ? r.ref() : td::Ref<vm::Cell>{};
        vm::Dictionary dict(root, 13);
        require(dict.check_for_each([](td::Ref<vm::CellSlice> value, td::ConstBitPtr, int bits) {
          if (bits != 13 || value->size() || value->size_refs() != 1)
            return false;
          auto row = vm::load_cell_slice(value->prefetch_ref());
          return row.size() == 1023 && row.size_refs() == 0;
        }));
      }
      auto clean = r.u(64);
      auto timeout = r.u(22);
      r.end();
      auto key = pq::unpack_pq_bytes(key_cell, 1312);
      require(key.is_ok() && key.ok().size() == 1312);
      auto id = pq::derive_key_id(pq::PQAlgorithmId::mldsa44, std::string_view(key.ok().data(), key.ok().size()));
      require(id.has_value());
      out << "{\"kind\":\"" << result.family << "\",\"algorithm_id\":1,\"public_key\":\"" << b64(key.ok().as_slice())
          << "\",\"consensus_key_id\":\"" << b64(td::Slice(reinterpret_cast<const char*>(id->data()), id->size()))
          << "\",\"subwallet_id\":" << subwallet << ",\"last_clean_time\":\"" << clean
          << "\",\"timeout_seconds\":" << timeout << "}";
      result.wallet_id = static_cast<td::uint32>(subwallet);
      result.account_model = "advanced.wallet.pq_highload";
      result.authorization_version = "auth.pq.highload.mldsa44.v1";
      result.wallet_type = "pq highload mldsa44 v1";
    } else if (result.family == "mldsa44_auth_module_v1" || result.family == "falcon512_padded_auth_module_v1") {
      bool falcon = result.family == "falcon512_padded_auth_module_v1";
      auto global = r.i32();
      if (falcon)
        require(r.u(16) == 1);
      auto key = raw_key(r.ref(), falcon ? 897 : 1312);
      r.end();
      out << "{\"kind\":\"" << result.family << "\",\"algorithm_id\":" << (falcon ? 2 : 1)
          << ",\"global_id\":" << global << ",\"public_key\":\"" << b64(key) << "\"";
      if (falcon)
        out << ",\"profile_version\":1";
      out << "}";
      result.account_model = falcon ? "advanced.auth_module.falcon512_padded" : "advanced.auth_module.mldsa44";
      result.authorization_version = falcon ? "auth.module.falcon512-padded.v1" : "auth.module.mldsa44.v1";
    } else if (result.family == "quantum_self_pay_v1") {
      require(r.u(8) == 1);
      auto seqno = r.u(32);
      auto wallet_id = r.u(32);
      auto retired = r.u(16);
      require((retired & ~td::uint64{2}) == 0);
      auto epoch = r.u(64);
      auto primary_nonce = r.u(64);
      auto rescue_nonce = r.u(64);
      auto authority_cell = r.ref();
      r.end();
      auto authority = module_state(authority_cell);
      require(!observation_global_id || authority.global == *observation_global_id);
      out << "{\"kind\":\"" << result.family << "\",\"seqno\":" << seqno << ",\"wallet_id\":" << wallet_id
          << ",\"retired_flags\":" << retired << ",\"authority_epoch\":\"" << epoch << "\",\"primary_nonce\":\""
          << primary_nonce << "\",\"rescue_nonce\":\"" << rescue_nonce << "\",\"global_id\":" << authority.global
          << ",\"network_tag\":\"" << hash_b64(authority.network) << "\",\"authority_hash\":\""
          << b64(authority_cell->get_hash().as_slice()) << "\",\"primary\":{\"algorithm_id\":1,\"public_key\":\""
          << b64(authority.primary) << "\"},\"rescue\":{\"algorithm_id\":3,\"public_key\":\""
          << hash_b64(authority.rescue) << "\",\"policy\":\"" << (authority.policy == 1 ? "ready" : "required")
          << "\"},\"fee_payment\":\"wallet_balance\"}";
      result.wallet_id = static_cast<td::uint32>(wallet_id);
      result.seqno = static_cast<td::uint32>(seqno);
      result.account_model = "advanced.wallet.quantum_self_pay";
      result.authorization_version = "auth.quantum.self_pay.v1";
      result.wallet_type = "quantum self-pay v1";
    } else if (result.family == "quantum_module_v1") {
      out << module_state(data).json;
      result.account_model = "advanced.auth_module.quantum";
      result.authorization_version = "auth.quantum.module.v1";
    } else if (result.family == "quantum_wallet_v4") {
      require(r.u(1) == 0);
      auto seqno = r.u(32);
      auto wallet_id = r.u(32);
      require(r.hash().is_zero() && r.u(1) == 0);
      Reader auth(r.ref());
      r.end();
      require(auth.u(8) == 4 && auth.u(2) == 2);
      auto retired = auth.u(16);
      auto epoch = auth.u(64);
      auto primary_nonce = auth.u(64);
      auto rescue_nonce = auth.u(64);
      auto witness = auth.ref();
      auto fee = auth.ref();
      auth.end();
      Reader init(witness);
      require(init.u(5) == 6);
      auto module_code = init.ref();
      auto module_data = init.ref();
      init.end();
      const auto* expected = find_family("quantum_module_v1");
      require(expected && expected->code->get_hash() == module_code->get_hash());
      auto module = module_state(module_data);
      require(!observation_global_id || module.global == *observation_global_id);
      require(module.network == registry_network_tag());
      out << "{\"kind\":\"" << result.family << "\",\"seqno\":" << seqno << ",\"wallet_id\":" << wallet_id
          << ",\"auth_mode\":2,\"retired_flags\":" << retired << ",\"authority_epoch\":\"" << epoch
          << "\",\"primary_nonce\":\"" << primary_nonce << "\",\"rescue_nonce\":\"" << rescue_nonce
          << "\",\"legacy_signature_enabled\":false,\"module_state_init_hash\":\""
          << b64(witness->get_hash().as_slice()) << "\",\"module\":" << module.json << ",\"fee\":" << fee_metadata(fee)
          << "}";
      result.wallet_id = static_cast<td::uint32>(wallet_id);
      result.seqno = static_cast<td::uint32>(seqno);
      result.account_model = "advanced.wallet.quantum";
      result.authorization_version = "auth.quantum.wallet.v4";
      result.wallet_type = "quantum wallet candidate v4";
    } else if (result.family == "quantum_fee_vault_v3") {
      require(r.u(8) == 3);
      auto leaf = r.u(32);
      require(leaf <= 1048576);
      auto config = r.hash();
      auto epoch = r.u(32);
      auto module = address_hash(r);
      auto parties = r.hash();
      auto key = fee_key(r.ref());
      auto prefix_cell = r.ref();
      r.end();
      Reader prefix(prefix_cell);
      require(prefix.u(32) == 0x41553252);
      auto global = prefix.i32();
      auto network = prefix.hash();
      auto wallet = address_hash(prefix);
      require(prefix.hash() == module && prefix.u(8) == 2);
      prefix.end();
      vm::CellBuilder binding;
      require(binding.store_long_bool(4, 3) && binding.store_long_bool(0, 8) &&
              binding.store_bits_bool(wallet.cbits(), 256) && binding.store_bits_bool(module.cbits(), 256));
      auto binding_cell = binding.finalize_novm();
      require(binding_cell.not_null() && td::Bits256(binding_cell->get_hash().bits()) == parties);
      out << "{\"kind\":\"" << result.family << "\",\"next_leaf\":" << leaf << ",\"configuration_hash\":\""
          << hash_b64(config) << "\",\"epoch0\":" << epoch
          << ",\"module_address\":\"0:" << td::to_lower(module.to_hex()) << "\",\"pop_parties_hash\":\""
          << hash_b64(parties) << "\",\"fee_public_key\":\"" << b64(key) << "\",\"intent_prefix_hash\":\""
          << b64(prefix_cell->get_hash().as_slice()) << "\",\"global_id\":" << global << ",\"network_tag\":\""
          << hash_b64(network) << "\",\"wallet_address\":\"" << raw_address(0, wallet) << "\",\"auth_mode\":2}";
      result.account_model = "advanced.fee_vault.quantum";
      result.authorization_version = "auth.quantum.fee-vault.v3";
    } else
      return error(Failure::StateInvalid);
    result.json = out.as_cslice().str();
    return result;
  } catch (const InvalidState&) {
    return error(Failure::StateInvalid);
  } catch (vm::VmError&) {
    return error(Failure::StateInvalid);
  } catch (vm::VmVirtError&) {
    return error(Failure::StateInvalid);
  }
}
}  // namespace tos::explorer
