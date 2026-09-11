#pragma once
#include "block/workchain-withdrawal-codec.h"

namespace block {
struct WorkchainDepositOrigin { td::Bits256 inbound_message; std::uint64_t sequence; };
struct WorkchainSettlementOrigin { td::Bits256 attempt_id; std::uint64_t sequence; };
struct WorkchainSweepOrigin {
  std::uint64_t sequence;
  gen::UnoV2SweepAttributionV1::Record attribution;
};
using WorkchainSystemOrigin = std::variant<WorkchainDepositOrigin, WorkchainSettlementOrigin, WorkchainSweepOrigin>;
// This is a required nonzero scalar, not evidence of a successful authenticated
// increment. All three sources share the host's deposit_sequence transaction.
inline std::uint64_t workchain_system_origin_sequence(const WorkchainSystemOrigin& origin) {
  return std::visit([](const auto& value) { return value.sequence; }, origin);
}
inline td::Result<td::Ref<vm::Cell>> encode_workchain_system_origin(const WorkchainSystemOrigin& origin) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<td::Ref<vm::Cell>> {
    if (workchain_system_origin_sequence(origin) == 0)
      return td::Status::Error("system origin requires issued sequence");
    using withdrawal_codec_detail::pack;
    using T = gen::UnoV2SystemOriginV1;
    if (const auto* value = std::get_if<WorkchainDepositOrigin>(&origin))
      return pack(T::Record_uno_v2_system_origin_deposit_v1{value->inbound_message, value->sequence});
    if (const auto* value = std::get_if<WorkchainSettlementOrigin>(&origin))
      return pack(T::Record_uno_v2_system_origin_settlement_v1{value->attempt_id, value->sequence});
    const auto& value = std::get<WorkchainSweepOrigin>(origin);
    TRY_RESULT(attribution, pack(value.attribution));
    return pack(T::Record_uno_v2_system_origin_sweep_v1{value.sequence, attribution});
  });
}
inline td::Result<WorkchainSystemOrigin> decode_workchain_system_origin(const td::Ref<vm::Cell>& root) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<WorkchainSystemOrigin> {
    if (root.is_null()) return td::Status::Error("missing system origin");
    bool special = false;
    auto slice = vm::load_cell_slice_special(root, special);
    if (special || slice.size() < 8) return td::Status::Error("malformed system origin");
    using withdrawal_codec_detail::unpack;
    using T = gen::UnoV2SystemOriginV1;
    WorkchainSystemOrigin result;
    switch (slice.prefetch_ulong(8)) {
      case 0: {
        TRY_RESULT(value, unpack<T::Record_uno_v2_system_origin_deposit_v1>(root));
        result = WorkchainDepositOrigin{value.inbound_message, value.sequence}; break;
      }
      case 1: {
        TRY_RESULT(value, unpack<T::Record_uno_v2_system_origin_settlement_v1>(root));
        result = WorkchainSettlementOrigin{value.attempt_id, value.sequence}; break;
      }
      case 2: {
        TRY_RESULT(value, unpack<T::Record_uno_v2_system_origin_sweep_v1>(root));
        TRY_RESULT(attribution, unpack<gen::UnoV2SweepAttributionV1::Record>(value.attribution));
        result = WorkchainSweepOrigin{value.sequence, attribution}; break;
      }
      default: return td::Status::Error("unknown system origin kind");
    }
    TRY_RESULT(canonical, encode_workchain_system_origin(result));
    if (canonical->get_hash() != root->get_hash()) return td::Status::Error("noncanonical system origin");
    return result;
  });
}
inline td::Result<td::Bits256> derive_workchain_system_receipt_id(const WorkchainSystemOrigin& origin) {
  if (const auto* deposit = std::get_if<WorkchainDepositOrigin>(&origin))
    return derive_workchain_deposit_id(deposit->inbound_message, deposit->sequence);
  TRY_RESULT(root, encode_workchain_system_origin(origin));
  return td::Bits256(root->get_hash().bits());
}
// Exact canonical origin bytes for the new transcript members. Cell data bits
// precede referenced attribution data bits; the sole trailing Bool is padded
// with zero low bits. References and BoC transport metadata are not absorbed.
// Deposit uses its unchanged D33 transcript, not this new member payload.
inline td::Result<std::string> encode_workchain_system_origin_transcript(const WorkchainSystemOrigin& origin) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<std::string> {
    TRY_RESULT(root, encode_workchain_system_origin(origin));
    std::string result;
    auto append = [&](const td::Ref<vm::Cell>& cell) {
      bool special = false;
      auto slice = vm::load_cell_slice_special(cell, special);
      if (special) return false;
      auto bits = slice.size();
      std::string part((bits + 7) / 8, '\0');
      td::BitPtr(reinterpret_cast<unsigned char*>(part.data())).copy_from(slice.data_bits(), bits);
      result += part;
      return true;
    };
    if (!append(root)) return td::Status::Error("special system origin");
    if (std::holds_alternative<WorkchainSweepOrigin>(origin)) {
      bool special = false;
      auto slice = vm::load_cell_slice_special(root, special);
      if (!append(slice.prefetch_ref())) return td::Status::Error("special sweep attribution");
    }
    return result;
  });
}
struct WorkchainSystemReceipt {
  td::Bits256 receipt_id;
  std::uint64_t amount;
  gen::UnoV2PendingTarget::Record target;
  WorkchainCiphertext ciphertext;
  WorkchainSystemOrigin origin;
};
inline td::Result<td::Ref<vm::Cell>> encode_workchain_system_receipt(const WorkchainSystemReceipt& value) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<td::Ref<vm::Cell>> {
    using withdrawal_codec_detail::pack;
    TRY_RESULT(id, derive_workchain_system_receipt_id(value.origin));
    if (id != value.receipt_id) return td::Status::Error("system receipt identity mismatch");
    if (!value.amount || !confidential_state_detail::canonical_ciphertext(value.ciphertext) ||
        value.ciphertext.handle == td::Bits256::zero()) return td::Status::Error("invalid system ciphertext or amount");
    TRY_RESULT(origin, encode_workchain_system_origin(value.origin));
    TRY_RESULT(target, pack(value.target)); TRY_RESULT(ciphertext, pack(value.ciphertext));
    return pack(gen::UnoV2PendingReceipt::Record_uno_v2_system_pending_origin_v1{
        value.receipt_id, value.amount, 0, target, ciphertext, origin});
  });
}
inline td::Result<WorkchainSystemReceipt> decode_workchain_system_receipt(const td::Ref<vm::Cell>& root) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<WorkchainSystemReceipt> {
    using withdrawal_codec_detail::unpack;
    TRY_RESULT(wire, unpack<gen::UnoV2PendingReceipt::Record_uno_v2_system_pending_origin_v1>(root));
    TRY_RESULT(origin, decode_workchain_system_origin(wire.origin));
    TRY_RESULT(target, unpack<gen::UnoV2PendingTarget::Record>(wire.target));
    TRY_RESULT(ciphertext, unpack<WorkchainCiphertext>(wire.ciphertext));
    WorkchainSystemReceipt value{wire.receipt_id, wire.amount, target, ciphertext, origin};
    TRY_RESULT(canonical, encode_workchain_system_receipt(value));
    if (canonical->get_hash() != root->get_hash()) return td::Status::Error("noncanonical system receipt");
    return value;
  });
}
}  // namespace block
