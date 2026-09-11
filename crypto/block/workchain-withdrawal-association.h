#pragma once

#include "block/workchain-withdrawal-codec.h"
#include <optional>

namespace block {

struct WorkchainWithdrawalAssociation {
  td::Bits256 inbound_message, withdrawal_id, attempt_id;
  std::uint64_t payout_created_lt;
  CurrencyCollection received;
  td::Ref<vm::Cell> original_body;
};

// Read-only association, not Native authentication or settlement. The enclosing
// host must authenticate the final-import Message and acquire the account's
// control envelope from its admitted predecessor before calling this function.
// No W/P release, receipt issuance, counter advance or timeout scan occurs here.
// Unmatched authenticated input proceeds to the separate late-return/disposal
// dispatch. Codec/acquisition errors remain neutral for source-aware handling.
inline td::Result<std::optional<WorkchainWithdrawalAssociation>> associate_workchain_withdrawal_return(
    const td::Ref<vm::Cell>& message_root, std::int32_t custody_workchain,
    const td::Bits256& custody_address, const gen::UnoV2OperationNetworkV1::Record& network,
    const WorkchainWithdrawalControl& authenticated_control) {
  return withdrawal_codec_detail::protect([&]()
      -> td::Result<std::optional<WorkchainWithdrawalAssociation>> {
    using withdrawal_codec_detail::unpack;
    using withdrawal_codec_detail::error;
    gen::Message::Record message;
    if (message_root.is_null() || !tlb::type_unpack_cell(message_root, gen::t_Message_Any, message))
      return error("malformed withdrawal record");
    gen::CommonMsgInfo::Record_int_msg_info info;
    if (!tlb::csr_unpack(message.info, info)) return error("return is not an internal Message");
    tos::WorkchainId destination_wc, source_wc;
    td::Bits256 destination, source;
    if (!tlb::t_MsgAddressInt.extract_std_address(info.dest, destination_wc, destination) ||
        !tlb::t_MsgAddressInt.extract_std_address(info.src, source_wc, source))
      return error("return address is not standard");
    if (!info.bounced || destination_wc != custody_workchain || destination != custody_address)
      return std::optional<WorkchainWithdrawalAssociation>{};
    auto body = *message.body;
    if (!body.have(1)) return error("return body selector is missing");
    td::Ref<vm::Cell> body_root;
    if (body.fetch_ulong(1) == 0) body_root = vm::CellBuilder().append_cellslice(body).finalize();
    else {
      if (body.size_ext() != 0x10000) return error("return body reference framing mismatch");
      body_root = body.fetch_ref();
    }
    // Legacy or unrelated bodies cannot release an open obligation.
    bool special = false;
    auto body_header = vm::load_cell_slice_special(body_root, special);
    if (special) return error("special return body");
    if (!body_header.have(32) || body_header.prefetch_ulong(32) != 0xfffffffeU)
      return std::optional<WorkchainWithdrawalAssociation>{};
    TRY_RESULT(rich, unpack<gen::NewBounceBody::Record>(body_root));
    TRY_RESULT(original, unpack<gen::NewBounceOriginalInfo::Record>(rich.original_info));
    const WorkchainWithdrawalRecord* matched = nullptr;
    for (const auto& record : authenticated_control.withdrawals) {
      if (record.timing.payout_created_lt != original.created_lt) continue;
      if (matched) return error("ambiguous Withdrawal payout created_lt");
      matched = &record;
    }
    if (!matched) return std::optional<WorkchainWithdrawalAssociation>{};
    TRY_RESULT(id, derive_workchain_withdrawal_id(network, matched->source, matched->consumed_auth_nonce));
    TRY_RESULT(attempt, derive_workchain_attempt_id(id));
    if (id != matched->withdrawal_id || attempt != matched->attempt_id)
      return error("authenticated Withdrawal identity does not recompute");
    if (source_wc != matched->destination.workchain || source != matched->destination.account)
      return error("matched return source differs from payout destination");
    CurrencyCollection original_value, received;
    if (!original_value.unpack(original.value) || !received.unpack(info.value))
      return error("invalid return value encoding");
    if (original_value != CurrencyCollection(td::make_refint(matched->principal)))
      return error("matched return original value differs from payout principal");
    return std::optional<WorkchainWithdrawalAssociation>{WorkchainWithdrawalAssociation{
        td::Bits256(message_root->get_hash().bits()), id, attempt, original.created_lt,
        received, rich.original_body}};
  });
}

}  // namespace block
