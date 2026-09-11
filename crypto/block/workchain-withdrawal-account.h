#pragma once
#include "block/workchain-system-origin.h"
namespace block {
// Three typed views of ONE authenticated pending dictionary. The two system
// views share a combined capacity of four, not four each. Legacy receipts keep
// their original encoding and D33 derivation. No automatic migration occurs.
struct WorkchainWithdrawalAccount {
  WorkchainConfidentialAccount account;
  WorkchainWithdrawalControl control;
  std::vector<WorkchainSystemReceipt> origin_pending;
};
inline td::Result<td::Ref<vm::Cell>> encode_workchain_withdrawal_account(
    const WorkchainWithdrawalAccount& value, std::uint32_t authenticated_limit) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<td::Ref<vm::Cell>> {
    using withdrawal_codec_detail::pack;
    const auto& account = value.account;
    if (account.schema_version != 3 || account.system_pending.size() + value.origin_pending.size() > 4)
      return td::Status::Error("invalid Withdrawal account schema or system capacity");
    TRY_RESULT(lifecycle, encode_workchain_account_lifecycle(account.lifecycle));
    TRY_RESULT(control_lifecycle, encode_workchain_account_lifecycle(value.control.lifecycle));
    if (lifecycle->get_hash() != control_lifecycle->get_hash())
      return td::Status::Error("Withdrawal control lifecycle mismatch");
    TRY_RESULT(control, encode_workchain_withdrawal_control(value.control, authenticated_limit));
    // Reuse the existing component validators on a local projection. This cell
    // is never installed or accepted as a migrated input; the new root below
    // carries the explicit version and complete control/pending state.
    auto projection = account; projection.schema_version = 2;
    TRY_RESULT(core, encode_workchain_confidential_account(projection));
    TRY_RESULT(wire, withdrawal_codec_detail::unpack<gen::UnoV2AccountStateDeposits::Record>(core));
    vm::Dictionary pending(wire.pending, 256);
    for (const auto& receipt : value.origin_pending) {
      if (receipt.target.instance != account.address.instance || receipt.target.asset != account.bindings.asset)
        return td::Status::Error("system pending target binding mismatch");
      TRY_RESULT(root, encode_workchain_system_receipt(receipt));
      if (!pending.set_ref(receipt.receipt_id, root, vm::Dictionary::SetMode::Add))
        return td::Status::Error("duplicate pending dictionary key");
    }
    for (const auto& record : value.control.withdrawals) {
      if (record.source.workchain_id != account.address.workchain_id || record.source.account != account.address.account ||
          record.source.instance != account.address.instance)
        return td::Status::Error("Withdrawal record account binding mismatch");
    }
    return pack(gen::UnoV2AccountStateWithdrawals::Record{3, wire.relation_profile, wire.proof_profile,
        wire.auth_nonce, wire.available_revision, wire.pending_count,
        static_cast<unsigned>(account.system_pending.size() + value.origin_pending.size()),
        wire.identity, wire.crypto, std::move(pending).extract_root(), control});
  });
}
inline td::Result<WorkchainWithdrawalAccount> decode_workchain_withdrawal_account(
    const td::Ref<vm::Cell>& root, std::uint32_t authenticated_limit) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<WorkchainWithdrawalAccount> {
    using withdrawal_codec_detail::pack;
    TRY_RESULT(wire, withdrawal_codec_detail::unpack<gen::UnoV2AccountStateWithdrawals::Record>(root));
    if (wire.schema_version != 3) return td::Status::Error("unsupported Withdrawal account schema");
    TRY_RESULT(control, decode_workchain_withdrawal_control(wire.control, authenticated_limit));
    vm::Dictionary pending(wire.pending, 256), legacy(256);
    std::vector<WorkchainSystemReceipt> origins;
    unsigned total = 0;
    td::Status error = td::Status::OK();
    if (!pending.check_for_each([&](td::Ref<vm::CellSlice> leaf, td::ConstBitPtr key, int width) {
          if (width != 256 || leaf->size_ext() != 0x10000 || ++total > 20) return false;
          auto entry = leaf->prefetch_ref();
          bool special = false;
          auto slice = vm::load_cell_slice_special(entry, special);
          if (special || slice.size() < 32) return false;
          if (gen::t_UnoV2PendingReceipt.get_tag(slice) == gen::UnoV2PendingReceipt::uno_v2_system_pending_origin_v1) {
            if (origins.size() >= 4) return false;
            auto decoded = decode_workchain_system_receipt(entry);
            if (decoded.is_error()) { error = decoded.move_as_error(); return false; }
            if (decoded.ok().receipt_id != td::Bits256(key)) return false;
            origins.push_back(decoded.move_as_ok()); return true;
          }
          return legacy.set_ref(key, 256, entry, vm::Dictionary::SetMode::Add);
        })) {
      if (error.is_error()) return std::move(error);
      return td::Status::Error("invalid Withdrawal account pending dictionary");
    }
    if (origins.size() > wire.system_pending_count)
      return td::Status::Error("system pending count mismatch");
    TRY_RESULT(lifecycle, encode_workchain_account_lifecycle(control.lifecycle));
    TRY_RESULT(core, pack(gen::UnoV2AccountStateDeposits::Record{2, wire.relation_profile, wire.proof_profile,
        wire.auth_nonce, wire.available_revision, wire.pending_count,
        wire.system_pending_count - static_cast<unsigned>(origins.size()), wire.identity, wire.crypto,
        std::move(legacy).extract_root(), lifecycle}));
    TRY_RESULT(account, decode_workchain_confidential_account(core));
    account.schema_version = 3;
    WorkchainWithdrawalAccount value{account, control, origins};
    TRY_RESULT(canonical, encode_workchain_withdrawal_account(value, authenticated_limit));
    if (canonical->get_hash() != root->get_hash()) return td::Status::Error("noncanonical Withdrawal account");
    return value;
  });
}
}  // namespace block
