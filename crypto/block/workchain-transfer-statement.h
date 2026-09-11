#pragma once
#include "block/workchain-confidential-input.h"

namespace block {

using WorkchainSelectedReceipt = std::variant<WorkchainPendingReceipt, WorkchainDepositReceipt>;

// Canonical commitment encoding only. No state acquisition, receipt selection,
// authentication or verdict is performed here. Each host independently supplies
// exactly the old public fields and the selected COMPLETE authenticated receipts.
struct WorkchainTransferOldStatement {
  td::Bits256 public_key;
  WorkchainCiphertext available;
  std::uint32_t key_epoch;
  std::uint64_t auth_nonce, available_revision;
  td::Bits256 destination_public_key;
  std::uint32_t destination_key_epoch;
  std::vector<WorkchainSelectedReceipt> selected;
};

inline td::Result<td::Bits256> hash_workchain_transfer_old_statement(
    unsigned kind, const WorkchainTransferOldStatement& value) {
  if ((kind != 1 && kind != 2) || value.selected.size() > 16 ||
      (kind == 1 && !value.selected.empty())) {
    return confidential_input_detail::invalid("invalid old statement shape");
  }
  // UMS1 root: domain tag:uint32, kind:uint8, selected_count:uint8,
  // source:^Cell, relation_state:^Cell. Cell representation hash, not BOC hash.
  // source: P,C,D (256 bits each), epoch:uint32, nonce/revision:uint64.
  auto source = vm::CellBuilder().store_bits(value.public_key.bits(),256)
      .store_bits(value.available.commitment.bits(),256).store_bits(value.available.handle.bits(),256)
      .store_long(value.key_epoch,32).store_long(value.auth_nonce,64)
      .store_long(value.available_revision,64).finalize();
  td::Ref<vm::Cell> relation_state;
  if (kind == 1) {
    // SEND commits the recipient key/epoch, not unrelated recipient receipts.
    relation_state = vm::CellBuilder().store_bits(value.destination_public_key.bits(),256)
        .store_long(value.destination_key_epoch,32).finalize();
  } else {
    // COLLECT: selected receipt order is preserved, NOT sorted/deduplicated by
    // the host. Each cons cell has two refs: complete receipt, then tail; the
    // terminator is an empty ordinary cell. Kernel checks selected-ID ordering.
    relation_state = vm::CellBuilder().finalize();
    for (auto it=value.selected.rbegin(); it!=value.selected.rend(); ++it) {
      // Retain the exact original constructor: system origin is message/sequence,
      // never a fabricated SEND nonce. Existing SEND-only commitments keep their
      // bytes. Mixed selections retain the kernel's selected-ID order.
      auto encoded = std::visit([](const auto& receipt) -> td::Result<td::Ref<vm::Cell>> {
        if constexpr (std::is_same_v<std::decay_t<decltype(receipt)>, WorkchainPendingReceipt>)
          return encode_workchain_pending_receipt(receipt);
        else
          return encode_workchain_deposit_receipt(receipt);
      }, *it);
      TRY_RESULT(receipt, std::move(encoded));
      relation_state = vm::CellBuilder().store_ref(receipt).store_ref(relation_state).finalize();
    }
  }
  auto root = vm::CellBuilder().store_long(0x554d5331,32).store_long(kind,8)
      .store_long(value.selected.size(),8).store_ref(source).store_ref(relation_state).finalize();
  return td::Bits256(root->get_hash().bits());
}
}  // namespace block
