#pragma once

#include <optional>
#include "uno/core/accounting.h"
#include "uno/core/crypto-verifier.h"
#include "uno/core/note-state.h"

namespace uno_workchain {

// Evidence of complete bundle crypto and the transfer public-value equation,
// not of canonical envelope authorization, expiry or fee-policy admission.
// The envelope layer must derive this digest from all authenticated fields.
// Own the verified bytes so later caller mutation cannot change applied effects
// or discard the proof/signature material needed by the block data archive.
class CryptoVerifiedTransfer {
 public:
  static td::Result<std::optional<CryptoVerifiedTransfer>> verify(const CryptoBundle& bundle, const Amount& fee,
      const std::array<td::uint8, 32>& sighash, CryptoLimits limits) {
    TRY_RESULT(valid, verify_crypto_bundle(bundle, BundleContext::Transfer, Amount{}, fee, sighash, limits));
    if (!valid) return std::optional<CryptoVerifiedTransfer>{};
    return std::optional<CryptoVerifiedTransfer>{CryptoVerifiedTransfer(bundle, fee, sighash)};
  }
  const CryptoBundle& bundle() const { return bundle_; }
  const Amount& fee() const { return fee_; }
  const std::array<td::uint8, 32>& sighash() const { return sighash_; }

 private:
  CryptoVerifiedTransfer(CryptoBundle bundle, Amount fee, std::array<td::uint8, 32> sighash)
      : bundle_(std::move(bundle)), fee_(fee), sighash_(sighash) {}
  CryptoBundle bundle_;
  Amount fee_;
  std::array<td::uint8, 32> sighash_;
};

// Unactivated private-transfer state component. This does not implement system
// transitions, Reserve accounting, wire admission or host engine registration.
// The outer engine must authenticate the entire state and its resource policy.
class PrivateTransferState {
 public:
  static td::Result<PrivateTransferState> assemble(NoteState notes, Accounting accounting) {
    // The aggregate must fit the selected wide accounting range as well as each
    // component. This is not a global monetary authority or a supply proof.
    TRY_RESULT(total, accounting.notes.checked_add(accounting.fees));
    TRY_STATUS(total.checked_add(accounting.withdrawals));
    return PrivateTransferState(std::move(notes), accounting);
  }
  const NoteState& notes() const { return notes_; }
  const Accounting& accounting() const { return accounting_; }

  td::Result<PrivateTransferState> apply_block(std::uint64_t height,
      const std::vector<CryptoVerifiedTransfer>& transfers, NoteState::Limits limits) const {
    if (transfers.size() > limits.bundles) return td::Status::Error("UNO transfer block bundle limit exceeded");
    std::size_t total = 0;
    for (const auto& transfer : transfers) {
      const auto count = transfer.bundle().actions.size();
      if (count > limits.actions_per_bundle || count > limits.total_actions - total) {
        return td::Status::Error("UNO transfer block action limit exceeded");
      }
      total += count;
    }
    auto accounting = accounting_;
    std::vector<NoteState::SpendEffects> effects;
    effects.reserve(transfers.size());
    for (const auto& transfer : transfers) {
      TRY_RESULT(updated, accounting.checked_transfer_fee(transfer.fee()));
      accounting = updated;
      NoteState::SpendEffects effect{transfer.bundle().anchor, {}};
      effect.actions.reserve(transfer.bundle().actions.size());
      for (const auto& action : transfer.bundle().actions) {
        NoteState::Action output;
        std::copy(std::begin(action.nullifier), std::end(action.nullifier), output.nullifier.as_slice().ubegin());
        std::copy(std::begin(action.cmx), std::end(action.cmx), output.commitment.begin());
        effect.actions.push_back(output);
      }
      effects.push_back(std::move(effect));
    }
    TRY_RESULT(notes, notes_.apply_spend_effects(height, effects, limits));
    return assemble(std::move(notes), accounting);
  }

  td::Result<td::Ref<vm::Cell>> to_cell() const try {
    TRY_RESULT(notes, notes_.to_cell());
    vm::CellBuilder root;
    root.store_long(0x55505430, 32);
    for (const auto& amount : {accounting_.notes, accounting_.fees, accounting_.withdrawals}) {
      root.store_long(amount.high(), 64).store_long(amount.low(), 64);
    }
    return root.store_ref(notes).finalize();
  } catch (vm::VmError&) {
    return td::Status::Error("UNO transfer state encoding failed");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO transfer state encoding encountered incomplete proof");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO transfer state encoding exhausted execution budget");
  }

  static td::Result<PrivateTransferState> from_cell(const td::Ref<vm::Cell>& cell, std::uint32_t window,
      std::uint32_t window_limit, NullifierState::LoadLimits limits) try {
    if (cell.is_null()) return td::Status::Error("UNO missing transfer state");
    bool special = false;
    auto root = vm::load_cell_slice_special(cell, special);
    if (special || root.size() != 416 || root.size_refs() != 1 || root.fetch_ulong(32) != 0x55505430) {
      return td::Status::Error("UNO invalid transfer state header");
    }
    Amount amounts[3];
    for (auto& amount : amounts) {
      auto high = root.fetch_ulong(64);
      auto low = root.fetch_ulong(64);
      amount = Amount::from_words(high, low);
    }
    TRY_RESULT(notes, NoteState::from_cell(root.fetch_ref(), window, window_limit, limits));
    return assemble(std::move(notes), {amounts[0], amounts[1], amounts[2]});
  } catch (vm::VmError&) {
    return td::Status::Error("UNO malformed transfer state cells");
  } catch (vm::VmVirtError&) {
    return td::Status::Error("UNO incomplete transfer state cells");
  } catch (vm::VmNoGas&) {
    return td::Status::Error("UNO transfer state loading exhausted execution budget");
  }

 private:
  PrivateTransferState(NoteState notes, Accounting accounting) : notes_(std::move(notes)), accounting_(accounting) {}
  NoteState notes_;
  Accounting accounting_;
};

}  // namespace uno_workchain
