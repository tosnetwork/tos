#pragma once

#include "block/workchain-deposit-admission.h"
#include "block/workchain-unexpected-bucket.h"
#include "block/workchain-proof-work.h"
#include "block/workchain-value-flow.h"
#include <array>

namespace block {
struct WorkchainDepositTransition {
  td::Ref<vm::Cell> account_data, coordinator_data;
  WorkchainDepositReceipt receipt;
  CurrencyCollection custody_balance, coordinator_balance;
  WorkchainInternalTransfer principal_transfer;
};
using WorkchainDepositTransitionResult = std::variant<WorkchainDepositRejection, WorkchainDepositTransition>;

// One immutable preparation result. The enclosing Native allocation settlement
// must install account/coordinator data, import value, and the principal edge
// atomically. No callback or mutable store allows the sequence or money to be
// published before the receipt. D is created and consumed within this result;
// there is no retained Claim, return association, or confidential bucket right.
//
// The message identity/value/declared principal and destination are independently
// obtained from the original authenticated Native inbox message. The domain is
// resolved from the same bound ConfigParam 84 as policy, not supplied by a
// candidate. Both hosts reconstruct this input; candidate effects are not inputs.
inline td::Result<WorkchainDepositTransitionResult> prepare_workchain_deposit_transition(
    const WorkchainDepositPolicy& policy, const std::array<unsigned char, 80>& domain,
    const td::Bits256& coordinator_address, const td::Bits256& custody_address,
    const td::Bits256& asset, const td::Bits256& message,
    const WorkchainConfidentialAddress& destination, std::uint64_t declared_principal,
    const CurrencyCollection& received,
    const td::Result<std::optional<WorkchainConfidentialAccount>>& historical,
    const WorkchainCoordinatorState& coordinator,
    const CurrencyCollection& old_custody, const CurrencyCollection& old_operating,
    WorkchainUnexpectedLimits bucket_limits, int extra_validation_cells,
    WorkchainProofVerifier& verifier) {
  auto local = [](td::Slice reason) { return td::Status::Error(-7201, reason); };
  if (coordinator.layout_version != 3 || !coordinator.deposit_sequence ||
      encode_workchain_coordinator_state(coordinator).is_error() || coordinator_address == custody_address)
    return local("authenticated Deposit coordinator unavailable");
  if (destination.account == coordinator_address || destination.account == custody_address)
    return WorkchainDepositTransitionResult{WorkchainDepositRejection::Identity};
  // Parse the mandatory root, not merely its presence. The bucket is distinct
  // from principal and unchanged on acceptance; it never supplies Deposit value.
  auto bucket = decode_workchain_unexpected_bucket(coordinator.unexpected, bucket_limits, extra_validation_cells);
  if (bucket.is_error()) return local("authenticated unexpected bucket unavailable");
  if (received.extra.not_null())
    return WorkchainDepositTransitionResult{WorkchainDepositRejection::ExtraCurrencies};
  TRY_RESULT(decision, admit_workchain_deposit(policy, message, destination, asset, custody_address,
      declared_principal, received.tomis, *coordinator.deposit_sequence, historical));
  if (const auto* rejected = std::get_if<WorkchainDepositRejection>(&decision))
    return WorkchainDepositTransitionResult{*rejected};
  const auto& admitted = std::get<WorkchainDepositAdmission>(decision);
  // A successful decision establishes authenticated presence and registration.
  const auto& old_account = *historical.ok();
  UnoCryptoSystemEncryptionRequest request{};
  request.abi_version = UNO_CRYPTO_ABI_VERSION;
  std::copy(domain.begin(), domain.end(), request.domain);
  std::copy(admitted.id.as_slice().begin(), admitted.id.as_slice().end(), request.deposit_id);
  std::copy(old_account.public_key.as_slice().begin(), old_account.public_key.as_slice().end(), request.recipient);
  request.amount = admitted.amount;  // The SAME x funds custody and encryption.
  // The metering entry predates this call site. Both hosts use this deterministic
  // reconstruction (7 profile-4 units); settlement compares the rebuilt effects
  // against the block. No candidate ciphertext/usage shortcut is accepted here.
  TRY_RESULT(ciphertext, verifier.system_encrypt(request));
  WorkchainCiphertext encrypted;
  encrypted.commitment.as_slice().copy_from(td::Slice(ciphertext.commitment, 32));
  encrypted.handle.as_slice().copy_from(td::Slice(ciphertext.handle, 32));
  WorkchainDepositReceipt receipt{admitted.id, message, admitted.next_sequence, admitted.amount,
      old_account.address.instance, old_account.key_epoch, asset, encrypted, 0};
  auto next_account = old_account;
  next_account.system_pending.push_back(receipt);
  auto next_coordinator = coordinator;
  next_coordinator.deposit_sequence = admitted.next_sequence;
  TRY_RESULT(account_data, encode_workchain_confidential_account(next_account));
  TRY_RESULT(coordinator_data, encode_workchain_coordinator_state(next_coordinator));
  CurrencyCollection principal(td::make_refint(admitted.amount)), fee(td::make_refint(admitted.operating_fee));
  CurrencyCollection custody_balance, operating_balance;
  if (!old_custody.is_valid() || !old_operating.is_valid() ||
      !old_custody.validate_extra(extra_validation_cells) || !old_operating.validate_extra(extra_validation_cells) ||
      !CurrencyCollection::add(old_custody, principal, custody_balance) ||
      !CurrencyCollection::add(old_operating, fee, operating_balance) ||
      !custody_balance.tomis->unsigned_fits_bits(256) || !operating_balance.tomis->unsigned_fits_bits(256))
    return local("Deposit Native balance arithmetic failed");
  WorkchainInternalTransfer transfer{coordinator_address, custody_address, principal};
  std::vector<WorkchainAccountValueFlow> rows{
      {coordinator_address, old_operating, received, operating_balance, CurrencyCollection(0), CurrencyCollection(0)},
      {custody_address, old_custody, CurrencyCollection(0), custody_balance, CurrencyCollection(0), CurrencyCollection(0)}};
  std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) { return a.account < b.account; });
  if (verify_workchain_value_flow(rows, {transfer}, 2, 1, extra_validation_cells).is_error())
    return local("Deposit principal and operating allocation do not conserve value");
  return WorkchainDepositTransitionResult{WorkchainDepositTransition{
      account_data, coordinator_data, receipt, custody_balance, operating_balance, transfer}};
}
}  // namespace block
