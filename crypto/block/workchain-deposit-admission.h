#pragma once

#include "block/workchain-confidential-state.h"
#include "block/workchain-coordinator-state.h"
#include <optional>

namespace block {

// Resolved from authenticated ConfigParam 84, never from local defaults.
// D8/D19 freeze the genesis values (1e9 and 3e6 nanotomi), not immutable
// prices: governance may change them. D19's slot price is a conservative
// choice, not a dimensional derivation. SEND already includes its slot price
// in the proof-bound fee (D25); Deposit pays it separately in Native value.
struct WorkchainDepositPolicy {
  std::uint64_t minimum, maximum, slot_fee;
  std::uint32_t user_slots, system_slots;
};

enum class WorkchainDepositRejection {
  Unregistered, Identity, Lifecycle, Amount, SlotFee, Capacity, Duplicate, SequenceExhausted, ExtraCurrencies
};
struct WorkchainDepositAdmission {
  td::Bits256 id;
  std::uint64_t next_sequence, amount, operating_fee;
};
using WorkchainDepositDecision = std::variant<WorkchainDepositRejection, WorkchainDepositAdmission>;

// This is a read-only decision, NOT a transaction commit. The caller must
// authenticate the unique original Native Message and target historical leaf.
// Verified absence is nullopt; failure to obtain that leaf is Error. Rejection
// is a normal result routed to deterministic Native disposal, not a block
// error. A candidate which disagrees with this decision is CandidateInvalid.
// Local acquisition/configuration failure must never select a disposal branch.
inline td::Result<WorkchainDepositDecision> admit_workchain_deposit(
    const WorkchainDepositPolicy& policy, const td::Bits256& message,
    const WorkchainConfidentialAddress& destination, const td::Bits256& asset,
    const td::Bits256& custody, std::uint64_t declared_principal, const td::RefInt256& imported_tomis,
    std::uint64_t sequence,
    const td::Result<std::optional<WorkchainConfidentialAccount>>& historical) {
  auto local = [](td::Slice reason) {
    return td::Status::Error(-7201, reason);
  };
  auto reject = [](WorkchainDepositRejection reason) -> WorkchainDepositDecision { return reason; };
  if (!policy.minimum || policy.minimum > policy.maximum || policy.maximum > ((std::uint64_t{1} << 62) - 1) ||
      policy.slot_fee < 1000000 || policy.slot_fee > policy.minimum / 100 ||
      !policy.user_slots || policy.user_slots > 16 || !policy.system_slots || policy.system_slots > 4)
    return local("unsupported authenticated Deposit policy");
  if (historical.is_error()) return local("authenticated Deposit target unavailable");
  if (!historical.ok()) return reject(WorkchainDepositRejection::Unregistered);
  const auto& account = *historical.ok();
  if (encode_workchain_confidential_account(account).is_error())
    return local("malformed authenticated Deposit target");
  if (account.address.workchain_id != destination.workchain_id || account.address.account != destination.account ||
      account.address.instance != destination.instance || account.bindings.asset != asset || account.bindings.custody != custody)
    return reject(WorkchainDepositRejection::Identity);
  if (!std::holds_alternative<WorkchainAccountActive>(account.lifecycle))
    return reject(WorkchainDepositRejection::Lifecycle);
  if (account.schema_version != 2) return local("authenticated account schema cannot store system receipts");
  if (imported_tomis.is_null() || !imported_tomis->is_valid() || td::sgn(imported_tomis) < 0)
    return local("invalid authenticated Native message value");
  // Principal is explicit in the authenticated message body. Subtracting the
  // current tariff from the message total would silently change the intended
  // principal after a governance price change while the message is in transit.
  // Exact payment rejects both shortfall and excess; neither is reassigned.
  // A tariff change between sending and admission therefore selects rejection/
  // bounce. Frequent repricing can make a sender repeatedly pay Native bounce
  // costs; this is an operating tradeoff, not a delivery or price-lock guarantee.
  // V_min/V_max constrain principal, NOT the message total. The smallest valid
  // payment is V_min + slot_fee. The fee never enters custody R or N_book.
  if (declared_principal < policy.minimum || declared_principal > policy.maximum)
    return reject(WorkchainDepositRejection::Amount);
  std::uint64_t required;
  if (__builtin_add_overflow(declared_principal, policy.slot_fee, &required))
    return reject(WorkchainDepositRejection::Amount);
  // The policy bounds above ensure required fits signed int64 for make_refint.
  if (td::cmp(imported_tomis, td::make_refint(required)) != 0)
    return reject(WorkchainDepositRejection::SlotFee);
  if (account.system_pending.size() >= policy.system_slots)
    return reject(WorkchainDepositRejection::Capacity);
  auto next = next_workchain_deposit_sequence(sequence);
  if (next.is_error()) return reject(WorkchainDepositRejection::SequenceExhausted);
  TRY_RESULT(id, derive_workchain_deposit_id(message, next.ok()));
  for (const auto& receipt : account.pending)
    if (receipt.receipt_id == id) return reject(WorkchainDepositRejection::Duplicate);
  for (const auto& receipt : account.system_pending)
    if (receipt.receipt_id == id) return reject(WorkchainDepositRejection::Duplicate);
  // Bounds checked above; no narrowing before the comparison. Counter and
  // receipt installation happen together with both Native balance updates.
  return WorkchainDepositDecision{WorkchainDepositAdmission{
      id, next.ok(), declared_principal, policy.slot_fee}};
}
}  // namespace block
