#pragma once

#include "block/workchain-coordinator-state.h"
#include "block/workchain-registration-proof.h"
#include "block/workchain-refund-message.h"
#include <limits>
#include "vm/excno.hpp"

namespace block {

// Resolved by the host from authenticated configuration, not from the request.
struct WorkchainRegistrationPolicy {
  std::int32_t global_id;
  td::Bits256 genesis_hash;
  td::Bits256 workchain_instance;
  WorkchainConfidentialBindings bindings;
  std::uint16_t schema_version, relation_profile, proof_profile;
  std::uint64_t deposit;
  WorkchainPossessionPolicy possession;
  const WorkchainSet& refund_workchains;  // Mandatory authenticated table, no local fallback.
};

// M3 implementation choice; incarnation semantics are NOT frozen by the
// specification. Do not treat this preimage as a production codec precedent.
// Registration operationID binds the complete initial registration intent and
// authenticated network/workchain domain. Only its own incarnation slot is
// zeroed in the PREIMAGE; no zero incarnation is installed. Proof bytes are not
// included. The wallet can therefore compute the ID before signing/payment,
// without a cycle through the Native message hash or an unknown future LT.
//
// Account incarnation and workchain instance are deliberately separate. Neither
// can be inferred from the other: the domain alone is insufficient without this
// account's registration intent. Add + retained closed records prevent reuse.
inline td::Result<td::Bits256> derive_workchain_registration_operation_id(
    const WorkchainRegistrationPolicy& policy, const WorkchainConfidentialAccount& registration) {
  auto intent = registration;
  intent.address.instance.set_zero();
  TRY_RESULT(data, encode_workchain_confidential_account(intent));
  auto domain = vm::CellBuilder().store_long(0x55524731, 32).store_long(policy.global_id, 32)
      .store_bits(policy.genesis_hash.bits(), 256).store_bits(policy.workchain_instance.bits(), 256).finalize();
  auto operation = vm::CellBuilder().store_long(0x55524f31, 32).store_ref(domain).store_ref(data).finalize();
  return td::Bits256(operation->get_hash().bits());
}

// Immutable authenticated inputs. Null account data means verified absence,
// never an acquisition failure. The payer identity/balance must come from the
// admitted Native payment/account, not untrusted registration funding fields.
struct WorkchainRegistrationSnapshot {
  WorkchainCoordinatorState coordinator;
  td::Ref<vm::Cell> existing_account;
  std::int32_t payer_workchain;
  td::Bits256 payer_account;
  std::uint64_t payer_balance;
};

// One construction result: callers must install all three changes together in
// the candidate's isolated batch, never debit first and register afterwards.
// This function has no mutable store, account actor, or partial publish callback.
struct WorkchainRegistrationTransition {
  td::Ref<vm::Cell> account_data;
  td::Ref<vm::Cell> coordinator_data;
  std::uint64_t payer_balance;
};

inline td::Result<WorkchainRegistrationTransition> prepare_workchain_registration_impl(
    const WorkchainRegistrationPolicy& policy,
    const WorkchainRegistrationSnapshot& old,
    const td::Bits256& destination_account,
    const td::Ref<vm::Cell>& registration_data,
    const std::array<unsigned char, 64>& proof, WorkchainProofVerifier& verifier) {
  auto invalid = [](td::Slice message) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid), message);
  };
  // The exact UnoV2AccountState constructor is the chain-side discriminator:
  // ordinary Native account data cannot be reinterpreted as confidential by a
  // UI prefix. Decode and configuration/address checks precede every write.
  // Only this decoding reads candidate-supplied bytes. Missing authenticated
  // state must have failed at acquisition, before constructing old/policy.
  auto decoded = [&]() -> td::Result<WorkchainConfidentialAccount> {
    try {
      return decode_workchain_confidential_account(registration_data);
    } catch (const vm::VmVirtError&) {
      return invalid("registration contains incomplete candidate data");
    } catch (const vm::VmError&) {
      return invalid("registration contains malformed candidate data");
    }
  }();
  if (decoded.is_error()) return invalid("malformed confidential registration record");
  auto account = decoded.move_as_ok();
  if (account.global_id != policy.global_id || account.genesis_hash != policy.genesis_hash ||
      account.address.workchain_id != 2 || account.address.account != destination_account ||
      account.bindings.asset != policy.bindings.asset ||
      account.bindings.custody != policy.bindings.custody || account.bindings.policy != policy.bindings.policy ||
      account.schema_version != policy.schema_version || account.relation_profile != policy.relation_profile ||
      account.proof_profile != policy.proof_profile) {
    return invalid("registration address or authenticated configuration binding mismatch");
  }
  // Closed identities remain present, preventing repeated registration/refund
  // cycles from reusing the same incarnation or erasing its replay history.
  if (old.existing_account.not_null()) return invalid("confidential account already exists");
  TRY_RESULT(registration_id, derive_workchain_registration_operation_id(policy, account));
  if (account.address.instance != registration_id) return invalid("registration incarnation differs from operationID");
  if (!std::holds_alternative<WorkchainAccountActive>(account.lifecycle) ||
      account.auth_nonce != 0 || account.available_revision != 0 || account.key_epoch != 0 ||
      !account.pending.empty() || !account.available.commitment.is_zero() ||
      !account.available.handle.is_zero()) {
    return invalid("registration must initialize an active empty confidential account");
  }
  if (account.funding.paid_deposit != policy.deposit ||
      account.funding.refund_workchain != old.payer_workchain ||
      account.funding.refund_account != old.payer_account) {
    return invalid("registration funding does not match authenticated payer and deposit");
  }
  TRY_STATUS(validate_workchain_refund_destination(account.funding, policy.refund_workchains));
  if (old.payer_balance < policy.deposit) return invalid("insufficient registration deposit");
  if (old.coordinator.system.registered_accounts == UINT64_MAX ||
      policy.deposit > UINT64_MAX - old.coordinator.refundable_deposits) {
    return invalid("registration counter or refundable deposit bucket exhausted");
  }
  TRY_STATUS(verify_workchain_registration_possession(account, policy.possession, proof, verifier));
  auto coordinator = old.coordinator;
  ++coordinator.system.registered_accounts;  // Checked strictly below UINT64_MAX above.
  coordinator.refundable_deposits += policy.deposit;  // Checked above, no wrap.
  auto encoded = encode_workchain_coordinator_state(coordinator);
  if (encoded.is_error()) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                            "cannot encode registration coordinator transition");
  }
  // Invariant: authenticated payer_balance >= authenticated deposit was checked
  // before subtraction. Deposit is locked separately: not principal or revenue.
  return WorkchainRegistrationTransition{registration_data, encoded.move_as_ok(),
                                         old.payer_balance - policy.deposit};
}

inline td::Result<WorkchainRegistrationTransition> execute_workchain_registration(
    const WorkchainRegistrationPolicy& policy, const WorkchainRegistrationSnapshot& old,
    const td::Bits256& destination_account, const td::Ref<vm::Cell>& registration_data,
    const std::array<unsigned char, 64>& proof, WorkchainProofVerifier& verifier) {
  auto local = [] {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                            "registration construction unavailable");
  };
  try {
    return prepare_workchain_registration_impl(policy, old, destination_account, registration_data, proof, verifier);
  } catch (const vm::CellBuilder::CellCreateError&) { return local();
  } catch (const vm::CellBuilder::CellWriteError&) { return local();
  } catch (const std::bad_alloc&) { return local();
  } catch (const vm::VmError&) { return local();
  } catch (const vm::VmVirtError&) { return local(); }
}

}  // namespace block
