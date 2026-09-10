#pragma once
#include "block/workchain-registration.h"
#include "block/workchain-registration-refund.h"

namespace block {

struct WorkchainAccountClosureTransition {
  td::Ref<vm::Cell> account_data;
  td::Ref<vm::Cell> coordinator_data;
  WorkchainRegistrationRefund refund;
};

// All state arguments, including the obligation count, must be independently
// acquired by the host. A missing obligation view is LocalUnavailable at that
// boundary; it must never be converted to count=0. No mutable publication
// handle is exposed: account closure, bucket debit and refund form one result.
inline td::Result<WorkchainAccountClosureTransition> execute_workchain_account_closure(
    const WorkchainConfidentialAccount& old_account, const WorkchainCoordinatorState& old_coordinator,
    std::uint64_t authenticated_inflight_obligations,
    const std::array<unsigned char, 80>& authenticated_domain,
    const std::array<unsigned char, 96>& proof) {
  auto invalid = [](td::Slice text) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid), text);
  };
  auto local = [] {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                            "closure construction unavailable");
  };
  try {
    if (!std::holds_alternative<WorkchainAccountActive>(old_account.lifecycle) &&
        !std::holds_alternative<WorkchainAccountReadOnly>(old_account.lifecycle)) {
      return invalid("closed or migrated account cannot be refunded again");
    }
    // These are plaintext authenticated-state properties, not DLEQ conclusions.
    if (!old_account.pending.empty()) return invalid("closure has unconsumed pending receipts");
    if (authenticated_inflight_obligations != 0) return invalid("closure has in-flight obligations");
    if (old_account.auth_nonce == UINT64_MAX) return invalid("closure nonce exhausted");
    // Randomized zero is not the identity ciphertext. This one DLEQ establishes
    // both possession and exhausted available; do not add registration Schnorr.
    TRY_STATUS(verify_workchain_closure_possession(old_account, authenticated_domain, proof));
    TRY_RESULT(refund, prepare_workchain_registration_refund(old_account.funding,
                                                           old_coordinator.refundable_deposits));
    auto account = old_account;
    account.lifecycle = WorkchainAccountClosed{};
    ++account.auth_nonce;  // Checked below UINT64_MAX before any construction.
    // Preserve identity, ciphertext/revision and historical funding. Only the
    // lifecycle and consumed nonce change. registered_accounts never decreases.
    auto coordinator = old_coordinator;
    coordinator.refundable_deposits = refund.remaining_refundable_deposits;
    auto account_cell = encode_workchain_confidential_account(account);
    auto coordinator_cell = encode_workchain_coordinator_state(coordinator);
    if (account_cell.is_error() || coordinator_cell.is_error()) return local();
    return WorkchainAccountClosureTransition{account_cell.move_as_ok(), coordinator_cell.move_as_ok(), refund};
  } catch (const vm::CellBuilder::CellCreateError&) { return local();
  } catch (const vm::CellBuilder::CellWriteError&) { return local();
  } catch (const std::bad_alloc&) { return local();
  } catch (const vm::VmError&) { return local();
  } catch (const vm::VmVirtError&) { return local(); }
}
}  // namespace block
