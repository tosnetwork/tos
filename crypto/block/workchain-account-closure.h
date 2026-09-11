#pragma once
#include "block/workchain-registration.h"
#include "block/workchain-registration-refund.h"

namespace block {

struct WorkchainAccountClosureTransition {
  td::Ref<vm::Cell> account_data;
  td::Ref<vm::Cell> coordinator_data;
  WorkchainRegistrationRefund refund;
};

// The engine supplies this locally verified result to Native settlement. Hashes
// bind it to the same authenticated read snapshot, not to candidate claims.
// No decoder exists: a validator constructs its own result by replaying DLEQ.
struct WorkchainAccountClosureExecution {
  td::Bits256 account;
  td::Bits256 old_account_data_hash;
  td::Bits256 old_coordinator_data_hash;
  WorkchainAccountClosureTransition transition;
};

// No M3 operation can create a settlement obligation: registration settles its
// deposit atomically, SEND creates a pending receipt (a separate closure
// condition), COLLECT consumes receipts, and closure commits a one-way refund
// message within the same transition, NOT guaranteed delivery. M3 creates no
// asynchronous return association, recredit, compensation or claim. Ordinary
// Native processing may consume value or produce no bounce; reliable delivery
// belongs to M5. Withdrawal and deposit operations do not exist before M4/M5.
// Nor can authenticated M3 state represent an obligation: account records carry
// no settlement refs and there is no chain-state obligation view. This condition
// is structurally satisfied, NOT checked at runtime or declared by a caller.
// M4 extends the scoped argument: accepted Deposit clears D in the same batch;
// a rejected Deposit can only return to src or credit sender-only unexpected
// funds. No confidential account_id can be recorded in that bucket. This does
// NOT assert that Native senders have no rights, only that this confidential
// account has no bucket entitlement. M5's account_id category is a claim to
// future Deposit credit (D29); once reachable, closure must also authenticate
// that no bucket entry belongs to this account, in addition to its obligations.
// EXPIRY: test-workchain-m3-closure-expiry guards this premise. Before adding an
// obligation representation or operation, replace it with an authenticated
// obligation view. Never restore a caller-supplied count or empty table.
// No mutable publication handle is exposed: closure, debit and refund form one
// result, which the host must commit atomically.
inline td::Result<WorkchainAccountClosureTransition> execute_workchain_account_closure(
    const WorkchainConfidentialAccount& old_account, const WorkchainCoordinatorState& old_coordinator,
    const WorkchainPossessionPolicy& possession,
    const std::array<unsigned char, 80>& authenticated_domain,
    const std::array<unsigned char, 96>& proof, WorkchainProofVerifier& verifier) {
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
    // Pending is an authenticated-state property, not a DLEQ conclusion.
    if (!old_account.pending.empty()) return invalid("closure has unconsumed pending receipts");
    if (old_account.auth_nonce == UINT64_MAX) return invalid("closure nonce exhausted");
    // Randomized zero is not the identity ciphertext. This one DLEQ establishes
    // both possession and exhausted available; do not add registration Schnorr.
    TRY_STATUS(verify_workchain_closure_possession(old_account, possession, authenticated_domain, proof, verifier));
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
