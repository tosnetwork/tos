#pragma once

#include "block/workchain-account-access-codec.h"
#include "block/workchain-block-execution.h"
#include "block/workchain-host-identity.h"

namespace block {

// The host supplies the complete authenticated inbox, not candidate claims.
// Native envelopes are not subjected to the ordinary-candidate wire profile.
// Before calling, admission must bound all supplied closures and the derived
// dictionary/wrapper cost. Count limits alone do not bound traversal or bytes.
// This encoder does not authenticate completeness, resolve policy or execute an
// engine. Native inbox failures must retain that source at the caller boundary.
// This is post-admission construction, not validator preflight: the inbox
// encoder performs semantic decoding. A validator must check the claimed input
// commitment before rebuilding the fully authenticated inbox through this path.
inline td::Result<td::Ref<vm::Cell>> encode_workchain_host_input(
    const WorkchainHostIdentity& identity, const AdmittedInput& admitted,
    const WorkchainAccountDeclarations& access,
    const std::vector<td::Ref<vm::Cell>>& authenticated_inbox,
    std::uint64_t max_reads, std::uint64_t max_writes, std::uint64_t max_inbound) {
  if (authenticated_inbox.size() > max_inbound) {
    return td::Status::Error("host inbox exceeds admitted count");
  }
  TRY_RESULT(identity_root, encode_admitted_workchain_host_identity(identity, admitted));
  TRY_RESULT(access_root, encode_workchain_account_declarations(access, max_reads, max_writes));
  td::Ref<vm::Cell> inbox_root;
  if (!authenticated_inbox.empty()) {
    TRY_RESULT(encoded, encode_workchain_batch_inbound(authenticated_inbox));
    inbox_root = std::move(encoded);
  }
  vm::CellBuilder cb;
  cb.store_long(0x7c0766c8, 32).store_ref(identity_root).store_ref(access_root)
      .store_ref(admitted.candidate());
  if (!cb.store_maybe_ref(inbox_root)) return td::Status::Error("cannot encode host input inbox reference");
  return cb.finalize();
}

}  // namespace block
