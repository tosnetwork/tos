#pragma once
#include "context.h"
#include "state.h"
#include "transfer.h"
namespace tos::auth {
// The caller establishes the current native governing committee and resulting
// inclusion-time registry independently. This proves current quorum authority;
// native configuration voting, nonce/CAS checks and application remain separate.
Result<VerifiedCertificate> verify_current_governance(const ChainContext&, const RegistrySnapshot& governing,
                                                      const CurrentRegistry& current, const Update&,
                                                      const Authorizations&, std::uint32_t inclusion, ObjectReader&);
}  // namespace tos::auth
