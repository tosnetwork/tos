#pragma once
#include "native-anchor-cache.h"
#include "native-config-transaction.h"
namespace tos::auth {
// Deciding whether a block may admit a registry update, separated from the
// collation that asks.
//
// The decision has five inputs and one of them being wrong produces no symptom:
// the answer is simply always "no", and a node that never admits an update
// looks exactly like a node on a chain that has none. Keeping the decision here
// leaves the collator with gathering inputs, and leaves this with everything
// that can be checked by failing.
struct RegistryAdmissionInputs {
  td::Ref<vm::Cell> message;     // the external message, as received
  Hash configuration_account{};  // the account this configuration was read from
  NativeConfigTransactionInputs transaction;
};

// Assembles the authority for one registry update, or refuses.
//
// A refusal is never an error to report upward: it means this block does not
// admit this message, and a later one may. The distinction the caller needs is
// only whether an authority came back.
Result<std::unique_ptr<NativeConfigTransaction>> admit_registry_message(const RegistryAdmissionInputs&,
                                                                        const NativeAnchorCache&);

// What the update declares it will read, so a caller that refused for missing
// history knows what to resolve before trying again.
Result<std::vector<std::uint32_t>> registry_message_requirements(td::Ref<vm::Cell> message,
                                                                 const Hash& configuration_account,
                                                                 std::uint32_t inclusion);
}  // namespace tos::auth
