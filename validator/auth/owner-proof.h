#pragma once
#include "context.h"
#include "native-proof.h"
namespace tos::auth {
inline constexpr std::uint32_t owner_approval_tag = 0x76616f31;
inline constexpr std::uint32_t owner_proof_tag = 0x76616f70;
// Only a finalized native transaction with a successful action phase can
// construct this value. It grants no PoP, identity or governance authority.
class VerifiedOwnerExecution {
  Hash update_id_{}, transaction_id_{};
  Anchor anchor_;
  VerifiedOwnerExecution(Hash update, Hash transaction, Anchor anchor)
      : update_id_(update), transaction_id_(transaction), anchor_(anchor) {
  }
  friend Result<VerifiedOwnerExecution> verify_owner_execution(const OwnerAuth&, const Update&, const Identity&,
                                                               const Anchor&, const ChainContext&, ObjectReader&);

 public:
  const Hash& update_id() const {
    return update_id_;
  }
  const Hash& transaction_id() const {
    return transaction_id_;
  }
  const Anchor& anchor() const {
    return anchor_;
  }
};
// Owner/stake binding is supplied from current authenticated allocation. The
// proof also checks that binding at its independently finalized anchor. Native
// election value/timelock rules, update nonce and atomic application are separate.
Result<VerifiedOwnerExecution> verify_owner_execution(const OwnerAuth&, const Update&, const Identity& current,
                                                      const Anchor& independently_trusted_anchor, const ChainContext&,
                                                      ObjectReader&);
Result<OwnerAuth> make_owner_execution_proof(td::Ref<vm::Cell> masterchain_state, td::Ref<vm::Cell> owner_block,
                                             const Anchor&, const ChainContext&, const Update&, const Identity&,
                                             std::uint64_t transaction_lt, std::uint16_t message_index,
                                             ObjectPublisher = {});
Result<td::Ref<vm::Cell>> owner_approval_body(const ChainContext&, const Update&, const Identity&);
}  // namespace tos::auth
