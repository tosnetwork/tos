#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

#include "native-committee.h"
#include "native-session-history.h"

namespace tos::auth {

// This context is immutable after admission. Reuse returns the same shared
// object; a new native session receives a different one only after its birth
// and committee have both authenticated successfully.
using NativeSessionCommitteeContext = SessionCommitteeContext<NativeCommittee>;

struct NativeSessionBlockRequest {
  tos::BlockIdExt id;
  std::size_t maximum_bytes{};
};

struct NativeSessionStateRequest {
  Anchor anchor;
};

struct NativeSessionIdentityRequest {
  Anchor anchor;
  td::Ref<vm::Cell> state;
  tos::ShardIdFull target;
};

using NativeSessionCommitteeRequest =
    std::variant<NativeSessionBlockRequest, NativeSessionStateRequest,
                 NativeSessionIdentityRequest>;

// The committee is derived only from the state owned by NativeSessionBirth.
// The detection tip is deliberately not an input to committee derivation.
Result<std::shared_ptr<const NativeSessionCommitteeContext>>
admit_native_session_committee(
    const std::shared_ptr<const NativeSessionCommitteeContext>& existing,
    const NativeSessionBirth& birth, const ChainContext& chain,
    StateReadBudget committee_budget = {});

// Bridges an asynchronous storage owner to the existing synchronous authenticated
// history selector without blocking that owner.
//
// The handoff retains the finalized head, chain/identity inputs, both budgets and
// raw responses already supplied by the caller. Raw responses are never cached
// as authenticated conclusions. advance() replays every retained input through
// NativeSessionBirth::resolve, with the original budgets, until it either emits
// exactly one next asynchronous request, fails closed, or owns a complete
// SessionCommitteeContext.
//
// Destroying this object mid-handoff publishes nothing. An existing context is
// held only by shared immutable ownership and is never modified in place.
class NativeSessionCommitteeAdmission {
 public:
  NativeSessionCommitteeAdmission(
      td::Ref<vm::Cell> finalized_head_state,
      Anchor independently_finalized_head, ChainContext chain,
      NativeSessionIdInput identity,
      std::shared_ptr<const NativeSessionCommitteeContext> existing = {},
      NativeSessionHistoryBudget history_budget = {},
      StateReadBudget committee_budget = {});

  Result<std::optional<NativeSessionCommitteeRequest>> advance();

  Result<bool> provide_block(const tos::BlockIdExt& id, Bytes bytes);
  Result<bool> provide_state(const Anchor& anchor, td::Ref<vm::Cell> state);
  Result<bool> provide_identity(const Anchor& anchor, tos::ShardIdFull target,
                                NativeSessionIdInput input);

  bool ready() const {
    return static_cast<bool>(result_);
  }

  Result<std::shared_ptr<const NativeSessionCommitteeContext>> context() const;

 private:
  struct BlockInput {
    tos::BlockIdExt id;
    Bytes bytes;
  };
  struct StateInput {
    Anchor anchor;
    td::Ref<vm::Cell> state;
  };
  struct IdentityInput {
    Anchor anchor;
    tos::ShardIdFull target;
    NativeSessionIdInput input;
  };

  td::Ref<vm::Cell> head_state_;
  Anchor head_;
  ChainContext chain_;
  NativeSessionIdInput identity_;
  NativeSessionHistoryBudget history_budget_;
  StateReadBudget committee_budget_;
  std::shared_ptr<const NativeSessionCommitteeContext> existing_;
  std::shared_ptr<const NativeSessionCommitteeContext> result_;
  std::optional<NativeSessionCommitteeRequest> pending_;
  std::vector<BlockInput> blocks_;
  std::vector<StateInput> states_;
  std::vector<IdentityInput> identities_;
};

}  // namespace tos::auth
