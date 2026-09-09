#pragma once

#include <cstddef>
#include <functional>
#include "td/utils/Status.h"

namespace block {

// Private construction stages only. No store transaction, recovery or consensus
// event is represented here. Observers borrow no mutable account/candidate data.
enum class WorkchainConstructionStage {
  ParticipantFinalize, AccountBlockStage, AccountRootStage, InboundStage,
  OutboundDescriptorStage, OutboundQueueStage, ValueFlowFreeze, CoverageFreeze,
  ShardUpdateBuild, FinalBudgetCheck, GenerationCheck, BeforeCandidateInstall
};
struct WorkchainConstructionPoint {
  WorkchainConstructionStage stage;
  std::size_t occurrence;
  bool operator==(const WorkchainConstructionPoint&) const = default;
};
using WorkchainConstructionObserver = std::function<td::Status(WorkchainConstructionPoint)>;
inline td::Status observe_workchain_construction(const WorkchainConstructionObserver& observer,
                                                WorkchainConstructionStage stage, std::size_t occurrence = 0) {
  return observer ? observer({stage, occurrence}) : td::Status::OK();
}

}  // namespace block
