#pragma once

// D47-APPROVED TEST CONTRACT ONLY. No host implementation or acceptance certificate.
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace i13e_proposal {
using Bytes = std::vector<unsigned char>;
enum class Field : unsigned {
  Accounts, AccountBlocks, InMsgDescr, OutMsgDescr, OutQueue, DispatchQueue,
  ShardState, ShardUpdate, ValueFlow, ProcessingMetadata, Count
};
constexpr unsigned field_count = static_cast<unsigned>(Field::Count);
struct Snapshot {
  std::uint64_t generation{}, committed_batches{};
  std::array<Bytes, field_count> same_block, recovered;
  // Append-only receipts of ALL logical handoff attempts at the real release
  // boundary, including orphan attempts: message identity, owning generation,
  // payload binding. Do not filter by committed state or deduplicate the observer.
  // Wire retransmission below this boundary is outside this test contract.
  Bytes released;
  bool operator==(const Snapshot&) const = default;
};
enum class Stage : unsigned {
  ParticipantFinalize, AccountRootStage, AccountBlockStage, InboundStage,
  OutboundDescriptorStage, OutboundQueueStage, ValueFlowFreeze, CoverageFreeze,
  ShardUpdateBuild, FinalBudgetCheck, ReferencedCellsPersist, GenerationCheck,
  BeforeAtomicPublish, AtomicStoreAbort
};
struct Point {
  Stage stage;
  unsigned occurrence;
  bool operator==(const Point&) const = default;
};
enum class FaultKind { None, FailAtPoint, AfterLinearizationBeforeReply, RestartAfterLinearization };
struct Fault {
  FaultKind kind{FaultKind::None};
  Point point{Stage::BeforeAtomicPublish, 0};
};
enum class Outcome { Committed, NotCommitted };
enum class FailureIdentity { None, InjectedAtPoint };
struct Attempt {
  Outcome outcome;
  FailureIdentity failure;
  std::uint64_t generation;
};
// The adapter installs this at the real host boundary, not in a test-side loop.
// A point notification occurs after that stage's private effects and before
// injecting its failure. AtomicStoreAbort must exercise the real store's abort
// path before its durable decision, not merely bypass the store call.
using Probe = std::function<void(Point)>;
class PreparedBatch {
 public:
  virtual ~PreparedBatch() = default;
};
struct PrivateVisibilityAudit {
  // Complete only after all consensus-affecting consumers are mapped to real
  // observation hooks. Missing hooks or an unknown consumer must fail closed.
  bool coverage_complete{};
  // Sticky, append-only observations of pre-decision builder intermediates by
  // consensus-affecting consumers, including observations later rolled back.
  // Internal engine calculation is not publication to a consumer. Observations
  // of the complete committed generation after the decision are not violations.
  Bytes intermediate_observations;
};
class Session {
 public:
  virtual ~Session() = default;
  // All observers must interrogate real publication/reader surfaces, using fresh
  // canonical deep copies. This must not return an adapter-maintained model.
  virtual Snapshot observe() = 0;
  // Arm at fresh_session creation and retain through release/retry. Read actual
  // consumer hooks, never infer isolation merely from unchanged root snapshots.
  virtual PrivateVisibilityAudit private_visibility_audit() = 0;
  // Prepare the request only; all tested host stages execute inside attempt().
  virtual std::unique_ptr<PreparedBatch> prepare() = 0;
  virtual std::vector<Point> registered_points() const = 0;
  virtual Attempt attempt(const PreparedBatch&, Fault, const Probe&) = 0;
  // Exercise real downstream release eligibility through a private recording
  // transport boundary; do not send live messages or bypass activation/finality.
  virtual void poll_release() = 0;
};
class Adapter {
 public:
  virtual ~Adapter() = default;
  // Fixed fixture: three participants, two inbound messages, three outputs,
  // both outgoing and deferred branches, and nonempty pre-existing state/receipts.
  // Every fresh session starts from the independently pinned 'before' oracle.
  virtual std::unique_ptr<Session> fresh_session() = 0;
};
// Intentionally undefined. A real host adapter is required; there is no fake,
// permissive implementation, weak symbol, skip, or successful missing-adapter path.
std::unique_ptr<Adapter> make_real_i13e_adapter();
}  // namespace i13e_proposal
