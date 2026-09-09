#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include "td/db/RocksDb.h"
#include "common/bitstring.h"
#include "block/workchain-candidate-construction.h"

namespace block {

// Full canonical bytes supplied by the host providers, not inferred here.
// components follows WorkchainCandidateField: accounts, AccountBlocks,
// InMsgDescr, OutMsgDescr, OutQueue, DispatchQueue, ShardState, ShardUpdate,
// ValueFlow, ProcessingMetadata. Messages include payload and queue metadata.
static_assert(static_cast<std::size_t>(WorkchainCandidateField::Count) == 10,
              "Update the persisted publication codec when the candidate field set changes");
struct WorkchainPublicationBundle {
  WorkchainPublicationBundle(td::Bits256 identity, td::Bits256 input, std::uint64_t count, std::uint64_t version)
      : batch_identity(identity), admitted_input(input), committed_batch_count(count), revision(version) {}
  td::Bits256 batch_identity;
  td::Bits256 admitted_input;
  std::uint64_t committed_batch_count;
  std::uint64_t revision;
  std::array<std::string, 10> components;
  std::string pending_messages;
  bool operator==(const WorkchainPublicationBundle&) const = default;
};

// Limits are supplied host bounds, not a certificate of D31 admission.
struct WorkchainPublicationLimits {
  std::size_t max_bundle_bytes;
};

enum class WorkchainPublicationOutcome { Committed, NotCommitted, Undetermined };
enum class WorkchainPublicationAvailability { Ready, LocalUnavailable };
struct WorkchainPublicationResult {
  WorkchainPublicationOutcome outcome;
  WorkchainPublicationAvailability availability;
  td::Status detail;
};
enum class WorkchainPublicationPoint {
  BeforeWrite, BatchStaged, AfterCommitBeforeRead, PersistentRead, ReleaseInstall
};
// Diagnostics only. No mutable store, view, engine, transport or authority token
// is exposed. These trusted diagnostic callbacks are not release consumers and
// must not perform external publication. Release is passive snapshot installation.
// A private batch commit does not grant consensus finality or permission to send.
using WorkchainPublicationObserver = std::function<void(WorkchainPublicationPoint)>;

// One synchronous writer owns this private store. Passive consumers acquire an
// immutable released view; no external notifications or network sends occur.
// Normal completion and recovery both release exclusively through disk readback.
class WorkchainCandidatePublication {
 public:
  using View = std::shared_ptr<const WorkchainPublicationBundle>;
  using Build = std::function<td::Result<WorkchainPublicationBundle>()>;
  static td::Result<std::unique_ptr<WorkchainCandidatePublication>> open(
      std::string path, const td::Bits256& store_identity, WorkchainPublicationLimits limits);
  static td::Result<std::unique_ptr<WorkchainCandidatePublication>> create_new(
      std::string path, const td::Bits256& store_identity, WorkchainPublicationLimits limits);
  td::Result<View> released() const;
  WorkchainPublicationResult publish(const td::Bits256& identity, const td::Bits256& admitted_input,
      const td::Bits256& expected_predecessor, const Build& build,
      const WorkchainPublicationObserver& observer = {});
  // Closing and reopening is mandatory. A read failure never means absence.
  WorkchainPublicationResult recover(const td::Bits256& identity, const td::Bits256& admitted_input,
      const WorkchainPublicationObserver& observer = {});
  // Explicit bootstrap, with the same sync and readback rules. Not implicit data
  // synthesis: initial contents and their identity/count are supplied by host.
  WorkchainPublicationResult initialize(const WorkchainPublicationBundle& initial,
      const WorkchainPublicationObserver& observer = {});
 private:
  WorkchainCandidatePublication(std::string path, const td::Bits256& store_identity, WorkchainPublicationLimits limits)
      : path_(std::move(path)), store_identity_(store_identity), limits_(limits) {}
  td::Status reopen();
  WorkchainPublicationResult read_and_release(const td::Bits256& identity,
      const td::Bits256& admitted_input, const WorkchainPublicationObserver& observer);
  WorkchainPublicationResult write(const WorkchainPublicationBundle& bundle,
      const WorkchainPublicationObserver& observer);
  std::string path_;
  td::Bits256 store_identity_;
  WorkchainPublicationLimits limits_;
  std::unique_ptr<td::RocksDb> db_;
  std::atomic<bool> recovery_required_{true};
  bool active_{false};
  std::atomic<View> released_{View{}};
};

}  // namespace block
