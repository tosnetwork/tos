#pragma once

#include <array>
#include <memory>
#include <utility>
#include "block/transaction.h"
#include "block/workchain-construction-observer.h"

namespace block {

enum class WorkchainCandidateField : std::size_t {
  Accounts, AccountBlocks, InMsgDescr, OutMsgDescr, OutQueue, DispatchQueue,
  ShardState, ShardUpdate, ValueFlow, ProcessingMetadata, Count
};
// Copy the caller's elements, not merely a shared_ptr to its mutable vector.
// Previously retained element references must not mutate a frozen generation.
class WorkchainCandidateMessages final {
 public:
  explicit WorkchainCandidateMessages(const std::vector<NewOutMsg>& messages) : messages_(messages) {}
  const std::vector<NewOutMsg>& items() const { return messages_; }
 private:
  const std::vector<NewOutMsg> messages_;
};

// One candidate's complete construction view, not consensus-authoritative state.
// Cell roots and message lists are persistent/immutable shared objects. Copying
// this carrier never walks their closures or duplicates the prior message list.
// Providers supply identity/count explicitly; this is not the I13a checker.
struct WorkchainCandidateContents {
  WorkchainCandidateContents(std::uint64_t supplied_count, std::uint64_t supplied_revision)
      : committed_batch_count(supplied_count), revision(supplied_revision) {}
  std::array<td::Ref<vm::Cell>, static_cast<std::size_t>(WorkchainCandidateField::Count)> roots;
  td::Ref<vm::Cell> batch_identity;
  std::shared_ptr<const WorkchainCandidateMessages> pending_messages;
  std::uint64_t committed_batch_count;
  std::uint64_t revision;
};

// Synchronous, single-owner candidate context. All same-block consumers must use
// snapshot(); no live mutable Account/dictionary/message queue is handed out.
// Integration with a collator still has to route every such consumer here.
// This class grants no finality, network handoff or persistent-store authority.
class WorkchainCandidateConstruction {
 public:
  using Snapshot = std::shared_ptr<const WorkchainCandidateContents>;
  explicit WorkchainCandidateConstruction(WorkchainCandidateContents initial)
      : current_(std::make_shared<const WorkchainCandidateContents>(std::move(initial))) {
  }
  WorkchainCandidateConstruction(const WorkchainCandidateConstruction&) = delete;
  WorkchainCandidateConstruction& operator=(const WorkchainCandidateConstruction&) = delete;

  Snapshot snapshot() const { return current_; }

  // Trusted host construction only: the engine must not receive this context or
  // the builder capability. The builder may alter the private draft and invoke
  // Native builders; it must propagate their failures. The sticky observer also
  // prevents swallowing an injected stage failure and then installing a draft.
  // Returned Status and thrown exceptions retain their caller-owned provenance.
  template <class Build>
  td::Status construct(const Snapshot& expected_predecessor, const Build& build,
                       const WorkchainConstructionObserver& observer = {}) {
    if (constructing_) return td::Status::Error("candidate construction is already active");
    constructing_ = true;
    struct Reset {
      bool& value;
      ~Reset() { value = false; }
    } reset{constructing_};
    const auto before = current_;
    auto draft = *before;
    td::Status observed_failure;
    WorkchainConstructionObserver checkpoint = [&](WorkchainConstructionPoint point) {
      if (observed_failure.is_error()) return observed_failure.clone();
      auto status = observe_workchain_construction(observer, point.stage, point.occurrence);
      if (status.is_error()) observed_failure = status.clone();
      return status;
    };
    TRY_STATUS(build(*before, draft, checkpoint));
    if (observed_failure.is_error()) return observed_failure;
    // Presence is a local programming precondition, not semantic admission.
    // Empty dictionaries must be supplied as their actual wrapped Native roots.
    for (const auto& root : draft.roots) {
      if (root.is_null()) return td::Status::Error("candidate construction omitted a root");
    }
    if (draft.batch_identity.is_null() || !draft.pending_messages) {
      return td::Status::Error("candidate construction omitted identity or pending messages");
    }
    if (current_ != expected_predecessor) return td::Status::Error("candidate predecessor differs from prepared input");
    TRY_STATUS(checkpoint({WorkchainConstructionStage::GenerationCheck, 0}));
    // Finish every allocating step before the sole installation. No callbacks,
    // mutable draft aliases, or fallible operations run after that assignment.
    auto next = std::make_shared<const WorkchainCandidateContents>(draft);
    TRY_STATUS(checkpoint({WorkchainConstructionStage::BeforeCandidateInstall, 0}));
    current_ = std::move(next);
    return td::Status::OK();
  }

 private:
  Snapshot current_;
  bool constructing_ = false;
};

}  // namespace block
