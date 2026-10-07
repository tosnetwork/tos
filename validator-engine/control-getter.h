/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <algorithm>
#include <functional>
#include <memory>

#include "block/get-method-context.h"
#include "td/utils/Status.h"

namespace tos::control_getter {

inline constexpr std::size_t kControlGetterActiveJobs = 2;
inline constexpr std::size_t kControlGetterQueuedJobs = 8;
inline constexpr std::size_t kControlGetterReplyBytes = 8 * 1024 * 1024;
inline constexpr std::size_t kMaxConfigProposals = 4096;
inline constexpr std::size_t kMaxElectorParticipants = 256;
inline constexpr std::size_t kMaxPastElections = 16;
inline constexpr std::size_t kMaxFrozenEntriesPerElection = 256;
inline constexpr std::size_t kMaxFrozenEntriesTotal = 4096;
inline constexpr std::size_t kMaxReturnedStakeWallets = 16;
inline constexpr long long kElectorParticipantsGasLimit = 1500000;
inline constexpr long long kPastElectionsGasLimit = 50000;
inline constexpr long long kReturnedStakeGasLimit = 40000;
inline constexpr long long kElectorStateGasLimit = 2190000;
inline constexpr long long kConfigProposalsGasLimit = 10000000;

enum class Getter { Participants, PastElections, ReturnedStake, Proposals, Proposal };

// A request owns one budget; results are delivered to its decoder only after both
// the individual and aggregate gas checks succeed.
class GasBudget {
 public:
  explicit GasBudget(long long limit) : limit_(limit) {
  }
  td::Status charge(long long amount);
  long long used() const {
    return used_;
  }

 private:
  long long limit_;
  long long used_{0};
};

class ReplyBudget {
 public:
  explicit ReplyBudget(std::size_t limit = kControlGetterReplyBytes)
      : limit_(std::min(limit, kControlGetterReplyBytes)) {
  }
  td::Status reserve(std::size_t bytes);
  std::size_t used() const {
    return used_;
  }

 private:
  std::size_t limit_;
  std::size_t used_{0};
};

struct Account {
  td::Ref<vm::Cell> root;
  td::Ref<vm::Cell> code;
  td::Ref<vm::Cell> data;
  td::Ref<vm::Cell> libraries;
  td::Ref<vm::CellSlice> address;
  block::CurrencyCollection balance;
  td::RefInt256 due_payment;
  bool belongs_to(const td::Ref<vm::Cell>& root) const {
    return owner_.not_null() && root.not_null() && owner_->get_hash() == root->get_hash();
  }

 private:
  friend class Snapshot;
  td::Ref<vm::Cell> owner_;
};

class Snapshot {
 public:
  static td::Result<std::shared_ptr<const Snapshot>> create(BlockIdExt block, td::Ref<vm::Cell> state);
  td::Result<Account> account(const td::Bits256& address) const;
  const BlockIdExt& block_id() const {
    return block_;
  }
  const td::Ref<vm::Cell>& state_root() const {
    return state_;
  }
  const block::ConfigInfo& config() const {
    return *config_;
  }
  UnixTime now() const {
    return now_;
  }
  LogicalTime lt() const {
    return lt_;
  }

 private:
  Snapshot() = default;
  BlockIdExt block_;
  td::Ref<vm::Cell> state_;
  td::Ref<vm::Cell> accounts_;
  std::unique_ptr<block::ConfigInfo> config_;
  UnixTime now_{0};
  LogicalTime lt_{0};
};

struct RunStats {
  int exit_code{0};
  long long gas_used{0};
};

// The decoder runs synchronously on the worker. No result stack is returned or
// serialized; c4/c5 remain private to this VM instance and are discarded.
td::Status run(const Snapshot& snapshot, const Account& account, Getter getter, std::vector<td::RefInt256> arguments,
               GasBudget& budget, const std::function<td::Status(const vm::Stack&)>& decode, RunStats* stats = nullptr);

// A bounded, iterative cons walk. Only TVM null terminates the list. The visitor
// must flatten the head before returning and must not retain a result subtree.
td::Status walk_cons(const vm::StackEntry& root, std::size_t limit,
                     const std::function<td::Status(const vm::StackEntry&)>& visit);

}  // namespace tos::control_getter
