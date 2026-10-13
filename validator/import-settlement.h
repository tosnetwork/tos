/*
    This file is part of TOS Blockchain.

    TOS Blockchain is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <array>
#include <cstddef>
#include <string>

#include "td/utils/Status.h"
#include "td/utils/StringBuilder.h"

namespace tos::validator {

// Settlement of one bounded archive import attempt.
//
// The attempt starts children (downloads, proof checks, applies, state and handle
// reads) and logical parents waiting on them (the per-masterchain-block shard join
// and each shard-block apply chain). Every one of them is counted here from the
// moment it is dispatched until it reports. The attempt's outcome is published
// only when completion was requested (the importer reached a terminal point) or
// the attempt is draining after its first error or its deadline, AND nothing is
// outstanding. A zero count between ordinary phases publishes nothing. While
// draining, no new work starts, so the count can only fall.
class ImportSettlement {
 public:
  enum class Child : std::size_t {
    MasterchainArchive,
    ShardArchive,
    RetryWait,
    ProofCheck,
    ProofLinkCheck,
    Apply,
    StateRead,
    HandleRead,
    StateDownload,
    ShardJoin,
    ShardChain,
    Count
  };

  static const char* child_name(Child child) {
    switch (child) {
      case Child::MasterchainArchive:
        return "masterchain archive download";
      case Child::ShardArchive:
        return "shard archive download";
      case Child::RetryWait:
        return "shard archive retry wait";
      case Child::ProofCheck:
        return "proof check";
      case Child::ProofLinkCheck:
        return "proof link check";
      case Child::Apply:
        return "block apply";
      case Child::StateRead:
        return "state read";
      case Child::HandleRead:
        return "handle read";
      case Child::StateDownload:
        return "state download";
      case Child::ShardJoin:
        return "shard join";
      case Child::ShardChain:
        return "shard block chain";
      case Child::Count:
        break;
    }
    return "unknown";
  }

  void begin(Child child) {
    auto index = static_cast<std::size_t>(child);
    counts_[index] = counts_[index] + 1;
    total_ = total_ + 1;
  }

  // Returns false (and changes nothing) for a report with nothing outstanding of
  // its kind, which would be a defect in the caller.
  bool end(Child child) {
    auto index = static_cast<std::size_t>(child);
    if (counts_[index] == 0 || total_ == 0) {
      return false;
    }
    counts_[index] = counts_[index] - 1;
    total_ = total_ - 1;
    return true;
  }

  // Records the first error and stops new work. Later errors are not recorded.
  void drain(td::Status error) {
    if (!draining_) {
      draining_ = true;
      first_error_ = std::move(error);
    }
  }

  void request_completion() {
    completion_requested_ = true;
  }

  bool draining() const {
    return draining_;
  }
  bool completion_requested() const {
    return completion_requested_;
  }
  std::size_t outstanding() const {
    return total_;
  }
  std::size_t outstanding(Child child) const {
    return counts_[static_cast<std::size_t>(child)];
  }
  bool published() const {
    return published_;
  }

  bool ready_to_publish() const {
    return !published_ && (draining_ || completion_requested_) && total_ == 0;
  }

  // Marks the outcome published and hands over the first error.
  td::Status publish() {
    published_ = true;
    return std::move(first_error_);
  }

  std::string outstanding_summary() const {
    td::StringBuilder sb;
    bool first = true;
    for (std::size_t i = 0; i < counts_.size(); ++i) {
      if (counts_[i] == 0) {
        continue;
      }
      if (!first) {
        sb << ", ";
      }
      first = false;
      sb << child_name(static_cast<Child>(i)) << "=" << counts_[i];
    }
    return sb.as_cslice().str();
  }

 private:
  std::array<std::size_t, static_cast<std::size_t>(Child::Count)> counts_{};
  std::size_t total_ = 0;
  bool draining_ = false;
  bool completion_requested_ = false;
  bool published_ = false;
  td::Status first_error_;
};

}  // namespace tos::validator
