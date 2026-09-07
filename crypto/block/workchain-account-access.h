#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

#include "common/bitstring.h"
#include "td/utils/Status.h"

namespace block {

struct WorkchainAccountRead {
  td::Bits256 account;
  // Empty means authenticated absence, not an unavailable local cell.
  std::optional<td::Bits256> old_account_hash;
};

// A bounded access ledger, not a state authenticator. The host obtains old
// hashes and actual changed keys from authenticated account dictionaries.
// Errors here are structural mismatches; provenance classification is a host
// responsibility. Allocation failures propagate, never becoming mismatches.
// The caller must bound materialization before constructing the input vectors.
class WorkchainAccountAccess {
 public:
  static td::Result<WorkchainAccountAccess> create(std::vector<WorkchainAccountRead> reads,
                                                  std::vector<td::Bits256> writes,
                                                  std::uint64_t max_reads, std::uint64_t max_writes);
  // Call before fetching the old account. A missing declaration sticks as an
  // error, and cannot be hidden by retrying a different account afterward.
  td::Result<std::optional<td::Bits256>> expected_read(const td::Bits256& account);
  td::Status record_old_read(const td::Bits256& account, const std::optional<td::Bits256>& actual_hash);
  td::Status record_write(const td::Bits256& account);
  // Both lists are independently reconstructed by the host, not engine claims.
  td::Status finish(const std::vector<td::Bits256>& actual_changed_accounts,
                    const std::vector<td::Bits256>& participant_accounts);

 private:
  WorkchainAccountAccess(std::vector<WorkchainAccountRead> reads, std::vector<td::Bits256> writes)
      : reads_(std::move(reads)), writes_(std::move(writes)), read_seen_(reads_.size()),
        write_seen_(writes_.size()) {
  }
  td::Status fail(const char* reason);
  std::vector<WorkchainAccountRead> reads_;
  std::vector<td::Bits256> writes_;
  std::vector<bool> read_seen_;
  std::vector<bool> write_seen_;
  const char* failure_{nullptr};
  bool finished_{false};
};

inline td::Result<WorkchainAccountAccess> WorkchainAccountAccess::create(
    std::vector<WorkchainAccountRead> reads, std::vector<td::Bits256> writes,
    std::uint64_t max_reads, std::uint64_t max_writes) {
  if (reads.size() > max_reads || writes.size() > max_writes) {
    return td::Status::Error("account access set exceeds admitted bounds");
  }
  const td::Bits256* previous = nullptr;
  for (const auto& read : reads) {
    if (previous && !(*previous < read.account)) {
      return td::Status::Error("read accounts are not strictly ordered");
    }
    previous = &read.account;
  }
  previous = nullptr;
  for (const auto& write : writes) {
    if (previous && !(*previous < write)) {
      return td::Status::Error("write accounts are not strictly ordered");
    }
    previous = &write;
    auto it = std::lower_bound(reads.begin(), reads.end(), write,
                              [](const WorkchainAccountRead& a, const td::Bits256& b) { return a.account < b; });
    if (it == reads.end() || it->account != write) {
      return td::Status::Error("write account missing from authenticated read declarations");
    }
  }
  return WorkchainAccountAccess(std::move(reads), std::move(writes));
}

inline td::Status WorkchainAccountAccess::fail(const char* reason) {
  if (!failure_) failure_ = reason;
  return td::Status::Error(td::CSlice(failure_));
}

inline td::Result<std::optional<td::Bits256>> WorkchainAccountAccess::expected_read(const td::Bits256& account) {
  if (failure_) return fail(failure_);
  if (finished_) return fail("account access ledger already finished");
  auto it = std::lower_bound(reads_.begin(), reads_.end(), account,
                            [](const WorkchainAccountRead& a, const td::Bits256& b) { return a.account < b; });
  if (it == reads_.end() || it->account != account) return fail("undeclared account read");
  return it->old_account_hash;
}
inline td::Status WorkchainAccountAccess::record_old_read(
    const td::Bits256& account, const std::optional<td::Bits256>& actual_hash) {
  TRY_RESULT(expected, expected_read(account));
  if (expected != actual_hash) return fail("old account hash or absence differs from declaration");
  auto it = std::lower_bound(reads_.begin(), reads_.end(), account,
                            [](const WorkchainAccountRead& a, const td::Bits256& b) { return a.account < b; });
  // expected_read established begin <= it < end; the distance is a valid index.
  read_seen_[static_cast<std::size_t>(it - reads_.begin())] = true;
  return td::Status::OK();
}
inline td::Status WorkchainAccountAccess::record_write(const td::Bits256& account) {
  if (failure_) return fail(failure_);
  if (finished_) return fail("account access ledger already finished");
  auto it = std::lower_bound(writes_.begin(), writes_.end(), account);
  if (it == writes_.end() || *it != account) return fail("undeclared account write");
  auto read = std::lower_bound(reads_.begin(), reads_.end(), account,
                              [](const WorkchainAccountRead& a, const td::Bits256& b) { return a.account < b; });
  // create established that every write key has exactly one read declaration.
  if (!read_seen_[static_cast<std::size_t>(read - reads_.begin())]) {
    return fail("write attempted before authenticated old-account read");
  }
  write_seen_[static_cast<std::size_t>(it - writes_.begin())] = true;
  return td::Status::OK();
}
inline td::Status WorkchainAccountAccess::finish(const std::vector<td::Bits256>& actual_changed_accounts,
                                               const std::vector<td::Bits256>& participant_accounts) {
  if (failure_) return fail(failure_);
  if (finished_) return fail("account access ledger already finished");
  if (std::find(read_seen_.begin(), read_seen_.end(), false) != read_seen_.end()) {
    return fail("declared account read was not verified");
  }
  if (std::find(write_seen_.begin(), write_seen_.end(), false) != write_seen_.end()) {
    return fail("declared account write was not performed");
  }
  if (actual_changed_accounts != writes_) return fail("actual account changes differ from write set");
  if (participant_accounts != writes_) return fail("participant records differ from write set");
  finished_ = true;
  return td::Status::OK();
}

}  // namespace block
