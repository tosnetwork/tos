#pragma once

#include "td/utils/Status.h"
#include "td/utils/common.h"

namespace uno_workchain {

// Counts include dummy leaves. This tracks aggregate capacity only: callers
// must bind each reservation to its authenticated pending withdrawal record.
class LeafBudget {
 public:
  static constexpr td::uint64 capacity = td::uint64{1} << 32;
  static td::Result<LeafBudget> from_counts(td::uint64 next, td::uint64 reserved) {
    if (next > capacity || reserved > capacity - next) {
      return td::Status::Error("UNO leaf budget exceeds tree capacity");
    }
    return LeafBudget(next, reserved);
  }
  // capacity is an exhausted count, never a valid leaf insertion index.
  td::uint64 next_position() const { return next_; }
  td::uint64 reserved_refund_leaves() const { return reserved_; }
  td::uint64 available() const { return capacity - next_ - reserved_; }

  td::Result<LeafBudget> checked_append(td::uint64 count) const {
    if (count > available()) {
      return td::Status::Error("UNO append would consume reserved tree capacity");
    }
    return LeafBudget(next_ + count, reserved_);
  }
  td::Result<LeafBudget> checked_reserve(td::uint64 count) const {
    if (count > available()) {
      return td::Status::Error("UNO refund reservation exceeds tree capacity");
    }
    return LeafBudget(next_, reserved_ + count);
  }
  td::Result<LeafBudget> checked_release(td::uint64 count) const {
    if (count > reserved_) {
      return td::Status::Error("UNO refund reservation underflow");
    }
    return LeafBudget(next_, reserved_ - count);
  }
  td::Result<LeafBudget> checked_refund_append(td::uint64 count) const {
    TRY_RESULT(released, checked_release(count));
    return released.checked_append(count);
  }
  td::Result<LeafBudget> checked_prepare(td::uint64 main_leaves, td::uint64 refund_leaves) const {
    TRY_RESULT(appended, checked_append(main_leaves));
    return appended.checked_reserve(refund_leaves);
  }

 private:
  LeafBudget(td::uint64 next, td::uint64 reserved) : next_(next), reserved_(reserved) {}
  td::uint64 next_;
  td::uint64 reserved_;
};

}  // namespace uno_workchain
