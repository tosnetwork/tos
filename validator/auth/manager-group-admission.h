#pragma once
#include <cstdint>
#include <optional>
#include <string>

namespace tos::auth {
// When a validator group may be created, on a chain that has activated the
// design, and what to do about one that was refused because it could not be.
//
// Two conditions have to hold before such a group exists, and they are
// established by two unrelated asynchronous reads that can complete in either
// order:
//
//   the cleanup records are loaded -- a group created before that could have
//   its own consensus directory deleted under it;
//
//   this node's chain context is established -- without it the committee the
//   group would run under cannot be derived, and the domain it would be checked
//   against would have to come from the registry being checked.
//
// Group creation itself is driven by a new masterchain block. That is the part
// which makes ordering a liveness question rather than a detail: if the context
// is late, every group is refused, and on a chain whose validators are all in
// that state the block that would drive the next attempt is the one none of
// them is producing. Nothing asks again, and the chain does not start.
//
// So a refusal is remembered here, and whichever of the two conditions arrives
// last says so. The manager holds the conditions -- the context is its own
// established context and is passed in rather than mirrored, because a second
// copy of that fact is a second answer waiting to differ from the first.
class GroupAdmissionGate {
  bool cleanup_loaded_ = false;
  bool deferred_ = false;

 public:
  // A group was refused only because the context had not arrived.
  void defer_groups() {
    deferred_ = true;
  }
  bool groups_deferred() const {
    return deferred_;
  }
  // The startup barrier: from here on, any group is created after the cleanup
  // records were loaded.
  void cleanup_records_loaded() {
    cleanup_loaded_ = true;
  }
  bool cleanup_records_are_loaded() const {
    return cleanup_loaded_;
  }
  // Whether a refused group must be created now. True at most once per refusal,
  // so two arrivals do not drive two passes, and never before both conditions
  // hold. `context` is the caller's own established context.
  bool create_deferred_groups(bool context) {
    if (!deferred_ || !cleanup_loaded_ || !context) {
      return false;
    }
    deferred_ = false;
    return true;
  }
};

// How long to wait before reading the zero state again.
//
// A read that failed once must not leave a node unable to validate until
// somebody restarts it: the zero state is fetched through the archive, which can
// answer with a transient error, and the only consumer of the answer is a gate
// that refuses every session without it. The interval doubles and then stops
// growing -- bounded in rate rather than in attempts, because a bounded number
// of attempts is the same permanent stall arriving later, and what is being
// waited on is a condition outside repair is expected to clear.
//
// Zero means nothing has failed yet; the first wait is the floor.
double next_chain_context_retry(double previous);

constexpr double chain_context_retry_floor = 1.0;
constexpr double chain_context_retry_ceiling = 16.0;

// One failed read owns one delayed retry. Admission may keep asking for a
// context while that delay is running, but those asks do not start a read and
// do not create another timer. The generation prevents an older delayed
// callback from consuming a newer retry after the first one has fired.
struct ChainContextRetryTicket {
  std::uint64_t generation = 0;
  double delay = 0.0;
};

class ChainContextRetryGate {
  double delay_ = 0.0;
  bool scheduled_ = false;
  std::uint64_t generation_ = 0;

 public:
  bool read_may_start() const;
  std::optional<ChainContextRetryTicket> failed();
  bool due(std::uint64_t generation);
  void succeeded();
  bool retry_scheduled() const { return scheduled_; }
  double retry_delay() const { return delay_; }
  std::uint64_t generation() const { return generation_; }
};
}  // namespace tos::auth
