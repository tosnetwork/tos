#pragma once

#include <atomic>
#include <cstdint>

namespace tos::health {
// Bounded node-state gauges the validator manager refreshes once per second:
// validator-set membership and leader-window duty counters, the depth and
// oldest wait of the manager's real waiter queues, and the storage position
// (disk space under the database root, garbage-collection and persistent-state
// seqnos). Every field is an independent relaxed atomic gauge or counter; the
// observation clock tells a reader how fresh the set is. Nothing here is
// invented: a queue that does not exist is not listed, and a duty denominator
// is only the protocol's own leader-window assignment.
struct NodeStateGauges {
  std::atomic<std::uint64_t> observed_unix_seconds{0};
  std::atomic<bool> validator_member{false};
  // Leader windows the collator schedule assigned to this node, and how each
  // ended before production could start.
  std::atomic<std::uint64_t> leader_windows_assigned{0};
  std::atomic<std::uint64_t> leader_windows_suppressed_behind{0};
  std::atomic<std::uint64_t> leader_windows_superseded{0};
  struct Queue {
    std::atomic<std::uint64_t> depth{0};
    std::atomic<std::uint64_t> oldest_age_ms{0};
  } block_data_waiters, state_waiters, shard_client_waiters;
  std::atomic<bool> storage_valid{false};
  // Steady-clock time of the last successful disk sample; the publisher
  // turns storage_valid off when it is older than the sample TTL.
  std::atomic<std::uint64_t> storage_sampled_steady_ms{0};
  std::atomic<std::uint64_t> db_total_bytes{0};
  std::atomic<std::uint64_t> db_free_bytes{0};
  std::atomic<std::uint32_t> gc_seqno{0};
  std::atomic<std::uint32_t> persistent_state_seqno{0};
};
inline NodeStateGauges node_state;
}  // namespace tos::health
