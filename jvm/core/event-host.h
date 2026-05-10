/*
    JVM Workchain — deterministic event host adapter.

    Avata's java.lang.Event native API emits up to four 32-byte topics plus an
    arbitrary byte payload. This adapter records the ordered event list for one
    transaction and exposes nested snapshots so failed calls can roll back
    emitted events with storage writes.
*/
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "jvm/core/storage-cell-host.h"  // kJvmStorageValueChunkBytes
#include "td/utils/Status.h"
#include "vm/cells.h"

struct AvataEventHost;

namespace jvm_workchain {

constexpr std::size_t kJvmEventTopicBytes = 32;
constexpr std::size_t kJvmEventMaxTopics = 4;
// Round 149 MEDIUM fix: cap event data at the maximum size the
// downstream encode_jvm_storage_value (which builds the chunk
// chain stored under the event payload) can actually represent.
// The encoder reserves a 16-cell wrapper margin under
// vm::CellTraits::max_depth (1024), so it accepts at most
// (1024 - 16) * 127 = 128016 bytes.  Pre-fix kJvmEventDataMaxBytes
// was 1 MiB, so payloads in (128016, 1048576] bytes were copied
// through Avata execution, accepted by the event host snapshot,
// and only failed at build_jvm_event_action_list — converting a
// successful contract call into sk_bad_state and billing only
// kJvmAdmissionGasFloor for unbounded validator memory/copy
// work.  Sizing this constant to the encoder's effective limit
// makes the event host reject the payload up-front under the
// caller's own gas budget.
constexpr std::size_t kJvmEventDataMaxBytes =
    (vm::CellTraits::max_depth - 16) * kJvmStorageValueChunkBytes;

// Round 150 MEDIUM fix: cap the per-tx event count so the linked
// action-list spine in build_jvm_event_action_list cannot exceed
// vm::CellTraits::max_depth.  Depth model: each event payload is
// itself a chunk chain of up to (max_depth - 16) = 1008 cells.
// Each action-list node refs the prior list node and the event
// message, adding one to depth per event.  For N events of
// max-depth payloads the list-root depth is 1008 + N + 2 (the
// +2 covers the message header + payload wrapper cells).  To
// keep us comfortably under max_depth = 1024 even when every
// event hits the per-event size cap, gate the per-tx event
// count at kJvmEventCountMax = 12 (yields max list-root depth
// of 1022, leaving a 2-cell margin for downstream wrappers).
// Pre-fix the only check was per-event size; a contract emitting
// 16+ max-sized events succeeded through Avata execution and
// the late build_jvm_event_action_list null-return turned the
// call into sk_bad_state with kJvmAdmissionGasFloor billing —
// repeatable underbilled validator memory + copy work.
constexpr std::size_t kJvmEventCountMax = 12;
constexpr std::uint32_t kJvmEventPayloadMagic = 0x4a564d45;  // "JVME"
constexpr std::uint8_t kJvmEventPayloadSchemaVersion = 1;

using JvmEventTopic = std::array<std::uint8_t, kJvmEventTopicBytes>;
using JvmEventData = std::vector<std::uint8_t>;

struct JvmEvent {
    std::vector<JvmEventTopic> topics;
    JvmEventData data;
};

class JvmEventHost {
 public:
    const std::vector<JvmEvent>& events() const;

    td::Status emit(const std::vector<JvmEventTopic>& topics,
                    const JvmEventData& data);
    td::Status begin_transaction();
    td::Status commit_transaction();
    td::Status rollback_transaction();

 private:
    std::vector<JvmEvent> events_;
    std::vector<std::size_t> snapshots_;
};

void configure_avata_event_host(JvmEventHost& events, AvataEventHost& host);

td::Ref<vm::Cell> encode_jvm_event_payload(const JvmEvent& event);
td::Result<JvmEvent> decode_jvm_event_payload(td::Ref<vm::Cell> cell);
td::Ref<vm::Cell> encode_jvm_event_message(const JvmEvent& event);
td::Ref<vm::Cell> build_jvm_event_action_list(
    const std::vector<JvmEvent>& events);

}  // namespace jvm_workchain
