/*
    JVM Workchain — read-only helpers that extract the inbound message
    fields that the engine + Avata Context need.

    Sharing this between `dispatch-engine.cpp` (first-activation auth) and
    `avata-runtime.cpp` (Context plumbing) keeps the unpack rules in one
    place and avoids the two paths drifting apart.  The function is
    `noexcept` and returns a status — none of its callers can afford an
    uncaught VmError on the hot path.
*/
#pragma once

#include <array>
#include <cstdint>

#include "td/utils/Status.h"
#include "vm/cells.h"

namespace jvm_workchain {

struct ParsedInboundMessage {
    bool present{false};
    bool is_internal{false};
    // True iff `src` was a valid `addr_std$10` with `anycast=Nothing`.
    bool src_present{false};
    std::int32_t src_workchain{0};
    std::array<std::uint8_t, 32> src_addr{};
    // Attached tomis as a 32-byte big-endian unsigned integer (Uint256
    // wire layout).  Zero on external inbound or when value parsing fails.
    std::array<std::uint8_t, 32> value_be{};
};

/// Parse an inbound message cell into the fields the JVM engine + Avata
/// Context need. Returns the canonical ParsedInboundMessage on success.
///
/// The function never throws and never accepts a special (library) cell.
/// On any malformed input the corresponding ParsedInboundMessage flag stays
/// false; the caller decides whether that's a hard error.
td::Result<ParsedInboundMessage> parse_jvm_inbound_message(
    const td::Ref<vm::Cell>& inbound_message);

}  // namespace jvm_workchain
