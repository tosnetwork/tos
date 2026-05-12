/*
    JVM Workchain — deterministic outbound-message host adapter.

    Avata's java.lang.System.sendMessage native API stages internal
    messages whose action_send_msg cells land in WorkchainComputeOutput.
    action_list after commit. This adapter records the ordered message
    list for one transaction and exposes nested snapshots so failed
    calls roll back outbound messages alongside storage writes and
    events.

    Message wire shape (matches `try_action_send_msg` expectations):

      action_send_msg#0ec3c86d mode:(## 8) out_msg:^MessageRelaxed
      MessageRelaxed.info = int_msg_info{
          ihr_disabled = 1, bounce = 0, bounced = 0,
          src = addr_none$00 (filled in by check_replace_src_addr),
          dest = addr_std$10 (workchain, account_id),
          value = CurrencyCollection{tomis from value_be, extra=Nothing},
          ihr_fee = 0, fwd_fee = 0,
          created_lt = 0, created_at = 0
      }
      MessageRelaxed.init = Nothing
      MessageRelaxed.body = ^body_cell
*/
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "td/utils/Status.h"
#include "vm/cells.h"

struct AvataMessageHost;

namespace jvm_workchain {

constexpr std::size_t kJvmMessageAddressBytes = 32;
constexpr std::size_t kJvmMessageValueBytes = 32;

// Body payload is bounded by the same depth budget as event payloads;
// the underlying chunk-chain encoder reserves a 16-cell wrapper margin.
constexpr std::size_t kJvmMessageBodyMaxBytes = 128016;

// Per-tx message count cap.  Each outbound message contributes one
// action_send_msg node to the linked action_list; combined with up to
// kJvmEventCountMax events (12), the spine must stay under
// vm::CellTraits::max_depth - 16 = 1008.  Set the message cap so the
// worst case (12 max-depth events + 12 messages) leaves head-room.
constexpr std::size_t kJvmMessageCountMax = 12;

struct JvmOutboundMessage {
    std::int32_t dest_workchain{0};
    std::array<std::uint8_t, kJvmMessageAddressBytes> dest_addr{};
    std::array<std::uint8_t, kJvmMessageValueBytes> value_be{};
    std::vector<std::uint8_t> body;
};

class JvmMessageHost {
 public:
    const std::vector<JvmOutboundMessage>& messages() const;

    td::Status send(std::int32_t dest_workchain,
                    const std::array<std::uint8_t, kJvmMessageAddressBytes>&
                        dest_addr,
                    const std::array<std::uint8_t, kJvmMessageValueBytes>&
                        value_be,
                    const std::vector<std::uint8_t>& body);
    td::Status begin_transaction();
    td::Status commit_transaction();
    td::Status rollback_transaction();

 private:
    std::vector<JvmOutboundMessage> messages_;
    std::vector<std::size_t> snapshots_;
};

void configure_avata_message_host(JvmMessageHost& messages,
                                  AvataMessageHost& host);

// Serialize one outbound message as an action_send_msg cell.  Returns
// null on encoding failure (oversize body, bad value, etc.).
td::Ref<vm::Cell> encode_jvm_outbound_action(const JvmOutboundMessage& msg);

// Build the combined action_list cell that splices the
// already-encoded event action list with all outbound messages.  The
// event list is consumed first so events emitted before a send
// observe in-order at the consumer side; outbound messages append
// after events.
td::Ref<vm::Cell> build_jvm_combined_action_list(
    td::Ref<vm::Cell> event_action_list,
    const std::vector<JvmOutboundMessage>& outbound_messages);

}  // namespace jvm_workchain
