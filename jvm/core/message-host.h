/*
    JVM Workchain — deterministic outbound-action host adapter.

    Two outbound action kinds, both staged through this single host:

      * SendMessage   — action_send_msg#0ec3c86d wrapping a
                        MessageRelaxed.int_msg_info to (dest_workchain,
                        dest_addr, value, body).  Mirrors TVM
                        SENDRAWMSG semantics.

      * CreateAccount — action_create_account#4a435241 carrying a raw
                        StateInit BOC for a brand-new account at the
                        emitter's own workchain.  The host action
                        phase (`Transaction::try_action_create_account`)
                        enforces `dest.workchain = account.workchain`,
                        so for wc=3 contracts createAccount always
                        targets wc=3.

    Both kinds are tracked in a single ordered vector so the resulting
    action_list reflects emission order; nested snapshots cover the
    whole vector so failed contract calls roll back outbound actions
    alongside storage writes and events.

    Per-tx action count: kJvmOutboundActionCountMax = 12 (combined
    across both kinds).  Combined with up to kJvmEventCountMax=12
    events the linked OutList spine still stays comfortably under
    vm::CellTraits::max_depth − 16 = 1008.

    Send wire shape (matches `try_action_send_msg`):

      action_send_msg#0ec3c86d mode:(## 8) out_msg:^MessageRelaxed
      MessageRelaxed.info = int_msg_info{
          ihr_disabled = 1, bounce = 0, bounced = 0,
          src = addr_none$00 (filled in by check_replace_src_addr),
          dest = addr_std$10 (workchain, account_id),
          value = CurrencyCollection{tomis from value_be, extra=Nothing},
          fwd_fee = 0, extra_flags = 0,
          created_lt = 0, created_at = 0
      }
      MessageRelaxed.init = Nothing
      MessageRelaxed.body = ^body_cell

    CreateAccount wire shape (matches `try_action_create_account`):

      action_create_account#4a435241 mode:(## 8)
          dest_addr:bits256
          state_init:^StateInit                 (caller-supplied BOC)
          value:Tomis                           (VarUInteger 16)
          body:(Maybe ^Cell)
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

// Body / state_init payload caps mirror the storage-value chunk-chain
// depth budget (max_depth − 16 = 1008 chunks × 127 bytes ≈ 128 KiB).
constexpr std::size_t kJvmMessageBodyMaxBytes = 128016;
constexpr std::size_t kJvmStateInitBocMaxBytes = 128016;

// Per-tx outbound action count cap (combined across both kinds).
constexpr std::size_t kJvmOutboundActionCountMax = 12;

// Legacy alias retained for any external consumer still naming the
// old single-kind constant.  New code should use the combined cap.
constexpr std::size_t kJvmMessageCountMax = kJvmOutboundActionCountMax;

enum class JvmOutboundActionKind : std::uint8_t {
    SendMessage = 0,
    CreateAccount = 1,
};

// Flat discriminated union — `kind` selects which subset of fields
// are meaningful.  Sticking to one struct (instead of `std::variant`)
// keeps the on-wire layout obvious and avoids extra dependencies.
struct JvmOutboundAction {
    JvmOutboundActionKind kind{JvmOutboundActionKind::SendMessage};

    // SendMessage: explicit destination workchain (int8 range).
    // CreateAccount: ignored; host action phase fills in the emitter's
    // own workchain.
    std::int32_t dest_workchain{0};

    std::array<std::uint8_t, kJvmMessageAddressBytes> dest_addr{};
    std::array<std::uint8_t, kJvmMessageValueBytes> value_be{};
    std::vector<std::uint8_t> body;

    // CreateAccount only: raw BOC of the StateInit cell to install on
    // the new account.  Empty for SendMessage.
    std::vector<std::uint8_t> state_init_boc;
};

// Backwards-compatible alias for the pre-Phase-H name.  Existing
// external consumers (none in-tree at this commit) keep compiling.
using JvmOutboundMessage = JvmOutboundAction;

class JvmMessageHost {
 public:
    /// Unified ordered list of outbound actions (preserves emission order).
    const std::vector<JvmOutboundAction>& actions() const;

    /// Backwards-compatible view: returns the same vector (since the
    /// new tagged-union shape is a superset of the pre-Phase-H one).
    /// New code should prefer `actions()`.
    const std::vector<JvmOutboundAction>& messages() const;

    td::Status send(std::int32_t dest_workchain,
                    const std::array<std::uint8_t, kJvmMessageAddressBytes>&
                        dest_addr,
                    const std::array<std::uint8_t, kJvmMessageValueBytes>&
                        value_be,
                    const std::vector<std::uint8_t>& body);

    td::Status create_account(
        const std::array<std::uint8_t, kJvmMessageAddressBytes>& dest_addr,
        const std::vector<std::uint8_t>& state_init_boc,
        const std::array<std::uint8_t, kJvmMessageValueBytes>& value_be,
        const std::vector<std::uint8_t>& body);

    td::Status begin_transaction();
    td::Status commit_transaction();
    td::Status rollback_transaction();

 private:
    std::vector<JvmOutboundAction> actions_;
    std::vector<std::size_t> snapshots_;
};

void configure_avata_message_host(JvmMessageHost& messages,
                                  AvataMessageHost& host);

// Serialize one outbound action (either kind) as its appropriate
// OutAction cell — either `action_send_msg#0ec3c86d` or
// `action_create_account#4a435241`.  Returns null on encoding failure
// (oversize body / state_init, malformed BOC, etc.).
td::Ref<vm::Cell> encode_jvm_outbound_action(const JvmOutboundAction& action);

// Build the combined action_list cell that splices the
// already-encoded event action list with all outbound actions in
// emission order.  Each outbound action becomes its own OutList node.
td::Ref<vm::Cell> build_jvm_combined_action_list(
    td::Ref<vm::Cell> event_action_list,
    const std::vector<JvmOutboundAction>& outbound_actions);

}  // namespace jvm_workchain
