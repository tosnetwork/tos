#pragma once

#include <algorithm>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/workchain-block-execution.h"

namespace block {

struct WorkchainNativeInboxPlan {
  std::vector<td::Ref<vm::Cell>> envelopes;
  std::uint64_t after_lt;
};

// Post-admission final-import planning, not queue authentication or disposal.
// Every message must address an explicitly allowed role; nothing is filtered.
// Native bodies do not inherit the ordinary-only user-candidate profile.
// The dictionary decoder retains legacy VM-to-Status conversion. This vector
// planner has no exception conversion: a Result signature is not a no-throw
// guarantee, including when invoked with an active VM state interface. The
// source-aware enclosing host must contain acquisition/VM failures separately.
namespace native_inbox_detail {
inline td::Result<WorkchainNativeInboxPlan> plan_envelopes(
    const std::vector<td::Ref<vm::Cell>>& envelopes, tos::WorkchainId workchain,
    const std::vector<td::Bits256>* recipients, std::uint64_t after_lt,
    std::uint64_t max_inbound) {
  if (workchain < 0 || (recipients && (recipients->empty() ||
      !std::is_sorted(recipients->begin(), recipients->end()) ||
      std::adjacent_find(recipients->begin(), recipients->end()) != recipients->end()))) {
    return td::Status::Error("invalid native inbox role set");
  }
  if (envelopes.size() > max_inbound) return td::Status::Error("native inbox exceeds admitted count");
  WorkchainNativeInboxPlan plan{{}, after_lt};
  for (const auto& cell : envelopes) {
    tlb::MsgEnvelope::Record_std envelope;
    gen::CommonMsgInfo::Record_int_msg_info info;
    gen::MsgAddressInt::Record_addr_std destination;
    if (!tlb::unpack_cell(cell, envelope) || !tlb::unpack_cell_inexact(envelope.msg, info) ||
        !gen::csr_unpack(info.dest, destination) || destination.anycast->size() != 1 ||
        destination.workchain_id != workchain ||
        (recipients && !std::binary_search(recipients->begin(), recipients->end(), destination.address))) {
      return td::Status::Error("native inbox destination is not an allowed final-import role");
    }
    plan.after_lt = std::max<std::uint64_t>(plan.after_lt, info.created_lt);
    if (envelope.emitted_lt) plan.after_lt = std::max(plan.after_lt, envelope.emitted_lt.value());
  }
  plan.envelopes = envelopes;
  return plan;
}

inline td::Result<WorkchainNativeInboxPlan> plan_inbox(
    td::Ref<vm::Cell> root, tos::WorkchainId workchain,
    const std::vector<td::Bits256>* recipients, std::uint64_t after_lt,
    std::uint64_t max_inbound) {
  TRY_RESULT(empty_plan, plan_envelopes({}, workchain, recipients, after_lt, max_inbound));
  if (root.is_null()) return empty_plan;
  // This is a count precheck only; prior admission must bound the full closure
  // and derived wrappers before semantic decoding traverses the dictionary.
  bool special = false;
  auto header = vm::load_cell_slice_special(root, special);
  if (special || header.size() != 48 || header.size_refs() != 1 ||
      header.fetch_ulong(32) != 0x57494e31 || header.fetch_ulong(15) > max_inbound) {
    return td::Status::Error("native inbox exceeds admitted count or profile");
  }
  TRY_RESULT(envelopes, decode_workchain_batch_inbound(root));
  return plan_envelopes(envelopes, workchain, recipients, after_lt, max_inbound);
}
}  // namespace native_inbox_detail

inline td::Result<WorkchainNativeInboxPlan> plan_workchain_native_envelopes(
    const std::vector<td::Ref<vm::Cell>>& envelopes, tos::WorkchainId workchain,
    const std::vector<td::Bits256>& recipients, std::uint64_t after_lt, std::uint64_t max_inbound) {
  return native_inbox_detail::plan_envelopes(envelopes, workchain, &recipients, after_lt, max_inbound);
}

inline td::Result<WorkchainNativeInboxPlan> plan_workchain_native_inbox(
    td::Ref<vm::Cell> root, tos::WorkchainId workchain, const std::vector<td::Bits256>& recipients,
    std::uint64_t after_lt, std::uint64_t max_inbound) {
  return native_inbox_detail::plan_inbox(root, workchain, &recipients, after_lt, max_inbound);
}

// Explicit disposal entry: preserve every final message, including destinations
// outside the entry roles. The caller must dispose of these, never filter them.
// This does not admit transit messages, anycast, or another workchain.
inline td::Result<WorkchainNativeInboxPlan> plan_workchain_disposal_inbox(
    td::Ref<vm::Cell> root, tos::WorkchainId workchain, std::uint64_t after_lt, std::uint64_t max_inbound) {
  return native_inbox_detail::plan_inbox(root, workchain, nullptr, after_lt, max_inbound);
}

}  // namespace block
