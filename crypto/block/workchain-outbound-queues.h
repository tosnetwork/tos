#pragma once

#include <algorithm>
#include <set>

#include "block/transaction.h"
#include "block/block-parse.h"
#include "block/workchain-participant-lt.h"

namespace block {

struct WorkchainOutboundQueueRoots {
  td::Ref<vm::Cell> descriptors, outgoing, dispatch;
};

struct WorkchainQueuedOutput {
  NewOutMsg output;
  bool defer;
};

struct WorkchainOutboundQueuePolicy {
  tos::ShardIdFull shard;
  tos::UnixTime now;
  int global_version;
  bool metadata_enabled, deferring_enabled;
  std::uint64_t max_outputs;
};

struct WorkchainOutboundQueueResult {
  WorkchainOutboundQueueRoots roots;
  std::uint64_t queued = 0, deferred = 0;
};

// Post-admission enqueue-only construction using Native queue encodings.
// Roots are the host's current private queues, after earlier Native processing,
// not necessarily the previous block's queues. Unprocessed dispatch sources
// come from that same processing pass. All closures/counts require prior
// source-aware authentication/admission; this is not a voting error classifier.
//
// The host must reconstruct the complete participant transactions and authorize
// every source/processing-account exception before calling. Membership below
// does not itself authorize a foreign-source bounce. Optional Native deferral
// choices are checked, not made into an engine policy or a new wire default.
// Exceptions propagate with provenance; only private dictionaries are changed.
inline td::Result<WorkchainOutboundQueueResult> build_workchain_outbound_queues(
    const WorkchainOutboundQueueRoots& old, const std::vector<WorkchainQueuedOutput>& supplied_outputs,
    const std::set<td::Bits256>& unprocessed_dispatch_sources, const WorkchainOutboundQueuePolicy& policy) {
  if (policy.shard.workchain < 0 || policy.shard.shard != tos::shardIdAll ||
      policy.global_version < transaction::Transaction::kStorageParticipantMinGlobalVersion ||
      supplied_outputs.size() > policy.max_outputs || old.descriptors.is_null() || old.outgoing.is_null() ||
      old.dispatch.is_null()) {
    return td::Status::Error("invalid outbound queue context");
  }
  for (const auto& item : supplied_outputs) {
    if (item.output.msg.is_null() || item.output.trans.is_null()) {
      return td::Status::Error("missing outbound transaction or message");
    }
  }
  auto outputs = supplied_outputs;
  std::sort(outputs.begin(), outputs.end(), [](const auto& a, const auto& b) { return a.output < b.output; });
  tlb::Aug_OutMsgDescr augmentation(policy.global_version);
  vm::AugmentedDictionary descriptors(vm::load_cell_slice_ref(old.descriptors), 256, augmentation);
  vm::AugmentedDictionary outgoing(vm::load_cell_slice_ref(old.outgoing), 352, tlb::aug_OutMsgQueue);
  vm::AugmentedDictionary dispatch(vm::load_cell_slice_ref(old.dispatch), 256, tlb::aug_DispatchQueue);
  WorkchainOutboundQueueResult result;
  for (const auto& item : outputs) {
    const auto& output = item.output;
    gen::Transaction::Record tx;
    gen::CommonMsgInfo::Record_int_msg_info info;
    gen::MsgAddressInt::Record_addr_std source, destination;
    if (output.msg_env_from_dispatch_queue.not_null() || !tlb::unpack_cell(output.trans, tx) ||
        !tlb::unpack_cell_inexact(output.msg, info) || !tlb::csr_unpack(info.src, source) ||
        !tlb::csr_unpack(info.dest, destination) || source.anycast->size() != 1 || destination.anycast->size() != 1 ||
        source.workchain_id != policy.shard.workchain || !info.ihr_disabled ||
        info.created_at != policy.now || tx.now != policy.now ||
        output.msg_idx >= static_cast<unsigned>(tx.outmsg_cnt)) {
      return td::Status::Error("invalid new outbound message or transaction");
    }
    TRY_RESULT(first_lt, participant_lt_detail::checked_add(tx.lt, 1));
    TRY_RESULT(expected_lt, participant_lt_detail::checked_add(first_lt, output.msg_idx));
    if (info.created_lt != output.lt || output.lt != expected_lt) {
      return td::Status::Error("outbound message logical time mismatch");
    }
    // The successfully decoded uint15 count and preceding index comparison
    // establish representability before narrowing the message dictionary key.
    vm::Dictionary transaction_messages(tx.r1.out_msgs, 15);
    auto bound_message = transaction_messages.lookup_ref(td::BitArray<15>(output.msg_idx));
    if (bound_message.is_null() || bound_message->get_hash() != output.msg->get_hash()) {
      return td::Status::Error("outbound message is not in the declared transaction");
    }
    td::optional<MsgMetadata> metadata;
    if (policy.metadata_enabled) metadata = MsgMetadata{0, policy.shard.workchain, tx.account_addr, tx.lt};
    if (output.metadata != metadata) return td::Status::Error("outbound metadata differs from processing account");
    const td::Bits256 actual_source = source.address;
    bool required = dispatch.lookup(actual_source).not_null() || unprocessed_dispatch_sources.count(actual_source);
    if ((required && !item.defer) || (item.defer && !required && (!policy.deferring_enabled || output.msg_idx == 0))) {
      return td::Status::Error("outbound deferral violates actual-source ordering");
    }
    auto remaining = tlb::t_Tomis.as_integer(info.fwd_fee);
    if (remaining.is_null() || !remaining->unsigned_fits_bits(256)) {
      return td::Status::Error("invalid remaining outbound forwarding fee");
    }
    auto src_prefix = tlb::t_MsgAddressInt.get_prefix(info.src);
    auto dst_prefix = tlb::t_MsgAddressInt.get_prefix(info.dest);
    if (!src_prefix.is_valid() || !dst_prefix.is_valid()) return td::Status::Error("invalid outbound route prefix");
    auto route = perform_hypercube_routing(src_prefix, dst_prefix, policy.shard);
    if (static_cast<unsigned>(route.first) > 96 || static_cast<unsigned>(route.second) > 96) {
      return td::Status::Error("invalid new outbound route");
    }
    tlb::MsgEnvelope::Record_std envelope{item.defer ? 0 : route.first, item.defer ? 0 : route.second,
                                        remaining, output.msg, {}, metadata};
    td::Ref<vm::Cell> envelope_root;
    if (!tlb::pack_cell(envelope_root, envelope)) return td::Status::Error("cannot encode outbound envelope");
    vm::CellBuilder record;
    record.store_long(item.defer ? 0b10100 : 0b001, item.defer ? 5 : 3).store_ref(envelope_root).store_ref(output.trans);
    if (!descriptors.set(output.msg->get_hash().bits(), 256, vm::load_cell_slice(record.finalize()),
                         vm::Dictionary::SetMode::Add)) {
      return td::Status::Error("duplicate outbound descriptor");
    }
    vm::CellBuilder enqueued;
    enqueued.store_long(output.lt, 64).store_ref(envelope_root);
    if (item.defer) {
      vm::Dictionary account_queue(64);
      std::uint64_t count;
      if (!unpack_account_dispatch_queue(dispatch.lookup(actual_source), account_queue, count)) {
        return td::Status::Error("invalid authenticated account dispatch queue");
      }
      TRY_RESULT(next_count, participant_lt_detail::checked_add(count, 1));
      if (next_count >= (std::uint64_t{1} << 48)) return td::Status::Error("account dispatch count exceeds wire width");
      if (!account_queue.set_builder(td::BitArray<64>(output.lt), enqueued, vm::Dictionary::SetMode::Add)) {
        return td::Status::Error("duplicate account dispatch logical time");
      }
      vm::CellBuilder account_record;
      if (!account_queue.append_dict_to_bool(account_record) || !account_record.store_long_bool(next_count, 48) ||
          !dispatch.set(actual_source, account_record.as_cellslice_ref())) {
        return td::Status::Error("cannot encode account dispatch queue");
      }
      TRY_RESULT(next, participant_lt_detail::checked_add(result.deferred, 1));
      result.deferred = next;
    } else {
      td::BitArray<352> key;
      if (!compute_out_msg_queue_key(envelope_root, key)) return td::Status::Error("cannot derive outbound queue key");
      if (!outgoing.set_builder(key.bits(), 352, enqueued, vm::Dictionary::SetMode::Add)) {
        return td::Status::Error("duplicate outbound queue message");
      }
      TRY_RESULT(next, participant_lt_detail::checked_add(result.queued, 1));
      result.queued = next;
    }
  }
  result.roots = {descriptors.get_wrapped_dict_root(), outgoing.get_wrapped_dict_root(), dispatch.get_wrapped_dict_root()};
  return result;
}

}  // namespace block
