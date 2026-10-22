/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The outbound message queue limits of ConfigParam 43, read through the real
// configuration parser and applied through the rules the collator and the
// validator share.
#include <optional>

#include "block/block.h"
#include "block/mc-config.h"
#include "td/utils/tests.h"
#include "validator/impl/out-msg-queue-limits.h"
#include "vm/cells/CellBuilder.h"

using namespace tos::validator;

namespace {

td::Ref<vm::CellSlice> size_limits_v3(td::uint32 hard_limit, td::uint32 soft_limit) {
  vm::CellBuilder cb;
  cb.store_long(0x03, 8);
  cb.store_long(1 << 21, 32).store_long(1 << 13, 32).store_long(1000, 32).store_long(512, 16);
  cb.store_long(65535, 32).store_long(512, 16);
  cb.store_long(1 << 16, 32).store_long(1 << 11, 32).store_long(256, 32).store_long(256, 32);
  cb.store_long(2, 32).store_long(8, 8).store_long(26, 32);
  cb.store_long(0, 1);
  cb.store_long((1 << 21) * 5 / 2, 32).store_long((1 << 13) * 5 / 2, 32);
  cb.store_long(hard_limit, 32).store_long(soft_limit, 32);
  return vm::load_cell_slice_ref(cb.finalize());
}

block::SizeLimitsConfig parse(td::Ref<vm::CellSlice> cs) {
  auto r = block::Config::do_get_size_limits_config(std::move(cs));
  CHECK(r.is_ok());
  return r.move_as_ok();
}

struct CollationResult {
  td::uint64 queue_size;
  size_t deferred;
};

// The collator's decision for new outbound messages, including outputs of special
// accounts: once the queue reaches the hard limit, further outputs are deferred.
// Synthetic mint/recover inputs are immediately delivered within the masterchain
// and do not add entries to its outbound queue.
CollationResult collate(td::uint64 queue_size, size_t message_count, td::uint64 hard_limit) {
  CollationResult result{queue_size, 0};
  for (size_t i = 0; i < message_count; ++i) {
    if (out_msg_queue_reached_hard_limit(result.queue_size, 0, hard_limit)) {
      ++result.deferred;
    } else {
      ++result.queue_size;
    }
  }
  return result;
}

}  // namespace

TEST(OutMsgQueueLimits, ConfigCarriesBothLimits) {
  auto limits = parse(size_limits_v3(100, 60));
  CHECK(limits.out_msg_queue_size_hard_limit == 100);
  CHECK(limits.out_msg_queue_size_soft_limit == 60);
  // Without ConfigParam 43 the node defaults apply.
  auto defaults = parse({});
  CHECK(defaults.out_msg_queue_size_hard_limit == 18000);
  CHECK(defaults.out_msg_queue_size_soft_limit == 12000);
}

TEST(OutMsgQueueLimits, CollatorDefersOverflowAndHoldsTheHardLimit) {
  auto limits = parse(size_limits_v3(100, 60));
  auto result = collate(0, 5000, limits.out_msg_queue_size_hard_limit);
  CHECK(result.queue_size == 100);
  CHECK(result.deferred == 4900);

  // Already at the limit: everything ordinary is deferred, nothing is lost.
  result = collate(100, 7, limits.out_msg_queue_size_hard_limit);
  CHECK(result.queue_size == 100);
  CHECK(result.deferred == 7);

  result = collate(99, 4, limits.out_msg_queue_size_hard_limit);
  CHECK(result.queue_size == 100);
  CHECK(result.deferred == 3);

  // Messages taken from the dispatch queue count against the limit before they land.
  CHECK(out_msg_queue_reached_hard_limit(95, 5, 100));
  CHECK(!out_msg_queue_reached_hard_limit(95, 4, 100));
  CHECK(out_msg_queue_reached_hard_limit(1, std::numeric_limits<td::uint64>::max(), 100));
}

TEST(OutMsgQueueLimits, ValidatorRejectsQueueOverHardLimit) {
  auto limits = parse(size_limits_v3(100, 60));
  td::uint64 hard = limits.out_msg_queue_size_hard_limit;
  // An honest block at or under the limit is accepted.
  CHECK(!out_msg_queue_exceeds_hard_limit(0, hard, td::uint64{0}));
  CHECK(!out_msg_queue_exceeds_hard_limit(100, hard, td::uint64{40}));
  // One entry over is refused.
  CHECK(out_msg_queue_exceeds_hard_limit(101, hard, td::uint64{40}));
  // A queue already over the limit (after a merge) may stay there but not grow.
  CHECK(!out_msg_queue_exceeds_hard_limit(150, hard, td::uint64{150}));
  CHECK(!out_msg_queue_exceeds_hard_limit(120, hard, td::uint64{150}));
  CHECK(out_msg_queue_exceeds_hard_limit(151, hard, td::uint64{150}));
  // Without a size recorded in the previous state there is no such allowance.
  CHECK(out_msg_queue_exceeds_hard_limit(150, hard, std::nullopt));
  CHECK(!out_msg_queue_exceeds_hard_limit(100, hard, std::nullopt));
}

TEST(OutMsgQueueLimits, TransitAdmissionReservesDispatchSlots) {
  auto limits = parse(size_limits_v3(18000, 12000));
  const auto hard = limits.out_msg_queue_size_hard_limit;
  // A foreign transit adds one queue entry, unlike a final delivery or an
  // own-queue requeue. The old block is valid at 18000; one more is invalid.
  CHECK(!out_msg_queue_exceeds_hard_limit(hard, hard, hard));
  CHECK(out_msg_queue_exceeds_hard_limit(hard + 1, hard, hard));
  CHECK(out_msg_queue_postpone_transit(false, false, false, hard, 0, hard));
  CHECK(!out_msg_queue_postpone_transit(false, false, false, hard - 1, 0, hard));

  // Dispatch entries have already been removed from DispatchQueue and cannot
  // be deferred again. Transit imports must not consume their reserved slots.
  CHECK(out_msg_queue_postpone_transit(false, false, false, hard - 5, 5, hard));
  CHECK(!out_msg_queue_postpone_transit(false, false, false, hard - 5, 4, hard));

  // Full queues must still drain, re-route their existing entries after a merge,
  // and skip messages a neighbor has not yet cleaned up after delivery.
  CHECK(!out_msg_queue_postpone_transit(false, false, true, hard, 0, hard));
  CHECK(!out_msg_queue_postpone_transit(false, true, false, hard, 0, hard));
  CHECK(!out_msg_queue_postpone_transit(true, false, false, hard, 0, hard));
}

TEST(OutMsgQueueLimits, MultiHopRoutingNeedsTransitCapacity) {
  // Five-bit shards can require more than one four-bit routing hop. This is
  // enabled by a future workchain split-depth configuration, even though the
  // initial genesis limits the basechain to two split bits.
  const tos::AccountIdPrefixFull src{0, 0x0000000000000000ULL};
  const tos::AccountIdPrefixFull dest{0, 0xf800000000000000ULL};
  const tos::ShardIdFull source_shard{0, 0x0400000000000000ULL};
  const tos::ShardIdFull relay_shard{0, 0xf400000000000000ULL};
  auto route = block::perform_hypercube_routing(src, dest, source_shard);
  CHECK(route.first >= 0 && route.second <= 96);
  auto cur = block::interpolate_addr(src, dest, route.first);
  auto next = block::interpolate_addr(src, dest, route.second);
  CHECK(tos::shard_contains(source_shard, cur));
  CHECK(tos::shard_contains(relay_shard, next));
  CHECK(!tos::shard_contains(relay_shard, dest));
  auto onward = block::perform_hypercube_routing(next, dest, relay_shard);
  CHECK(onward.first >= 0 && onward.second <= 96);
  auto final_hop = block::interpolate_addr(next, dest, onward.second);
  CHECK(final_hop.workchain == dest.workchain && final_hop.account_id_prefix == dest.account_id_prefix);
  CHECK(out_msg_queue_postpone_transit(false, tos::shard_contains(relay_shard, cur),
                                       tos::shard_contains(relay_shard, dest), 18000, 0, 18000));
}

TEST(OutMsgQueueLimits, SoftLimitOpensDeferral) {
  auto limits = parse(size_limits_v3(100, 60));
  td::uint64 soft = limits.out_msg_queue_size_soft_limit;
  CHECK(!out_msg_queue_soft_limit_exceeded(td::uint64{60}, soft));
  CHECK(out_msg_queue_soft_limit_exceeded(td::uint64{61}, soft));
  CHECK(!out_msg_queue_soft_limit_exceeded(std::nullopt, soft));

  // Under the soft limit the first message and special accounts cannot be deferred.
  CHECK(deferral_refusal(true, false, false, false) == DeferralRefusal::FirstMessage);
  CHECK(deferral_refusal(false, true, false, false) == DeferralRefusal::SpecialAccount);
  CHECK(deferral_refusal(false, false, false, false) == DeferralRefusal::None);
  // Over it, or with a non-empty dispatch queue, any message may be deferred.
  CHECK(deferral_refusal(true, true, false, true) == DeferralRefusal::None);
  // An earlier deferred message of the account allows the rest to be deferred.
  CHECK(deferral_refusal(true, true, true, false) == DeferralRefusal::None);
}

TEST(OutMsgQueueLimits, LongQueueBlocksMerge) {
  auto limits = parse(size_limits_v3(100, 60));
  td::uint64 hard = limits.out_msg_queue_size_hard_limit;
  CHECK(!out_msg_queue_blocks_merge(0, hard));
  CHECK(!out_msg_queue_blocks_merge(50, hard));
  CHECK(out_msg_queue_blocks_merge(51, hard));
  auto defaults = parse({});
  CHECK(!out_msg_queue_blocks_merge(9000, defaults.out_msg_queue_size_hard_limit));
  CHECK(out_msg_queue_blocks_merge(9001, defaults.out_msg_queue_size_hard_limit));
}

TEST(OutMsgQueueLimits, ConfigWithoutQueueLimitsIsRefused) {
  vm::CellBuilder cb;
  auto full = size_limits_v3(100, 60);
  cb.append_cellslice(full);
  auto cell = cb.finalize();
  vm::CellSlice cs{vm::NoVm(), cell};
  CHECK(cs.size() >= 64);
  vm::CellBuilder truncated;
  truncated.store_bits(cs.data_bits(), cs.size() - 64);
  CHECK(block::Config::do_get_size_limits_config(vm::load_cell_slice_ref(truncated.finalize())).is_error());
}
