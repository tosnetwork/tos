/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The outbound message queue limits of ConfigParam 43, read through the real
// configuration parser and applied through the rules the collator and the
// validator share.
#include <optional>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "td/actor/core/ActorExecuteContext.h"
#include "td/utils/tests.h"
#include "validator/impl/collator-impl.h"
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

namespace tos::validator {

// Exercise the real ordered import loop, transaction commit, queue dictionaries,
// frontier update and transit admission without network/state-fetch actors.
class CollatorQueueLimitsTestAccess {
 public:
  struct Options {
    td::uint64 hard = 2;
    td::uint64 old_size = 2;
    unsigned transit = 1;
    unsigned local = 1;
    bool size_recorded = true;
    bool stop_after_transit = false;
    bool timed_out = false;
    bool dispatch = false;
    bool requeue = false;
    bool foreign_final = false;
  };
  struct Result {
    td::uint64 queue_size;
    td::uint64 dictionary_size;
    tos::LogicalTime frontier;
    unsigned transactions;
    bool empty;
    // The final size satisfies the rule a validator applies to the candidate.
    bool valid;
    bool stopped;
  };

  static Result run(Options options) {
    const tos::ShardIdFull source{0, 0x0400000000000000ULL};
    const tos::ShardIdFull relay{0, 0xf400000000000000ULL};
    vm::AugmentedDictionary foreign{352, block::tlb::aug_OutMsgQueue};
    vm::AugmentedDictionary own{352, block::tlb::aug_OutMsgQueue};
    CHECK(options.local + static_cast<unsigned>(options.requeue) <= options.old_size);
    for (unsigned i = 0; i < options.transit; ++i) {
      put(foreign, source, 0, 0xf800000000000000ULL, 10 + i);
    }
    for (unsigned i = 0; i < options.local; ++i) {
      put(own, relay, 0xf000000000000000ULL, 0xf100000000000000ULL, 100 + i);
    }
    if (options.requeue) {
      // After a merge, an old intermediate address may now lie inside our shard.
      put(own, relay, 0xf000000000000000ULL, 0xf800000000000000ULL, 90, true);
    }
    if (options.foreign_final) {
      put(foreign, source, 0, 0xf100000000000000ULL, 50);
    }
    // These entries belong to the outbound queue but not our inbound merger.
    for (td::uint64 i = options.local + static_cast<unsigned>(options.requeue); i < options.old_size; ++i) {
      put(own, relay, 0xf000000000000000ULL, 0xf800000000000000ULL, 200 + i);
    }
    CollateParams params;
    params.shard = relay;
    params.hard_timeout = td::Timestamp::in(60);
    params.soft_timeout = td::Timestamp::in(60);
    Collator collator(std::move(params), {}, {}, {});
    td::actor::core::ActorExecuteContext context(&collator);
    td::actor::core::ActorExecuteContext::Guard context_guard(&context);
    collator.start_lt = collator.max_lt = 50000;
    collator.now_ = 1750000000;
    collator.internal_msg_timeout_ = options.timed_out ? td::Timestamp::in(-1) : td::Timestamp::in(60);
    collator.last_proc_int_msg_ = {0, td::Bits256::zero()};
    collator.out_msg_queue_size_ = collator.old_out_msg_queue_size_ = options.old_size;
    collator.out_msg_queue_size_hard_limit_ = options.hard;
    collator.have_out_msg_queue_size_in_state_ = options.size_recorded;
    collator.store_out_msg_queue_size_ = true;
    collator.state_usage_tree_ = std::make_shared<vm::CellUsageTree>();
    collator.block_limits_ = std::make_unique<block::BlockLimits>();
    auto& limits = *collator.block_limits_;
    limits.bytes = options.stop_after_transit ? block::ParamLimits{1000, 2100, 4200}
                                              : block::ParamLimits{1 << 18, 1 << 20, 2 << 20};
    limits.gas = {2000000, 10000000, 20000000};
    limits.lt_delta = {1000, 5000, 10000};
    limits.collated_data = {1 << 18, 1 << 20, 2 << 20};
    limits.start_lt = collator.start_lt;
    limits.usage_tree = collator.state_usage_tree_.get();
    collator.block_limit_status_ = std::make_unique<block::BlockLimitStatus>(limits);
    collator.aug_InMsgDescr.global_version = collator.aug_OutMsgDescr.global_version = 16;
    collator.in_msg_dict = std::make_unique<vm::AugmentedDictionary>(256, collator.aug_InMsgDescr);
    collator.out_msg_dict = std::make_unique<vm::AugmentedDictionary>(256, collator.aug_OutMsgDescr);
    collator.out_msg_queue_ = std::make_unique<vm::AugmentedDictionary>(own);
    collator.dispatch_queue_ = std::make_unique<vm::AugmentedDictionary>(256, block::tlb::aug_DispatchQueue);
    collator.account_dict_estimator_ = std::make_unique<vm::AugmentedDictionary>(256, block::tlb::aug_ShardAccounts);
    collator.processed_upto_ = std::make_shared<block::MsgProcessedUptoCollection>(relay);
    collator.processed_upto_->valid = true;
    collator.neighbors_.emplace_back(tos::BlockIdExt{tos::BlockId{source, 1}}, 1, 20000);
    collator.neighbors_.emplace_back(tos::BlockIdExt{tos::BlockId{relay, 1}}, 1, 20000);
    collator.stats_.neighbors.resize(2);
    collator.nb_out_msgs_ = std::make_unique<block::OutputQueueMerger>(
        relay, std::vector<block::OutputQueueMerger::Neighbor>{{collator.neighbors_[0].blk_, foreign.get_root_cell()},
                                                               {collator.neighbors_[1].blk_, own.get_root_cell()}});
    auto addr = address(0xf100000000000000ULL);
    auto account = std::make_unique<block::Account>(0, addr.cbits());
    CHECK(account->init_new(collator.now_));
    account->block_lt = collator.start_lt;
    collator.accounts.emplace(addr, std::move(account));
    collator.storage_phase_cfg_.global_version = 16;
    collator.compute_phase_cfg_.global_version = 16;
    collator.compute_phase_cfg_.gas_limit = 1000000;
    collator.compute_phase_cfg_.special_gas_limit = 1000000;
    collator.compute_phase_cfg_.gas_credit = 10000;
    collator.compute_phase_cfg_.set_gas_price(1000);
    collator.compute_phase_cfg_.libraries = std::make_unique<vm::Dictionary>(256);
    collator.action_phase_cfg_.global_version = 16;
    collator.action_phase_cfg_.fwd_std = collator.action_phase_cfg_.fwd_mc = block::MsgPrices(0, 0, 0, 0, 0, 0);
    collator.serialize_cfg_.global_version = 16;
    if (options.dispatch) {
      auto msg = message(0xf000000000000000ULL, 0xf800000000000000ULL, 50);
      block::tlb::MsgEnvelope::Record_std env{0, 0, td::zero_refint(), msg, {}, {}};
      Ref<vm::Cell> envelope;
      CHECK(block::tlb::t_MsgEnvelope.pack_cell(envelope, env));
      vm::CellBuilder cb;
      CHECK(cb.store_long_bool(50, 64) && cb.store_ref_bool(envelope));
      auto enqueued = cb.finalize();
      vm::Dictionary dispatch{64};
      td::BitArray<64> key;
      key.store_ulong(50);
      CHECK(dispatch.set(key, vm::load_cell_slice_ref(enqueued)));
      auto src = address(0xf000000000000000ULL);
      CHECK(collator.dispatch_queue_->set(src, block::pack_account_dispatch_queue(dispatch, 1)));
      td::optional<block::MsgMetadata> metadata;
      CHECK(collator.process_deferred_message(vm::load_cell_slice_ref(enqueued), src, 50, metadata));
      CHECK(collator.new_msgs_from_dispatch == 1);
    }
    CHECK(collator.process_inbound_internal_messages());
    CHECK(collator.update_processed_upto());
    if (collator.last_proc_int_msg_.first == 0) {
      CHECK(collator.processed_upto_->list.empty());
    } else {
      CHECK(collator.processed_upto_->list.size() == 1);
      CHECK(collator.processed_upto_->list[0].last_inmsg_lt == collator.last_proc_int_msg_.first);
      CHECK(collator.processed_upto_->list[0].last_inmsg_hash == collator.last_proc_int_msg_.second);
    }
    if (options.dispatch) {
      bool enqueue_only = !collator.inbound_queues_empty_;
      CHECK(collator.process_new_messages(enqueue_only));
      CHECK(collator.new_msgs_from_dispatch == 0 && collator.new_msgs.empty());
    }
    bool valid = !out_msg_queue_exceeds_hard_limit(
        collator.out_msg_queue_size_, options.hard,
        options.size_recorded ? std::optional<td::uint64>{options.old_size} : std::nullopt);
    td::uint64 count = 0;
    CHECK(collator.out_msg_queue_->check_for_each([&](Ref<vm::CellSlice>, td::ConstBitPtr, int) {
      ++count;
      return true;
    }));
    return {collator.out_msg_queue_size_,
            count,
            collator.last_proc_int_msg_.first,
            collator.block_limit_status_->transactions,
            collator.inbound_queues_empty_,
            valid,
            context.get_stop()};
  }

 private:
  static tos::StdSmcAddress address(td::uint64 prefix) {
    auto result = tos::StdSmcAddress::zero();
    result.bits().store_uint(prefix, 64);
    return result;
  }
  static Ref<vm::Cell> message(td::uint64 src, td::uint64 dst, tos::LogicalTime lt) {
    vm::CellBuilder cb;
    CHECK(cb.store_long_bool(4, 4));  // internal, ihr-disabled, non-bouncing
    CHECK(cb.store_long_bool(0x400, 11) && cb.store_bits_bool(address(src)));
    CHECK(cb.store_long_bool(0x400, 11) && cb.store_bits_bool(address(dst)));
    CHECK(block::CurrencyCollection(1000000).store(cb));
    CHECK(cb.store_zeroes_bool(8));
    CHECK(cb.store_long_bool(lt, 64) && cb.store_long_bool(1750000000, 32) && cb.store_zeroes_bool(2));
    auto result = cb.finalize();
    CHECK(block::gen::t_Message_Any.validate_ref(result));
    return result;
  }
  static void put(vm::AugmentedDictionary& dict, tos::ShardIdFull source, td::uint64 src, td::uint64 dst,
                  tos::LogicalTime lt, bool requeue = false) {
    auto msg = message(src, dst, lt);
    auto route = block::perform_hypercube_routing({0, src}, {0, dst}, source);
    block::tlb::MsgEnvelope::Record_std record{
        requeue ? 0 : route.first, requeue ? 36 : route.second, td::zero_refint(), msg, {}, {}};
    Ref<vm::Cell> envelope;
    CHECK(block::tlb::t_MsgEnvelope.pack_cell(envelope, record));
    vm::CellBuilder cb;
    CHECK(cb.store_long_bool(lt, 64) && cb.store_ref_bool(envelope));
    td::BitArray<352> key;
    CHECK(block::compute_out_msg_queue_key(envelope, key));
    CHECK(dict.set_builder(key, cb, vm::Dictionary::SetMode::Add));
  }
};
}  // namespace tos::validator

TEST(OutMsgQueueLimits, RealCollatorPostponesTransitAtCapacity) {
  using Access = CollatorQueueLimitsTestAccess;
  for (unsigned count : {1u, 2u, 3u}) {
    auto result = Access::run({.hard = 4, .old_size = 4, .transit = count, .local = count});
    CHECK(result.queue_size == 4 && result.dictionary_size == 4);
    CHECK(result.frontier == 0 && result.transactions == 0 && !result.empty);
    CHECK(result.valid && !result.stopped);
  }
  auto full = Access::run({.hard = 18000, .old_size = 18000});
  CHECK(full.queue_size == 18000 && full.dictionary_size == 18000);
  CHECK(full.frontier == 0 && full.transactions == 0 && !full.empty && full.valid && !full.stopped);
}

TEST(OutMsgQueueLimits, RealCollatorImportsTransitBelowCapacity) {
  using Access = CollatorQueueLimitsTestAccess;
  auto room = Access::run({.hard = 3, .old_size = 2});
  CHECK(room.queue_size == 2 && room.dictionary_size == 2 && room.frontier == 100);
  CHECK(room.transactions == 1 && room.empty && room.valid && !room.stopped);
  // The first transit takes the last free slot; the second waits for a later block.
  auto last_slot = Access::run({.hard = 3, .old_size = 2, .transit = 2, .local = 0});
  CHECK(last_slot.queue_size == 3 && last_slot.dictionary_size == 3 && last_slot.frontier == 10);
  CHECK(last_slot.transactions == 0 && !last_slot.empty && last_slot.valid && !last_slot.stopped);
}

TEST(OutMsgQueueLimits, RealCollatorRespectsBlockBudgets) {
  using Access = CollatorQueueLimitsTestAccess;
  auto full = Access::run({.hard = 3, .old_size = 2, .stop_after_transit = true});
  CHECK(full.queue_size == 3 && full.frontier == 10 && full.transactions == 0 && !full.empty);
  CHECK(full.valid && !full.stopped);
  auto timed = Access::run({.hard = 3, .old_size = 2, .timed_out = true});
  CHECK(timed.queue_size == 2 && timed.frontier == 0 && timed.transactions == 0 && !timed.empty);
  CHECK(timed.valid && !timed.stopped);
}

TEST(OutMsgQueueLimits, RealCollatorReservesDispatchedMessages) {
  using Access = CollatorQueueLimitsTestAccess;
  auto reserved = Access::run({.hard = 2, .old_size = 1, .local = 0, .dispatch = true});
  CHECK(reserved.queue_size == 2 && reserved.dictionary_size == 2 && reserved.frontier == 0);
  CHECK(!reserved.empty && reserved.valid && !reserved.stopped);
  auto unreserved = Access::run({.hard = 2, .old_size = 1, .local = 0});
  CHECK(unreserved.queue_size == 2 && unreserved.dictionary_size == 2 && unreserved.frontier == 10);
  CHECK(unreserved.empty && unreserved.valid && !unreserved.stopped);
}

TEST(OutMsgQueueLimits, RealCollatorKeepsOversizedQueueFromGrowing) {
  using Access = CollatorQueueLimitsTestAccess;
  auto oversized = Access::run({.hard = 2, .old_size = 4});
  CHECK(oversized.queue_size == 4 && oversized.dictionary_size == 4 && oversized.frontier == 0);
  CHECK(!oversized.empty && oversized.valid && !oversized.stopped);
}

TEST(OutMsgQueueLimits, RealCollatorAllowsNeutralImportsAtCapacity) {
  using Access = CollatorQueueLimitsTestAccess;
  auto requeue = Access::run({.transit = 0, .local = 0, .requeue = true});
  CHECK(requeue.queue_size == 2 && requeue.dictionary_size == 2 && requeue.frontier == 90);
  CHECK(requeue.transactions == 0 && requeue.empty && requeue.valid && !requeue.stopped);
  auto final = Access::run({.transit = 0, .local = 0, .foreign_final = true});
  CHECK(final.queue_size == 2 && final.dictionary_size == 2 && final.frontier == 50);
  CHECK(final.transactions == 1 && final.empty && final.valid && !final.stopped);
  auto local = Access::run({.transit = 0});
  CHECK(local.queue_size == 1 && local.dictionary_size == 1 && local.frontier == 100);
  CHECK(local.transactions == 1 && local.empty && local.valid && !local.stopped);
}

// Known limitation: a postponed transit also holds back later messages in the
// merged input order, including deliveries that would free a queue slot. They
// wait for a block in which neighbours have consumed part of this shard's queue.
TEST(OutMsgQueueLimits, RealCollatorStopsAtFirstPostponedTransit) {
  using Access = CollatorQueueLimitsTestAccess;
  auto mixed = Access::run({.foreign_final = true});
  CHECK(mixed.queue_size == 2 && mixed.dictionary_size == 2 && mixed.frontier == 0);
  CHECK(mixed.transactions == 0 && !mixed.empty && mixed.valid && !mixed.stopped);
}
