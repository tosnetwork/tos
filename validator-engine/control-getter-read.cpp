/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <bit>
#include <set>

#include "block/block-parse.h"
#include "td/utils/tl_storers.h"
#include "tl-utils/common-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "tos/tos-tl.hpp"
#include "vm/boc.h"
#include "vm/dict.h"

#include "control-getter-read.h"

namespace tos::control_getter {
namespace {
using Entry = vm::StackEntry;
using Tuple = td::Ref<vm::Tuple>;
using namespace tos_api;

td::Result<Tuple> tuple(const Entry& value, std::size_t size) {
  if (!value.is_tuple() || value.as_tuple()->size() != size) {
    return td::Status::Error("control getter tuple arity mismatch");
  }
  return value.as_tuple();
}
td::Result<td::RefInt256> integer(const Entry& value, unsigned bits, bool signed_value = false) {
  if (!value.is_int() || value.as_int().is_null() ||
      !(signed_value ? value.as_int()->signed_fits_bits(bits) : value.as_int()->unsigned_fits_bits(bits))) {
    return td::Status::Error("control getter integer range mismatch");
  }
  return value.as_int();
}
td::Result<td::int32> u32(const Entry& value) {
  TRY_RESULT(number, integer(value, 32));
  return std::bit_cast<td::int32>(static_cast<td::uint32>(number->to_long()));
}
td::Result<td::int64> i64(const Entry& value) {
  TRY_RESULT(number, integer(value, 64, true));
  return number->to_long();
}
td::Result<td::Bits256> id(const Entry& value) {
  TRY_RESULT(number, integer(value, 256));
  td::Bits256 result;
  if (!number->export_bits(result.bits(), 256, false)) {
    return td::Status::Error("control getter identifier encoding failed");
  }
  return result;
}
td::Result<bool> flag(const Entry& value) {
  TRY_RESULT(number, integer(value, 2, true));
  auto raw = number->to_long();
  if (raw != 0 && raw != -1) {
    return td::Status::Error("control getter boolean is not zero or minus one");
  }
  return raw != 0;
}
td::Result<td::BufferSlice> coins(const Entry& value) {
  TRY_RESULT(number, integer(value, 120));
  unsigned bytes = 0;
  while (bytes < 15 && !number->unsigned_fits_bits(bytes * 8)) {
    ++bytes;
  }
  td::BufferSlice result(bytes);
  if (bytes && !number->export_bytes(reinterpret_cast<unsigned char*>(result.as_slice().data()), bytes, false)) {
    return td::Status::Error("control getter Coins encoding failed");
  }
  return result;
}
std::size_t tl_bytes(std::size_t size) {
  return (size + (size < 254 ? 1 : 4) + 3) & ~std::size_t{3};
}
td::Result<td::Bits256> address(const Snapshot& snapshot, int parameter) {
  auto cell = snapshot.config().get_config_param(parameter);
  if (cell.is_null()) {
    return td::Status::Error("control getter system address is missing from config");
  }
  auto slice = vm::load_cell_slice(cell);
  td::Bits256 value;
  if (!slice.fetch_bits_to(value) || !slice.empty_ext()) {
    return td::Status::Error("invalid control getter system address");
  }
  return value;
}
td::RefInt256 argument(const td::Bits256& value) {
  td::RefInt256 result{true};
  if (!result.write().import_bits(value.cbits(), 256, false)) {
    return {};
  }
  return result;
}
struct Ordered {
  td::optional<td::Bits256> previous;
  td::Status accept(const td::Bits256& key) {
    if (previous && !(previous.value() < key)) {
      return td::Status::Error("control getter keys are not strictly ascending");
    }
    previous = key;
    return td::Status::OK();
  }
};

template <class T>
td::Result<td::BufferSlice> serialize(const object_ptr<T>& result, ReplyBudget& budget) {
  td::TlStorerCalcLength counter;
  result->store(counter);
  auto size = counter.get_length() + 4;
  if (size != budget.used() || size > kControlGetterReplyBytes) {
    return td::Status::Error("control getter encoded reply exceeds its reserved byte budget: encoded=" +
                             std::to_string(size) + " reserved=" + std::to_string(budget.used()));
  }
  return tos::serialize_tl_object(result, true);
}

td::Result<object_ptr<engine_validator_configProposalMeta>> proposal_meta(const Entry& value, const td::Bits256& hash,
                                                                          ReplyBudget& bytes,
                                                                          td::Ref<vm::Cell>* proposed) {
  TRY_RESULT(fields, tuple(value, 9));
  TRY_RESULT(expires, u32(fields->at(0)));
  TRY_RESULT(critical, flag(fields->at(1)));
  TRY_RESULT(parameter, tuple(fields->at(2), 3));
  TRY_RESULT(param_number, integer(parameter->at(0), 32, true));
  bool has_value = !parameter->at(1).is_null();
  if (has_value && !parameter->at(1).is_cell()) {
    return td::Status::Error("proposal parameter is not a cell or null");
  }
  td::Bits256 param_hash;
  param_hash.set_zero();
  td::int32 flags = 0;
  const auto& hash_field = parameter->at(2);
  const bool no_hash = hash_field.is_null() || (hash_field.is_int() && hash_field.as_int()->to_long() == -1 &&
                                                hash_field.as_int()->signed_fits_bits(2));
  if (!no_hash) {
    TRY_RESULT(hash_value, id(hash_field));
    param_hash = hash_value;
    flags = 1;
  }
  TRY_RESULT(vset, id(fields->at(3)));
  TRY_RESULT(weight, i64(fields->at(5)));
  TRY_RESULT(rounds_number, integer(fields->at(6), 8));
  TRY_RESULT(losses_number, integer(fields->at(7), 8));
  TRY_RESULT(wins_number, integer(fields->at(8), 8));
  TRY_STATUS(bytes.reserve(108 + (flags ? 32 : 0)));
  std::vector<td::int32> voters;
  td::optional<td::uint16> previous;
  TRY_STATUS(walk_cons(fields->at(4), 65536, [&](const Entry& voter) {
    TRY_RESULT(number, integer(voter, 16));
    auto raw = static_cast<td::uint16>(number->to_long());
    if (previous && previous.value() >= raw) {
      return td::Status::Error("proposal voters are not strictly ascending");
    }
    previous = raw;
    TRY_STATUS(bytes.reserve(4));
    voters.push_back(raw);
    return td::Status::OK();
  }));
  if (proposed) {
    *proposed = has_value ? parameter->at(1).as_cell() : td::Ref<vm::Cell>{};
  }
  return create_tl_object<engine_validator_configProposalMeta>(
      flags, hash, expires, critical, static_cast<td::int32>(param_number->to_long()), param_hash, has_value, vset,
      std::move(voters), weight, static_cast<td::int32>(rounds_number->to_long()),
      static_cast<td::int32>(wins_number->to_long()), static_cast<td::int32>(losses_number->to_long()));
}

td::Result<td::BufferSlice> proposals(const Snapshot& snapshot, const Request& request) {
  TRY_RESULT(config_address, address(snapshot, 0));
  TRY_RESULT(account, snapshot.account(config_address));
  ReplyBudget bytes;
  GasBudget gas{kConfigProposalsGasLimit};
  if (request.kind == ReadKind::Proposals) {
    TRY_STATUS(bytes.reserve(88));
    std::vector<object_ptr<engine_validator_configProposalMeta>> result;
    Ordered ordered;
    TRY_STATUS(run(snapshot, account, Getter::Proposals, {}, gas, [&](const vm::Stack& stack) {
      if (stack.depth() != 1) {
        return td::Status::Error("proposal list stack arity mismatch");
      }
      return walk_cons(stack[0], kMaxConfigProposals, [&](const Entry& head) {
        TRY_RESULT(pair, tuple(head, 2));
        TRY_RESULT(hash, id(pair->at(0)));
        TRY_STATUS(ordered.accept(hash));
        if (hash == td::Bits256::ones()) {
          return td::Status::Error("proposal list includes exclusive maximum-hash sentinel");
        }
        TRY_RESULT(meta, proposal_meta(pair->at(1), hash, bytes, nullptr));
        result.push_back(std::move(meta));
        return td::Status::OK();
      });
    }));
    auto reply = create_tl_object<engine_validator_configProposals>(tos::create_tl_block_id(snapshot.block_id()),
                                                                    std::move(result));
    return serialize(reply, bytes);
  }
  TRY_STATUS(bytes.reserve(88));
  object_ptr<engine_validator_configProposalMeta> meta;
  td::Ref<vm::Cell> value;
  TRY_STATUS(run(snapshot, account, Getter::Proposal, {argument(request.hash)}, gas, [&](const vm::Stack& stack) {
    if (stack.depth() != 1) {
      return td::Status::Error("proposal detail stack arity mismatch");
    }
    if (stack[0].is_null()) {
      return td::Status::OK();
    }
    TRY_RESULT(found, proposal_meta(stack[0], request.hash, bytes, &value));
    meta = std::move(found);
    return td::Status::OK();
  }));
  td::BufferSlice encoded;
  td::int32 flags = meta ? 1 : 0;
  if (value.not_null()) {
    // Bound cell collection before the BOC serializer allocates its index/output.
    vm::CellStorageStat storage{kControlGetterReplyBytes / 2};
    storage.limit_bits = kControlGetterReplyBytes * 8;
    auto usage = storage.compute_used_storage(value);
    if (usage.is_error()) {
      return td::Status::Error("proposal value exceeds reply byte limit");
    }
    vm::BagOfCells boc;
    boc.set_roots({value});
    TRY_STATUS(boc.import_cells());
    auto size = boc.estimate_serialized_size(0);
    if (size > kControlGetterReplyBytes) {
      return td::Status::Error("proposal value exceeds reply byte limit");
    }
    TRY_STATUS(bytes.reserve(tl_bytes(size)));
    TRY_RESULT(serialized, vm::std_boc_serialize(value, 0));
    encoded = std::move(serialized);
    flags |= 2;
  }
  auto reply = create_tl_object<engine_validator_configProposalDetail>(
      flags, tos::create_tl_block_id(snapshot.block_id()), std::move(meta), std::move(encoded));
  return serialize(reply, bytes);
}

td::Result<td::BufferSlice> elector(const Snapshot& snapshot, const Request& request) {
  TRY_STATUS(validate_wallets(request.wallets));
  TRY_RESULT(elector_address, address(snapshot, 1));
  TRY_RESULT(account, snapshot.account(elector_address));
  ReplyBudget bytes;
  GasBudget gas{kElectorStateGasLimit};
  TRY_STATUS(bytes.reserve(112));
  td::int32 elect_at = 0, elect_close = 0;
  td::BufferSlice minimum, total;
  bool failed = false, finished = false;
  std::vector<object_ptr<engine_validator_electionParticipant>> participants;
  TRY_STATUS(run(snapshot, account, Getter::Participants, {}, gas, [&](const vm::Stack& stack) {
    if (stack.depth() != 7) {
      return td::Status::Error("elector participant stack arity mismatch");
    }
    TRY_RESULT(at, u32(stack[6]));
    elect_at = at;
    TRY_RESULT(close, u32(stack[5]));
    elect_close = close;
    TRY_RESULT(min, coins(stack[4]));
    minimum = std::move(min);
    TRY_RESULT(sum, coins(stack[3]));
    total = std::move(sum);
    TRY_RESULT(fail, flag(stack[1]));
    failed = fail;
    TRY_RESULT(done, flag(stack[0]));
    finished = done;
    TRY_STATUS(bytes.reserve(tl_bytes(minimum.size()) + tl_bytes(total.size())));
    Ordered ordered;
    TRY_STATUS(walk_cons(stack[2], kMaxElectorParticipants, [&](const Entry& head) {
      TRY_RESULT(pair, tuple(head, 2));
      TRY_RESULT(key, id(pair->at(0)));
      TRY_STATUS(ordered.accept(key));
      if (key == td::Bits256::ones()) {
        return td::Status::Error("elector list includes exclusive maximum-id sentinel");
      }
      TRY_RESULT(fields, tuple(pair->at(1), 6));
      TRY_RESULT(stake, coins(fields->at(0)));
      TRY_RESULT(factor, u32(fields->at(1)));
      TRY_RESULT(owner, id(fields->at(2)));
      if (owner != key) {
        return td::Status::Error("elector participant owner differs from its id");
      }
      TRY_RESULT(adnl, id(fields->at(3)));
      TRY_RESULT(algorithm_number, integer(fields->at(4), 16));
      TRY_RESULT(consensus_key, id(fields->at(5)));
      TRY_STATUS(bytes.reserve(104 + tl_bytes(stake.size())));
      participants.push_back(create_tl_object<engine_validator_electionParticipant>(
          key, std::move(stake), factor, adnl, static_cast<td::int32>(algorithm_number->to_long()), consensus_key));
      return td::Status::OK();
    }));
    if (elect_at == 0 &&
        (elect_close != 0 || !minimum.empty() || !total.empty() || failed || finished || !participants.empty())) {
      return td::Status::Error("non-canonical empty election");
    }
    return td::Status::OK();
  }));
  std::vector<object_ptr<engine_validator_pastElection>> history;
  std::size_t frozen_total = 0;
  TRY_STATUS(run(snapshot, account, Getter::PastElections, {}, gas, [&](const vm::Stack& stack) {
    if (stack.depth() != 1) {
      return td::Status::Error("past election stack arity mismatch");
    }
    td::optional<td::uint32> previous;
    return walk_cons(stack[0], kMaxPastElections, [&](const Entry& head) {
      TRY_RESULT(fields, tuple(head, 8));
      TRY_RESULT(election, u32(fields->at(0)));
      auto unsigned_id = std::bit_cast<td::uint32>(election);
      if (previous && previous.value() >= unsigned_id) {
        return td::Status::Error("past election ids are not strictly ascending");
      }
      previous = unsigned_id;
      TRY_RESULT(unfreeze, u32(fields->at(1)));
      TRY_RESULT(held, u32(fields->at(2)));
      TRY_RESULT(vset, id(fields->at(3)));
      TRY_RESULT(stake, coins(fields->at(5)));
      TRY_RESULT(bonus, coins(fields->at(6)));
      if (!fields->at(7).is_null() && !fields->at(7).is_cell()) {
        return td::Status::Error("invalid past election complaints field");
      }
      TRY_STATUS(bytes.reserve(48 + tl_bytes(stake.size()) + tl_bytes(bonus.size())));
      std::vector<object_ptr<engine_validator_frozenStake>> frozen;
      const auto& book = fields->at(4);
      if (!book.is_null()) {
        if (!book.is_cell()) {
          return td::Status::Error("past frozen book is not a cell or null");
        }
        vm::Dictionary dictionary{book.as_cell(), 256};
        td::Bits256 key;
        auto value = dictionary.get_minmax_key(key.bits(), 256);
        while (value.not_null()) {
          if (frozen.size() == kMaxFrozenEntriesPerElection || frozen_total == kMaxFrozenEntriesTotal) {
            return td::Status::Error("frozen stake count limit exceeded");
          }
          vm::CellSlice data = *value;
          td::Bits256 owner;
          unsigned long long weight;
          if (!data.fetch_bits_to(owner) || !data.fetch_ulong_bool(64, weight)) {
            return td::Status::Error("invalid frozen stake record");
          }
          auto amount = block::tlb::t_Tomis.as_integer_skip(data);
          if (amount.is_null()) {
            return td::Status::Error("invalid frozen stake amount");
          }
          auto banned = data.fetch_long(1);
          if ((banned != 0 && banned != -1) || !data.empty_ext()) {
            return td::Status::Error("invalid frozen stake record end");
          }
          TRY_RESULT(encoded, coins(Entry{amount}));
          TRY_STATUS(bytes.reserve(76 + tl_bytes(encoded.size())));
          frozen.push_back(create_tl_object<engine_validator_frozenStake>(
              key, owner, std::bit_cast<td::int64>(static_cast<td::uint64>(weight)), std::move(encoded), banned != 0));
          ++frozen_total;
          value = dictionary.lookup_nearest_key(key.bits(), 256, true);
        }
      }
      history.push_back(create_tl_object<engine_validator_pastElection>(
          election, unfreeze, held, vset, std::move(stake), std::move(bonus), std::move(frozen)));
      return td::Status::OK();
    });
  }));
  std::vector<object_ptr<engine_validator_returnedStake>> returned;
  for (const auto& wallet : request.wallets) {
    TRY_STATUS(run(snapshot, account, Getter::ReturnedStake, {argument(wallet)}, gas, [&](const vm::Stack& stack) {
      if (stack.depth() != 1) {
        return td::Status::Error("returned stake stack arity mismatch");
      }
      TRY_RESULT(amount, coins(stack[0]));
      TRY_STATUS(bytes.reserve(32 + tl_bytes(amount.size())));
      returned.push_back(create_tl_object<engine_validator_returnedStake>(wallet, std::move(amount)));
      return td::Status::OK();
    }));
  }
  auto reply = create_tl_object<engine_validator_electorState>(
      tos::create_tl_block_id(snapshot.block_id()), elect_at, elect_close, std::move(minimum), std::move(total), failed,
      finished, std::move(participants), std::move(history), std::move(returned));
  return serialize(reply, bytes);
}
}  // namespace

td::Status validate_wallets(const std::vector<td::Bits256>& wallets) {
  if (wallets.size() > kMaxReturnedStakeWallets) {
    return td::Status::Error("more than 16 returned-stake wallets; reduce the configured wallet set");
  }
  std::set<td::Bits256> distinct;
  for (const auto& wallet : wallets) {
    if (!distinct.insert(wallet).second) {
      return td::Status::Error("duplicate returned-stake wallet");
    }
  }
  return td::Status::OK();
}

td::Result<td::BufferSlice> read(const Snapshot& snapshot, const Request& request) {
  try {
    switch (request.kind) {
      case ReadKind::Elector:
        return elector(snapshot, request);
      case ReadKind::Proposals:
      case ReadKind::Proposal:
        return proposals(snapshot, request);
    }
    return td::Status::Error("unknown control getter read kind");
  } catch (const vm::VmError&) {
    return td::Status::Error("malformed control getter result");
  } catch (const vm::CellSlice::CellReadError&) {
    return td::Status::Error("truncated control getter result");
  }
}
}  // namespace tos::control_getter
