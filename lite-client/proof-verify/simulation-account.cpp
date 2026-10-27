/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <limits>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "vm/boc.h"

#include "simulation-account.h"
#include "simulation-config.h"

namespace tos::proofverify::detail {
namespace {
td::Status refuse(SimulationAccountError error) {
  return td::Status::Error(static_cast<int>(error), "simulation account refused");
}

td::Result<std::size_t> preflight(td::Slice bytes, int roots, std::size_t cell_limit) {
  vm::BagOfCells::Info header;
  if (bytes.empty() || header.parse_serialized_header(bytes) <= 0 || !header.valid || header.root_count != roots ||
      header.absent_count != 0 || header.cell_count < 1 || header.total_size != bytes.size()) {
    return refuse(SimulationAccountError::Input);
  }
  if (static_cast<std::size_t>(header.cell_count) > cell_limit) {
    return refuse(SimulationAccountError::Resource);
  }
  return static_cast<std::size_t>(header.cell_count);
}
}  // namespace

td::Result<PreparedSimulationAccount> restore_simulation_account(const block::StdAddress& address,
                                                                 const block::AccountState::Info& proven,
                                                                 const block::ConfigInfo& config,
                                                                 std::int64_t local_now) {
  try {
    if (local_now <= 0 || local_now > std::numeric_limits<td::uint32>::max() || config.get_global_version() < 16) {
      return refuse(SimulationAccountError::Context);
    }
    const bool exists = proven.true_root.not_null();
    if (!exists && (proven.last_trans_lt != 0 || !proven.last_trans_hash.is_zero())) {
      return refuse(SimulationAccountError::State);
    }
    const auto now = std::max({proven.gen_utime, config.utime, static_cast<td::uint32>(local_now)});
    block::Account account{address.workchain, address.addr.bits()};
    td::Bits256 state_hash = td::Bits256::zero();
    if (exists) {
      // The shared scanner checks actual loaded representations, not virtual
      // commitments. Serialized account inputs have the tighter BOC cell cap.
      auto complete = check_complete_simulation_config(proven.true_root);
      if (complete.is_error()) {
        return refuse(complete.error().code() == static_cast<int>(SimulationConfigError::Resource)
                          ? SimulationAccountError::Resource
                          : SimulationAccountError::State);
      }
      block::gen::Account::Record_account record;
      if (!tlb::unpack_cell(proven.true_root, record)) {
        return refuse(SimulationAccountError::State);
      }
      block::StdAddress embedded;
      if (!block::tlb::t_MsgAddressInt.extract_std_address(record.addr, embedded) ||
          embedded.workchain != address.workchain || embedded.addr != address.addr) {
        return refuse(SimulationAccountError::State);
      }
      block::gen::ShardAccount::Record shard;
      shard.account = proven.true_root;
      shard.last_trans_hash = proven.last_trans_hash;
      shard.last_trans_lt = proven.last_trans_lt;
      td::Ref<vm::Cell> wrapped;
      if (!tlb::pack_cell(wrapped, shard)) {
        return refuse(SimulationAccountError::State);
      }
      bool special = false;
      if (address.workchain == tos::masterchainId) {
        // The native predicate CHECKs its extraction flag; fail structurally
        // before calling it if a caller supplies an incomplete configuration.
        auto specials = config.get_special_smartcontracts();
        if (specials.is_error()) {
          return refuse(SimulationAccountError::Context);
        }
        special = std::find(specials.ok().begin(), specials.ok().end(), address.addr) != specials.ok().end();
      }
      if (!account.unpack(vm::load_cell_slice_ref(wrapped), now, special)) {
        return refuse(SimulationAccountError::State);
      }
      state_hash = td::Bits256{proven.true_root->get_hash().bits()};
    } else if (!account.init_new(now)) {
      return refuse(SimulationAccountError::State);
    }
    auto context = derive_self_pay_simulation_context({proven.gen_utime, config.utime, proven.gen_lt, config.lt,
                                                       account.last_trans_lt_, account.last_trans_end_lt_, exists},
                                                      local_now, static_cast<td::uint32>(config.get_global_version()));
    if (context.is_error()) {
      return refuse(SimulationAccountError::Context);
    }
    account.block_lt = context.ok().estimated_block_start_lt;
    return PreparedSimulationAccount{std::move(account), context.move_as_ok(), state_hash, exists};
  } catch (vm::VmError&) {
    return refuse(SimulationAccountError::State);
  } catch (vm::VmVirtError&) {
    return refuse(SimulationAccountError::State);
  } catch (vm::CellBuilder::CellWriteError&) {
    return refuse(SimulationAccountError::State);
  } catch (vm::CellBuilder::CellCreateError&) {
    return refuse(SimulationAccountError::State);
  }
}

td::Result<PreparedSimulationAccount> prepare_simulation_account(const tos::BlockIdExt& target,
                                                                 const block::StdAddress& address, td::Slice raw_reply,
                                                                 const block::ConfigInfo& config,
                                                                 std::int64_t local_now) {
  try {
    if (config.block_id != target) {
      return refuse(SimulationAccountError::Proof);
    }
    if (raw_reply.empty() || raw_reply.size() > kMaxSimulationConfigReplyBytes) {
      return refuse(SimulationAccountError::Resource);
    }
    auto answer = tos::fetch_tl_object<tos::lite_api::liteServer_accountState>(td::BufferSlice(raw_reply), true);
    if (answer.is_error()) {
      return refuse(SimulationAccountError::Input);
    }
    auto& info = answer.ok();
    block::AccountState state;
    state.blk = tos::create_block_id(info->id_);
    state.shard_blk = tos::create_block_id(info->shardblk_);
    if (state.blk != target) {
      return refuse(SimulationAccountError::Proof);
    }
    if (info->state_.size() > kMaxSimulationAccountBytes) {
      return refuse(SimulationAccountError::Resource);
    }
    std::size_t remaining = kMaxSimulationConfigProofCells;
    if (!info->state_.empty()) {
      TRY_RESULT(cells, preflight(info->state_.as_slice(), 1, kMaxSimulationAccountCells));
      remaining -= cells;
    }
    TRY_RESULT(proof_cells, preflight(info->proof_.as_slice(), 2, remaining));
    remaining -= proof_cells;
    if (!info->shard_proof_.empty()) {
      TRY_RESULT(shard_cells, preflight(info->shard_proof_.as_slice(), 2, remaining));
      remaining -= shard_cells;
    }
    state.shard_proof = std::move(info->shard_proof_);
    state.proof = std::move(info->proof_);
    state.state = std::move(info->state_);
    auto proven = state.validate(target, address);
    if (proven.is_error()) {
      return refuse(SimulationAccountError::Proof);
    }
    return restore_simulation_account(address, proven.ok(), config, local_now);
  } catch (vm::VmError&) {
    return refuse(SimulationAccountError::Proof);
  } catch (vm::VmVirtError&) {
    return refuse(SimulationAccountError::Proof);
  }
}

}  // namespace tos::proofverify::detail
