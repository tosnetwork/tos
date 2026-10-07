/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "td/utils/Random.h"
#include "td/utils/crypto.h"
#include "vm/dict.h"
#include "vm/vm.h"

#include "control-getter.h"

namespace tos::control_getter {

namespace {
struct Method {
  const char* name;
  long long gas;
  std::size_t arguments;
};
td::Result<Method> method(Getter getter) {
  switch (getter) {
    case Getter::Participants:
      return Method{"participant_list_extended", kElectorParticipantsGasLimit, 0};
    case Getter::PastElections:
      return Method{"past_elections", kPastElectionsGasLimit, 0};
    case Getter::ReturnedStake:
      return Method{"compute_returned_stake", kReturnedStakeGasLimit, 1};
    case Getter::Proposals:
      return Method{"list_proposals", kConfigProposalsGasLimit, 0};
    case Getter::Proposal:
      return Method{"get_proposal", kConfigProposalsGasLimit, 1};
  }
  return td::Status::Error("unknown control getter");
}
}  // namespace

td::Status GasBudget::charge(long long amount) {
  if (limit_ < 0 || amount < 0 || used_ > limit_ || amount > limit_ - used_) {
    return td::Status::Error("control getter aggregate gas limit exceeded");
  }
  used_ += amount;
  return td::Status::OK();
}

td::Status ReplyBudget::reserve(std::size_t bytes) {
  if (bytes > limit_ - used_) {
    return td::Status::Error("control getter reply byte limit exceeded");
  }
  used_ += bytes;
  return td::Status::OK();
}

td::Result<std::shared_ptr<const Snapshot>> Snapshot::create(BlockIdExt block_id, td::Ref<vm::Cell> state) {
  try {
    if (!block_id.is_masterchain() || state.is_null()) {
      return td::Status::Error("control getter requires a masterchain snapshot");
    }
    block::gen::ShardStateUnsplit::Record header;
    tos::ShardIdFull shard;
    if (!tlb::unpack_cell(state, header) || !block::tlb::t_ShardIdent.unpack(header.shard_id.write(), shard) ||
        shard != tos::ShardIdFull{masterchainId, shardIdAll} || header.seq_no != block_id.seqno()) {
      return td::Status::Error("control getter snapshot block identity mismatch");
    }
    TRY_RESULT(config, block::ConfigInfo::extract_config(state, block_id,
                                                         block::ConfigInfo::needLibraries |
                                                             block::ConfigInfo::needCapabilities |
                                                             block::ConfigInfo::needPrevBlocks));
    auto previous = config->get_prev_blocks_info();
    if (previous.is_error()) {
      return td::Status::Error("control getter previous-block context unavailable");
    }
    std::shared_ptr<Snapshot> snapshot{new Snapshot};
    snapshot->block_ = block_id;
    snapshot->now_ = header.gen_utime;
    snapshot->lt_ = header.gen_lt;
    snapshot->accounts_ = header.accounts;
    snapshot->state_ = std::move(state);
    snapshot->config_ = std::move(config);
    return std::shared_ptr<const Snapshot>{std::move(snapshot)};
  } catch (const vm::VmError&) {
    return td::Status::Error("invalid control getter snapshot");
  } catch (const vm::CellSlice::CellReadError&) {
    return td::Status::Error("truncated control getter snapshot");
  }
}

td::Result<Account> Snapshot::account(const td::Bits256& address) const {
  try {
    vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(accounts_), 256, block::tlb::aug_ShardAccounts};
    auto entry = accounts.lookup(address);
    if (entry.is_null()) {
      return td::Status::Error("control getter account is missing");
    }
    Account result;
    result.owner_ = state_;
    result.root = entry->prefetch_ref();
    block::gen::Account::Record_account account;
    block::gen::AccountStorage::Record storage;
    block::gen::StorageInfo::Record info;
    block::gen::StateInit::Record init;
    if (!tlb::unpack_cell(result.root, account) || !tlb::csr_unpack(account.storage, storage) ||
        !result.balance.validate_unpack(storage.balance) || storage.state->prefetch_ulong(1) != 1 ||
        !storage.state.write().advance(1) || !tlb::csr_unpack(storage.state, init) ||
        !tlb::csr_unpack(account.storage_stat, info)) {
      return td::Status::Error("control getter account is frozen, uninitialized or malformed");
    }
    block::StdAddress parsed;
    if (!block::tlb::t_MsgAddressInt.extract_std_address(account.addr, parsed) || parsed.workchain != masterchainId ||
        parsed.addr != address) {
      return td::Status::Error("control getter account address mismatch");
    }
    result.address = account.addr;
    result.code = init.code->prefetch_ref();
    result.data = init.data->prefetch_ref();
    result.libraries = init.library->prefetch_ref();
    if (result.code.is_null() || result.data.is_null()) {
      return td::Status::Error("control getter account code or data is missing");
    }
    if (info.due_payment.write().fetch_long(1)) {
      result.due_payment = block::tlb::t_Tomis.as_integer(info.due_payment);
      if (result.due_payment.is_null()) {
        return td::Status::Error("invalid control getter due payment");
      }
    } else {
      result.due_payment = td::zero_refint();
    }
    return result;
  } catch (const vm::VmError&) {
    return td::Status::Error("invalid control getter account");
  } catch (const vm::CellSlice::CellReadError&) {
    return td::Status::Error("truncated control getter account");
  }
}

td::Status run(const Snapshot& snapshot, const Account& account, Getter getter, std::vector<td::RefInt256> arguments,
               GasBudget& budget, const std::function<td::Status(const vm::Stack&)>& decode, RunStats* stats) {
  TRY_RESULT(selected, method(getter));
  if (!account.belongs_to(snapshot.state_root())) {
    return td::Status::Error("control getter account belongs to another snapshot");
  }
  if (arguments.size() != selected.arguments || !decode || account.code.is_null() || account.data.is_null()) {
    return td::Status::Error("invalid control getter execution arguments");
  }
  auto stack = td::make_ref<vm::Stack>();
  for (auto& value : arguments) {
    if (value.is_null() || !value->unsigned_fits_bits(256)) {
      return td::Status::Error("control getter argument is not an unsigned 256-bit integer");
    }
    stack.write().push_int(std::move(value));
  }
  stack.write().push_smallint(static_cast<td::int32>((td::crc16(td::Slice{selected.name}) & 0xffff) | 0x10000));
  td::BitArray<256> seed;
  td::Random::secure_bytes(seed.as_slice());
  auto c7 = block::prepare_get_method_c7(snapshot.now(), snapshot.lt(), account.address, account.balance,
                                         &snapshot.config(), account.code, account.due_payment, seed);
  if (c7.is_null()) {
    return td::Status::Error("control getter context unavailable");
  }
  try {
    vm::VmState vm{account.code,
                   snapshot.config().get_global_version(),
                   std::move(stack),
                   vm::GasLimits{selected.gas, selected.gas},
                   1,
                   account.data,
                   vm::VmLog::Null(),
                   block::get_method_libraries(snapshot.config(), account.libraries)};
    vm.set_c7(std::move(c7));
    vm.set_chksig_always_succeed(false);
    const int exit_code = ~vm.run();
    const auto used = vm.gas_consumed();
    if (stats) {
      *stats = RunStats{exit_code, used};
    }
    if (used < 0 || used > selected.gas || exit_code == 13 || exit_code == -14) {
      return td::Status::Error("control getter per-run gas limit exceeded");
    }
    TRY_STATUS(budget.charge(used));
    if (exit_code != 0 && exit_code != 1) {
      return td::Status::Error("control getter VM exit " + std::to_string(exit_code));
    }
    return decode(vm.get_stack_const());
  } catch (const vm::VmError&) {
    return td::Status::Error("control getter VM error");
  } catch (const vm::VmVirtError&) {
    return td::Status::Error("control getter library or virtualized context unavailable");
  } catch (const vm::VmNoGas&) {
    return td::Status::Error("control getter per-run gas limit exceeded");
  } catch (const vm::VmFatal&) {
    return td::Status::Error("control getter VM fatal error");
  }
}

td::Status walk_cons(const vm::StackEntry& root, std::size_t limit,
                     const std::function<td::Status(const vm::StackEntry&)>& visit) {
  if (!visit) {
    return td::Status::Error("missing control getter list visitor");
  }
  std::size_t count = 0;
  vm::StackEntry cursor = root;
  while (!cursor.is_null()) {
    if (!cursor.is_tuple() || cursor.as_tuple()->size() != 2) {
      return td::Status::Error("malformed control getter cons list");
    }
    if (count == limit) {
      return td::Status::Error("control getter list count limit exceeded");
    }
    ++count;
    const auto pair = cursor.as_tuple();
    TRY_STATUS(visit(pair->at(0)));
    cursor = pair->at(1);
  }
  // Tuple/stack/continuation release uses the VM reference deletion queue; shared
  // subtrees and rejected deep results are also destroyed without recursive drops.
  return td::Status::OK();
}

}  // namespace tos::control_getter
