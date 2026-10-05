/*
    TOS wc=0 in-process wallet index — block-apply writer.
    See https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-wc0-wallet-index.md.

    Walks an applied block's account_blocks -> transactions and appends an
    account event entry per transaction. Token ownership is never taken from
    message claims (any contract can fake a notification op): messages only
    *nominate candidates*, and every candidate is verified against the
    post-apply shard state by executing the standard get-methods —
      jetton: get_wallet_data on the wallet, then get_wallet_address on the
              master must resolve back to the wallet (the master is the only
              authority on which contract is the owner's wallet);
      NFT:    get_nft_data on the item, then get_nft_address_by_index on the
              collection must resolve back to the item.
    Only verified facts are indexed. Best-effort and off the consensus path.
*/
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "smc-envelope/SmartContract.h"
#include "td/utils/logging.h"
#include "vm/cells.h"
#include "vm/dict.h"

#include "wallet-index-queue.h"
#include "wallet-index-writer.h"
#include "wallet-index.h"

namespace tos_wallet_index {

namespace {

// TEP-74 jetton ops handled by the jetton-wallet contract itself.
constexpr unsigned long long kJettonTransfer = 0x0f8a7ea5ULL;
constexpr unsigned long long kJettonInternalTransfer = 0x178d4519ULL;
constexpr unsigned long long kJettonBurn = 0x595f07bcULL;
// Notification ops received by the owner; the message *source* is the token contract.
constexpr unsigned long long kJettonTransferNotification = 0x7362d09cULL;  // TEP-74
constexpr unsigned long long kNftOwnershipAssigned = 0x05138d91ULL;        // TEP-62
// TEP-62 op handled by the NFT item itself.
constexpr unsigned long long kNftTransfer = 0x5fcc3d14ULL;

// Read the 32-bit op-code from a message body. cell_unpack_message returns the raw
// body field `(Either X ^X)` with the selector bit NOT consumed, so resolve it here:
// selector 0 = inline body, 1 = body in a ref.
unsigned long long read_op(td::Ref<vm::CellSlice> body) {
  if (body.is_null() || body->size() < 1) {
    return 0;
  }
  vm::CellSlice cs{*body};
  bool in_ref = cs.fetch_ulong(1) != 0;
  if (in_ref) {
    if (cs.size_refs() < 1) {
      return 0;
    }
    cs = vm::load_cell_slice(cs.prefetch_ref());
  }
  return cs.size() >= 32 ? cs.prefetch_ulong(32) : 0;
}

// Post-apply shard state accounts, the ground truth token claims are verified against.
class StateAccounts {
 public:
  // OtherShard: the account lives outside the shard whose state this is.
  enum class LoadResult { Active, Inactive, Indeterminate, OtherShard };

  StateAccounts(td::Ref<vm::Cell> state_root, tos::ShardIdFull shard) : shard_(shard) {
    block::gen::ShardStateUnsplit::Record sstate;
    if (state_root.not_null() && tlb::unpack_cell(state_root, sstate)) {
      dict_ = std::make_unique<vm::AugmentedDictionary>(vm::load_cell_slice_ref(sstate.accounts), 256,
                                                        block::tlb::aug_ShardAccounts);
    }
  }
  bool ok() const {
    return dict_ != nullptr;
  }
  // Load the active-state code+data of `addr`. False for missing / uninit / frozen.
  LoadResult load(const td::Bits256& addr, tos::SmartContract::State& out) {
    if (!dict_) {
      return LoadResult::Indeterminate;
    }
    if (!wallet_index_state_contains(shard_, addr)) {
      return LoadResult::OtherShard;
    }
    auto shard_acc_csr = dict_->lookup(addr.bits(), 256);
    if (shard_acc_csr.is_null()) {
      return LoadResult::Inactive;
    }
    block::gen::ShardAccount::Record shard_acc;
    block::gen::Account::Record_account acc;
    block::gen::AccountStorage::Record store;
    block::gen::StateInit::Record state_init;
    if (!(tlb::csr_unpack(std::move(shard_acc_csr), shard_acc) && tlb::unpack_cell(shard_acc.account, acc) &&
          tlb::csr_unpack(std::move(acc.storage), store)) || store.state.is_null() || store.state->size() < 1) {
      return LoadResult::Indeterminate;
    }
    if (store.state->prefetch_ulong(1) != 1) {
      return LoadResult::Inactive;
    }
    if (!(store.state.write().advance(1) && tlb::csr_unpack(std::move(store.state), state_init))) {
      return LoadResult::Indeterminate;
    }
    if (state_init.code.is_null() || state_init.data.is_null() || state_init.code->size_refs() < 1 ||
        state_init.data->size_refs() < 1) {
      return LoadResult::Indeterminate;
    }
    out.code = state_init.code->prefetch_ref();
    out.data = state_init.data->prefetch_ref();
    return LoadResult::Active;
  }

 private:
  tos::ShardIdFull shard_;
  std::unique_ptr<vm::AugmentedDictionary> dict_;
};

struct GetMethodResult {
  WalletIndexGetMethodStatus status;
  td::Ref<vm::Stack> stack;
};

// Run a gas-bounded get-method while keeping node-side budget exhaustion
// distinct from a contract that fails or returns no usable result.
GetMethodResult run_get(const tos::SmartContract::State& st, const td::Bits256& addr, td::Slice method,
                        std::vector<vm::StackEntry> params, WalletIndexVerificationBudget& budget) {
  auto reserved_gas = budget.acquire();
  if (reserved_gas <= 0) {
    return {WalletIndexGetMethodStatus::Indeterminate, {}};
  }
  try {
    auto smc = tos::SmartContract::create(st);
    tos::SmartContract::Args args;
    args.set_address(block::StdAddress(0, addr));
    args.set_limits(wallet_index_get_method_gas_limits(reserved_gas));
    args.set_stack(std::move(params));
    auto res = smc->run_get_method(method, std::move(args));
    budget.refund_unused(reserved_gas, res.gas_used);
    if (!res.success || res.stack.is_null()) {
      return {wallet_index_classify_get_method_failure(reserved_gas, res.code, res.gas_used), {}};
    }
    return {WalletIndexGetMethodStatus::Success, std::move(res.stack)};
  } catch (vm::VmError& err) {
    auto status = err.get_errno() == static_cast<int>(vm::Excno::virt_err)
                      ? WalletIndexGetMethodStatus::Indeterminate
                      : WalletIndexGetMethodStatus::ContractFailure;
    return {status, {}};
  } catch (vm::VmVirtError&) {
    return {WalletIndexGetMethodStatus::Indeterminate, {}};
  }
}

// An internal MsgAddressInt slice for `addr` in wc=0, as a get-method argument.
vm::StackEntry make_addr_slice(const td::Bits256& addr) {
  vm::CellBuilder cb;
  cb.store_long(4, 3);  // addr_std$10 anycast:nothing$0
  cb.store_long(0, 8);  // workchain 0
  cb.store_bits(addr.bits(), 256);
  return vm::StackEntry{vm::load_cell_slice_ref(cb.finalize())};
}

enum class AddressExtraction { Wc0, OutsideWc0, Invalid };

AddressExtraction extract_indexed_address(td::Ref<vm::CellSlice> csr, td::Bits256& out) {
  if (csr.is_null()) {
    return AddressExtraction::Invalid;
  }
  tos::WorkchainId wc;
  tos::StdSmcAddress addr;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(csr, wc, addr)) {
    return AddressExtraction::Invalid;
  }
  if (wc != 0) {
    return AddressExtraction::OutsideWc0;
  }
  out = addr;
  return AddressExtraction::Wc0;
}

bool extract_wc0_address(td::Ref<vm::CellSlice> csr, td::Bits256& out) {
  return extract_indexed_address(std::move(csr), out) == AddressExtraction::Wc0;
}

bool is_addr_none(const td::Ref<vm::CellSlice>& csr) {
  return csr.not_null() && csr->size() >= 2 && csr->prefetch_ulong(2) == 0;
}

// Verify that `wallet` is a jetton wallet acknowledged by its master, against the
// post-apply state. The master's own get_wallet_address resolver is the only
// authority on which contract is (owner, master)'s wallet — a hostile contract
// can claim any owner/master in get_wallet_data, but cannot make a master it
// does not control resolve back to it.
enum class JettonVerification { Verified, Rejected, Indeterminate, OtherShard };

JettonVerification jetton_load_failure(StateAccounts::LoadResult load) {
  switch (load) {
    case StateAccounts::LoadResult::Indeterminate:
      return JettonVerification::Indeterminate;
    case StateAccounts::LoadResult::OtherShard:
      return JettonVerification::OtherShard;
    case StateAccounts::LoadResult::Active:
    case StateAccounts::LoadResult::Inactive:
      break;
  }
  return JettonVerification::Rejected;
}

JettonVerification jetton_get_failure(WalletIndexGetMethodStatus status) {
  return status == WalletIndexGetMethodStatus::Indeterminate ? JettonVerification::Indeterminate
                                                             : JettonVerification::Rejected;
}

JettonVerification verify_jetton_wallet(StateAccounts& state, const td::Bits256& wallet, td::Bits256& owner_out,
                                        td::Bits256& master_out, WalletIndexVerificationBudget& budget) {
  tos::SmartContract::State wstate;
  auto wallet_load = state.load(wallet, wstate);
  if (wallet_load != StateAccounts::LoadResult::Active) {
    return jetton_load_failure(wallet_load);
  }
  auto result = run_get(wstate, wallet, "get_wallet_data", {}, budget);
  auto stack = std::move(result.stack);
  if (result.status != WalletIndexGetMethodStatus::Success) {
    return jetton_get_failure(result.status);
  }
  if (stack->depth() < 4) {
    return JettonVerification::Rejected;
  }
  // get_wallet_data -> (int balance, slice owner, slice master, cell wallet_code)
  auto& s = stack.write();
  s.pop();  // wallet_code
  auto master_csr = s.pop_cellslice();
  auto owner_csr = s.pop_cellslice();
  td::Bits256 owner, master;
  if (!extract_wc0_address(std::move(owner_csr), owner) || !extract_wc0_address(std::move(master_csr), master)) {
    return JettonVerification::Rejected;
  }
  tos::SmartContract::State mstate;
  auto master_load = state.load(master, mstate);
  if (master_load != StateAccounts::LoadResult::Active) {
    return jetton_load_failure(master_load);  // fail-closed: unverifiable claim is not indexed
  }
  auto resolved_result = run_get(mstate, master, "get_wallet_address", {make_addr_slice(owner)}, budget);
  auto resolved_stack = std::move(resolved_result.stack);
  if (resolved_result.status != WalletIndexGetMethodStatus::Success) {
    return jetton_get_failure(resolved_result.status);
  }
  if (resolved_stack->depth() < 1) {
    return JettonVerification::Rejected;
  }
  td::Bits256 resolved;
  if (!extract_wc0_address(resolved_stack.write().pop_cellslice(), resolved) || resolved != wallet) {
    return JettonVerification::Rejected;
  }
  owner_out = owner;
  master_out = master;
  return JettonVerification::Verified;
}

// Verify `item` via get_nft_data against the post-apply state. For collection
// NFTs the collection's get_nft_address_by_index must resolve back to the item;
// a standalone NFT (collection = addr_none) is its own sole authority and is
// indexed as a self-claim, keyed by its own address.
enum class NftVerification { Verified, Absent, Indeterminate, OtherShard };

NftVerification verify_nft_item(StateAccounts& state, const td::Bits256& item, td::Bits256& owner_out,
                                bool& has_collection, td::Bits256& collection_out,
                                WalletIndexVerificationBudget& budget) {
  tos::SmartContract::State istate;
  auto item_status = state.load(item, istate);
  if (item_status == StateAccounts::LoadResult::Inactive) {
    return NftVerification::Absent;
  }
  if (item_status == StateAccounts::LoadResult::OtherShard) {
    return NftVerification::OtherShard;
  }
  if (item_status != StateAccounts::LoadResult::Active) {
    return NftVerification::Indeterminate;
  }
  auto item_result = run_get(istate, item, "get_nft_data", {}, budget);
  if (item_result.status == WalletIndexGetMethodStatus::Indeterminate) {
    return NftVerification::Indeterminate;
  }
  auto stack = std::move(item_result.stack);
  if (item_result.status != WalletIndexGetMethodStatus::Success || stack->depth() < 5) {
    return NftVerification::Absent;
  }
  try {
    // get_nft_data -> (int init?, int index, slice collection, slice owner, cell content)
    auto& s = stack.write();
    s.pop();  // content
    auto owner_csr = s.pop_cellslice();
    auto coll_csr = s.pop_cellslice();
    auto index = s.pop_int();
    auto init = s.pop_int();
    if (init->sgn() == 0) {
      return NftVerification::Absent;
    }
    td::Bits256 owner;
    if (is_addr_none(owner_csr)) {
      return NftVerification::Absent;
    }
    auto owner_address = extract_indexed_address(std::move(owner_csr), owner);
    if (owner_address != AddressExtraction::Wc0) {
      return NftVerification::Absent;
    }
    if (is_addr_none(coll_csr)) {
      has_collection = false;
    } else {
      td::Bits256 collection;
      auto collection_address = extract_indexed_address(std::move(coll_csr), collection);
      if (collection_address != AddressExtraction::Wc0) {
        return NftVerification::Absent;
      }
      tos::SmartContract::State cstate;
      auto collection_status = state.load(collection, cstate);
      if (collection_status == StateAccounts::LoadResult::Inactive) {
        return NftVerification::Absent;
      }
      if (collection_status == StateAccounts::LoadResult::OtherShard) {
        return NftVerification::OtherShard;
      }
      if (collection_status != StateAccounts::LoadResult::Active) {
        return NftVerification::Indeterminate;
      }
      auto resolved_result =
          run_get(cstate, collection, "get_nft_address_by_index", {vm::StackEntry(std::move(index))}, budget);
      if (resolved_result.status == WalletIndexGetMethodStatus::Indeterminate) {
        return NftVerification::Indeterminate;
      }
      auto resolved_stack = std::move(resolved_result.stack);
      if (resolved_result.status != WalletIndexGetMethodStatus::Success || resolved_stack->depth() < 1) {
        return NftVerification::Absent;
      }
      td::Bits256 resolved;
      auto resolved_address = extract_indexed_address(resolved_stack.write().pop_cellslice(), resolved);
      if (resolved_address != AddressExtraction::Wc0 || resolved != item) {
        return NftVerification::Absent;
      }
      has_collection = true;
      collection_out = collection;
    }
    owner_out = owner;
    return NftVerification::Verified;
  } catch (vm::VmError& err) {
    return err.get_errno() == static_cast<int>(vm::Excno::virt_err) ? NftVerification::Indeterminate
                                                                    : NftVerification::Absent;
  } catch (vm::VmVirtError&) {
    return NftVerification::Indeterminate;
  }
}

td::Ref<vm::Cell> make_jetton_value(const td::Bits256& wallet, unsigned long long lt) {
  vm::CellBuilder cb;
  cb.store_bits(wallet.bits(), 256);
  cb.store_long(static_cast<long long>(lt), 64);
  return cb.finalize();
}

td::Ref<vm::Cell> make_nft_value(bool has_collection, const td::Bits256& collection, unsigned long long lt) {
  vm::CellBuilder cb;
  cb.store_long(has_collection ? 1 : 0, 1);
  if (has_collection) {
    cb.store_bits(collection.bits(), 256);
  }
  cb.store_long(static_cast<long long>(lt), 64);
  return cb.finalize();
}

// If the incoming message carries a token op, nominate the implicated token
// contract as a verification candidate. Messages never write to the index
// directly — they only say where to look.
void collect_token_candidates(const td::Bits256& account, td::Ref<vm::Cell> in_msg,
                              std::set<td::Bits256>& jettons, std::set<td::Bits256>& nfts) {
  if (in_msg.is_null()) {
    return;
  }
  td::Ref<vm::CellSlice> info_cs, init_cs, body_cs;
  if (!block::gen::t_Message_Any.cell_unpack_message(in_msg, info_cs, init_cs, body_cs)) {
    return;
  }
  unsigned long long op = read_op(body_cs);
  switch (op) {
    case kJettonTransfer:
    case kJettonInternalTransfer:
    case kJettonBurn:
      // Ops handled by the jetton wallet itself: the receiving account is the wallet.
      jettons.insert(account);
      return;
    case kNftTransfer:
      nfts.insert(account);
      return;
    case kJettonTransferNotification:
    case kNftOwnershipAssigned: {
      // Notification received by the owner: the source is the token contract.
      block::gen::CommonMsgInfo::Record_int_msg_info imsg;
      if (info_cs.is_null() || !tlb::csr_unpack(std::move(info_cs), imsg)) {
        return;
      }
      tos::WorkchainId src_wc;
      tos::StdSmcAddress src;
      if (!block::tlb::t_MsgAddressInt.extract_std_address(imsg.src, src_wc, src) || src_wc != 0) {
        return;
      }
      if (op == kJettonTransferNotification) {
        jettons.insert(src);
      } else {
        nfts.insert(src);
      }
      return;
    }
    default:
      return;
  }
}

// Verify and index one jetton-wallet candidate (into the open batch). A check
// that reached no verdict is retried and leaves the index as it was.
TokenVerifyOutcome index_jetton_candidate(WalletIndexDb* db, StateAccounts& state, const td::Bits256& wallet,
                                          unsigned long long end_lt, WalletIndexVerificationBudget& budget) {
  td::Bits256 owner = td::Bits256::zero();
  td::Bits256 master = td::Bits256::zero();
  JettonWalletCheck check = JettonWalletCheck::Rejected;
  switch (verify_jetton_wallet(state, wallet, owner, master, budget)) {
    case JettonVerification::Indeterminate:
      check = JettonWalletCheck::Indeterminate;
      break;
    case JettonVerification::OtherShard:
      check = JettonWalletCheck::OtherShard;
      break;
    case JettonVerification::Rejected:
      check = JettonWalletCheck::Rejected;
      break;
    case JettonVerification::Verified:
      check = JettonWalletCheck::Verified;
      break;
  }
  td::Ref<vm::Cell> value;
  if (check == JettonWalletCheck::Verified) {
    value = make_jetton_value(wallet, end_lt);
  }
  return record_jetton_wallet_check(*db, wallet, check, owner, master, std::move(value), end_lt);
}

// Verify and index one NFT-item candidate; erases the previous owner's entry
// when ownership changed (no stale entries).
TokenVerifyOutcome index_nft_candidate(WalletIndexDb* db, StateAccounts& state, const td::Bits256& item,
                                       unsigned long long end_lt, WalletIndexVerificationBudget& budget) {
  td::Bits256 owner, collection;
  bool has_collection = false;
  td::Bits256 prev_owner;
  auto prev_r = db->get_nft_owner(item, prev_owner);
  if (prev_r.is_error()) {
    LOG(WARNING) << "wc0-index: get_nft_owner failed: " << prev_r.error().message();
    return TokenVerifyOutcome::WriteFailed;
  }
  const bool had_owner = prev_r.ok();
  auto verification = verify_nft_item(state, item, owner, has_collection, collection, budget);
  if (verification == NftVerification::Indeterminate || verification == NftVerification::OtherShard) {
    if (had_owner) {
      LOG(WARNING) << "wc0-index: NFT verification inconclusive; preserving previous ownership";
    }
    return verification == NftVerification::Indeterminate ? TokenVerifyOutcome::Retry
                                                          : TokenVerifyOutcome::Unverifiable;
  }
  // A previously indexed NFT can become unowned, uninitialized, frozen, or
  // deleted (DNS expiry/release is the important case): its committed
  // post-state no longer proves the old ownership claim, and the verdict
  // removes it.
  WalletIndexDb::NftVerdict verdict{verification == NftVerification::Verified, owner, {}};
  if (verdict.owned) {
    verdict.value = make_nft_value(has_collection, collection, end_lt);
  }
  auto status = db->apply_nft_verdict(item, verdict, end_lt);
  if (status.is_error()) {
    LOG(WARNING) << "wc0-index: recording NFT ownership failed: " << status.message();
    return TokenVerifyOutcome::WriteFailed;
  }
  return TokenVerifyOutcome::Done;
}

// Walk the block's account_blocks: write event entries (into the open batch) and
// collect token-verification candidates. Returns false if the block envelope
// does not parse; fills `end_lt` from the block info.
bool index_block_walk(WalletIndexDb* db, td::Ref<vm::Cell> block_root, std::set<td::Bits256>& jettons,
                      std::set<td::Bits256>& nfts, unsigned long long& end_lt, uint32_t& gen_utime,
                      size_t& age_rows_added, bool& write_error) {
  block::gen::Block::Record blk;
  block::gen::BlockInfo::Record info;
  block::gen::BlockExtra::Record extra;
  if (!(tlb::unpack_cell(block_root, blk) && tlb::unpack_cell(blk.info, info) && tlb::unpack_cell(blk.extra, extra))) {
    return false;
  }
  end_lt = info.end_lt;
  gen_utime = info.gen_utime;
  vm::AugmentedDictionary acc_dict{vm::load_cell_slice_ref(extra.account_blocks), 256,
                                   block::tlb::aug_ShardAccountBlocks};
  acc_dict.check_for_each_extra([db, &jettons, &nfts, gen_utime, &age_rows_added, &write_error](
                                    td::Ref<vm::CellSlice> value, td::Ref<vm::CellSlice> /*extra*/,
                                    td::ConstBitPtr /*key*/, int /*n*/) -> bool {
    block::gen::AccountBlock::Record acc_blk;
    if (!tlb::csr_unpack(value, acc_blk)) {
      return true;  // skip
    }
    td::Bits256 account = acc_blk.account_addr;
    vm::AugmentedDictionary trans_dict{vm::DictNonEmpty(), acc_blk.transactions, 64,
                                       block::tlb::aug_AccountTransactions};
    // Re-verify a known NFT at most once per touched account, not once per
    // transaction in that account block.
    td::Bits256 previous_owner;
    auto previous_owner_r = db->get_nft_owner(account, previous_owner);
    if (previous_owner_r.is_ok() && previous_owner_r.ok()) {
      nfts.insert(account);
    }
    size_t events_added = 0;
    trans_dict.check_for_each_extra([db, &account, &jettons, &nfts, &events_added, gen_utime, &age_rows_added,
                                     &write_error](td::Ref<vm::CellSlice> tvalue, td::Ref<vm::CellSlice> /*textra*/,
                                                   td::ConstBitPtr /*tkey*/, int /*tn*/) -> bool {
      auto tx_cell = tvalue->prefetch_ref();
      if (tx_cell.is_null()) {
        return true;
      }
      block::gen::Transaction::Record trans;
      if (!tlb::unpack_cell(tx_cell, trans)) {
        return true;
      }
      auto status = db->put_event(account, static_cast<uint64_t>(trans.lt), tx_cell);
      if (status.is_error()) {
        LOG(WARNING) << "wc0-index: put_event failed: " << status.message();
      } else {
        // Pair every event with its age-index row so the global time-based prune
        // can reach it. Committing the event without its age row would leave an
        // orphan the pruner can never find, so a failed age write fails the whole
        // block (aborted below) rather than persisting a half-pair.
        auto age_status = db->put_event_age(account, static_cast<uint64_t>(trans.lt), gen_utime);
        if (age_status.is_error()) {
          LOG(WARNING) << "wc0-index: put_event_age failed: " << age_status.message();
          write_error = true;
        } else {
          ++events_added;
          ++age_rows_added;
        }
      }
      // A freshly deployed token contract has no token operation in its first
      // inbound message: StateInit plus an application-specific mint body
      // activates it. Nominate every newly activated account for both probes;
      // the post-state getters below are authoritative and reject ordinary
      // contracts. This closes initial NFT/jetton mint indexing without
      // trusting message shape or contract code hashes.
      if (trans.orig_status != block::gen::AccountStatus::acc_state_active &&
          trans.end_status == block::gen::AccountStatus::acc_state_active) {
        jettons.insert(account);
        nfts.insert(account);
      }
      // Collected without a bound: schedule_token_candidates bounds the
      // verification work and defers the excess instead of dropping it.
      collect_token_candidates(account, trans.r1.in_msg->prefetch_ref(), jettons, nfts);
      return true;
    });
    // Trim this account once, after all its events for the block are in -- not
    // once per transaction, which would re-scan its whole history each time.
    // The scan reads the committed DB, blind to the pending batch, so pass the
    // number of rows just added for this account: trim keeps that many fewer
    // committed rows (so the post-commit total stays bounded) and deletes at
    // least that many (so a high per-block add rate cannot outrun the bound).
    auto trim_status = db->trim_events(account, events_added);
    if (trim_status.is_error()) {
      LOG(WARNING) << "wc0-index: trim_events failed: " << trim_status.message();
    }
    return true;
  });
  return true;
}

}  // namespace

namespace {

bool token_candidate_in_shard(tos::ShardIdFull shard, const td::Bits256& address) {
  return wallet_index_state_contains(shard, address);
}

// The newest block state the index has verified against, kept so the token
// backlog can drain while no new block arrives.
struct IndexContext {
  tos::BlockIdExt block_id;
  uint64_t end_lt = 0;
  td::Ref<vm::Cell> state_root;
};
std::mutex g_context_mutex;
td::optional<IndexContext> g_context;  // guarded by g_context_mutex

void remember_context(const tos::BlockIdExt& block_id, uint64_t end_lt, td::Ref<vm::Cell> state_root) {
  std::lock_guard<std::mutex> guard(g_context_mutex);
  if (g_context && g_context.value().block_id.id.shard == block_id.id.shard && g_context.value().end_lt > end_lt) {
    return;
  }
  g_context = IndexContext{block_id, end_lt, std::move(state_root)};
}

td::optional<IndexContext> current_context() {
  std::lock_guard<std::mutex> guard(g_context_mutex);
  return g_context;
}

void forget_context() {
  std::lock_guard<std::mutex> guard(g_context_mutex);
  g_context = {};
}

// Verify the scheduled candidates against `state` (into the open batch).
td::Status verify_scheduled(WalletIndexDb* db, StateAccounts& state,
                            const std::vector<ScheduledTokenCandidate>& scheduled, uint64_t end_lt) {
  WalletIndexVerificationBudget verification_budget;
  // Each candidate is verified independently; one hostile contract must not
  // be able to abort the rest of the block's token indexing.
  return db->process_token_candidates(
      scheduled, [&](const ScheduledTokenCandidate& scheduled_candidate, size_t remaining) {
        verification_budget.begin_candidate(remaining);
        const auto& candidate = scheduled_candidate.candidate;
        if (candidate.kind == TokenKind::Jetton) {
          return index_jetton_candidate(db, state, candidate.address, end_lt, verification_budget);
        }
        return index_nft_candidate(db, state, candidate.address, end_lt, verification_budget);
      });
}

// Verify one candidate against `state` as of `end_lt` (into the open batch).
TokenVerifyOutcome verify_one(WalletIndexDb* db, StateAccounts& state, const TokenCandidate& candidate, uint64_t end_lt,
                              WalletIndexVerificationBudget& budget) {
  try {
    if (candidate.kind == TokenKind::Jetton) {
      return index_jetton_candidate(db, state, candidate.address, end_lt, budget);
    }
    return index_nft_candidate(db, state, candidate.address, end_lt, budget);
  } catch (...) {
    // The node failed to finish, not a verdict on the contract.
    return TokenVerifyOutcome::Retry;
  }
}

// Verify up to one block's worth of a pending block's remaining candidates
// against `context`'s state, which must be at least as new as the block.
// A candidate the state cannot decide goes to the back with one more
// attempt, and is parked once it has used them all; one of another shard
// waits for that shard's state. When none remain, the block is finished.
// The caller holds write_mutex. Returns whether anything moved.
bool resume_pending_block_locked(WalletIndexDb* db, const tos::BlockIdExt& block_id,
                                 const WalletIndexDb::PendingBlock& pending, const IndexContext& context) {
  if (context.end_lt < pending.end_lt) {
    return false;
  }
  tos::ShardIdFull shard{context.block_id.id.workchain, context.block_id.id.shard};
  StateAccounts state{context.state_root, shard};
  if (!state.ok() || !db->begin_batch().is_ok()) {
    return false;
  }
  auto pass = [&]() -> td::Result<bool> {
    TRY_STATUS(db->begin_token_pass());
    WalletIndexDb::PendingBlock rest;
    rest.end_lt = pending.end_lt;
    std::vector<ScheduledTokenCandidate> later;
    size_t take = std::min(pending.remaining.size(), kMaxTokenCandidatesPerBlock);
    bool moved = false;
    WalletIndexVerificationBudget budget;
    for (size_t i = 0; i < pending.remaining.size(); ++i) {
      const auto& entry = pending.remaining[i];
      if (i >= take || !token_candidate_in_shard(shard, entry.candidate.address)) {
        rest.remaining.push_back(entry);
        continue;
      }
      budget.begin_candidate(take - i);
      switch (verify_one(db, state, entry.candidate, context.end_lt, budget)) {
        case TokenVerifyOutcome::Done:
          moved = true;
          break;
        case TokenVerifyOutcome::Unverifiable:
          db->count_unverifiable_token_candidate();
          moved = true;
          break;
        case TokenVerifyOutcome::WriteFailed:
          return td::Status::Error("an index write failed");
        case TokenVerifyOutcome::Retry: {
          moved = true;
          auto attempts = static_cast<uint8_t>(entry.attempts + 1);
          if (attempts >= kMaxTokenCandidateAttempts) {
            TRY_STATUS(
                db->park_token_candidate(ScheduledTokenCandidate{entry.candidate, entry.attempts, pending.end_lt}));
          } else {
            later.push_back(ScheduledTokenCandidate{entry.candidate, attempts, pending.end_lt});
          }
          break;
        }
      }
    }
    rest.remaining.insert(rest.remaining.end(), later.begin(), later.end());
    if (rest.remaining.empty()) {
      TRY_STATUS(db->delete_pending_block(block_id));
      TRY_STATUS(db->delete_incomplete_block(block_id));
    } else {
      TRY_STATUS(db->put_pending_block(block_id, rest));
    }
    TRY_STATUS(db->save_token_counters());
    return moved;
  };
  auto moved = pass();
  if (moved.is_error()) {
    LOG(WARNING) << "wc0-index: resuming block " << block_id.id.to_str() << " failed: " << moved.error().message();
    db->abort_batch();
    return false;
  }
  auto committed = db->commit_batch();
  if (committed.is_error()) {
    LOG(WARNING) << "wc0-index: resuming block " << block_id.id.to_str() << " failed: " << committed.message();
    return false;
  }
  return moved.ok();
}

// Parked candidates retried per pass, and the pause after a full round.
constexpr size_t kParkedRetryPerPass = 256;
std::atomic<long long> g_parked_retry_pause_ms{10 * 60 * 1000};
std::mutex g_parked_mutex;
std::chrono::steady_clock::time_point g_parked_not_before{};  // guarded by g_parked_mutex

// Retry the next parked candidates, in turn, against `context`'s state. A
// definite result releases a candidate; one still undecided stays parked with
// its identity. After a full round the next waits a pause. The caller holds
// write_mutex. Returns whether any candidate was released.
bool retry_parked_locked(WalletIndexDb* db, const IndexContext& context) {
  {
    std::lock_guard<std::mutex> guard(g_parked_mutex);
    if (std::chrono::steady_clock::now() < g_parked_not_before) {
      return false;
    }
  }
  tos::ShardIdFull shard{context.block_id.id.workchain, context.block_id.id.shard};
  StateAccounts state{context.state_root, shard};
  if (!state.ok() || !db->begin_batch().is_ok()) {
    return false;
  }
  bool wrapped = false;
  auto pass = [&]() -> td::Result<bool> {
    TRY_STATUS(db->begin_token_pass());
    TRY_RESULT(parked, db->next_parked_token_candidates(kParkedRetryPerPass, wrapped));
    bool released = false;
    WalletIndexVerificationBudget budget;
    size_t remaining = parked.size();
    for (const auto& entry : parked) {
      budget.begin_candidate(remaining--);
      if (entry.lt > context.end_lt || !token_candidate_in_shard(shard, entry.candidate.address)) {
        continue;
      }
      switch (verify_one(db, state, entry.candidate, context.end_lt, budget)) {
        case TokenVerifyOutcome::Done:
          TRY_STATUS(db->unpark_token_candidate(entry.candidate));
          released = true;
          break;
        case TokenVerifyOutcome::Unverifiable:
          TRY_STATUS(db->unpark_token_candidate(entry.candidate));
          db->count_unverifiable_token_candidate();
          released = true;
          break;
        case TokenVerifyOutcome::WriteFailed:
          return td::Status::Error("an index write failed");
        case TokenVerifyOutcome::Retry:
          break;
      }
    }
    TRY_STATUS(db->save_token_counters());
    return released;
  };
  auto released = pass();
  if (released.is_error()) {
    LOG(WARNING) << "wc0-index: retrying parked candidates failed: " << released.error().message();
    db->abort_batch();
    return false;
  }
  if (db->commit_batch().is_error()) {
    return false;
  }
  if (wrapped) {
    std::lock_guard<std::mutex> guard(g_parked_mutex);
    g_parked_not_before = std::chrono::steady_clock::now() + std::chrono::milliseconds(g_parked_retry_pause_ms.load());
  }
  return released.ok();
}

}  // namespace

void wc0_index_block(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, tos::BlockIdExt block_id) {
  auto* db = wallet_index_db();
  // A block whose data could not be obtained keeps the recovery mark the
  // queue gave it, so startup recovery retries it.
  if (db == nullptr || block_root.is_null()) {
    return;
  }
  // Index the basechain (wc=0) for now; masterchain accounts are handled later.
  if (block_id.id.workchain != 0) {
    return;
  }
  auto seqno = block_id.id.seqno;
  // Indexing passes can come from the worker and from startup recovery, and
  // the write batch below is a single unsynchronized object: serialize
  // whole-block passes.
  std::lock_guard<std::mutex> guard(db->write_mutex());
  // A block indexed before whose remaining candidates are persisted with it:
  // nothing of the block itself is needed again. Its state, being at hand,
  // verifies them now.
  auto pending_r = db->get_pending_block(block_id);
  if (pending_r.is_error()) {
    LOG(WARNING) << "wc0-index: could not read the remaining candidates of block seqno=" << seqno
                 << ", skipping this pass: " << pending_r.error().message();
    return;
  }
  if (pending_r.ok()) {
    auto pending = pending_r.move_as_ok().value();
    tos::ShardIdFull shard{block_id.id.workchain, block_id.id.shard};
    if (state_root.not_null() && StateAccounts{state_root, shard}.ok()) {
      IndexContext context{block_id, pending.end_lt, state_root};
      resume_pending_block_locked(db, block_id, pending, context);
      remember_context(block_id, pending.end_lt, std::move(state_root));
    }
    return;
  }
  // Crash recovery: durably mark the block in-progress before indexing; the
  // marker delete joins the batch, so it disappears atomically with the
  // entries. A marker left behind on restart flags a block whose indexing
  // never committed. Keyed off the full block id (not just seqno): a
  // different shard can reuse the same seqno after a split/merge, and the
  // marker must identify exactly this block for crash recovery to re-fetch
  // the right one. If this write fails there is no safety net for a crash
  // during the indexing below, so the pass is skipped; the block keeps the
  // mark the recorder gave it when it was queued.
  auto marker_status = db->put_incomplete_block(block_id);
  if (marker_status.is_error()) {
    LOG(ERROR) << "wc0-index: failed to durably mark block seqno=" << seqno
               << " in-progress, skipping indexing this pass: " << marker_status.message();
    return;
  }
  if (!db->begin_batch().is_ok()) {
    LOG(WARNING) << "wc0-index: begin_batch failed for block seqno=" << seqno
                 << "; skipping indexing this pass (marker retained for retry)";
    return;
  }
  bool ok = false;
  std::set<td::Bits256> jetton_candidates, nft_candidates;
  unsigned long long end_lt = 0;
  uint32_t gen_utime = 0;
  size_t age_rows_added = 0;
  bool write_error = false;
  td::optional<TokenCandidate> unhandled;
  std::vector<TokenCandidate> spilled;
  auto state_for_context = state_root;
  bool state_usable = false;
  try {
    ok = index_block_walk(db, block_root, jetton_candidates, nft_candidates, end_lt, gen_utime, age_rows_added,
                          write_error);
    // Runs even when this block nominated nothing: deferred candidates from
    // earlier blocks drain here.
    tos::ShardIdFull shard{block_id.id.workchain, block_id.id.shard};
    StateAccounts state{std::move(state_root), shard};
    state_usable = state.ok();
    if (ok) {
      std::vector<TokenCandidate> block_candidates;
      block_candidates.reserve(jetton_candidates.size() + nft_candidates.size());
      for (const auto& wallet : jetton_candidates) {
        block_candidates.push_back(TokenCandidate{TokenKind::Jetton, wallet});
      }
      for (const auto& item : nft_candidates) {
        block_candidates.push_back(TokenCandidate{TokenKind::Nft, item});
      }
      // Without a usable post-apply state nothing can be verified; every
      // candidate of the block is deferred instead.
      size_t capacity = state.ok() ? kMaxTokenCandidatesPerBlock : 0;
      if (!state.ok() && !block_candidates.empty()) {
        LOG(WARNING) << "wc0-index: no usable post-apply state for block seqno=" << seqno << "; deferring "
                     << block_candidates.size() << " token candidates (events still indexed)";
      }
      auto scheduled_r = db->schedule_token_candidates(block_candidates, shard, capacity, end_lt);
      if (scheduled_r.is_error()) {
        // Fail closed: committing without the schedule would drop the block's
        // candidates. Keep the marker so a later pass retries the block.
        LOG(WARNING) << "wc0-index: token scheduling failed for block seqno=" << seqno << ": "
                     << scheduled_r.error().message();
        write_error = true;
      } else {
        auto scheduled = scheduled_r.move_as_ok();
        unhandled = db->first_unhandled_block_candidate();
        if (unhandled) {
          // Everything from the first candidate that found no room on, in
          // candidate order, is persisted with the block.
          auto from = unhandled.value();
          std::set<TokenCandidate> rest;
          for (const auto& candidate : block_candidates) {
            if (!(candidate < from)) {
              rest.insert(candidate);
            }
          }
          spilled.assign(rest.begin(), rest.end());
        }
        auto process_status = verify_scheduled(db, state, scheduled, end_lt);
        if (process_status.is_error()) {
          LOG(WARNING) << "wc0-index: token indexing failed for block seqno=" << seqno << ": "
                       << process_status.message();
          write_error = true;
        }
      }
    }
  } catch (vm::VmError& err) {
    LOG(WARNING) << "wc0-index: VmError while indexing block seqno=" << seqno << ": " << err.get_msg();
    ok = false;
  } catch (...) {
    LOG(WARNING) << "wc0-index: unknown error while indexing block seqno=" << seqno;
    ok = false;
  }
  if (!ok || write_error) {
    // Never persist a partial block: a parse failure, or a half-written
    // event/age pair. The retained incomplete-block marker triggers a re-index.
    db->abort_batch();
    return;
  }
  {
    // Advance the retention watermark and prune expired events inside this
    // block's batch. Fails closed: on any error -- a failed or would-be-regressed
    // watermark, or a failed prune -- abort the block and keep the
    // incomplete-block marker so a later pass retries, rather than commit event
    // rows with a broken retention state.
    auto retention_status = db->advance_retention(gen_utime, age_rows_added);
    if (retention_status.is_error()) {
      LOG(WARNING) << "wc0-index: retention maintenance failed for block seqno=" << seqno
                   << ", aborting this pass (marker retained for retry): " << retention_status.message();
      db->abort_batch();
      return;
    }
  }
  td::Status finish = td::Status::OK();
  if (unhandled) {
    // Some candidates found no room in the backlog: they are persisted with
    // the block, which stays marked unfinished until the indexing worker has
    // verified them all.
    WalletIndexDb::PendingBlock pending;
    pending.end_lt = end_lt;
    for (const auto& candidate : spilled) {
      pending.remaining.push_back(ScheduledTokenCandidate{candidate, 0, end_lt});
    }
    finish = db->put_pending_block(block_id, pending);
  } else {
    // Indexing completed for this block; clear its in-progress marker and
    // commit the block's entries atomically with it.
    finish = db->delete_pending_block(block_id);
    if (finish.is_ok()) {
      finish = db->delete_incomplete_block(block_id);
    }
  }
  if (finish.is_error()) {
    LOG(WARNING) << "wc0-index: recording the outcome of block seqno=" << seqno
                 << " failed, aborting this pass (marker retained for retry): " << finish.message();
    db->abort_batch();
    return;
  }
  auto s = db->commit_batch();
  if (s.is_error()) {
    LOG(WARNING) << "wc0-index: commit failed for block seqno=" << seqno << ": " << s.message();
    return;
  }
  if (state_usable) {
    remember_context(block_id, end_lt, std::move(state_for_context));
  }
}

namespace {

// After a sweep that left legacy rows undecided, wait this long before the
// next one, so rows that cannot be verified here do not keep the worker busy.
constexpr auto kLegacySweepPause = std::chrono::seconds(30);
std::mutex g_legacy_mutex;
std::chrono::steady_clock::time_point g_legacy_not_before{};  // guarded by g_legacy_mutex

}  // namespace

bool reconstruct_legacy_jetton_rows(size_t row_limit) {
  auto* db = wallet_index_db();
  if (db == nullptr) {
    return false;
  }
  {
    std::lock_guard<std::mutex> guard(g_legacy_mutex);
    if (std::chrono::steady_clock::now() < g_legacy_not_before) {
      return false;
    }
  }
  auto context_r = current_context();
  if (!context_r) {
    // Nothing to verify against yet: the rows stay unpublished.
    return false;
  }
  auto context = context_r.value();
  std::lock_guard<std::mutex> guard(db->write_mutex());
  auto pending = db->legacy_jettons_pending();
  if (pending.is_error() || !pending.ok()) {
    return false;
  }
  if (!db->begin_batch().is_ok()) {
    return false;
  }
  tos::ShardIdFull shard{context.block_id.id.workchain, context.block_id.id.shard};
  StateAccounts state{context.state_root, shard};
  uint64_t undecided = 0;
  size_t decided = 0;
  bool published = false;
  bool reached_end = false;
  auto pass = [&]() -> td::Status {
    TRY_RESULT(rows, db->legacy_jetton_rows(row_limit));
    reached_end = rows.reached_end;
    WalletIndexVerificationBudget budget;
    size_t remaining = rows.rows.size();
    for (const auto& row : rows.rows) {
      budget.begin_candidate(remaining--);
      if (!row.has_wallet) {
        // An unreadable row names no wallet to verify.
        ++undecided;
        continue;
      }
      TRY_RESULT(known, db->jetton_wallet_state(row.wallet));
      WalletIndexDb::JettonVerdict verdict{false, HashKey::zero(), HashKey::zero(), {}};
      uint64_t lt = context.end_lt;
      if (known && known.value().lt >= context.end_lt) {
        // A block at least as new as this state already decided the wallet;
        // its verified record decides the row.
        lt = known.value().lt;
        if (known.value().present) {
          verdict = {true, known.value().owner, known.value().master, make_jetton_value(row.wallet, lt)};
        }
      } else if (row.lt > context.end_lt || !state.ok()) {
        // This state is older than the row, or unusable: it cannot say.
        ++undecided;
        continue;
      } else {
        td::Bits256 owner = td::Bits256::zero();
        td::Bits256 master = td::Bits256::zero();
        auto checked = verify_jetton_wallet(state, row.wallet, owner, master, budget);
        if (checked == JettonVerification::Indeterminate || checked == JettonVerification::OtherShard) {
          ++undecided;
          continue;
        }
        if (checked == JettonVerification::Verified) {
          verdict = {true, owner, master, make_jetton_value(row.wallet, lt)};
        }
      }
      TRY_RESULT(done, db->decide_legacy_jetton(row, verdict, lt));
      if (done) {
        ++decided;
      } else {
        ++undecided;
      }
    }
    TRY_RESULT(finished, db->finish_legacy_jetton_pass(rows, undecided));
    published = finished;
    return td::Status::OK();
  };
  td::Status status;
  try {
    status = pass();
  } catch (...) {
    status = td::Status::Error("legacy reconstruction threw");
  }
  if (status.is_error()) {
    LOG(WARNING) << "wc0-index: legacy jetton reconstruction pass failed: " << status.message();
    db->abort_batch();
    return false;
  }
  auto committed = db->commit_batch();
  if (committed.is_error()) {
    LOG(WARNING) << "wc0-index: legacy jetton reconstruction commit failed: " << committed.message();
    return false;
  }
  if (reached_end && !published) {
    std::lock_guard<std::mutex> legacy_guard(g_legacy_mutex);
    g_legacy_not_before = std::chrono::steady_clock::now() + kLegacySweepPause;
    return decided > 0;
  }
  return true;
}

namespace {

// One bounded backlog pass against `context`'s state: candidates nominated no
// later than that state are verified, as a new block of the shard would.
// Returns whether any candidate was taken.
bool drain_backlog_once(WalletIndexDb* db, const IndexContext& context) {
  std::lock_guard<std::mutex> guard(db->write_mutex());
  if (!db->begin_batch().is_ok()) {
    return false;
  }
  tos::ShardIdFull shard{context.block_id.id.workchain, context.block_id.id.shard};
  StateAccounts state{context.state_root, shard};
  if (!state.ok()) {
    db->abort_batch();
    return false;
  }
  bool took = false;
  try {
    auto scheduled_r = db->schedule_token_candidates({}, shard, kMaxTokenCandidatesPerBlock, context.end_lt);
    if (scheduled_r.is_error()) {
      LOG(WARNING) << "wc0-index: backlog pass failed: " << scheduled_r.error().message();
      db->abort_batch();
      return false;
    }
    auto scheduled = scheduled_r.move_as_ok();
    took = !scheduled.empty();
    auto processed = verify_scheduled(db, state, scheduled, context.end_lt);
    if (processed.is_error()) {
      LOG(WARNING) << "wc0-index: backlog pass failed: " << processed.message();
      db->abort_batch();
      return false;
    }
  } catch (...) {
    LOG(WARNING) << "wc0-index: backlog pass threw";
    db->abort_batch();
    return false;
  }
  auto committed = db->commit_batch();
  if (committed.is_error()) {
    LOG(WARNING) << "wc0-index: backlog pass commit failed: " << committed.message();
    return false;
  }
  return took;
}

}  // namespace

namespace {

struct BlockToIndex {
  td::Ref<vm::Cell> block_root;
  td::Ref<vm::Cell> state_root;
  tos::BlockIdExt block_id;
};

using IndexQueue = BoundedWorkQueue<tos::BlockIdExt, BlockToIndex>;

// Lifecycle (start, flush, stop) is serialized by g_index_queue_mutex, which
// may be held across database writes and waits. The block-apply hook never
// takes it: it takes only g_producer_mutex, which nothing holds across I/O or
// a wait, so a stalled index cannot hold block application up.
std::unique_ptr<IndexQueue> g_index_queue;
std::mutex g_index_queue_mutex;
std::mutex g_producer_mutex;
IndexQueue* g_producer_queue = nullptr;  // guarded by g_producer_mutex
// Set by flush_wc0_index_for_exit (under g_producer_mutex): a block handed
// over from now on is only recorded for recovery, never indexed in this run.
bool g_producers_closed = false;  // guarded by g_producer_mutex
// Blocks handed over after the exit flush closed the queue.
std::atomic<uint64_t> g_late_blocks{0};
// The flush recorded the run as finished. Read and written under
// g_run_marker_mutex together with the run marker itself.
std::mutex g_run_marker_mutex;
std::atomic<bool> g_run_cleared{false};
// Blocks the hook could not queue because the worker was too far behind.
std::atomic<uint64_t> g_dropped_blocks{0};
std::atomic<uint64_t> g_dropped_blocks_logged{0};

std::atomic<bool> g_marking_fault{false};
std::mutex g_marking_stall_mutex;
std::condition_variable g_marking_stall_cv;
bool g_marking_stalled = false;  // guarded by g_marking_stall_mutex

// Waits while a test holds the recorder's writes, as a stalled disk would.
void wait_while_marking_stalled() {
  std::unique_lock<std::mutex> lock(g_marking_stall_mutex);
  g_marking_stall_cv.wait(lock, [] { return !g_marking_stalled; });
}

td::Status mark_blocks(WalletIndexDb& db, const std::vector<tos::BlockIdExt>& block_ids) {
  wait_while_marking_stalled();
  if (g_marking_fault.load()) {
    return td::Status::Error("injected marking fault");
  }
  return db.mark_blocks_incomplete(block_ids);
}

td::Status record_needs_rebuild(WalletIndexDb& db) {
  wait_while_marking_stalled();
  if (g_marking_fault.load()) {
    return td::Status::Error("injected marking fault");
  }
  return db.mark_needs_rebuild();
}

td::Status record_run_active(WalletIndexDb& db) {
  wait_while_marking_stalled();
  if (g_marking_fault.load()) {
    return td::Status::Error("injected marking fault");
  }
  return db.begin_indexing_run();
}

// Durably mark queued blocks before any of them is indexed: a block the worker
// never reaches (dropped, or the node stopped first) stays marked, startup
// recovery re-indexes it, and RPC reports the index unfinished until then.
bool mark_queued_blocks(const std::vector<tos::BlockIdExt>& block_ids) {
  auto dropped = g_dropped_blocks.load();
  auto logged = g_dropped_blocks_logged.exchange(dropped);
  if (dropped > logged) {
    LOG(WARNING) << "wc0-index: indexing fell " << kWc0IndexQueueCapacity << " blocks behind; " << dropped - logged
                 << " block(s) left marked for re-indexing at the next start";
  }
  auto* db = wallet_index_db();
  if (db == nullptr) {
    return false;
  }
  {
    std::lock_guard<std::mutex> run_guard(g_run_marker_mutex);
    if (g_run_cleared.load()) {
      // A block arrived after the exit flush recorded the run as finished:
      // the run is active again before the block is marked, so even if the
      // mark is lost the next start does not take the index for complete.
      LOG(ERROR) << "wc0-index: a block was handed over after the index was flushed for exit; "
                 << "recording the run as unfinished again";
      auto rearmed = record_run_active(*db);
      if (rearmed.is_error()) {
        LOG(ERROR) << "wc0-index: could not record the run as unfinished, will retry: " << rearmed.message();
        return false;
      }
      g_run_cleared.store(false);
    }
  }
  auto status = mark_blocks(*db, block_ids);
  if (status.is_error()) {
    LOG(ERROR) << "wc0-index: could not mark " << block_ids.size()
               << " queued block(s) for recovery, will retry: " << status.message();
    return false;
  }
  return true;
}

// The queue lost track of a block: record durably that the index needs a
// rebuild. Runs on the recorder thread, which retries until it succeeds.
bool persist_index_degraded() {
  LOG(ERROR) << "wc0-index: a block may have gone unindexed with no mark to recover it; the index needs a rebuild";
  auto* db = wallet_index_db();
  if (db == nullptr) {
    return false;
  }
  auto status = record_needs_rebuild(*db);
  if (status.is_error()) {
    LOG(ERROR) << "wc0-index: could not record that the index needs a rebuild, will retry: " << status.message();
    return false;
  }
  return true;
}

// --- Fetching block data the hook did not have ---

std::mutex g_fetcher_mutex;
Wc0IndexBlockFetcher g_fetcher;  // guarded by g_fetcher_mutex

// One answer the worker waits for. It may come after the worker gave up on
// it, so it is shared with the answering callback.
struct AnswerSlotBase {
  std::mutex mutex;
  std::condition_variable cv;
  bool done = false;
};

template <class T>
struct AnswerSlot : AnswerSlotBase {
  td::Result<T> result = td::Status::Error("not answered");
};

std::mutex g_fetch_wait_mutex;
std::shared_ptr<AnswerSlotBase> g_fetch_in_flight;  // guarded by g_fetch_wait_mutex
std::atomic<bool> g_fetch_abort{false};
std::atomic<long long> g_fetch_timeout_ms{
    std::chrono::duration_cast<std::chrono::milliseconds>(kWc0IndexFetchTimeout).count()};

// Start a request with `start`, handing it the answering callback, and wait
// for the answer on the worker thread. Gives up when the worker is stopping or
// the answer takes too long.
template <class T>
td::Result<T> await_answer(const std::function<void(std::function<void(td::Result<T>)>)>& start) {
  auto slot = std::make_shared<AnswerSlot<T>>();
  {
    std::lock_guard<std::mutex> guard(g_fetch_wait_mutex);
    g_fetch_in_flight = slot;
  }
  try {
    start([slot](td::Result<T> result) {
      {
        std::lock_guard<std::mutex> lock(slot->mutex);
        if (slot->done) {
          return;
        }
        slot->result = std::move(result);
        slot->done = true;
      }
      slot->cv.notify_all();
    });
  } catch (...) {
    std::lock_guard<std::mutex> guard(g_fetch_wait_mutex);
    g_fetch_in_flight.reset();
    return td::Status::Error("the fetcher threw");
  }
  td::Result<T> result = td::Status::Error("fetch abandoned");
  {
    std::unique_lock<std::mutex> lock(slot->mutex);
    auto limit = std::chrono::milliseconds(g_fetch_timeout_ms.load());
    bool answered = slot->cv.wait_for(lock, limit, [&] { return slot->done || g_fetch_abort.load(); });
    if (slot->done) {
      result = std::move(slot->result);
    } else {
      // Nobody will take a late answer.
      slot->done = true;
      result = answered ? td::Status::Error("fetch abandoned at shutdown") : td::Status::Error("fetch timed out");
    }
  }
  std::lock_guard<std::mutex> guard(g_fetch_wait_mutex);
  g_fetch_in_flight.reset();
  return result;
}

// Ask the installed fetcher for what the hook could not hand over. When it
// fails, the block stays marked for recovery.
td::Result<Wc0FetchedBlock> fetch_block(const tos::BlockIdExt& block_id, bool need_state) {
  Wc0IndexBlockFetcher fetcher;
  {
    std::lock_guard<std::mutex> guard(g_fetcher_mutex);
    fetcher = g_fetcher;
  }
  if (!fetcher) {
    return td::Status::Error("no block fetcher is installed");
  }
  return await_answer<Wc0FetchedBlock>(
      [&](std::function<void(td::Result<Wc0FetchedBlock>)> done) { fetcher(block_id, need_state, std::move(done)); });
}

std::mutex g_state_fetcher_mutex;
Wc0IndexStateFetcher g_state_fetcher;  // guarded by g_state_fetcher_mutex

// The newest state of the shard holding `address`, from the installed state
// fetcher: what the worker verifies against when no block it indexed gives
// one new enough, such as after a restart with no new block.
td::Result<Wc0NewestState> fetch_newest_state(const td::Bits256& address) {
  Wc0IndexStateFetcher fetcher;
  {
    std::lock_guard<std::mutex> guard(g_state_fetcher_mutex);
    fetcher = g_state_fetcher;
  }
  if (!fetcher) {
    return td::Status::Error("no state fetcher is installed");
  }
  return await_answer<Wc0NewestState>(
      [&](std::function<void(td::Result<Wc0NewestState>)> done) { fetcher(address, std::move(done)); });
}

void abort_block_fetch() {
  g_fetch_abort.store(true);
  std::shared_ptr<AnswerSlotBase> slot;
  {
    std::lock_guard<std::mutex> guard(g_fetch_wait_mutex);
    slot = g_fetch_in_flight;
  }
  if (slot) {
    // Taking the slot's lock orders this with the waiter's predicate check.
    {
      std::lock_guard<std::mutex> lock(slot->mutex);
    }
    slot->cv.notify_all();
  }
}

// After the newest state could not be had, wait this long before asking
// again, so an unanswerable request does not keep the worker busy.
constexpr auto kStateRetryPause = std::chrono::seconds(5);
std::mutex g_state_retry_mutex;
std::chrono::steady_clock::time_point g_state_not_before{};  // guarded by g_state_retry_mutex

// A state to verify `address`'s candidates against, at least as new as
// `min_lt`: the newest one a block gave, or else the newest the node has.
// With `refresh`, the node is asked for its newest state even when a usable
// one is at hand, so a verification that failed against an older state can
// meet a newer one.
td::optional<IndexContext> context_for(const td::Bits256& address, uint64_t min_lt, bool refresh) {
  auto context = current_context();
  bool usable =
      context && context.value().end_lt >= min_lt &&
      token_candidate_in_shard(
          tos::ShardIdFull{context.value().block_id.id.workchain, context.value().block_id.id.shard}, address);
  if (usable && !refresh) {
    return context;
  }
  {
    std::lock_guard<std::mutex> guard(g_state_retry_mutex);
    if (std::chrono::steady_clock::now() < g_state_not_before) {
      return usable ? context : td::optional<IndexContext>{};
    }
  }
  auto newest = fetch_newest_state(address);
  if (newest.is_error() || newest.ok().state_root.is_null()) {
    std::lock_guard<std::mutex> guard(g_state_retry_mutex);
    g_state_not_before = std::chrono::steady_clock::now() + kStateRetryPause;
    return usable ? context : td::optional<IndexContext>{};
  }
  auto state = newest.move_as_ok();
  remember_context(state.block_id, state.end_lt, state.state_root);
  IndexContext fresh{state.block_id, state.end_lt, state.state_root};
  bool fresh_usable =
      fresh.end_lt >= min_lt &&
      token_candidate_in_shard(tos::ShardIdFull{fresh.block_id.id.workchain, fresh.block_id.id.shard}, address);
  if (fresh_usable) {
    return fresh;
  }
  return usable ? context : td::optional<IndexContext>{};
}

std::atomic<uint64_t> g_pending_block_limit{kMaxPendingTokenBlocks};

// Background work while no block waits for the worker, bounded per call:
// drain the token backlog against the newest state the index knows, verify
// the persisted remaining candidates of an unfinished block, reconstruct
// legacy jetton rows, and retry parked candidates. Returns whether anything
// moved.
bool index_idle_step() {
  auto* db = wallet_index_db();
  if (db == nullptr) {
    return false;
  }
  bool progress = false;
  auto context = current_context();
  if (context) {
    auto stats = db->token_backlog_stats();
    if (stats.is_ok() && stats.ok().entries > 0) {
      progress = drain_backlog_once(db, context.value());
    }
    if (reconstruct_legacy_jetton_rows(kLegacyJettonRowsPerPass)) {
      progress = true;
    }
  }
  // An unfinished block: its remaining candidates are persisted, so only a
  // state at least as new as the block is needed, not the block itself.
  td::optional<std::pair<tos::BlockIdExt, WalletIndexDb::PendingBlock>> pending;
  auto scan = db->for_each_pending_block(1, [&](const tos::BlockIdExt& id, const WalletIndexDb::PendingBlock& p) {
    pending = std::make_pair(id, p);
    return td::Status::OK();
  });
  if (scan.is_ok() && pending && !pending.value().second.remaining.empty()) {
    const auto& block = pending.value();
    auto ctx = context_for(block.second.remaining.front().candidate.address, block.second.end_lt, false);
    if (ctx) {
      std::lock_guard<std::mutex> guard(db->write_mutex());
      auto current = db->get_pending_block(block.first);
      if (current.is_ok() && current.ok() &&
          resume_pending_block_locked(db, block.first, current.ok().value(), ctx.value())) {
        progress = true;
      }
    }
  }
  // Parked candidates, a bounded number per pass, against the node's newest
  // state.
  auto stats = db->token_backlog_stats();
  if (stats.is_ok() && stats.ok().parked > 0) {
    bool due = false;
    {
      std::lock_guard<std::mutex> guard(g_parked_mutex);
      due = std::chrono::steady_clock::now() >= g_parked_not_before;
    }
    td::optional<td::Bits256> address;
    if (due) {
      std::lock_guard<std::mutex> guard(db->write_mutex());
      address = db->first_parked_address();
    }
    if (address) {
      auto ctx = context_for(address.value(), 0, true);
      if (ctx) {
        std::lock_guard<std::mutex> guard(db->write_mutex());
        if (retry_parked_locked(db, ctx.value())) {
          progress = true;
        }
      }
    }
  }
  return progress;
}

// While the index holds as many unfinished blocks as it may, finish them
// before indexing another. Waits on the worker thread only; blocks applied
// meanwhile wait in the queue or stay marked for recovery.
void wait_for_pending_room(const tos::BlockIdExt& block_id) {
  auto* db = wallet_index_db();
  if (db == nullptr) {
    return;
  }
  bool logged = false;
  while (!g_fetch_abort.load()) {
    auto count = db->pending_block_count();
    if (count.is_error() || count.ok() < g_pending_block_limit.load()) {
      return;
    }
    if (!logged) {
      LOG(WARNING) << "wc0-index: " << count.ok() << " blocks still have candidates to verify; block "
                   << block_id.id.to_str() << " waits until one is finished";
      logged = true;
    }
    if (!index_idle_step()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }
}

void index_queued_block(BlockToIndex& block) {
  try {
    if (block.block_root.is_null()) {
      // The hook had only the block id: read the block here, off the
      // block-application path. The block keeps the recovery mark it was
      // given until it is indexed, so a read that fails or never answers
      // leaves it for startup recovery.
      auto fetched = fetch_block(block.block_id, block.state_root.is_null());
      if (fetched.is_error()) {
        LOG(WARNING) << "wc0-index: block " << block.block_id.id.to_str()
                     << " left marked for recovery: its data could not be read: " << fetched.error().message();
        return;
      }
      auto data = fetched.move_as_ok();
      if (data.block_root.is_null()) {
        LOG(WARNING) << "wc0-index: block " << block.block_id.id.to_str()
                     << " left marked for recovery: the read returned no block data";
        return;
      }
      block.block_root = std::move(data.block_root);
      if (block.state_root.is_null()) {
        block.state_root = std::move(data.state_root);
      }
    }
    wait_for_pending_room(block.block_id);
    wc0_index_block(std::move(block.block_root), std::move(block.state_root), block.block_id);
  } catch (...) {
    LOG(ERROR) << "wc0-index: indexing block " << block.block_id.id.to_str() << " threw";
  }
}

// Leave the index closed and say why, so RPC reports it unavailable rather
// than serving what it has as if it were complete.
bool refuse_to_index(std::string reason) {
  LOG(ERROR) << "wc0-index: indexing is disabled for this run: " << reason
             << "; the account-index RPC reports the index unavailable";
  set_wallet_index_unavailable(std::move(reason));
  set_wallet_index_db(nullptr);
  return false;
}

}  // namespace

void set_wc0_index_state_fetcher(Wc0IndexStateFetcher fetcher) {
  std::lock_guard<std::mutex> guard(g_state_fetcher_mutex);
  g_state_fetcher = std::move(fetcher);
}

void set_wc0_index_parked_retry_pause_for_testing(std::chrono::milliseconds pause) {
  g_parked_retry_pause_ms.store(pause.count());
}

void set_wc0_index_pending_block_limit_for_testing(uint64_t limit) {
  g_pending_block_limit.store(limit);
}

void set_wc0_index_block_fetcher(Wc0IndexBlockFetcher fetcher) {
  std::lock_guard<std::mutex> guard(g_fetcher_mutex);
  g_fetcher = std::move(fetcher);
}

bool start_wc0_index_worker(bool paused) {
  std::lock_guard<std::mutex> guard(g_index_queue_mutex);
  if (g_index_queue) {
    return true;
  }
  auto* db = wallet_index_db();
  if (db == nullptr) {
    LOG(ERROR) << "wc0-index: no index is open; the indexing worker is not started";
    return false;
  }
  auto previous_run = db->indexing_run_active();
  if (previous_run.is_error()) {
    return refuse_to_index(PSTRING() << "could not read the indexing-run marker: " << previous_run.error().message());
  }
  if (previous_run.ok()) {
    LOG(WARNING) << "wc0-index: the previous run did not finish cleanly and may have lost a block; "
                 << "the index is marked as needing a rebuild";
    auto latched = db->mark_needs_rebuild();
    if (latched.is_error()) {
      return refuse_to_index(PSTRING() << "the previous run did not finish cleanly and recording that the index "
                                       << "needs a rebuild failed: " << latched.message());
    }
  }
  // Durable (WAL-synced) before the queue exists, so before any block can be
  // handed over: a block applied in this run is always covered by the run
  // marker, even if the process stops before the block is marked.
  auto begun = record_run_active(*db);
  if (begun.is_error()) {
    return refuse_to_index(PSTRING() << "could not record the indexing run: " << begun.message());
  }
  g_run_cleared.store(false);
  g_late_blocks.store(0);
  g_fetch_abort.store(false);
  forget_context();
  {
    std::lock_guard<std::mutex> state_guard(g_state_retry_mutex);
    g_state_not_before = {};
  }
  {
    std::lock_guard<std::mutex> parked_guard(g_parked_mutex);
    g_parked_not_before = {};
  }
  {
    std::lock_guard<std::mutex> legacy_guard(g_legacy_mutex);
    g_legacy_not_before = {};
  }
  g_index_queue = std::make_unique<IndexQueue>(kWc0IndexQueueCapacity, mark_queued_blocks, index_queued_block,
                                               persist_index_degraded, 0, paused, index_idle_step);
  std::lock_guard<std::mutex> producers(g_producer_mutex);
  g_producers_closed = false;
  g_producer_queue = g_index_queue.get();
  return true;
}

void resume_wc0_index_worker() {
  std::lock_guard<std::mutex> guard(g_index_queue_mutex);
  if (!g_index_queue) {
    return;
  }
  std::lock_guard<std::mutex> producers(g_producer_mutex);
  if (!g_producers_closed) {
    g_index_queue->resume();
  }
}

bool flush_wc0_index_for_exit(Wc0IndexProducers producers, std::chrono::milliseconds limit) {
  std::lock_guard<std::mutex> guard(g_index_queue_mutex);
  if (!g_index_queue) {
    return true;
  }
  {
    std::lock_guard<std::mutex> producer_guard(g_producer_mutex);
    g_producers_closed = true;
  }
  // From here on nothing is indexed; every block handed over, before or
  // after this point, is covered by its recovery mark.
  g_index_queue->pause();
  bool recorded = g_index_queue->wait_recorded(limit);
  if (!recorded) {
    LOG(ERROR) << "wc0-index: queued blocks were not all marked for recovery in time; "
               << "the run stays recorded as unfinished";
    return false;
  }
  if (g_index_queue->degraded()) {
    LOG(ERROR) << "wc0-index: this run lost track of a block; the run stays recorded as unfinished";
    return false;
  }
  if (producers != Wc0IndexProducers::Quiesced) {
    LOG(WARNING) << "wc0-index: blocks may still be applied during this exit; the run stays recorded as "
                 << "unfinished and the next start reports that the index needs a rebuild";
    return false;
  }
  auto* db = wallet_index_db();
  if (db == nullptr) {
    return false;
  }
  // Serialized with the recorder's check of g_run_cleared: a block handed
  // over before this point is seen here and keeps the run active, and one
  // handed over after it is recorded only after the recorder has recorded the
  // run as active again.
  std::lock_guard<std::mutex> run_guard(g_run_marker_mutex);
  if (g_late_blocks.load() != 0) {
    LOG(ERROR) << "wc0-index: blocks were handed over after the queue was closed; the run stays recorded as "
               << "unfinished";
    return false;
  }
  auto ended = db->end_indexing_run();
  if (ended.is_error()) {
    LOG(ERROR) << "wc0-index: could not record the indexing run as finished: " << ended.message();
    return false;
  }
  g_run_cleared.store(true);
  return true;
}

void stop_wc0_index_worker() {
  std::unique_ptr<IndexQueue> queue;
  {
    std::lock_guard<std::mutex> guard(g_index_queue_mutex);
    abort_block_fetch();
    {
      std::lock_guard<std::mutex> producer_guard(g_producer_mutex);
      g_producer_queue = nullptr;
      g_producers_closed = false;
    }
    queue = std::move(g_index_queue);
  }
  // Joined outside the lifecycle lock; the hook no longer reaches the queue.
  // The recorder gets a last chance to mark what it holds (and, for a block
  // that arrived after the run was recorded as finished, to record the run
  // as active again first).
  queue.reset();
  forget_context();
  g_late_blocks.store(0);
  g_run_cleared.store(false);
}

bool wc0_index_degraded() {
  std::lock_guard<std::mutex> guard(g_producer_mutex);
  return g_producer_queue != nullptr && g_producer_queue->degraded();
}

void enqueue_wc0_index_block(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, tos::BlockIdExt block_id) {
  // Runs on the block-application path: no I/O, no logging, no lock that is
  // held across I/O or a wait anywhere else.
  std::lock_guard<std::mutex> guard(g_producer_mutex);
  if (g_producer_queue == nullptr) {
    return;
  }
  if (g_producers_closed) {
    // The exit flush has already accounted for the queue. This block is only
    // recorded; the recorder marks it, and the run is not recorded as
    // finished while such a block exists.
    g_late_blocks.fetch_add(1);
    g_producer_queue->record(block_id);
    return;
  }
  if (!g_producer_queue->push(block_id, BlockToIndex{std::move(block_root), std::move(state_root), block_id})) {
    g_dropped_blocks.fetch_add(1);
  }
}

void set_wc0_index_marking_stall_for_testing(bool stall) {
  {
    std::lock_guard<std::mutex> lock(g_marking_stall_mutex);
    g_marking_stalled = stall;
  }
  g_marking_stall_cv.notify_all();
}

void set_wc0_index_fetch_timeout_for_testing(std::chrono::milliseconds limit) {
  g_fetch_timeout_ms.store(limit.count());
}

void set_wc0_index_marking_fault_for_testing(bool fail) {
  g_marking_fault.store(fail);
}

}  // namespace tos_wallet_index
