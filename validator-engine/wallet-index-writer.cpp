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
#include <deque>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include "../validator/db/archive-gc-floor.h"
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
  // Where to look up accounts outside this shard; null for none.
  void set_other_shards(std::function<StateAccounts*(const td::Bits256&)> other) {
    other_shard_ = std::move(other);
  }
  // Load the active-state code+data of `addr`. False for missing / uninit / frozen.
  LoadResult load(const td::Bits256& addr, tos::SmartContract::State& out) {
    if (!dict_) {
      return LoadResult::Indeterminate;
    }
    if (!wallet_index_state_contains(shard_, addr)) {
      // Another shard's account (a jetton master or NFT collection beside
      // the wallet or item): its own shard's state answers, when one is at
      // hand.
      if (other_shard_) {
        if (auto* other = other_shard_(addr)) {
          return other->load(addr, out);
        }
      }
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
  std::function<StateAccounts*(const td::Bits256&)> other_shard_;
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
  auto newest = fetch_newest_state(address);
  if (newest.is_error() || newest.ok().state_root.is_null()) {
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
// Tests only: block commits still to fail.
std::atomic<int> g_commit_faults{0};

// Archive blocks the index may still need to read: those marked but whose
// candidates it has not extracted. The floor handed to archive pruning sits
// this far before the earliest of them, as slack for packages filed by
// masterchain time.
constexpr uint32_t kArchiveFloorMargin = 3600;
std::mutex g_floor_mutex;

uint32_t floor_for(uint32_t gen_utime) {
  return gen_utime > kArchiveFloorMargin ? gen_utime - kArchiveFloorMargin : 0;
}

// Blocks handed over but not yet durably marked, so their markers cannot yet
// keep them in the archive. Bounded however many are handed over: up to
// g_tracking_capacity are tracked one by one, in hand-over order; past that,
// the rest fold into one overflow floor, kept until every block handed over
// up to the last folded one is marked. Guarded by g_inflight_mutex, which
// nothing holds across I/O, so the block-apply hook may take it.
struct TrackedHandover {
  uint64_t seq;
  uint32_t floor;
};
std::mutex g_inflight_mutex;
std::deque<TrackedHandover> g_tracked;
uint32_t g_overflow_floor = tos::validator::kNoArchiveGcFloor;
uint64_t g_overflow_through_seq = 0;
uint64_t g_next_handover_seq = 1;
std::atomic<size_t> g_tracking_capacity{4096};

uint32_t inflight_floor_locked() {
  uint32_t value = g_overflow_floor;
  for (const auto& entry : g_tracked) {
    value = std::min(value, entry.floor);
  }
  return value;
}

// The block-apply hook, before it hands a block over: from here on archive
// pruning keeps the block, unless pruning had already given up a package
// that may hold it (then false). No I/O; both locks it takes are held for a
// few comparisons. Fills in the block's hand-over order.
bool protect_handed_over_block(MarkedBlock& block) {
  std::lock_guard<std::mutex> guard(g_inflight_mutex);
  block.handover_seq = g_next_handover_seq++;
  auto value = floor_for(block.gen_utime);
  if (!tos::validator::archive_retain(value, block.gen_utime)) {
    return false;
  }
  if (g_tracked.size() < g_tracking_capacity.load()) {
    g_tracked.push_back(TrackedHandover{block.handover_seq, value});
  } else {
    g_overflow_floor = std::min(g_overflow_floor, value);
    g_overflow_through_seq = block.handover_seq;
  }
  return true;
}

// The recorder, once the blocks' markers are durable: the markers keep them
// from now on. Ids are recorded in hand-over order, so everything handed over
// up to the last of them is marked, or was lost and is already recorded as
// needing a rebuild. Under g_floor_mutex, so a recomputation either reads the
// markers or still counts these blocks as handed over.
void release_handed_over_blocks(const std::vector<MarkedBlock>& blocks) {
  uint64_t through = 0;
  for (const auto& block : blocks) {
    through = std::max(through, block.handover_seq);
  }
  if (through == 0) {
    return;
  }
  std::lock_guard<std::mutex> floor_guard(g_floor_mutex);
  std::lock_guard<std::mutex> guard(g_inflight_mutex);
  while (!g_tracked.empty() && g_tracked.front().seq <= through) {
    g_tracked.pop_front();
  }
  if (g_overflow_floor != tos::validator::kNoArchiveGcFloor && g_overflow_through_seq <= through) {
    g_overflow_floor = tos::validator::kNoArchiveGcFloor;
  }
}

// Recompute the floor from the durable markers and the blocks handed over
// but not yet marked.
void publish_archive_floor(WalletIndexDb& db) {
  std::lock_guard<std::mutex> floor_guard(g_floor_mutex);
  auto floor = db.unextracted_block_floor();
  if (floor.is_error()) {
    // Keep what is published: a floor too low only keeps data longer.
    LOG(WARNING) << "wc0-index: could not read the archive floor: " << floor.error().message();
    return;
  }
  auto value = floor.ok() ? floor_for(floor.ok().value()) : tos::validator::kNoArchiveGcFloor;
  std::lock_guard<std::mutex> guard(g_inflight_mutex);
  tos::validator::archive_set_floor(std::min(value, inflight_floor_locked()));
}

// After a block's candidates were extracted: when it may have been the one
// holding the floor down, recompute it.
void refresh_archive_floor(WalletIndexDb& db, uint32_t gen_utime) {
  if (floor_for(gen_utime) <= tos::validator::archive_floor()) {
    publish_archive_floor(db);
  }
}

// The states one pass verifies against, one per shard, found as candidates
// need them: the newest a block gave, or the node's newest. A shard whose
// state cannot be had is remembered as such for the rest of the pass, so one
// unavailable shard costs one request, and candidates of other shards go on.
// Accounts of another shard than the candidate's (a master or collection)
// are looked up in that shard's state the same way.
class PassStates {
 public:
  PassStates(uint64_t min_lt, bool refresh) : min_lt_(min_lt), refresh_(refresh) {
  }
  PassStates(const PassStates&) = delete;
  PassStates& operator=(const PassStates&) = delete;
  void seed(const IndexContext& context) {
    add(context);
  }
  // The state for `address`'s shard, with its end lt; null when none can be
  // had at least min_lt new.
  StateAccounts* state_for(const td::Bits256& address, uint64_t& end_lt, tos::ShardIdFull* shard = nullptr) {
    for (auto& entry : states_) {
      if (token_candidate_in_shard(entry.shard, address)) {
        end_lt = entry.end_lt;
        if (shard != nullptr) {
          *shard = entry.shard;
        }
        return entry.state.get();
      }
    }
    for (const auto& missing : missing_) {
      if (missing == address) {
        return nullptr;
      }
    }
    auto context = context_for(address, min_lt_, refresh_);
    if (!context || !token_candidate_in_shard(shard_of(context.value()), address)) {
      missing_.push_back(address);
      return nullptr;
    }
    auto* state = add(context.value());
    if (state == nullptr) {
      missing_.push_back(address);
      return nullptr;
    }
    end_lt = context.value().end_lt;
    if (shard != nullptr) {
      *shard = shard_of(context.value());
    }
    return state;
  }

 private:
  struct Entry {
    tos::ShardIdFull shard;
    uint64_t end_lt;
    std::unique_ptr<StateAccounts> state;
  };
  static tos::ShardIdFull shard_of(const IndexContext& context) {
    return tos::ShardIdFull{context.block_id.id.workchain, context.block_id.id.shard};
  }
  StateAccounts* add(const IndexContext& context) {
    auto state = std::make_unique<StateAccounts>(context.state_root, shard_of(context));
    if (!state->ok()) {
      return nullptr;
    }
    state->set_other_shards([this](const td::Bits256& other) {
      uint64_t ignored = 0;
      return state_for(other, ignored);
    });
    states_.push_back(Entry{shard_of(context), context.end_lt, std::move(state)});
    return states_.back().state.get();
  }
  uint64_t min_lt_;
  bool refresh_;
  std::vector<Entry> states_;
  std::vector<td::Bits256> missing_;
};

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

// Verify up to one block's worth of a pending block's remaining candidates,
// each against its own shard's state, at least as new as the block. A
// candidate no state can decide yet goes to the back with one more attempt,
// and is parked once it has used them all, or stays here if parking is full;
// one whose shard's state cannot be had now stays as it is. When none
// remain, the block is finished. The caller holds write_mutex. Returns
// whether anything moved.
bool resume_pending_block_locked(WalletIndexDb* db, const tos::BlockIdExt& block_id,
                                 const WalletIndexDb::PendingBlock& pending, PassStates& states) {
  if (!db->begin_batch().is_ok()) {
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
    // The candidates not examined this pass go first; every examined one that
    // is still undecided, including one whose shard's state cannot be had
    // now, goes to the back. The record rotates, so no prefix of it can keep
    // the rest from being examined.
    for (size_t i = take; i < pending.remaining.size(); ++i) {
      rest.remaining.push_back(pending.remaining[i]);
    }
    for (size_t i = 0; i < take; ++i) {
      const auto& entry = pending.remaining[i];
      uint64_t end_lt = 0;
      StateAccounts* state = states.state_for(entry.candidate.address, end_lt);
      if (state == nullptr) {
        later.push_back(entry);
        continue;
      }
      budget.begin_candidate(take - i);
      switch (verify_one(db, *state, entry.candidate, end_lt, budget)) {
        case TokenVerifyOutcome::Done:
          moved = true;
          break;
        case TokenVerifyOutcome::WriteFailed:
          return td::Status::Error("an index write failed");
        case TokenVerifyOutcome::Unverifiable:
        case TokenVerifyOutcome::Retry: {
          moved = true;
          auto attempts = static_cast<uint8_t>(entry.attempts + 1);
          ScheduledTokenCandidate next{entry.candidate, attempts, pending.end_lt};
          if (attempts >= kMaxTokenCandidateAttempts) {
            TRY_RESULT(parked, db->park_token_candidate(next));
            if (!parked) {
              // No parking room: it keeps its place in this record.
              next.attempts = static_cast<uint8_t>(kMaxTokenCandidateAttempts - 1);
              later.push_back(next);
            }
          } else {
            later.push_back(next);
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

// Retry the next parked candidates, in turn from the durable cursor, each
// against the node's newest state of its own shard (and of any shard its
// master or collection is in). A definite result releases a candidate; one
// still undecided, or whose shard's state cannot be had, stays parked with
// its identity, and the cursor moves past it either way. After a full round
// the next waits a pause. The caller holds write_mutex. Returns whether any
// candidate was released.
bool retry_parked_locked(WalletIndexDb* db) {
  {
    std::lock_guard<std::mutex> guard(g_parked_mutex);
    if (std::chrono::steady_clock::now() < g_parked_not_before) {
      return false;
    }
  }
  if (!db->begin_batch().is_ok()) {
    return false;
  }
  bool wrapped = false;
  auto pass = [&]() -> td::Result<bool> {
    TRY_STATUS(db->begin_token_pass());
    TRY_RESULT(parked, db->next_parked_token_candidates(kParkedRetryPerPass, wrapped));
    bool released = false;
    WalletIndexVerificationBudget budget;
    size_t remaining = parked.size();
    PassStates states(0, true);
    for (const auto& entry : parked) {
      budget.begin_candidate(remaining--);
      uint64_t end_lt = 0;
      auto* state = states.state_for(entry.candidate.address, end_lt);
      if (state == nullptr || entry.lt > end_lt) {
        continue;
      }
      switch (verify_one(db, *state, entry.candidate, end_lt, budget)) {
        case TokenVerifyOutcome::Done:
          TRY_STATUS(db->unpark_token_candidate(entry.candidate));
          released = true;
          break;
        case TokenVerifyOutcome::WriteFailed:
          return td::Status::Error("an index write failed");
        case TokenVerifyOutcome::Unverifiable:
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

Wc0IndexResult wc0_index_block(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, tos::BlockIdExt block_id) {
  auto* db = wallet_index_db();
  // A block whose data could not be obtained keeps the recovery mark the
  // queue gave it, so startup recovery retries it.
  if (db == nullptr || block_root.is_null()) {
    return Wc0IndexResult::NotDone;
  }
  // Index the basechain (wc=0) for now; masterchain accounts are handled later.
  if (block_id.id.workchain != 0) {
    return Wc0IndexResult::NotDone;
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
    return Wc0IndexResult::NotDone;
  }
  if (pending_r.ok()) {
    auto pending = pending_r.move_as_ok().value();
    PassStates states(pending.end_lt, false);
    if (state_root.not_null()) {
      states.seed(IndexContext{block_id, pending.end_lt, state_root});
      remember_context(block_id, pending.end_lt, state_root);
    }
    resume_pending_block_locked(db, block_id, pending, states);
    return Wc0IndexResult::Done;
  }
  // Admission: the index holds at most a bounded number of blocks with
  // persisted candidates. At the bound a new block is not started; it keeps
  // its recovery mark (and with it the archive keeps its data), and the
  // caller finishes pending blocks before trying it again.
  auto pending_count = db->pending_block_count();
  if (pending_count.is_error() || pending_count.ok() >= g_pending_block_limit.load()) {
    return Wc0IndexResult::AtPendingCap;
  }
  uint32_t header_utime = 0;
  {
    block::gen::Block::Record header_blk;
    block::gen::BlockInfo::Record header_info;
    if (tlb::unpack_cell(block_root, header_blk) && tlb::unpack_cell(header_blk.info, header_info)) {
      header_utime = header_info.gen_utime;
    }
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
  auto marker_status = db->put_incomplete_block(block_id, header_utime);
  if (marker_status.is_error()) {
    LOG(ERROR) << "wc0-index: failed to durably mark block seqno=" << seqno
               << " in-progress, skipping indexing this pass: " << marker_status.message();
    return Wc0IndexResult::NotDone;
  }
  if (!db->begin_batch().is_ok()) {
    LOG(WARNING) << "wc0-index: begin_batch failed for block seqno=" << seqno
                 << "; skipping indexing this pass (marker retained for retry)";
    return Wc0IndexResult::NotDone;
  }
  bool ok = false;
  std::set<td::Bits256> jetton_candidates, nft_candidates;
  unsigned long long end_lt = 0;
  uint32_t gen_utime = 0;
  size_t age_rows_added = 0;
  bool write_error = false;
  td::optional<TokenCandidate> unhandled;
  std::vector<TokenCandidate> spilled;
  std::vector<ScheduledTokenCandidate> overflow;
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
        } else {
          overflow = db->overflow_block_candidates();
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
    return Wc0IndexResult::NotDone;
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
      return Wc0IndexResult::NotDone;
    }
  }
  td::Status finish = td::Status::OK();
  if (unhandled || !overflow.empty()) {
    // Some candidates found no room in the backlog: they are persisted with
    // the block, which stays marked unfinished until the indexing worker has
    // verified them all.
    WalletIndexDb::PendingBlock pending;
    pending.end_lt = end_lt;
    for (const auto& candidate : spilled) {
      pending.remaining.push_back(ScheduledTokenCandidate{candidate, 0, end_lt});
    }
    pending.remaining.insert(pending.remaining.end(), overflow.begin(), overflow.end());
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
    return Wc0IndexResult::NotDone;
  }
  if (g_commit_faults.load() > 0) {
    g_commit_faults.fetch_sub(1);
    LOG(WARNING) << "wc0-index: injected commit fault for block seqno=" << seqno;
    db->abort_batch();
    return Wc0IndexResult::NotDone;
  }
  auto s = db->commit_batch();
  if (s.is_error()) {
    LOG(WARNING) << "wc0-index: commit failed for block seqno=" << seqno << ": " << s.message();
    return Wc0IndexResult::NotDone;
  }
  if (state_usable) {
    remember_context(block_id, end_lt, std::move(state_for_context));
  }
  // Its candidates are extracted now (indexed, or persisted with it): the
  // archive need not keep it any longer.
  refresh_archive_floor(*db, header_utime);
  return Wc0IndexResult::Done;
}

namespace {

// One bounded backlog pass for the shard holding `address`, against that
// shard's newest known state: candidates nominated no later than that state
// are verified, as a new block of the shard would. Returns whether any
// candidate was taken.
bool drain_backlog_for(WalletIndexDb* db, const td::Bits256& address) {
  std::lock_guard<std::mutex> guard(db->write_mutex());
  PassStates states(0, false);
  uint64_t end_lt = 0;
  tos::ShardIdFull shard{0, tos::shardIdAll};
  auto* state = states.state_for(address, end_lt, &shard);
  if (state == nullptr) {
    return false;
  }
  if (!db->begin_batch().is_ok()) {
    return false;
  }
  bool took = false;
  try {
    auto scheduled_r = db->schedule_token_candidates({}, shard, kMaxTokenCandidatesPerBlock, end_lt);
    if (scheduled_r.is_error()) {
      LOG(WARNING) << "wc0-index: backlog pass failed: " << scheduled_r.error().message();
      db->abort_batch();
      return false;
    }
    auto scheduled = scheduled_r.move_as_ok();
    took = !scheduled.empty();
    auto processed = verify_scheduled(db, *state, scheduled, end_lt);
    if (processed.is_ok() && !db->overflow_block_candidates().empty()) {
      // Backlog entries keep their slots; only a block's own candidates can
      // overflow, and this pass has none.
      processed = td::Status::Error("a backlog entry lost its slot");
    }
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

using IndexQueue = BoundedWorkQueue<MarkedBlock, BlockToIndex>;

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

td::Status mark_blocks(WalletIndexDb& db, const std::vector<MarkedBlock>& block_ids) {
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
bool mark_queued_blocks(const std::vector<MarkedBlock>& block_ids) {
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
  // Their markers keep them in the archive from now on.
  release_handed_over_blocks(block_ids);
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

// Blocks marked by an earlier run whose candidates were never extracted,
// gathered when the worker starts and indexed by it before anything newer.
struct RecoveryEntry {
  MarkedBlock block;
  std::chrono::milliseconds pause{0};
  std::chrono::steady_clock::time_point not_before{};
};
std::mutex g_recovery_mutex;
std::deque<RecoveryEntry> g_recovery;  // guarded by g_recovery_mutex

// Rotation points of the background passes, so that one shard or block that
// cannot progress does not hold up the others. Worker thread only.
size_t g_drain_bucket = 0;
td::optional<tos::BlockIdExt> g_pending_after;

// After a failed attempt a recovered block waits before the next one, at most
// this long; it is never given up while it stays marked.
constexpr auto kRecoveryFirstPause = std::chrono::milliseconds(100);
constexpr auto kRecoveryLongestPause = std::chrono::seconds(60);

// Index the next recovered block that is due, read back from the archive
// (which keeps it while it is marked) by a block-only read: its candidates
// are verified later against newer states, so its own state is never waited
// for. A block whose read or indexing fails goes to the back with a growing
// pause, so the others go on. Returns whether a block was indexed; at_cap
// tells when the index is at its bound of unfinished blocks.
bool recover_one_marked_block(bool& at_cap) {
  at_cap = false;
  auto* db = wallet_index_db();
  RecoveryEntry entry;
  {
    std::lock_guard<std::mutex> guard(g_recovery_mutex);
    if (db == nullptr) {
      return false;
    }
    auto now = std::chrono::steady_clock::now();
    auto due =
        std::find_if(g_recovery.begin(), g_recovery.end(), [&](const RecoveryEntry& e) { return e.not_before <= now; });
    if (due == g_recovery.end()) {
      return false;
    }
    entry = *due;
    g_recovery.erase(due);
  }
  auto retry_later = [&](const char* what) {
    LOG(WARNING) << "wc0-index: recovery: block " << entry.block.id.id.to_str() << " " << what
                 << "; it stays marked and is tried again";
    entry.pause =
        std::min(entry.pause * 2, std::chrono::duration_cast<std::chrono::milliseconds>(kRecoveryLongestPause));
    entry.not_before = std::chrono::steady_clock::now() + entry.pause;
    std::lock_guard<std::mutex> guard(g_recovery_mutex);
    g_recovery.push_back(entry);
  };
  auto marked = db->has_incomplete_block(entry.block.id);
  if (marked.is_ok() && !marked.ok()) {
    return true;  // finished meanwhile
  }
  auto fetched = fetch_block(entry.block.id, false);
  if (fetched.is_error() || fetched.ok().block_root.is_null()) {
    retry_later("could not be read now");
    return false;
  }
  switch (wc0_index_block(fetched.ok().block_root, td::Ref<vm::Cell>{}, entry.block.id)) {
    case Wc0IndexResult::Done:
      return true;
    case Wc0IndexResult::AtPendingCap: {
      at_cap = true;
      std::lock_guard<std::mutex> guard(g_recovery_mutex);
      g_recovery.push_front(entry);
      return false;
    }
    case Wc0IndexResult::NotDone:
      retry_later("could not be indexed now");
      return false;
  }
  return false;
}

// Background work while no block waits for the worker, bounded per call:
// recover a block from an earlier run, drain the token backlog of one shard
// in turn, verify the persisted candidates of
// one unfinished block in turn, and retry parked candidates. Returns whether
// anything moved.
bool index_idle_step() {
  auto* db = wallet_index_db();
  if (db == nullptr) {
    return false;
  }
  bool progress = false;
  bool at_cap = false;
  if (recover_one_marked_block(at_cap)) {
    progress = true;
  }
  auto stats = db->token_backlog_stats();
  if (stats.is_ok() && stats.ok().entries > 0) {
    auto next = db->next_waiting_token_candidate(g_drain_bucket);
    if (next) {
      g_drain_bucket = (next.value().second + 1) % kTokenBacklogBuckets;
      if (drain_backlog_for(db, next.value().first)) {
        progress = true;
      }
    }
  }
  // An unfinished block, in turn: its remaining candidates are persisted, so
  // only states at least as new as the block are needed, not the block.
  td::optional<std::pair<tos::BlockIdExt, WalletIndexDb::PendingBlock>> pending;
  auto scan =
      db->next_pending_block(g_pending_after, [&](const tos::BlockIdExt& id, const WalletIndexDb::PendingBlock& p) {
        pending = std::make_pair(id, p);
        return td::Status::OK();
      });
  if (scan.is_ok()) {
    g_pending_after = pending ? td::optional<tos::BlockIdExt>(pending.value().first) : td::optional<tos::BlockIdExt>{};
  }
  if (pending) {
    std::lock_guard<std::mutex> guard(db->write_mutex());
    PassStates states(pending.value().second.end_lt, false);
    auto current = db->get_pending_block(pending.value().first);
    if (current.is_ok() && current.ok() &&
        resume_pending_block_locked(db, pending.value().first, current.ok().value(), states)) {
      progress = true;
    }
  }
  if (stats.is_ok() && stats.ok().parked > 0) {
    std::lock_guard<std::mutex> guard(db->write_mutex());
    if (retry_parked_locked(db)) {
      progress = true;
    }
  }
  return progress;
}

// Index a block, first recovering blocks of earlier runs; at the bound of
// unfinished blocks, finish some before trying again. Waits on the worker
// thread only; blocks applied meanwhile wait in the queue or, past it, stay
// marked, and the archive keeps them.
void index_with_admission(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, const tos::BlockIdExt& block_id) {
  bool logged = false;
  while (!g_fetch_abort.load()) {
    bool at_cap = false;
    while (recover_one_marked_block(at_cap)) {
    }
    if (!at_cap && wc0_index_block(block_root, state_root, block_id) != Wc0IndexResult::AtPendingCap) {
      return;
    }
    if (!logged) {
      LOG(WARNING) << "wc0-index: the index holds as many unfinished blocks as it may; block " << block_id.id.to_str()
                   << " waits until one is finished";
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
      // Block data only: a missing state is never waited for; the block's
      // candidates then wait for a newer state.
      auto fetched = fetch_block(block.block_id, false);
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
    }
    index_with_admission(std::move(block.block_root), std::move(block.state_root), block.block_id);
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

void set_wc0_index_tracking_capacity_for_testing(size_t capacity) {
  g_tracking_capacity.store(capacity);
}

size_t wc0_index_tracked_handovers_for_testing() {
  std::lock_guard<std::mutex> guard(g_inflight_mutex);
  return g_tracked.size();
}

void set_wc0_index_commit_faults_for_testing(int count) {
  g_commit_faults.store(count);
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
    std::lock_guard<std::mutex> parked_guard(g_parked_mutex);
    g_parked_not_before = {};
  }
  g_drain_bucket = 0;
  g_pending_after = {};
  {
    // Blocks of earlier runs whose candidates were never extracted: the
    // worker indexes them first, reading them back from the archive.
    std::deque<RecoveryEntry> recovery;
    auto collected = db->for_each_marked_block([&](const MarkedBlock& block) -> td::Status {
      TRY_RESULT(pending, db->get_pending_block(block.id));
      if (!pending) {
        recovery.push_back(RecoveryEntry{block, kRecoveryFirstPause / 2, {}});
      }
      return td::Status::OK();
    });
    if (collected.is_error()) {
      LOG(ERROR) << "wc0-index: could not read the blocks earlier runs left unfinished: " << collected.message();
    }
    std::lock_guard<std::mutex> recovery_guard(g_recovery_mutex);
    g_recovery = std::move(recovery);
  }
  // Before any block can be applied in this run: archive pruning keeps every
  // block the index has yet to read.
  publish_archive_floor(*db);
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
  {
    std::lock_guard<std::mutex> recovery_guard(g_recovery_mutex);
    g_recovery.clear();
  }
  {
    std::lock_guard<std::mutex> guard(g_inflight_mutex);
    g_tracked.clear();
    g_overflow_floor = tos::validator::kNoArchiveGcFloor;
    g_overflow_through_seq = 0;
  }
  tos::validator::archive_set_floor(tos::validator::kNoArchiveGcFloor);
  g_late_blocks.store(0);
  g_run_cleared.store(false);
}

bool wc0_index_degraded() {
  std::lock_guard<std::mutex> guard(g_producer_mutex);
  return g_producer_queue != nullptr && g_producer_queue->degraded();
}

void enqueue_wc0_index_block(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, tos::BlockIdExt block_id,
                             uint32_t gen_utime) {
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
    MarkedBlock late{block_id, gen_utime, 0};
    if (!protect_handed_over_block(late)) {
      // Not recorded for a later read: it could not be read back.
      g_producer_queue->latch_lost();
      return;
    }
    g_producer_queue->record(late);
    return;
  }
  MarkedBlock marked{block_id, gen_utime, 0};
  if (!protect_handed_over_block(marked)) {
    // Archive pruning already gave up a package that may hold this block, so
    // it cannot be read back later: it is indexed from what the hook holds
    // now, which the queue keeps even past its capacity (within a bound).
    // Without the block's data, or past that bound, it is lost beyond
    // recovery and the index is recorded as needing a rebuild.
    if (block_root.is_null() ||
        !g_producer_queue->push(marked, BlockToIndex{std::move(block_root), std::move(state_root), block_id}, true,
                                kWc0IndexPinnedExtra)) {
      g_producer_queue->latch_lost();
    }
    return;
  }
  if (!g_producer_queue->push(marked, BlockToIndex{std::move(block_root), std::move(state_root), block_id})) {
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
