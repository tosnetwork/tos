/*
    TOS wc=0 in-process wallet index — block-apply writer.
    See doc/tos-wc0-wallet-index.md.

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
#include "wallet-index-writer.h"
#include "wallet-index.h"

#include "block/block.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "smc-envelope/SmartContract.h"
#include "vm/cells.h"
#include "vm/dict.h"
#include "td/utils/logging.h"

#include <memory>
#include <mutex>
#include <set>
#include <vector>

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

// Get-method execution budget. Standard get_wallet_data / get_nft_data /
// resolver methods use a few thousand gas; the cap bounds what a hostile
// contract can burn per verification attempt.
constexpr long long kGetMethodGasLimit = 1'000'000;
// Bound the TVM verification work a single block can demand.
constexpr size_t kMaxTokenCandidatesPerBlock = 1024;

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
  explicit StateAccounts(td::Ref<vm::Cell> state_root) {
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
  bool load(const td::Bits256& addr, tos::SmartContract::State& out) {
    if (!dict_) {
      return false;
    }
    auto shard_acc_csr = dict_->lookup(addr.bits(), 256);
    if (shard_acc_csr.is_null()) {
      return false;
    }
    block::gen::ShardAccount::Record shard_acc;
    block::gen::Account::Record_account acc;
    block::gen::AccountStorage::Record store;
    block::gen::StateInit::Record state_init;
    if (!(tlb::csr_unpack(std::move(shard_acc_csr), shard_acc) && tlb::unpack_cell(shard_acc.account, acc) &&
          tlb::csr_unpack(std::move(acc.storage), store) && store.state->prefetch_ulong(1) == 1 &&
          store.state.write().advance(1) && tlb::csr_unpack(std::move(store.state), state_init))) {
      return false;
    }
    if (state_init.code->size_refs() < 1 || state_init.data->size_refs() < 1) {
      return false;
    }
    out.code = state_init.code->prefetch_ref();
    out.data = state_init.data->prefetch_ref();
    return true;
  }

 private:
  std::unique_ptr<vm::AugmentedDictionary> dict_;
};

// Run a gas-bounded get-method on (code,data) at wc=0 address `addr`.
// Returns a null stack on any failure.
td::Ref<vm::Stack> run_get(const tos::SmartContract::State& st, const td::Bits256& addr, td::Slice method,
                           std::vector<vm::StackEntry> params) {
  auto smc = tos::SmartContract::create(st);
  tos::SmartContract::Args args;
  args.set_address(block::StdAddress(0, addr));
  args.set_limits(vm::GasLimits{kGetMethodGasLimit});
  args.set_stack(std::move(params));
  auto res = smc->run_get_method(method, std::move(args));
  if (!res.success || res.stack.is_null()) {
    return {};
  }
  return res.stack;
}

// An internal MsgAddressInt slice for `addr` in wc=0, as a get-method argument.
vm::StackEntry make_addr_slice(const td::Bits256& addr) {
  vm::CellBuilder cb;
  cb.store_long(4, 3);  // addr_std$10 anycast:nothing$0
  cb.store_long(0, 8);  // workchain 0
  cb.store_bits(addr.bits(), 256);
  return vm::StackEntry{vm::load_cell_slice_ref(cb.finalize())};
}

bool extract_wc0_address(td::Ref<vm::CellSlice> csr, td::Bits256& out) {
  if (csr.is_null()) {
    return false;
  }
  tos::WorkchainId wc;
  tos::StdSmcAddress addr;
  if (!block::tlb::t_MsgAddressInt.extract_std_address(csr, wc, addr) || wc != 0) {
    return false;
  }
  out = addr;
  return true;
}

bool is_addr_none(const td::Ref<vm::CellSlice>& csr) {
  return csr.not_null() && csr->size() >= 2 && csr->prefetch_ulong(2) == 0;
}

// Verify that `wallet` is a jetton wallet acknowledged by its master, against the
// post-apply state. The master's own get_wallet_address resolver is the only
// authority on which contract is (owner, master)'s wallet — a hostile contract
// can claim any owner/master in get_wallet_data, but cannot make a master it
// does not control resolve back to it.
bool verify_jetton_wallet(StateAccounts& state, const td::Bits256& wallet, td::Bits256& owner_out,
                          td::Bits256& master_out) {
  tos::SmartContract::State wstate;
  if (!state.load(wallet, wstate)) {
    return false;
  }
  auto stack = run_get(wstate, wallet, "get_wallet_data", {});
  if (stack.is_null() || stack->depth() < 4) {
    return false;
  }
  // get_wallet_data -> (int balance, slice owner, slice master, cell wallet_code)
  auto& s = stack.write();
  s.pop();  // wallet_code
  auto master_csr = s.pop_cellslice();
  auto owner_csr = s.pop_cellslice();
  td::Bits256 owner, master;
  if (!extract_wc0_address(std::move(owner_csr), owner) || !extract_wc0_address(std::move(master_csr), master)) {
    return false;
  }
  tos::SmartContract::State mstate;
  if (!state.load(master, mstate)) {
    return false;  // fail-closed: unverifiable claim is not indexed
  }
  auto resolved_stack = run_get(mstate, master, "get_wallet_address", {make_addr_slice(owner)});
  if (resolved_stack.is_null() || resolved_stack->depth() < 1) {
    return false;
  }
  td::Bits256 resolved;
  if (!extract_wc0_address(resolved_stack.write().pop_cellslice(), resolved) || resolved != wallet) {
    return false;
  }
  owner_out = owner;
  master_out = master;
  return true;
}

// Verify `item` via get_nft_data against the post-apply state. For collection
// NFTs the collection's get_nft_address_by_index must resolve back to the item;
// a standalone NFT (collection = addr_none) is its own sole authority and is
// indexed as a self-claim, keyed by its own address.
bool verify_nft_item(StateAccounts& state, const td::Bits256& item, td::Bits256& owner_out, bool& has_collection,
                     td::Bits256& collection_out) {
  tos::SmartContract::State istate;
  if (!state.load(item, istate)) {
    return false;
  }
  auto stack = run_get(istate, item, "get_nft_data", {});
  if (stack.is_null() || stack->depth() < 5) {
    return false;
  }
  // get_nft_data -> (int init?, int index, slice collection, slice owner, cell content)
  auto& s = stack.write();
  s.pop();  // content
  auto owner_csr = s.pop_cellslice();
  auto coll_csr = s.pop_cellslice();
  auto index = s.pop_int();
  auto init = s.pop_int();
  if (init->sgn() == 0) {
    return false;  // uninitialized item
  }
  td::Bits256 owner;
  if (!extract_wc0_address(std::move(owner_csr), owner)) {
    return false;
  }
  if (is_addr_none(coll_csr)) {
    has_collection = false;
  } else {
    td::Bits256 collection;
    if (!extract_wc0_address(std::move(coll_csr), collection)) {
      return false;  // collection outside wc=0 cannot be verified — fail-closed
    }
    tos::SmartContract::State cstate;
    if (!state.load(collection, cstate)) {
      return false;
    }
    auto resolved_stack = run_get(cstate, collection, "get_nft_address_by_index", {vm::StackEntry(std::move(index))});
    if (resolved_stack.is_null() || resolved_stack->depth() < 1) {
      return false;
    }
    td::Bits256 resolved;
    if (!extract_wc0_address(resolved_stack.write().pop_cellslice(), resolved) || resolved != item) {
      return false;
    }
    has_collection = true;
    collection_out = collection;
  }
  owner_out = owner;
  return true;
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

// Verify and index one jetton-wallet candidate (into the open batch).
void index_jetton_candidate(WalletIndexDb* db, StateAccounts& state, const td::Bits256& wallet,
                            unsigned long long end_lt) {
  td::Bits256 owner, master;
  if (!verify_jetton_wallet(state, wallet, owner, master)) {
    return;
  }
  auto status = db->put_jetton(owner, master, make_jetton_value(wallet, end_lt));
  if (status.is_error()) {
    LOG(WARNING) << "wc0-index: put_jetton failed: " << status.message();
  }
}

// Verify and index one NFT-item candidate; erases the previous owner's entry
// when ownership changed (no stale entries).
void index_nft_candidate(WalletIndexDb* db, StateAccounts& state, const td::Bits256& item,
                         unsigned long long end_lt) {
  td::Bits256 owner, collection;
  bool has_collection = false;
  if (!verify_nft_item(state, item, owner, has_collection, collection)) {
    return;
  }
  td::Bits256 prev_owner;
  auto prev_r = db->get_nft_owner(item, prev_owner);
  if (prev_r.is_ok() && prev_r.ok() && prev_owner != owner) {
    db->erase_nft(prev_owner, item).ignore();
  }
  auto status = db->put_nft(owner, item, make_nft_value(has_collection, collection, end_lt));
  if (status.is_error()) {
    LOG(WARNING) << "wc0-index: put_nft failed: " << status.message();
  }
  db->put_nft_owner(item, owner).ignore();
}

// Walk the block's account_blocks: write event entries (into the open batch) and
// collect token-verification candidates. Returns false if the block envelope
// does not parse; fills `end_lt` from the block info.
bool index_block_walk(WalletIndexDb* db, td::Ref<vm::Cell> block_root, std::set<td::Bits256>& jettons,
                      std::set<td::Bits256>& nfts, unsigned long long& end_lt) {
  block::gen::Block::Record blk;
  block::gen::BlockInfo::Record info;
  block::gen::BlockExtra::Record extra;
  if (!(tlb::unpack_cell(block_root, blk) && tlb::unpack_cell(blk.info, info) && tlb::unpack_cell(blk.extra, extra))) {
    return false;
  }
  end_lt = info.end_lt;
  vm::AugmentedDictionary acc_dict{vm::load_cell_slice_ref(extra.account_blocks), 256,
                                   block::tlb::aug_ShardAccountBlocks};
  acc_dict.check_for_each_extra([db, &jettons, &nfts](td::Ref<vm::CellSlice> value,
                                                      td::Ref<vm::CellSlice> /*extra*/, td::ConstBitPtr /*key*/,
                                                      int /*n*/) -> bool {
    block::gen::AccountBlock::Record acc_blk;
    if (!tlb::csr_unpack(value, acc_blk)) {
      return true;  // skip
    }
    td::Bits256 account = acc_blk.account_addr;
    vm::AugmentedDictionary trans_dict{vm::DictNonEmpty(), acc_blk.transactions, 64,
                                       block::tlb::aug_AccountTransactions};
    trans_dict.check_for_each_extra([db, &account, &jettons, &nfts](td::Ref<vm::CellSlice> tvalue,
                                                                    td::Ref<vm::CellSlice> /*textra*/,
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
      }
      if (jettons.size() + nfts.size() < kMaxTokenCandidatesPerBlock) {
        collect_token_candidates(account, trans.r1.in_msg->prefetch_ref(), jettons, nfts);
      }
      return true;
    });
    return true;
  });
  return true;
}

}  // namespace

void wc0_index_block(td::Ref<vm::Cell> block_root, td::Ref<vm::Cell> state_root, tos::BlockIdExt block_id) {
  auto* db = wallet_index_db();
  if (db == nullptr || block_root.is_null()) {
    return;
  }
  // Index the basechain (wc=0) for now; masterchain accounts are handled later.
  if (block_id.id.workchain != 0) {
    return;
  }
  auto seqno = block_id.id.seqno;
  // Block-apply actors can run concurrently and the write batch below is a single
  // unsynchronized object — serialize whole-block passes.
  std::lock_guard<std::mutex> guard(db->write_mutex());
  // W3 crash recovery: durably mark the block in-progress before indexing; the
  // marker delete joins the batch, so it disappears atomically with the entries.
  // A marker left behind on restart flags a block whose indexing never committed.
  // Keyed off the full block id (not just seqno): a different shard can reuse
  // the same seqno after a split/merge, and the marker must identify exactly
  // this block for crash recovery to re-fetch the right one.
  //
  // If this write itself fails (or its WAL sync fails), there is no safety
  // net for a crash during the indexing below — skip indexing this pass
  // rather than proceed without one. This hook fires exactly once per block
  // (from ApplyBlock::applied_set), so skipping here leaves this specific
  // block's index entries permanently missing — nothing re-triggers it
  // automatically. That's logged at ERROR (not swallowed) so it's visible,
  // consistent with the "best-effort, never blocks consensus" tradeoff
  // already documented for this feature; a stronger guarantee would need an
  // in-memory retry queue or a full-index-rebuild path, neither of which
  // exists today.
  auto marker_status = db->put_incomplete_block(block_id);
  if (marker_status.is_error()) {
    LOG(ERROR) << "wc0-index: failed to durably mark block seqno=" << seqno
              << " in-progress, skipping indexing this pass: " << marker_status.message();
    return;
  }
  bool batch_open = db->begin_batch().is_ok();
  bool ok = false;
  std::set<td::Bits256> jetton_candidates, nft_candidates;
  unsigned long long end_lt = 0;
  try {
    ok = index_block_walk(db, block_root, jetton_candidates, nft_candidates, end_lt);
    if (ok && !(jetton_candidates.empty() && nft_candidates.empty())) {
      if (jetton_candidates.size() + nft_candidates.size() >= kMaxTokenCandidatesPerBlock) {
        LOG(WARNING) << "wc0-index: token candidate cap (" << kMaxTokenCandidatesPerBlock
                     << ") hit in block seqno=" << seqno << "; some token updates were skipped";
      }
      StateAccounts state{std::move(state_root)};
      if (state.ok()) {
        // Each candidate is verified independently; one hostile contract must not
        // be able to abort the rest of the block's token indexing.
        for (const auto& wallet : jetton_candidates) {
          try {
            index_jetton_candidate(db, state, wallet, end_lt);
          } catch (vm::VmError&) {
          } catch (vm::VmVirtError&) {
          }
        }
        for (const auto& item : nft_candidates) {
          try {
            index_nft_candidate(db, state, item, end_lt);
          } catch (vm::VmError&) {
          } catch (vm::VmVirtError&) {
          }
        }
      } else {
        LOG(WARNING) << "wc0-index: no usable post-apply state for block seqno=" << seqno
                     << "; token updates skipped (events still indexed)";
      }
    }
  } catch (vm::VmError& err) {
    LOG(WARNING) << "wc0-index: VmError while indexing block seqno=" << seqno << ": " << err.get_msg();
  } catch (...) {
    LOG(WARNING) << "wc0-index: unknown error while indexing block seqno=" << seqno;
  }
  if (!batch_open) {
    return;
  }
  if (ok) {
    // Indexing completed for this block; clear the in-progress marker and commit
    // the block's entries atomically. This is the second of two necessary WAL
    // syncs per block — the first was put_incomplete_block()'s own sync,
    // durable before indexing started; this one covers the entries themselves.
    db->delete_incomplete_block(block_id).ignore();
    auto s = db->commit_batch();
    if (s.is_error()) {
      LOG(WARNING) << "wc0-index: commit failed for block seqno=" << seqno << ": " << s.message();
    }
  } else {
    // Never persist a partial block.
    db->abort_batch();
  }
}

}  // namespace tos_wallet_index
