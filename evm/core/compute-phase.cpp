/*
    EVM Workchain — compute phase adapter implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/compute-phase.h"

#include "evm/core/transaction.h"
#include "evm/core/block-context.h"
#include "evm/core/executor.h"
#include "evm/core/state-root.h"
#include "evm/core/incremental-trie.h"
#include "evm/core/cell-state.h"
#include "evm/core/cell-codec.h"
#include "evm/core/init.h"
#include "evm/core/post-accept.h"
#include "evm/rpc/cache-codec.h"

#include <ethash/keccak.hpp>
#include "vm/cells/CellBuilder.h"

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>

#include <limits>
#include <memory>

#include "td/utils/logging.h"

namespace evm_workchain {

namespace {

// Build a fresh EvmState seeded from `account_data` (the cp.new_data v4
// cell from the previous block). Returns nullptr if the cell is malformed
// — caller must handle by emitting `sk_bad_state`. A null `account_data`
// returns a genesis-equivalent state with the EIP-4788 / EIP-2935
// predeploys present, so the very first transaction on a fresh executor
// account works under Cancun / Pectra.
std::unique_ptr<EvmState> build_local_state_from_account_data(
    td::Ref<vm::Cell> account_data,
    td::Ref<vm::Cell>* block_accumulator_root_out = nullptr) {
    auto cell_state = std::make_unique<CellEvmState>();
    if (block_accumulator_root_out) {
        *block_accumulator_root_out = {};
    }

    if (account_data.not_null()) {
        td::Ref<vm::Cell> state_root;
        evmc::bytes32 eth_state_root{};
        td::Ref<vm::Cell> rpc_cache_root;
        td::Ref<vm::Cell> block_hashes_root;
        td::Ref<vm::Cell> block_accumulator_root;
        if (!decode_cp_new_data(account_data, state_root, eth_state_root,
                                rpc_cache_root,
                                /*verify_eth_state_root=*/true,
                                &block_hashes_root,
                                &block_accumulator_root)) {
            return nullptr;
        }
        if (state_root.not_null() && !cell_state->load_from_cell(state_root)) {
            return nullptr;
        }
        if (!cell_state->load_block_hashes_from_cell(block_hashes_root)) {
            return nullptr;
        }
        if (block_accumulator_root_out) {
            *block_accumulator_root_out = std::move(block_accumulator_root);
        }
    }

    auto state = std::make_unique<EvmState>(std::move(cell_state));

    // First-activation seeding: the genesis builder
    // (build_evm_zerostate_accounts_cell) primes the 10 Hardhat dev EOAs
    // on a real chain start, but the snapshot path also runs in the test
    // harness and during the very first compute on an executor account
    // that was activated mid-life (no zerostate). Mirror what
    // init_evm_workchain does for g_evm_state so behaviour is identical
    // regardless of whether `account_data` was null because we're at
    // genesis or because the caller hasn't wired the executor yet.
    if (account_data.is_null()) {
        seed_eip4788_predeploy(*state);
        seed_eip2935_predeploy(*state);
    }

    return state;
}

struct EvmBlockAccumulator {
    uint64_t number{0};
    uint64_t timestamp{0};
    uint64_t gas_limit{0};
    intx::uint256 base_fee_per_gas{0};
    evmc::bytes32 parent_hash{};
    std::vector<evmc::bytes32> tx_hashes;
    std::vector<StoredTransaction> transactions;
    std::vector<StoredReceipt> receipts;
};

void store_uint256(vm::CellBuilder& cb, const intx::uint256& v) {
    auto be = intx::be::store<evmc::uint256be>(v);
    cb.store_bytes(be.bytes, 32);
}

bool load_uint256(vm::CellSlice& cs, intx::uint256& out) {
    evmc::uint256be be{};
    if (!cs.fetch_bytes(be.bytes, 32)) return false;
    out = intx::be::load<intx::uint256>(be);
    return true;
}

td::Ref<vm::Cell> encode_hash_list(const std::vector<evmc::bytes32>& hashes) {
    td::Ref<vm::Cell> next;
    for (auto it = hashes.rbegin(); it != hashes.rend(); ++it) {
        vm::CellBuilder cb;
        cb.store_bytes(it->bytes, 32);
        cb.store_long(next.not_null() ? 1 : 0, 1);
        if (next.not_null()) {
            cb.store_ref(next);
        }
        next = cb.finalize();
    }
    return next;
}

bool decode_hash_list(td::Ref<vm::Cell> root, std::vector<evmc::bytes32>& out) {
    out.clear();
    constexpr size_t kMaxAccumulatorItems = 10000;
    td::Ref<vm::Cell> cell = std::move(root);
    try {
        for (size_t i = 0; cell.not_null() && i < kMaxAccumulatorItems; ++i) {
            bool special = false;
            auto cs = vm::load_cell_slice_special(cell, special);
            if (special || cs.size() != 257) return false;
            evmc::bytes32 hash{};
            if (!cs.fetch_bytes(hash.bytes, 32)) return false;
            bool has_next = cs.fetch_ulong(1) != 0;
            if (cs.size() != 0) return false;
            if (cs.size_refs() != (has_next ? 1U : 0U)) return false;
            out.push_back(hash);
            cell = has_next ? cs.fetch_ref() : td::Ref<vm::Cell>{};
        }
        return cell.is_null();
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

td::Ref<vm::Cell> encode_transaction_list(const std::vector<StoredTransaction>& txs) {
    td::Ref<vm::Cell> next;
    for (auto it = txs.rbegin(); it != txs.rend(); ++it) {
        vm::CellBuilder cb;
        cb.store_long(next.not_null() ? 1 : 0, 1);
        cb.store_ref(encode_persisted_transaction(*it));
        if (next.not_null()) {
            cb.store_ref(next);
        }
        next = cb.finalize();
    }
    return next;
}

bool decode_transaction_list(td::Ref<vm::Cell> root,
                             std::vector<StoredTransaction>& out) {
    out.clear();
    constexpr size_t kMaxAccumulatorItems = 10000;
    td::Ref<vm::Cell> cell = std::move(root);
    try {
        for (size_t i = 0; cell.not_null() && i < kMaxAccumulatorItems; ++i) {
            bool special = false;
            auto cs = vm::load_cell_slice_special(cell, special);
            if (special || cs.size() != 1) return false;
            bool has_next = cs.fetch_ulong(1) != 0;
            if (cs.size_refs() != (has_next ? 2U : 1U)) return false;
            StoredTransaction tx;
            if (!decode_persisted_transaction(cs.fetch_ref(), tx)) return false;
            out.push_back(std::move(tx));
            cell = has_next ? cs.fetch_ref() : td::Ref<vm::Cell>{};
        }
        return cell.is_null();
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

td::Ref<vm::Cell> encode_receipt_list(const std::vector<StoredReceipt>& receipts) {
    td::Ref<vm::Cell> next;
    for (auto it = receipts.rbegin(); it != receipts.rend(); ++it) {
        vm::CellBuilder cb;
        cb.store_long(next.not_null() ? 1 : 0, 1);
        cb.store_ref(encode_persisted_receipt(*it));
        if (next.not_null()) {
            cb.store_ref(next);
        }
        next = cb.finalize();
    }
    return next;
}

bool decode_receipt_list(td::Ref<vm::Cell> root,
                         std::vector<StoredReceipt>& out) {
    out.clear();
    constexpr size_t kMaxAccumulatorItems = 10000;
    td::Ref<vm::Cell> cell = std::move(root);
    try {
        for (size_t i = 0; cell.not_null() && i < kMaxAccumulatorItems; ++i) {
            bool special = false;
            auto cs = vm::load_cell_slice_special(cell, special);
            if (special || cs.size() != 1) return false;
            bool has_next = cs.fetch_ulong(1) != 0;
            if (cs.size_refs() != (has_next ? 2U : 1U)) return false;
            StoredReceipt receipt;
            if (!decode_persisted_receipt(cs.fetch_ref(), receipt)) return false;
            out.push_back(std::move(receipt));
            cell = has_next ? cs.fetch_ref() : td::Ref<vm::Cell>{};
        }
        return cell.is_null();
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

td::Ref<vm::Cell> encode_block_accumulator(const EvmBlockAccumulator& acc) {
    constexpr uint32_t kBlockAccumulatorMagic = 0x42414343;  // "BACC"
    vm::CellBuilder cb;
    cb.store_long(kBlockAccumulatorMagic, 32);
    cb.store_long(acc.number, 64);
    cb.store_long(acc.timestamp, 64);
    cb.store_long(acc.gas_limit, 64);
    store_uint256(cb, acc.base_fee_per_gas);
    cb.store_bytes(acc.parent_hash.bytes, 32);
    cb.store_maybe_ref(encode_hash_list(acc.tx_hashes));
    cb.store_maybe_ref(encode_transaction_list(acc.transactions));
    cb.store_maybe_ref(encode_receipt_list(acc.receipts));
    return cb.finalize();
}

bool decode_block_accumulator(td::Ref<vm::Cell> root, EvmBlockAccumulator& out) {
    constexpr uint32_t kBlockAccumulatorMagic = 0x42414343;  // "BACC"
    out = {};
    try {
        if (root.is_null()) return false;
        bool special = false;
        auto cs = vm::load_cell_slice_special(root, special);
        if (special) return false;
        if (cs.size() < 32 + 64 + 64 + 64 + 256 + 256 + 3) return false;
        if (cs.fetch_ulong(32) != kBlockAccumulatorMagic) return false;
        out.number = cs.fetch_ulong(64);
        out.timestamp = cs.fetch_ulong(64);
        out.gas_limit = cs.fetch_ulong(64);
        if (!load_uint256(cs, out.base_fee_per_gas)) return false;
        if (!cs.fetch_bytes(out.parent_hash.bytes, 32)) return false;
        auto has_hashes = cs.fetch_ulong(1);
        td::Ref<vm::Cell> hashes_root;
        if (has_hashes == 1) {
            if (cs.size_refs() == 0) return false;
            hashes_root = cs.fetch_ref();
        }
        auto has_transactions = cs.fetch_ulong(1);
        td::Ref<vm::Cell> transactions_root;
        if (has_transactions == 1) {
            if (cs.size_refs() == 0) return false;
            transactions_root = cs.fetch_ref();
        }
        auto has_receipts = cs.fetch_ulong(1);
        td::Ref<vm::Cell> receipts_root;
        if (has_receipts == 1) {
            if (cs.size_refs() == 0) return false;
            receipts_root = cs.fetch_ref();
        }
        if (cs.size() != 0 || cs.size_refs() != 0) return false;
        if (!decode_hash_list(hashes_root, out.tx_hashes)) return false;
        if (!decode_transaction_list(transactions_root, out.transactions)) return false;
        if (!decode_receipt_list(receipts_root, out.receipts)) return false;
        return out.tx_hashes.size() == out.transactions.size() &&
               out.tx_hashes.size() == out.receipts.size();
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

bool same_bytes32(const evmc::bytes32& a, const evmc::bytes32& b) {
    return std::memcmp(a.bytes, b.bytes, 32) == 0;
}

// Core compute body, parameterised on the EvmState reference. Returns a
// non-null EvmBlockSideEffects when the tx executed (success or revert);
// returns nullptr only on infrastructure failure (caller should also have
// already populated cp.skip_reason).
std::shared_ptr<EvmBlockSideEffects> run_compute_against_state(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    EvmState& state,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32],
    td::Ref<vm::Cell> block_accumulator_root = {}) {

    // --- Step 1: Extract the raw Ethereum transaction from the message body ---
    auto payload_opt = extract_evm_payload(in_msg_body);
    if (!payload_opt.has_value()) {
        LOG(WARNING) << "evm-workchain: failed to extract EVM payload from message body";
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        return nullptr;
    }

    // --- Step 2: Decode the RLP transaction and recover sender ---
    auto decode_result = decode_evm_transaction(*payload_opt);
    if (auto* err = std::get_if<TxDecodeError>(&decode_result)) {
        LOG(WARNING) << "evm-workchain: transaction decode failed: " << err->reason;
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        return nullptr;
    }

    auto& decoded = std::get<DecodedTransaction>(decode_result);

    // --- Step 3: Build EVM block context from host-chain metadata ---
    auto block = make_evm_block(block_seqno, timestamp, rand_seed, gas_limit);
    const auto& config = evm_chain_config();

    // EIP-1559 base fee. All validators use the same fixed value so
    // gas accounting is consensus-deterministic across collator /
    // validator / restart. A "real" EIP-1559 base fee derived from the
    // parent block's gas usage would require threading parent
    // base_fee_per_gas + gas_used + gas_limit through ComputePhaseConfig
    // — tracked separately; not consensus-blocking because the fixed
    // value is the same on every node.
    block.header.base_fee_per_gas = intx::uint256{kInitialBaseFee};

    // Prefer the canonical EVM parent hash carried in cp.new_data. The host
    // parent block hash remains a fallback for the first block before any EVM
    // history has been serialized.
    evmc::bytes32 effective_parent_hash{};
    std::memcpy(effective_parent_hash.bytes, parent_block_hash, 32);
    if (block_seqno > 0) {
        std::unique_lock hash_lock(state.mutex());
        if (auto parent = state.state().canonical_hash(block_seqno - 1)) {
            effective_parent_hash = *parent;
        }
    }
    block.header.parent_hash = effective_parent_hash;

    EvmBlockAccumulator prior_accumulator;
    bool has_prior_accumulator = false;
    if (block_accumulator_root.not_null()) {
        if (!decode_block_accumulator(std::move(block_accumulator_root), prior_accumulator)) {
            LOG(WARNING) << "evm-workchain: malformed block accumulator in cp.new_data";
            cp.skip_reason = block::ComputePhase::sk_bad_state;
            return nullptr;
        }
        if (prior_accumulator.number > block_seqno) {
            LOG(WARNING) << "evm-workchain: future block accumulator in cp.new_data: "
                         << prior_accumulator.number << " > " << block_seqno;
            cp.skip_reason = block::ComputePhase::sk_bad_state;
            return nullptr;
        }
        if (prior_accumulator.number == block_seqno) {
            if (prior_accumulator.timestamp != timestamp ||
                prior_accumulator.gas_limit != block.header.gas_limit ||
                prior_accumulator.base_fee_per_gas != block.header.base_fee_per_gas.value_or(0) ||
                !same_bytes32(prior_accumulator.parent_hash, effective_parent_hash)) {
                LOG(WARNING) << "evm-workchain: block accumulator context mismatch in cp.new_data";
                cp.skip_reason = block::ComputePhase::sk_bad_state;
                return nullptr;
            }
            has_prior_accumulator = true;
        }
    }

    // --- Step 3b: EIP-4788 / EIP-2935 system calls (Cancun+ / Pectra+) ---
    {
        const auto rev = config.revision(block_seqno, timestamp);
        if (rev >= EVMC_CANCUN) {
            block.header.parent_beacon_block_root = evmc::bytes32{};
            silkworm::Transaction sys_txn{};
            sys_txn.type = silkworm::TransactionType::kSystem;
            sys_txn.to = silkworm::protocol::kBeaconRootsAddress;
            sys_txn.data = silkworm::Bytes(32, 0);
            sys_txn.set_sender(silkworm::protocol::kSystemAddress);
            std::unique_lock sys_lock(state.mutex());
            silkworm::IntraBlockState sys_ibs(state.state());
            silkworm::EVM sys_evm(block, sys_ibs, config);
            try {
                sys_evm.execute(sys_txn, silkworm::protocol::kSystemCallGasLimit);
                sys_ibs.destruct_touched_dead();
                sys_ibs.write_to_db(block_seqno);
            } catch (const std::exception& e) {
                LOG(ERROR) << "evm-workchain: EIP-4788 system call threw at block "
                           << block_seqno << ": " << e.what()
                           << " (continuing — predeploy may be missing)";
            } catch (...) {
                LOG(ERROR) << "evm-workchain: EIP-4788 system call threw at block "
                           << block_seqno << " (unknown exception)";
            }
        }

        if (rev >= EVMC_PRAGUE && block_seqno > 0) {
            // EIP-2935 historical-block-hash ring buffer write. The
            // host threads the wc=1 parent block's root_hash in via
            // `parent_block_hash`; we re-use the value already stored
            // on the block header above. Contracts that read the ring
            // buffer (L2 fraud-proof helpers, etc.) get the actual
            // parent hash instead of zero.
            silkworm::Transaction sys_txn{};
            sys_txn.type = silkworm::TransactionType::kSystem;
            sys_txn.to = silkworm::protocol::kHistoryStorageAddress;
            sys_txn.data = silkworm::Bytes{
                silkworm::ByteView{block.header.parent_hash.bytes, 32}};
            sys_txn.set_sender(silkworm::protocol::kSystemAddress);
            std::unique_lock sys_lock(state.mutex());
            silkworm::IntraBlockState sys_ibs(state.state());
            silkworm::EVM sys_evm(block, sys_ibs, config);
            try {
                sys_evm.execute(sys_txn, silkworm::protocol::kSystemCallGasLimit);
                sys_ibs.destruct_touched_dead();
                sys_ibs.write_to_db(block_seqno);
            } catch (const std::exception& e) {
                LOG(ERROR) << "evm-workchain: EIP-2935 system call threw at block "
                           << block_seqno << ": " << e.what()
                           << " (continuing — predeploy may be missing)";
            } catch (...) {
                LOG(ERROR) << "evm-workchain: EIP-2935 system call threw at block "
                           << block_seqno << " (unknown exception)";
            }
        }
    }

    // --- Step 4: Execute the transaction against the local state ---
    auto exec_result = execute_evm_transaction(decoded.txn, block, state, config);

    // Audit #2 (2026-04-26): pre-validation failures (bad nonce, insufficient
    // funds, intrinsic gas exceeds limit, EIP-1559/4844 violations, EIP-3607
    // sender-has-code, EIP-2681 nonce-at-max) must NOT be admitted as accepted
    // transactions. The previous behaviour mapped them to cp.accepted=true with
    // gas_used=0, which let an attacker spam the block with free invalid txs.
    // A pre-validation reject leaves state untouched (run_evm early-returned
    // before any state mutation), so we short-circuit with sk_bad_state and
    // no side effects.
    if (exec_result.disposition == EvmTxDisposition::InvalidPreValidation) {
        LOG(WARNING) << "evm-workchain: tx rejected at pre-validation: "
                     << exec_result.error_message;
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        cp.accepted = false;
        cp.success = false;
        cp.gas_used = 0;
        cp.gas_limit = gas_limit;
        cp.gas_credit = 0;
        cp.gas_max = gas_limit;
        cp.exit_code = 1;
        cp.vm_steps = 0;
        cp.vm_init_state_hash.set_zero();
        cp.vm_final_state_hash.set_zero();
        if (!exec_result.error_message.empty()) {
            cp.vm_log = exec_result.error_message;
        }
        return nullptr;  // No side effects, cp.new_data stays untouched
    }

    auto fx = std::make_shared<EvmBlockSideEffects>();
    auto tx_hash = decoded.txn.hash();
    fx->tx_hash = tx_hash;
    std::memcpy(fx->rand_seed.bytes, rand_seed, 32);

    // --- Step 5a: Capture receipt ---
    fx->receipt.type = decoded.txn.type;
    fx->receipt.success = exec_result.success;
    fx->receipt.gas_used = exec_result.gas_used;
    fx->receipt.cumulative_gas_used = exec_result.gas_used;
    fx->receipt.block_number = block_seqno;
    fx->receipt.tx_index = 0;
    fx->receipt.from = decoded.sender;
    fx->receipt.to = decoded.txn.to;
    fx->receipt.contract_address = exec_result.contract_address;
    fx->receipt.logs = exec_result.logs;
    fx->receipt.return_data = exec_result.return_data;

    // --- Step 5b: Capture transaction record ---
    fx->transaction.from = decoded.sender;
    fx->transaction.to = decoded.txn.to;
    fx->transaction.value = decoded.txn.value;
    fx->transaction.data = decoded.txn.data;
    fx->transaction.nonce = decoded.txn.nonce;
    fx->transaction.gas_limit = decoded.txn.gas_limit;
    fx->transaction.gas_price = decoded.txn.max_fee_per_gas;
    fx->transaction.block_number = block_seqno;
    fx->transaction.tx_index = 0;
    fx->transaction.raw_rlp = silkworm::Bytes{(*payload_opt).begin(), (*payload_opt).end()};

    // --- Step 5c: Capture logs ---
    fx->logs = exec_result.logs;

    // --- Step 5d: Compute EVM stateRoot (always, for cp.new_data) ---
    //
    // Audit #1 (2026-04-26): use a FRESH per-compute IncrementalTrieCalculator
    // and full recompute (nullptr change sets). The previous global cache held
    // mutable state across candidate blocks and the dirty set only tracked
    // sender / to / beneficiary / CREATE — inner-call touched accounts and
    // storage slots were not tracked, so two validators that had processed
    // different rejected candidates could compute different eth_state_root
    // for the same accepted block → state hash divergence / chain halt.
    // Each compute now starts from a fresh local state (built from the
    // previous executor transaction's cp.new_data) and a fresh trie calculator, so the
    // result is purely a function of the serialized state at that point.
    evmc::bytes32 evm_state_root;
    {
        std::unique_lock trie_lock(state.mutex());
        IncrementalTrieCalculator calc;
        evm_state_root = calc.compute_state_root(state, nullptr, nullptr);
        state.clear_change_tracking();
    }

    // --- Step 5e: Capture FULL EVM state cell tree for TOS account data ---
    td::Ref<vm::Cell> evm_state_cell;
    {
        std::unique_lock root_lock(state.mutex());
        auto* cs = dynamic_cast<CellEvmState*>(&state.state());
        if (cs) {
            evm_state_cell = cs->serialize_to_cell();
        }
    }

    // Audit #1 debug invariant: the cell tree we persist as cp.new_data
    // must round-trip to exactly the state root we just hashed in 5d.
    // Keep this as a debug/test guard so production avoids a second
    // O(N log N) trie pass per transaction.
#ifndef NDEBUG
    if (evm_state_cell.not_null()) {
        auto verify_cell_state = std::make_unique<CellEvmState>();
        CHECK(verify_cell_state->load_from_cell(evm_state_cell));
        EvmState verify_state(std::move(verify_cell_state));
        std::unique_lock vlock(verify_state.mutex());
        IncrementalTrieCalculator vcalc;
        auto verify_root = vcalc.compute_state_root(verify_state, nullptr, nullptr);
        CHECK(verify_root == evm_state_root);
    }
#endif

    {
        vm::CellBuilder actions_cb;
        cp.actions = actions_cb.finalize();
    }

    // --- Step 5f: Build cumulative block summary (always — apply will dedup) ---
    std::vector<evmc::bytes32> block_tx_hashes =
        has_prior_accumulator ? prior_accumulator.tx_hashes : std::vector<evmc::bytes32>{};
    std::vector<StoredTransaction> block_transactions =
        has_prior_accumulator ? prior_accumulator.transactions : std::vector<StoredTransaction>{};
    std::vector<StoredReceipt> block_receipts =
        has_prior_accumulator ? prior_accumulator.receipts : std::vector<StoredReceipt>{};

    if (block_tx_hashes.size() > std::numeric_limits<uint32_t>::max()) {
        LOG(WARNING) << "evm-workchain: too many EVM txs in block accumulator";
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        return nullptr;
    }
    const uint32_t current_tx_index = static_cast<uint32_t>(block_tx_hashes.size());
    const uint64_t prior_gas_used =
        block_receipts.empty() ? 0 : block_receipts.back().cumulative_gas_used;
    if (exec_result.gas_used > std::numeric_limits<uint64_t>::max() - prior_gas_used) {
        LOG(WARNING) << "evm-workchain: cumulative gas overflow in block accumulator";
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        return nullptr;
    }
    const uint64_t cumulative_gas_used = prior_gas_used + exec_result.gas_used;

    fx->receipt.tx_index = current_tx_index;
    fx->receipt.cumulative_gas_used = cumulative_gas_used;
    fx->transaction.tx_index = current_tx_index;

    block_tx_hashes.push_back(tx_hash);
    block_transactions.push_back(fx->transaction);
    block_receipts.push_back(fx->receipt);

    fx->has_block = true;
    fx->block.number = block_seqno;
    fx->block.timestamp = timestamp;
    fx->block.gas_used = cumulative_gas_used;
    fx->block.gas_limit = block.header.gas_limit;
    fx->block.base_fee_per_gas = block.header.base_fee_per_gas.value_or(0);
    fx->block.transaction_hashes = block_tx_hashes;
    fx->block.state_root = evm_state_root;
    // Audit #5 (2026-04-26): thread the real wc=1 parent block hash through
    // to fx->block.parent_hash. The previous behaviour wrote a zero parent
    // hash here, which made the reported eth-block hash inconsistent with
    // the EIP-2935 ring-buffer write and broke RPC block hash continuity.
    fx->block.parent_hash = effective_parent_hash;

    {
        uint8_t bloom[256] = {};
        for (const auto& receipt : block_receipts) {
            for (const auto& log : receipt.logs) {
                auto ah = ethash::keccak256(log.address.bytes, 20);
                for (int i = 0; i < 6; i += 2) {
                    uint16_t bit = (static_cast<uint16_t>(ah.bytes[i]) << 8 | ah.bytes[i + 1]) & 0x7FF;
                    bloom[bit / 8] |= (1 << (bit % 8));
                }
                for (const auto& topic : log.topics) {
                    auto th = ethash::keccak256(topic.bytes, 32);
                    for (int i = 0; i < 6; i += 2) {
                        uint16_t bit = (static_cast<uint16_t>(th.bytes[i]) << 8 | th.bytes[i + 1]) & 0x7FF;
                        bloom[bit / 8] |= (1 << (bit % 8));
                    }
                }
            }
        }
        std::memcpy(fx->block.logs_bloom, bloom, 256);
    }

    // Audit #5 (2026-04-26): derive block roots from the cumulative
    // side-effect records carried in cp.new_data, NOT from EvmState. This
    // lets the last transaction in a TOS block persist the final canonical
    // Ethereum transactionsRoot/receiptsRoot/blockHash for the whole EVM block.
    fx->block.transactions_root = compute_transactions_root_from_records(block_transactions);
    fx->block.receipts_root = compute_receipts_root_from_records(block_receipts);

    {
        silkworm::BlockHeader hdr{};
        std::memcpy(hdr.parent_hash.bytes, fx->block.parent_hash.bytes, 32);
        hdr.ommers_hash = silkworm::kEmptyListHash;
        std::memcpy(hdr.state_root.bytes, fx->block.state_root.bytes, 32);
        std::memcpy(hdr.transactions_root.bytes, fx->block.transactions_root.bytes, 32);
        std::memcpy(hdr.receipts_root.bytes, fx->block.receipts_root.bytes, 32);
        std::memcpy(hdr.logs_bloom.data(), fx->block.logs_bloom, 256);
        hdr.difficulty = 0;
        hdr.number = block_seqno;
        hdr.gas_limit = fx->block.gas_limit;
        hdr.gas_used = fx->block.gas_used;
        hdr.timestamp = timestamp;
        const std::string client_id = "evm-workchain/0.1.0";
        hdr.extra_data.assign(client_id.begin(), client_id.end());
        hdr.base_fee_per_gas = fx->block.base_fee_per_gas;
        hdr.withdrawals_root = silkworm::kEmptyRoot;
        hdr.blob_gas_used = 0;
        hdr.excess_blob_gas = 0;
        hdr.parent_beacon_block_root = evmc::bytes32{};
        {
            evmc::bytes32 rh{};
            static const uint8_t kSha256Empty[32] = {
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
            std::memcpy(rh.bytes, kSha256Empty, 32);
            hdr.requests_hash = rh;
        }
        const auto eth_hash = hdr.hash();
        std::memcpy(fx->block.hash.bytes, eth_hash.bytes, 32);
    }

    // Persist the EVM block-hash history alongside the account dictionary so
    // BLOCKHASH can be answered after snapshot rebuild or validator restart.
    td::Ref<vm::Cell> block_hashes_cell;
    {
        std::unique_lock root_lock(state.mutex());
        if (auto* cs = dynamic_cast<CellEvmState*>(&state.state())) {
            cs->canonize_block(block_seqno, fx->block.hash);
            block_hashes_cell = cs->serialize_block_hashes_to_cell();
        }
    }

    EvmBlockAccumulator next_accumulator;
    next_accumulator.number = block_seqno;
    next_accumulator.timestamp = timestamp;
    next_accumulator.gas_limit = fx->block.gas_limit;
    next_accumulator.base_fee_per_gas = fx->block.base_fee_per_gas;
    next_accumulator.parent_hash = effective_parent_hash;
    next_accumulator.tx_hashes = block_tx_hashes;
    next_accumulator.transactions = block_transactions;
    next_accumulator.receipts = block_receipts;
    auto block_accumulator_cell = encode_block_accumulator(next_accumulator);

    // --- Step 5g: Embed FULL EVM state + block history in cp.new_data ---
    {
        vm::CellBuilder data_cb;
        data_cb.store_long(static_cast<long long>(kEvmAccountMagic), kEvmMagicBits);
        data_cb.store_long(kCpNewDataSchemaVersion, 8);
        if (evm_state_cell.not_null()) {
            data_cb.store_long(1, 1);
            data_cb.store_ref(evm_state_cell);
        } else {
            data_cb.store_long(0, 1);
        }
        data_cb.store_bytes(reinterpret_cast<const char*>(evm_state_root.bytes), 32);
        data_cb.store_long(0, 1);  // rpc_cache_root = nothing
        if (block_hashes_cell.not_null()) {
            data_cb.store_long(1, 1);
            data_cb.store_ref(block_hashes_cell);
        } else {
            data_cb.store_long(0, 1);
        }
        if (block_accumulator_cell.not_null()) {
            data_cb.store_long(1, 1);
            data_cb.store_ref(block_accumulator_cell);
        } else {
            data_cb.store_long(0, 1);
        }
        cp.new_data = data_cb.finalize();
    }

    // --- Step 6: Map results back into the host-chain ComputePhase ---
    cp.success = exec_result.success;
    cp.accepted = true;
    cp.gas_used = exec_result.gas_used;
    cp.gas_limit = gas_limit;
    cp.gas_credit = 0;
    cp.gas_max = gas_limit;
    cp.exit_code = exec_result.success ? 0 : 1;
    cp.vm_steps = 0;

    cp.vm_init_state_hash.set_zero();
    cp.vm_final_state_hash.set_zero();

    if (!exec_result.error_message.empty()) {
        cp.vm_log = exec_result.error_message;
    }

    LOG(INFO) << "evm-workchain: execution " << (exec_result.success ? "success" : "revert")
              << ", gas_used=" << exec_result.gas_used
              << ", logs=" << exec_result.logs.size()
              << ", tx_hash=0x" << std::hex << tx_hash.bytes[0] << tx_hash.bytes[1];

    return fx;
}

}  // namespace

bool run_evm_compute_phase_snapshot(
    block::ComputePhase& cp,
    td::Ref<vm::Cell> account_data,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32]) {

    td::Ref<vm::Cell> block_accumulator_root;
    auto local_state = build_local_state_from_account_data(
        std::move(account_data), &block_accumulator_root);
    if (!local_state) {
        LOG(WARNING) << "evm-workchain: account_data did not decode as cp.new_data";
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        return true;
    }

    auto fx = run_compute_against_state(
        cp, in_msg_body, gas_limit, *local_state,
        block_seqno, timestamp, rand_seed, parent_block_hash,
        std::move(block_accumulator_root));

    if (fx) {
        cp.evm_side_effects = std::move(fx);
    }

    // Always return true: a malformed message body is a "skipped" tx
    // (cp.skip_reason populated above), not an infrastructure failure.
    return true;
}

bool run_evm_compute_phase(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    EvmState& state,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]) {

    // Legacy global-state path: no parent block hash plumbed in.
    // Pass zeros (matches its prior EIP-2935 behaviour) so the legacy
    // entry point retains identical semantics to before.
    static const uint8_t kZeroParentHash[32] = {0};
    auto fx = run_compute_against_state(
        cp, in_msg_body, gas_limit, state,
        block_seqno, timestamp, rand_seed, kZeroParentHash);

    if (fx) {
        cp.evm_side_effects = std::move(fx);
    }
    return true;
}

}  // namespace evm_workchain
