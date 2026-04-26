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

#include <ethash/keccak.hpp>
#include "vm/cells/CellBuilder.h"

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>

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
    td::Ref<vm::Cell> account_data) {
    auto cell_state = std::make_unique<CellEvmState>();

    if (account_data.not_null()) {
        td::Ref<vm::Cell> state_root;
        evmc::bytes32 eth_state_root{};
        td::Ref<vm::Cell> rpc_cache_root;
        td::Ref<vm::Cell> block_hashes_root;
        // The cp.new_data cell itself is already bound by the TOS account
        // state root. Snapshot compute executes from state_root and writes a
        // fresh eth_state_root after the transaction, so doing a full
        // Ethereum trie recompute here for every tx is redundant and
        // unmetered. Full declared-root verification remains enabled for
        // snapshot/global-state hydration paths.
        if (!decode_cp_new_data(account_data, state_root, eth_state_root,
                                rpc_cache_root,
                                /*verify_eth_state_root=*/false,
                                &block_hashes_root)) {
            return nullptr;
        }
        if (state_root.not_null() && !cell_state->load_from_cell(state_root)) {
            return nullptr;
        }
        if (!cell_state->load_block_hashes_from_cell(block_hashes_root)) {
            return nullptr;
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
    const uint8_t parent_block_hash[32]) {

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

    // Until a bounded incremental Ethereum tx/receipt trie accumulator exists,
    // accept at most one EVM transaction per TOS block. This avoids carrying
    // full transactions/receipts/logs in consensus cp.new_data while keeping
    // the persisted BLOCKHASH history canonical for the single-tx block.
    {
        std::unique_lock hash_lock(state.mutex());
        if (state.state().canonical_hash(block_seqno).has_value()) {
            LOG(WARNING) << "evm-workchain: rejecting extra EVM tx in TOS block #"
                         << block_seqno
                         << " (single-tx EVM block cap active)";
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
            cp.vm_log = "only one EVM transaction is allowed per TOS block";
            return nullptr;
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

    // --- Step 5f: Build single-transaction block summary ---
    std::vector<evmc::bytes32> block_tx_hashes;
    std::vector<StoredTransaction> block_transactions;
    std::vector<StoredReceipt> block_receipts;

    const uint32_t current_tx_index = 0;
    const uint64_t cumulative_gas_used = exec_result.gas_used;

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

    // The consensus compute path derives block roots from the side-effect
    // records produced by this transaction, not from EvmState. Multi-tx EVM
    // blocks are deliberately rejected above until we have a bounded
    // incremental trie accumulator that does not put full RPC payloads into
    // cp.new_data.
    auto transactions_root =
        try_compute_transactions_root_from_records(block_transactions);
    if (!transactions_root) {
        LOG(WARNING) << "evm-workchain: missing raw signed tx RLP while "
                     << "building transactionsRoot";
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        return nullptr;
    }
    fx->block.transactions_root = *transactions_root;
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
        data_cb.store_long(0, 1);  // block_accumulator = disabled/reserved
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

    auto local_state = build_local_state_from_account_data(std::move(account_data));
    if (!local_state) {
        LOG(WARNING) << "evm-workchain: account_data did not decode as cp.new_data";
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        return true;
    }

    auto fx = run_compute_against_state(
        cp, in_msg_body, gas_limit, *local_state,
        block_seqno, timestamp, rand_seed, parent_block_hash);

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
