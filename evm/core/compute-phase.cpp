/*
    EVM Workchain — compute phase adapter implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/compute-phase.h"

#include "evm/core/transaction.h"
#include "evm/core/block-context.h"
#include "evm/core/executor.h"
#include "evm/core/native-commitment.h"
#include "evm/core/cell-state.h"
#include "evm/core/cell-codec.h"
#include "evm/core/init.h"
#include "evm/core/post-accept.h"
#include "evm/core/workchain.h"

#include <ethash/keccak.hpp>
#include "vm/cells/CellBuilder.h"

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>

#include <memory>
#include <string>

#include "td/utils/logging.h"

namespace evm_workchain {

namespace {

void reject_compute_phase(block::ComputePhase& cp,
                          uint64_t gas_limit,
                          std::string vm_log) {
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
    cp.vm_log = std::move(vm_log);
}

class CellStateRollbackSnapshot {
  public:
    bool capture(EvmState& state) {
        std::unique_lock lock(state.mutex());
        cell_state_ = dynamic_cast<CellEvmState*>(&state.state());
        if (cell_state_ == nullptr) {
            return false;
        }
        account_root_ = cell_state_->serialize_to_cell();
        block_hashes_root_ = cell_state_->serialize_block_hashes_to_cell();
        captured_ = true;
        return true;
    }

    void restore(EvmState& state) {
        if (!captured_) {
            return;
        }
        std::unique_lock lock(state.mutex());
        auto* current_cell_state = dynamic_cast<CellEvmState*>(&state.state());
        if (current_cell_state != nullptr) {
            // Rebind via TrustedLazy: the captured root cell hash is owned by
            // this snapshot (no external attacker influence) so the per-rollback
            // cost stays O(1) instead of O(global state size).
            CHECK(current_cell_state->load_from_cell(
                account_root_, CellStateLoadMode::TrustedLazy));
            CHECK(current_cell_state->load_block_hashes_from_cell(block_hashes_root_));
            current_cell_state->reset_delta_stats();
        }
    }

    bool captured() const noexcept { return captured_; }

  private:
    CellEvmState* cell_state_{nullptr};
    td::Ref<vm::Cell> account_root_;
    td::Ref<vm::Cell> block_hashes_root_;
    bool captured_{false};
};

// Helper that runs an EIP-4788 / EIP-2935 (or any future protocol-injected)
// system transaction directly against the underlying state. Returns
// `td::Status::OK()` when the system tx ran without throwing; any system
// call exception (predeploy missing or corrupt) surfaces as a non-OK status
// and the caller MUST treat it as a deterministic reject for the entire
// block-tx attempt.
//
// Contract: the caller does NOT hold `state.mutex()`. The helper takes the
// unique_lock itself and executes the system tx via the same silkworm EVM
// machinery the user path uses.
td::Status execute_system_transaction(
    EvmState& state,
    const silkworm::Block& block,
    const silkworm::ChainConfig& config,
    const silkworm::Transaction& sys_txn,
    uint64_t block_seqno,
    const char* label) {
    std::unique_lock lock(state.mutex());

    try {
        silkworm::IntraBlockState ibs(state.state());
        silkworm::EVM sys_evm(block, ibs, config);
        sys_evm.execute(sys_txn, silkworm::protocol::kSystemCallGasLimit);
        ibs.destruct_touched_dead();
        ibs.write_to_db(block_seqno);
    } catch (const std::exception& e) {
        return td::Status::Error(
            std::string(label) + " system call threw: " + e.what());
    } catch (...) {
        return td::Status::Error(
            std::string(label) + " system call threw unknown exception");
    }

    return td::Status::OK();
}

// Build a fresh EvmState seeded from `account_data` (the cp.new_data v6
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
        evmc::bytes32 native_state_commitment{};
        td::Ref<vm::Cell> rpc_cache_root;
        td::Ref<vm::Cell> block_hashes_root;
        if (!decode_cp_new_data(account_data, state_root,
                                native_state_commitment,
                                rpc_cache_root,
                                &block_hashes_root,
                                nullptr)) {
            return nullptr;
        }
        // Cross-check the declared native_state_commitment against the
        // recomputed cell hash of state_root. The decoder already does this,
        // but recomputing here defends against a future caller-edit that
        // bypasses the decoder.
        evmc::bytes32 recomputed =
            compute_native_evm_state_commitment(state_root);
        if (std::memcmp(recomputed.bytes,
                        native_state_commitment.bytes, 32) != 0) {
            return nullptr;
        }
        // Hot path: bind the account dictionary without enumerating accounts,
        // storage, or code. The cell hash of `state_root` is already
        // authenticated by the surrounding TOS account state, and the full
        // strict scan in `StrictValidateNative` mode scales with global state
        // size — that is unmetered host work and must not run for every EVM
        // tx.
        if (state_root.not_null() &&
            !cell_state->load_from_cell(state_root, CellStateLoadMode::TrustedLazy)) {
            return nullptr;
        }
        if (!cell_state->load_block_hashes_from_cell(block_hashes_root)) {
            return nullptr;
        }
    }

    auto state = std::make_unique<EvmState>(std::move(cell_state));

    // First-activation seeding for protocol predeploys. Production genesis
    // account allocations come from the parameterised alloc path, while this
    // snapshot path also runs in tests or when an executor account is first
    // activated mid-life. Mirror init_evm_workchain's protocol predeploy setup
    // without introducing any default funded EOAs.
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

    // tos8 audit: reject cheap admission failures before EIP-4788/EIP-2935
    // system calls and before the bounded full-state budget scan. Wrong
    // chain-id, oversized gas limit, bad nonce, and insufficient-balance
    // messages must not force an unpaid dictionary walk.
    if (auto prevalidation_error = prevalidate_evm_transaction_admission(
            decoded.txn, block, state, config)) {
        LOG(WARNING) << "evm-workchain: tx rejected before system calls: "
                     << *prevalidation_error;
        reject_compute_phase(cp, gas_limit, *prevalidation_error);
        return nullptr;
    }

    CellStateRollbackSnapshot rollback_snapshot;
    rollback_snapshot.capture(state);

    // --- Step 3b: EIP-4788 / EIP-2935 system calls (Cancun+ / Pectra+) ---
    //
    // A system call failure at this stage is a deterministic
    // consensus-level reject (the predeploy is either present and
    // executable or the entire block-tx attempt is invalid). The
    // legacy "continuing — predeploy may be missing" graceful-continue
    // path is GONE.
    {
        const auto rev = config.revision(block_seqno, timestamp);
        if (rev >= EVMC_CANCUN) {
            block.header.parent_beacon_block_root = evmc::bytes32{};
            silkworm::Transaction sys_txn{};
            sys_txn.type = silkworm::TransactionType::kSystem;
            sys_txn.to = silkworm::protocol::kBeaconRootsAddress;
            sys_txn.data = silkworm::Bytes(32, 0);
            sys_txn.set_sender(silkworm::protocol::kSystemAddress);
            auto st = execute_system_transaction(
                state, block, config, sys_txn, block_seqno, "EIP-4788");
            if (st.is_error()) {
                LOG(WARNING) << "evm-workchain: EIP-4788 system call rejected "
                                "block-tx attempt at #"
                             << block_seqno << ": " << st.message();
                rollback_snapshot.restore(state);
                reject_compute_phase(cp, gas_limit, st.message().str());
                return nullptr;
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
            auto st = execute_system_transaction(
                state, block, config, sys_txn, block_seqno, "EIP-2935");
            if (st.is_error()) {
                LOG(WARNING) << "evm-workchain: EIP-2935 system call rejected "
                                "block-tx attempt at #"
                             << block_seqno << ": " << st.message();
                rollback_snapshot.restore(state);
                reject_compute_phase(cp, gas_limit, st.message().str());
                return nullptr;
            }
        }
    }

    {
        std::unique_lock state_lock(state.mutex());
        if (auto* cs = dynamic_cast<CellEvmState*>(&state.state())) {
            cs->reset_delta_stats();
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
        rollback_snapshot.restore(state);
        reject_compute_phase(cp, gas_limit, exec_result.error_message);
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

    // --- Step 5d: Capture EVM state cell and compute native commitment ---
    td::Ref<vm::Cell> evm_state_cell;
    {
        std::unique_lock root_lock(state.mutex());
        auto* cs = dynamic_cast<CellEvmState*>(&state.state());
        if (cs == nullptr) {
            root_lock.unlock();
            rollback_snapshot.restore(state);
            reject_compute_phase(
                cp, gas_limit,
                "EVM state backend is not a CellEvmState; cannot serialize");
            return nullptr;
        }
        evm_state_cell = cs->serialize_to_cell();
    }
    const evmc::bytes32 native_state_commitment =
        compute_native_evm_state_commitment(evm_state_cell);

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
    fx->block.state_root = native_state_commitment;
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

    // The consensus compute path derives block-content commitments from the
    // side-effect records produced by this transaction, not from any MPT.
    // Multi-tx EVM blocks are deliberately rejected above until we have a
    // bounded incremental commitment accumulator that does not put full RPC
    // payloads into cp.new_data.
    bool have_raw_rlp_for_all_txs = true;
    for (const auto& t : block_transactions) {
        if (t.raw_rlp.empty()) {
            have_raw_rlp_for_all_txs = false;
            break;
        }
    }
    if (!have_raw_rlp_for_all_txs) {
        LOG(WARNING) << "evm-workchain: missing raw signed tx RLP while "
                     << "building native transactions commitment";
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        return nullptr;
    }
    fx->block.transactions_root =
        compute_native_tx_list_commitment(block_transactions);
    fx->block.receipts_root =
        compute_native_receipt_list_commitment(block_receipts);

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

    // --- Step 5g: Encode cp.new_data v6 (native-only) ---
    cp.new_data = encode_cp_new_data_v6(
        evm_state_cell,
        native_state_commitment,
        /*rpc_cache_root=*/{},
        block_hashes_cell);

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
