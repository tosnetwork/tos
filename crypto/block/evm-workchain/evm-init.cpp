/*
    EVM Workchain — module initialisation implementation.

    Registers the EVM compute phase handler with the host-chain dispatch
    mechanism defined in evm-workchain-dispatch.h.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-init.h"
#include "evm-workchain.h"

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/evm-workchain-dispatch.h"
#include "evm-cell-codec.h"
#include "evm-compute-phase.h"
#include "evm-state.h"
#include "evm-cell-state.h"
#include "evm-incremental-trie.h"

#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

#include <silkworm/core/types/account.hpp>

#include <cstdio>
#include <cstring>

#include "td/utils/logging.h"

namespace evm_workchain {

static std::unique_ptr<EvmState> g_evm_state;
static std::unique_ptr<IncrementalTrieCalculator> g_trie_calc;

EvmState& global_evm_state() {
    return *g_evm_state;
}

IncrementalTrieCalculator& global_trie_calculator() {
    return *g_trie_calc;
}

// =============================================================================
// PRE-FUNDED TEST ACCOUNTS  --  TEST CREDENTIALS, DO NOT USE FOR REAL FUNDS
// =============================================================================
//
// On a fresh chain (or any restart where the EVM state is empty) we seed
// 10 well-known test accounts with 10,000 TOS each. The mnemonic and private
// keys below are the standard Hardhat / Anvil / ethers test accounts —
// publicly documented, used by every Solidity tutorial and testnet on Earth.
// They MUST NEVER hold real value on any production chain.
//
// Mnemonic:  "test test test test test test test test test test test junk"
// Derivation path: m/44'/60'/0'/0/N (BIP-44 standard for ETH)
//
// To regenerate:
//   npx ts-node -e 'console.log(ethers.Wallet.fromPhrase("test test test ..."))'
//   cast wallet derive "test test test test test test test test test test test junk" -i N
//
// =============================================================================

namespace {

struct TestAccount {
    const char* address;   // 40 hex chars, no 0x prefix
    const char* privkey;   // 64 hex chars, no 0x prefix
};

// Hardhat / Anvil standard accounts #0..#9
constexpr TestAccount kTestAccounts[] = {
    {"f39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
     "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"},
    {"70997970C51812dc3A010C7d01b50e0d17dc79C8",
     "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"},
    {"3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
     "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"},
    {"90F79bf6EB2c4f870365E785982E1f101E93b906",
     "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"},
    {"15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
     "47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"},
    {"9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
     "8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"},
    {"976EA74026E726554dB657fA54763abd0C3a0aa9",
     "92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e"},
    {"14dC79964da2C08b23698B3D3cc7Ca32193d9955",
     "4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"},
    {"23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
     "dbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97"},
    {"a0Ee7A142d267C1f36714E4a8F75612F20a79720",
     "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"},
};

constexpr uint64_t kSeedAmountTos = 10000;  // 10,000 TOS per account

bool parse_hex_address(const char* hex, evmc::address& out) {
    for (int i = 0; i < 20; ++i) {
        unsigned x;
        if (std::sscanf(hex + i * 2, "%2x", &x) != 1) return false;
        out.bytes[i] = static_cast<uint8_t>(x);
    }
    return true;
}

void seed_test_accounts(EvmState& state) {
    // Idempotency: if account #0 already has any state (from a previous run
    // that was persisted), assume seeding has been done and skip. This makes
    // the function safe to call on every node startup, even after users have
    // moved test funds around.
    evmc::address first_addr{};
    parse_hex_address(kTestAccounts[0].address, first_addr);
    if (state.read_account(first_addr).has_value()) {
        LOG(WARNING) << "evm-workchain: test accounts already seeded, skipping";
        return;
    }

    // 10,000 TOS = 10000 × 10^18 wei
    intx::uint256 amount{kSeedAmountTos};
    for (int i = 0; i < 18; ++i) amount *= intx::uint256{10};

    LOG(WARNING) << "evm-workchain: seeding " << std::size(kTestAccounts)
                 << " TEST accounts (Hardhat/Anvil mnemonic) with "
                 << kSeedAmountTos << " TOS each";
    LOG(WARNING) << "evm-workchain: ⚠️  TEST CREDENTIALS — DO NOT USE FOR REAL FUNDS";
    LOG(WARNING) << "evm-workchain: mnemonic: \"test test test test test test "
                    "test test test test test junk\"";

    for (const auto& a : kTestAccounts) {
        evmc::address addr{};
        if (!parse_hex_address(a.address, addr)) continue;
        state.seed_account(addr, amount, /*nonce=*/0);
        LOG(WARNING) << "evm-workchain:   0x" << a.address;
    }
}

}  // anonymous namespace

// Decode a cp.new_data-shaped cell (see evm-compute-phase.cpp). Layout:
//   v1: magic:24 + has_state_root:1 + [state_root:^Cell] + eth_state_root:bits256
//   v2: same + Maybe ^EvmRpcCacheRoot (trailing bit, optional ref)
//
// Returns true if the cell parses. Backward-compatible: a v1 cell with
// no trailing bit is treated as `rpc_cache_root = nothing`. state_root
// may be null (has_state_root=0 case, valid per the encoder).
static bool decode_cp_new_data(const td::Ref<vm::Cell>& cell,
                               td::Ref<vm::Cell>& state_root_out,
                               evmc::bytes32& eth_state_root_out,
                               td::Ref<vm::Cell>& rpc_cache_root_out) {
    state_root_out = {};
    rpc_cache_root_out = {};
    if (cell.is_null()) return false;
    auto cs = vm::load_cell_slice(cell);
    if (cs.size() < kEvmMagicBits + 1 + 256) return false;
    auto magic = cs.fetch_ulong(kEvmMagicBits);
    if (magic != kEvmAccountMagic) return false;
    auto has_root = cs.fetch_ulong(1);
    if (has_root == 1) {
        if (cs.size_refs() == 0) return false;
        state_root_out = cs.fetch_ref();
    }
    if (cs.size() < 256) return false;
    cs.fetch_bytes(eth_state_root_out.bytes, 32);

    // v2 trailing field — tolerate v1 cells (no remaining bits) as nothing.
    if (cs.size() >= 1) {
        auto has_cache = cs.fetch_ulong(1);
        if (has_cache == 1) {
            if (cs.size_refs() == 0) return false;
            rpc_cache_root_out = cs.fetch_ref();
        }
    }
    return true;
}

size_t populate_state_from_shard_accounts(
    EvmState& target,
    vm::AugmentedDictionary& shard_accounts) {
    // Single-executor: the entire EVM world state lives inside the one
    // executor account's StateInit.data (cp.new_data format). Look up
    // kEvmExecutorAddress, decode the state_root ref, and load it into
    // the target's CellEvmState. Returns 1 on success, 0 otherwise.
    auto exec_value = shard_accounts.lookup(
        td::ConstBitPtr{kEvmExecutorAddressBytes}, 256);
    if (exec_value.is_null()) return 0;

    td::Ref<vm::Cell> account_cell;
    if (!block::tlb::t_ShardAccount.extract_account_state(exec_value, account_cell) ||
        account_cell.is_null()) {
        return 0;
    }

    block::gen::Account::Record_account acc_rec;
    if (!tlb::unpack_cell(account_cell, acc_rec)) return 0;

    unsigned long long last_trans_lt;
    td::Ref<vm::CellSlice> balance_cs, state_cs;
    if (!block::gen::t_AccountStorage.unpack_account_storage(
            acc_rec.storage.write(), last_trans_lt, balance_cs, state_cs)) {
        return 0;
    }

    td::Ref<vm::CellSlice> state_init_cs;
    if (!block::gen::t_AccountState.unpack_account_active(state_cs.write(), state_init_cs)) {
        return 0;
    }

    block::gen::StateInit::Record si_rec;
    if (!block::gen::t_StateInit.unpack(state_init_cs.write(), si_rec)) return 0;

    if (si_rec.data.is_null() || !si_rec.data->have(1) ||
        si_rec.data->prefetch_ulong(1) != 1) {
        return 0;
    }
    auto data_slice = si_rec.data;
    data_slice.write().advance(1);
    td::Ref<vm::Cell> cp_new_data_cell;
    if (!data_slice->prefetch_ref_to(cp_new_data_cell)) return 0;

    td::Ref<vm::Cell> state_root;
    evmc::bytes32 eth_state_root{};
    td::Ref<vm::Cell> rpc_cache_root;  // F.4 will hydrate from this
    if (!decode_cp_new_data(cp_new_data_cell, state_root, eth_state_root, rpc_cache_root)) {
        LOG(WARNING) << "evm-workchain: executor StateInit.data does not decode as cp.new_data";
        return 0;
    }
    if (state_root.is_null()) {
        LOG(WARNING) << "evm-workchain: executor cp.new_data has no inner state_root ref";
        return 0;
    }

    {
        std::unique_lock lock(target.mutex());
        auto* cs = dynamic_cast<CellEvmState*>(&target.state());
        if (!cs) {
            LOG(ERROR) << "evm-workchain: hydration target is not a CellEvmState";
            return 0;
        }
        if (!cs->load_from_cell(state_root)) {
            LOG(ERROR) << "evm-workchain: CellEvmState::load_from_cell failed during hydration";
            return 0;
        }
    }
    LOG(WARNING) << "evm-workchain: hydrated world state from executor cell (eth_state_root="
                 << td::Bits256{eth_state_root.bytes}.to_hex() << ")";
    return 1;
}

td::Ref<vm::Cell> build_evm_zerostate_accounts_cell() {
    // Single-executor zerostate: the wc=1 ShardAccounts dict contains exactly
    // one entry, the executor account. Its StateInit.data is a cp.new_data-
    // shaped cell (magic + Maybe ^state_root + bits256 eth_state_root)
    // holding a pre-populated CellEvmState with the 10 test EOAs.
    //
    // Layout matches what evm-compute-phase.cpp:118-141 produces every block
    // so hydration reads exactly the same format whether the chain is at
    // genesis or at block N.

    CellEvmState cell_state;
    intx::uint256 amount{kSeedAmountTos};
    for (int i = 0; i < 18; ++i) amount *= intx::uint256{10};
    for (const auto& a : kTestAccounts) {
        evmc::address addr{};
        if (!parse_hex_address(a.address, addr)) continue;
        silkworm::Account acct{};
        acct.balance = amount;
        cell_state.update_account(addr, std::nullopt, acct);
    }
    auto state_root = cell_state.serialize_to_cell();

    // Build cp.new_data v2-shaped cell:
    //   magic + has_root:1 + ^state_root + bits256:eth_root + has_cache:1
    // eth_state_root at genesis is zero (recomputed on first tx).
    // rpc_cache_root at genesis is nothing (no cache yet).
    vm::CellBuilder data_cb;
    data_cb.store_long(static_cast<long long>(kEvmAccountMagic), kEvmMagicBits);
    if (state_root.not_null()) {
        data_cb.store_long(1, 1);
        data_cb.store_ref(state_root);
    } else {
        data_cb.store_long(0, 1);
    }
    data_cb.store_zeroes(256);  // eth_state_root = 0 at genesis
    data_cb.store_long(0, 1);   // rpc_cache_root = nothing (Phase F.2)
    auto cp_new_data_cell = data_cb.finalize();

    // Wrap as executor ShardAccount and insert as sole entry.
    td::Bits256 exec_addr_bits;
    exec_addr_bits.bits().copy_from(td::ConstBitPtr{kEvmExecutorAddressBytes}, 256);
    auto account_cell = build_evm_shard_account_cell(exec_addr_bits, cp_new_data_cell);

    vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccounts);
    vm::CellBuilder vcb;
    vcb.store_ref_bool(account_cell);
    vcb.store_zeroes_bool(256 + 64);  // last_trans_hash + last_trans_lt
    accounts.set_builder(exec_addr_bits.bits(), 256, vcb);

    vm::CellBuilder cb;
    accounts.append_dict_to_bool(cb);
    return cb.finalize();
}

size_t hydrate_global_state_if_empty(vm::AugmentedDictionary& shard_accounts) {
    if (!g_evm_state) return 0;
    // One-shot per process. After init_evm_workchain calls
    // seed_test_accounts the state isn't strictly empty, but it's still in
    // the "fresh process" state that needs canonical-state hydration.
    if (!g_evm_state->needs_initial_hydration()) return 0;
    if (shard_accounts.is_empty()) return 0;
    auto count = populate_state_from_shard_accounts(*g_evm_state, shard_accounts);
    g_evm_state->mark_initial_hydration_done();
    return count;
}

void init_evm_workchain(const std::string& /*db_root*/) {
    // db_root used to point at the legacy evm-state.boc sidecar location.
    // After Phase B that file is no longer read or written; canonical state
    // is rehydrated from the wc=1 ShardAccounts at first block load. The
    // parameter remains for backward source compatibility with the existing
    // callers in validator-engine and tests.
    LOG(WARNING) << "evm-workchain: initialising (workchain_id=1, chain_id="
                 << kEvmChainId << ")";

    // Cell-native state. The dictionary starts empty here; the canonical
    // wc=1 ShardAccounts (loaded by the collator/validate-query from CellDb)
    // is what populates this state via populate_state_from_shard_accounts()
    // on the first wc=1 block load. The previous evm-state.boc sidecar load
    // path was removed in Phase B — there is no second store anymore.
    auto cell_state = std::make_unique<CellEvmState>();
    g_evm_state = std::make_unique<EvmState>(std::move(cell_state));

    // Seed Hardhat/Anvil standard test accounts (idempotent: skips if already seeded).
    // Production deployments should remove or guard this call. See the
    // PRE-FUNDED TEST ACCOUNTS block above for the full list and rationale.
    seed_test_accounts(*g_evm_state);

    evm_workchain_dispatch::set_evm_compute_handler(
        [](block::ComputePhase& cp,
           vm::CellSlice& in_msg_body,
           uint64_t gas_limit,
           uint64_t block_seqno,
           uint64_t timestamp,
           const uint8_t rand_seed[32]) -> bool {
            return run_evm_compute_phase(
                cp, in_msg_body, gas_limit,
                *g_evm_state,
                block_seqno, timestamp, rand_seed);
        });

    g_trie_calc = std::make_unique<IncrementalTrieCalculator>();

    LOG(WARNING) << "evm-workchain: handler registered";
}

}  // namespace evm_workchain
