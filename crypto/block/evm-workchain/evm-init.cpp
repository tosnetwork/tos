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

void copy_test_accounts_into_dict(vm::Dictionary& target) {
    // 10,000 TOS = 10000 × 10^18 wei (matches seed_test_accounts).
    intx::uint256 amount{kSeedAmountTos};
    for (int i = 0; i < 18; ++i) amount *= intx::uint256{10};

    for (const auto& a : kTestAccounts) {
        evmc::address addr{};
        if (!parse_hex_address(a.address, addr)) continue;

        silkworm::Account acct{};
        acct.nonce = 0;
        acct.balance = amount;
        // code_hash defaults to silkworm::kEmptyHash (no code) — fine for EOAs

        auto data_cell = encode_evm_account_data(acct, /*storage_root=*/{});

        unsigned char key[32];
        address_to_key(addr, key);

        vm::CellBuilder val_cb;
        val_cb.store_ref(data_cell);
        target.set_builder(td::ConstBitPtr{key}, 256, val_cb);
    }
}

size_t populate_state_from_shard_accounts(
    EvmState& target,
    vm::AugmentedDictionary& shard_accounts) {
    size_t count = 0;
    // check_for_each_extra walks the augmented dict; we only need the leaf
    // value (the ShardAccount cell slice), not the augmentation extra.
    shard_accounts.check_for_each_extra(
        [&target, &count](td::Ref<vm::CellSlice> cs_ref,
                          td::Ref<vm::CellSlice> /*extra*/,
                          td::ConstBitPtr key, int n) -> bool {
            if (n != 256) return true;  // skip malformed entries

            // ShardAccount value layout: ^Account + last_trans_hash:bits256 + last_trans_lt:uint64
            td::Ref<vm::Cell> account_cell;
            if (!block::tlb::t_ShardAccount.extract_account_state(cs_ref, account_cell) ||
                account_cell.is_null()) {
                return true;
            }

            // Account → AccountStorage → AccountState (active) → StateInit
            block::gen::Account::Record_account acc_rec;
            if (!tlb::unpack_cell(account_cell, acc_rec)) return true;

            unsigned long long last_trans_lt;
            td::Ref<vm::CellSlice> balance_cs, state_cs;
            if (!block::gen::t_AccountStorage.unpack_account_storage(
                    acc_rec.storage.write(), last_trans_lt, balance_cs, state_cs)) {
                return true;
            }

            td::Ref<vm::CellSlice> state_init_cs;
            if (!block::gen::t_AccountState.unpack_account_active(state_cs.write(), state_init_cs)) {
                return true;  // not an active EVM account; skip
            }

            block::gen::StateInit::Record si_rec;
            if (!block::gen::t_StateInit.unpack(state_init_cs.write(), si_rec)) return true;

            // data:Maybe ^Cell — must be present and reference an EvmAccountData cell.
            if (si_rec.data.is_null() || !si_rec.data->have(1) ||
                si_rec.data->prefetch_ulong(1) != 1) {
                return true;
            }
            auto data_slice = si_rec.data;
            data_slice.write().advance(1);  // skip Maybe tag
            td::Ref<vm::Cell> evm_data_cell;
            if (!data_slice->prefetch_ref_to(evm_data_cell)) return true;

            silkworm::Account decoded;
            td::Ref<vm::Cell> storage_root;
            if (!decode_evm_account_data(evm_data_cell, decoded, storage_root)) {
                return true;  // not an EvmAccountData cell (wrong magic) — skip
            }

            // Reconstruct the EVM address from the 256-bit dict key
            // (lower 20 bytes are the EVM address; upper 12 are zero pad).
            evmc::address addr{};
            td::Bits256 key_bits;
            key_bits.bits().copy_from(key, 256);
            std::memcpy(addr.bytes, key_bits.data() + 12, 20);

            // Push to target via update_account (storage_root handled separately
            // because silkworm::State::update_account doesn't carry it).
            {
                std::unique_lock lock(target.mutex());
                target.state().update_account(addr, std::nullopt, decoded);
                if (storage_root.not_null()) {
                    if (auto* cs = dynamic_cast<CellEvmState*>(&target.state())) {
                        cs->set_storage_root_for_hydration(addr, storage_root);
                    }
                }
            }
            ++count;
            return true;
        });
    return count;
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
           const uint8_t rand_seed[32],
           vm::Dictionary* shard_accounts) -> bool {
            return run_evm_compute_phase(
                cp, in_msg_body, gas_limit,
                *g_evm_state,
                block_seqno, timestamp, rand_seed,
                shard_accounts);
        });

    g_trie_calc = std::make_unique<IncrementalTrieCalculator>();

    LOG(WARNING) << "evm-workchain: handler registered";
}

}  // namespace evm_workchain
