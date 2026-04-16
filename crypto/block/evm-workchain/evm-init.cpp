/*
    EVM Workchain — module initialisation implementation.

    Registers the EVM compute phase handler with the host-chain dispatch
    mechanism defined in evm-workchain-dispatch.h.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-init.h"
#include "evm-workchain.h"

#include "block/evm-workchain-dispatch.h"
#include "evm-compute-phase.h"
#include "evm-state.h"
#include "evm-cell-state.h"
#include "evm-incremental-trie.h"

#include "vm/boc.h"

#include <cstdio>
#include <fstream>

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

void init_evm_workchain(const std::string& db_root) {
    LOG(WARNING) << "evm-workchain: initialising (workchain_id=1, chain_id="
                 << kEvmChainId << ")";

    // Cell-native state. The dictionary lives entirely in cells; the root
    // can be serialized to / loaded from a BoC file at {db_root}/evm-state.boc
    // for development persistence. Production persistence will route through
    // the collator's ShardAccounts → CellDb (single atomic WriteBatch).
    auto cell_state = std::make_unique<CellEvmState>();

    if (!db_root.empty()) {
        std::string boc_path = db_root + "/evm-state.boc";
        std::ifstream in(boc_path, std::ios::binary);
        if (in.good()) {
            std::string data((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
            auto cell_r = vm::std_boc_deserialize(td::Slice{data});
            if (cell_r.is_ok()) {
                cell_state->load_from_cell(cell_r.move_as_ok());
                LOG(WARNING) << "evm-workchain: loaded cell-native state from " << boc_path;
            } else {
                LOG(WARNING) << "evm-workchain: failed to deserialize "
                             << boc_path << ", starting empty";
            }
        } else {
            LOG(WARNING) << "evm-workchain: no existing state at " << boc_path
                         << ", starting empty";
        }
    } else {
        LOG(WARNING) << "evm-workchain: in-memory state only (no db_root)";
    }

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
