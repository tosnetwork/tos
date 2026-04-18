/*
    EVM Workchain — module initialisation implementation.

    Registers the EVM compute phase handler with the host-chain dispatch
    mechanism defined in evm-workchain-dispatch.h.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/init.h"
#include "evm/core/workchain.h"

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/evm-workchain-dispatch.h"
#include "evm/core/cell-codec.h"
#include "evm/rpc/cache-codec.h"
#include "evm/rpc/cache-db.h"
#include "evm/core/compute-phase.h"
#include "evm/core/state.h"
#include "evm/core/cell-state.h"
#include "evm/core/incremental-trie.h"

#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

#include <silkworm/core/types/account.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/execution/precompile.hpp>
#include <silkworm/core/protocol/param.hpp>

#include <ethash/keccak.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "td/utils/logging.h"

namespace evm_workchain {

// Runtime-overridable chain id. Stored as a plain `uint64_t` (not atomic)
// because writes happen exactly once during process init, before any RPC
// thread spins up. Reads are unsynchronised but safe in that ordering —
// see the contract on `set_evm_chain_id` in `evm-workchain.h`.
static uint64_t g_evm_chain_id = kEvmChainId;

uint64_t current_evm_chain_id() noexcept {
    return g_evm_chain_id;
}

void set_evm_chain_id(uint64_t chain_id) noexcept {
    g_evm_chain_id = chain_id;
}

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

// =============================================================================
// CANCUN PRE-FORK PREP (Category E, doc/evm-workchain-known-divergences.md)
//
// These helpers prepare the production runtime for a future flip of
// `cancun_time = 0` in evm-block-context.cpp::evm_chain_config(). They are
// **safe to call at every Shanghai-era node startup** — none of them changes
// consensus or state semantics until Cancun is actually activated. Once
// Cancun activates, silkworm's MergeRuleSet::initialize() invokes the
// EIP-4788 system call per block; the predeploy must be in state by then.
//
// Added in clearly-marked section to coordinate with parallel work on
// genesis-alloc helpers (Agent K) — DO NOT collapse into init_evm_workchain
// flow; new helpers are appended here, then dispatched from the bottom of
// init_evm_workchain.
// =============================================================================

namespace {

// EIP-4788 deployed runtime bytecode at kBeaconRootsAddress.
// Source: https://eips.ethereum.org/EIPS/eip-4788 §"Deployment".
// This is the *runtime* bytecode (not the deployer init code) — exactly
// what every Cancun-spec mainnet client has at 0x000F…Beac02. Length: 97
// bytes (194 hex chars). The on-chain deployment transaction's `input`
// field is `0x60618060095f395ff3` + this runtime; the 9-byte init prefix
// CODECOPYs the rest into memory and RETURNs it. Logic: when called with
// sender == kSystemAddress it stores the calldata to ring-buffer slot
// (timestamp % HISTORY_BUFFER_LENGTH); otherwise it serves a parent-
// beacon-root lookup keyed by the calldata timestamp.
// HISTORY_BUFFER_LENGTH = 8191 = 0x1FFF.
constexpr const char* kEip4788Bytecode =
    "3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b"
    "5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b"
    "5f5ffd5b62001fff42064281555f359062001fff015500";

// EIP-2935 deployed runtime bytecode at kHistoryStorageAddress
// (0x0000F90827F1C53A10CB7A02335B175320002935). Source: https://eips.ethereum.org/EIPS/eip-2935
// §"Specification". Length: 84 bytes (168 hex chars). Logic: when called
// with sender == kSystemAddress it stores parent_hash to ring-buffer slot
// (block_number - 1) % 8191; otherwise serves a parent-block-hash lookup
// keyed by the calldata block number.
constexpr const char* kEip2935Bytecode =
    "3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111"
    "604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303068155"
    "00";

bool hex_decode(const char* hex, silkworm::Bytes& out) {
    size_t len = std::strlen(hex);
    if (len % 2 != 0) return false;
    out.clear();
    out.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        unsigned x;
        if (std::sscanf(hex + i, "%2x", &x) != 1) return false;
        out.push_back(static_cast<uint8_t>(x));
    }
    return true;
}

}  // anonymous namespace

void seed_eip4788_predeploy(EvmState& state) {
    // The beacon-roots system contract lives at the magic address
    // kBeaconRootsAddress = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02.
    // EIP-4788 deploys it with: nonce = 1, balance = 0, code = the
    // 200-byte runtime above, storage = empty.
    //
    // Idempotent: if the contract is already deployed (correct code_hash),
    // skip — this lets us call seed_eip4788_predeploy() unconditionally on
    // every node startup without re-writing state.
    const evmc::address addr = silkworm::protocol::kBeaconRootsAddress;

    silkworm::Bytes code;
    if (!hex_decode(kEip4788Bytecode, code)) {
        LOG(ERROR) << "evm-workchain: EIP-4788 bytecode literal failed to hex-decode (programmer error)";
        return;
    }

    auto code_hash_kk = ethash::keccak256(code.data(), code.size());
    evmc::bytes32 code_hash{};
    std::memcpy(code_hash.bytes, code_hash_kk.bytes, 32);

    if (auto existing = state.read_account(addr); existing.has_value()) {
        if (existing->code_hash == code_hash) {
            LOG(INFO) << "evm-workchain: EIP-4788 beacon-roots predeploy already present (code_hash match), skipping";
            return;
        }
        LOG(WARNING) << "evm-workchain: EIP-4788 predeploy address has unexpected code_hash; overwriting";
    }

    {
        std::unique_lock lock(state.mutex());
        // Account record (nonce=1, balance=0, code_hash set per EIP).
        silkworm::Account acct;
        acct.nonce = 1;
        acct.balance = 0;
        acct.code_hash = code_hash;
        // Two-step: update_account first (registers the account at code_hash),
        // then update_account_code (stores the actual bytecode and refreshes
        // the embedded EvmAccountData cell so the bytecode survives restart).
        state.state().update_account(addr, std::nullopt, acct);
        state.state().update_account_code(addr, /*incarnation=*/0,
                                          code_hash,
                                          silkworm::ByteView{code.data(), code.size()});
    }

    LOG(WARNING) << "evm-workchain: seeded EIP-4788 beacon-roots predeploy at "
                    "0x000f3df6d732807ef1319fb7b8bb8522d0beac02 (code=97 bytes, nonce=1)";
}

void seed_eip2935_predeploy(EvmState& state) {
    // The history-storage system contract lives at the magic address
    // kHistoryStorageAddress = 0x0000F90827F1C53A10CB7A02335B175320002935.
    // EIP-2935 deploys it with: nonce = 1, balance = 0, code = the
    // 84-byte runtime above, storage = empty.
    //
    // Idempotent (same pattern as seed_eip4788_predeploy).
    const evmc::address addr = silkworm::protocol::kHistoryStorageAddress;

    silkworm::Bytes code;
    if (!hex_decode(kEip2935Bytecode, code)) {
        LOG(ERROR) << "evm-workchain: EIP-2935 bytecode literal failed to hex-decode (programmer error)";
        return;
    }

    auto code_hash_kk = ethash::keccak256(code.data(), code.size());
    evmc::bytes32 code_hash{};
    std::memcpy(code_hash.bytes, code_hash_kk.bytes, 32);

    if (auto existing = state.read_account(addr); existing.has_value()) {
        if (existing->code_hash == code_hash) {
            LOG(INFO) << "evm-workchain: EIP-2935 history-storage predeploy already present (code_hash match), skipping";
            return;
        }
        LOG(WARNING) << "evm-workchain: EIP-2935 predeploy address has unexpected code_hash; overwriting";
    }

    {
        std::unique_lock lock(state.mutex());
        silkworm::Account acct;
        acct.nonce = 1;
        acct.balance = 0;
        acct.code_hash = code_hash;
        state.state().update_account(addr, std::nullopt, acct);
        state.state().update_account_code(addr, /*incarnation=*/0,
                                          code_hash,
                                          silkworm::ByteView{code.data(), code.size()});
    }

    LOG(WARNING) << "evm-workchain: seeded EIP-2935 history-storage predeploy at "
                    "0x0000f90827f1c53a10cb7a02335b175320002935 (code=" << code.size()
                 << " bytes, nonce=1)";
}

void verify_kzg_setup_loaded() {
    // Sanity check: silkworm + evmone bundle the trusted-setup G2_1 point
    // as a constexpr in third-party/evmone/evmone/lib/evmone_precompiles/kzg.cpp.
    // No external trusted_setup file is required and there is no separate
    // loader entry-point — point_evaluation_run() is callable as soon as the
    // process is up.
    //
    // To prove that the precompile is wired into our build (and to surface
    // any future regression early), we run point_evaluation_run on the
    // canonical EIP-4844 spec test vector and assert the success bytes
    // (FIELD_ELEMENTS_PER_BLOB || BLS_MODULUS, 64 bytes total).
    static const uint8_t kInputHex[192] = {
        // versioned_hash (32) — sha256(commitment) with first byte = 0x01
        0x01,0x4e,0xdf,0xed,0x85,0x47,0x66,0x1f,0x6c,0xb4,0x16,0xeb,0xa5,0x30,0x61,0xa2,
        0xf6,0xdc,0xe8,0x72,0xc0,0x49,0x7e,0x6d,0xd4,0x85,0xa8,0x76,0xfe,0x25,0x67,0xf1,
        // z (32) — evaluation point
        0x56,0x4c,0x0a,0x11,0xa0,0xf7,0x04,0xf4,0xfc,0x3e,0x8a,0xcf,0xe0,0xf8,0x24,0x5f,
        0x0a,0xd1,0x34,0x7b,0x37,0x8f,0xbf,0x96,0xe2,0x06,0xda,0x11,0xa5,0xd3,0x63,0x06,
        // y (32) — claimed value at z
        0x6d,0x92,0x8e,0x13,0xfe,0x44,0x3e,0x95,0x7d,0x82,0xe3,0xe7,0x1d,0x48,0xcb,0x65,
        0xd5,0x10,0x28,0xeb,0x44,0x83,0xe7,0x19,0xbf,0x8e,0xfc,0xdf,0x12,0xf7,0xc3,0x21,
        // commitment (48)
        0xa4,0x21,0xe2,0x29,0x56,0x59,0x52,0xcf,0xff,0x4e,0xf3,0x51,0x71,0x00,0xa9,0x7d,
        0xa1,0xd4,0xfe,0x57,0x95,0x6f,0xa5,0x0a,0x44,0x2f,0x92,0xaf,0x03,0xb1,0xbf,0x37,
        0xad,0xac,0xc8,0xad,0x4e,0xd2,0x09,0xb3,0x12,0x87,0xea,0x5b,0xb9,0x4d,0x9d,0x06,
        // proof (48)
        0xa4,0x44,0xd6,0xbb,0x5a,0xad,0xc3,0xce,0xb6,0x15,0xb5,0x0d,0x66,0x06,0xbd,0x54,
        0xbf,0xe5,0x29,0xf5,0x92,0x47,0x98,0x7c,0xd1,0xab,0x84,0x8d,0x19,0xde,0x59,0x9a,
        0x90,0x52,0xf1,0x83,0x5f,0xb0,0xd0,0xd4,0x4c,0xf7,0x01,0x83,0xe1,0x9a,0x68,0xc9,
    };
    auto out = silkworm::precompile::point_evaluation_run(
        silkworm::ByteView{kInputHex, sizeof(kInputHex)});
    if (!out || out->size() != 64) {
        LOG(ERROR) << "evm-workchain: KZG point-evaluation precompile (0x0a) self-test FAILED — "
                      "spec vector did not return 64-byte success blob. "
                      "Cancun activation must NOT proceed.";
        return;
    }
    LOG(WARNING) << "evm-workchain: KZG point-evaluation precompile (0x0a) is ready "
                    "(spec vector verified, no external trusted_setup file needed; "
                    "evmone bundles the G2_1 point as a constexpr)";
}


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

td::Ref<vm::Cell> build_evm_zerostate_accounts_cell(
    const std::vector<GenesisAccount>& accounts) {
    // Phase D — parameterised version. Same single-executor wrapper as the
    // zero-arg overload (the wc=1 ShardAccounts dict contains exactly one
    // entry, the executor, whose StateInit.data is a cp.new_data v2 cell
    // referencing a CellEvmState root); the only thing that varies is which
    // accounts are pre-populated inside that state.
    //
    // Layout matches what evm-compute-phase.cpp produces every block so
    // hydration reads exactly the same format whether the chain is at
    // genesis or at block N.

    CellEvmState cell_state;

    // Walk caller-supplied allocs in input order. Each entry produces a
    // sequence of silkworm::State writes that mirror what would happen if
    // the genesis tx synthetically funded / created the account.
    for (const auto& a : accounts) {
        // 1. Account header (balance + nonce). update_account() preserves
        //    storage_root/code_root if the account already exists, so this
        //    is safe to call before update_account_code/update_storage.
        silkworm::Account acct{};
        acct.balance = a.balance;
        acct.nonce = a.nonce;
        cell_state.update_account(a.addr, std::nullopt, acct);

        // 2. Code (only if non-empty — empty bytes ⇒ EOA, code_hash stays
        //    silkworm::kEmptyHash). update_account_code computes the code
        //    hash internally and embeds the bytecode chain via
        //    encode_evm_bytecode().
        if (!a.code.empty()) {
            auto code_hash_be = ethash::keccak256(a.code.data(), a.code.size());
            evmc::bytes32 code_hash{};
            std::memcpy(code_hash.bytes, code_hash_be.bytes, 32);
            cell_state.update_account_code(
                a.addr, /*incarnation=*/0, code_hash,
                silkworm::ByteView{a.code.data(), a.code.size()});
        }

        // 3. Storage slots. Iterate in the caller's std::map order (key-
        //    sorted) so the output is deterministic across runs; values of
        //    zero are no-ops by the silkworm contract.
        static const evmc::bytes32 zero{};
        for (const auto& [slot, value] : a.storage) {
            if (value == zero) continue;
            cell_state.update_storage(a.addr, /*incarnation=*/0, slot, zero, value);
        }
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

    vm::AugmentedDictionary accounts_dict(256, block::tlb::aug_ShardAccounts);
    vm::CellBuilder vcb;
    vcb.store_ref_bool(account_cell);
    vcb.store_zeroes_bool(256 + 64);  // last_trans_hash + last_trans_lt
    accounts_dict.set_builder(exec_addr_bits.bits(), 256, vcb);

    vm::CellBuilder cb;
    accounts_dict.append_dict_to_bool(cb);
    return cb.finalize();
}

td::Ref<vm::Cell> build_evm_zerostate_accounts_cell() {
    // Backwards-compatible zero-arg overload: seeds the 10 Hardhat/Anvil
    // standard test EOAs with kSeedAmountTos TOS each. Internally translates
    // to a GenesisAccount vector and forwards to the parameterised overload.
    intx::uint256 amount{kSeedAmountTos};
    for (int i = 0; i < 18; ++i) amount *= intx::uint256{10};

    std::vector<GenesisAccount> accounts;
    accounts.reserve(std::size(kTestAccounts));
    for (const auto& a : kTestAccounts) {
        GenesisAccount g{};
        if (!parse_hex_address(a.address, g.addr)) continue;
        g.balance = amount;
        g.nonce = 0;
        accounts.push_back(std::move(g));
    }
    return build_evm_zerostate_accounts_cell(accounts);
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

void init_evm_workchain(const std::string& db_root) {
    // db_root historically pointed at the legacy evm-state.boc sidecar
    // location (removed in Phase B — canonical state lives in wc=1
    // ShardAccounts now). It now serves Phase F.3/F.4: open the
    // side-channel RPC cache DB at db_root + "/evm-rpc-cache" so
    // receipts survive restart without touching consensus.

    // Read TOS_EVM_CHAIN_ID once at startup. Used by the Hive harness to
    // boot a validator with a spec-mandated chain id (e.g. the
    // execution-apis fixtures bake `0xc72dd9d5e883e`). Falls back to the
    // historical default (`kEvmChainId` == 0x544F53). MUST NOT change on
    // an existing chain — EIP-155 v-recovery and stored receipts assume a
    // stable chain id (see contract on `set_evm_chain_id`).
    if (const char* env = std::getenv("TOS_EVM_CHAIN_ID"); env && *env) {
        char* endp = nullptr;
        // Accept both decimal ("5525331") and hex ("0x544f53") forms.
        unsigned long long parsed = std::strtoull(env, &endp, 0);
        if (endp == env || *endp != '\0' || parsed == 0) {
            LOG(ERROR) << "evm-workchain: ignoring TOS_EVM_CHAIN_ID='" << env
                       << "' (failed to parse as positive integer)";
        } else {
            set_evm_chain_id(static_cast<uint64_t>(parsed));
            LOG(WARNING) << "evm-workchain: TOS_EVM_CHAIN_ID override → 0x"
                         << std::hex << current_evm_chain_id() << std::dec
                         << " (default would have been 0x" << std::hex
                         << kEvmChainId << std::dec << ")";
        }
    }

    LOG(WARNING) << "evm-workchain: initialising (workchain_id=1, chain_id="
                 << current_evm_chain_id() << ")";

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

    // Cancun pre-fork prep (Category E in known-divergences). Both calls are
    // safe at the current Shanghai-revision config — they only matter once
    // cancun_time = 0 is flipped:
    //   * KZG self-test logs readiness of precompile 0x0a (no init action,
    //     just a sanity check that the bundled G2_1 setup is linked).
    //   * Beacon-roots predeploy is idempotent — once it's in CellEvmState
    //     it round-trips through cp.new_data → restart with the right
    //     code_hash, and we skip on subsequent calls.
    verify_kzg_setup_loaded();
    seed_eip4788_predeploy(*g_evm_state);
    seed_eip2935_predeploy(*g_evm_state);  // EIP-2935 (Pectra)

    // Phase F.3/F.4: open the per-validator side-channel RPC cache DB.
    // Skipped on the test harness path (no db_root provided).
    if (!db_root.empty()) {
        auto cache_path = db_root + "/evm-rpc-cache";
        auto db_r = EvmRpcCacheDb::open(cache_path);
        if (db_r.is_error()) {
            LOG(ERROR) << "evm-workchain: failed to open rpc cache db at "
                       << cache_path << ": " << db_r.error().message();
        } else {
            set_evm_rpc_cache_db(db_r.move_as_ok());
            // Hydrate g_evm_state.receipts_ from the cache so RPC
            // queries for pre-restart txs return data immediately.
            size_t hydrated = 0;
            size_t decode_fails = 0;
            auto walk_status = evm_rpc_cache_db()->for_each_receipt(
                [&hydrated, &decode_fails](const td::Bits256& tx_hash,
                            td::Ref<vm::Cell> cell) -> td::Status {
                    StoredReceipt r;
                    if (!decode_persisted_receipt(cell, r)) {
                        ++decode_fails;
                        return td::Status::OK();
                    }
                    evmc::bytes32 tx_hash_be{};
                    std::memcpy(tx_hash_be.bytes, tx_hash.data(), 32);
                    g_evm_state->store_receipt(tx_hash_be, std::move(r));
                    ++hydrated;
                    return td::Status::OK();
                });
            if (walk_status.is_error()) {
                LOG(ERROR) << "evm-workchain: rpc cache walk failed: "
                           << walk_status.message();
            } else {
                LOG(WARNING) << "evm-workchain: hydrated " << hydrated
                             << " receipts from rpc cache db"
                             << (decode_fails > 0 ? " (skipped " + std::to_string(decode_fails) + " corrupt entries)" : "");
            }

            // Phase F.6: hydrate transactions, blocks (both indexes) and
            // per-block log vectors. Each walk is independent and uses the
            // same EvmState mutators that compute-phase calls; they are all
            // idempotent for replays.
            size_t txs_hydrated = 0, tx_decode_fails = 0;
            auto tx_walk = evm_rpc_cache_db()->for_each_transaction(
                [&txs_hydrated, &tx_decode_fails](const td::Bits256& tx_hash,
                            td::Ref<vm::Cell> cell) -> td::Status {
                    StoredTransaction t;
                    if (!decode_persisted_transaction(cell, t)) {
                        ++tx_decode_fails;
                        return td::Status::OK();
                    }
                    evmc::bytes32 tx_hash_be{};
                    std::memcpy(tx_hash_be.bytes, tx_hash.data(), 32);
                    g_evm_state->store_transaction(tx_hash_be, std::move(t));
                    ++txs_hydrated;
                    return td::Status::OK();
                });
            if (tx_walk.is_error()) {
                LOG(ERROR) << "evm-workchain: rpc cache tx walk failed: "
                           << tx_walk.message();
            } else {
                LOG(WARNING) << "evm-workchain: hydrated " << txs_hydrated
                             << " transactions from rpc cache db"
                             << (tx_decode_fails > 0 ? " (skipped " + std::to_string(tx_decode_fails) + " corrupt entries)" : "");
            }

            size_t blocks_hydrated = 0, block_decode_fails = 0;
            // Walk by-number first so chain-order iteration populates
            // hash_to_block_ alongside blocks_; the by-hash walk is then a
            // safety-net (no-op if both indexes were written together).
            auto block_walk = evm_rpc_cache_db()->for_each_block_by_number(
                [&blocks_hydrated, &block_decode_fails](
                    uint64_t /*block_number*/, td::Ref<vm::Cell> cell) -> td::Status {
                    StoredBlock b;
                    if (!decode_persisted_block(cell, b)) {
                        ++block_decode_fails;
                        return td::Status::OK();
                    }
                    g_evm_state->store_block(b);
                    ++blocks_hydrated;
                    return td::Status::OK();
                });
            if (block_walk.is_error()) {
                LOG(ERROR) << "evm-workchain: rpc cache block walk failed: "
                           << block_walk.message();
            } else {
                LOG(WARNING) << "evm-workchain: hydrated " << blocks_hydrated
                             << " blocks from rpc cache db"
                             << (block_decode_fails > 0 ? " (skipped " + std::to_string(block_decode_fails) + " corrupt entries)" : "");
            }

            // Logs walk: each entry is the full IndexedLog vector for a
            // block. The state's store_logs() appends per-tx entries with a
            // log_index derived from the existing vector size, which would
            // mis-number if we replayed per-tx; instead we write directly into
            // the block_logs_ slot via repeated store_logs grouped by tx_hash.
            size_t log_blocks_hydrated = 0;
            size_t log_decode_fails = 0;
            auto logs_walk = evm_rpc_cache_db()->for_each_block_logs(
                [&log_blocks_hydrated, &log_decode_fails](
                    uint64_t block_number, td::Ref<vm::Cell> cell) -> td::Status {
                    std::vector<IndexedLog> logs;
                    if (!decode_persisted_logs_for_block(cell, logs)) {
                        ++log_decode_fails;
                        return td::Status::OK();
                    }
                    // Re-group by tx_hash preserving order so store_logs
                    // recreates the original log_index sequence. Each
                    // store_logs call appends `logs.size()` entries with
                    // log_index continuing from the current vector size.
                    std::vector<silkworm::Log> bucket;
                    evmc::bytes32 cur_tx{};
                    uint32_t cur_tx_index = 0;
                    bool first = true;
                    auto flush = [&]() {
                        if (bucket.empty()) return;
                        g_evm_state->store_logs(block_number, cur_tx, bucket, cur_tx_index);
                        bucket.clear();
                    };
                    for (const auto& il : logs) {
                        if (first || il.tx_hash != cur_tx) {
                            flush();
                            cur_tx = il.tx_hash;
                            cur_tx_index = il.tx_index;
                            first = false;
                        }
                        bucket.push_back(il.log);
                    }
                    flush();
                    ++log_blocks_hydrated;
                    return td::Status::OK();
                });
            if (logs_walk.is_error()) {
                LOG(ERROR) << "evm-workchain: rpc cache logs walk failed: "
                           << logs_walk.message();
            } else {
                LOG(WARNING) << "evm-workchain: hydrated logs for "
                             << log_blocks_hydrated << " blocks from rpc cache db"
                             << (log_decode_fails > 0 ? " (skipped " + std::to_string(log_decode_fails) + " corrupt entries)" : "");
            }
        }
    }

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
