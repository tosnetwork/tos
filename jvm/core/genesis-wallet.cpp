/*
    JVM Workchain — wc=3 genesis wallet seeder implementation.
*/
#include "jvm/core/genesis-wallet.h"

#include <cstring>
#include <ethash/keccak.hpp>
#include <string>

#include "block/block.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "jvm/core/class-manifest.h"
#include "jvm/core/dispatch-engine.h"
#include "jvm/core/message-abi.h"
#include "jvm/core/storage-cell-host.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

namespace jvm_workchain {

namespace {

constexpr std::uint8_t kJvmAccountWorkchainId = 3;

// Keccak256 helper — identical primitive the rt.jar Wallet uses inside
// `slot(String)`, so genesis and runtime hash the same bytes.
std::array<std::uint8_t, 32> keccak256_array(td::Slice input) {
    auto digest = ethash::keccak256(
        reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), digest.bytes, 32);
    return out;
}

JvmStorageSlot slot_for(const char* name) {
    return keccak256_array(td::Slice(name));
}

// First 4 bytes of keccak256(signature) — the canonical method_id used
// by JvmCallDescriptor entries.  Matches Solidity / ABI selector
// convention so off-chain tooling can derive the same ids.
std::uint32_t method_id_for(const char* abi_signature) {
    auto hash = keccak256_array(td::Slice(abi_signature));
    return (static_cast<std::uint32_t>(hash[0]) << 24)
         | (static_cast<std::uint32_t>(hash[1]) << 16)
         | (static_cast<std::uint32_t>(hash[2]) << 8)
         |  static_cast<std::uint32_t>(hash[3]);
}

// Build the three-slot storage_root for an Ed25519-authenticated
// single-owner contract.  Wallet and Deployer share the same storage
// shape (ownerPubKey / nonce / initFlag); only the slot-name prefix
// differs (`Wallet.*` vs `Deployer.*`).  Both prefixes are
// consensus-stable strings the on-chain runtime hashes the same way.
td::Result<td::Ref<vm::Cell>> build_owner_nonce_storage_root(
    const std::array<std::uint8_t, 32>& owner_pubkey,
    const char* owner_slot_name,
    const char* nonce_slot_name,
    const char* flag_slot_name) {
    JvmStorageCellHost storage;

    auto owner_slot = slot_for(owner_slot_name);
    JvmStorageValue owner_value(owner_pubkey.begin(), owner_pubkey.end());
    TRY_STATUS(storage.store(owner_slot, owner_value));

    auto nonce_slot = slot_for(nonce_slot_name);
    JvmStorageValue nonce_value(32, 0);  // Uint256.ZERO
    TRY_STATUS(storage.store(nonce_slot, nonce_value));

    auto flag_slot = slot_for(flag_slot_name);
    JvmStorageValue flag_value{static_cast<std::uint8_t>(0x01)};
    TRY_STATUS(storage.store(flag_slot, flag_value));

    return storage.root_cell();
}

td::Ref<vm::Cell> build_owner_init_args(
    const std::array<std::uint8_t, 32>& owner_pubkey) {
    JvmArgs args;
    JvmTypedArg arg;
    arg.type = JvmArgType::Bytes32;
    arg.bytes.assign(owner_pubkey.begin(), owner_pubkey.end());
    args.values.push_back(std::move(arg));
    return encode_jvm_args(args);
}

td::Ref<vm::Cell> build_account_cell(
    const JvmContractId& addr,
    td::Ref<vm::Cell> state_init_cell,
    const td::RefInt256& balance) {
    // AccountStorage = last_trans_lt:uint64
    //                   balance:CurrencyCollection
    //                   state:account_active$1 _:StateInit
    vm::CellBuilder as_cb;
    if (!as_cb.store_ulong_rchk_bool(0, 64)) {        // last_trans_lt = 0
        return {};
    }
    if (!block::CurrencyCollection{balance}.store(as_cb)) {
        return {};
    }
    // state = account_active$1 prefix + StateInit body inlined.
    if (!as_cb.store_long_bool(1, 1)) {               // account_active$1
        return {};
    }
    // StateInit body is the cellslice form of the StateInit cell
    // we already built; the dispatch engine consumes it the same
    // way `prepare_compute_phase` does.
    auto state_init_cs = vm::load_cell_slice(state_init_cell);
    if (!as_cb.append_cellslice_bool(std::move(state_init_cs))) {
        return {};
    }
    auto storage_cell = as_cb.finalize();
    if (storage_cell.is_null()) {
        return {};
    }

    // StorageInfo.used computed from the storage cell.
    vm::CellStorageStat stats;
    auto stat_status =
        stats.compute_used_storage(td::Ref<vm::Cell>(storage_cell));
    if (stat_status.is_error()) {
        return {};
    }

    // Account = account$1 addr:addr_std$10 storage_stat:StorageInfo
    //           storage:AccountStorage
    vm::CellBuilder acc_cb;
    if (!acc_cb.store_long_bool(1, 1)) {              // account$1
        return {};
    }
    if (!acc_cb.store_long_bool(2, 2)                 // addr_std$10
        || !acc_cb.store_long_bool(0, 1)              // anycast: Nothing
        || !acc_cb.store_long_rchk_bool(
                kJvmAccountWorkchainId, 8)            // workchain_id = 3
        || !acc_cb.store_bytes_bool(addr.data(), addr.size())) {
        return {};
    }
    if (!block::store_UInt7(acc_cb, stats.cells)
        || !block::store_UInt7(acc_cb, stats.bits)) {
        return {};
    }
    // storage_extra:StorageExtraInfo = regular$0 (1 bit) + reserved 2 bits.
    if (!acc_cb.store_zeroes_bool(3)) {
        return {};
    }
    // last_paid:uint32 = 0, due_payment:Maybe(Tomis) = Nothing.
    if (!acc_cb.store_long_bool(0, 33)) {
        return {};
    }
    if (!acc_cb.append_data_cell_bool(storage_cell)) {
        return {};
    }
    return acc_cb.finalize();
}

td::Ref<vm::Cell> build_shard_account_entry(td::Ref<vm::Cell> account_cell) {
    vm::CellBuilder cb;
    if (!cb.store_ref_bool(std::move(account_cell))
        || !cb.store_zeroes_bool(256 + 64)) {  // last_trans_hash + last_trans_lt
        return {};
    }
    return cb.finalize();
}

}  // namespace

td::Ref<vm::Cell> build_wallet_manifest_cell() {
    std::vector<JvmMethodManifestEntry> entries;

    JvmMethodManifestEntry init_entry;
    init_entry.method_id = method_id_for("init(bytes32)");
    init_entry.class_name = "java/lang/Wallet";
    init_entry.method_name = "init";
    init_entry.method_spec = "(Ljava/lang/Bytes32;)V";
    entries.push_back(std::move(init_entry));

    JvmMethodManifestEntry execute_entry;
    execute_entry.method_id = method_id_for("execute(uint256,bytes,bytes)");
    execute_entry.class_name = "java/lang/Wallet";
    execute_entry.method_name = "execute";
    execute_entry.method_spec =
        "(Ljava/lang/Uint256;Ljava/lang/Bytes;Ljava/lang/Bytes;)V";
    entries.push_back(std::move(execute_entry));

    JvmMethodManifestEntry get_nonce_entry;
    get_nonce_entry.method_id = method_id_for("getNonce()");
    get_nonce_entry.class_name = "java/lang/Wallet";
    get_nonce_entry.method_name = "getNonce";
    get_nonce_entry.method_spec = "()V";
    entries.push_back(std::move(get_nonce_entry));

    return encode_jvm_method_manifest(entries);
}

// Manifest for `java.lang.Deployer`.  ABI signatures mirror the four-
// byte selectors the off-chain JvmDeployerContract (tosctl Rust side)
// derives from the same strings; method specs are the JNI descriptors
// that match the @ContractEntry surface in `Deployer.java`.
td::Ref<vm::Cell> build_deployer_manifest_cell() {
    std::vector<JvmMethodManifestEntry> entries;

    JvmMethodManifestEntry init_entry;
    init_entry.method_id = method_id_for("init(bytes32)");
    init_entry.class_name = "java/lang/Deployer";
    init_entry.method_name = "init";
    init_entry.method_spec = "(Ljava/lang/Bytes32;)V";
    entries.push_back(std::move(init_entry));

    JvmMethodManifestEntry deploy_entry;
    deploy_entry.method_id = method_id_for(
        "deploy(uint256,bytes32,bytes,uint256,bytes,bytes)");
    deploy_entry.class_name = "java/lang/Deployer";
    deploy_entry.method_name = "deploy";
    deploy_entry.method_spec =
        "(Ljava/lang/Uint256;Ljava/lang/Bytes32;Ljava/lang/Bytes;"
        "Ljava/lang/Uint256;Ljava/lang/Bytes;Ljava/lang/Bytes;)V";
    entries.push_back(std::move(deploy_entry));

    JvmMethodManifestEntry get_nonce_entry;
    get_nonce_entry.method_id = method_id_for("getNonce()");
    get_nonce_entry.class_name = "java/lang/Deployer";
    get_nonce_entry.method_name = "getNonce";
    get_nonce_entry.method_spec = "()V";
    entries.push_back(std::move(get_nonce_entry));

    return encode_jvm_method_manifest(entries);
}

td::Result<JvmGenesisWalletBuild> build_jvm_genesis_wallet(
    const JvmGenesisWallet& wallet,
    const std::array<std::uint8_t, 32>& stdlib_hash,
    td::Slice wallet_class_bytes) {
    if (wallet_class_bytes.empty()) {
        return td::Status::Error(
            "JVM genesis wallet build: empty class bytes");
    }
    if (wallet.initial_balance.is_null()) {
        return td::Status::Error(
            "JVM genesis wallet build: null initial balance");
    }

    // Build all of the cryptographic commitments.
    JvmStorageValue class_bytes_vec(wallet_class_bytes.ubegin(),
                                     wallet_class_bytes.uend());
    auto class_hash = compute_jvm_class_hash(class_bytes_vec);

    auto init_args_cell = build_owner_init_args(wallet.owner_pubkey);
    if (init_args_cell.is_null()) {
        return td::Status::Error(
            "JVM genesis wallet build: init_args encode failed");
    }

    auto address_commit = compute_jvm_address_commit(
        kJvmGenesisDeployer, wallet.salt, init_args_cell);

    auto manifest_cell = build_wallet_manifest_cell();
    if (manifest_cell.is_null()) {
        return td::Status::Error(
            "JVM genesis wallet build: manifest encode failed");
    }
    auto manifest_hash = compute_jvm_manifest_root_hash(manifest_cell);

    auto address = derive_jvm_contract_address_from_state(
        kJvmGenesisDeployer, address_commit, class_hash, manifest_hash);

    // Encode the JVAC state cell with pre-populated storage_root that
    // mirrors `Wallet.init(ownerPubKey)` outputs.
    TRY_RESULT(storage_root, build_owner_nonce_storage_root(
                                 wallet.owner_pubkey,
                                 "Wallet.ownerPubKey",
                                 "Wallet.nonce",
                                 "Wallet.initFlag"));

    JvmContractAccountState state;
    state.schema_version = kJvmContractAccountStateSchemaVersion;
    state.stdlib_hash = stdlib_hash;
    state.class_hash = class_hash;
    state.deployer = kJvmGenesisDeployer;
    state.address_commit = address_commit;
    state.class_bytes = encode_jvm_storage_value(class_bytes_vec);
    state.storage_root = storage_root;
    state.manifest_root = manifest_cell;
    if (state.class_bytes.is_null()) {
        return td::Status::Error(
            "JVM genesis wallet build: class_bytes encode failed");
    }

    auto contract_state_cell = encode_jvm_contract_account_state(state);
    if (contract_state_cell.is_null()) {
        return td::Status::Error(
            "JVM genesis wallet build: JVAC encode failed");
    }

    auto state_init_cell = encode_jvm_state_init_cell(state);
    if (state_init_cell.is_null()) {
        return td::Status::Error(
            "JVM genesis wallet build: StateInit encode failed");
    }

    auto account_cell =
        build_account_cell(address, state_init_cell, wallet.initial_balance);
    if (account_cell.is_null()) {
        return td::Status::Error(
            "JVM genesis wallet build: account cell encode failed");
    }
    if (!block::gen::t_Account.validate_ref(account_cell)) {
        return td::Status::Error(
            "JVM genesis wallet build: account cell failed TLB validation");
    }

    auto shard_entry = build_shard_account_entry(account_cell);
    if (shard_entry.is_null()) {
        return td::Status::Error(
            "JVM genesis wallet build: ShardAccount entry encode failed");
    }

    JvmGenesisWalletBuild built;
    built.address = address;
    built.shard_account_cell = std::move(shard_entry);
    built.account_cell = std::move(account_cell);
    built.contract_account_state_cell = std::move(contract_state_cell);
    return built;
}

td::Result<JvmGenesisDeployerBuild> build_jvm_genesis_deployer(
    const JvmGenesisDeployer& deployer,
    const std::array<std::uint8_t, 32>& stdlib_hash,
    td::Slice deployer_class_bytes) {
    if (deployer_class_bytes.empty()) {
        return td::Status::Error(
            "JVM genesis deployer build: empty class bytes");
    }
    if (deployer.initial_balance.is_null()) {
        return td::Status::Error(
            "JVM genesis deployer build: null initial balance");
    }

    JvmStorageValue class_bytes_vec(deployer_class_bytes.ubegin(),
                                     deployer_class_bytes.uend());
    auto class_hash = compute_jvm_class_hash(class_bytes_vec);

    auto init_args_cell = build_owner_init_args(deployer.owner_pubkey);
    if (init_args_cell.is_null()) {
        return td::Status::Error(
            "JVM genesis deployer build: init_args encode failed");
    }

    auto address_commit = compute_jvm_address_commit(
        kJvmGenesisDeployer, deployer.salt, init_args_cell);

    auto manifest_cell = build_deployer_manifest_cell();
    if (manifest_cell.is_null()) {
        return td::Status::Error(
            "JVM genesis deployer build: manifest encode failed");
    }
    auto manifest_hash = compute_jvm_manifest_root_hash(manifest_cell);

    auto address = derive_jvm_contract_address_from_state(
        kJvmGenesisDeployer, address_commit, class_hash, manifest_hash);

    TRY_RESULT(storage_root, build_owner_nonce_storage_root(
                                 deployer.owner_pubkey,
                                 "Deployer.ownerPubKey",
                                 "Deployer.nonce",
                                 "Deployer.initFlag"));

    JvmContractAccountState state;
    state.schema_version = kJvmContractAccountStateSchemaVersion;
    state.stdlib_hash = stdlib_hash;
    state.class_hash = class_hash;
    state.deployer = kJvmGenesisDeployer;
    state.address_commit = address_commit;
    state.class_bytes = encode_jvm_storage_value(class_bytes_vec);
    state.storage_root = storage_root;
    state.manifest_root = manifest_cell;
    if (state.class_bytes.is_null()) {
        return td::Status::Error(
            "JVM genesis deployer build: class_bytes encode failed");
    }

    auto contract_state_cell = encode_jvm_contract_account_state(state);
    if (contract_state_cell.is_null()) {
        return td::Status::Error(
            "JVM genesis deployer build: JVAC encode failed");
    }

    auto state_init_cell = encode_jvm_state_init_cell(state);
    if (state_init_cell.is_null()) {
        return td::Status::Error(
            "JVM genesis deployer build: StateInit encode failed");
    }

    auto account_cell =
        build_account_cell(address, state_init_cell, deployer.initial_balance);
    if (account_cell.is_null()) {
        return td::Status::Error(
            "JVM genesis deployer build: account cell encode failed");
    }
    if (!block::gen::t_Account.validate_ref(account_cell)) {
        return td::Status::Error(
            "JVM genesis deployer build: account cell failed TLB validation");
    }

    auto shard_entry = build_shard_account_entry(account_cell);
    if (shard_entry.is_null()) {
        return td::Status::Error(
            "JVM genesis deployer build: ShardAccount entry encode failed");
    }

    JvmGenesisDeployerBuild built;
    built.address = address;
    built.shard_account_cell = std::move(shard_entry);
    built.account_cell = std::move(account_cell);
    built.contract_account_state_cell = std::move(contract_state_cell);
    return built;
}

}  // namespace jvm_workchain
