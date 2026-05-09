/*
    JVM Workchain — per-account contract state envelope.

    Each JVM contract is a real wc=3 account at a deterministic 256-bit
    address with its own class bytes, per-account method manifest, and
    isolated storage.  This codec defines the canonical
    `JvmContractAccountState` cell (magic JVAC) carried in `account.data`
    plus a `StateInit{code, data}` builder used by `action_create_account`.
*/
#pragma once

#include <array>
#include <cstdint>

#include "jvm/core/config-param.h"
#include "jvm/core/deploy-abi.h"
#include "vm/cells.h"

namespace jvm_workchain {

constexpr std::uint32_t kJvmContractAccountStateMagic = 0x4a564143;  // "JVAC"
constexpr unsigned kJvmContractAccountStateMagicBits = 32;
constexpr std::uint8_t kJvmContractAccountStateSchemaVersion = 2;

// One contract == one wc=3 account.  Stored in `account.data`; the matching
// `account.code` cell is the activation marker (single byte 0x4a, see
// `jvm_activation_code_cell()` in dispatch-engine.cpp).
struct JvmContractAccountState {
    std::uint8_t schema_version{kJvmContractAccountStateSchemaVersion};
    std::array<std::uint8_t, kJvmStdlibHashBytes> stdlib_hash{};
    JvmClassHash class_hash{};
    // 32-byte address of the wc=3 contract that emitted the
    // `action_create_account` for this account.  Bound directly into
    // the account address derivation so the engine can reject any
    // first-activation message whose source != deployer (round-14
    // front-run fix).  Without this, an attacker who saw a victim's
    // pending deploy could copy the StateInit and run their own first
    // call body on the same address.
    JvmContractId deployer{};
    // address_commit = sha256(deployer || salt || init_args_cell_hash).
    // The wc=3 account address is sha256("TOS-JVM-CONTRACT-v2" ||
    // deployer || address_commit || class_hash || manifest_root_hash);
    // the engine verifies this on every run_compute so an attacker
    // cannot squat a victim's deterministic address with attacker
    // bytecode (the address-binding gate).
    JvmAddressCommit address_commit{};
    // class_bytes is held as a Cell ref so the Cell DB physically deduplicates
    // contracts that share identical bytecode (verified: CellStorage keys by
    // hash with refcount accounting; see crypto/vm/db/CellStorage.cpp:267).
    td::Ref<vm::Cell> class_bytes;
    td::Ref<vm::Cell> storage_root;
    td::Ref<vm::Cell> manifest_root;  // per-account method-id → method spec
    // Decoded class_bytes size in bytes — populated by
    // `decode_jvm_contract_account_state` after the sha256 binding check.
    // Allows the engine to cheaply enforce ConfigParam 85's
    // `max_class_bytes` cap without a second decode pass.  Not part of
    // the wire format; the encoder never reads it.
    std::size_t decoded_class_bytes_size{0};
};

// Layout:
//   jvm_contract_account#4a564143
//     schema_version:uint8 (=2)
//     stdlib_hash:bits256
//     deployer:bits256
//     address_commit:bits256
//     class_bytes:^Cell                 -- class_hash is recomputed
//                                          from this, not stored on
//                                          the wire
//     storage_root:(Maybe ^Cell)
//     manifest_root:(Maybe ^Cell)
//     = JvmContractAccountState;
//
// `class_hash` is intentionally NOT stored on the wire.  Pre-round-14
// JVAC stored `class_hash` inline, but adding `deployer` (round-14)
// pushed the root cell over the 1023-bit limit.  The decoder
// recomputes `class_hash = sha256(decoded class_bytes)` and surfaces
// it on the struct.  The encoder writes nothing for class_hash.
// Address binding still uses class_hash because the recomputed value
// is canonical (Cell DB keys class_bytes by hash, so two contracts
// with the same class_bytes produce the same recomputed hash).
//
// Address-binding invariant: after a successful decode, the decoded state's
// `(address_commit, class_hash)` MUST satisfy
//     account_addr == sha256("TOS-JVM-CONTRACT-v2" || address_commit ||
//                             class_hash)
// otherwise the engine rejects the run_compute (`run_contract` checks via
// `derive_jvm_contract_address_from_state`).  This is why an attacker
// cannot squat a victim's deterministic but not-yet-active address by
// sending an arbitrary StateInit there.
td::Ref<vm::Cell> encode_jvm_contract_account_state(
    const JvmContractAccountState& state);

// Decode the canonical v2 per-account envelope.  Rejects null/special cells,
// wrong magic/schema, zero class_hash, non-canonical Maybe refs, and trailing
// bits/refs.  Does not validate the storage trie or the method manifest in
// depth; callers re-validate those once they have a config + workchain
// context.
bool decode_jvm_contract_account_state(td::Ref<vm::Cell> cell,
                                       JvmContractAccountState& out);

// Build the canonical TLB `StateInit{code, data}` cell that materializes a
// new wc=3 account whose initial state is `state`.  `code` is the JVM
// activation marker (0x4a) and `data` is the encoded
// `JvmContractAccountState` cell.  Returns `td::Ref{}` if the state fails to
// encode.
td::Ref<vm::Cell> encode_jvm_state_init_cell(
    const JvmContractAccountState& state);

}  // namespace jvm_workchain
