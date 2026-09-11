#pragma once

#include "block/workchain-resource-policy.h"
#include "vm/dict.h"
#include <sodium/crypto_core_ristretto255.h>
#include <variant>
#include <vector>

namespace block {

using WorkchainConfidentialAddress = gen::UnoV2AccountAddress::Record;
using WorkchainConfidentialBindings = gen::UnoV2AccountBindings::Record;
using WorkchainRegistrationFunding = gen::UnoV2RegistrationFunding::Record;
using WorkchainCiphertext = gen::UnoV2AccountCiphertext::Record;
struct WorkchainAccountActive {};
struct WorkchainAccountReadOnly {};
struct WorkchainAccountMigrated {
  WorkchainConfidentialAddress successor;
  td::Bits256 migration_operation;
};
// Closed retains identity/replay state. The host must establish deposit refunded,
// available exhausted and pending empty. M3's no-settlement-obligation premise
// is structural, guarded by test-workchain-m3-closure-expiry, not a runtime
// caller declaration. registered_accounts never decreases; no dormant state.
struct WorkchainAccountClosed {};
using WorkchainConfidentialLifecycle = std::variant<WorkchainAccountActive, WorkchainAccountReadOnly,
                                                  WorkchainAccountMigrated, WorkchainAccountClosed>;

struct WorkchainPendingReceipt {
  td::Bits256 receipt_id;
  WorkchainConfidentialAddress source;
  std::uint64_t source_operation_nonce;
  td::Bits256 target_instance;
  std::uint32_t target_key_epoch;
  td::Bits256 asset;
  WorkchainCiphertext ciphertext;
  // Full source operation identity, not a ticket counter or proof hash. The
  // admitting host authenticates this origin; decoding it is not authentication.
  td::Bits256 operation_id;
  std::uint32_t output_index;
  // M3 stores available receipts (0); COLLECT removes consumed entries. Unknown
  // status encodings are rejected, never interpreted as available.
  std::uint8_t status;
};

struct WorkchainConfidentialAccount {
  // Independent axes, never inferred from admission_version or one another.
  std::uint16_t schema_version, relation_profile, proof_profile;
  std::int32_t global_id;
  td::Bits256 genesis_hash;
  WorkchainConfidentialAddress address;
  WorkchainConfidentialBindings bindings;
  // Historical amount paid and Native refund address, not today's config price.
  // This public refundable deposit is not the confidential available balance.
  WorkchainRegistrationFunding funding;
  td::Bits256 public_key;
  std::uint32_t key_epoch;
  WorkchainCiphertext available;
  std::uint64_t auth_nonce, available_revision;
  std::vector<WorkchainPendingReceipt> pending;
  WorkchainConfidentialLifecycle lifecycle;
  // No settlement refs in M3. Withdrawal adds them through a future tag migration.
};

namespace confidential_state_detail {
template <class Record>
td::Result<td::Ref<vm::Cell>> pack(const Record& record) {
  td::Ref<vm::Cell> root;
  if (!tlb::pack_cell(root, record)) return td::Status::Error("unrepresentable confidential record");
  return root;
}
template <class Record>
td::Result<Record> unpack(const td::Ref<vm::Cell>& root) {
  Record record;
  if (!resource_policy_detail::unpack_exact(root, record)) {
    return td::Status::Error("malformed confidential record");
  }
  return record;
}
inline bool canonical_point(const td::Bits256& point) {
  return crypto_core_ristretto255_is_valid_point(
      reinterpret_cast<const unsigned char*>(point.as_slice().data())) == 1;
}
inline bool canonical_ciphertext(const WorkchainCiphertext& value) {
  // Identity is permitted for ciphertext components, including initial (0,0).
  // Plaintext value and validity of state transitions are proved by the kernel.
  return canonical_point(value.commitment) && canonical_point(value.handle);
}
}  // namespace confidential_state_detail

inline td::Result<td::Bits256> derive_workchain_receipt_id(const td::Bits256& source_instance,
    const td::Bits256& operation_id, std::uint64_t output_index) {
  if (output_index > UINT32_MAX) return td::Status::Error("receipt output index overflow");
  // CellRepr provides H over a canonical, version-tagged record. Explicit source
  // instance separates independently allocated operation IDs/nonce spaces;
  // otherwise cross-instance collisions undermine COLLECT's strict ID ordering.
  gen::UnoV2ReceiptIdentity::Record preimage{source_instance, operation_id, static_cast<unsigned>(output_index)};
  TRY_RESULT(root, confidential_state_detail::pack(preimage));
  return td::Bits256(root->get_hash().bits());
}

inline td::Result<td::Ref<vm::Cell>> encode_workchain_pending_receipt(const WorkchainPendingReceipt& value) {
  using confidential_state_detail::pack;
  if (!confidential_state_detail::canonical_ciphertext(value.ciphertext)) {
    return td::Status::Error("noncanonical pending ciphertext");
  }
  TRY_RESULT(id, derive_workchain_receipt_id(value.source.instance, value.operation_id, value.output_index));
  if (id != value.receipt_id) return td::Status::Error("pending receipt identity mismatch");
  TRY_RESULT(source, pack(value.source));
  TRY_RESULT(target, pack(gen::UnoV2PendingTarget::Record{value.target_instance, value.target_key_epoch, value.asset}));
  TRY_RESULT(ciphertext, pack(value.ciphertext));
  TRY_RESULT(origin, pack(gen::UnoV2PendingOrigin::Record{value.operation_id, value.output_index}));
  return pack(gen::UnoV2PendingReceipt::Record{value.receipt_id, value.source_operation_nonce,
      value.status, source, target, ciphertext, origin});
}

inline td::Result<WorkchainPendingReceipt> decode_workchain_pending_receipt(const td::Ref<vm::Cell>& root) {
  using confidential_state_detail::unpack;
  TRY_RESULT(record, unpack<gen::UnoV2PendingReceipt::Record>(root));
  TRY_RESULT(source, unpack<WorkchainConfidentialAddress>(record.source));
  TRY_RESULT(target, unpack<gen::UnoV2PendingTarget::Record>(record.target));
  TRY_RESULT(ciphertext, unpack<WorkchainCiphertext>(record.ciphertext));
  TRY_RESULT(origin, unpack<gen::UnoV2PendingOrigin::Record>(record.origin));
  WorkchainPendingReceipt value{record.receipt_id, source, record.source_operation_nonce,
      target.instance, target.key_epoch, target.asset, ciphertext, origin.operation_id,
      origin.output_index, static_cast<std::uint8_t>(record.status)};
  TRY_RESULT(canonical, encode_workchain_pending_receipt(value));
  if (canonical->get_hash() != root->get_hash()) return td::Status::Error("noncanonical pending receipt");
  return value;
}

inline td::Result<td::Ref<vm::Cell>> encode_workchain_account_lifecycle(const WorkchainConfidentialLifecycle& value) {
  using T = gen::UnoV2AccountLifecycle;
  using confidential_state_detail::pack;
  if (std::holds_alternative<WorkchainAccountActive>(value)) return pack(T::Record_uno_v2_account_active{});
  if (std::holds_alternative<WorkchainAccountReadOnly>(value)) return pack(T::Record_uno_v2_account_read_only{});
  if (std::holds_alternative<WorkchainAccountClosed>(value)) return pack(T::Record_uno_v2_account_closed{});
  const auto& migrated = std::get<WorkchainAccountMigrated>(value);
  TRY_RESULT(successor, pack(migrated.successor));
  return pack(T::Record_uno_v2_account_migrated{successor, migrated.migration_operation});
}

inline td::Result<WorkchainConfidentialLifecycle> decode_workchain_account_lifecycle(const td::Ref<vm::Cell>& root) {
  using T = gen::UnoV2AccountLifecycle;
  using confidential_state_detail::unpack;
  if (root.is_null()) return td::Status::Error("missing account lifecycle");
  bool special = false;
  auto cs = vm::load_cell_slice_special(root, special);
  if (special) return td::Status::Error("special account lifecycle");
  switch (gen::t_UnoV2AccountLifecycle.check_tag(cs)) {
    case T::uno_v2_account_active: {
      auto record = unpack<T::Record_uno_v2_account_active>(root);
      if (record.is_error()) return record.move_as_error();
      return WorkchainConfidentialLifecycle{WorkchainAccountActive{}};
    }
    case T::uno_v2_account_read_only: {
      auto record = unpack<T::Record_uno_v2_account_read_only>(root);
      if (record.is_error()) return record.move_as_error();
      return WorkchainConfidentialLifecycle{WorkchainAccountReadOnly{}};
    }
    case T::uno_v2_account_closed: {
      auto record = unpack<T::Record_uno_v2_account_closed>(root);
      if (record.is_error()) return record.move_as_error();
      return WorkchainConfidentialLifecycle{WorkchainAccountClosed{}};
    }
    case T::uno_v2_account_migrated: {
      TRY_RESULT(record, unpack<T::Record_uno_v2_account_migrated>(root));
      TRY_RESULT(successor, unpack<WorkchainConfidentialAddress>(record.successor));
      return WorkchainConfidentialLifecycle{WorkchainAccountMigrated{successor, record.migration_operation}};
    }
    default: return td::Status::Error("unknown account lifecycle tag");
  }
}

inline td::Result<td::Ref<vm::Cell>> encode_workchain_confidential_account(const WorkchainConfidentialAccount& value) {
  using confidential_state_detail::pack;
  if (value.schema_version != 1) return td::Status::Error("unsupported confidential account schema");
  if (value.public_key.is_zero() || !confidential_state_detail::canonical_point(value.public_key)) {
    return td::Status::Error("invalid confidential public key");
  }
  if (!confidential_state_detail::canonical_ciphertext(value.available)) {
    return td::Status::Error("noncanonical available ciphertext");
  }
  if (value.pending.size() > 16) return td::Status::Error("pending capacity exceeded");
  vm::Dictionary pending(256);
  for (const auto& receipt : value.pending) {
    // Historical epochs survive key rotation; newly created receipt epoch
    // authorization is a host transition check, not a decoder default.
    if (receipt.target_instance != value.address.instance ||
        receipt.asset != value.bindings.asset) return td::Status::Error("pending target binding mismatch");
    TRY_RESULT(encoded, encode_workchain_pending_receipt(receipt));
    // A map cannot encode two values for one key; do not silently overwrite.
    // Input vector order is irrelevant. COLLECT's selected-ID ordering and
    // distinctness checks belong to the existing crypto relation, not here.
    if (!pending.set_ref(receipt.receipt_id, encoded, vm::Dictionary::SetMode::Add)) {
      return td::Status::Error("duplicate pending dictionary key");
    }
  }
  TRY_RESULT(address, pack(value.address));
  TRY_RESULT(bindings, pack(value.bindings));
  TRY_RESULT(funding, pack(value.funding));
  TRY_RESULT(identity, pack(gen::UnoV2AccountIdentity::Record{value.global_id, value.genesis_hash, address, bindings, funding}));
  TRY_RESULT(available, pack(value.available));
  TRY_RESULT(crypto, pack(gen::UnoV2AccountCrypto::Record{value.public_key, value.key_epoch, available}));
  TRY_RESULT(lifecycle, encode_workchain_account_lifecycle(value.lifecycle));
  return pack(gen::UnoV2AccountState::Record{value.schema_version, value.relation_profile, value.proof_profile,
      value.auth_nonce, value.available_revision, static_cast<unsigned>(value.pending.size()), identity, crypto,
      std::move(pending).extract_root(), lifecycle});
}

// Fixed-width records plus at most 16 complete receipts. No fallback formats,
// no hash-only restoration, and no exception-to-malformed conversion. Callers
// classify candidate bytes versus unavailable authenticated state themselves.
inline td::Result<WorkchainConfidentialAccount> decode_workchain_confidential_account(const td::Ref<vm::Cell>& root) {
  using confidential_state_detail::unpack;
  TRY_RESULT(record, unpack<gen::UnoV2AccountState::Record>(root));
  if (record.schema_version != 1) return td::Status::Error("unsupported confidential account schema");
  TRY_RESULT(identity, unpack<gen::UnoV2AccountIdentity::Record>(record.identity));
  TRY_RESULT(address, unpack<WorkchainConfidentialAddress>(identity.address));
  TRY_RESULT(bindings, unpack<WorkchainConfidentialBindings>(identity.bindings));
  TRY_RESULT(funding, unpack<WorkchainRegistrationFunding>(identity.funding));
  TRY_RESULT(crypto, unpack<gen::UnoV2AccountCrypto::Record>(record.crypto));
  TRY_RESULT(available, unpack<WorkchainCiphertext>(crypto.available));
  TRY_RESULT(lifecycle, decode_workchain_account_lifecycle(record.lifecycle));
  WorkchainConfidentialAccount value{static_cast<std::uint16_t>(record.schema_version),
      static_cast<std::uint16_t>(record.relation_profile), static_cast<std::uint16_t>(record.proof_profile),
      identity.global_id, identity.genesis_hash, address, bindings, funding, crypto.public_key, crypto.key_epoch,
      available, record.auth_nonce, record.available_revision, {}, lifecycle};
  vm::Dictionary pending(record.pending, 256);
  td::Status error = td::Status::OK();
  if (!pending.check_for_each([&](td::Ref<vm::CellSlice> leaf, td::ConstBitPtr key, int width) {
        if (value.pending.size() >= 16 || width != 256 || leaf->size_ext() != 0x10000) return false;
        auto decoded = decode_workchain_pending_receipt(leaf->prefetch_ref());
        if (decoded.is_error()) { error = decoded.move_as_error(); return false; }
        if (decoded.ok().receipt_id != td::Bits256(key)) return false;
        value.pending.push_back(decoded.move_as_ok());
        return true;
      })) {
    if (error.is_error()) return std::move(error);
    return td::Status::Error("invalid or excessive pending dictionary");
  }
  if (value.pending.size() != record.pending_count) return td::Status::Error("pending count mismatch");
  TRY_RESULT(canonical, encode_workchain_confidential_account(value));
  if (canonical->get_hash() != root->get_hash()) return td::Status::Error("noncanonical confidential account");
  return value;
}

}  // namespace block
