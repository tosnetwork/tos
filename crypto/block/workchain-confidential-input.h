#pragma once

#include "block/workchain-confidential-state.h"
#include "block/workchain-execution-errors.h"
#include <algorithm>
#include <array>
#include <string>

namespace block {
// Wire claims, never authenticated state or an execution verdict.
struct WorkchainTransferClaims {
  WorkchainConfidentialAddress source;
  std::uint64_t auth_nonce, available_revision;
  std::uint32_t key_epoch, expiry_height;
  std::uint64_t authorized_fee;
};
struct WorkchainSendData {
  WorkchainTransferClaims claims;
  WorkchainConfidentialAddress destination;
  std::uint32_t destination_key_epoch;
  WorkchainCiphertext available;
  gen::UnoV2SendCiphertextV1::Record transfer;
  td::Bits256 auxiliary;
};
struct WorkchainCollectItem {
  td::Bits256 receipt_id, auxiliary;
};
struct WorkchainCollectData {
  WorkchainTransferClaims claims;
  WorkchainCiphertext available;
  td::Bits256 auxiliary_old;
  std::vector<WorkchainCollectItem> selected;
};
using WorkchainTransferData = std::variant<WorkchainSendData, WorkchainCollectData>;
struct WorkchainTransferAuthorization {
  std::vector<td::Bits256> commitments, responses;
  std::string range_proof;
};
struct WorkchainTransferInput {
  td::Bits256 claimed_operation_id;
  WorkchainTransferData data;
  WorkchainTransferAuthorization authorization;
};

// All fields are untrusted claims. Each validator reconstructs them from the
// authenticated configuration and account, then compares; they are not defaults
// or inputs to old-state acquisition. Account incarnation and workchain_instance
// occupy different slots. The enclosing constructor identifies the operation.
struct WorkchainReplayContext {
  gen::UnoV2ReplayProtocolV1::Record protocol;
  gen::UnoV2TransferRulesV1::Record rules;
  gen::UnoV2TransferProfilesV1::Record profiles;
  td::Bits256 fee_profile;
  std::uint32_t fee_effective_height;
  WorkchainConfidentialAddress subject;
  std::uint64_t auth_nonce, available_revision;
  std::uint32_t key_epoch;
};
struct WorkchainRegistrationReplayInput {
  td::Bits256 claimed_operation_id;
  WorkchainReplayContext context;
  std::array<unsigned char, 64> proof;
};
struct WorkchainClosureReplayInput {
  td::Bits256 claimed_operation_id;
  WorkchainReplayContext context;
  std::array<unsigned char, 96> proof;
};
using WorkchainReplayInput = std::variant<WorkchainTransferInput,
    WorkchainRegistrationReplayInput, WorkchainClosureReplayInput>;

namespace confidential_input_detail {
inline td::Status invalid(td::Slice message) {
  return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid), message);
}
template <class R> td::Result<R> unpack(const td::Ref<vm::Cell>& root) {
  R result;
  if (!resource_policy_detail::unpack_exact(root, result)) return invalid("malformed confidential input record");
  return result;
}
using confidential_state_detail::pack;


// Compact authorization bytes, not an alternative account/state representation.
// The enclosing typed relation determines the exact length before traversal.
// Every non-final cell has 127 bytes and one forward reference; the last has
// the exact remaining bytes and no references. No hash/ID points back at this
// chain. Acquisition exceptions propagate to the caller with their provenance.
inline td::Result<td::Ref<vm::Cell>> encode_bytes(td::Slice bytes, std::size_t expected) {
  if (expected == 0 || expected > 4096 || bytes.size() != expected) {
    return invalid("confidential authorization length mismatch");
  }
  td::Ref<vm::Cell> next;
  std::size_t end = expected;
  while (end != 0) {
    // end > 0 makes end - 1 safe. start <= end, so neither subtraction wraps.
    const auto start = ((end - 1) / 127) * 127;
    vm::CellBuilder builder;
    if (!builder.store_bytes_bool(bytes.substr(start, end - start)) ||
        (next.not_null() && !builder.store_ref_bool(next))) {
      return td::Status::Error("unrepresentable confidential authorization");
    }
    next = builder.finalize();
    end = start;
  }
  return next;
}

inline td::Result<std::string> decode_bytes(td::Ref<vm::Cell> root, std::size_t expected) {
  if (expected == 0 || expected > 4096) {
    return invalid("confidential authorization length mismatch");
  }
  std::string out;
  out.reserve(expected);
  std::size_t remaining = expected;
  while (remaining != 0) {
    if (root.is_null()) return invalid("missing confidential authorization cell");
    bool special = false;
    auto slice = vm::load_cell_slice_special(root, special);
    const auto count = std::min<std::size_t>(remaining, 127);
    const bool more = remaining > count;
    if (special || slice.size() != count * 8 || slice.size_refs() != unsigned(more)) {
      return invalid("noncanonical confidential authorization chain");
    }
    char bytes[127];
    if (!slice.fetch_bytes(td::MutableSlice(bytes, count))) {
      return invalid("truncated confidential authorization bytes");
    }
    out.append(bytes, count);
    root = more ? slice.fetch_ref() : td::Ref<vm::Cell>{};
    // count <= remaining was established above. The decreasing bound also
    // caps traversal if a malicious cell implementation repeats a reference.
    remaining -= count;
  }
  return out;
}

}  // namespace confidential_input_detail

inline const WorkchainTransferClaims& workchain_transfer_claims(const WorkchainTransferData& data) {
  return std::visit([](const auto& value) -> const WorkchainTransferClaims& { return value.claims; }, data);
}
inline unsigned workchain_transfer_kind(const WorkchainTransferData& data) {
  return std::holds_alternative<WorkchainSendData>(data) ? 1 : 2;
}

// This primitive hashes explicit inputs. Each host must supply authenticated
// network/source identity and the independently checked consumed nonce. The
// proof binds operationID as an INPUT: including T_j/z/range would be cyclic.
inline td::Result<td::Bits256> derive_workchain_operation_id(
    const gen::UnoV2OperationNetworkV1::Record& network, const WorkchainConfidentialAddress& source,
    unsigned kind, std::uint64_t auth_nonce) {
  using namespace confidential_input_detail;
  if (kind != 1 && kind != 2) return invalid("unknown confidential operation kind");
  TRY_RESULT(net, pack(network));
  TRY_RESULT(address, pack(source));
  TRY_RESULT(root, pack(gen::UnoV2OperationIdentityV1::Record_uno_v2_operation_identity_v1{kind, auth_nonce, net, address}));
  return root->get_hash().bits();
}

// Section 7.3: network/workchain instance, full source/incarnation, operation
// kind and consumed nonce derive the logical identity before applying anything.
// Only the numeric host Close=4 assignment is an M3 implementation choice whose
// specification allocation is unfrozen; it is NOT a new crypto relation ID.
// Old revision is already known, not a future result: the proof context binds it
// as the state being authorized. It is deliberately outside this identity tuple.
// No resulting revision, proof, claimed digest, future LT or block hash enters
// this preimage. The host supplies authenticated values and consumes nonce once;
// this encoding helper performs neither acquisition nor a replay verdict.
inline td::Result<td::Bits256> derive_workchain_closure_operation_id(
    const gen::UnoV2OperationNetworkV1::Record& network, const WorkchainConfidentialAddress& source,
    std::uint64_t consumed_nonce) {
  using namespace confidential_input_detail;
  TRY_RESULT(net, pack(network));
  TRY_RESULT(address, pack(source));
  TRY_RESULT(root, pack(gen::UnoV2OperationIdentityV1::Record_uno_v2_closure_identity_v1{
      4, consumed_nonce, net, address}));
  return root->get_hash().bits();
}

// Only compares the untrusted claim to an already independently recomputed ID.
// Never use claimed_operation_id to derive receipts or a proof statement.
inline td::Status check_workchain_claimed_operation_id(const WorkchainTransferInput& input,
                                                       const td::Bits256& recomputed) {
  if (input.claimed_operation_id != recomputed) {
    return confidential_input_detail::invalid("claimed operationID mismatch");
  }
  return td::Status::OK();
}

namespace confidential_input_detail {
inline td::Result<td::Ref<vm::Cell>> pack_claims(const WorkchainTransferClaims& value) {
  TRY_RESULT(source, pack(value.source));
  return pack(gen::UnoV2TransferClaimsV1::Record{value.auth_nonce, value.available_revision,
      value.key_epoch, value.expiry_height, value.authorized_fee, source});
}
inline td::Result<WorkchainTransferClaims> unpack_claims(const td::Ref<vm::Cell>& root) {
  TRY_RESULT(value, unpack<gen::UnoV2TransferClaimsV1::Record>(root));
  TRY_RESULT(source, unpack<WorkchainConfidentialAddress>(value.source));
  return WorkchainTransferClaims{source, value.auth_nonce, value.available_revision,
      value.key_epoch, value.expiry_height, value.authorized_fee};
}
inline void append_word(std::string& bytes, const td::Bits256& word) {
  bytes.append(word.as_slice().data(), 32);
}
inline td::Bits256 read_word(td::Slice& bytes) {
  CHECK(bytes.size() >= 32);  // Exact relation-derived size was checked first.
  td::Bits256 result;
  result.as_slice().copy_from(bytes.substr(0, 32));
  bytes.remove_prefix(32);
  return result;
}
struct Shape { std::size_t commitments, responses, range; };
inline td::Result<Shape> shape(const WorkchainTransferData& data) {
  if (std::holds_alternative<WorkchainSendData>(data)) return Shape{8, 6, 864};
  const auto k = std::get<WorkchainCollectData>(data).selected.size();
  if (k == 0 || k > 16) return invalid("COLLECT selection must contain 1..16 items");
  // k <= 16 bounds all following size arithmetic (not monetary arithmetic).
  std::size_t padded = 1, log = 6;
  while (padded < 4 + 2 * k) { padded *= 2; ++log; }
  return Shape{5 + 2 * k, 4 + 2 * k, (2 * log + 9) * 32};
}
}  // namespace confidential_input_detail

// txid is the representation hash of this semantic cell, excluding every
// authorization byte. All new ciphertexts/J and receipt selections are included.
// It contains no operationID, txid, proof hash or current block hash.
inline td::Result<td::Ref<vm::Cell>> encode_workchain_transfer_data(const WorkchainTransferData& data) {
  using namespace confidential_input_detail;
  TRY_RESULT(claims, pack_claims(workchain_transfer_claims(data)));
  if (const auto* send = std::get_if<WorkchainSendData>(&data)) {
    TRY_RESULT(destination, pack(send->destination));
    TRY_RESULT(available, pack(send->available));
    TRY_RESULT(transfer, pack(send->transfer));
    return pack(gen::UnoV2TransferDataV1::Record_uno_v2_send_data_v1{
        send->destination_key_epoch, send->auxiliary, claims, destination, available, transfer});
  }
  const auto& collect = std::get<WorkchainCollectData>(data);
  TRY_RESULT(checked_shape, shape(data));
  (void)checked_shape;
  TRY_RESULT(available, pack(collect.available));
  std::string selected;
  for (const auto& item : collect.selected) {
    append_word(selected, item.receipt_id); append_word(selected, item.auxiliary);
  }
  TRY_RESULT(items, encode_bytes(selected, collect.selected.size() * 64));
  return pack(gen::UnoV2TransferDataV1::Record_uno_v2_collect_data_v1{
      static_cast<unsigned>(collect.selected.size()), collect.auxiliary_old, claims, available, items});
}

inline td::Result<td::Bits256> workchain_transfer_txid(const WorkchainTransferData& data) {
  TRY_RESULT(root, encode_workchain_transfer_data(data));
  return root->get_hash().bits();
}

inline td::Result<WorkchainTransferData> decode_workchain_transfer_data(const td::Ref<vm::Cell>& root) {
  using namespace confidential_input_detail;
  if (root.is_null()) return invalid("missing confidential transfer data");
  bool special = false;
  auto slice = vm::load_cell_slice_special(root, special);
  if (special || slice.size() < 32) return invalid("invalid confidential transfer tag");
  const auto tag = slice.prefetch_ulong(32);
  if (tag == gen::UnoV2TransferDataV1::cons_tag[gen::UnoV2TransferDataV1::uno_v2_send_data_v1]) {
    TRY_RESULT(wire, unpack<gen::UnoV2TransferDataV1::Record_uno_v2_send_data_v1>(root));
    TRY_RESULT(claims, unpack_claims(wire.claims));
    TRY_RESULT(destination, unpack<WorkchainConfidentialAddress>(wire.destination));
    TRY_RESULT(available, unpack<WorkchainCiphertext>(wire.available));
    TRY_RESULT(transfer, unpack<gen::UnoV2SendCiphertextV1::Record>(wire.transfer));
    return WorkchainTransferData{WorkchainSendData{claims, destination, wire.destination_key_epoch,
                                                  available, transfer, wire.auxiliary}};
  }
  if (tag != gen::UnoV2TransferDataV1::cons_tag[gen::UnoV2TransferDataV1::uno_v2_collect_data_v1]) {
    return invalid("unknown confidential transfer tag");
  }
  TRY_RESULT(wire, unpack<gen::UnoV2TransferDataV1::Record_uno_v2_collect_data_v1>(root));
  TRY_RESULT(claims, unpack_claims(wire.claims));
  TRY_RESULT(available, unpack<WorkchainCiphertext>(wire.available));
  TRY_RESULT(bytes, decode_bytes(wire.selected, std::size_t(wire.count) * 64));
  td::Slice cursor(bytes);
  std::vector<WorkchainCollectItem> selected;
  for (unsigned i = 0; i < wire.count; ++i) {
    auto id = read_word(cursor); auto auxiliary = read_word(cursor);
    selected.push_back({id, auxiliary});
  }
  // Preserve input order. The kernel checks sorted/distinct receiptIDs; the
  // host authenticates ownership, origin, availability and consumption.
  return WorkchainTransferData{WorkchainCollectData{claims, available, wire.auxiliary_old, std::move(selected)}};
}

inline td::Result<td::Ref<vm::Cell>> encode_workchain_transfer_input(const WorkchainTransferInput& input) {
  using namespace confidential_input_detail;
  TRY_RESULT(s, shape(input.data));
  const auto& auth = input.authorization;
  if (auth.commitments.size() != s.commitments || auth.responses.size() != s.responses ||
      auth.range_proof.size() != s.range) return invalid("confidential proof shape mismatch");
  TRY_RESULT(data, encode_workchain_transfer_data(input.data));
  std::string bytes;
  for (const auto& word : auth.commitments) append_word(bytes, word);
  for (const auto& word : auth.responses) append_word(bytes, word);
  bytes.append(auth.range_proof);
  TRY_RESULT(authorization, encode_bytes(bytes, (s.commitments + s.responses) * 32 + s.range));
  return pack(gen::UnoV2TransferInputV1::Record_uno_v2_transfer_input_v1{input.claimed_operation_id, data, authorization});
}

inline td::Result<WorkchainTransferInput> decode_workchain_transfer_input(const td::Ref<vm::Cell>& root) {
  using namespace confidential_input_detail;
  TRY_RESULT(wire, unpack<gen::UnoV2TransferInputV1::Record_uno_v2_transfer_input_v1>(root));
  TRY_RESULT(data, decode_workchain_transfer_data(wire.data));
  TRY_RESULT(s, shape(data));
  TRY_RESULT(bytes, decode_bytes(wire.authorization, (s.commitments + s.responses) * 32 + s.range));
  td::Slice cursor(bytes);
  WorkchainTransferAuthorization auth;
  for (std::size_t i = 0; i < s.commitments; ++i) auth.commitments.push_back(read_word(cursor));
  for (std::size_t i = 0; i < s.responses; ++i) auth.responses.push_back(read_word(cursor));
  auth.range_proof = cursor.str();
  // No fallback, no signature/point validity verdict and no state acquisition.
  // Cell-loading/allocation exceptions reach the host's local-failure boundary.
  return WorkchainTransferInput{wire.claimed_operation_id, std::move(data), std::move(auth)};
}

namespace confidential_input_detail {
inline td::Result<td::Ref<vm::Cell>> pack_replay_context(const WorkchainReplayContext& value) {
  TRY_RESULT(address, pack(value.subject));
  TRY_RESULT(subject, pack(gen::UnoV2ReplaySubjectV1::Record{
      value.auth_nonce, value.available_revision, value.key_epoch, address}));
  TRY_RESULT(protocol, pack(value.protocol));
  TRY_RESULT(rules, pack(value.rules));
  TRY_RESULT(profiles, pack(value.profiles));
  return pack(gen::UnoV2ReplayContextV1::Record{
      value.fee_profile, value.fee_effective_height, subject, protocol, rules, profiles});
}
inline td::Result<WorkchainReplayContext> unpack_replay_context(const td::Ref<vm::Cell>& root) {
  TRY_RESULT(wire, unpack<gen::UnoV2ReplayContextV1::Record>(root));
  TRY_RESULT(subject, unpack<gen::UnoV2ReplaySubjectV1::Record>(wire.subject));
  TRY_RESULT(address, unpack<WorkchainConfidentialAddress>(subject.address));
  TRY_RESULT(protocol, unpack<gen::UnoV2ReplayProtocolV1::Record>(wire.protocol));
  TRY_RESULT(rules, unpack<gen::UnoV2TransferRulesV1::Record>(wire.rules));
  TRY_RESULT(profiles, unpack<gen::UnoV2TransferProfilesV1::Record>(wire.profiles));
  return WorkchainReplayContext{protocol, rules, profiles, wire.fee_profile,
      wire.fee_effective_height, address, subject.auth_nonce, subject.available_revision, subject.key_epoch};
}
template <class Input, class Wire>
inline td::Result<td::Ref<vm::Cell>> pack_possession_input(const Input& input) {
  TRY_RESULT(context, pack_replay_context(input.context));
  TRY_RESULT(authorization, encode_bytes(td::Slice(input.proof.data(), input.proof.size()), input.proof.size()));
  return pack(Wire{input.claimed_operation_id, context, authorization});
}
template <class Input, class Wire>
inline td::Result<WorkchainReplayInput> unpack_possession_input(const td::Ref<vm::Cell>& root) {
  TRY_RESULT(wire, unpack<Wire>(root));
  TRY_RESULT(context, unpack_replay_context(wire.context));
  Input result{wire.claimed_operation_id, std::move(context), {}};
  TRY_RESULT(bytes, decode_bytes(wire.authorization, result.proof.size()));
  std::copy(bytes.begin(), bytes.end(), result.proof.begin());
  return WorkchainReplayInput{std::move(result)};
}
}  // namespace confidential_input_detail

// One permanent input family. No fallback to account records or test files;
// loading/allocation exceptions propagate to the host's provenance boundary.
inline td::Result<td::Ref<vm::Cell>> encode_workchain_replay_input(const WorkchainReplayInput& input) {
  using namespace confidential_input_detail;
  if (const auto* transfer = std::get_if<WorkchainTransferInput>(&input))
    return encode_workchain_transfer_input(*transfer);
  if (const auto* registration = std::get_if<WorkchainRegistrationReplayInput>(&input))
    return pack_possession_input<WorkchainRegistrationReplayInput,
        gen::UnoV2TransferInputV1::Record_uno_v2_registration_replay_v1>(*registration);
  return pack_possession_input<WorkchainClosureReplayInput,
      gen::UnoV2TransferInputV1::Record_uno_v2_closure_replay_v1>(std::get<WorkchainClosureReplayInput>(input));
}
inline td::Result<WorkchainReplayInput> decode_workchain_replay_input(const td::Ref<vm::Cell>& root) {
  using namespace confidential_input_detail;
  if (root.is_null()) return invalid("missing confidential replay input");
  bool special = false;
  auto slice = vm::load_cell_slice_special(root, special);
  if (special || slice.size() < 32) return invalid("invalid confidential replay tag");
  const auto tag = slice.prefetch_ulong(32);
  using Wire = gen::UnoV2TransferInputV1;
  if (tag == Wire::cons_tag[Wire::uno_v2_transfer_input_v1]) {
    TRY_RESULT(transfer, decode_workchain_transfer_input(root));
    return WorkchainReplayInput{std::move(transfer)};
  }
  if (tag == Wire::cons_tag[Wire::uno_v2_registration_replay_v1])
    return unpack_possession_input<WorkchainRegistrationReplayInput, Wire::Record_uno_v2_registration_replay_v1>(root);
  if (tag == Wire::cons_tag[Wire::uno_v2_closure_replay_v1])
    return unpack_possession_input<WorkchainClosureReplayInput, Wire::Record_uno_v2_closure_replay_v1>(root);
  return invalid("unknown confidential replay tag");
}
inline td::Status check_workchain_claimed_operation_id(const WorkchainReplayInput& input,
                                                       const td::Bits256& recomputed) {
  return std::visit([&](const auto& value) {
    if (value.claimed_operation_id != recomputed)
      return confidential_input_detail::invalid("claimed operationID mismatch");
    return td::Status::OK();
  }, input);
}

// Fixed 426-byte context encoding: operation constructor tag, context bits,
// subject bits, full address bits, protocol bits, rules bits, profiles bits.
// The host rebuilds every field from authenticated data before passing these
// bytes to the versioned Schnorr/DLEQ transcript. Never pass candidate claims
// directly to a proof verifier. Neither the claimed operationID nor authorization enters this encoding:
// proofs consume independently derived identities, so hashing proofs into those
// identities would create a cycle. The full block still commits every proof byte.
enum class WorkchainReplayOperation { Registration, Closure };
inline td::Result<std::string> encode_workchain_replay_context(
    const WorkchainReplayContext& value, WorkchainReplayOperation operation) {
  using namespace confidential_input_detail;
  using Wire = gen::UnoV2TransferInputV1;
  unsigned tag;
  switch (operation) {
    case WorkchainReplayOperation::Registration: tag = Wire::cons_tag[Wire::uno_v2_registration_replay_v1]; break;
    case WorkchainReplayOperation::Closure: tag = Wire::cons_tag[Wire::uno_v2_closure_replay_v1]; break;
    default: return invalid("unknown possession replay operation");
  }
  TRY_RESULT(root, pack_replay_context(value));
  TRY_RESULT(wire, unpack<gen::UnoV2ReplayContextV1::Record>(root));
  TRY_RESULT(subject, unpack<gen::UnoV2ReplaySubjectV1::Record>(wire.subject));
  td::Ref<vm::Cell> prefix = vm::CellBuilder().store_long(tag, 32).finalize();
  std::string out;
  for (const auto& cell : {prefix, root, wire.subject, subject.address, wire.protocol, wire.rules, wire.profiles}) {
    auto slice = vm::load_cell_slice(cell);
    if (slice.size() % 8) return invalid("non-byte-aligned replay context");
    std::string bytes(slice.size() / 8, '\0');
    if (!slice.fetch_bytes(td::MutableSlice(bytes))) return invalid("truncated replay context");
    out += bytes;
  }
  if (out.size() != 426) return invalid("fixed replay context size mismatch");
  return out;
}

inline td::Result<std::string> encode_workchain_replay_context(const WorkchainReplayInput& input) {
  if (const auto* registration = std::get_if<WorkchainRegistrationReplayInput>(&input))
    return encode_workchain_replay_context(registration->context, WorkchainReplayOperation::Registration);
  if (const auto* closure = std::get_if<WorkchainClosureReplayInput>(&input))
    return encode_workchain_replay_context(closure->context, WorkchainReplayOperation::Closure);
  return confidential_input_detail::invalid("transfer context requires independently rebuilt transfer binding");
}

struct WorkchainTransferContext {
  gen::UnoV2TransferProtocolV1::Record protocol;
  gen::UnoV2TransferRulesV1::Record rules;
  gen::UnoV2TransferProfilesV1::Record profiles;
  gen::UnoV2TransferBindingV1::Record binding;
  td::Bits256 fee_profile;
  std::uint32_t fee_effective_height;
};

// Exactly 427 bytes, fixed BE integers and byte arrays in TL-B declaration order:
// context's own bits, then protocol, rules, profiles, binding leaf bits (tags
// included). No BOC headers, optional fields, caller-selected generators or
// authorization arrays. The host independently builds binding from authenticated
// old balances/P/selected COMPLETE pending and semantic data. It must not hash
// unrelated pending receipts, nor accept candidate-provided context digests.
// Missing historical state remains LocalUnavailable at acquisition, not a codec
// CandidateInvalid. This encoder does not fetch state or change that provenance.
inline td::Result<std::string> encode_workchain_transfer_context(const WorkchainTransferContext& value) {
  using confidential_state_detail::pack;
  if (value.protocol.wire_version != 1) return td::Status::Error("unsupported transfer context wire version");
  TRY_RESULT(protocol, pack(value.protocol));
  TRY_RESULT(rules, pack(value.rules));
  TRY_RESULT(profiles, pack(value.profiles));
  TRY_RESULT(binding, pack(value.binding));
  TRY_RESULT(root, pack(gen::UnoV2TransferContextV1::Record{value.fee_profile, value.fee_effective_height,
                                                         protocol, rules, profiles, binding}));
  std::string out;
  for (const auto& cell : {root, protocol, rules, profiles, binding}) {
    auto slice = vm::load_cell_slice(cell);
    const auto size = slice.size() / 8;
    std::string bytes(size, '\0');
    if (slice.size() % 8 || !slice.fetch_bytes(td::MutableSlice(bytes))) {
      return td::Status::Error("unrepresentable fixed transfer context");
    }
    out += bytes;
  }
  if (out.size() != 427) return td::Status::Error("fixed transfer context size mismatch");
  return out;
}
}  // namespace block
