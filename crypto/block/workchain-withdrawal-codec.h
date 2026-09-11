#pragma once

#include "block/block-parse.h"
#include "block/workchain-confidential-input.h"
#include <limits>

namespace block {
// Explicit record inputs only. Encoding never authenticates identity, prices,
// state provenance or an Attempt sequence and never installs an obligation.
using WorkchainWithdrawalDestination = gen::UnoV2WithdrawalDestinationV1::Record;
using WorkchainWithdrawalAmounts = gen::UnoV2WithdrawalAmountsV1::Record;
using WorkchainWithdrawalCosts = gen::UnoV2WithdrawalCostsV1::Record;
using WorkchainWithdrawalTiming = gen::UnoV2WithdrawalTimingV1::Record;
struct WorkchainWithdrawalData {
  WorkchainTransferClaims claims;
  WorkchainWithdrawalDestination destination;
  WorkchainWithdrawalAmounts amounts;
  std::uint64_t attempt_sequence;
  WorkchainCiphertext available;
  td::Bits256 auxiliary;
};
struct WorkchainWithdrawalInput {
  td::Bits256 claimed_operation_id, claimed_attempt_id;
  WorkchainWithdrawalData data;
  WorkchainTransferAuthorization authorization;
};
struct WorkchainWithdrawalContext {
  WorkchainReplayContext common;
  gen::UnoV2TransferBindingV1::Record binding;
  td::Bits256 attempt_id;
  std::uint32_t settlement_blocks, withdrawal_limit;
};
struct WorkchainWithdrawalRecord {
  td::Bits256 withdrawal_id, attempt_id;
  std::uint64_t attempt_sequence, consumed_auth_nonce, principal;
  WorkchainConfidentialAddress source;
  WorkchainWithdrawalDestination destination;
  WorkchainWithdrawalCosts costs;
  WorkchainWithdrawalTiming timing;
};

namespace withdrawal_codec_detail {
inline td::Status error(td::Slice message) { return td::Status::Error(message); }
// No consensus classification here. A source-aware caller distinguishes an
// unavailable historical closure from malformed candidate input.
template <class F> auto protect(F&& f) -> decltype(f()) {
  try { return f(); }
  catch (const vm::VmError& e) { return e.as_status("withdrawal codec: "); }
  catch (const vm::VmVirtError& e) { return e.as_status("withdrawal acquisition: "); }
  catch (const vm::CellBuilder::CellCreateError&) { return error("withdrawal cell creation failed"); }
  catch (const vm::CellBuilder::CellWriteError&) { return error("withdrawal cell write failed"); }
}
template <class R> td::Result<R> unpack(const td::Ref<vm::Cell>& root) {
  R value;
  if (!resource_policy_detail::unpack_exact(root, value)) return error("malformed withdrawal record");
  return value;
}
using confidential_state_detail::pack;
inline td::Result<std::uint64_t> sum(std::uint64_t a, std::uint64_t b) {
  if (b > std::numeric_limits<std::uint64_t>::max() - a) return error("withdrawal u64 addition overflow");
  return a + b;
}
}

// D66: only the input-link sum is checked here. V_max and secret balance
// sufficiency remain properties of the existing proof, not extra codec gates.
inline td::Result<std::uint64_t> workchain_withdrawal_total(const WorkchainWithdrawalAmounts& value) {
  TRY_RESULT(part, withdrawal_codec_detail::sum(value.principal, value.outward_fee));
  return withdrawal_codec_detail::sum(part, value.return_reserve);
}
inline td::Result<td::Bits256> derive_workchain_withdrawal_id(
    const gen::UnoV2OperationNetworkV1::Record& network, const WorkchainConfidentialAddress& source,
    std::uint64_t consumed_nonce) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<td::Bits256> {
    using withdrawal_codec_detail::pack;
    TRY_RESULT(net, pack(network)); TRY_RESULT(address, pack(source));
    TRY_RESULT(root, pack(gen::UnoV2OperationIdentityV1::Record_uno_v2_withdrawal_identity_v1{
        5, consumed_nonce, net, address}));
    return root->get_hash().bits();
  });
}
// Section 7.3 independent sequence. The host supplies its authenticated value;
// this helper neither allocates it nor chooses its storage or initial value.
// No proof, future LT, resulting revision or current block hash enters either ID.
inline td::Result<td::Bits256> derive_workchain_attempt_id(const td::Bits256& withdrawal,
    std::uint64_t sequence) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<td::Bits256> {
    TRY_RESULT(root, withdrawal_codec_detail::pack(gen::UnoV2WithdrawalAttemptIdentityV1::Record{withdrawal, sequence}));
    return root->get_hash().bits();
  });
}

inline td::Result<td::Ref<vm::Cell>> encode_workchain_withdrawal_data(const WorkchainWithdrawalData& value) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<td::Ref<vm::Cell>> {
    using withdrawal_codec_detail::pack;
    TRY_RESULT(total, workchain_withdrawal_total(value.amounts)); (void)total;
    if (value.claims.authorized_fee != value.amounts.operation_fee)
      return withdrawal_codec_detail::error("withdrawal operation fee claims disagree");
    TRY_RESULT(claims, confidential_input_detail::pack_claims(value.claims));
    TRY_RESULT(destination, pack(value.destination)); TRY_RESULT(amounts, pack(value.amounts));
    TRY_RESULT(available, pack(value.available));
    return pack(gen::UnoV2WithdrawalDataV1::Record{value.attempt_sequence, value.auxiliary,
        claims, destination, amounts, available});
  });
}
inline td::Result<WorkchainWithdrawalData> decode_workchain_withdrawal_data(const td::Ref<vm::Cell>& root) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<WorkchainWithdrawalData> {
    using withdrawal_codec_detail::unpack;
    TRY_RESULT(wire, unpack<gen::UnoV2WithdrawalDataV1::Record>(root));
    TRY_RESULT(claims, confidential_input_detail::unpack_claims(wire.claims));
    TRY_RESULT(destination, unpack<WorkchainWithdrawalDestination>(wire.destination));
    TRY_RESULT(amounts, unpack<WorkchainWithdrawalAmounts>(wire.amounts));
    TRY_RESULT(available, unpack<WorkchainCiphertext>(wire.available));
    TRY_RESULT(total, workchain_withdrawal_total(amounts)); (void)total;
    if (claims.authorized_fee != amounts.operation_fee)
      return withdrawal_codec_detail::error("withdrawal operation fee claims disagree");
    return WorkchainWithdrawalData{claims, destination, amounts, wire.attempt_sequence, available, wire.auxiliary};
  });
}

inline td::Result<td::Ref<vm::Cell>> encode_workchain_withdrawal_input(const WorkchainWithdrawalInput& value) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<td::Ref<vm::Cell>> {
    const auto& auth = value.authorization;
    if (auth.commitments.size() != 8 || auth.responses.size() != 6 || auth.range_proof.size() != 864)
      return withdrawal_codec_detail::error("withdrawal authorization shape mismatch");
    TRY_RESULT(data, encode_workchain_withdrawal_data(value.data));
    std::string bytes;
    for (const auto& p : auth.commitments) confidential_input_detail::append_word(bytes, p);
    for (const auto& z : auth.responses) confidential_input_detail::append_word(bytes, z);
    bytes += auth.range_proof;
    TRY_RESULT(authorization, confidential_input_detail::encode_bytes(bytes, 1312));
    return withdrawal_codec_detail::pack(gen::UnoV2TransferInputV1::Record_uno_v2_withdrawal_input_v1{
        value.claimed_operation_id, value.claimed_attempt_id, data, authorization});
  });
}
inline td::Result<WorkchainWithdrawalInput> decode_workchain_withdrawal_input(const td::Ref<vm::Cell>& root) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<WorkchainWithdrawalInput> {
    TRY_RESULT(wire, withdrawal_codec_detail::unpack<gen::UnoV2TransferInputV1::Record_uno_v2_withdrawal_input_v1>(root));
    TRY_RESULT(data, decode_workchain_withdrawal_data(wire.data));
    TRY_RESULT(bytes, confidential_input_detail::decode_bytes(wire.authorization, 1312));
    td::Slice cursor(bytes);
    WorkchainTransferAuthorization auth;
    for (unsigned i = 0; i < 8; ++i) auth.commitments.push_back(confidential_input_detail::read_word(cursor));
    for (unsigned i = 0; i < 6; ++i) auth.responses.push_back(confidential_input_detail::read_word(cursor));
    auth.range_proof = cursor.str();
    return WorkchainWithdrawalInput{wire.claimed_operation_id, wire.claimed_attempt_id, std::move(data), std::move(auth)};
  });
}

// Fixed byte order: root bits, common root, subject, full address, protocol,
// rules, profiles, binding. All generated constructor tags are included once.
// HOST-REBUILT bytes only; claimed wire values are never authentication.
inline td::Result<std::string> encode_workchain_withdrawal_context(const WorkchainWithdrawalContext& value) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<std::string> {
    using withdrawal_codec_detail::pack; using withdrawal_codec_detail::unpack;
    TRY_RESULT(common, confidential_input_detail::pack_replay_context(value.common));
    TRY_RESULT(binding, pack(value.binding));
    TRY_RESULT(root, pack(gen::UnoV2WithdrawalContextV1::Record{value.attempt_id,
        value.settlement_blocks, value.withdrawal_limit, common, binding}));
    TRY_RESULT(c, unpack<gen::UnoV2ReplayContextV1::Record>(common));
    TRY_RESULT(subject, unpack<gen::UnoV2ReplaySubjectV1::Record>(c.subject));
    std::string bytes;
    for (const auto& cell : {root, common, c.subject, subject.address, c.protocol, c.rules, c.profiles, binding}) {
      bool special = false;
      auto slice = vm::load_cell_slice_special(cell, special);
      if (special || slice.size() % 8) return withdrawal_codec_detail::error("invalid withdrawal context cell");
      std::string part(slice.size() / 8, '\0');
      if (!slice.fetch_bytes(td::MutableSlice(part))) return withdrawal_codec_detail::error("truncated withdrawal context");
      bytes += part;
    }
    if (bytes.size() != 566) return withdrawal_codec_detail::error("withdrawal context size mismatch");
    return bytes;
  });
}

inline td::Status check_workchain_withdrawal_record(const WorkchainWithdrawalRecord& value) {
  using namespace withdrawal_codec_detail;
  TRY_RESULT(remaining_sum, sum(value.costs.consumed_return_cost, value.costs.refundable_reserve));
  if (remaining_sum != value.costs.original_reserve) return error("withdrawal reserve reconciliation mismatch");
  TRY_RESULT(total, workchain_withdrawal_total({value.principal, value.costs.outward_fee_paid,
      value.costs.original_reserve, 0})); (void)total;
  // Zero here denotes no protocol-income component in W, not a fee default.
  const auto& t = value.timing;
  if (t.phase > 1 || (t.phase == 0 && t.queue_removed_height != 0) ||
      (t.phase == 1 && t.queue_removed_height < t.opened_height))
    return error("withdrawal phase/queue height mismatch");
  if (t.phase == 1 && t.settlement_blocks > UINT32_MAX - t.queue_removed_height)
    return error("withdrawal settlement height overflow");
  return td::Status::OK();
}
inline td::Result<td::Ref<vm::Cell>> encode_workchain_withdrawal_record(const WorkchainWithdrawalRecord& value) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<td::Ref<vm::Cell>> {
    using withdrawal_codec_detail::pack;
    TRY_STATUS(check_workchain_withdrawal_record(value));
    TRY_RESULT(source, pack(value.source)); TRY_RESULT(destination, pack(value.destination));
    TRY_RESULT(costs, pack(value.costs)); TRY_RESULT(timing, pack(value.timing));
    return pack(gen::UnoV2WithdrawalRecordV1::Record{value.withdrawal_id, value.attempt_id,
        value.attempt_sequence, value.consumed_auth_nonce, value.principal, source, destination, costs, timing});
  });
}
inline td::Result<WorkchainWithdrawalRecord> decode_workchain_withdrawal_record(const td::Ref<vm::Cell>& root) {
  return withdrawal_codec_detail::protect([&]() -> td::Result<WorkchainWithdrawalRecord> {
    using withdrawal_codec_detail::unpack;
    TRY_RESULT(wire, unpack<gen::UnoV2WithdrawalRecordV1::Record>(root));
    TRY_RESULT(source, unpack<WorkchainConfidentialAddress>(wire.source));
    TRY_RESULT(destination, unpack<WorkchainWithdrawalDestination>(wire.destination));
    TRY_RESULT(costs, unpack<WorkchainWithdrawalCosts>(wire.costs));
    TRY_RESULT(timing, unpack<WorkchainWithdrawalTiming>(wire.timing));
    WorkchainWithdrawalRecord result{wire.withdrawal_id, wire.attempt_id, wire.attempt_sequence,
        wire.consumed_auth_nonce, wire.principal, source, destination, costs, timing};
    TRY_STATUS(check_workchain_withdrawal_record(result));
    return result;
  });
}
}  // namespace block
