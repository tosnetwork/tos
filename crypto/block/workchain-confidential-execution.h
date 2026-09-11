#pragma once

#include <array>
#include <optional>

#include "block/workchain-confidential-transition.h"
#include "block/workchain-proof-work.h"
#include "block/workchain-transfer-statement.h"
#include "vm/excno.hpp"

namespace block {

// Mandatory, host-resolved historical configuration. No field is a candidate
// claim or local default. execution_fee is the independently evaluated tariff
// for this operation (including selected count for COLLECT), not a fee ceiling.
struct WorkchainTransferEnvironment {
  UnoCryptoLimits limits;
  std::array<unsigned char, 80> domain;
  gen::UnoV2TransferProtocolV1::Record protocol;
  gen::UnoV2TransferRulesV1::Record rules;
  gen::UnoV2TransferProfilesV1::Record profiles;
  td::Bits256 fee_profile;
  std::uint32_t fee_effective_height, height;
  std::uint64_t execution_fee, pending_capacity;
  std::uint16_t account_schema, relation_profile, proof_profile;
};

// A verified absence is nullopt; inability to obtain a historical account is
// Error. Do not pass decoded candidate state as authenticated historical state.
using WorkchainHistoricalConfidentialAccount = td::Result<std::optional<WorkchainConfidentialAccount>>;

struct WorkchainPreparedTransferStatement {
  td::Bits256 operation_id;
  std::string context;
  std::vector<std::array<unsigned char, 32>> points, receipt_ids;
};
struct WorkchainConfidentialTransferResult {
  td::Bits256 operation_id;
  td::Ref<vm::Cell> source_data;
  td::Ref<vm::Cell> destination_data;  // Distinct-recipient SEND only.
};

namespace confidential_execution_detail {
inline td::Status invalid(td::Slice message) {
  return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid), message);
}
inline td::Status local(td::Slice message) {
  return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable), message);
}
inline bool same_address(const WorkchainConfidentialAddress& a, const WorkchainConfidentialAddress& b) {
  return a.workchain_id == b.workchain_id && a.account == b.account && a.instance == b.instance;
}
inline bool matches_policy(const WorkchainConfidentialAccount& a, const WorkchainTransferEnvironment& e) {
  return a.global_id == e.protocol.global_id && a.genesis_hash == e.protocol.genesis_hash &&
         a.address.workchain_id == e.protocol.workchain_id && a.bindings.asset == e.rules.asset &&
         a.bindings.custody == e.rules.custody && a.bindings.policy == e.rules.policy &&
         a.schema_version == e.account_schema && a.relation_profile == e.relation_profile &&
         a.proof_profile == e.proof_profile;
}
inline std::array<unsigned char, 32> word(const td::Bits256& b) {
  std::array<unsigned char, 32> out;
  std::copy(b.as_slice().begin(), b.as_slice().end(), out.begin());
  return out;
}
inline gen::UnoV2OperationNetworkV1::Record network(const WorkchainTransferEnvironment& e) {
  return {e.protocol.global_id, e.protocol.genesis_hash, e.protocol.workchain_instance};
}
}  // namespace confidential_execution_detail

// Read-only preparation also serves wallet statement construction. It grants no
// execution authority; execute below always calls the real metered verifier.
inline td::Result<WorkchainPreparedTransferStatement> prepare_workchain_transfer_statement(
    const WorkchainTransferEnvironment& env, const WorkchainTransferInput& input,
    const WorkchainHistoricalConfidentialAccount& source, const WorkchainHistoricalConfidentialAccount& destination) {
  using namespace confidential_execution_detail;
  if (source.is_error())
    return local("historical source account unavailable");
  if (!source.ok())
    return invalid("source confidential account does not exist");
  const auto& a = *source.ok();
  if (encode_workchain_confidential_account(a).is_error())
    return local("malformed authenticated source state");
  const auto& claims = workchain_transfer_claims(input.data);
  const unsigned kind = workchain_transfer_kind(input.data);
  if (env.protocol.kind != kind || env.protocol.workchain_id != 2 || env.pending_capacity != 16 ||
      env.limits.max_collect == 0 || env.limits.max_collect > env.pending_capacity) {
    return local("unsupported authenticated transfer configuration");
  }
  if (!matches_policy(a, env) || !same_address(a.address, claims.source) || a.key_epoch != claims.key_epoch) {
    return invalid("source identity or key epoch mismatch");
  }
  if (env.height > claims.expiry_height)
    return invalid("confidential operation expired");
  if (claims.authorized_fee != env.execution_fee)
    return invalid("operation fee differs from authenticated tariff");
  // This is candidate validation, not proposer selection/defer logic (D28).
  TRY_RESULT(next, next_workchain_confidential_counters(a, claims.auth_nonce, claims.available_revision));
  (void)next;
  if (!std::holds_alternative<WorkchainAccountActive>(a.lifecycle) &&
      !(kind == 2 && std::holds_alternative<WorkchainAccountReadOnly>(a.lifecycle))) {
    return invalid("source lifecycle forbids operation");
  }
  TRY_RESULT(id, derive_workchain_operation_id(network(env), a.address, kind, a.auth_nonce));
  TRY_STATUS(check_workchain_claimed_operation_id(input, id));
  WorkchainPreparedTransferStatement result{id, {}, {}, {}};
  WorkchainTransferOldStatement old{a.public_key,         a.available,         a.key_epoch, a.auth_nonce,
                                    a.available_revision, td::Bits256::zero(), 0,           {}};
  auto add = [&](const td::Bits256& b) { result.points.push_back(word(b)); };
  if (kind == 1) {
    if (destination.is_error())
      return local("historical destination account unavailable");
    if (!destination.ok())
      return invalid("destination confidential account does not exist");
    const auto& b = *destination.ok();
    if (encode_workchain_confidential_account(b).is_error())
      return local("malformed authenticated destination state");
    const auto& send = std::get<WorkchainSendData>(input.data);
    if (!matches_policy(b, env) || !same_address(b.address, send.destination) ||
        b.key_epoch != send.destination_key_epoch || !std::holds_alternative<WorkchainAccountActive>(b.lifecycle)) {
      return invalid("destination registration or lifecycle mismatch");
    }
    if (a.address.account == b.address.account &&
        encode_workchain_confidential_account(a).move_as_ok()->get_hash() !=
            encode_workchain_confidential_account(b).move_as_ok()->get_hash()) {
      return local("inconsistent authenticated self-SEND snapshots");
    }
    TRY_STATUS(check_workchain_pending_capacity(b, env.pending_capacity));
    old.destination_public_key = b.public_key;
    old.destination_key_epoch = b.key_epoch;
    add(a.public_key);
    add(b.public_key);
    add(a.available.commitment);
    add(a.available.handle);
    add(send.available.commitment);
    add(send.available.handle);
    add(send.transfer.commitment);
    add(send.transfer.sender_handle);
    add(send.transfer.recipient_handle);
    add(send.auxiliary);
  } else {
    const auto& collect = std::get<WorkchainCollectData>(input.data);
    if (collect.selected.empty() || collect.selected.size() > env.limits.max_collect)
      return invalid("COLLECT count exceeds policy");
    add(a.public_key);
    add(a.available.commitment);
    add(a.available.handle);
    add(collect.available.commitment);
    add(collect.available.handle);
    add(collect.auxiliary_old);
    for (const auto& selected : collect.selected) {
      auto it = std::find_if(a.pending.begin(), a.pending.end(),
                             [&](const auto& r) { return r.receipt_id == selected.receipt_id; });
      if (it == a.pending.end())
        return invalid("selected pending receipt does not exist");
      if (it->status != 0 || it->target_instance != a.address.instance || it->target_key_epoch != a.key_epoch ||
          it->asset != a.bindings.asset || it->source.workchain_id != env.protocol.workchain_id) {
        return invalid("pending consumption, ownership or source domain mismatch");
      }
      // The complete receipt comes from authenticated historical account state,
      // whose admission authenticated the source SEND. Recheck its identity and
      // origin binding; candidate-supplied receipt bodies are never consulted.
      TRY_RESULT(origin, derive_workchain_operation_id(network(env), it->source, 1, it->source_operation_nonce));
      TRY_RESULT(receipt_id, derive_workchain_receipt_id(it->source.instance, origin, it->output_index));
      if (origin != it->operation_id || receipt_id != it->receipt_id)
        return invalid("pending source identity mismatch");
      old.selected.push_back(*it);
      result.receipt_ids.push_back(word(it->receipt_id));
      add(it->ciphertext.commitment);
      add(it->ciphertext.handle);
      add(selected.auxiliary);
    }
    // relation.rs prepare (line 64) checks selected-ID order and distinctness.
    // Do not repeat it here. Existence alone above is not source authentication:
    // historical-state acquisition and all four receipt checks remain mandatory.
  }
  TRY_RESULT(semantic, workchain_transfer_txid(input.data));
  TRY_RESULT(statement, hash_workchain_transfer_old_statement(kind, old));
  WorkchainTransferContext context{
      env.protocol, env.rules, env.profiles, {id, semantic, statement}, env.fee_profile, env.fee_effective_height};
  TRY_RESULT(bytes, encode_workchain_transfer_context(context));
  result.context = std::move(bytes);
  return result;
}

inline td::Result<WorkchainConfidentialTransferResult> execute_workchain_confidential_transfer(
    const WorkchainTransferEnvironment& env, const WorkchainTransferInput& input,
    const WorkchainHistoricalConfidentialAccount& source, const WorkchainHistoricalConfidentialAccount& destination,
    WorkchainProofVerifier& verifier) {
  using namespace confidential_execution_detail;
  try {
    TRY_RESULT(statement, prepare_workchain_transfer_statement(env, input, source, destination));
    TRY_RESULT(shape, confidential_input_detail::shape(input.data));
    const auto& auth = input.authorization;
    if (auth.commitments.size() != shape.commitments || auth.responses.size() != shape.responses ||
        auth.range_proof.size() != shape.range)
      return invalid("confidential authorization shape mismatch");
    std::vector<std::array<unsigned char, 32>> commitments, responses;
    for (const auto& b : auth.commitments)
      commitments.push_back(word(b));
    for (const auto& b : auth.responses)
      responses.push_back(word(b));
    UnoCryptoVerifyRequestV2 request{};
    request.abi_version = 2;
    request.relation = workchain_transfer_kind(input.data);
    request.limits = env.limits;
    std::copy(env.domain.begin(), env.domain.end(), request.domain);
    request.fee = env.execution_fee;
    request.context = reinterpret_cast<const unsigned char*>(statement.context.data());
    request.context_bytes = statement.context.size();
    request.points = reinterpret_cast<const unsigned char (*)[32]>(statement.points.data());
    request.point_count = statement.points.size();
    request.receipt_ids = reinterpret_cast<const unsigned char (*)[32]>(statement.receipt_ids.data());
    request.receipt_count = statement.receipt_ids.size();
    request.commitments = reinterpret_cast<const unsigned char (*)[32]>(commitments.data());
    request.commitment_count = commitments.size();
    request.responses = reinterpret_cast<const unsigned char (*)[32]>(responses.data());
    request.response_count = responses.size();
    request.proof = reinterpret_cast<const unsigned char*>(auth.range_proof.data());
    request.proof_bytes = auth.range_proof.size();
    TRY_STATUS(verifier.verify(request));
    const auto& a = *source.ok();
    auto updated = a;
    TRY_RESULT(counters, next_workchain_confidential_counters(a, a.auth_nonce, a.available_revision));
    updated.auth_nonce = counters.auth_nonce;
    updated.available_revision = counters.available_revision;
    if (updated.auth_nonce == UINT64_MAX)
      updated.lifecycle = WorkchainAccountReadOnly{};
    td::Ref<vm::Cell> destination_data;
    if (const auto* send = std::get_if<WorkchainSendData>(&input.data)) {
      auto target = *destination.ok();
      // Same immutable target snapshot was checked for capacity above. There is
      // no callback or external write between check and insertion. Only one
      // complete result is returned after BOTH accounts have encoded successfully.
      updated.available = send->available;
      TRY_RESULT(receipt_id, derive_workchain_receipt_id(a.address.instance, statement.operation_id, 0));
      if (std::any_of(target.pending.begin(), target.pending.end(),
                      [&](const auto& r) { return r.receipt_id == receipt_id; })) {
        return invalid("SEND receipt already present");
      }
      target.pending.push_back({receipt_id,
                                a.address,
                                a.auth_nonce,
                                target.address.instance,
                                target.key_epoch,
                                a.bindings.asset,
                                {send->transfer.commitment, send->transfer.recipient_handle},
                                statement.operation_id,
                                0,
                                0});
      if (a.address.account == target.address.account) {
        updated.pending = std::move(target.pending);
      } else {
        auto encoded = encode_workchain_confidential_account(target);
        if (encoded.is_error())
          return local("cannot encode SEND destination transition");
        destination_data = encoded.move_as_ok();
      }
    } else {
      const auto& collect = std::get<WorkchainCollectData>(input.data);
      updated.available = collect.available;
      // Kernel has now accepted strict unique selected IDs. Erase precisely
      // these entries; unselected complete receipts and their ciphertexts remain.
      updated.pending.erase(
          std::remove_if(updated.pending.begin(), updated.pending.end(),
                         [&](const auto& receipt) {
                           return std::any_of(collect.selected.begin(), collect.selected.end(),
                                              [&](const auto& item) { return item.receipt_id == receipt.receipt_id; });
                         }),
          updated.pending.end());
    }
    auto encoded_source = encode_workchain_confidential_account(updated);
    if (encoded_source.is_error())
      return local("cannot encode confidential source transition");
    return WorkchainConfidentialTransferResult{statement.operation_id, encoded_source.move_as_ok(),
                                               std::move(destination_data)};
  } catch (const vm::CellBuilder::CellCreateError&) {
    return local("transfer allocation failure");
  } catch (const vm::CellBuilder::CellWriteError&) {
    return local("transfer construction failure");
  } catch (const std::bad_alloc&) {
    return local("transfer allocation failure");
  } catch (const vm::VmError&) {
    return local("transfer historical data or construction unavailable");
  } catch (const vm::VmVirtError&) {
    return local("transfer historical data unavailable");
  }
}
}  // namespace block
