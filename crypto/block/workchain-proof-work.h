#pragma once

#include "block/workchain-execution-errors.h"
#include "uno/crypto/include/uno_crypto.h"
#include <cstdint>
#include <initializer_list>
#include <limits>

namespace block {

inline td::Result<std::uint64_t> proof_count_sum(std::initializer_list<std::uint64_t> parts) {
  std::uint64_t result = 0;
  for (auto part : parts) {
    if (part > std::numeric_limits<std::uint64_t>::max() - result) {
      return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                               "proof operation count overflow");
    }
    result += part;
  }
  return result;
}

inline td::Result<std::uint64_t> proof_count_product(std::uint64_t a, std::uint64_t b) {
  if (a && b > std::numeric_limits<std::uint64_t>::max() / a) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                             "proof operation count product overflow");
  }
  return a * b;
}

// Profile 4 counts operations at the verifier's public algorithm boundary,
// not CPU instructions, elapsed time or fee units. These named components
// remain visible so a backend trace can check more than a coincidental total.
// Counts reserve the full verification path; early rejection does not refund.
struct WorkchainProofOperations {
  std::uint64_t msm_terms{0}, scalar_multiplications{0}, generated_points{0};
  std::uint64_t decoded_points{0}, encoded_points{0};
  std::uint64_t range_rounds{0}, sigma_equations{0}, sigma_witnesses{0};
  std::uint64_t context_bytes{0};

  td::Result<std::uint64_t> total() const {
    return proof_count_sum({msm_terms, scalar_multiplications, generated_points,
                            decoded_points, encoded_points, range_rounds,
                            sigma_equations, sigma_witnesses, context_bytes});
  }
};

inline td::Result<WorkchainProofOperations> workchain_proof_operations_v4(
    const UnoCryptoVerifyRequestV2& request) {
  auto invalid = []() {
    // The request is assembled by the local engine. Candidate shape rejection
    // belongs to its earlier decoder; an inconsistent backend request is not
    // independent evidence that the candidate is invalid.
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                             "inconsistent local verification request shape");
  };
  if (request.abi_version != UNO_BALANCE_ABI_VERSION || request.receipt_count > 64) return invalid();
  // These conditions can otherwise produce DECODE inside the ABI even when
  // the failure is a locally assembled policy/context mismatch. Establish them
  // here before interpreting any backend DECODE as candidate data failure.
  const auto& limits = request.limits;
  if (!limits.max_value || limits.max_value > limits.max_balance ||
      !limits.max_collect || limits.max_collect > 64 || !limits.max_context_bytes ||
      !limits.max_proof_bytes || request.receipt_count > limits.max_collect ||
      !request.context_bytes || request.context_bytes > limits.max_context_bytes ||
      request.proof_bytes > limits.max_proof_bytes) return invalid();
  std::uint64_t points, equations, witnesses, padded;
  if (request.relation == UNO_RELATION_SEND && request.receipt_count == 0) {
    points = 10; equations = 8; witnesses = 6; padded = 8;
  } else if (request.relation == UNO_RELATION_COLLECT && request.receipt_count != 0) {
    TRY_RESULT(triple, proof_count_product(3, request.receipt_count));
    TRY_RESULT(twice, proof_count_product(2, request.receipt_count));
    TRY_RESULT(q, proof_count_sum({triple, 6}));
    TRY_RESULT(e, proof_count_sum({twice, 5}));
    TRY_RESULT(w, proof_count_sum({twice, 4}));
    points = q; equations = e; witnesses = w;
    padded = 1;
    while (padded < witnesses) {
      TRY_RESULT(next, proof_count_product(padded, 2));
      padded = next;
    }
  } else {
    return invalid();
  }
  TRY_RESULT(n, proof_count_product(64, padded));
  std::uint64_t rounds = 0;
  for (auto size = n; size > 1; size /= 2) ++rounds;
  TRY_RESULT(twice_rounds, proof_count_product(2, rounds));
  TRY_RESULT(proof_words, proof_count_sum({twice_rounds, 9}));
  TRY_RESULT(proof_bytes, proof_count_product(proof_words, 32));
  if (request.point_count != points || request.commitment_count != equations ||
      request.response_count != witnesses || request.proof_bytes != proof_bytes) return invalid();
  WorkchainProofOperations result;
  // Dense Sigma rows plus the TWO independent range MSMs, including both
  // fixed bases in each range equation. Identity coefficients still occupy
  // backend MSM terms; no sparsity discount is inferred from their values.
  TRY_RESULT(sigma_terms, proof_count_product(equations, witnesses));
  TRY_RESULT(twice_n, proof_count_product(2, n));
  TRY_RESULT(ip_terms, proof_count_sum({twice_n, twice_rounds, 4}));
  TRY_RESULT(poly_terms, proof_count_sum({padded, 4}));
  TRY_RESULT(msm_terms, proof_count_sum({sigma_terms, ip_terms, poly_terms}));
  result.msm_terms = msm_terms;
  TRY_RESULT(multiplications, proof_count_sum({equations, 3}));
  result.scalar_multiplications = multiplications;
  // The current verifier reconstructs G/H on every invocation and constructs
  // the Pedersen blinding base twice. This is not a cached-generator profile.
  TRY_RESULT(generated, proof_count_sum({twice_n, 2}));
  result.generated_points = generated;
  TRY_RESULT(decoded, proof_count_sum({points, equations, twice_rounds, 4, padded}));
  result.decoded_points = decoded;
  result.encoded_points = padded;
  result.range_rounds = rounds;
  result.sigma_equations = equations;
  result.sigma_witnesses = witnesses;
  // Each byte supplied to the variable-length context absorption is one
  // operation at that interface. Not a time estimate or a permutation weight.
  result.context_bytes = request.context_bytes;
  return result;
}

inline constexpr char kWorkchainWithdrawalStatementDomainV2[] = "uno-v2/withdrawal-statement/v2";

// A typed boundary, not an arbitrary Status whose name determines provenance.
inline td::Result<WorkchainProofOperations> workchain_proof_operations_v4(
    const UnoCryptoWithdrawalVerifyRequestV2& request) {
  if (request.abi_version != 2 || request.context_bytes != 566)
    return td::Status::Error(-7201, "inconsistent Withdrawal verification shape");
  UnoCryptoVerifyRequestV2 send{};
  send.abi_version = 2; send.relation = UNO_RELATION_SEND; send.limits = request.limits;
  // D78: Rust statement tag + two IDs + three u64 fields. The independent
  // canonical host context remains 566 bytes; f stays separate from T=x+q.
  send.context_bytes = (sizeof(kWorkchainWithdrawalStatementDomainV2) - 1) + 64 + 3 * sizeof(std::uint64_t) + 566;
  send.point_count = 10; send.commitment_count = request.commitment_count;
  send.response_count = request.response_count; send.proof_bytes = request.proof_bytes;
  TRY_RESULT(work, workchain_proof_operations_v4(send));
  // Existing constructor additionally derives the opening/points and calls
  // relation::prepare once before verify calls prepare again. Count both;
  // these are proof-work units, NEVER Withdrawal's one billing unit.
  work.scalar_multiplications += 6;
  work.generated_points += 2;
  work.decoded_points += 12;
  work.encoded_points += 10;
  work.context_bytes += send.context_bytes;
  return work;
}

enum class WorkchainProofVerdict { Valid, InvalidProof, LocalContractFailure, BackendUnavailable };

// Fixed-shape v2 possession verification, in the existing v4 operation basis.
// Unlike SEND/COLLECT, no admitted k or range-object size changes this work.
// key_possession.rs::verify: decompress P/R; z*P and c*H; one PedersenGens
// construction; one Sigma equation/witness. No MSM or point compression.
// closure_possession.rs::verify/challenge: decompress P/D/C/R1/R2; four scalar
// multiplications; construct H twice (challenge and equation), compress H once;
// two equations sharing one witness. Reserve the full path despite early exits.
// context_bytes uses the SAME v4 convention as relations: canonical context
// absorption only (426), not fixed domain/other transcript fields or hash rounds.
inline WorkchainProofOperations workchain_registration_operations_v4() {
  return {0, 2, 1, 2, 0, 0, 1, 1, UNO_POSSESSION_CONTEXT_BYTES};
}
inline WorkchainProofOperations workchain_closure_operations_v4() {
  return {0, 4, 2, 5, 1, 0, 2, 1, UNO_POSSESSION_CONTEXT_BYTES};
}

inline td::Result<WorkchainProofOperations> workchain_proof_operations_v4(
    const UnoCryptoKeyPossessionRequestV2& request) {
  if (request.abi_version != 2) return td::Status::Error(-7201, "registration verification ABI mismatch");
  return workchain_registration_operations_v4();
}
inline td::Result<WorkchainProofOperations> workchain_proof_operations_v4(
    const UnoCryptoClosurePossessionRequestV2& request) {
  if (request.abi_version != 2) return td::Status::Error(-7201, "closure verification ABI mismatch");
  return workchain_closure_operations_v4();
}

// system_encryption.rs::encrypt_encoded/finish: one point decode, three
// scalar multiplications, one Pedersen blinding-base construction, two point
// encodings. Verification reconstructs exactly the same ciphertext and compares
// bytes, not another curve equation. As for the other v4 families, fixed
// transcript fields are not variable context absorption or hash-round units.
inline WorkchainProofOperations workchain_system_operations_v4() {
  return {0, 3, 1, 1, 2, 0, 0, 0, 0};
}
inline td::Result<WorkchainProofOperations> workchain_proof_operations_v4(
    const UnoCryptoSystemEncryptionRequest& request) {
  if (request.abi_version != UNO_CRYPTO_ABI_VERSION || !request.amount) {
    return td::Status::Error(-7201, "inconsistent local system encryption request");
  }
  return workchain_system_operations_v4();
}

inline td::Result<WorkchainProofOperations> workchain_proof_operations_v4(
    const UnoCryptoSystemEncryptionRequestV2& request) {
  if (request.abi_version != 2 || !request.amount ||
      (request.origin_bytes != 41 && request.origin_bytes != 115)) {
    return td::Status::Error(-7201, "inconsistent local system origin encryption request");
  }
  const bool short_origin = request.origin_bytes == 41 && request.origin[0] <= 1;
  const bool sweep_origin = request.origin_bytes == 115 && request.origin[0] == 2 &&
                            (request.origin[114] & 0x7f) == 0;
  if (!short_origin && !sweep_origin)
    return td::Status::Error(-7201, "inconsistent local system origin framing");
  for (std::size_t i = request.origin_bytes; i < sizeof(request.origin); ++i) {
    if (request.origin[i] != 0)
      return td::Status::Error(-7201, "nonzero local system origin tail");
  }
  // D72: fixed transcript per authenticated event kind, not variable context.
  // Keep each profile independent even while all three have equal curve work.
  switch (request.origin[0]) {
    case 0: return WorkchainProofOperations{0, 3, 1, 1, 2, 0, 0, 0, 0};  // Deposit
    case 1: return WorkchainProofOperations{0, 3, 1, 1, 2, 0, 0, 0, 0};  // Settlement
    case 2: return WorkchainProofOperations{0, 3, 1, 1, 2, 0, 0, 0, 0};  // Sweep
  }
  return td::Status::Error(-7201, "unknown local system origin kind");
}

class WorkchainProofVerifier {
 public:
  WorkchainProofVerifier(const WorkchainProofVerifier&) = delete;
  WorkchainProofVerifier& operator=(const WorkchainProofVerifier&) = delete;
  WorkchainProofVerifier(WorkchainProofVerifier&&) = delete;
  WorkchainProofVerifier& operator=(WorkchainProofVerifier&&) = delete;

  td::Status verify(const UnoCryptoVerifyRequestV2& request) {
    return verify_request(request, "cryptographic proof rejected");
  }
  td::Status verify(const UnoCryptoWithdrawalVerifyRequestV2& request) {
    return verify_request(request, "Withdrawal cryptographic proof rejected");
  }
  td::Status verify(const UnoCryptoKeyPossessionRequestV2& request) {
    return verify_request(request, "invalid registration key possession proof");
  }
  td::Status verify(const UnoCryptoClosurePossessionRequestV2& request) {
    return verify_request(request, "invalid closure zero-balance possession proof");
  }
  td::Status status() const { return failure_.clone(); }
  // Request must be independently rebuilt from authenticated ingress/state.
  // A result is published only on success; neither operation authorizes credit.
  td::Result<UnoCryptoSystemCiphertext> system_encrypt(const UnoCryptoSystemEncryptionRequest& request) {
    UnoCryptoSystemCiphertext result{};
    TRY_STATUS(attempt(request, "system ciphertext construction failed",
                       [&] { return run_system_backend(request, result); }));
    return result;
  }
  td::Status verify(const UnoCryptoSystemEncryptionRequest& request,
                    const UnoCryptoSystemCiphertext& supplied) {
    return attempt(request, "system ciphertext differs from authenticated derivation",
                   [&] { return run_system_verify_backend(request, supplied); });
  }
  std::uint64_t consumed() const { return consumed_; }
  td::Result<UnoCryptoSystemCiphertext> system_encrypt(const UnoCryptoSystemEncryptionRequestV2& request) {
    UnoCryptoSystemCiphertext result{};
    TRY_STATUS(attempt(request, "system ciphertext construction failed",
                       [&] { return run_system_backend(request, result); }));
    return result;
  }
  td::Status verify(const UnoCryptoSystemEncryptionRequestV2& request,
                    const UnoCryptoSystemCiphertext& supplied) {
    return attempt(request, "system ciphertext differs from authenticated derivation",
                   [&] { return run_system_verify_backend(request, supplied); });
  }
 private:
  // Every request family uses this one precharge and sticky failure path.
  // No public raw backend entry or unmetered possession overload exists.
  template <class Request>
  td::Status verify_request(const Request& request, td::Slice invalid_message) {
    return attempt(request, invalid_message, [&] { return run_backend(request); });
  }
  template <class Request, class Backend>
  td::Status attempt(const Request& request, td::Slice invalid_message, Backend&& backend) {
    if (failure_.is_error()) return failure_.clone();
    auto operations = workchain_proof_operations_v4(request);
    if (operations.is_error()) return fail(operations.move_as_error());
    auto units = operations.ok().total();
    if (units.is_error()) return fail(units.move_as_error());
    // consumed_ <= declared_ is maintained here: only a successful precharge
    // changes consumed_, and no decrement or refund operation exists.
    if (units.ok() > declared_ - consumed_) {
      return fail(td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                                    "engine underestimated attempted verification work"));
    }
    consumed_ += units.ok();
    // The only expensive backend boundary. Failed proofs consume the same
    // reservation; an engine ignoring this Result cannot erase sticky failure.
    switch (backend()) {
      case WorkchainProofVerdict::Valid: return td::Status::OK();
      case WorkchainProofVerdict::InvalidProof:
        return fail(td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                                      invalid_message));
      case WorkchainProofVerdict::LocalContractFailure:
      case WorkchainProofVerdict::BackendUnavailable:
        return fail(td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                                      "verification backend unavailable or contract failure"));
    }
    return fail(td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                                  "unknown typed verification verdict"));
  }
  friend class ProofAdmittedBatchInput;
  friend struct WorkchainProofTestAccess;
  explicit WorkchainProofVerifier(std::uint64_t declared) : declared_(declared) {}
  static WorkchainProofVerdict run_backend(const UnoCryptoVerifyRequestV2& request);
  static WorkchainProofVerdict run_backend(const UnoCryptoWithdrawalVerifyRequestV2& request);
  static WorkchainProofVerdict run_backend(const UnoCryptoKeyPossessionRequestV2& request);
  static WorkchainProofVerdict run_backend(const UnoCryptoClosurePossessionRequestV2& request);
  static WorkchainProofVerdict run_system_backend(const UnoCryptoSystemEncryptionRequest& request,
                                                 UnoCryptoSystemCiphertext& output);
  static WorkchainProofVerdict run_system_verify_backend(const UnoCryptoSystemEncryptionRequest& request,
                                                        const UnoCryptoSystemCiphertext& supplied);
  td::Status fail(td::Status error) { failure_ = std::move(error); return failure_.clone(); }
  static WorkchainProofVerdict run_system_backend(const UnoCryptoSystemEncryptionRequestV2& request,
                                                 UnoCryptoSystemCiphertext& output);
  static WorkchainProofVerdict run_system_verify_backend(const UnoCryptoSystemEncryptionRequestV2& request,
                                                        const UnoCryptoSystemCiphertext& supplied);
  const std::uint64_t declared_;
  std::uint64_t consumed_{0};
  td::Status failure_;
};

}  // namespace block
