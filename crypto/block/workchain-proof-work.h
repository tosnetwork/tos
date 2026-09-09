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

// A typed boundary, not an arbitrary Status whose name determines provenance.
enum class WorkchainProofVerdict { Valid, InvalidProof, LocalContractFailure, BackendUnavailable };

class WorkchainProofVerifier {
 public:
  WorkchainProofVerifier(const WorkchainProofVerifier&) = delete;
  WorkchainProofVerifier& operator=(const WorkchainProofVerifier&) = delete;
  WorkchainProofVerifier(WorkchainProofVerifier&&) = delete;
  WorkchainProofVerifier& operator=(WorkchainProofVerifier&&) = delete;

  td::Status verify(const UnoCryptoVerifyRequestV2& request) {
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
    switch (run_backend(request)) {
      case WorkchainProofVerdict::Valid: return td::Status::OK();
      case WorkchainProofVerdict::InvalidProof:
        return fail(td::Status::Error(static_cast<int>(WorkchainExecutionFailure::CandidateInvalid),
                                      "cryptographic proof rejected"));
      case WorkchainProofVerdict::LocalContractFailure:
      case WorkchainProofVerdict::BackendUnavailable:
        return fail(td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                                      "verification backend unavailable or contract failure"));
    }
    return fail(td::Status::Error(static_cast<int>(WorkchainExecutionFailure::LocalUnavailable),
                                  "unknown typed verification verdict"));
  }
  td::Status status() const { return failure_.clone(); }
  std::uint64_t consumed() const { return consumed_; }
 private:
  friend class ProofAdmittedBatchInput;
  friend struct WorkchainProofTestAccess;
  explicit WorkchainProofVerifier(std::uint64_t declared) : declared_(declared) {}
  static WorkchainProofVerdict run_backend(const UnoCryptoVerifyRequestV2& request);
  td::Status fail(td::Status error) { failure_ = std::move(error); return failure_.clone(); }
  const std::uint64_t declared_;
  std::uint64_t consumed_{0};
  td::Status failure_;
};

}  // namespace block
