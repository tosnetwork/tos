/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "auto/tl/lite_api.hpp"
#include "common/errorcode.h"
#include "crypto/common/refcnt.hpp"
#include "crypto/pq/pq-consensus.h"
#include "tos/tos-types.h"
#include "vm/cells.h"

#include "validator-set.h"

namespace block {

struct PQBlockSignature {
  tos::ValidatorId validator_id;
  tos::pq::PQAlgorithmId algorithm_id{tos::pq::PQAlgorithmId::unknown};
  td::BufferSlice signature;
};

enum class FinalityRole { Final, Approve };

struct PQFinalityVerificationContext {
  td::Ref<ValidatorSet> validator_set;
  tos::BlockIdExt block_id;
  tos::ValidatorSessionId expected_session_id;
};

class BlockSignatureSet : public td::CntObject {
 public:
  virtual size_t get_size() const = 0;
  // TL bytes occupied by signer identities, algorithm selectors and framed
  // signature byte strings, excluding the surrounding carrier metadata.
  virtual td::Result<std::size_t> get_signature_data_size() const = 0;
  virtual td::Result<tos::ValidatorWeight> get_weight(td::Ref<ValidatorSet> vset) const = 0;
  virtual bool is_ordinary() const {
    return false;
  }
  virtual bool is_pq() const {
    return false;
  }
  virtual bool is_final() const = 0;

  td::Result<tos::ValidatorWeight> check_signatures(td::Ref<ValidatorSet> vset, tos::BlockIdExt block_id) const;
  td::Result<tos::ValidatorWeight> check_approve_signatures(td::Ref<ValidatorSet> vset, tos::BlockIdExt block_id) const;

  // Test-only cryptographic primitive: verifies a PQ set under the session id
  // carried by that set. Production proof consumers must instead call
  // verify_pq_finality with a session id derived from trusted chain context.
  td::Result<tos::ValidatorWeight> check_pq_signatures_under_carried_session_for_test(td::Ref<ValidatorSet> vset,
                                                                                      tos::BlockIdExt block_id,
                                                                                      FinalityRole role) const;

  // The one Simplex vote-envelope builder shared by the historical and
  // post-quantum verification paths. It deliberately binds the carried session,
  // role, slot, candidate hash and candidate block id, but does not claim that the
  // carried session is the trusted expected session (that belongs to the higher
  // level verification context).
  static td::Result<td::BufferSlice> build_simplex_data_to_sign(
      td::Bits256 session_id, td::uint32 slot,
      const tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>& candidate, bool final,
      tos::BlockIdExt block_id);

  virtual td::Result<td::Ref<vm::Cell>> serialize(td::Ref<ValidatorSet> vset) const = 0;
  virtual tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet> tl() const = 0;
  virtual tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet> tl_lite() const = 0;

  // ordinary signature set only (is_ordinary())
  virtual std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_blockSignature>> tl_legacy() const {
    UNREACHABLE();
  }

  BlockSignatureSet(tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash)
      : cc_seqno_(cc_seqno), validator_set_hash_(validator_set_hash) {
  }
  tos::CatchainSeqno get_catchain_seqno() const {
    return cc_seqno_;
  }
  td::uint32 get_validator_set_hash() const {
    return validator_set_hash_;
  }

 protected:
  friend td::Result<tos::ValidatorWeight> verify_pq_finality(const PQFinalityVerificationContext& context,
                                                             const BlockSignatureSet& signature_set, FinalityRole role);
  tos::CatchainSeqno cc_seqno_;
  td::uint32 validator_set_hash_;

  virtual td::Result<tos::ValidatorWeight> check_signatures_impl(td::Ref<ValidatorSet> vset,
                                                                 tos::BlockIdExt block_id) const = 0;

 public:
  static td::Ref<BlockSignatureSet> create_ordinary(std::vector<tos::BlockSignature> signatures,
                                                    tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash);
  static td::Ref<BlockSignatureSet> create_simplex(
      std::vector<tos::BlockSignature> signatures, tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
      td::Bits256 session_id, td::uint32 slot, tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate);
  static td::Ref<BlockSignatureSet> create_simplex_approve(
      std::vector<tos::BlockSignature> signatures, tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
      td::Bits256 session_id, td::uint32 slot, tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate);
  static td::Result<td::Ref<BlockSignatureSet>> create_simplex_pq_final(
      std::vector<PQBlockSignature> signatures, tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
      td::Bits256 session_id, td::uint32 slot, tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate);
  static td::Result<td::Ref<BlockSignatureSet>> create_simplex_pq_approve(
      std::vector<PQBlockSignature> signatures, tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
      td::Bits256 session_id, td::uint32 slot, tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData> candidate);
  static td::Result<td::Ref<vm::Cell>> serialize_simplex_pq(
      const std::vector<PQBlockSignature>& signatures, tos::CatchainSeqno cc_seqno, td::uint32 validator_set_hash,
      tos::ValidatorWeight signature_weight, td::Bits256 session_id, td::uint32 slot,
      const tos::tl_object_ptr<tos::tos_api::consensus_CandidateHashData>& candidate);

  virtual td::Result<std::vector<PQBlockSignature>> export_pq_signatures() const;
  virtual td::Result<td::Bits256> pq_session_id() const;
  virtual td::Result<td::uint32> pq_slot() const;
  virtual td::Result<td::BufferSlice> pq_candidate_data() const;

  static td::Result<td::Ref<BlockSignatureSet>> fetch(td::Ref<vm::Cell> cell, tos::ValidatorWeight& total_weight);
  static td::Result<td::Ref<BlockSignatureSet>> fetch(td::Ref<vm::Cell> cell, td::Ref<ValidatorSet> vset);
  static td::Ref<BlockSignatureSet> fetch(
      const std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_blockSignature>>& f, tos::CatchainSeqno cc_seqno,
      td::uint32 validator_set_hash);
  static td::Result<td::Ref<BlockSignatureSet>> fetch_legacy_checked(
      const std::vector<tos::tl_object_ptr<tos::tos_api::tosNode_blockSignature>>& f, tos::CatchainSeqno cc_seqno,
      td::uint32 validator_set_hash);
  // Legacy adapter for already-trusted/test-owned objects. Untrusted network
  // callers must use fetch_node_checked.
  static td::Ref<BlockSignatureSet> fetch(const tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet>& f);
  static td::Result<td::Ref<BlockSignatureSet>> fetch_node_checked(
      const tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet>& f);
  static td::Result<td::Ref<BlockSignatureSet>> fetch(
      const tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet>& f);
  static td::Result<td::Ref<BlockSignatureSet>> fetch_lite_checked(
      const tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet>& f);

  // Checked post-quantum adapters used by the dual-carrier entry points above.
  static td::Result<td::Ref<BlockSignatureSet>> fetch_pq_node_checked(
      const tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet>& f);
  static td::Result<td::Ref<BlockSignatureSet>> fetch_pq_lite_checked(
      const tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet>& f);

  static constexpr size_t MAX_SIGNATURES = 1024;
};

// The production verification boundary for persisted post-quantum finality.
// The expected session is trusted input; it is never inferred from the proof.
td::Result<tos::ValidatorWeight> verify_pq_finality(const PQFinalityVerificationContext& context,
                                                    const BlockSignatureSet& signature_set, FinalityRole role);

}  // namespace block
