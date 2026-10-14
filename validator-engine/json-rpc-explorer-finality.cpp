/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "auto/tl/lite_api.hpp"
#include "lite-client/lite-client-common.h"
#include "td/utils/base64.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "tos/quorum.h"
#include "vm/boc.h"

#include "json-rpc-explorer.h"
#include "json-rpc-server-parse.h"
namespace tos::explorer {
td::Result<std::string> inspect_finality_reply(td::BufferSlice reply, BlockIdExt anchor, BlockIdExt target,
                                               bool with_proof, td::CancellationToken cancellation) {
  if (reply.size() > kProofBytes)
    return error(Failure::ResourceLimit);
  TRY_RESULT(object, fetch_tl_object<lite_api::liteServer_partialBlockProof>(reply.clone(), true));
  if (!object->from_ || !object->to_ || create_block_id(object->from_) != anchor ||
      create_block_id(object->to_) != target)
    return error(Failure::EvidenceInvalid);
  if (!object->complete_)
    return error(Failure::BlockUnavailable);
  if (object->steps_.empty() || object->steps_.size() > kMaxLinks)
    return error(Failure::ResourceLimit);
  unsigned relevant = 0;
  for (const auto& step : object->steps_) {
    if (!step)
      return error(Failure::EvidenceInvalid);
    if (step->get_id() == lite_api::liteServer_blockLinkForward::ID) {
      const auto& link = static_cast<const lite_api::liteServer_blockLinkForward&>(*step);
      if (!link.from_ || !link.to_ || !link.signatures_)
        return error(Failure::EvidenceInvalid);
      if (create_block_id(link.to_) == target)
        ++relevant;
    }
  }
  if (relevant != 1 || object->steps_.back()->get_id() != lite_api::liteServer_blockLinkForward::ID)
    return error(Failure::EvidenceInvalid);
  auto decoded = liteclient::deserialize_proof_chain(std::move(object));
  if (decoded.is_error())
    return error(Failure::EvidenceInvalid);
  auto chain = decoded.move_as_ok();
  block::FinalityVerificationInfo finality;
  auto checked = chain->validate(cancellation, &finality);
  if (checked.is_error())
    return error(checked.code() == block::kPQVerificationBackendFailure ? Failure::BackendFailure
                                                                        : Failure::EvidenceInvalid);
  const auto& link = chain->last_link();
  if (link.to != target || link.sig_set.is_null() || !link.sig_set->is_final())
    return error(Failure::EvidenceInvalid);
  if (!link.sig_set->is_pq()) {
    auto native = link.sig_set->tl_lite();
    return render_masterchain_block_signatures_json(native.get(), block_json(target));
  }
  TRY_RESULT(session, link.sig_set->pq_session_id());
  TRY_RESULT(slot, link.sig_set->pq_slot());
  TRY_RESULT(candidate_bytes, link.sig_set->pq_candidate_data());
  TRY_RESULT(candidate, fetch_tl_object<tos_api::consensus_CandidateHashData>(candidate_bytes.clone(), true));
  TRY_RESULT(payload, block::BlockSignatureSet::build_simplex_data_to_sign(session, slot, candidate, true, target));
  if (payload.size() > 3072)
    return error(Failure::ResourceLimit);
  TRY_RESULT(signatures, link.sig_set->export_pq_signatures());
  td::StringBuilder out;
  out << "{\"@type\":\"blocks.blockSignatures.simplexPq\",\"schema_version\":1,\"id\":" << block_json(target)
      << ",\"cc_seqno\":" << link.sig_set->get_catchain_seqno()
      << ",\"validator_set_hash\":" << link.sig_set->get_validator_set_hash() << ",\"session_id\":\""
      << td::base64_encode(session.as_slice()) << "\",\"slot\":" << slot << ",\"candidate\":\""
      << td::base64_encode(candidate_bytes.as_slice())
      << "\",\"signature_context\":\"TOS-CONSENSUS-SIMPLEX-v1\",\"signing_payload\":\""
      << td::base64_encode(payload.as_slice()) << "\",\"signatures\":[";
  bool first = true;
  for (const auto& signature : signatures) {
    if (!first)
      out << ",";
    first = false;
    out << "{\"@type\":\"blocks.signature.pq\",\"validator_id\":\""
        << td::base64_encode(signature.validator_id.value.as_slice())
        << "\",\"algorithm_id\":" << static_cast<unsigned>(signature.algorithm_id) << ",\"signature\":\""
        << td::base64_encode(signature.signature.as_slice()) << "\"}";
  }
  out << "],\"verification\":{\"status\":\"node_verified\",\"scope\":\"anchored_finality\",\"trust_anchor\":"
      << block_json(anchor) << ",\"validator_set_source\":" << block_json(link.from) << ",\"expected_session_id\":\""
      << td::base64_encode(finality.expected_session_id.as_slice()) << "\",\"verified_weight\":\""
      << finality.verified_weight << "\",\"total_weight\":\"" << finality.total_weight << "\",\"quorum_threshold\":\""
      << quorum_threshold(finality.total_weight) << "\"}";
  if (with_proof)
    out << ",\"proof\":{\"format\":\"liteServer.partialBlockProof.tl\",\"bytes\":\""
        << td::base64_encode(reply.as_slice()) << "\",\"from\":" << block_json(anchor)
        << ",\"to\":" << block_json(target) << "}";
  out << "}";
  if (out.as_cslice().size() > kSignatureJsonBytes - 512)
    return error(Failure::ResourceLimit);
  return out.as_cslice().str();
}

}  // namespace tos::explorer
