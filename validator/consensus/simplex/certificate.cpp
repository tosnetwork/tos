/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include <algorithm>

#include "td/utils/overloaded.h"
#include "tos/quorum.h"
#include "validator/consensus/bus.h"

#include "certificate.h"

namespace tos::validator::consensus::simplex {

template <ValidVote T>
td::Result<td::Ref<Certificate<T>>> Certificate<T>::from_tl(tl::voteSignatureSet&& set, T vote, const Bus& bus) {
  auto vote_to_sign = serialize_tl_object(vote.to_tl(), true);

  std::vector<bool> voted(bus.validator_set.size(), false);
  std::vector<VoteSignature> signatures;
  ValidatorWeight voted_weight = 0;

  for (auto& signature : set.votes_) {
    auto who = static_cast<td::uint32>(signature->who_);
    if (who >= bus.validator_set.size()) {
      return td::Status::Error(PSTRING() << "Invalid validator index " << who << " in certificate");
    }
    if (voted[who]) {
      return td::Status::Error(PSTRING() << "Duplicate validator index " << who << " in certificate");
    }
    voted[who] = true;

    auto validator = PeerValidatorId{who}.get_using(bus);
    signatures.emplace_back(VoteSignature{validator.idx, std::move(signature->signature_)});
    if (!tos::checked_add_validator_weight(voted_weight, validator.weight)) {
      return td::Status::Error("Validator vote weight sum exceeds protocol cap");
    }
  }

  if (voted_weight < tos::quorum_threshold(bus.total_weight)) {
    return td::Status::Error("Not enough signatures in certificate");
  }

  for (const auto& [who, signature] : signatures) {
    auto validator = PeerValidatorId{who}.get_using(bus);
    if (!validator.check_signature(bus.session_id, vote_to_sign, signature)) {
      return td::Status::Error(PSTRING() << "Invalid vote signature for " << validator);
    }
  }

  return td::make_ref<Certificate<T>>(std::move(vote), std::move(signatures));
}

template <ValidVote T>
td::Result<td::Ref<Certificate<Vote>>> Certificate<T>::from_tl(tl::certificate&& cert, const Bus& bus)
  requires std::same_as<T, Vote>
{
  auto vote_to_sign = serialize_tl_object(cert.vote_, true);
  auto vote = Vote::from_tl(std::move(*cert.vote_));
  return from_tl(std::move(*cert.signatures_), std::move(vote), bus);
}

template <ValidVote T>
td::CntObject* Certificate<T>::make_copy() const {
  std::vector<VoteSignature> copied_signatures;
  for (const auto& sig : signatures) {
    copied_signatures.emplace_back(VoteSignature{sig.validator, sig.signature.clone()});
  }
  return new Certificate<T>(vote, std::move(copied_signatures));
}

template <ValidVote T>
tl::VoteSignatureSetRef Certificate<T>::to_tl_vote_signature_set() const {
  std::vector<tl::VoteSignatureRef> tl_sigs;
  for (const auto& [validator, signature] : signatures) {
    auto idx = static_cast<td::uint32>(validator.value());
    tl_sigs.push_back(create_tl_object<tl::voteSignature>(idx, signature.clone()));
  }
  return create_tl_object<tl::voteSignatureSet>(std::move(tl_sigs));
}

template <ValidVote T>
tl::CertificateRef Certificate<T>::to_tl() const {
  return create_tl_object<tl::certificate>(vote.to_tl(), to_tl_vote_signature_set());
}

template <ValidVote T>
td::BufferSlice Certificate<T>::serialize() const {
  return serialize_tl_object(to_tl(), true);
}

template <ValidVote T>
td::Result<td::Ref<block::BlockSignatureSet>> Certificate<T>::to_signature_set(const CandidateRef& candidate,
                                                                               const Bus& bus) const
  requires td::OneOf<T, NotarizeVote, FinalizeVote>
{
  if (candidate.is_null()) {
    return td::Status::Error("pq certificate conversion: missing candidate");
  }
  if (candidate->id != vote.id) {
    return td::Status::Error("pq certificate conversion: vote id does not match candidate id");
  }
  if (candidate->hash_data().build_id_with(vote.id.slot) != vote.id) {
    return td::Status::Error("pq certificate conversion: candidate hash data does not reconstruct candidate id");
  }
  if (candidate->hash_data().block() != candidate->block_id()) {
    return td::Status::Error("pq certificate conversion: candidate hash data does not reconstruct block id");
  }

  std::vector<const VoteSignature*> ordered;
  ordered.reserve(signatures.size());
  for (const auto& signature : signatures) {
    ordered.push_back(&signature);
  }
  std::sort(ordered.begin(), ordered.end(),
            [](const auto* lhs, const auto* rhs) { return lhs->validator.value() < rhs->validator.value(); });

  std::vector<bool> seen(bus.validator_set.size(), false);
  std::vector<block::PQBlockSignature> carried;
  carried.reserve(ordered.size());
  ValidatorWeight weight = 0;
  for (const auto* item : ordered) {
    const auto index = item->validator.value();
    if (index >= bus.validator_set.size()) {
      return td::Status::Error(PSTRING() << "pq certificate conversion: validator index " << index
                                         << " is outside the trusted set");
    }
    if (seen[index]) {
      return td::Status::Error(PSTRING() << "pq certificate conversion: duplicate validator index " << index);
    }
    seen[index] = true;
    const auto& descriptor = bus.validator_set[index];
    if (!tos::pq::valid_public_key(descriptor.consensus_key.algorithm_id, descriptor.consensus_key.public_key)) {
      return td::Status::Error(PSTRING() << "pq certificate conversion: validator " << index
                                         << " has a malformed or unadmitted consensus descriptor");
    }
    auto derived_key_id =
        tos::pq::derive_key_id(descriptor.consensus_key.algorithm_id, descriptor.consensus_key.public_key);
    if (!derived_key_id || *derived_key_id != descriptor.consensus_key.key_id) {
      return td::Status::Error(PSTRING() << "pq certificate conversion: validator " << index
                                         << " consensus key id disagrees with its public key");
    }
    if (!tos::pq::valid_signature(descriptor.consensus_key.algorithm_id,
                                  std::string_view(item->signature.data(), item->signature.size()))) {
      return td::Status::Error(PSTRING() << "pq certificate conversion: validator " << index
                                         << " has a signature of the wrong length");
    }
    if (!tos::checked_add_validator_weight(weight, descriptor.weight)) {
      return td::Status::Error("pq certificate conversion: validator weight sum exceeds protocol cap");
    }
    carried.push_back(block::PQBlockSignature{descriptor.validator_id, descriptor.consensus_key.algorithm_id,
                                              item->signature.clone()});
  }
  if (weight < tos::quorum_threshold(bus.total_weight)) {
    return td::Status::Error("pq certificate conversion: certificate is below weighted quorum");
  }

  if constexpr (std::same_as<T, FinalizeVote>) {
    return block::BlockSignatureSet::create_simplex_pq_final(std::move(carried), bus.cc_seqno, bus.validator_set_hash,
                                                             bus.session_id, vote.id.slot,
                                                             candidate->hash_data().to_tl());
  } else {
    return block::BlockSignatureSet::create_simplex_pq_approve(std::move(carried), bus.cc_seqno, bus.validator_set_hash,
                                                               bus.session_id, vote.id.slot,
                                                               candidate->hash_data().to_tl());
  }
}

template <ValidVote T>
td::Ref<Certificate<Vote>> Certificate<T>::consume_and_upcast() &&
  requires(!std::same_as<T, Vote>)
{
  std::vector<Certificate<Vote>::VoteSignature> casted_signatures;
  for (auto& sig : signatures) {
    casted_signatures.emplace_back(sig.validator, std::move(sig.signature));
  }
  return td::make_ref<Certificate<Vote>>(vote, std::move(casted_signatures));
}

template struct Certificate<NotarizeVote>;
template struct Certificate<SkipVote>;
template struct Certificate<FinalizeVote>;
template struct Certificate<Vote>;

}  // namespace tos::validator::consensus::simplex
