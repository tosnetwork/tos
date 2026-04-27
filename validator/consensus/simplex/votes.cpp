/*
 * Copyright (c) 2025-2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "td/utils/overloaded.h"
#include "validator/consensus/bus.h"

#include "votes.h"

namespace tos::validator::consensus::simplex {

NotarizeVote NotarizeVote::from_tl(const tl::notarizeVote& vote) {
  return {CandidateId::from_tl(vote.id_)};
}

tl::UnsignedVoteRef NotarizeVote::to_tl() const {
  return create_tl_object<tl::notarizeVote>(id.to_tl());
}

td::StringBuilder& operator<<(td::StringBuilder& sb, const NotarizeVote& vote) {
  return sb << "NotarizeVote{id=" << vote.id << "}";
}

FinalizeVote FinalizeVote::from_tl(const tl::finalizeVote& vote) {
  return {CandidateId::from_tl(vote.id_)};
}

tl::UnsignedVoteRef FinalizeVote::to_tl() const {
  return create_tl_object<tl::finalizeVote>(id.to_tl());
}

td::StringBuilder& operator<<(td::StringBuilder& sb, const FinalizeVote& vote) {
  return sb << "FinalizeVote{id=" << vote.id << "}";
}

SkipVote SkipVote::from_tl(const tl::skipVote& vote) {
  return {static_cast<td::uint32>(vote.slot_)};
}

tl::UnsignedVoteRef SkipVote::to_tl() const {
  return create_tl_object<tl::skipVote>(slot);
}

td::StringBuilder& operator<<(td::StringBuilder& sb, const SkipVote& vote) {
  return sb << "SkipVote{slot=" << vote.slot << "}";
}

Vote Vote::from_tl(const tl::UnsignedVote& vote) {
  auto notarize_fn = [&](const tl::notarizeVote& tl_vote) -> Vote { return NotarizeVote::from_tl(tl_vote); };
  auto finalize_fn = [&](const tl::finalizeVote& tl_vote) -> Vote { return FinalizeVote::from_tl(tl_vote); };
  auto skip_fn = [&](const tl::skipVote& tl_vote) -> Vote { return SkipVote::from_tl(tl_vote); };

  // The natural single-expression form below does not compile
  // because `tos_api::downcast_call` requires a non-const reference
  // and cannot deduce the return type from the `td::overloaded`
  // visitor:
  //   return tos_api::downcast_call(
  //       vote, td::overloaded(notarize_fn, finalize_fn, skip_fn));
  // Instead, capture the visited result in an `optional` from
  // inside the lambda.
  std::optional<Vote> result;
  tos_api::downcast_call(const_cast<tl::UnsignedVote&>(vote),
                         [&](auto& vote) { result = td::overloaded(notarize_fn, finalize_fn, skip_fn)(vote); });
  return *result;
}

tl::UnsignedVoteRef Vote::to_tl() const {
  return std::visit([](const auto& v) { return v.to_tl(); }, vote);
}

td::StringBuilder& operator<<(td::StringBuilder& sb, const Vote& vote) {
  return std::visit([&](const auto& v) -> td::StringBuilder& { return sb << v; }, vote.vote);
}

template <ValidVote T>
td::BufferSlice Signed<T>::serialize() const {
  return create_serialize_tl_object<tl::vote>(vote.to_tl(), signature.clone());
}

template <ValidVote T>
td::Result<Signed<Vote>> Signed<T>::from_tl(tl::vote&& vote, PeerValidatorId validator, const Bus& bus)
  requires std::same_as<T, Vote>
{
  auto vote_to_sign = serialize_tl_object(vote.vote_, true);
  Signed<Vote> result{validator, Vote::from_tl(std::move(*vote.vote_)), std::move(vote.signature_)};

  if (!validator.get_using(bus).check_signature(bus.session_id, vote_to_sign, result.signature)) {
    return td::Status::Error("Invalid vote signature");
  }
  return result;
}

template <ValidVote T>
td::Result<Signed<Vote>> Signed<T>::deserialize(td::Slice data, PeerValidatorId validator, const Bus& bus)
  requires std::same_as<T, Vote>
{
  TRY_RESULT(vote, fetch_tl_object<tl::vote>(data, true));
  return from_tl(std::move(*vote), validator, bus);
}

template struct Signed<NotarizeVote>;
template struct Signed<SkipVote>;
template struct Signed<FinalizeVote>;
template struct Signed<Vote>;

}  // namespace tos::validator::consensus::simplex
