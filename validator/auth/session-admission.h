#pragma once

#include <algorithm>
#include <cstddef>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include "session-birth.h"

namespace tos::auth {

using AuthenticatedSessionHistoryRead =
    std::function<Result<SessionBirthObservation>(const SessionBirthBlock& expected)>;

class AuthenticatedSessionBirth;
Result<AuthenticatedSessionBirth> resolve_authenticated_session_birth(
    const SessionBirthBlock& trusted_tip, const SessionBirthEpoch& expected_epoch,
    const AuthenticatedSessionHistoryRead& read, std::size_t observation_limit = 4096);

// Construction is restricted to resolve_authenticated_session_birth. This does
// not make a reader authentic by naming it; the production adapter still has to
// verify every returned state against one independently finalized native chain.
class AuthenticatedSessionBirth {
 public:
  AuthenticatedSessionBirth(const AuthenticatedSessionBirth&) = default;
  AuthenticatedSessionBirth(AuthenticatedSessionBirth&&) noexcept = default;
  AuthenticatedSessionBirth& operator=(const AuthenticatedSessionBirth&) = default;
  AuthenticatedSessionBirth& operator=(AuthenticatedSessionBirth&&) noexcept = default;

  const SessionBirthBlock& trusted_tip() const {
    return trusted_tip_;
  }
  const SessionBirthResult& selected() const {
    return selected_;
  }

 private:
  AuthenticatedSessionBirth(SessionBirthBlock trusted_tip, SessionBirthResult selected)
      : trusted_tip_(std::move(trusted_tip)), selected_(std::move(selected)) {
  }

  SessionBirthBlock trusted_tip_;
  SessionBirthResult selected_;

  friend Result<AuthenticatedSessionBirth> resolve_authenticated_session_birth(
      const SessionBirthBlock&, const SessionBirthEpoch&, const AuthenticatedSessionHistoryRead&, std::size_t);
};

// Incrementally reads one exact chain from the independently selected tip. The
// selector remains the only implementation of birth semantics. If the boundary
// is not established within the budget, this adapter returns a budget error; it
// never treats the last locally available state as a birth.
inline Result<AuthenticatedSessionBirth> resolve_authenticated_session_birth(
    const SessionBirthBlock& trusted_tip, const SessionBirthEpoch& expected_epoch,
    const AuthenticatedSessionHistoryRead& read, std::size_t observation_limit) {
  constexpr std::size_t max_observations = 65536;
  if (!read)
    return Error{"session-birth-history-unavailable"};
  if (observation_limit == 0 || observation_limit > max_observations)
    return Error{"session-birth-budget"};

  std::vector<SessionBirthObservation> history;
  history.reserve(std::min<std::size_t>(observation_limit, 4096));
  SessionBirthBlock expected = trusted_tip;
  for (std::size_t count = 0; count < observation_limit; ++count) {
    auto observation = read(expected);
    if (!observation.ok())
      return observation.error();
    history.push_back(observation.value());

    auto selected = resolve_session_birth(trusted_tip, expected_epoch, history, observation_limit);
    if (selected.ok())
      return AuthenticatedSessionBirth{trusted_tip, selected.value()};
    if (selected.error().code != "session-birth-history-incomplete")
      return selected.error();

    // The selector can report incomplete only after accepting a current record
    // with a complete predecessor coordinate. Keep this check explicit so a
    // future selector change cannot turn a missing parent into a reader request.
    if (!history.back().parent)
      return Error{"session-birth-parent"};
    expected = *history.back().parent;
  }
  return Error{"session-birth-budget"};
}

// The native session ID is produced by the existing canonical manager encoder
// and is supplied here; this helper does not reproduce that grammar. It only
// normalizes coordinates omitted by historical ID variants so the same native
// lifetime cannot acquire metadata copied from a later key block.
struct NativeSessionEpochInput {
  Hash native_session_id{};
  Hash election_cell_hash{};
  Hash native_options_hash{};
  std::int32_t workchain{};
  std::uint64_t shard{};
  std::uint32_t catchain{};
  std::uint32_t maximal_vertical_seqno{};
  std::uint32_t last_key_block_seqno{};
  bool new_catchain_ids{};
};

inline Result<SessionBirthEpoch> map_native_session_epoch(const NativeSessionEpochInput& input) {
  if (input.native_session_id == Hash{} || input.election_cell_hash == Hash{})
    return Error{"session-birth-epoch"};
  if (input.native_options_hash == Hash{})
    return Error{"session-birth-options"};
  if (input.workchain < -1 || input.shard == 0)
    return Error{"session-birth-coordinate"};
  return SessionBirthEpoch{input.native_session_id,
                           input.election_cell_hash,
                           input.native_options_hash,
                           input.workchain,
                           input.shard,
                           input.catchain,
                           input.maximal_vertical_seqno,
                           input.new_catchain_ids ? input.last_key_block_seqno : 0};
}

enum class SessionAdmissionDecision { reuse_existing, create_new };

template <class Committee>
class SessionCommitteeContext {
 public:
  SessionCommitteeContext(AuthenticatedSessionBirth birth, Committee committee)
      : birth_(std::move(birth)), committee_(std::move(committee)) {
  }

  const AuthenticatedSessionBirth& birth() const {
    return birth_;
  }
  const Committee& committee() const {
    return committee_;
  }

 private:
  AuthenticatedSessionBirth birth_;
  Committee committee_;
};

template <class Committee>
Result<SessionAdmissionDecision> classify_session_admission(
    const SessionCommitteeContext<Committee>& existing, const AuthenticatedSessionBirth& candidate) {
  const auto& held = existing.birth().selected();
  const auto& incoming = candidate.selected();
  if (held.epoch.native_session_id != incoming.epoch.native_session_id)
    return SessionAdmissionDecision::create_new;
  if (held.epoch != incoming.epoch)
    return Error{"session-admission-epoch-conflict"};
  if (held.block != incoming.block)
    return Error{"session-admission-birth-conflict"};
  return SessionAdmissionDecision::reuse_existing;
}

template <class Committee, class Derive>
Result<std::shared_ptr<const SessionCommitteeContext<Committee>>> derive_session_committee(
    AuthenticatedSessionBirth birth, Derive&& derive) {
  // Derive from the authenticated birth, never from the later tip at which this
  // node happened to notice or recreate the session.
  auto committee = std::invoke(std::forward<Derive>(derive), birth.selected().block);
  if (!committee.ok())
    return committee.error();
  using Context = SessionCommitteeContext<Committee>;
  return std::shared_ptr<const Context>(new Context(std::move(birth), std::move(committee.value())));
}

template <class Committee, class Derive>
Result<std::shared_ptr<const SessionCommitteeContext<Committee>>> admit_session_committee(
    const std::shared_ptr<const SessionCommitteeContext<Committee>>& existing,
    AuthenticatedSessionBirth candidate, Derive&& derive) {
  if (existing) {
    auto decision = classify_session_admission(*existing, candidate);
    if (!decision.ok())
      return decision.error();
    if (decision.value() == SessionAdmissionDecision::reuse_existing)
      return existing;
  }
  return derive_session_committee<Committee>(std::move(candidate), std::forward<Derive>(derive));
}

}  // namespace tos::auth
