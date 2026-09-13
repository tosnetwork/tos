#pragma once
#include <optional>

#include "codec.h"

namespace tos::auth {
// These are local history views, not wire objects or independently verified
// proofs. The adapter must copy them from one authenticated native history.
// No encoding, hashing, block authentication or committee admission occurs here.
struct SessionBirthBlock {
  std::uint32_t seqno{};
  Hash root{}, file{}, state{};
  bool operator==(const SessionBirthBlock&) const = default;
};

struct SessionBirthEpoch {
  Hash native_session_id{}, election_cell_hash{}, native_options_hash{};
  std::int32_t workchain{};
  std::uint64_t shard{};
  std::uint32_t catchain{}, vertical_seqno{}, key_block_seqno{};
  bool operator==(const SessionBirthEpoch&) const = default;
};

struct SessionBirthObservation {
  SessionBirthBlock block;
  std::optional<SessionBirthBlock> parent;
  // Empty means the native history positively established no current session
  // for this shard. A failed lookup is an Error, never an empty optional.
  Result<std::optional<SessionBirthEpoch>> current{Error{"session-birth-history-unavailable"}};
};

struct SessionBirthResult {
  SessionBirthBlock block;
  SessionBirthEpoch epoch;
  std::size_t observations_used{};
};

namespace session_birth_detail {
inline bool valid_block(const SessionBirthBlock& block) {
  return block.seqno != std::numeric_limits<std::uint32_t>::max() &&
         block.root != Hash{} && block.file != Hash{} && block.state != Hash{};
}
inline bool valid_epoch(const SessionBirthEpoch& epoch) {
  return epoch.native_session_id != Hash{} && epoch.election_cell_hash != Hash{};
}
}  // namespace session_birth_detail

// A bounded, read-only walk of the consecutive current-epoch suffix. The tip
// and expected epoch are independently selected by the native adapter, not by
// the certificate sender. History is ordered from tip towards genesis.
//
// A boundary requires the authenticated predecessor to have a different
// current epoch (or explicitly no session). Exhausting retained history is not
// a boundary. Extra older observations after the boundary are not consumed.
// The result selects a state; it grants no signing or verification authority.
inline Result<SessionBirthResult> resolve_session_birth(
    const SessionBirthBlock& trusted_tip, const SessionBirthEpoch& expected_epoch,
    std::span<const SessionBirthObservation> history, std::size_t observation_limit = 4096) {
  constexpr std::size_t max_observations = 65536;
  if (history.size() > observation_limit || history.size() > max_observations)
    return Error{"session-birth-budget"};
  if (!session_birth_detail::valid_block(trusted_tip))
    return Error{"session-birth-anchor"};
  if (!session_birth_detail::valid_epoch(expected_epoch))
    return Error{"session-birth-epoch"};

  SessionBirthBlock expected_block = trusted_tip;
  std::optional<SessionBirthBlock> candidate;
  std::size_t used = 0;
  for (const auto& observation : history) {
    ++used;
    if (observation.block != expected_block)
      return Error{"session-birth-link"};
    if (!session_birth_detail::valid_block(observation.block))
      return Error{"session-birth-anchor"};
    if (!observation.current.ok())
      return observation.current.error();
    const auto& current = observation.current.value();
    if (current && !session_birth_detail::valid_epoch(*current))
      return Error{"session-birth-epoch"};
    if (!current || *current != expected_epoch) {
      if (!candidate)
        return Error{"session-birth-not-current"};
      return SessionBirthResult{*candidate, expected_epoch, used};
    }
    candidate = observation.block;
    if (observation.block.seqno == 0 || !observation.parent) {
      if (observation.block.seqno != 0 || observation.parent)
        return Error{"session-birth-parent"};
      return SessionBirthResult{*candidate, expected_epoch, used};
    }
    if (observation.parent->seqno != observation.block.seqno - 1)
      return Error{"session-birth-parent-step"};
    expected_block = *observation.parent;
  }
  return Error{"session-birth-history-incomplete"};
}
}  // namespace tos::auth
