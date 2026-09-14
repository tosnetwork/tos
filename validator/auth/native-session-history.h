#pragma once

#include <algorithm>
#include <cstddef>
#include <functional>
#include <limits>
#include <optional>
#include <utility>

#include "block/block-auto.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "tos/tos-shard.h"

#include "native-history.h"
#include "native-session-id.h"
#include "session-admission.h"

namespace tos::auth {

// The node state store returns the root for this exact independently
// authenticated anchor. Returning a local latest state for a missing coordinate
// violates this contract; the adapter binds the returned root before use.
using NativeSessionStateReader =
    std::function<Result<td::Ref<vm::Cell>>(const Anchor&)>;

// The manager owns the identity constructor form, options hash and vertical/key
// coordinates used at each native state. The adapter never recomputes those
// values beside the manager. The reader receives an exact authenticated state
// and must return the input for that state and target shard.
using NativeSessionIdentityInputReader = std::function<Result<NativeSessionIdInput>(
    const Anchor&, td::Ref<vm::Cell>, tos::ShardIdFull)>;

struct NativeSessionHistoryBudget {
  std::size_t observations = 4096;
  HistoryReadBudget finalized{4096, 268435456};
};

namespace native_session_history_detail {
inline Hash hash(td::Slice raw) {
  Hash result{};
  if (raw.size() == result.size())
    std::copy(raw.ubegin(), raw.uend(), result.begin());
  return result;
}

inline td::Bits256 bits(const Hash& value) {
  return td::Bits256(td::ConstBitPtr(value.data()));
}

inline SessionBirthBlock session_block(const Anchor& anchor) {
  return {anchor.seqno_, anchor.root_, anchor.file_, anchor.state_};
}

inline Result<bool> bind_state(td::Ref<vm::Cell> state, const Anchor& anchor,
                               const ChainContext& chain) {
  if (state.is_null() || state->get_level() != 0 ||
      hash(state->get_hash().as_slice()) != anchor.state_)
    return Error{"session-history-state-binding"};
  block::gen::ShardStateUnsplit::Record header;
  if (!tlb::unpack_cell(state, header))
    return Error{"session-history-state-header"};
  block::ShardId source(header.shard_id);
  if (header.global_id != chain.network || header.seq_no != anchor.seqno_ ||
      source.workchain_id != tos::masterchainId || source.shard_pfx_len != 0)
    return Error{"session-history-state-context"};
  return true;
}
}  // namespace native_session_history_detail

// Derives the session identity and election metadata established by one exact
// authenticated masterchain state. The identity form, options hash and vertical
// coordinates remain caller-owned facts; the state supplies the validator set,
// member order and catchain through the same native selection path as the
// manager. Authenticated pre-activation may establish absence; malformed
// active state is always an error.
namespace native_session_history_detail {
using NativeSessionIdentityInputLoad =
    std::function<Result<NativeSessionIdInput>()>;

inline Result<std::optional<SessionBirthEpoch>> derive_epoch(
    td::Ref<vm::Cell> state, const Anchor& anchor, const ChainContext& chain,
    tos::ShardIdFull target, const NativeSessionIdentityInputLoad& load_input) {
  try {
    if (target.workchain < -1 || target.shard == 0)
      return Error{"native-session-coordinate"};
    auto bound = bind_state(state, anchor, chain);
    if (!bound.ok())
      return bound.error();
    tos::BlockIdExt block_id{{tos::masterchainId, tos::shardIdAll,
                              anchor.seqno_},
                             bits(anchor.root_), bits(anchor.file_)};
    auto config = block::ConfigInfo::extract_config(
        state, block_id,
        block::ConfigInfo::needValidatorSet |
            block::ConfigInfo::needShardHashes |
            block::Config::needCapabilities);
    if (config.is_error())
      return Error{"session-history-native-state"};
    const auto& cfg = *config.ok();
    if (cfg.get_global_blockchain_id() != chain.network)
      return Error{"session-history-network"};

    // The authenticated state alone establishes pre-activation. The caller's
    // historical identity metadata is not consulted for a session that cannot
    // exist yet.
    if (cfg.get_global_version() < 16 ||
        !(cfg.get_capabilities() & tos::capValidatorAuth))
      return std::optional<SessionBirthEpoch>{};

    auto advertised_catchain = cfg.get_shard_cc_seqno(target);
    if (advertised_catchain ==
        std::numeric_limits<tos::CatchainSeqno>::max())
      return std::optional<SessionBirthEpoch>{};
    if (!load_input)
      return Error{"session-history-identity-unavailable"};
    auto loaded_input = load_input();
    if (!loaded_input.ok())
      return loaded_input.error();
    auto identity_input = std::move(loaded_input.value());
    if (identity_input.workchain != target.workchain ||
        identity_input.shard != target.shard)
      return Error{"session-history-identity-shard"};

    const auto& total = cfg.get_cur_validator_set();
    if (!total)
      return Error{"native-session-validator-set"};
    tos::CatchainSeqno catchain = 0;
    auto members = cfg.compute_validator_set_cc(target, *total, cfg.utime,
                                                &catchain);
    if (members.empty())
      return Error{"native-session-validator-set"};
    auto validator_set = td::make_ref<block::ValidatorSet>(
        catchain, target, std::move(members));
    auto identity =
        derive_native_session_identity(std::move(validator_set), identity_input);
    if (!identity.ok())
      return identity.error();

    auto election = cfg.get_config_param(35, 34);
    if (election.is_null())
      return Error{"native-session-election"};
    auto election_hash = hash(election->get_hash().as_slice());
    if (election_hash == Hash{})
      return Error{"native-session-election"};
    const auto& established = identity.value();
    return std::optional{SessionBirthEpoch{
        established.native_session_id, election_hash,
        established.native_options_hash, established.workchain,
        established.shard, established.catchain,
        established.vertical_seqno, established.key_block_seqno}};
  } catch (const vm::VmError&) {
    return Error{"session-history-native-state"};
  } catch (const vm::VmVirtError&) {
    return Error{"session-history-pruned"};
  }
}
}  // namespace native_session_history_detail

inline Result<std::optional<SessionBirthEpoch>> derive_native_session_epoch(
    td::Ref<vm::Cell> state, const Anchor& anchor, const ChainContext& chain,
    const NativeSessionIdInput& identity_input) {
  tos::ShardIdFull target{identity_input.workchain, identity_input.shard};
  return native_session_history_detail::derive_epoch(
      std::move(state), anchor, chain, target,
      [&identity_input]() -> Result<NativeSessionIdInput> {
        return identity_input;
      });
}

// Owns both the authenticated birth decision and the exact state root selected
// by it. Construction is possible only after every visited coordinate has been
// resolved through one independently finalized history and bound to its state.
class NativeSessionBirth {
 public:
  NativeSessionBirth(const NativeSessionBirth&) = default;
  NativeSessionBirth(NativeSessionBirth&&) noexcept = default;
  NativeSessionBirth& operator=(const NativeSessionBirth&) = default;
  NativeSessionBirth& operator=(NativeSessionBirth&&) noexcept = default;

  static Result<NativeSessionBirth> resolve(
      td::Ref<vm::Cell> finalized_head_state,
      const Anchor& independently_finalized_head, const ChainContext&,
      const NativeSessionIdInput&, NativeBlockReader, NativeSessionStateReader,
      NativeSessionIdentityInputReader, NativeSessionHistoryBudget = {});

  const AuthenticatedSessionBirth& birth() const {
    return birth_;
  }
  const td::Ref<vm::Cell>& state() const {
    return state_;
  }

 private:
  NativeSessionBirth(AuthenticatedSessionBirth birth, td::Ref<vm::Cell> state)
      : birth_(std::move(birth)), state_(std::move(state)) {
  }

  AuthenticatedSessionBirth birth_;
  td::Ref<vm::Cell> state_;
};

namespace native_session_history_detail {
class Source {
 public:
  Source(NativeFinalizedHistory history, Anchor head,
         td::Ref<vm::Cell> head_state, ChainContext chain,
         NativeSessionStateReader state_reader,
         NativeSessionIdentityInputReader identity_reader,
         SessionBirthEpoch expected)
      : history_(std::move(history)),
        head_(std::move(head)),
        head_state_(std::move(head_state)),
        chain_(std::move(chain)),
        state_reader_(std::move(state_reader)),
        identity_reader_(std::move(identity_reader)),
        expected_(std::move(expected)),
        target_(expected_.workchain, expected_.shard) {
  }

  Result<SessionBirthObservation> read(const SessionBirthBlock& expected_block) {
    auto authenticated = history_.finalized_anchor(expected_block.seqno);
    if (!authenticated.ok())
      return authenticated.error();
    auto block = session_block(authenticated.value());
    if (block != expected_block)
      return Error{"session-birth-link"};

    td::Ref<vm::Cell> state;
    Result<std::optional<SessionBirthEpoch>> current{
        std::optional<SessionBirthEpoch>{expected_}};
    if (authenticated.value() == head_) {
      // The expected epoch was already derived once from this exact bound head.
      // Recomputing it here would create a second source for the same fact.
      state = head_state_;
    } else {
      if (!state_reader_)
        return Error{"session-history-state-unavailable"};
      auto loaded = state_reader_(authenticated.value());
      if (!loaded.ok())
        return loaded.error();
      state = std::move(loaded.value());

      current = derive_epoch(
          state, authenticated.value(), chain_, target_,
          [this, &authenticated, &state]() -> Result<NativeSessionIdInput> {
            if (!identity_reader_)
              return Error{"session-history-identity-unavailable"};
            return identity_reader_(authenticated.value(), state, target_);
          });
      if (!current.ok())
        return current.error();
    }

    remember(block, state);
    std::optional<SessionBirthBlock> parent;
    if (current.value() && *current.value() == expected_ && block.seqno != 0) {
      auto authenticated_parent = history_.finalized_anchor(block.seqno - 1);
      if (!authenticated_parent.ok())
        return authenticated_parent.error();
      parent = session_block(authenticated_parent.value());
    }
    return SessionBirthObservation{block, std::move(parent), current.value()};
  }

  Result<td::Ref<vm::Cell>> selected_state(
      const SessionBirthBlock& selected) const {
    if (latest_ && latest_->block == selected)
      return latest_->state;
    if (previous_ && previous_->block == selected)
      return previous_->state;
    return Error{"session-history-result-state"};
  }

 private:
  struct RetainedState {
    SessionBirthBlock block;
    td::Ref<vm::Cell> state;
  };

  void remember(const SessionBirthBlock& block, td::Ref<vm::Cell> state) {
    previous_ = std::move(latest_);
    latest_ = RetainedState{block, std::move(state)};
  }

  NativeFinalizedHistory history_;
  Anchor head_;
  td::Ref<vm::Cell> head_state_;
  ChainContext chain_;
  NativeSessionStateReader state_reader_;
  NativeSessionIdentityInputReader identity_reader_;
  SessionBirthEpoch expected_;
  tos::ShardIdFull target_;
  std::optional<RetainedState> latest_, previous_;
};
}  // namespace native_session_history_detail

inline Result<NativeSessionBirth> NativeSessionBirth::resolve(
    td::Ref<vm::Cell> head_state, const Anchor& head,
    const ChainContext& chain, const NativeSessionIdInput& identity,
    NativeBlockReader block_reader, NativeSessionStateReader state_reader,
    NativeSessionIdentityInputReader identity_reader,
    NativeSessionHistoryBudget budget) {
  auto finalized = NativeFinalizedHistory::open(
      head_state, head, chain, std::move(block_reader), budget.finalized);
  if (!finalized.ok())
    return finalized.error();

  auto expected = derive_native_session_epoch(head_state, head, chain, identity);
  if (!expected.ok())
    return expected.error();
  if (!expected.value())
    return Error{"session-birth-not-current"};

  native_session_history_detail::Source source(
      std::move(finalized.value()), head, head_state, chain,
      std::move(state_reader), std::move(identity_reader), *expected.value());
  auto read = [&source](const SessionBirthBlock& block) {
    return source.read(block);
  };
  auto selected = resolve_authenticated_session_birth(
      native_session_history_detail::session_block(head), *expected.value(),
      read, budget.observations);
  if (!selected.ok())
    return selected.error();
  auto selected_state = source.selected_state(selected.value().selected().block);
  if (!selected_state.ok())
    return selected_state.error();
  return NativeSessionBirth(std::move(selected.value()),
                            std::move(selected_state.value()));
}

}  // namespace tos::auth
