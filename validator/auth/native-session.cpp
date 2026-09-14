#include "auto/tl/tos_api.h"
#include "auto/tl/tos_api.hpp"
#include "block/mc-config.h"
#include "keys/keys.hpp"
#include "tl-utils/tl-utils.hpp"
#include "vm/cells/CellSlice.h"

#include "native-session.h"
namespace tos::auth {
namespace {
Hash hash(td::Slice raw) {
  Hash value{};
  if (raw.size() == value.size())
    std::copy(raw.ubegin(), raw.uend(), value.begin());
  return value;
}

// The exact three forms the manager selects between. Reproducing the selection
// here rather than always emitting the newest one matters: the identity is the
// hash of whichever form was chosen, so emitting a different constructor would
// name a session that never existed even with identical field values.
Hash session_identity(tos::ShardIdFull shard, const std::vector<tos::ValidatorDescr>& members,
                      std::uint32_t catchain, td::Bits256 options, std::uint32_t vertical,
                      std::uint32_t key_block, bool new_catchain_ids) {
  std::vector<tl_object_ptr<tos_api::validator_groupMember>> encoded;
  encoded.reserve(members.size());
  for (const auto& member : members) {
    auto key = PublicKey{pubkeys::Ed25519{member.key}};
    encoded.push_back(create_tl_object<tos_api::validator_groupMember>(key.compute_short_id().bits256_value(),
                                                                      member.addr, member.weight));
  }
  td::Bits256 identity;
  if (!new_catchain_ids) {
    if (vertical == 0)
      identity = create_hash_tl_object<tos_api::validator_group>(shard.workchain, shard.shard, catchain, options,
                                                                 std::move(encoded));
    else
      identity = create_hash_tl_object<tos_api::validator_groupEx>(shard.workchain, shard.shard, vertical, catchain,
                                                                   options, std::move(encoded));
  } else {
    identity = create_hash_tl_object<tos_api::validator_groupNew>(shard.workchain, shard.shard, vertical, key_block,
                                                                  catchain, options, std::move(encoded));
  }
  return hash(identity.as_slice());
}
}  // namespace

Result<std::optional<SessionBirthEpoch>> native_session_epoch(const block::ConfigInfo& config, tos::ShardIdFull shard,
                                                              const NativeSessionContext& context) {
  try {
    if (!shard.is_valid_ext() || tos::shard_pfx_len(shard.shard) > tos::max_shard_pfx_len ||
        (shard.is_masterchain() && shard.shard != tos::shardIdAll))
      return Error{"session-epoch-shard"};

    // The election cell is the member list's origin. Binding its hash lets a
    // later observation disagree about the roster under an unchanged identity
    // instead of being read as a new session.
    auto election_cell = config.get_config_param(35, 34);
    if (election_cell.is_null())
      return Error{"session-epoch-election"};
    auto election = block::Config::unpack_validator_set(election_cell);
    if (election.is_error())
      return Error{"session-epoch-election"};

    tos::CatchainSeqno catchain = 0;
    auto members = config.compute_validator_set_cc(shard, *election.ok(), config.utime, &catchain);
    if (members.empty())
      return std::optional<SessionBirthEpoch>{};

    // The key block coordinate enters the identity only in the newest form.
    // Refusing a state without one would refuse chains that have not produced a
    // key block yet, for a value those forms never hash.
    tos::BlockIdExt key_block;
    tos::LogicalTime key_lt = 0;
    if (!config.get_last_key_block(key_block, key_lt) && context.new_catchain_ids)
      return Error{"session-epoch-key-block"};

    SessionBirthEpoch epoch;
    epoch.workchain = shard.workchain;
    epoch.shard = shard.shard;
    epoch.catchain = catchain;
    epoch.vertical_seqno = context.vertical_seqno;
    epoch.key_block_seqno = key_block.seqno();
    epoch.native_options_hash = context.options_hash;
    epoch.election_cell_hash = hash(election_cell->get_hash().as_slice());
    td::Bits256 options;
    options.as_slice().copy_from(
        td::Slice(reinterpret_cast<const char*>(context.options_hash.data()), context.options_hash.size()));
    epoch.native_session_id = session_identity(shard, members, epoch.catchain, options, epoch.vertical_seqno,
                                               epoch.key_block_seqno, context.new_catchain_ids);
    if (!session_birth_detail::valid_epoch(epoch))
      return Error{"session-epoch-invalid"};
    return std::optional<SessionBirthEpoch>{epoch};
  } catch (const vm::VmError&) {
    return Error{"session-epoch-cell"};
  } catch (const vm::VmVirtError&) {
    return Error{"session-epoch-pruned"};
  }
}

Result<std::optional<SessionBirthEpoch>> native_session_epoch(td::Ref<vm::Cell> masterchain_state,
                                                              const Anchor& anchor, tos::ShardIdFull shard,
                                                              const NativeSessionContext& context, StateReadBudget) {
  if (masterchain_state.is_null())
    return Error{"session-epoch-state"};
  if (anchor.seqno_ == std::numeric_limits<std::uint32_t>::max() || anchor.root_ == Hash{} || anchor.file_ == Hash{})
    return Error{"session-epoch-anchor"};
  tos::BlockIdExt id{tos::BlockId{tos::masterchainId, tos::shardIdAll, anchor.seqno_}};
  id.root_hash.as_slice().copy_from(
      td::Slice(reinterpret_cast<const char*>(anchor.root_.data()), anchor.root_.size()));
  id.file_hash.as_slice().copy_from(
      td::Slice(reinterpret_cast<const char*>(anchor.file_.data()), anchor.file_.size()));
  auto config = block::ConfigInfo::extract_config(
      masterchain_state, id, block::ConfigInfo::needValidatorSet | block::ConfigInfo::needCapabilities);
  if (config.is_error())
    return Error{"session-epoch-config"};
  return native_session_epoch(*config.ok(), shard, context);
}
}  // namespace tos::auth
