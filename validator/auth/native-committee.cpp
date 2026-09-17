#include "block/block-auto.h"
#include "block/mc-config.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"

#include "native-committee.h"
#include "registry-view.h"
namespace tos::auth {
namespace {
Hash hash(td::Slice raw) {
  Hash value{};
  if (raw.size() == value.size())
    std::copy(raw.ubegin(), raw.uend(), value.begin());
  return value;
}
}  // namespace
Result<std::vector<Key>> committee_identity_keys(const Identity& identity, const KeyHistory& archive,
                                                 std::uint32_t anchor, const std::set<Hash>& consensus_keys) {
  const std::vector<KeySlot> required{{1, 1, 1}, {2, 1, 1}, {3, 1, 1}, {4, 1, 1}, {5, 1, 1}};
  auto keys = select_identity_keys(identity, archive, anchor, required);
  if (!keys.ok())
    return keys.error();
  for (const auto& key : keys.value())
    if (consensus_keys.contains(hash({reinterpret_cast<const char*>(key.public_key_.data()), key.public_key_.size()})))
      return Error{"network-key-reuse"};
  return keys;
}

Result<AdmittedState> admit_masterchain_state(td::Ref<vm::Cell> root) {
  try {
    if (root.is_null())
      return Error{"masterchain-state"};
    block::gen::ShardStateUnsplit::Record header;
    if (!tlb::unpack_cell(root, header))
      return Error{"masterchain-state"};
    block::ShardId source(header.shard_id);
    if (source.workchain_id != -1 || source.shard_pfx_len != 0)
      return Error{"state-context"};
    auto config = block::Config::extract_from_state(root, block::Config::needCapabilities);
    if (config.is_error())
      return Error{"native-config"};
    auto held = config.move_as_ok();
    const auto& cfg = *held;
    if (cfg.get_global_version() < 16 || !(cfg.get_capabilities() & tos::capValidatorAuth))
      return Error{"committee-capability"};
    for (int index : {9, 10}) {
      auto param = cfg.get_config_param(index);
      if (param.is_null())
        return Error{"config-mandatory"};
      vm::Dictionary required(param, 32);
      std::array<std::uint8_t, 4> key{0, 0, 0, 46};
      auto entry = required.lookup(td::ConstBitPtr(key.data()), 32);
      if (entry.is_null() || entry->size() != 0 || entry->size_refs() != 0)
        return Error{"config-mandatory"};
    }
    block::gen::ConfigParam::Record_cons16 count;
    if (!block::gen::ConfigParam(16).cell_unpack(cfg.get_config_param(16), count) || count.max_validators > 400 ||
        count.max_main_validators > count.max_validators || count.min_validators < 1 ||
        count.min_validators > count.max_main_validators)
      return Error{"validator-count"};
    auto election_cell = cfg.get_config_param(35, 34);
    auto election = block::Config::unpack_validator_set(election_cell);
    if (election.is_error())
      return Error{"native-election"};
    auto held_election = election.move_as_ok();
    const auto& elected = *held_election;
    if (elected.total < 1 || static_cast<unsigned>(elected.total) > count.max_validators || elected.main < 1 ||
        static_cast<unsigned>(elected.main) > count.max_main_validators || elected.utime_since > header.gen_utime ||
        header.gen_utime >= elected.utime_until)
      return Error{"election-boundary"};
    // Parse the exact native selector before using it; its legacy fallback is
    // inappropriate for an authenticated P0 committee.
    auto selector = cfg.get_config_param(28);
    if (selector.is_null() || !block::gen::t_CatchainConfig.validate_ref(selector))
      return Error{"committee-selector"};
    std::set<Hash> identities, stakes, network_keys;
    for (const auto& member : elected.list) {
      if (!member.auth_binding)
        return Error{"election-binding-required"};
      auto identity = hash(member.auth_binding->identity.as_slice());
      auto stake = hash(member.auth_binding->stake_id.as_slice());
      if (!identities.insert(identity).second || !stakes.insert(stake).second ||
          !network_keys.insert(hash(member.pubkey.as_bits256().as_slice())).second)
        return Error{"election-duplicate"};
    }
    AdmittedState admitted;
    admitted.config = std::move(held);
    admitted.elected = std::move(held_election);
    admitted.election_cell = std::move(election_cell);
    admitted.consensus_keys = std::move(network_keys);
    admitted.gen_utime = header.gen_utime;
    admitted.network = header.global_id;
    admitted.seqno = header.seq_no;
    return admitted;
  } catch (const vm::VmError&) {
    return Error{"committee-cell"};
  } catch (const vm::VmVirtError&) {
    return Error{"committee-pruned"};
  }
}

Result<NativeCommittee> NativeCommittee::derive(td::Ref<vm::Cell> root, const Anchor& anchor, const ChainContext& chain,
                                                tos::ShardIdFull shard, std::uint32_t catchain,
                                                StateReadBudget budget) {
  try {
    if (!shard.is_valid_ext() || tos::shard_pfx_len(shard.shard) > tos::max_shard_pfx_len ||
        (shard.is_masterchain() && shard.shard != tos::shardIdAll))
      return Error{"committee-shard"};
    if (anchor.seqno_ == std::numeric_limits<std::uint32_t>::max() || anchor.root_ == Hash{} ||
        anchor.file_ == Hash{} || root.is_null() || hash(root->get_hash().as_slice()) != anchor.state_)
      return Error{"committee-anchor"};
    if (chain.genesis_root == Hash{} || chain.genesis_file == Hash{} || chain.chain_domain == Hash{})
      return Error{"chain-context"};
    auto state = admit_masterchain_state(root);
    if (!state.ok())
      return state.error();
    auto& admitted = state.value();
    // What the anchor and the chain context add to what the state already says.
    // The state's own shape is decided above, once, for every caller.
    if (admitted.network != chain.network || admitted.seqno != anchor.seqno_)
      return Error{"state-context"};
    const auto& cfg = *admitted.config;
    const auto& elected = *admitted.elected;
    const auto& network_keys = admitted.consensus_keys;
    auto registry = RegistryView::open(cfg.get_config_param(46), anchor.seqno_, budget);
    if (!registry.ok())
      return registry.error();
    if (registry.value().chain_domain() != chain.chain_domain)
      return Error{"chain-domain"};
    for (const auto& member : elected.list) {
      auto identity = hash(member.auth_binding->identity.as_slice());
      auto stake = hash(member.auth_binding->stake_id.as_slice());
      auto found = registry.value().identity(identity);
      if (!found.ok() || found.value().stake_id_ != stake)
        return Error{"election-registry-binding"};
    }
    auto selected = cfg.compute_validator_set(shard, elected, admitted.gen_utime, catchain);
    auto election_hash = hash(admitted.election_cell->get_hash().as_slice());
    auto election_id = digest("election", election_hash);
    if (!election_id.ok())
      return election_id.error();
    Committee committee{registry.value().current_policy(),
                        election_id.value(),
                        shard.workchain,
                        shard.shard,
                        catchain,
                        anchor.seqno_,
                        {}};
    for (const auto& member : selected) {
      if (!member.auth_binding)
        return Error{"selected-binding-required"};
      auto identity = hash(member.auth_binding->identity.as_slice());
      auto found = registry.value().identity(identity);
      if (!found.ok())
        return Error{"selected-identity"};
      auto keys = committee_identity_keys(found.value(), registry.value(), anchor.seqno_, network_keys);
      if (!keys.ok())
        return keys.error();
      committee.members_.push_back(
          {identity, found.value().stake_id_, member.weight, hash(member.addr.as_slice()), keys.value()});
    }
    std::sort(committee.members_.begin(), committee.members_.end(),
              [](const auto& a, const auto& b) { return a.identity_ < b.identity_; });
    auto snapshot = RegistrySnapshot::compile(committee, registry.value().policy());
    if (!snapshot.ok())
      return snapshot.error();
    return NativeCommittee(std::move(snapshot.value()), std::move(selected), anchor);
  } catch (const vm::VmError&) {
    return Error{"committee-cell"};
  } catch (const vm::VmVirtError&) {
    return Error{"committee-pruned"};
  }
}
}  // namespace tos::auth
