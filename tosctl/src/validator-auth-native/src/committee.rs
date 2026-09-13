use crate::{
    native,
    registry::{RegistryState, StateReadBudget},
};
use chain_block::{
    CatchainConfig, Cell, CellType, Deserializable, HashmapE, McStateExtra, Serializable,
    ShardStateUnsplit, SliceData, ValidatorDescr, ValidatorSet,
};
use std::collections::BTreeSet;
use tos_validator_auth::{
    codec::{Error, Hash},
    crypto::digest,
    lifecycle::select_identity_keys,
    types::{Anchor, Committee, Member},
    verify::RegistrySnapshot,
};
#[derive(Clone)]
pub struct ChainContext {
    pub network: i32,
    pub genesis_root: Hash,
    pub genesis_file: Hash,
    pub chain_domain: Hash,
}
pub struct NativeCommittee {
    snapshot: RegistrySnapshot,
    transport_order: Vec<ValidatorDescr>,
    anchor: Anchor,
}
fn hash(raw: &[u8]) -> Result<Hash, Error> {
    raw.try_into().map_err(|_| Error("native-hash"))
}
fn parameter(config: &chain_block::ConfigParams, index: u32) -> Result<Cell, Error> {
    let entry = native(config.config_params.get(native(index.write_to_bitstring())?))?
        .ok_or(Error("native-config"))?;
    if entry.remaining_bits() != 0 || entry.remaining_references() != 1 {
        return Err(Error("native-config"));
    }
    native(entry.reference(0))
}
impl NativeCommittee {
    pub fn snapshot(&self) -> &RegistrySnapshot {
        &self.snapshot
    }
    pub fn transport_order(&self) -> &[ValidatorDescr] {
        &self.transport_order
    }
    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }
    pub fn derive(
        root: Cell,
        anchor: &Anchor,
        chain: &ChainContext,
        workchain: i32,
        shard: u64,
        catchain: u32,
        budget: StateReadBudget,
    ) -> Result<Self, Error> {
        if workchain == i32::MIN
            || shard == 0
            || shard.trailing_zeros() < 3
            || workchain == -1 && shard != 1 << 63
        {
            return Err(Error("committee-shard"));
        }
        if anchor.seqno == u32::MAX
            || anchor.root == [0; 32]
            || anchor.file == [0; 32]
            || root.repr_hash().as_slice() != &anchor.state
        {
            return Err(Error("committee-anchor"));
        }
        if chain.genesis_root == [0; 32]
            || chain.genesis_file == [0; 32]
            || chain.chain_domain == [0; 32]
        {
            return Err(Error("chain-context"));
        }
        let header = native(ShardStateUnsplit::construct_from_full_cell(root))?;
        if header.global_id() != chain.network
            || header.seq_no() != anchor.seqno
            || !header.shard().is_masterchain_ext()
        {
            return Err(Error("state-context"));
        }
        let extra = native(McStateExtra::construct_from_full_cell(
            header.custom_cell().ok_or(Error("native-config"))?,
        ))?;
        let config = &extra.config;
        let mut cap = native(SliceData::load_cell(parameter(config, 8)?))?;
        if cap.cell_type() != CellType::Ordinary
            || cap.remaining_bits() != 104
            || cap.remaining_references() != 0
            || native(cap.get_next_byte())? != 0xc4
        {
            return Err(Error("committee-capability"));
        }
        if native(cap.get_next_u32())? < 16 || native(cap.get_next_u64())? & 1024 == 0 {
            return Err(Error("committee-capability"));
        }
        for index in [9, 10] {
            let required = HashmapE::with_hashmap(32, Some(parameter(config, index)?));
            let entry = native(required.get(native(46u32.write_to_bitstring())?))?
                .ok_or(Error("config-mandatory"))?;
            if entry.remaining_bits() != 0 || entry.remaining_references() != 0 {
                return Err(Error("config-mandatory"));
            }
        }
        let mut count = native(SliceData::load_cell(parameter(config, 16)?))?;
        if count.cell_type() != CellType::Ordinary
            || count.remaining_bits() != 48
            || count.remaining_references() != 0
        {
            return Err(Error("validator-count"));
        }
        let maximum = native(count.get_next_u16())?;
        let main = native(count.get_next_u16())?;
        let minimum = native(count.get_next_u16())?;
        if maximum > 400 || main > maximum || minimum < 1 || minimum > main {
            return Err(Error("validator-count"));
        }
        let election_cell = if native(config.config_present(35))? {
            parameter(config, 35)?
        } else {
            parameter(config, 34)?
        };
        let election = native(ValidatorSet::construct_from_full_cell(election_cell.clone()))?;
        if election.total() == 0
            || election.total() > maximum
            || election.main() == 0
            || election.main() > main
            || election.utime_since() > header.gen_time()
            || header.gen_time() >= election.utime_until()
        {
            return Err(Error("election-boundary"));
        }
        let mut selector =
            native(CatchainConfig::construct_from_full_cell(parameter(config, 28)?))?;
        if selector.isolate_mc_validators
            || selector.mc_catchain_lifetime == 0
            || selector.shard_catchain_lifetime == 0
            || selector.shard_validators_lifetime == 0
            || selector.shard_validators_num == 0
        {
            return Err(Error("committee-selector"));
        }
        let registry = RegistryState::decode_cell(parameter(config, 46)?, anchor.seqno, budget)?;
        if registry.chain_domain != chain.chain_domain {
            return Err(Error("chain-domain"));
        }
        let mut identities = BTreeSet::new();
        let mut stakes = BTreeSet::new();
        let mut network_keys = BTreeSet::new();
        for member in election.list() {
            let binding = member.auth_binding.as_ref().ok_or(Error("election-binding-required"))?;
            let id = hash(binding.identity.as_slice())?;
            let stake = hash(binding.stake_id.as_slice())?;
            if !identities.insert(id)
                || !stakes.insert(stake)
                || !network_keys.insert(hash(member.public_key.as_slice())?)
            {
                return Err(Error("election-duplicate"));
            }
            let identity =
                registry.identities.get(&id).ok_or(Error("election-registry-binding"))?;
            if identity.stake_id != stake {
                return Err(Error("election-registry-binding"));
            }
        }
        // The native selector takes min(u32 requested, total) before narrowing.
        // Bound this input before the inherited Rust selector's u16 conversion.
        selector.shard_validators_num =
            selector.shard_validators_num.min(u32::from(election.total()));
        let (selected, _) = native(election.calc_subset(&selector, shard, workchain, catchain))?;
        let mut committee = Committee {
            policy: registry.current_policy,
            election: digest("election", election_cell.repr_hash().as_slice())?,
            workchain,
            shard,
            catchain,
            anchor_mc: anchor.seqno,
            members: Vec::new(),
        };
        for member in &selected {
            let binding = member.auth_binding.as_ref().ok_or(Error("selected-binding-required"))?;
            let id = hash(binding.identity.as_slice())?;
            let identity = registry.identities.get(&id).ok_or(Error("selected-identity"))?;
            let keys = select_identity_keys(
                identity,
                &registry,
                anchor.seqno,
                &[(1, 1, 1), (2, 1, 1), (3, 1, 1), (4, 1, 1), (5, 1, 1)],
            )?;
            for key in &keys {
                if network_keys.contains(&hash(&key.public_key)?) {
                    return Err(Error("network-key-reuse"));
                }
            }
            let adnl = member.adnl_addr.as_ref().ok_or(Error("election-binding-required"))?;
            committee.members.push(Member {
                identity: id,
                stake_id: identity.stake_id,
                weight: member.weight,
                adnl_id: hash(adnl.as_slice())?,
                keys,
            });
        }
        committee.members.sort_by_key(|m| m.identity);
        let snapshot = RegistrySnapshot::compile(&committee, registry.policy_at(anchor.seqno)?)?;
        Ok(Self { snapshot, transport_order: selected, anchor: anchor.clone() })
    }
}
