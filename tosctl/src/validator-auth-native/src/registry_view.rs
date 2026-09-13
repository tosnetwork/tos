use crate::{cells, native, registry::StateReadBudget};
use chain_block::{Cell, CellType, HashmapE, SliceData};
use std::{cell::RefCell, collections::BTreeMap};
use tos_validator_auth::{
    codec::{decode, Error, Hash, Wire},
    crypto::{object_id, AdmittedKey},
    lifecycle::{KeyHistory, KeySlot},
    types::*,
};
struct Cache {
    budget: StateReadBudget,
    identities: BTreeMap<Hash, Identity>,
    keys: BTreeMap<Hash, Key>,
}
// An anchored entry view provides no global mutation or maximum-epoch authority.
pub struct RegistryView {
    pub chain_domain: Hash,
    pub current_policy: Hash,
    policy: Policy,
    identities: Cell,
    keys: Cell,
    cache: RefCell<Cache>,
}
fn ordinary(cell: Cell) -> Result<SliceData, Error> {
    let s = native(SliceData::load_cell(cell))?;
    if s.cell_type() != CellType::Ordinary {
        return Err(Error("dictionary-shape"));
    }
    Ok(s)
}
fn read_hash(s: &mut SliceData) -> Result<Hash, Error> {
    native(s.get_next_bits(256))?.try_into().map_err(|_| Error("native-hash"))
}
fn read<T: Wire>(
    root: Cell,
    id: &Hash,
    maximum: usize,
    budget: &mut StateReadBudget,
) -> Result<T, Error> {
    let mut wrapper = ordinary(root)?;
    if wrapper.remaining_bits() != 1 {
        return Err(Error("dictionary-shape"));
    }
    let present = native(wrapper.get_next_bit())?;
    if wrapper.remaining_references() != usize::from(present) {
        return Err(Error("dictionary-shape"));
    }
    let dict = HashmapE::with_hashmap(
        256,
        if present { Some(native(wrapper.checked_drain_reference())?) } else { None },
    );
    let key = native(SliceData::load_bitstring(native(chain_block::BuilderData::with_raw(
        id.to_vec(),
        256,
    ))?))?;
    let leaf = native(dict.get(key))?.ok_or(Error("history-unavailable"))?;
    if leaf.remaining_bits() != 0 || leaf.remaining_references() != 1 {
        return Err(Error("dictionary-shape"));
    }
    budget.entries = budget.entries.checked_sub(1).ok_or(Error("state-resource"))?;
    let raw = cells::unpack_bytes(native(leaf.reference(0))?, budget.bytes.min(maximum))?;
    budget.bytes = budget.bytes.checked_sub(raw.len()).ok_or(Error("state-resource"))?;
    decode(&raw)
}
impl RegistryView {
    pub fn open(root: Cell, coordinate: u32, mut budget: StateReadBudget) -> Result<Self, Error> {
        if coordinate == u32::MAX {
            return Err(Error("config-context"));
        }
        let mut s = ordinary(root)?;
        if s.remaining_bits() != 880
            || s.remaining_references() != 4
            || native(s.get_next_u32())? != 0x76617131
            || native(s.get_next_u16())? != 1
        {
            return Err(Error("config-shape"));
        }
        let chain_domain = read_hash(&mut s)?;
        if chain_domain == [0; 32] || read_hash(&mut s)? != INTERFACE_FINGERPRINT {
            return Err(Error("interface-digest"));
        }
        native(s.get_next_u64())?;
        let current_policy = read_hash(&mut s)?;
        let identities = native(s.checked_drain_reference())?;
        let keys = native(s.checked_drain_reference())?;
        let policies = native(s.checked_drain_reference())?;
        let p: Policy = read(policies, &current_policy, 4096, &mut budget)?;
        if object_id("policy", &p)? != current_policy {
            return Err(Error("policy-hash"));
        }
        if p.revision == 0
            || p.effective_from > coordinate
            || p.interface_digest != INTERFACE_FINGERPRINT
            || p.phase != 0
            || p.suites != vec![Suite { suite: 1, parameters: 1 }]
            || p.max_envelope != 4096
            || p.max_certificate != 524288
        {
            return Err(Error("unsupported-profile"));
        }
        Ok(Self {
            chain_domain,
            current_policy,
            policy: p,
            identities,
            keys,
            cache: RefCell::new(Cache {
                budget,
                identities: BTreeMap::new(),
                keys: BTreeMap::new(),
            }),
        })
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn identity(&self, id: &Hash) -> Result<Identity, Error> {
        let mut cache = self.cache.try_borrow_mut().map_err(|_| Error("registry-view-reentry"))?;
        if let Some(value) = cache.identities.get(id) {
            return Ok(value.clone());
        }
        if *id == [0; 32] {
            return Err(Error("identity-key"));
        }
        let value: Identity = read(self.identities.clone(), id, 4096, &mut cache.budget)?;
        if value.identity != *id || value.stake_id == [0; 32] {
            return Err(Error("identity-key"));
        }
        cache.identities.insert(*id, value.clone());
        Ok(value)
    }
    pub fn remaining(&self) -> Result<StateReadBudget, Error> {
        Ok(self.cache.try_borrow().map_err(|_| Error("registry-view-reentry"))?.budget)
    }
}
impl KeyHistory for RegistryView {
    fn find(&self, id: &Hash) -> Result<Key, Error> {
        let mut cache = self.cache.try_borrow_mut().map_err(|_| Error("registry-view-reentry"))?;
        if let Some(value) = cache.keys.get(id) {
            return Ok(value.clone());
        }
        let key: Key = read(self.keys.clone(), id, 32768, &mut cache.budget)?;
        if object_id("key", &key)? != *id {
            return Err(Error("key-hash"));
        }
        if key.identity == [0; 32]
            || !(1..=5).contains(&key.role)
            || key.suite != 1
            || key.parameters != 1
            || key.epoch == 0
            || key.epoch == u64::MAX
            || key.valid_from >= key.valid_until
            || key.capacity_domain != [0; 32]
            || key.capacity_limit != 0
        {
            return Err(Error("key-descriptor"));
        }
        AdmittedKey::admit(&key.public_key)?;
        cache.keys.insert(*id, key.clone());
        Ok(key)
    }
    fn latest_epoch(&self, _identity: &Hash, _slot: KeySlot) -> Result<u64, Error> {
        Err(Error("read-only-view"))
    }
    fn ever_registered(&self, _identity: &Hash) -> Result<bool, Error> {
        Err(Error("read-only-view"))
    }
}
