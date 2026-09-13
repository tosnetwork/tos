use crate::{cells, native};
use chain_block::{Cell, CellType, HashmapE, HashmapType, SliceData};
use std::collections::{BTreeMap, BTreeSet};
use tos_validator_auth::{
    codec::{decode, Error, Hash, Wire},
    crypto::{object_id, AdmittedKey},
    lifecycle::{validate_identity, KeyHistory, KeySlot},
    types::*,
};
#[derive(Clone, Copy)]
pub struct StateReadBudget {
    pub entries: usize,
    pub bytes: usize,
}
impl Default for StateReadBudget {
    fn default() -> Self {
        Self { entries: 1_000_000, bytes: 268_435_456 }
    }
}
pub struct RegistryState {
    chain_domain: Hash,
    current_policy: Hash,
    pub(crate) identities: BTreeMap<Hash, Identity>,
    keys: BTreeMap<Hash, Key>,
    policies: BTreeMap<Hash, Policy>,
    epochs: BTreeMap<(Hash, KeySlot), u64>,
}
fn ordinary(cell: Cell) -> Result<SliceData, Error> {
    let s = native(SliceData::load_cell(cell))?;
    if s.cell_type() != CellType::Ordinary || s.level() != 0 {
        return Err(Error("dictionary-shape"));
    }
    Ok(s)
}
fn read_hash(s: &mut SliceData) -> Result<Hash, Error> {
    native(s.get_next_bits(256))?.try_into().map_err(|_| Error("native-hash"))
}
fn dictionary<T: Wire>(
    cell: Cell,
    width: usize,
    budget: &mut StateReadBudget,
) -> Result<BTreeMap<Vec<u8>, T>, Error> {
    let mut s = ordinary(cell)?;
    if s.remaining_bits() != 1 {
        return Err(Error("dictionary-shape"));
    }
    let present = native(s.get_next_bit())?;
    if s.remaining_references() != usize::from(present) {
        return Err(Error("dictionary-shape"));
    }
    let root = if present { Some(native(s.checked_drain_reference())?) } else { None };
    let dict = HashmapE::with_hashmap(width, root);
    let mut result = BTreeMap::new();
    let mut failure = Error("dictionary-shape");
    let complete = native(dict.iterate_slices(|mut key, mut value| {
        let entry = (|| -> Result<(), Error> {
            if key.remaining_bits() != width
                || value.remaining_bits() != 0
                || value.remaining_references() != 1
            {
                return Err(Error("dictionary-shape"));
            }
            budget.entries = budget.entries.checked_sub(1).ok_or(Error("state-resource"))?;
            let raw = cells::unpack_bytes(native(value.checked_drain_reference())?, budget.bytes)?;
            budget.bytes = budget.bytes.checked_sub(raw.len()).ok_or(Error("state-resource"))?;
            let id = native(key.get_next_bits(width))?;
            if result.insert(id, decode::<T>(&raw)?).is_some() {
                return Err(Error("dictionary-key"));
            }
            Ok(())
        })();
        match entry {
            Ok(()) => Ok(true),
            Err(error) => {
                failure = error;
                Ok(false)
            }
        }
    }))?;
    if !complete {
        return Err(failure);
    }
    Ok(result)
}
fn map256<T: Wire>(cell: Cell, budget: &mut StateReadBudget) -> Result<BTreeMap<Hash, T>, Error> {
    dictionary(cell, 256, budget)?
        .into_iter()
        .map(|(k, v)| Ok((k.try_into().map_err(|_| Error("dictionary-key"))?, v)))
        .collect()
}
impl RegistryState {
    pub fn chain_domain(&self) -> &Hash {
        &self.chain_domain
    }
    pub fn current_policy(&self) -> &Hash {
        &self.current_policy
    }
    pub fn decode_cell(
        root: Cell,
        coordinate: u32,
        mut budget: StateReadBudget,
    ) -> Result<Self, Error> {
        let mut s = ordinary(root)?;
        if s.remaining_bits() != 880
            || s.remaining_references() != 4
            || native(s.get_next_u32())? != 0x76617131
            || native(s.get_next_u16())? != 1
        {
            return Err(Error("config-shape"));
        }
        let chain_domain = read_hash(&mut s)?;
        if chain_domain == [0; 32] || coordinate == u32::MAX {
            return Err(Error("config-context"));
        }
        if read_hash(&mut s)? != INTERFACE_FINGERPRINT {
            return Err(Error("interface-digest"));
        }
        native(s.get_next_u64())?;
        let current_policy = read_hash(&mut s)?;
        let identities = map256::<Identity>(native(s.checked_drain_reference())?, &mut budget)?;
        let keys = map256::<Key>(native(s.checked_drain_reference())?, &mut budget)?;
        let policies = map256::<Policy>(native(s.checked_drain_reference())?, &mut budget)?;
        let mut control = ordinary(native(s.checked_drain_reference())?)?;
        if control.remaining_bits() != 32
            || control.remaining_references() != 2
            || native(control.get_next_u32())? != 0x76616331
        {
            return Err(Error("control-shape"));
        }
        let activations =
            dictionary::<Activation>(native(control.checked_drain_reference())?, 32, &mut budget)?;
        let observations =
            map256::<Observation>(native(control.checked_drain_reference())?, &mut budget)?;
        let mut state = Self {
            chain_domain,
            current_policy,
            identities,
            keys,
            policies,
            epochs: BTreeMap::new(),
        };
        let policy = state.policy_at(coordinate)?;
        if object_id("policy", policy)? != current_policy {
            return Err(Error("current-policy"));
        }
        let mut unique_epochs = BTreeSet::new();
        for (id, k) in &state.keys {
            if object_id("key", k)? != *id
                || k.identity == [0; 32]
                || !state.identities.contains_key(&k.identity)
            {
                return Err(Error("key-hash-identity"));
            }
            if !(1..=5).contains(&k.role)
                || k.suite != 1
                || k.parameters != 1
                || k.epoch == 0
                || k.epoch == u64::MAX
                || k.valid_from >= k.valid_until
                || k.capacity_domain != [0; 32]
                || k.capacity_limit != 0
            {
                return Err(Error("key-descriptor"));
            }
            AdmittedKey::admit(&k.public_key)?;
            let slot = (k.role, k.suite, k.parameters);
            if !unique_epochs.insert((k.identity, slot, k.epoch)) {
                return Err(Error("duplicate-key-epoch"));
            }
            let epoch = state.epochs.entry((k.identity, slot)).or_default();
            *epoch = (*epoch).max(k.epoch);
        }
        for (id, identity) in &state.identities {
            if *id != identity.identity {
                return Err(Error("identity-key"));
            }
            if *id == [0; 32] {
                if !identity.active.is_empty() || !identity.pending.is_empty() {
                    return Err(Error("global-identity"));
                }
            } else {
                validate_identity(identity, &state)?;
            }
            if identity.pending.iter().any(|p| p.effective_from <= coordinate) {
                return Err(Error("state-overdue"));
            }
        }
        let mut previous = [0; 32];
        let mut revision = 0u64;
        for (key, a) in activations {
            let at = u32::from_be_bytes(key.try_into().map_err(|_| Error("activation-key"))?);
            let p = state.policies.get(&a.next_policy).ok_or(Error("activation-history"))?;
            revision = revision.checked_add(1).ok_or(Error("activation-history"))?;
            if at != a.effective_from
                || p.effective_from != at
                || a.checkpoint_seqno >= at
                || a.checkpoint_root == [0; 32]
                || a.checkpoint_file == [0; 32]
                || a.checkpoint_state == [0; 32]
                || a.revision != revision
                || a.previous != previous
            {
                return Err(Error("activation-history"));
            }
            previous = object_id("activation", &a)?;
        }
        for (id, o) in observations {
            if object_id("observation", &o)? != id
                || o.suite == 0
                || o.parameters == 0
                || o.valid_from >= o.valid_until
                || o.enabled > 1
            {
                return Err(Error("observation"));
            }
            if o.enabled != 0 {
                return Err(Error("unapproved-observation"));
            }
        }
        Ok(state)
    }
    pub fn policy_at(&self, at: u32) -> Result<&Policy, Error> {
        if at == u32::MAX || self.policies.is_empty() {
            return Err(Error("policy-history"));
        }
        let mut ordered: Vec<_> = self.policies.iter().collect();
        ordered.sort_by_key(|(_, p)| p.effective_from);
        let mut previous = [0; 32];
        let mut revision = 0u64;
        let mut height = None;
        let mut selected = None;
        for (id, p) in ordered {
            revision = revision.checked_add(1).ok_or(Error("policy-history"))?;
            if object_id("policy", p)? != *id {
                return Err(Error("policy-hash"));
            }
            if p.revision != revision
                || p.previous != previous
                || height.is_none() && p.effective_from != 0
                || height.is_some_and(|h| p.effective_from <= h)
            {
                return Err(Error("policy-history"));
            }
            if p.interface_digest != INTERFACE_FINGERPRINT
                || p.phase != 0
                || p.suites != vec![Suite { suite: 1, parameters: 1 }]
                || p.max_envelope != 4096
                || p.max_certificate != 524288
            {
                return Err(Error("unsupported-profile"));
            }
            if p.effective_from <= at {
                selected = Some(p);
            }
            previous = *id;
            height = Some(p.effective_from);
        }
        selected.ok_or(Error("policy-history"))
    }
}
impl KeyHistory for RegistryState {
    fn find(&self, id: &Hash) -> Result<Key, Error> {
        self.keys.get(id).cloned().ok_or(Error("unknown-key"))
    }
    fn latest_epoch(&self, identity: &Hash, slot: KeySlot) -> Result<u64, Error> {
        Ok(self.epochs.get(&(*identity, slot)).copied().unwrap_or(0))
    }
    fn ever_registered(&self, identity: &Hash) -> Result<bool, Error> {
        Ok(self.epochs.keys().any(|(id, _)| id == identity))
    }
}
