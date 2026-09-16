use crate::{cells, native};
use chain_block::{BuilderData, Cell, CellType, HashmapE, HashmapType, IBitstring, SliceData};
use std::collections::{BTreeMap, BTreeSet};
use tos_validator_auth::{
    codec::{decode, encode, Error, Hash, Wire},
    crypto::{object_id, AdmittedKey},
    lifecycle::{
        apply_due_transitions, apply_global_update, apply_identity_update, validate_identity,
        BlockChange, GlobalChange, GlobalContext, KeyHistory, KeySlot, LifecycleAuthority,
    },
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
#[derive(Clone)]
pub struct RegistryState {
    chain_domain: Hash,
    current_policy: Hash,
    revision: u64,
    coordinate: u32,
    activations: BTreeMap<Vec<u8>, Activation>,
    observations: BTreeMap<Hash, Observation>,
    due: BTreeMap<u32, BTreeSet<Hash>>,
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
fn store_dictionary<'a, K: AsRef<[u8]> + 'a, T: Wire + 'a>(
    width: usize,
    values: impl Iterator<Item = (&'a K, &'a T)>,
) -> Result<Cell, Error> {
    let mut dict = HashmapE::with_bit_len(width);
    for (id, value) in values {
        let mut key = BuilderData::new();
        native(key.append_raw(id.as_ref(), width))?;
        let slice = native(SliceData::load_builder(key))?;
        if native(dict.setref(slice, cells::pack_bytes(&encode(value)?)?))?.is_some() {
            return Err(Error("dictionary-key"));
        }
    }
    let mut wrapper = BuilderData::new();
    native(dict.write_hashmap_data(&mut wrapper))?;
    native(wrapper.into_cell())
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
        let revision = native(s.get_next_u64())?;
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
            revision,
            coordinate,
            activations,
            observations,
            due: BTreeMap::new(),
            identities,
            keys,
            policies,
            epochs: BTreeMap::new(),
        };
        state.validate()?;
        Ok(state)
    }
    fn validate(&mut self) -> Result<(), Error> {
        let state = self;
        let coordinate = state.coordinate;
        let current_policy = state.current_policy;
        if state.chain_domain == [0; 32] || coordinate == u32::MAX {
            return Err(Error("config-context"));
        }
        state.epochs.clear();
        state.due.clear();
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
                validate_identity(identity, state)?;
            }
            for pending in &identity.pending {
                if pending.effective_from <= coordinate {
                    return Err(Error("state-overdue"));
                }
                state.due.entry(pending.effective_from).or_default().insert(*id);
            }
        }
        let mut previous = [0; 32];
        let mut revision = 0u64;
        for (key, a) in &state.activations {
            let at =
                u32::from_be_bytes(key.as_slice().try_into().map_err(|_| Error("activation-key"))?);
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
            previous = object_id("activation", a)?;
        }
        // The converse, which nothing checked: a policy that takes effect is a
        // policy something attested to. The activation carries the finalized
        // checkpoint that witnessed the change, and policy_at selects purely by
        // coordinate, so a policy with no activation would govern every
        // committee and session from its boundary onward with no record that
        // the change ever happened.
        //
        // Which policy the attestation is about needs no check here: the loop
        // above requires every activation to name a policy effective at its own
        // coordinate, and policy_at refuses two policies sharing one.
        for p in state.policies.values() {
            if p.effective_from == 0 {
                continue;
            }
            if !state.activations.contains_key(p.effective_from.to_be_bytes().as_slice()) {
                return Err(Error("policy-activation"));
            }
        }
        for (id, o) in &state.observations {
            if object_id("observation", o)? != *id
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
        Ok(())
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn coordinate(&self) -> u32 {
        self.coordinate
    }
    pub fn identities(&self) -> &BTreeMap<Hash, Identity> {
        &self.identities
    }
    pub fn keys(&self) -> &BTreeMap<Hash, Key> {
        &self.keys
    }
    pub fn policies(&self) -> &BTreeMap<Hash, Policy> {
        &self.policies
    }
    /// Builds a registry from an independently approved offline allocation manifest.
    /// This constructor does not allocate stake or authenticate the manifest.
    pub fn genesis(
        domain: Hash,
        policy: Policy,
        identities: Vec<Identity>,
        keys: Vec<Key>,
    ) -> Result<Self, Error> {
        let id = object_id("policy", &policy)?;
        let mut state = Self {
            chain_domain: domain,
            current_policy: id,
            revision: 0,
            coordinate: 0,
            identities: BTreeMap::new(),
            keys: BTreeMap::new(),
            policies: BTreeMap::from([(id, policy)]),
            activations: BTreeMap::new(),
            observations: BTreeMap::new(),
            epochs: BTreeMap::new(),
            due: BTreeMap::new(),
        };
        for identity in identities {
            if state.identities.insert(identity.identity, identity).is_some() {
                return Err(Error("duplicate-identity"));
            }
        }
        for key in keys {
            if state.keys.insert(object_id("key", &key)?, key).is_some() {
                return Err(Error("duplicate-key"));
            }
        }
        state.validate()?;
        Ok(state)
    }
    pub fn encode_cell(&self) -> Result<Cell, Error> {
        let mut control = BuilderData::new();
        native(control.append_u32(0x76616331))?;
        native(control.checked_append_reference(store_dictionary(32, self.activations.iter())?))?;
        native(control.checked_append_reference(store_dictionary(256, self.observations.iter())?))?;
        let mut root = BuilderData::new();
        native(root.append_u32(0x76617131))?;
        native(root.append_u16(1))?;
        native(root.append_raw(&self.chain_domain, 256))?;
        native(root.append_raw(&INTERFACE_FINGERPRINT, 256))?;
        native(root.append_u64(self.revision))?;
        native(root.append_raw(&self.current_policy, 256))?;
        native(root.checked_append_reference(store_dictionary(256, self.identities.iter())?))?;
        native(root.checked_append_reference(store_dictionary(256, self.keys.iter())?))?;
        native(root.checked_append_reference(store_dictionary(256, self.policies.iter())?))?;
        native(root.checked_append_reference(native(control.into_cell())?))?;
        native(root.into_cell())
    }
    /// Replays one authenticated complete block. The parent is immutable and no
    /// successor escapes if an operation or its external authority check fails.
    pub fn apply_block(
        &self,
        at: u32,
        updates: &[(Update, Authorizations)],
        authority: &impl LifecycleAuthority,
    ) -> Result<Self, Error> {
        self.apply_identity_block(at, updates, |current, update, evidence| {
            if update.identity == [0; 32] {
                return Ok(BlockChange::Global(
                    current.apply_global(update, evidence, at, authority)?,
                ));
            }
            let identity =
                current.identities.get(&update.identity).ok_or(Error("unknown-identity"))?;
            Ok(BlockChange::Identity(apply_identity_update(
                identity, current, update, evidence, at, authority,
            )?))
        })
    }
    /// The pieces a global operation needs, gathered from this state rather
    /// than from the caller: the policy in force, the record holding the global
    /// nonce and the newest activation.
    pub(crate) fn apply_global(
        &self,
        update: &Update,
        evidence: &Authorizations,
        at: u32,
        authority: &impl LifecycleAuthority,
    ) -> Result<GlobalChange, Error> {
        let in_force =
            self.policies.get(&self.current_policy).ok_or(Error("global-current-policy"))?;
        // Absent until a global operation first writes one. Its only content is
        // the nonce, and the encoding already admits a zero-identity record
        // with no keys and no pending transitions.
        let global = self.identities.get(&[0; 32]).cloned().unwrap_or_default();
        let latest = self.activations.values().next_back();
        apply_global_update(
            update,
            evidence,
            &GlobalContext {
                current_policy: &self.current_policy,
                in_force,
                global: &global,
                latest,
            },
            at,
            authority,
        )
    }
    pub(crate) fn apply_identity_block(
        &self,
        at: u32,
        updates: &[(Update, Authorizations)],
        mut apply: impl FnMut(&Self, &Update, &Authorizations) -> Result<BlockChange, Error>,
    ) -> Result<Self, Error> {
        if self.coordinate >= u32::MAX - 1 || self.coordinate.checked_add(1) != Some(at) {
            return Err(Error("block-gap"));
        }
        let mut next = self.clone();
        let mut changed = false;
        if let Some(due) = self.due.get(&at) {
            for id in due {
                let current = next.identities.get(id).ok_or(Error("due-index"))?;
                let effect = apply_due_transitions(current, &next, self.coordinate, at)?;
                next.identities.insert(*id, effect);
                changed = true;
            }
        }
        next.due.remove(&at);
        next.coordinate = at;
        next.current_policy = object_id("policy", next.policy_at(at)?)?;
        for (update, evidence) in updates {
            if update.identity == [0; 32] {
                let effect = match apply(&next, update, evidence)? {
                    BlockChange::Global(effect) => effect,
                    BlockChange::Identity(_) => return Err(Error("global-target")),
                };
                let policy_id = object_id("policy", &effect.policy)?;
                if next.policies.insert(policy_id, effect.policy).is_some() {
                    return Err(Error("duplicate-policy"));
                }
                if next
                    .activations
                    .insert(
                        effect.activation.effective_from.to_be_bytes().to_vec(),
                        effect.activation,
                    )
                    .is_some()
                {
                    return Err(Error("duplicate-activation"));
                }
                next.identities.insert([0; 32], effect.global);
                changed = true;
                continue;
            }
            let current = next.identities.get(&update.identity).ok_or(Error("unknown-identity"))?;
            let effect = match apply(&next, update, evidence)? {
                BlockChange::Identity(effect) => effect,
                BlockChange::Global(_) => return Err(Error("operation-target")),
            };
            // Remove canceled schedules only for this identity, preserving other
            // identities due at the same coordinate.
            let old_due: BTreeSet<_> = current.pending.iter().map(|p| p.effective_from).collect();
            for coordinate in old_due {
                if let Some(ids) = next.due.get_mut(&coordinate) {
                    ids.remove(&update.identity);
                    if ids.is_empty() {
                        next.due.remove(&coordinate);
                    }
                }
            }
            if let Some(key) = effect.archived_key {
                let id = object_id("key", &key)?;
                next.epochs
                    .insert((key.identity, (key.role, key.suite, key.parameters)), key.epoch);
                if next.keys.insert(id, key).is_some() {
                    return Err(Error("duplicate-key"));
                }
            }
            for pending in &effect.identity.pending {
                next.due.entry(pending.effective_from).or_default().insert(update.identity);
            }
            next.identities.insert(update.identity, effect.identity);
            changed = true;
        }
        if changed {
            next.revision = self.revision.checked_add(1).ok_or(Error("registry-revision"))?;
        }
        Ok(next)
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
