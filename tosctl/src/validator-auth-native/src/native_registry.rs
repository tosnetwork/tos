use crate::{
    cells, native,
    native_apply::{
        CurrentRegistry, FinalizedAnchorSource, NativeIdentityContext, NativeLifecycleAuthority,
    },
    registry::{RegistryState, StateReadBudget},
};
use chain_block::{BuilderData, Cell, CellType, HashmapE, HashmapType, IBitstring, SliceData};
use std::{cell::RefCell, collections::BTreeSet};
use tos_validator_auth::{
    codec::{decode, encode, Error, Hash, Wire},
    crypto::object_id,
    lifecycle::{
        apply_due_transitions, apply_identity_update, IdentityChange, KeyHistory, KeySlot,
        LifecycleAuthority,
    },
    transfer::ObjectReader,
    types::*,
};
/// Only validated bootstrap/checkpoint paths construct this type. Successors
/// share immutable native cell paths instead of copying the public archive.
#[derive(Clone)]
pub struct NativeRegistry {
    identities: Cell,
    keys: Cell,
    policies: Cell,
    control: Cell,
    epochs: Cell,
    due: Cell,
    schedule: Cell,
    domain: Hash,
    policy: Hash,
    revision: u64,
    coordinate: u32,
    budget: RefCell<StateReadBudget>,
}
fn need(ok: bool, reason: &'static str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error(reason))
    }
}
fn hash(cell: &Cell) -> Result<Hash, Error> {
    Ok(*cell.repr_hash().as_slice())
}
fn ordinary(cell: Cell) -> Result<SliceData, Error> {
    let s = native(SliceData::load_cell(cell))?;
    need(s.cell_type() == CellType::Ordinary, "index-shape")?;
    Ok(s)
}
fn dict(root: Cell, width: usize) -> Result<HashmapE, Error> {
    let mut s = ordinary(root)?;
    need(s.remaining_bits() == 1, "index-shape")?;
    let present = native(s.get_next_bit())?;
    need(s.remaining_references() == usize::from(present), "index-shape")?;
    Ok(HashmapE::with_hashmap(
        width,
        if present { Some(native(s.checked_drain_reference())?) } else { None },
    ))
}
fn wrap(d: &HashmapE) -> Result<Cell, Error> {
    let mut b = BuilderData::new();
    native(d.write_hashmap_data(&mut b))?;
    native(b.into_cell())
}
fn bits(bytes: &[u8]) -> Result<SliceData, Error> {
    native(SliceData::load_bitstring(native(BuilderData::with_raw(
        bytes.to_vec(),
        bytes.len() * 8,
    ))?))
}
fn slot_key(id: &Hash, slot: KeySlot) -> Vec<u8> {
    let mut result = id.to_vec();
    result.push(slot.0);
    result.extend_from_slice(&slot.1.to_be_bytes());
    result.extend_from_slice(&slot.2.to_be_bytes());
    result
}
fn due_key(at: u32, id: &Hash) -> Vec<u8> {
    let mut result = at.to_be_bytes().to_vec();
    result.extend_from_slice(id);
    result
}
fn read_hash(s: &mut SliceData) -> Result<Hash, Error> {
    native(s.get_next_bits(256))?.try_into().map_err(|_| Error("native-hash"))
}
fn epoch_put(root: &mut Cell, key: &Key) -> Result<(), Error> {
    let mut d = dict(root.clone(), 296)?;
    let id = slot_key(&key.identity, (key.role, key.suite, key.parameters));
    let epoch = match native(d.get(bits(&id)?))? {
        Some(mut old) => native(old.get_next_u64())?,
        None => 0,
    };
    let mut value = BuilderData::new();
    native(value.append_u64(epoch.max(key.epoch)))?;
    native(d.set_builder(bits(&id)?, &value))?;
    *root = wrap(&d)?;
    Ok(())
}
fn schedules(root: &mut Cell, identity: &Identity, insert: bool) -> Result<(), Error> {
    let mut d = dict(root.clone(), 288)?;
    let heights: BTreeSet<_> = identity.pending.iter().map(|p| p.effective_from).collect();
    for at in heights {
        let key = bits(&due_key(at, &identity.identity))?;
        if insert {
            native(d.set_builder(key, &BuilderData::new()))?;
        } else {
            need(native(d.remove(key))?.is_some(), "due-index")?;
        }
    }
    *root = wrap(&d)?;
    Ok(())
}
impl NativeRegistry {
    fn charge(&self, bytes: usize) -> Result<(), Error> {
        let mut b = self.budget.try_borrow_mut().map_err(|_| Error("registry-reentry"))?;
        need(b.entries != 0 && bytes <= b.bytes, "state-resource")?;
        b.entries = b.entries.checked_sub(1).ok_or(Error("state-resource"))?;
        b.bytes = b.bytes.checked_sub(bytes).ok_or(Error("state-resource"))?;
        Ok(())
    }
    fn read<T: Wire>(&self, root: Cell, id: &Hash) -> Result<T, Error> {
        self.charge(0)?;
        let leaf = native(dict(root, 256)?.get(bits(id)?))?.ok_or(Error("unknown-entry"))?;
        need(leaf.remaining_bits() == 0 && leaf.remaining_references() == 1, "dictionary-shape")?;
        let mut b = self.budget.try_borrow_mut().map_err(|_| Error("registry-reentry"))?;
        let bytes = cells::unpack_bytes(native(leaf.reference(0))?, b.bytes.min(32768))?;
        b.bytes = b.bytes.checked_sub(bytes.len()).ok_or(Error("state-resource"))?;
        decode(&bytes)
    }
    fn put<T: Wire>(&self, root: Cell, id: &Hash, value: &T, add: bool) -> Result<Cell, Error> {
        let raw = encode(value)?;
        self.charge(raw.len())?;
        let mut d = dict(root, 256)?;
        let old = native(d.setref(bits(id)?, cells::pack_bytes(&raw)?))?;
        need(old.is_none() == add, "dictionary-write")?;
        wrap(&d)
    }
    pub fn bootstrap(root: Cell, at: u32, budget: StateReadBudget) -> Result<Self, Error> {
        let state = RegistryState::decode_cell(root.clone(), at, budget)?;
        let mut s = ordinary(root)?;
        let mut result = Self {
            identities: native(s.checked_drain_reference())?,
            keys: native(s.checked_drain_reference())?,
            policies: native(s.checked_drain_reference())?,
            control: native(s.checked_drain_reference())?,
            epochs: wrap(&HashmapE::with_bit_len(296))?,
            due: wrap(&HashmapE::with_bit_len(288))?,
            schedule: wrap(&HashmapE::with_bit_len(32))?,
            domain: *state.chain_domain(),
            policy: *state.current_policy(),
            revision: state.revision(),
            coordinate: at,
            budget: RefCell::new(StateReadBudget::default()),
        };
        for key in state.keys().values() {
            epoch_put(&mut result.epochs, key)?;
        }
        for identity in state.identities().values() {
            schedules(&mut result.due, identity, true)?;
        }
        let mut schedule = HashmapE::with_bit_len(32);
        for (id, p) in state.policies() {
            let mut value = BuilderData::new();
            native(value.append_raw(id, 256))?;
            need(
                native(schedule.set_builder(bits(&p.effective_from.to_be_bytes())?, &value))?
                    .is_none(),
                "policy-index",
            )?;
        }
        result.schedule = wrap(&schedule)?;
        Ok(result)
    }
    pub fn encode_cell(&self) -> Result<Cell, Error> {
        let mut b = BuilderData::new();
        native(b.append_u32(0x76617131))?;
        native(b.append_u16(1))?;
        native(b.append_raw(&self.domain, 256))?;
        native(b.append_raw(&INTERFACE_FINGERPRINT, 256))?;
        native(b.append_u64(self.revision))?;
        native(b.append_raw(&self.policy, 256))?;
        for cell in [&self.identities, &self.keys, &self.policies, &self.control] {
            native(b.checked_append_reference(cell.clone()))?;
        }
        native(b.into_cell())
    }
    pub fn checkpoint(&self) -> Result<Cell, Error> {
        let mut b = BuilderData::new();
        native(b.append_u32(0x76616e31))?;
        native(b.append_u16(1))?;
        native(b.append_u32(self.coordinate))?;
        for cell in
            [self.encode_cell()?, self.epochs.clone(), self.due.clone(), self.schedule.clone()]
        {
            native(b.checked_append_reference(cell))?;
        }
        native(b.into_cell())
    }
    pub fn restore(
        checkpoint: Cell,
        expected: &Hash,
        at: u32,
        budget: StateReadBudget,
    ) -> Result<Self, Error> {
        let mut s = ordinary(checkpoint.clone())?;
        need(
            s.remaining_bits() == 80
                && s.remaining_references() == 4
                && native(s.get_next_u32())? == 0x76616e31
                && native(s.get_next_u16())? == 1,
            "checkpoint-shape",
        )?;
        need(native(s.get_next_u32())? == at, "checkpoint-coordinate")?;
        let root = native(s.checked_drain_reference())?;
        need(hash(&root)? == *expected, "checkpoint-registry")?;
        let result = Self::bootstrap(root, at, budget)?;
        need(hash(&result.checkpoint()?)? == hash(&checkpoint)?, "checkpoint-index")?;
        Ok(result)
    }
    pub fn identity(&self, id: &Hash) -> Result<Identity, Error> {
        self.read(self.identities.clone(), id)
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn remaining(&self) -> Result<StateReadBudget, Error> {
        Ok(*self.budget.try_borrow().map_err(|_| Error("registry-reentry"))?)
    }
    fn apply(
        &self,
        at: u32,
        updates: &[(Update, Authorizations)],
        apply: impl FnMut(&Self, &Identity, &Update, &Authorizations) -> Result<IdentityChange, Error>,
        budget: StateReadBudget,
    ) -> Result<Self, Error> {
        need(
            self.coordinate < u32::MAX - 1 && self.coordinate.checked_add(1) == Some(at),
            "block-gap",
        )?;
        let mut next = self.clone();
        next.budget = RefCell::new(budget);
        let mut changed = false;
        loop {
            next.charge(0)?;
            let d = dict(next.due.clone(), 288)?;
            let Some((key, _)) = native(d.get_min(false, &mut 0))? else {
                break;
            };
            let mut key = native(SliceData::load_builder(key))?;
            let height = native(key.get_next_u32())?;
            need(height >= at, "state-overdue")?;
            if height != at {
                break;
            }
            let id = read_hash(&mut key)?;
            let before = next.identity(&id)?;
            let after = apply_due_transitions(&before, &next, self.coordinate, at)?;
            schedules(&mut next.due, &before, false)?;
            schedules(&mut next.due, &after, true)?;
            next.identities = next.put(next.identities.clone(), &id, &after, false)?;
            changed = true;
        }
        next.coordinate = at;
        next.charge(32)?;
        let d = dict(next.schedule.clone(), 32)?;
        let (_, mut selected) =
            native(d.find_leaf(bits(&at.to_be_bytes())?, false, true, false, &mut 0))?
                .ok_or(Error("policy-index"))?;
        need(
            selected.remaining_bits() == 256 && selected.remaining_references() == 0,
            "policy-index",
        )?;
        next.policy = read_hash(&mut selected)?;
        Self::apply_updates(&mut next, updates, apply)?;
        changed |= !updates.is_empty();
        if changed {
            next.revision = self.revision.checked_add(1).ok_or(Error("registry-revision"))?;
        }
        Ok(next)
    }
    fn apply_updates(
        next: &mut Self,
        updates: &[(Update, Authorizations)],
        mut apply: impl FnMut(
            &Self,
            &Identity,
            &Update,
            &Authorizations,
        ) -> Result<IdentityChange, Error>,
    ) -> Result<(), Error> {
        for (update, evidence) in updates {
            need(update.identity != [0; 32], "unknown-identity")?;
            let before = next.identity(&update.identity)?;
            let effect = apply(next, &before, update, evidence)?;
            if let Some(key) = effect.archived_key {
                next.keys = next.put(next.keys.clone(), &object_id("key", &key)?, &key, true)?;
                epoch_put(&mut next.epochs, &key)?;
            }
            schedules(&mut next.due, &before, false)?;
            schedules(&mut next.due, &effect.identity, true)?;
            next.identities =
                next.put(next.identities.clone(), &update.identity, &effect.identity, false)?;
        }
        Ok(())
    }
    pub fn apply_block(
        &self,
        at: u32,
        updates: &[(Update, Authorizations)],
        authority: &impl LifecycleAuthority,
        budget: StateReadBudget,
    ) -> Result<Self, Error> {
        self.apply(
            at,
            updates,
            |current, identity, update, evidence| {
                apply_identity_update(identity, current, update, evidence, at, authority)
            },
            budget,
        )
    }
    pub fn apply_native_block<
        F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>,
        H: FinalizedAnchorSource,
    >(
        &self,
        at: u32,
        updates: &[(Update, Authorizations)],
        context: &NativeIdentityContext<'_, H>,
        reader: &mut ObjectReader<F>,
        budget: StateReadBudget,
    ) -> Result<Self, Error> {
        self.apply(
            at,
            updates,
            |current, identity, update, evidence| {
                let authority = NativeLifecycleAuthority::new(current, context, reader);
                authority.validate_context()?;
                apply_identity_update(identity, current, update, evidence, at, &authority)
            },
            budget,
        )
    }
}
impl CurrentRegistry for NativeRegistry {
    fn chain_domain(&self) -> &Hash {
        &self.domain
    }
    fn current_policy(&self) -> &Hash {
        &self.policy
    }
    fn coordinate(&self) -> u32 {
        self.coordinate
    }
}
impl KeyHistory for NativeRegistry {
    fn find(&self, id: &Hash) -> Result<Key, Error> {
        self.read(self.keys.clone(), id)
    }
    fn latest_epoch(&self, id: &Hash, slot: KeySlot) -> Result<u64, Error> {
        self.charge(8)?;
        let d = dict(self.epochs.clone(), 296)?;
        match native(d.get(bits(&slot_key(id, slot))?))? {
            None => Ok(0),
            Some(mut leaf) => {
                need(
                    leaf.remaining_bits() == 64 && leaf.remaining_references() == 0,
                    "epoch-index",
                )?;
                native(leaf.get_next_u64())
            }
        }
    }
    fn ever_registered(&self, id: &Hash) -> Result<bool, Error> {
        self.charge(8)?;
        let d = dict(self.epochs.clone(), 296)?;
        match native(d.find_leaf(bits(&slot_key(id, (0, 0, 0)))?, true, true, false, &mut 0))? {
            None => Ok(false),
            Some((key, _)) => Ok(read_hash(&mut native(SliceData::load_builder(key))?)? == *id),
        }
    }
}

/// Immutable accepted transaction prefix of one native block. Only begin() creates
/// a prefix; failed requests never replace it. Restart replays the whole block
/// from its authenticated parent rather than trusting a caller-supplied revision.
#[derive(Clone)]
pub struct NativeRegistryBlock {
    accepted: NativeRegistry,
    parent_revision: u64,
}
impl NativeRegistryBlock {
    pub fn begin(parent: &NativeRegistry, at: u32, budget: StateReadBudget) -> Result<Self, Error> {
        let accepted = parent.apply(at, &[], |_, _, _, _| Err(Error("empty-replay")), budget)?;
        Ok(Self { accepted, parent_revision: parent.revision })
    }
    pub fn state(&self) -> &NativeRegistry {
        &self.accepted
    }
    pub fn apply_transaction<
        F: FnMut(&ObjectRef, u8) -> Result<Vec<u8>, Error>,
        H: FinalizedAnchorSource,
    >(
        &self,
        update: &Update,
        evidence: &Authorizations,
        context: &NativeIdentityContext<'_, H>,
        reader: &mut ObjectReader<F>,
    ) -> Result<Self, Error> {
        let mut accepted = self.accepted.clone();
        NativeRegistry::apply_updates(
            &mut accepted,
            &[(update.clone(), evidence.clone())],
            |view, identity, update, evidence| {
                let authority = NativeLifecycleAuthority::new(view, context, reader);
                authority.validate_context()?;
                apply_identity_update(identity, view, update, evidence, view.coordinate, &authority)
            },
        )?;
        accepted.revision =
            self.parent_revision.checked_add(1).ok_or(Error("registry-revision"))?;
        Ok(Self { accepted, parent_revision: self.parent_revision })
    }
}
