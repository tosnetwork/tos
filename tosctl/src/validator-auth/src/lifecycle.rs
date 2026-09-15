use crate::{
    codec::{decode, encode, Error, Hash},
    crypto::{object_id, AdmittedKey},
    types::*,
    verify::key_reference,
};
use std::collections::{BTreeMap, BTreeSet};
pub type KeySlot = (u8, u16, u16);
pub trait KeyHistory {
    fn find(&self, id: &Hash) -> Result<Key, Error>;
    fn latest_epoch(&self, identity: &Hash, slot: KeySlot) -> Result<u64, Error>;
    fn ever_registered(&self, identity: &Hash) -> Result<bool, Error>;
}
pub trait LifecycleAuthority {
    fn owner(&self, proof: &OwnerAuth, update: &Update, identity: &Identity)
        -> Result<bool, Error>;
    fn possession(&self, proof: &PossessionAuth, update: &Update, key: &Key)
        -> Result<bool, Error>;
    fn administration(
        &self,
        proof: &IdentityAuth,
        update: &Update,
        identity: &Identity,
        inclusion: u32,
    ) -> Result<bool, Error>;
}
pub struct IdentityChange {
    pub identity: Identity,
    pub archived_key: Option<Key>,
}
fn key_slot(k: &Key) -> KeySlot {
    (k.role, k.suite, k.parameters)
}
fn ref_slot(k: &Roleref) -> KeySlot {
    (k.role, k.key.suite, k.key.parameters)
}
fn transition_slot(k: &Transition) -> KeySlot {
    (k.role, k.suite, k.parameters)
}
const MAX_DELAY: u32 = 65_536;
struct Overlay<'a, H> {
    parent: &'a H,
    key: &'a Key,
    id: Hash,
}
impl<H: KeyHistory> KeyHistory for Overlay<'_, H> {
    fn find(&self, id: &Hash) -> Result<Key, Error> {
        if *id == self.id {
            Ok(self.key.clone())
        } else {
            self.parent.find(id)
        }
    }
    fn latest_epoch(&self, identity: &Hash, slot: KeySlot) -> Result<u64, Error> {
        self.parent.latest_epoch(identity, slot)
    }
    fn ever_registered(&self, identity: &Hash) -> Result<bool, Error> {
        self.parent.ever_registered(identity)
    }
}
fn verified<T>(
    needed: bool,
    rows: &[T],
    callback: impl FnOnce(&T) -> Result<bool, Error>,
) -> Result<(), Error> {
    if rows.len() != usize::from(needed) {
        return Err(Error("authority-shape"));
    }
    if needed && !callback(&rows[0])? {
        return Err(Error("authority-refused"));
    }
    Ok(())
}
pub fn validate_identity(state: &Identity, archive: &impl KeyHistory) -> Result<(), Error> {
    encode(state)?;
    if state.identity == [0; 32] || state.stake_id == [0; 32] {
        return Err(Error("identity-allocation"));
    }
    let mut active = BTreeMap::new();
    let mut slots = BTreeSet::new();
    let mut previous = (0, 0, 0);
    for reference in &state.active {
        let slot = ref_slot(reference);
        if slot <= previous
            || !(1..=5).contains(&reference.role)
            || reference.key.suite == 0
            || reference.key.parameters == 0
        {
            return Err(Error("state-order"));
        }
        previous = slot;
        let key = archive.find(&reference.key.key_id)?;
        if key_reference(&key)? != reference.key
            || key.identity != state.identity
            || key.role != reference.role
        {
            return Err(Error("archive-binding"));
        }
        active.insert(slot, reference.key.key_id);
        slots.insert(slot);
    }
    previous = (0, 0, 0);
    for pending in &state.pending {
        let slot = transition_slot(pending);
        if slot <= previous
            || !(1..=5).contains(&pending.role)
            || pending.suite == 0
            || pending.parameters == 0
        {
            return Err(Error("state-order"));
        }
        previous = slot;
        slots.insert(slot);
        if !(1..=3).contains(&pending.operation) {
            return Err(Error("pending-operation"));
        }
        if pending.accepted_at >= pending.effective_from
            || pending.effective_from == u32::MAX
            || pending
                .effective_from
                .checked_sub(pending.accepted_at)
                .is_none_or(|delay| delay > MAX_DELAY)
        {
            return Err(Error("pending-coordinate"));
        }
        if pending.nonce >= state.next_nonce
            || [pending.update_id, pending.authorization_id, pending.predecessor].contains(&[0; 32])
        {
            return Err(Error("pending-acceptance"));
        }
        let old = active.get(&slot).copied().unwrap_or([0; 32]);
        if old != pending.old_key
            || (pending.old_key == [0; 32]) != (pending.operation == 1)
            || (pending.new_key == [0; 32]) != (pending.operation == 3)
        {
            return Err(Error("pending-old"));
        }
        if pending.new_key != [0; 32] {
            let key = archive.find(&pending.new_key)?;
            if object_id("key", &key)? != pending.new_key
                || key.identity != state.identity
                || key_slot(&key) != slot
                || key.valid_from != pending.effective_from
                || key.valid_until <= pending.effective_from
            {
                return Err(Error("pending-key"));
            }
        }
    }
    if slots.len() > 10 {
        return Err(Error("role-component-bound"));
    }
    let mut count = [0u8; 5];
    for (role, _, _) in slots {
        let index = usize::from(role - 1);
        count[index] += 1;
        if count[index] > 2 {
            return Err(Error("role-component-bound"));
        }
    }
    Ok(())
}
pub fn apply_due_transitions(
    parent: &Identity,
    archive: &impl KeyHistory,
    parent_coordinate: u32,
    coordinate: u32,
) -> Result<Identity, Error> {
    if parent_coordinate >= u32::MAX - 1 || parent_coordinate.checked_add(1) != Some(coordinate) {
        return Err(Error("block-gap"));
    }
    validate_identity(parent, archive)?;
    if parent.pending.iter().any(|p| p.effective_from <= parent_coordinate) {
        return Err(Error("stale-parent-state"));
    }
    let mut result = parent.clone();
    let mut active: BTreeMap<_, _> =
        parent.active.iter().map(|r| (ref_slot(r), r.clone())).collect();
    let mut changed = false;
    result.pending.clear();
    for pending in &parent.pending {
        if pending.effective_from > coordinate {
            result.pending.push(pending.clone());
            continue;
        }
        changed = true;
        let slot = transition_slot(pending);
        active.remove(&slot);
        if pending.new_key != [0; 32] {
            let key = archive.find(&pending.new_key)?;
            active.insert(slot, Roleref { role: pending.role, key: key_reference(&key)? });
        }
    }
    if changed {
        result.previous = object_id("identity", parent)?;
        result.active = active.into_values().collect();
    }
    Ok(result)
}
pub fn apply_identity_update(
    state: &Identity,
    archive: &impl KeyHistory,
    update: &Update,
    evidence: &Authorizations,
    at: u32,
    authority: &impl LifecycleAuthority,
) -> Result<IdentityChange, Error> {
    validate_identity(state, archive)?;
    let uid = object_id("update", update)?;
    let aid = object_id("authorizations", evidence)?;
    let predecessor = object_id("identity", state)?;
    if at == u32::MAX {
        return Err(Error("coordinate"));
    }
    if state.pending.iter().any(|p| p.effective_from <= at) {
        return Err(Error("due-phase-required"));
    }
    let op = update.operation;
    if ![1, 2, 3, 7].contains(&op) || update.identity != state.identity {
        return Err(Error("operation-target"));
    }
    if update.nonce < state.next_nonce || update.nonce == u64::MAX {
        return Err(Error("nonce"));
    }
    if update.previous != predecessor {
        return Err(Error("predecessor"));
    }
    if !update.new_policy.is_empty() {
        return Err(Error("unused-field"));
    }
    let effective =
        if [3, 7].contains(&op) && update.effective_from == 0 { at } else { update.effective_from };
    if effective == u32::MAX || effective.checked_sub(at).is_none_or(|delay| delay > MAX_DELAY) {
        return Err(Error("effective-coordinate"));
    }
    let mut result = IdentityChange { identity: state.clone(), archived_key: None };
    let mut target = (0, 0, 0);
    let mut new_id = [0; 32];
    if op == 7 {
        if update.effective_from != 0
            || update.old_key != [0; 32]
            || !update.new_key.is_empty()
            || update.operation_data.len() != 32
        {
            return Err(Error("cancel-shape"));
        }
        let mut found = None;
        for (index, pending) in state.pending.iter().enumerate() {
            if object_id("transition", pending)?.as_slice() == update.operation_data {
                found = Some(index);
            }
        }
        let index = found.ok_or(Error("cancel-target"))?;
        result.identity.pending.remove(index);
    } else {
        if !update.operation_data.is_empty() {
            return Err(Error("unused-field"));
        }
        if op == 1 || op == 2 {
            let key = decode::<Key>(&update.new_key)?;
            target = key_slot(&key);
            if key.identity != state.identity
                || !(1..=5).contains(&key.role)
                || key.suite != 1
                || key.parameters != 1
            {
                return Err(Error("new-key-identity"));
            }
            if key.valid_from != effective || key.valid_until <= effective {
                return Err(Error("new-key-validity"));
            }
            let epoch = archive.latest_epoch(&key.identity, target)?;
            if key.epoch <= epoch || key.epoch == u64::MAX {
                return Err(Error("epoch"));
            }
            if key.capacity_domain != [0; 32] || key.capacity_limit != 0 {
                return Err(Error("c0-capacity"));
            }
            AdmittedKey::admit(&key.public_key)?;
            new_id = object_id("key", &key)?;
            result.archived_key = Some(key);
        } else {
            if !update.new_key.is_empty() {
                return Err(Error("unused-field"));
            }
            let old = archive.find(&update.old_key)?;
            if old.identity != state.identity {
                return Err(Error("old-key"));
            }
            target = key_slot(&old);
        }
        let old =
            state.active.iter().find(|r| ref_slot(r) == target).map_or([0; 32], |r| r.key.key_id);
        if update.old_key != old || (old == [0; 32]) != (op == 1) {
            return Err(Error("old-key"));
        }
        if state.pending.iter().any(|p| transition_slot(p) == target) {
            return Err(Error("pending-conflict"));
        }
        if effective == at {
            result.identity.active.retain(|r| ref_slot(r) != target);
            if let Some(key) = &result.archived_key {
                result.identity.active.push(Roleref { role: target.0, key: key_reference(key)? });
            }
            result.identity.active.sort_by_key(ref_slot);
        } else {
            result.identity.pending.push(Transition {
                operation: op,
                role: target.0,
                suite: target.1,
                parameters: target.2,
                old_key: old,
                new_key: new_id,
                effective_from: effective,
                accepted_at: at,
                nonce: update.nonce,
                predecessor: update.previous,
                update_id: uid,
                authorization_id: aid,
            });
            result.identity.pending.sort_by_key(transition_slot);
        }
    }
    let initial = !archive.ever_registered(&state.identity)?;
    if initial && (op != 1 || target.0 != 5) {
        return Err(Error("initial-register"));
    }
    if !evidence.governance.is_empty() {
        return Err(Error("authority-shape"));
    }
    verified(op == 1 || op == 2, &evidence.owner, |proof| {
        if proof.update_id != uid
            || proof.stake_id != state.stake_id
            || proof.owner_workchain != state.owner_workchain
            || proof.owner_address != state.owner_address
        {
            return Err(Error("owner-binding"));
        }
        authority.owner(proof, update, state)
    })?;
    verified(op == 1 || op == 2, &evidence.possession, |proof| {
        let key = result.archived_key.as_ref().ok_or(Error("pop-key"))?;
        if proof.update_id != uid || proof.key != key_reference(key)? {
            return Err(Error("pop-binding"));
        }
        authority.possession(proof, update, key)
    })?;
    verified(!initial, &evidence.administration, |proof| {
        if proof.update_id != uid || proof.identity != state.identity {
            return Err(Error("admin-binding"));
        }
        authority.administration(proof, update, state, at)
    })?;
    result.identity.next_nonce = update.nonce.checked_add(1).ok_or(Error("nonce"))?;
    result.identity.previous = predecessor;
    if let Some(key) = &result.archived_key {
        validate_identity(&result.identity, &Overlay { parent: archive, key, id: new_id })?;
    } else {
        validate_identity(&result.identity, archive)?;
    }
    Ok(result)
}
pub fn select_identity_keys(
    state: &Identity,
    archive: &impl KeyHistory,
    anchor: u32,
    required: &[KeySlot],
) -> Result<Vec<Key>, Error> {
    validate_identity(state, archive)?;
    if state.pending.iter().any(|p| p.effective_from <= anchor) {
        return Err(Error("snapshot-state-not-current"));
    }
    let mut keys = Vec::new();
    for wanted in required {
        let reference = state
            .active
            .iter()
            .find(|r| ref_slot(r) == *wanted)
            .ok_or(Error("snapshot-missing"))?;
        let key = archive.find(&reference.key.key_id)?;
        if key.valid_from > anchor || key.valid_until <= anchor {
            return Err(Error("snapshot-validity"));
        }
        keys.push(key);
    }
    Ok(keys)
}
