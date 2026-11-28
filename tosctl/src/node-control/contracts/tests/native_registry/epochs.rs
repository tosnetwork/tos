/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Authorization epochs and delegation withdrawal, executed on the release code.
//!
//! Every Agent carries a u64 authorization epoch: registration sets 1, and a
//! policy update (identical policy bytes included), recovery completion and
//! tombstone each advance it once and drop every delegation of the old epoch.
//! A delegation add or withdrawal signs the epoch it expects, which must be the
//! current one. Within one epoch at most 128 digests are live and at most 384
//! were ever admitted; an add is refused only while a count is full, and a
//! withdrawal never needs capacity.
//!
//! Each test names the layer it exercises. Contract refusals are reached with
//! the current predecessor and the next sequence, so only the intended check
//! can refuse. States beyond what a practical number of actions reaches (an
//! epoch at its maximum, 384 admissions) are seeded directly into the account,
//! in exactly the layout the contract writes.

use super::*;
use chain_block::{HashmapE, HashmapType};
use contracts::native_registry::{
    NATIVE_REGISTRY_ERR_CAPACITY_FULL, NATIVE_REGISTRY_ERR_DIGEST_NOT_LIVE,
    NATIVE_REGISTRY_ERR_EPOCH_EXHAUSTED, NATIVE_REGISTRY_ERR_EPOCH_MISMATCH,
    NATIVE_REGISTRY_ERR_WITHDRAWN_DIGEST, NATIVE_REGISTRY_MAX_ADMITTED_DELEGATIONS,
    NATIVE_REGISTRY_MAX_DELEGATIONS, NativeDelegationEntry, NativeRegistryState,
    NativeRegistryStateDetail, decode_native_registry_state, native_delegation,
};

const WITHDRAW_DELEGATION: u8 = 11;
const ERR_EPOCH_MISMATCH: i32 = NATIVE_REGISTRY_ERR_EPOCH_MISMATCH;
const ERR_EPOCH_EXHAUSTED: i32 = NATIVE_REGISTRY_ERR_EPOCH_EXHAUSTED;
const ERR_WITHDRAWN_DIGEST: i32 = NATIVE_REGISTRY_ERR_WITHDRAWN_DIGEST;
const ERR_CAPACITY_FULL: i32 = NATIVE_REGISTRY_ERR_CAPACITY_FULL;
const ERR_DIGEST_NOT_LIVE: i32 = NATIVE_REGISTRY_ERR_DIGEST_NOT_LIVE;
const LIVE_BOUND: usize = NATIVE_REGISTRY_MAX_DELEGATIONS as usize;
const ADMITTED_BOUND: usize = NATIVE_REGISTRY_MAX_ADMITTED_DELEGATIONS as usize;

/// Hash-shaped digest `index`: SHA-256 of `registry-epoch-measure-<index>`.
fn hashed(index: usize) -> [u8; 32] {
    bytes_hash(format!("registry-epoch-measure-{index}").as_bytes())
}

/// Deep-spine digest `index`: `2^index` for 0..=255, then `2^255 + j`; the
/// keys share the longest prefixes a 256-bit dictionary can hold.
fn spine(index: usize) -> [u8; 32] {
    let mut key = [0u8; 32];
    if index < 256 {
        let bit = 255 - index;
        key[bit / 8] = 0x80 >> (bit % 8);
    } else {
        let j = index - 255;
        key[0] = 0x80;
        key[30] = (j >> 8) as u8;
        key[31] = j as u8;
    }
    key
}

/// A key shape for a seeded population.
#[derive(Clone, Copy, Debug)]
enum Shape {
    Hashed,
    Spine,
}

impl Shape {
    fn digest(self, index: usize) -> [u8; 32] {
        match self {
            Shape::Hashed => hashed(index),
            Shape::Spine => spine(index),
        }
    }
}

/// `(digest, withdrawn)` entries: the first `live` of `admitted` keys live,
/// the rest withdrawn.
fn population(shape: Shape, live: usize, admitted: usize) -> Vec<([u8; 32], bool)> {
    (0..admitted).map(|index| (shape.digest(index), index >= live)).collect()
}

impl Fixture {
    /// The fixture Agent's state through the strict reader, so every state the
    /// contract writes in these tests is also checked by it.
    fn decoded(&self) -> NativeRegistryState {
        decode_native_registry_state(&self.state()).expect("the strict reader admits the state")
    }

    /// `(epoch, live, admitted)` of the fixture Agent.
    fn counts(&self) -> (u64, u16, u16) {
        match self.decoded().detail {
            NativeRegistryStateDetail::Agent {
                authorization_epoch,
                live_delegations,
                admitted_delegations,
                ..
            } => (authorization_epoch, live_delegations, admitted_delegations),
            NativeRegistryStateDetail::Capability { .. } => panic!("an Agent state"),
        }
    }

    /// `(epoch, live, admitted)` as stored, read without the strict reader, so
    /// a contract-layer assertion names the transition the contract got wrong
    /// even when the state it wrote is also malformed.
    fn raw_counts(&self) -> (u64, u16, u16) {
        let state = self.state();
        let mut wrapper = SliceData::load_cell(state.reference(1).unwrap()).unwrap();
        (agent_epoch(&state), wrapper.get_next_u16().unwrap(), wrapper.get_next_u16().unwrap())
    }

    fn entry(&self, digest: &[u8; 32]) -> Option<NativeDelegationEntry> {
        native_delegation(&self.decoded().detail, digest).expect("lookup")
    }

    /// The action of `kind` at the Agent's next position: recovery completion
    /// opens the next generation, every other kind takes the next sequence.
    fn next_action(&self, kind: u8, payload: Cell) -> Cell {
        let (generation, sequence) = self.state_position();
        let (generation, sequence) = if kind == COMPLETE_RECOVERY {
            (generation + 1, 1)
        } else {
            (generation, sequence + 1)
        };
        let nonce = (sequence % 250) as u8 + 1;
        self.build_action(kind, generation, sequence, nonce, payload)
    }

    /// Sends `action` signed by `authority`, with the possession set of
    /// `counterparty` (empty for none).
    fn submit(
        &mut self,
        action: &Cell,
        authority: &[&RegistryKey],
        counterparty: &[&RegistryKey],
    ) -> SendResult {
        let counterparty = if counterparty.is_empty() {
            empty_signatures()
        } else {
            signature_set_many(counterparty, action)
        };
        self.send_value(
            self.registry.clone(),
            submit_body(action.clone(), signature_set_many(authority, action), counterparty),
            MEASURE_VALUE,
        )
    }

    /// A delegation add (kind 3) or withdrawal (kind 11) of `digest` naming
    /// `epoch`, signed by `authority`. Returns the action and the result.
    fn delegation(
        &mut self,
        kind: u8,
        digest: &[u8; 32],
        epoch: u64,
        authority: &[&RegistryKey],
    ) -> (Cell, SendResult) {
        let action = self.next_action(kind, delegation_payload(digest, epoch));
        let result = self.submit(&action, authority, &[]);
        (action, result)
    }

    fn add(&mut self, digest: &[u8; 32]) -> SendResult {
        let (epoch, key) = (self.epoch(), self.old_key.clone());
        self.delegation(DELEGATE_AGENT, digest, epoch, &[&key]).1
    }

    fn withdraw(&mut self, digest: &[u8; 32]) -> SendResult {
        let (epoch, key) = (self.epoch(), self.old_key.clone());
        self.delegation(WITHDRAW_DELEGATION, digest, epoch, &[&key]).1
    }

    /// A policy update to `next`, signed by `authority` and by every
    /// controller of `next`.
    fn update(
        &mut self,
        next: &Cell,
        authority: &[&RegistryKey],
        possession: &[&RegistryKey],
    ) -> (Cell, SendResult) {
        let mut payload = BuilderData::new();
        payload.checked_append_reference(next.clone()).unwrap();
        let action = self.next_action(UPDATE_AGENT_POLICY, payload.into_cell().unwrap());
        let result = self.submit(&action, authority, possession);
        (action, result)
    }

    fn tombstone(&mut self, authority: &[&RegistryKey]) -> (Cell, SendResult) {
        let action = self.next_action(REVOKE_AGENT, BuilderData::new().into_cell().unwrap());
        let result = self.submit(&action, authority, &[]);
        (action, result)
    }

    /// Initiates recovery to `recovery`'s single-key policy and completes it
    /// once its timelock has passed. Returns the completion's result.
    fn recover(&mut self, authority: &[&RegistryKey], recovery: &RegistryKey) -> SendResult {
        let execute_after = u64::from(self.bc.now()) + 10;
        let mut payload = BuilderData::new();
        payload
            .append_u64(execute_after)
            .unwrap()
            .checked_append_reference(policy(recovery))
            .unwrap();
        let initiate = self.next_action(INITIATE_RECOVERY, payload.into_cell().unwrap());
        self.submit(&initiate, authority, &[recovery]).expect_success();
        self.bc.set_now((execute_after + 1) as u32);
        let mut payload = BuilderData::new();
        payload.append_raw(initiate.hash(0).as_slice(), 256).unwrap();
        let complete = self.next_action(COMPLETE_RECOVERY, payload.into_cell().unwrap());
        self.submit(&complete, authority, &[])
    }

    /// Replaces the stored epoch and delegation set with `entries` at
    /// `epoch`, in the layout the contract writes, keeping the policy, the
    /// pending recovery and the position.
    fn seed(&mut self, epoch: u64, entries: &[([u8; 32], bool)]) {
        let mut map = HashmapE::with_bit_len(256);
        for (digest, withdrawn) in entries {
            let mut leaf = BuilderData::new();
            leaf.append_u64(epoch).unwrap().append_bit_bool(*withdrawn).unwrap();
            map.set_builder(SliceData::from_raw(digest.to_vec(), 256), &leaf).unwrap();
        }
        let live = entries.iter().filter(|(_, withdrawn)| !withdrawn).count();
        let mut wrapper = BuilderData::new();
        wrapper.append_u16(live as u16).unwrap().append_u16(entries.len() as u16).unwrap();
        map.write_hashmap_data(&mut wrapper).unwrap();
        self.seed_wrapper(epoch, wrapper.into_cell().unwrap());
    }

    fn seed_wrapper(&mut self, epoch: u64, wrapper: Cell) {
        let mut state = SliceData::load_cell(self.state()).unwrap();
        let header = state.get_next_slice(32 + 16 + 8 + 1 + 64 + 64 + 256).unwrap();
        state.get_next_u64().unwrap();
        let policy = state.checked_drain_reference().unwrap();
        state.checked_drain_reference().unwrap();
        let recovery = state.checked_drain_reference().unwrap();
        let mut next = BuilderData::new();
        next.append_builder(&header.as_builder().unwrap())
            .unwrap()
            .append_u64(epoch)
            .unwrap()
            .checked_append_reference(policy)
            .unwrap()
            .checked_append_reference(wrapper)
            .unwrap()
            .checked_append_reference(recovery)
            .unwrap();
        let mut data = BuilderData::new();
        data.append_u32(MAGIC_DATA)
            .unwrap()
            .append_u16(1)
            .unwrap()
            .append_u8(1)
            .unwrap()
            .append_u256(&self.object_id)
            .unwrap()
            .checked_append_reference(self.config.clone())
            .unwrap()
            .append_bit_one()
            .unwrap()
            .checked_append_reference(next.into_cell().unwrap())
            .unwrap();
        let mut account = self.bc.get_account(&self.registry).unwrap().clone();
        assert!(account.set_data(data.into_cell().unwrap()));
        self.bc.set_account(self.registry.clone(), account);
    }

    /// Asserts that `result` refused with `code` and left the state unchanged.
    fn refused(&self, result: &SendResult, code: i32, before: &Cell, case: &str) {
        let gas = gas_at(result, &self.registry);
        assert!(gas.aborted && gas.exit == code, "{case}: expected exit {code}, got {gas:?}");
        assert_eq!(self.state().hash(0), before.hash(0), "{case} changed state");
    }
}

fn out_messages(result: &SendResult, address: &MsgAddressInt) -> usize {
    let transaction =
        result.transactions_for(address).into_iter().last().expect("a transaction on the account");
    transaction.out_msgs.len().expect("out_msgs")
}

/// Contract layer, vector sequence 1: register at epoch 1; add A and B;
/// withdraw A, leaving B live; re-adding A, withdrawing it again and
/// withdrawing a never-admitted digest refuse; the exact withdrawal replays as
/// a no-op.
#[test]
fn epoch_add_withdraw_readd_and_replay() {
    let mut f = Fixture::new();
    let (a, b, c) = ([0xa1; 32], [0xb1; 32], [0xc1; 32]);
    assert_eq!(f.counts(), (1, 0, 0), "registration starts at epoch 1, empty");
    f.add(&a).expect_success();
    f.add(&b).expect_success();
    assert_eq!(f.raw_counts(), (1, 2, 2), "two adds at epoch 1");
    assert_eq!(f.counts(), (1, 2, 2));
    assert_eq!(
        f.entry(&a),
        Some(NativeDelegationEntry { digest: a, admission_epoch: 1, withdrawn: false })
    );

    let key = f.old_key.clone();
    let (withdrawal, result) = f.delegation(WITHDRAW_DELEGATION, &a, 1, &[&key]);
    result.expect_success();
    assert_eq!(out_messages(&result, &f.registry), 0, "a withdrawal emits nothing");
    assert_eq!(f.raw_counts(), (1, 1, 2), "live drops, admitted and epoch stay");
    assert_eq!(f.counts(), (1, 1, 2));
    assert_eq!(
        f.entry(&a),
        Some(NativeDelegationEntry { digest: a, admission_epoch: 1, withdrawn: true })
    );
    assert!(!f.entry(&b).expect("B").withdrawn, "B stays live");

    let after = f.state();
    let result = f.add(&a);
    f.refused(&result, ERR_WITHDRAWN_DIGEST, &after, "re-add of a withdrawn digest");
    let result = f.withdraw(&a);
    f.refused(&result, ERR_WITHDRAWN_DIGEST, &after, "second withdrawal");
    let result = f.withdraw(&c);
    f.refused(&result, ERR_DIGEST_NOT_LIVE, &after, "withdrawal of a never-admitted digest");
    let result = f.add(&b);
    f.refused(&result, ERR_BAD_TRANSITION, &after, "duplicate live digest");

    f.submit(&withdrawal, &[&key], &[]).expect_success();
    assert_eq!(f.state().hash(0), after.hash(0), "an exact replay changes nothing");
}

/// Contract layer, vector sequences 2-4: every policy update (A to B, B to A
/// and the identical A to A), recovery completion and tombstone advance the
/// epoch once and clear live and withdrawn digests; recovery initiation does
/// not; a replay after tombstone bumps nothing and any other action refuses.
#[test]
fn every_bump_advances_the_epoch_once_and_clears_both_sets() {
    let mut f = Fixture::new();
    let a_key = f.old_key.clone();
    let b_key = RegistryKey::from_bytes(&[0xe2; 32]);
    let (a_policy, b_policy) = (policy(&a_key), policy(&b_key));
    let (d1, d2) = ([0x11; 32], [0x12; 32]);

    let populate = |f: &mut Fixture, signer: &RegistryKey| {
        let epoch = f.epoch();
        f.delegation(DELEGATE_AGENT, &d1, epoch, &[signer]).1.expect_success();
        f.delegation(DELEGATE_AGENT, &d2, epoch, &[signer]).1.expect_success();
        f.delegation(WITHDRAW_DELEGATION, &d1, epoch, &[signer]).1.expect_success();
        assert_eq!(f.counts(), (epoch, 1, 2));
    };

    populate(&mut f, &a_key);
    f.update(&b_policy, &[&a_key], &[&b_key]).1.expect_success();
    assert_eq!(f.raw_counts(), (2, 0, 0), "A to B");
    assert_eq!(f.counts(), (2, 0, 0));
    assert_eq!((f.entry(&d1), f.entry(&d2)), (None, None));

    populate(&mut f, &b_key);
    f.update(&a_policy, &[&b_key], &[&a_key]).1.expect_success();
    assert_eq!(
        f.raw_counts(),
        (3, 0, 0),
        "B back to A: the policy hash repeats, the epoch does not"
    );
    assert_eq!(f.counts(), (3, 0, 0));
    let before = f.state();
    let result = f.delegation(WITHDRAW_DELEGATION, &d2, 2, &[&a_key]).1;
    f.refused(&result, ERR_EPOCH_MISMATCH, &before, "a document of the old epoch");
    let result = f.delegation(WITHDRAW_DELEGATION, &d2, 3, &[&a_key]).1;
    f.refused(&result, ERR_DIGEST_NOT_LIVE, &before, "the old live digest is gone");

    populate(&mut f, &a_key);
    f.update(&a_policy, &[&a_key], &[&a_key]).1.expect_success();
    assert_eq!(f.raw_counts(), (4, 0, 0), "identical policy bytes still advance");
    assert_eq!(f.counts(), (4, 0, 0));

    // Initiation changes only the pending recovery; completion advances once.
    populate(&mut f, &a_key);
    let execute_after = u64::from(f.bc.now()) + 10;
    let mut payload = BuilderData::new();
    payload.append_u64(execute_after).unwrap().checked_append_reference(b_policy.clone()).unwrap();
    let initiate = f.next_action(INITIATE_RECOVERY, payload.into_cell().unwrap());
    f.submit(&initiate, &[&a_key], &[&b_key]).expect_success();
    assert_eq!(f.raw_counts(), (4, 1, 2), "initiation keeps the epoch and the delegations");
    assert_eq!(f.counts(), (4, 1, 2));
    f.bc.set_now((execute_after + 1) as u32);
    let mut payload = BuilderData::new();
    payload.append_raw(initiate.hash(0).as_slice(), 256).unwrap();
    let complete = f.next_action(COMPLETE_RECOVERY, payload.into_cell().unwrap());
    f.submit(&complete, &[&a_key], &[]).expect_success();
    assert_eq!(f.raw_counts(), (5, 0, 0), "completion advances and clears");
    assert_eq!(f.counts(), (5, 0, 0));
    assert_eq!(f.state_position(), (2, 1), "the generation reset is unchanged");

    populate(&mut f, &b_key);
    let (revoke, result) = f.tombstone(&[&b_key]);
    result.expect_success();
    assert_eq!(f.raw_counts(), (6, 0, 0), "tombstone advances and clears");
    assert_eq!(f.counts(), (6, 0, 0));
    let dead = f.state();
    f.submit(&revoke, &[&b_key], &[]).expect_success();
    assert_eq!(f.state().hash(0), dead.hash(0), "a replay after tombstone bumps nothing");
    let result = f.delegation(DELEGATE_AGENT, &d1, 6, &[&b_key]).1;
    f.refused(&result, ERR_TOMBSTONED, &dead, "a new action after tombstone");
}

/// Contract layer: with the current predecessor and the next sequence, only
/// the expected epoch is wrong -- one behind, one ahead -- and both an add
/// and a withdrawal refuse with 2216. A zero epoch or digest is malformed.
#[test]
fn expected_epoch_must_be_the_current_one() {
    let mut f = Fixture::new();
    let key = f.old_key.clone();
    f.update(&policy(&key), &[&key], &[&key]).1.expect_success();
    let live = [0x21; 32];
    f.add(&live).expect_success();
    assert_eq!(f.counts(), (2, 1, 1));
    let before = f.state();
    for (kind, digest) in [(DELEGATE_AGENT, [0x22; 32]), (WITHDRAW_DELEGATION, live)] {
        for epoch in [1, 3, u64::MAX] {
            let result = f.delegation(kind, &digest, epoch, &[&key]).1;
            f.refused(&result, ERR_EPOCH_MISMATCH, &before, &format!("kind {kind} epoch {epoch}"));
        }
        let result = f.delegation(kind, &digest, 0, &[&key]).1;
        f.refused(&result, ERR_BAD_ACTION, &before, "zero epoch");
        let result = f.delegation(kind, &[0; 32], 2, &[&key]).1;
        f.refused(&result, ERR_BAD_ACTION, &before, "zero digest");
    }
}

/// Contract layer, vector sequence 6: an Agent seeded at MAX - 1 advances to
/// MAX once; the exact replay of that bump is still a no-op; at MAX adds and
/// withdrawals still work, and every bump -- update, recovery completion,
/// tombstone -- refuses with 2217 before anything is saved.
#[test]
fn the_largest_epoch_cannot_advance_and_still_admits_delegations() {
    let mut f = Fixture::new();
    let key = f.old_key.clone();
    let rescue = RegistryKey::from_bytes(&[0xe3; 32]);
    let (live, other) = ([0x31; 32], [0x32; 32]);
    f.seed(u64::MAX - 1, &[(live, false)]);
    assert_eq!(f.counts(), (u64::MAX - 1, 1, 1));
    let (update, result) = f.update(&policy(&key), &[&key], &[&key]);
    result.expect_success();
    assert_eq!(f.counts(), (u64::MAX, 0, 0), "MAX - 1 advances to MAX");
    let at_max = f.state();
    f.submit(&update, &[&key], &[&key]).expect_success();
    assert_eq!(f.state().hash(0), at_max.hash(0), "the replay of the bump to MAX is a no-op");

    f.add(&live).expect_success();
    f.add(&other).expect_success();
    f.withdraw(&live).expect_success();
    assert_eq!(f.counts(), (u64::MAX, 1, 2), "adds and withdrawals at MAX");

    let before = f.state();
    let result = f.update(&policy(&key), &[&key], &[&key]).1;
    f.refused(&result, ERR_EPOCH_EXHAUSTED, &before, "update at MAX");
    let result = f.tombstone(&[&key]).1;
    f.refused(&result, ERR_EPOCH_EXHAUSTED, &before, "tombstone at MAX");
    let result = f.recover(&[&key], &rescue);
    let pending = f.state();
    assert_ne!(pending.hash(0), before.hash(0), "initiation at MAX is not a bump");
    f.refused(&result, ERR_EPOCH_EXHAUSTED, &pending, "recovery completion at MAX");
    assert_eq!(f.counts(), (u64::MAX, 1, 2));
}

/// Contract layer, vector sequence 7, live bound through real actions: 128
/// adds fill the live set; the next add refuses; withdrawing one bad key
/// frees a slot at once, the replacement fits and the set is full again.
#[test]
fn the_live_bound_refuses_only_while_full() {
    let mut f = Fixture::new();
    for index in 0..LIVE_BOUND {
        f.add(&hashed(index)).expect_success();
    }
    assert_eq!(f.counts(), (1, 128, 128), "127 to 128 live");
    let full = f.state();
    let result = f.add(&hashed(LIVE_BOUND));
    f.refused(&result, ERR_CAPACITY_FULL, &full, "a 129th live digest");
    f.withdraw(&hashed(7)).expect_success();
    assert_eq!(f.counts(), (1, 127, 128));
    f.add(&hashed(LIVE_BOUND)).expect_success();
    assert_eq!(f.counts(), (1, 128, 129), "the replacement is admitted at once");
    let full = f.state();
    let result = f.add(&hashed(LIVE_BOUND + 1));
    f.refused(&result, ERR_CAPACITY_FULL, &full, "full again");
}

/// Contract layer: each bound refuses on its own. Live 128 / admitted 128
/// refuses for the live bound; live 127 / admitted 384 for the admitted bound;
/// live 127 / admitted 383 admits the 384th digest.
#[test]
fn each_bound_refuses_independently() {
    let mut f = Fixture::new();
    f.seed(1, &population(Shape::Hashed, 128, 128));
    let before = f.state();
    let result = f.add(&[0x41; 32]);
    f.refused(&result, ERR_CAPACITY_FULL, &before, "live 128, admitted 128");

    f.seed(1, &population(Shape::Hashed, 127, 384));
    let before = f.state();
    let result = f.add(&[0x41; 32]);
    f.refused(&result, ERR_CAPACITY_FULL, &before, "live 127, admitted 384");

    f.seed(1, &population(Shape::Hashed, 127, 383));
    f.add(&[0x41; 32]).expect_success();
    assert_eq!(f.counts(), (1, 128, 384), "383 to 384 admitted");
}

/// Contract layer, vector sequence 7, admitted bound: from 128 live / 256
/// withdrawn every live digest is withdrawn -- each dictionary position, at
/// the full admitted count -- without a capacity refusal and without moving
/// the admitted count; at 0 / 384 an add refuses; an update, and separately
/// a recovery completion, clears the set and admits again.
#[test]
fn withdrawal_at_every_position_needs_no_capacity() {
    for shape in [Shape::Hashed, Shape::Spine] {
        let mut f = Fixture::new();
        let entries = population(shape, 128, 384);
        f.seed(1, &entries);
        for (index, (digest, _)) in entries.iter().take(LIVE_BOUND).enumerate() {
            let result = f.withdraw(digest);
            result.expect_success();
            assert_eq!(out_messages(&result, &f.registry), 0, "{shape:?} {index}: no out action");
            let expected = (1, (LIVE_BOUND - index - 1) as u16, ADMITTED_BOUND as u16);
            assert_eq!(
                f.raw_counts(),
                expected,
                "{shape:?} {index}: the admitted count never moves"
            );
            assert_eq!(f.counts(), expected);
        }
        let drained = f.state();
        let result = f.add(&[0x51; 32]);
        f.refused(&result, ERR_CAPACITY_FULL, &drained, "0 live, 384 admitted");

        let mut again = Fixture::new();
        again.seed(1, &population(shape, 0, 384));
        let key = f.old_key.clone();
        f.update(&policy(&key), &[&key], &[&key]).1.expect_success();
        assert_eq!(f.counts(), (2, 0, 0));
        f.add(&[0x51; 32]).expect_success();

        let key = again.old_key.clone();
        again.recover(&[&key], &key).expect_success();
        assert_eq!(again.counts(), (2, 0, 0));
        again.add(&[0x51; 32]).expect_success();
    }
}

/// Contract layer, same-block orderings: a withdrawal and a policy update
/// built from one predecessor serialize. Whichever runs second is refused as a
/// stale predecessor and changes nothing; reconciled against the new state,
/// an update is rebuilt and applies, while a withdrawal after the bump finds
/// its digest absent from the post-state -- already revoked, proven by that
/// state, not by the error code alone.
#[test]
fn withdrawal_and_update_from_one_predecessor_serialize() {
    for withdrawal_first in [true, false] {
        let mut f = Fixture::new();
        let key = f.old_key.clone();
        let digest = [0x61; 32];
        f.add(&digest).expect_success();
        let withdrawal = f.next_action(WITHDRAW_DELEGATION, delegation_payload(&digest, 1));
        let mut payload = BuilderData::new();
        payload.checked_append_reference(policy(&key)).unwrap();
        let update = f.next_action(UPDATE_AGENT_POLICY, payload.into_cell().unwrap());
        let (first, second) =
            if withdrawal_first { (&withdrawal, &update) } else { (&update, &withdrawal) };
        let possession = [&key];
        let none: [&RegistryKey; 0] = [];
        let (first_counterparty, second_counterparty): (&[&RegistryKey], &[&RegistryKey]) =
            if withdrawal_first { (&none, &possession) } else { (&possession, &none) };
        f.submit(first, &[&key], first_counterparty).expect_success();
        let between = f.state();
        let result = f.submit(second, &[&key], second_counterparty);
        f.refused(&result, ERR_BAD_PREDECESSOR, &between, "the second of one predecessor");
        if withdrawal_first {
            assert!(f.entry(&digest).expect("withdrawn").withdrawn);
            f.update(&policy(&key), &[&key], &[&key]).1.expect_success();
        } else {
            let result = f.withdraw(&digest);
            let after = f.state();
            f.refused(&result, ERR_DIGEST_NOT_LIVE, &after, "withdrawal after the bump");
            assert_eq!(f.entry(&digest), None, "the bump already removed the digest");
        }
        assert_eq!(f.counts(), (2, 0, 0), "withdrawal first: {withdrawal_first}");
    }
}

/// Contract layer: a withdrawal takes no counterparty signatures, needs the
/// delegation purpose, cannot arrive as a Capability authorization, and its
/// payload ends exactly.
#[test]
fn withdrawal_shape_and_authorization_refusals() {
    let mut f = Fixture::new();
    let key = f.old_key.clone();
    let digest = [0x71; 32];
    f.add(&digest).expect_success();
    let before = f.state();

    let action = f.next_action(WITHDRAW_DELEGATION, delegation_payload(&digest, 1));
    let result = f.submit(&action, &[&key], &[&key]);
    f.refused(&result, ERR_BAD_SIGNATURE, &before, "counterparty signatures");

    let (isolated, keys) = purpose_isolated_policy();
    let mut g = Fixture::new();
    g.install_policy(isolated);
    let without_delegation: Vec<&RegistryKey> =
        keys.iter().filter(|candidate| candidate.id() != keys[1].id()).collect();
    let epoch = g.epoch();
    let delegate = keys[1].clone();
    g.delegation(DELEGATE_AGENT, &digest, epoch, &[&delegate]).1.expect_success();
    let isolated_before = g.state();
    for signer in without_delegation {
        let result = g.delegation(WITHDRAW_DELEGATION, &digest, epoch, &[signer]).1;
        g.refused(&result, ERR_BAD_SIGNATURE, &isolated_before, "a key without the purpose");
    }
    g.delegation(WITHDRAW_DELEGATION, &digest, epoch, &[&delegate]).1.expect_success();

    let action = f.next_action(WITHDRAW_DELEGATION, delegation_payload(&digest, 1));
    let result = f.send_value(
        f.registry.clone(),
        capability_body(
            OP_AUTHORIZED_CAPABILITY,
            action.clone(),
            signature_set(&key, &action),
            empty_signatures(),
        ),
        MEASURE_VALUE,
    );
    f.refused(&result, ERR_BAD_TRANSITION, &before, "as a Capability authorization");

    let mut long = BuilderData::new();
    long.append_u256(&digest).unwrap().append_u64(1).unwrap().append_bit_zero().unwrap();
    let action = f.next_action(WITHDRAW_DELEGATION, long.into_cell().unwrap());
    let result = f.submit(&action, &[&key], &[]);
    assert!(gas_at(&result, &f.registry).aborted, "a trailing bit");
    assert_eq!(f.state().hash(0), before.hash(0));
}

/// Contract layer, identity tags: an Agent registered under an id derived
/// with tag 1 (the earlier release) or tag 2 (the Capability tag) from the
/// same nonce, policy and network is refused as a caller-selected id; the
/// same registration under tag 3 is admitted.
#[test]
fn agent_identity_tag_is_three() {
    let mut f = Fixture::new();
    let key = RegistryKey::from_bytes(&[0x81; 32]);
    for tag in [1, 2] {
        let (message, address) = f.tagged_registration(policy(&key), [0x82; 32], tag, |action| {
            signature_set(&key, action)
        });
        let result = traced(&mut f.bc, |bc| bc.send_message(message).expect("register"));
        assert_eq!(refusal(&result, &address), ERR_BAD_TRANSITION, "tag {tag}");
        assert!(!f.registered(&address), "tag {tag} registers nothing");
    }
    let (message, address) =
        f.tagged_registration(policy(&key), [0x82; 32], AGENT_IDENTITY_TAG, |action| {
            signature_set(&key, action)
        });
    let result = traced(&mut f.bc, |bc| bc.send_message(message).expect("register"));
    assert_address_success(&result, &address);
    assert_eq!(agent_epoch(&f.state_at(&address)), 1);
}

/// Contract layer: a Capability state is schema 2 with its earlier bit layout,
/// and no Capability operation touches its owner Agent's epoch.
#[test]
fn capability_state_is_schema_two_with_its_layout_unchanged() {
    let mut f = Fixture::new();
    let (owner_id, owner) = (f.object_id, f.registry.clone());
    let key = f.old_key.clone();
    f.add(&[0x91; 32]).expect_success();
    let capability =
        f.register_capability(&owner_id, &owner, &key, [0x92; 32], b"1.0.0", [0x93; 32]);
    let state = f.state_at(&capability.address);
    let mut header = SliceData::load_cell(state.clone()).unwrap();
    assert_eq!(header.get_next_u32().unwrap(), MAGIC_STATE);
    assert_eq!(header.get_next_u16().unwrap(), 2, "Capability schema 2");
    assert_eq!(header.get_next_byte().unwrap(), 2, "Capability kind");
    assert_eq!(capability_owner(&state), owner_id, "the owner stays at its earlier offset");
    assert_eq!(state.bit_length(), 32 + 16 + 8 + 1 + 64 + 64 + 256 + 256);
    assert_eq!(state.references_count(), 1);
    let decoded = decode_native_registry_state(&state).expect("strict reader");
    assert!(
        matches!(decoded.detail, NativeRegistryStateDetail::Capability { owner, .. } if owner == owner_id)
    );
    assert_eq!(f.counts(), (1, 1, 1), "the owner Agent's epoch and set are untouched");
}

impl Fixture {
    /// A deploying Agent registration whose object id is derived with
    /// identity tag `tag`.
    fn tagged_registration(
        &self,
        agent_policy: Cell,
        object_nonce: [u8; 32],
        tag: u8,
        authority: impl Fn(&Cell) -> Cell,
    ) -> (chain_block::Message, MsgAddressInt) {
        let mut identity = BuilderData::new();
        identity
            .append_u32(MAGIC_IDENTITY)
            .unwrap()
            .append_u8(tag)
            .unwrap()
            .append_u256(&object_nonce)
            .unwrap()
            .append_raw(agent_policy.hash(0).as_slice(), 256)
            .unwrap()
            .checked_append_reference(self.identity_domain.clone())
            .unwrap();
        let object_id = *identity.into_cell().unwrap().hash(0).as_slice();
        let (address, state_init) = self.object_address(1, &object_id);
        let mut payload = BuilderData::new();
        payload.append_u256(&object_nonce).unwrap().checked_append_reference(agent_policy).unwrap();
        let register = action(
            REGISTER_AGENT,
            1,
            1,
            1,
            &object_id,
            &[0; 32],
            object_nonce[0],
            &self.domain,
            payload.into_cell().unwrap(),
        );
        let deploy = MessageBuilder::internal(self.relayer.address(), &address, 20 * TOS)
            .bounce(false)
            .state_init(state_init)
            .body(submit_body(register.clone(), authority(&register), empty_signatures()))
            .build();
        (deploy, address)
    }
}

// ---------------------------------------------------------------------------
// Measurements: gas against the 800,000 ceiling at a 2,000,000 transaction
// limit, signed message size against ConfigParam 43, and storage rent from
// ConfigParam 18 with the freeze and delete limits of ConfigParam 21.
// ---------------------------------------------------------------------------

fn assert_within_ceiling(path: &str, gas: Gas, succeeds: bool) {
    assert_eq!(gas.limit, NATIVE_REGISTRY_TRANSACTION_GAS_LIMIT, "{path}: gas limit");
    assert_eq!(!gas.aborted && gas.exit == 0, succeeds, "{path}: outcome {gas:?}");
    assert!(
        gas.used <= NATIVE_REGISTRY_GAS_CEILING,
        "{path}: {} gas exceeds the ceiling of {NATIVE_REGISTRY_GAS_CEILING}",
        gas.used
    );
}

/// A fixture whose Agent holds a `width`-controller policy (every key every
/// purpose, every key needed) and the population `entries` at epoch 1.
fn measured(width: usize, entries: &[([u8; 32], bool)]) -> (Fixture, Vec<RegistryKey>) {
    let mut f = Fixture::new();
    let keys = if width == 1 { vec![f.old_key.clone()] } else { width_keys(width, 9) };
    if width > 1 {
        f.install_policy(wide_policy(&keys));
    }
    f.seed(1, entries);
    (f, keys)
}

fn refs(keys: &[RegistryKey]) -> Vec<&RegistryKey> {
    keys.iter().collect()
}

/// Every changed path and every refused add, at one and eight controllers,
/// over hashed and deep-spine keys at the bounding populations, stays at or
/// below the gas ceiling; withdrawal is measured at every position of a full
/// 128 / 384 set. Prints one row per path.
#[test]
fn epoch_paths_fit_the_gas_ceiling() {
    for width in [1, MAX_WIDTH] {
        for shape in [Shape::Hashed, Shape::Spine] {
            let row = |path: &str, gas: Gas| {
                eprintln!("width {width} {shape:?}: {path}: gas {} exit {}", gas.used, gas.exit);
            };
            let probe = [0xd1; 32];

            // Add 127 -> 128 live, and 383 -> 384 admitted with live below 128.
            for (path, live, admitted) in
                [("add 127->128 live", 127, 127), ("add 383->384 admitted", 100, 383)]
            {
                let (mut f, keys) = measured(width, &population(shape, live, admitted));
                let (_, result) = f.delegation(DELEGATE_AGENT, &probe, 1, &refs(&keys));
                let gas = gas_at(&result, &f.registry);
                row(path, gas);
                assert_within_ceiling(path, gas, true);
            }

            // Every refused add.
            let full_live = population(shape, 128, 128);
            let full_admitted = population(shape, 127, 384);
            let withdrawn = population(shape, 127, 383);
            let withdrawn_digest = withdrawn[200].0;
            let live_digest = withdrawn[0].0;
            for (path, entries, digest, epoch, code) in [
                ("refused add: live full", &full_live, probe, 1, ERR_CAPACITY_FULL),
                ("refused add: admitted full", &full_admitted, probe, 1, ERR_CAPACITY_FULL),
                (
                    "refused add: withdrawn digest",
                    &withdrawn,
                    withdrawn_digest,
                    1,
                    ERR_WITHDRAWN_DIGEST,
                ),
                ("refused add: duplicate live", &withdrawn, live_digest, 1, ERR_BAD_TRANSITION),
                ("refused add: stale epoch", &withdrawn, probe, 2, ERR_EPOCH_MISMATCH),
            ] {
                let (mut f, keys) = measured(width, entries);
                let (_, result) = f.delegation(DELEGATE_AGENT, &digest, epoch, &refs(&keys));
                let gas = gas_at(&result, &f.registry);
                row(path, gas);
                assert_eq!(gas.exit, code, "{path}");
                assert_within_ceiling(path, gas, false);
            }

            // Withdrawal at every position of a full 128 / 384 set.
            let entries = population(shape, 128, 384);
            let (mut f, keys) = measured(width, &entries);
            let mut worst = 0;
            for (digest, _) in entries.iter().take(LIVE_BOUND) {
                let (_, result) = f.delegation(WITHDRAW_DELEGATION, digest, 1, &refs(&keys));
                let gas = gas_at(&result, &f.registry);
                assert_within_ceiling("withdraw", gas, true);
                worst = worst.max(gas.used);
            }
            eprintln!("width {width} {shape:?}: withdraw (worst of 128 positions): gas {worst}");

            // Every bump with all 384 entries populated.
            for path in ["update_agent_policy", "complete_recovery", "revoke_agent"] {
                let (mut f, keys) = measured(width, &population(shape, 128, 384));
                let signers = refs(&keys);
                let result = match path {
                    "update_agent_policy" => {
                        let next = if width == 1 { policy(&keys[0]) } else { wide_policy(&keys) };
                        f.update(&next, &signers, &signers).1
                    }
                    "complete_recovery" => {
                        let execute_after = u64::from(f.bc.now()) + 10;
                        let next = if width == 1 { policy(&keys[0]) } else { wide_policy(&keys) };
                        let mut payload = BuilderData::new();
                        payload
                            .append_u64(execute_after)
                            .unwrap()
                            .checked_append_reference(next)
                            .unwrap();
                        let initiate =
                            f.next_action(INITIATE_RECOVERY, payload.into_cell().unwrap());
                        let result = f.submit(&initiate, &signers, &signers);
                        let gas = gas_at(&result, &f.registry);
                        row("initiate_recovery", gas);
                        assert_within_ceiling("initiate_recovery", gas, true);
                        f.bc.set_now((execute_after + 1) as u32);
                        let mut payload = BuilderData::new();
                        payload.append_raw(initiate.hash(0).as_slice(), 256).unwrap();
                        let complete =
                            f.next_action(COMPLETE_RECOVERY, payload.into_cell().unwrap());
                        f.submit(&complete, &signers, &[])
                    }
                    _ => f.tombstone(&signers).1,
                };
                let gas = gas_at(&result, &f.registry);
                row(&format!("{path} (384 populated)"), gas);
                assert_within_ceiling(path, gas, true);
                assert_eq!(f.counts(), (2, 0, 0), "{path} cleared the set");
            }
        }
        // Registration at this width.
        let mut f = Fixture::new();
        let keys = if width == 1 {
            vec![RegistryKey::from_bytes(&[0xd2; 32])]
        } else {
            width_keys(width, 9)
        };
        let agent_policy = if width == 1 { policy(&keys[0]) } else { wide_policy(&keys) };
        let (result, address) =
            f.register_with(agent_policy, [0xd3; 32], |action| all_sign(&keys, action));
        let gas = gas_at(&result, &address);
        eprintln!("width {width}: register_agent: gas {}", gas.used);
        assert_within_ceiling("register_agent", gas, true);
    }
}

/// The widest add and withdrawal -- eight signatures -- fit one relayed
/// external message under both the fixture's 65,535-byte maximum and the
/// generated genesis' ConfigParam 43.
#[test]
fn widest_delegation_messages_fit_one_external_message() {
    let genesis = genesis_config();
    let limit = genesis.size_limits_config().expect("ConfigParam 43").max_ext_msg_size as usize;
    eprintln!("ConfigParam 43 max_ext_msg_size: {limit} B");
    let (f, keys) = measured(MAX_WIDTH, &population(Shape::Hashed, 127, 383));
    for (path, kind) in
        [("delegate_agent", DELEGATE_AGENT), ("withdraw_delegation", WITHDRAW_DELEGATION)]
    {
        let action = f.next_action(kind, delegation_payload(&hashed(0), 1));
        let message = MessageBuilder::internal(f.relayer.address(), &f.registry, MEASURE_VALUE)
            .body(submit_body(action.clone(), all_sign(&keys, &action), empty_signatures()))
            .build();
        let bytes = relayer_external_bytes(&message);
        eprintln!("width {MAX_WIDTH}: {path}: external message {bytes} B");
        assert!(bytes <= MAX_EXTERNAL_MESSAGE_BYTES, "{path}: {bytes} B over the fixture maximum");
        assert!(bytes <= limit, "{path}: {bytes} B over ConfigParam 43");
    }
}

/// The configuration of the genesis this repository generates.
fn genesis_config() -> chain_block::ConfigParams {
    let directory = tempfile::tempdir().expect("genesis wrapper directory");
    let wrapper = directory.path().join("genesis.fif");
    let template =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont/gen-zerostate.fif");
    std::fs::write(
        &wrapper,
        format!(
            "0x{} constant quantum-network-tag\ntrue constant quantum-admission-candidate\n\"{template}\" include\n",
            "42".repeat(32)
        ),
    )
    .expect("write genesis wrapper");
    let state = tos_sandbox::generate_zerostate_state(&wrapper).expect("generate genesis");
    state.read_custom().expect("masterchain extra").expect("masterchain").config
}

/// Account storage at the bound and after a bump, the rent it accrues under
/// the generated genesis' ConfigParam 18, and the ConfigParam 21 limits at
/// which the basechain freezes and deletes it. Then, under the fixture's own
/// prices, the account is aged to either side of its freeze threshold: below
/// it a withdrawal succeeds and pays the debt; past it the account freezes,
/// and a frozen Agent refuses the withdrawal.
#[test]
fn storage_rent_at_the_bound_and_the_frozen_refusal() {
    use tos_executor::BlockchainConfig;
    let genesis = genesis_config();
    let genesis_prices = BlockchainConfig::with_config(genesis.clone()).expect("genesis executor");
    let basechain = genesis.gas_prices(false).expect("ConfigParam 21");
    eprintln!(
        "ConfigParam 21: freeze_due_limit {} delete_due_limit {}",
        basechain.freeze_due_limit, basechain.delete_due_limit
    );
    let stored = genesis.storage_prices().expect("ConfigParam 18");
    for price in stored.prices().expect("prices") {
        eprintln!(
            "ConfigParam 18: since {} bit_ps {} cell_ps {}",
            price.utime_since, price.bit_price_ps, price.cell_price_ps
        );
    }

    let year = 365 * 24 * 3600u32;
    let used = |f: &Fixture| {
        let account = f.bc.get_account(&f.registry).expect("account");
        let info = account.storage_info().expect("storage info").clone();
        (info.used().cells(), info.used().bits(), info)
    };
    let mut rows = Vec::new();
    for (label, seeded, added) in [
        ("one live", Vec::new(), [0xe1; 32]),
        ("hashed 128/384", population(Shape::Hashed, 127, 383), Shape::Hashed.digest(383)),
        ("spine 128/384", population(Shape::Spine, 127, 383), Shape::Spine.digest(383)),
    ] {
        let full = !seeded.is_empty();
        // One real add brings the population to its size and refreshes the
        // account's storage statistics.
        let (mut f, keys) = measured(MAX_WIDTH, &seeded);
        f.delegation(DELEGATE_AGENT, &added, 1, &refs(&keys)).1.expect_success();
        if full {
            assert_eq!(f.counts(), (1, 128, 384));
        }
        let (cells, bits, info) = used(&f);
        let rent = genesis_prices
            .calc_storage_fees(&info, false, info.last_paid() + year)
            .expect("rent")
            .as_u128();
        let to_freeze = u128::from(basechain.freeze_due_limit) * u128::from(year) / rent.max(1);
        eprintln!(
            "storage {label}: {cells} cells {bits} bits; genesis rent {rent} nanotomi per year; \
             debt reaches freeze_due_limit after ~{to_freeze} s"
        );
        rows.push((label, cells, bits));

        if full {
            let signers = refs(&keys);
            let next = wide_policy(&keys);
            f.update(&next, &signers, &signers).1.expect_success();
            let (after_cells, after_bits, _) = used(&f);
            eprintln!("storage {label} after a bump: {after_cells} cells {after_bits} bits");
            assert!(after_cells < cells && after_bits < bits, "a bump releases the storage");
        }
    }
    assert!(rows[1].1 > rows[0].1, "the bounded set is stored");

    // Ages under the fixture's prices: debt below and past the freeze limit.
    // The messages bounce, so the storage phase charges before any value is
    // credited, as it does for a relayed submission.
    let fixture_gas = Fixture::new().bc.config_params().gas_prices(false).expect("fixture CP21");
    for (age, freezes) in [(30 * 24 * 3600u32, false), (50 * year, true)] {
        let mut f = Fixture::new();
        f.add(&[0xe2; 32]).expect_success();
        let mut account = f.bc.get_account(&f.registry).unwrap().clone();
        account.set_balance(chain_block::CurrencyCollection::with_coins(1_000));
        f.bc.set_account(f.registry.clone(), account);
        let now = f.bc.now() + age;
        f.bc.set_now(now);
        // The fixture runs the default configuration at the network's version.
        let config =
            BlockchainConfig::default_with_global_version(current_network::global_version())
                .expect("fixture configuration");
        let info = f.bc.get_account(&f.registry).unwrap().storage_info().unwrap().clone();
        let debt = config.calc_storage_fees(&info, false, now).expect("debt").as_u128();
        eprintln!(
            "age {age} s: debt {debt} nanotomi against freeze_due_limit {}",
            fixture_gas.freeze_due_limit
        );
        let action = f.next_action(WITHDRAW_DELEGATION, delegation_payload(&[0xe2; 32], 1));
        let key = f.old_key.clone();
        let value = if freezes { 1_000 } else { MEASURE_VALUE };
        let message = MessageBuilder::internal(f.relayer.address(), &f.registry, value)
            .bounce(true)
            .body(submit_body(action.clone(), signature_set(&key, &action), empty_signatures()))
            .build();
        let result = traced(&mut f.bc, |bc| bc.send_message(message).expect("withdraw"));
        let account = f.bc.get_account(&f.registry).expect("account");
        if freezes {
            assert!(debt > u128::from(fixture_gas.freeze_due_limit), "aged past the limit");
            assert!(account.is_frozen(), "the debt froze the Agent");
            let transaction = result.transactions_for(&f.registry).into_iter().last().expect("tx");
            let TransactionDescr::Ordinary(description) = transaction.read_description().unwrap()
            else {
                panic!("ordinary")
            };
            assert!(
                matches!(description.compute_ph, TrComputePhase::Skipped(_)),
                "a frozen Agent runs no code: the withdrawal is refused"
            );
            assert!(
                f.bc.get_account(&f.registry).unwrap().get_data().is_none() || account.is_frozen()
            );
        } else {
            assert!(debt <= u128::from(fixture_gas.freeze_due_limit), "below the limit");
            assert!(!account.is_frozen());
            assert_address_success(&result, &f.registry);
            assert!(f.entry(&[0xe2; 32]).expect("entry").withdrawn);
        }
    }
}
