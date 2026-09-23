/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Sections 6 and 8 of the V1 implementation profile: the anchor policy, and
//! the execution domain and recipient hashing.
//!
//! The anchor rules are what let a proof made a moment ago still land. They are
//! also the place where "the slot is occupied" must never be mistaken for "the
//! root is authentic", so every acceptance test here pairs a valid case with a
//! slot that holds something else.
//!
//! Retention is stated by the profile in leaf versions, not in transactions, so
//! the overwrite tests use exact version arithmetic rather than counting
//! transactions: a deposit appends one leaf and a transact appends three, and
//! assuming 4096 transactions would be assuming a traffic mix.

use sha2::{Digest, Sha256};

use chain_block::{
    BuilderData, Cell, HashmapE, HashmapType, IBitstring, MsgAddressInt, Serializable, SliceData,
    StateInit,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::StackItem;
use tos_vm::stack::integer::IntegerData;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;
const RECENT_SLOTS: u64 = 4096;
const EPOCH_SECONDS: u64 = 30;
const EPOCH_SLOTS: u64 = 2880;

type Field = [u8; 32];

const ANCHOR_CURRENT: u64 = 0;
const ANCHOR_RECENT: u64 = 1;
const ANCHOR_EPOCH: u64 = 2;

// ---------------------------------------------------------------------------
// Reference: sections 6 and 8 written out.

fn modulus() -> Field {
    from_dec("52435875175126190479447740508185965837690552500527637822603658699938581184513")
}

/// A digest brought into the field, which sections 1.4 and 8 allow only for
/// values the contract derives itself.
fn reduce(digest: [u8; 32]) -> Field {
    let mut value = digest;
    let m = modulus();
    while value[..] >= m[..] {
        value = subtract(&value, &m);
    }
    value
}

fn subtract(a: &Field, b: &Field) -> Field {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let mut diff = a[index] as i16 - b[index] as i16 - borrow;
        borrow = if diff < 0 {
            diff += 256;
            1
        } else {
            0
        };
        out[index] = diff as u8;
    }
    out
}

fn reference_execution_domain(global_id: i32, pool_account: &Field) -> Field {
    let mut hasher = Sha256::new();
    hasher.update(b"TOS-SHIELDED-EXEC-v1");
    hasher.update(global_id.to_be_bytes());
    hasher.update([0u8]);
    hasher.update(pool_account);
    hasher.update(1u16.to_be_bytes());
    reduce(hasher.finalize().into())
}

fn reference_recipient_hash(account: &Field) -> Field {
    let mut hasher = Sha256::new();
    hasher.update(b"TOS-SHIELDED-RECIPIENT-v1");
    hasher.update(account);
    reduce(hasher.finalize().into())
}

// ---------------------------------------------------------------------------

fn dec(bytes: &Field) -> String {
    let mut digits = vec![0u8];
    for &byte in bytes {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            let value = (*digit as u32) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

fn from_dec(text: &str) -> Field {
    let mut out = [0u8; 32];
    for ch in text.bytes() {
        let mut carry = (ch - b'0') as u32;
        for byte in out.iter_mut().rev() {
            let value = (*byte as u32) * 10 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        assert_eq!(carry, 0, "value does not fit in 256 bits: {text}");
    }
    out
}

fn small(value: u64) -> Field {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// A root that looks like a root: full width, so a comparison against it is not
/// two truncated zeros agreeing.
fn root(seed: u64) -> Field {
    let mut hasher = Sha256::new();
    hasher.update(b"anchor-test-root");
    hasher.update(seed.to_be_bytes());
    reduce(hasher.finalize().into())
}

const PROBE: &str = r#"
int p_execution_domain() method_id { return execution_domain(); }
int p_recipient_hash(slice recipient) method_id { return public_recipient_hash(recipient); }
int p_global_id() method_id { return global_id(); }
cell p_empty_anchors() method_id { return anchors_empty(); }
(cell, int) p_preserve(cell anchors, int next_index, int root, int now, int last_epoch) method_id {
  return anchors_preserve(anchors, next_index, root, now, last_epoch);
}
int p_check(cell anchors, int kind, int id, int root, int current_root, int now) method_id {
  anchor_require_valid(anchors, kind, id, root, current_root, now);
  return 1;
}
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

struct Probe {
    bc: Blockchain,
    addr: MsgAddressInt,
    account: Field,
}

impl Probe {
    fn deploy() -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
            .expect("blockchain at version 17");
        let payer = bc.treasury("deployer", 1_000 * TOS).expect("treasury");
        let library = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont/shielded");
        // A directory of this call's own. These probes are written from several tests at
        // once, and a shared path is truncated under a concurrent `func` reading it.
        let probe_dir = tempfile::tempdir().expect("a directory for the probe");
        let probe_path = probe_dir.path().join("tos_shielded_anchors_probe.fc");
        std::fs::write(&probe_path, PROBE).expect("write probe");
        let code = compile_func_with_stdlib(&[
            format!("{library}/domains.fc").into(),
            format!("{library}/empty-roots.fc").into(),
            format!("{library}/notes.fc").into(),
            format!("{library}/domain.fc").into(),
            format!("{library}/anchors.fc").into(),
            probe_path,
        ])
        .expect("compile the shielded library (needs build/crypto/func)");
        let mut data = BuilderData::new();
        data.append_u32(0).unwrap();
        let si = StateInit::with_code_and_data(code, data.into_cell().unwrap());
        let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
        let mut account = [0u8; 32];
        account.copy_from_slice(hash.as_slice());
        let addr = MsgAddressInt::with_params(0, hash).unwrap();
        bc.send_message(
            MessageBuilder::internal(payer.address(), &addr, 2 * TOS)
                .bounce(false)
                .state_init(si)
                .body(Cell::default())
                .build(),
        )
        .expect("deploy")
        .expect_success();
        Self { bc, addr, account }
    }

    fn field(value: &Field) -> StackItem {
        StackItem::integer(IntegerData::from_str_radix(&dec(value), 10).expect("a field element"))
    }

    fn call(&self, method: &str, args: Vec<StackItem>) -> Result<Vec<StackItem>, i32> {
        let result = self
            .bc
            .run_get_method(&self.addr, method, args)
            .unwrap_or_else(|e| panic!("{method}: {e}"));
        if result.exit_code != 0 {
            return Err(result.exit_code);
        }
        Ok(result.stack)
    }

    fn call_field(&self, method: &str, args: Vec<StackItem>) -> Field {
        let stack = self.call(method, args).unwrap_or_else(|code| panic!("{method} exited {code}"));
        let text = stack.last().expect("a result").as_integer().expect("integer").to_string();
        let value = from_dec(&text);
        assert_eq!(dec(&value), text, "{method}: the decimal round trip is not exact");
        value
    }

    fn global_id(&self) -> i32 {
        let stack = self.call("p_global_id", vec![]).expect("p_global_id");
        stack
            .last()
            .expect("a result")
            .as_integer()
            .expect("integer")
            .to_string()
            .parse()
            .expect("i32")
    }

    fn empty_anchors(&self) -> Cell {
        let stack = self.call("p_empty_anchors", vec![]).expect("p_empty_anchors");
        stack.last().expect("a result").as_cell().expect("a cell").clone()
    }

    fn preserve(
        &self,
        anchors: &Cell,
        next_index: u64,
        root: &Field,
        now: u64,
        last_epoch: u64,
    ) -> (Cell, u64) {
        let stack = self
            .call(
                "p_preserve",
                vec![
                    StackItem::Cell(anchors.clone()),
                    StackItem::int(next_index as i64),
                    Self::field(root),
                    StackItem::int(now as i64),
                    StackItem::int(last_epoch as i64),
                ],
            )
            .unwrap_or_else(|code| panic!("p_preserve exited {code}"));
        assert_eq!(stack.len(), 2, "preserve returns the store and the epoch");
        let epoch: u64 = stack[1].as_integer().expect("integer").to_string().parse().expect("u64");
        (stack[0].as_cell().expect("a cell").clone(), epoch)
    }

    fn preserve_exit(&self, anchors: &Cell, next_index: &str, root: &Field) -> i32 {
        self.call(
            "p_preserve",
            vec![
                StackItem::Cell(anchors.clone()),
                StackItem::integer(IntegerData::from_str_radix(next_index, 10).expect("index")),
                Self::field(root),
                StackItem::int(0),
                StackItem::int(0),
            ],
        )
        .err()
        .unwrap_or(0)
    }

    fn check(
        &self,
        anchors: &Cell,
        kind: u64,
        id: u64,
        anchor_root: &Field,
        current_root: &Field,
        now: u64,
    ) -> i32 {
        self.call(
            "p_check",
            vec![
                StackItem::Cell(anchors.clone()),
                StackItem::int(kind as i64),
                StackItem::int(id as i64),
                Self::field(anchor_root),
                Self::field(current_root),
                StackItem::int(now as i64),
            ],
        )
        .err()
        .unwrap_or(0)
    }
}

/// The two rings, read out of the store the way a reader that is not this
/// contract would have to read them.
fn read_rings(anchors: &Cell) -> (Vec<(u64, u64, Field)>, Vec<(u64, u64, Field)>) {
    let mut slice = SliceData::load_cell_ref(anchors).expect("anchor root");
    assert_eq!(slice.remaining_bits(), 0, "the anchor root carries data");
    assert_eq!(slice.remaining_references(), 2, "the anchor root is not two references");
    let mut out = Vec::new();
    for _ in 0..2 {
        let holder = slice.checked_drain_reference().expect("a ring reference");
        let mut holder = SliceData::load_cell(holder).expect("a ring holder");
        // A HashmapE is one maybe-bit and, when it holds anything, the root.
        let present = holder.get_next_bit().expect("the HashmapE maybe bit");
        let dict = if present {
            Some(holder.checked_drain_reference().expect("the hashmap root"))
        } else {
            None
        };
        assert_eq!(holder.remaining_bits(), 0, "a ring holder carries trailing data");
        assert_eq!(holder.remaining_references(), 0, "a ring holder carries extra references");
        let mut entries = Vec::new();
        HashmapType::iterate_slices(&HashmapE::with_hashmap(12, dict), |key, mut value| {
            let slot = key.clone().get_next_int(12).expect("a slot key");
            assert_eq!(value.remaining_bits(), 288, "an entry is not 32 + 256 bits");
            assert_eq!(value.remaining_references(), 0, "an entry carries a reference");
            let id = value.get_next_int(32).expect("an id");
            let mut root = [0u8; 32];
            for byte in root.iter_mut() {
                *byte = value.get_next_byte().expect("a root byte");
            }
            entries.push((slot, id, root));
            Ok(true)
        })
        .expect("iterate a ring");
        out.push(entries);
    }
    let epoch = out.pop().expect("the epoch ring");
    let recent = out.pop().expect("the recent ring");
    (recent, epoch)
}

// ---------------------------------------------------------------------------

#[test]
fn the_execution_domain_is_the_profiles_preimage_over_this_account() {
    let probe = Probe::deploy();
    let global_id = probe.global_id();
    let expected = reference_execution_domain(global_id, &probe.account);
    assert_eq!(
        probe.call_field("p_execution_domain", vec![]),
        expected,
        "the contract's execution domain is not section 8's preimage"
    );
    assert!(dec(&expected).len() > 70, "the domain is not a full-width field element");

    // Both of the values that make it this pool's domain have to reach it.
    assert_ne!(
        expected,
        reference_execution_domain(global_id ^ 1, &probe.account),
        "the global id does not reach the domain"
    );
    assert_ne!(
        expected,
        reference_execution_domain(global_id, &small(1)),
        "the pool account does not reach the domain"
    );
}

#[test]
fn a_recipient_hash_is_only_defined_for_a_workchain_zero_std_address() {
    let probe = Probe::deploy();
    let account = root(7);

    let mut ok = BuilderData::new();
    ok.append_bits(2, 2).unwrap(); // addr_std
    ok.append_bit_zero().unwrap(); // no anycast
    ok.append_i8(0).unwrap(); // workchain 0
    ok.append_raw(&account, 256).unwrap();
    let address = SliceData::load_builder(ok).expect("an address");
    assert_eq!(
        probe.call_field("p_recipient_hash", vec![StackItem::Slice(address)]),
        reference_recipient_hash(&account),
        "the recipient hash is not section 8's preimage"
    );

    // Anything that is not a non-anycast workchain-0 std address is refused.
    let mut wrong_chain = BuilderData::new();
    wrong_chain.append_bits(2, 2).unwrap();
    wrong_chain.append_bit_zero().unwrap();
    wrong_chain.append_i8(-1).unwrap();
    wrong_chain.append_raw(&account, 256).unwrap();
    let mut anycast = BuilderData::new();
    anycast.append_bits(2, 2).unwrap();
    anycast.append_bit_one().unwrap();
    anycast.append_i8(0).unwrap();
    anycast.append_raw(&account, 256).unwrap();
    let mut trailing = BuilderData::new();
    trailing.append_bits(2, 2).unwrap();
    trailing.append_bit_zero().unwrap();
    trailing.append_i8(0).unwrap();
    trailing.append_raw(&account, 256).unwrap();
    trailing.append_bit_zero().unwrap();

    for (what, builder) in [
        ("a masterchain address", wrong_chain),
        ("an anycast address", anycast),
        ("trailing bits", trailing),
    ] {
        let slice = SliceData::load_builder(builder).expect("an address");
        let exit = probe.call("p_recipient_hash", vec![StackItem::Slice(slice)]).err().unwrap_or(0);
        assert_eq!(exit, 170, "{what} was hashed anyway");
    }
}

#[test]
fn preserving_writes_the_pre_transaction_root_under_its_own_version() {
    let probe = Probe::deploy();
    let anchors = probe.empty_anchors();
    let (recent, epoch) = read_rings(&anchors);
    assert!(recent.is_empty() && epoch.is_empty(), "the genesis store is not empty");

    // A deposit about to append its first leaf: the version is the index the
    // leaf will take, and the root is the one before the append.
    let before = root(1);
    let (after, last_epoch) = probe.preserve(&anchors, 0, &before, 0, 0xffff_ffff);
    let (recent, epoch) = read_rings(&after);
    assert_eq!(
        recent,
        vec![(0, 0, before)],
        "the recent ring did not take the pre-transaction root"
    );
    assert_eq!(epoch, vec![(0, 0, before)], "the first mutation did not open an epoch checkpoint");
    assert_eq!(last_epoch, 0, "the epoch was not recorded");

    // Half a ring away lands on its own slot and disturbs nothing. This is the
    // case that distinguishes the ring's own modulus from any smaller one: a
    // 2048-slot ring would fold this version onto slot 0 and lose the first.
    let half = root(6);
    let (half_way, _) = probe.preserve(&after, RECENT_SLOTS / 2, &half, 0, 0);
    let (recent, _) = read_rings(&half_way);
    assert_eq!(
        recent,
        vec![(0, 0, before), (RECENT_SLOTS / 2, RECENT_SLOTS / 2, half)],
        "half a ring away did not land on its own slot"
    );
    assert_eq!(
        probe.check(&half_way, ANCHOR_RECENT, 0, &before, &half, 0),
        0,
        "the earlier root stopped being valid although its slot was untouched"
    );

    // A full ring away lands on slot 0 again and takes it over. This is exact
    // version arithmetic, not a transaction count.
    let later = root(2);
    let (after, _) = probe.preserve(&after, RECENT_SLOTS, &later, 0, 0);
    let (recent, _) = read_rings(&after);
    assert_eq!(
        recent,
        vec![(0, RECENT_SLOTS, later)],
        "the slot was not overwritten by its own version"
    );
    assert_eq!(
        probe.check(&after, ANCHOR_RECENT, 0, &before, &later, 0),
        153,
        "the overwritten root is still accepted"
    );
}

#[test]
fn the_epoch_checkpoint_keeps_the_root_that_opened_the_epoch() {
    let probe = Probe::deploy();
    let opening = root(3);
    let (anchors, epoch_id) = probe.preserve(&probe.empty_anchors(), 0, &opening, 90, 0xffff_ffff);
    assert_eq!(epoch_id, 3, "90 seconds is epoch 3");

    // A second mutation inside the same epoch moves the recent ring but must
    // leave the checkpoint alone.
    let later = root(4);
    let (anchors, epoch_id) = probe.preserve(&anchors, 1, &later, 119, epoch_id);
    assert_eq!(epoch_id, 3, "the epoch changed inside the same 30 seconds");
    let (recent, epoch) = read_rings(&anchors);
    assert_eq!(recent.len(), 2, "the recent ring did not take the second root");
    assert_eq!(epoch, vec![(3, 3, opening)], "the checkpoint was overwritten inside its epoch");

    // The next epoch opens a new one.
    let next = root(5);
    let (anchors, epoch_id) = probe.preserve(&anchors, 2, &next, 120, epoch_id);
    assert_eq!(epoch_id, 4, "120 seconds is epoch 4");
    let (_, epoch) = read_rings(&anchors);
    assert_eq!(epoch.len(), 2, "the new epoch did not open a checkpoint");
}

#[test]
fn an_anchor_is_accepted_only_on_an_exact_match() {
    let probe = Probe::deploy();
    let current = root(10);
    let (anchors, _) = probe.preserve(&probe.empty_anchors(), 5, &current, 3000, 0xffff_ffff);
    let now = 3000u64;
    let epoch = now / EPOCH_SECONDS;

    // Current.
    assert_eq!(probe.check(&anchors, ANCHOR_CURRENT, 0, &current, &current, now), 0);
    assert_eq!(
        probe.check(&anchors, ANCHOR_CURRENT, 1, &current, &current, now),
        152,
        "a current anchor with a non-zero id was accepted"
    );
    assert_eq!(
        probe.check(&anchors, ANCHOR_CURRENT, 0, &root(11), &current, now),
        152,
        "a current anchor that is not the current root was accepted"
    );

    // Recent: the stored pair, and nothing else.
    assert_eq!(probe.check(&anchors, ANCHOR_RECENT, 5, &current, &root(11), now), 0);
    assert_eq!(
        probe.check(&anchors, ANCHOR_RECENT, 5, &root(11), &root(11), now),
        153,
        "the slot was occupied, so a different root was accepted"
    );
    assert_eq!(
        probe.check(&anchors, ANCHOR_RECENT, 5 + RECENT_SLOTS, &current, &root(11), now),
        153,
        "a version that only shares a slot was accepted"
    );
    assert_eq!(
        probe.check(&anchors, ANCHOR_RECENT, 6, &current, &root(11), now),
        153,
        "an empty slot was accepted"
    );

    // Epoch: the stored pair, and inside the ring's retention.
    assert_eq!(probe.check(&anchors, ANCHOR_EPOCH, epoch, &current, &root(11), now), 0);
    assert_eq!(
        probe.check(&anchors, ANCHOR_EPOCH, epoch, &root(11), &root(11), now),
        154,
        "an epoch slot accepted a root it does not hold"
    );
    let a_day_later = now + EPOCH_SLOTS * EPOCH_SECONDS;
    assert_eq!(
        probe.check(&anchors, ANCHOR_EPOCH, epoch, &current, &root(11), a_day_later),
        155,
        "an epoch anchor a full ring old was still accepted"
    );
    assert_eq!(
        probe.check(
            &anchors,
            ANCHOR_EPOCH,
            epoch,
            &current,
            &root(11),
            a_day_later - EPOCH_SECONDS
        ),
        0,
        "the last epoch the ring still retains was refused"
    );

    // No other kind exists.
    for kind in [3u64, 4, 255] {
        assert_eq!(
            probe.check(&anchors, kind, 0, &current, &current, now),
            151,
            "anchor kind {kind} was accepted"
        );
    }
}

#[test]
fn an_exhausted_tree_has_no_version_left_to_preserve() {
    let probe = Probe::deploy();
    let anchors = probe.empty_anchors();
    assert_eq!(probe.preserve_exit(&anchors, "4294967296", &root(20)), 156, "2^32 was preserved");
    assert_eq!(
        probe.preserve_exit(&anchors, "4294967295", &root(20)),
        0,
        "the last usable version was refused"
    );
}

#[test]
fn a_store_that_is_not_the_frozen_shape_is_refused() {
    let probe = Probe::deploy();
    let anchors = probe.empty_anchors();

    // One reference instead of two.
    let mut one = BuilderData::new();
    one.checked_append_reference(Cell::default()).unwrap();
    // Three references.
    let mut three = BuilderData::new();
    for _ in 0..3 {
        three.checked_append_reference(Cell::default()).unwrap();
    }
    // Two references but data in the root.
    let mut with_data = BuilderData::new();
    with_data.append_bit_zero().unwrap();
    for _ in 0..2 {
        with_data.checked_append_reference(Cell::default()).unwrap();
    }

    for (what, builder) in
        [("one reference", one), ("three references", three), ("data in the root", with_data)]
    {
        let cell = builder.into_cell().expect("a store");
        assert_eq!(
            probe.check(&cell, ANCHOR_RECENT, 0, &root(1), &root(1), 0),
            150,
            "{what} was parsed as an anchor store"
        );
    }

    // The canonical store still works, so the assertions above are about shape.
    assert_eq!(probe.check(&anchors, ANCHOR_RECENT, 0, &root(1), &root(1), 0), 153);
}
