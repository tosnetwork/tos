/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The elector's post-quantum state: a member is a controlling account, and a consensus
//! key belongs to exactly one of them.
//!
//! Two directions of one fact. Membership is keyed by the controller, so rotating a key
//! does not move a validator in or out of the set; the reverse index exists so two
//! controllers cannot register the same key, because the validator set that would produce
//! is one the node refuses for duplicate key identity — after it is already authoritative.
//!
//! The state this builds is also measured, against the figures the design was approved
//! with. A layout that grew would be a different design than the one that was sized.

use chain_block::{Cell, GetRepresentationHash, MsgAddressInt, Serializable, StateInit};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::{StackItem, integer::IntegerData};

const TOS: u64 = 1_000_000_000;
const MLDSA44_PUBLIC_KEY_BYTES: usize = 1312;
/// A key already registered by another controller.
const ERROR_KEY_OWNED: i32 = 68;
const ERROR_ZERO_VALIDATOR_ID: i32 = 65;
/// The member record and the reverse index disagree about who holds a key.
const ERROR_INDEX_DISAGREES: i32 = 69;

/// What the same state cost when the storage shape was approved, from
/// `build/crypto/pq/n3-state-measure`: members plus the reverse index, in cells.
const APPROVED_CELLS_AT_100: u64 = 1698;
const APPROVED_CELLS_AT_400: u64 = 6798;

fn repo_root() -> std::path::PathBuf {
    std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root")
            .to_path_buf()
    })
}

fn probe_code() -> Cell {
    let probe = std::env::temp_dir().join("tos_pq_elector_state_probe.fc");
    std::fs::write(
        &probe,
        r#"
(cell, cell) probe_register(cell members, cell key_owner, int validator_id, int algorithm_id,
                            cell public_key, int adnl) method_id {
  ;; The controller code is a fixed stand-in here: this file measures and exercises the
  ;; book, and which code admitted a member is the elector's business.
  return pq::register_member(members, key_owner, validator_id, 11000000000000, 1789434000, 0x10000,
                             algorithm_id, public_key, adnl, 0xc0de);
}
int probe_key_holder(cell key_owner, int key_id) method_id {
  return pq::key_holder(key_owner, key_id);
}
(int, int, int, int, int, int) probe_member(cell members, int validator_id) method_id {
  (slice ms, int found) = members.udict_get?(256, validator_id);
  ifnot (found) {
    return (0, 0, 0, 0, 0, 0);
  }
  (int stake, int at, int max_factor, int algorithm_id, int key_id, cell public_key, int adnl, _) =
    pq::unpack_member(ms);
  return (stake, at, max_factor, algorithm_id, key_id, adnl);
}
;; Builds a whole registration book from real keys, so its size is the size of state the
;; contract writes rather than of a model of it. The keys arrive as a dictionary because
;; they have to be distinct: identical cells are stored once, and a book of one repeated
;; key would measure the cache instead of the state.
(cell, cell) probe_fill(cell keys, int count) method_id {
  cell members = new_dict();
  cell key_owner = new_dict();
  int index = 0;
  while (index < count) {
    (cell public_key, int found) = keys.udict_get_ref?(32, index);
    throw_unless(70, found);
    int validator_id = cell_hash(begin_cell().store_uint(index, 32).end_cell());
    int adnl = cell_hash(begin_cell().store_uint(index, 32).store_uint(1, 8).end_cell());
    (members, key_owner) = pq::register_member(members, key_owner, validator_id, 11000000000000,
                                               1789434000, 0x10000, 1, public_key, adnl, 0xc0de);
    index += 1;
  }
  return (members, key_owner);
}
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
}
"#,
    )
    .expect("probe source");
    compile_func_with_stdlib(&[repo_root().join("crypto/smartcont/pq-validator.fc"), probe])
        .expect("the library and its probe compile")
}

fn deploy(chain: &mut Blockchain) -> MsgAddressInt {
    let state = StateInit::with_code_and_data(probe_code(), Cell::default());
    let address = MsgAddressInt::with_params(
        -1,
        state.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("address");
    let deployer = chain.treasury("elector-state-funder", 1_000 * TOS).expect("funding");
    chain
        .send_message(
            MessageBuilder::internal(deployer.address(), &address, 100 * TOS)
                .bounce(false)
                .state_init(state)
                .body(Cell::default())
                .build(),
        )
        .expect("deployment")
        .expect_success();
    address
}

fn stored_key(seed: u8) -> Cell {
    chain_block::pq_bytes::pack_pq_bytes(
        &vec![seed; MLDSA44_PUBLIC_KEY_BYTES],
        chain_block::pq_bytes::PQ_BYTES_HARD_MAX,
    )
    .expect("a key of admitted length")
}

fn key_id_of(seed: u8) -> IntegerData {
    IntegerData::from_unsigned_bytes_be(
        chain_block::derive_consensus_key_id(1, &vec![seed; MLDSA44_PUBLIC_KEY_BYTES]).as_slice(),
    )
}

fn identity(byte: u8) -> IntegerData {
    IntegerData::from_unsigned_bytes_be(&[byte; 32])
}

struct Book {
    members: StackItem,
    key_owner: StackItem,
}

impl Book {
    fn empty() -> Self {
        Book { members: StackItem::None, key_owner: StackItem::None }
    }
}

/// Register a key for a controller, returning the updated book or the error code.
#[allow(clippy::result_large_err)]
fn register(
    chain: &Blockchain,
    probe: &MsgAddressInt,
    book: &Book,
    validator: u8,
    key_seed: u8,
    adnl: u8,
) -> Result<Book, i32> {
    let result = chain
        .run_get_method(
            probe,
            "probe_register",
            vec![
                book.members.clone(),
                book.key_owner.clone(),
                StackItem::integer(identity(validator)),
                StackItem::int(1),
                StackItem::Cell(stored_key(key_seed)),
                StackItem::integer(identity(adnl)),
            ],
        )
        .expect("the probe answers");
    if result.exit_code != 0 {
        return Err(result.exit_code);
    }
    let key_owner = result.stack.last().expect("the reverse index").clone();
    let members = result.stack[result.stack.len() - 2].clone();
    Ok(Book { members, key_owner })
}

fn holder(chain: &Blockchain, probe: &MsgAddressInt, book: &Book, key_seed: u8) -> String {
    let result = chain
        .run_get_method(
            probe,
            "probe_key_holder",
            vec![book.key_owner.clone(), StackItem::integer(key_id_of(key_seed))],
        )
        .expect("the probe answers");
    assert_eq!(result.exit_code, 0, "key_holder failed");
    result.stack.last().expect("a holder").as_integer().expect("an integer").to_string()
}

fn member_key_id(chain: &Blockchain, probe: &MsgAddressInt, book: &Book, validator: u8) -> String {
    let result = chain
        .run_get_method(
            probe,
            "probe_member",
            vec![book.members.clone(), StackItem::integer(identity(validator))],
        )
        .expect("the probe answers");
    assert_eq!(result.exit_code, 0, "member lookup failed");
    // stake, at, max_factor, algorithm_id, key_id, adnl
    result.stack[result.stack.len() - 2].as_integer().expect("an integer").to_string()
}

fn chain_at_16() -> Blockchain {
    let mut chain =
        Blockchain::with_global_version(16).expect("a chain at the post-quantum version");
    chain.set_workchain(-1);
    chain
}

#[test]
fn a_registration_records_the_member_and_claims_the_key() {
    let mut chain = chain_at_16();
    let probe = deploy(&mut chain);

    let book = register(&chain, &probe, &Book::empty(), 0xa1, 0x11, 0xc1).expect("a registration");
    assert_eq!(
        holder(&chain, &probe, &book, 0x11),
        identity(0xa1).to_string(),
        "the key was not claimed by the controller that registered it"
    );
    assert_eq!(
        member_key_id(&chain, &probe, &book, 0xa1),
        key_id_of(0x11).to_string(),
        "the member record does not hold the key that was registered"
    );
}

#[test]
fn a_key_registered_by_one_controller_cannot_be_registered_by_another() {
    let mut chain = chain_at_16();
    let probe = deploy(&mut chain);

    let book = register(&chain, &probe, &Book::empty(), 0xa1, 0x11, 0xc1).expect("a registration");
    assert_eq!(
        register(&chain, &probe, &book, 0xa2, 0x11, 0xc2).err(),
        Some(ERROR_KEY_OWNED),
        "two controllers registered the same consensus key"
    );
    // The refused attempt changed nothing: the key is still the first controller's.
    assert_eq!(holder(&chain, &probe, &book, 0x11), identity(0xa1).to_string());
}

#[test]
fn rotating_a_key_releases_the_one_it_replaces() {
    let mut chain = chain_at_16();
    let probe = deploy(&mut chain);

    let first = register(&chain, &probe, &Book::empty(), 0xa1, 0x11, 0xc1).expect("a registration");
    let rotated = register(&chain, &probe, &first, 0xa1, 0x22, 0xc1).expect("a rotation");

    assert_eq!(
        member_key_id(&chain, &probe, &rotated, 0xa1),
        key_id_of(0x22).to_string(),
        "the member record still holds the key that was rotated away from"
    );
    assert_eq!(holder(&chain, &probe, &rotated, 0x22), identity(0xa1).to_string());
    assert_eq!(
        holder(&chain, &probe, &rotated, 0x11),
        "0",
        "the released key is still claimed, so nobody else can ever register it"
    );

    // And the released key really is free: another controller may now take it.
    register(&chain, &probe, &rotated, 0xa2, 0x11, 0xc2).expect("the released key is free");
}

/// A rotation reads which key to release from the member record, and releases it from an
/// index it is handed. Both are arguments, so the two can be made to disagree, and the
/// book that results is not one any registration builds.
///
/// Releasing on the word of the member record alone would take a key from the controller
/// the index says holds it. Nothing downstream could notice: the robbed controller keeps
/// a member record naming a key anyone may now register, and the validator set that
/// eventually carries two claims to one key is refused by the node after it is already
/// authoritative.
#[test]
fn a_rotation_will_not_release_a_key_the_index_gives_to_someone_else() {
    let mut chain = chain_at_16();
    let probe = deploy(&mut chain);

    let mine = register(&chain, &probe, &Book::empty(), 0xa1, 0x11, 0xc1).expect("a registration");
    let theirs =
        register(&chain, &probe, &Book::empty(), 0xa2, 0x11, 0xc2).expect("a registration");

    // One controller's records, another's index: the record claims a key the index gives
    // to someone else.
    let disagreeing = Book { members: mine.members.clone(), key_owner: theirs.key_owner.clone() };
    assert_eq!(
        register(&chain, &probe, &disagreeing, 0xa1, 0x22, 0xc1).err(),
        Some(ERROR_INDEX_DISAGREES),
        "a rotation released a key the index had given to another controller"
    );

    // And the same when the index has forgotten the key entirely, which is the other way
    // the two halves can part.
    let unindexed = Book { members: mine.members.clone(), key_owner: StackItem::None };
    assert_eq!(
        register(&chain, &probe, &unindexed, 0xa1, 0x22, 0xc1).err(),
        Some(ERROR_INDEX_DISAGREES),
        "a rotation released a key the index does not record at all"
    );

    // The rule is about disagreement, not about rotation: the consistent book still works.
    register(&chain, &probe, &mine, 0xa1, 0x22, 0xc1).expect("a rotation of a consistent book");
}

#[test]
fn a_registration_without_an_identity_is_refused() {
    let mut chain = chain_at_16();
    let probe = deploy(&mut chain);
    assert_eq!(
        register(&chain, &probe, &Book::empty(), 0x00, 0x11, 0xc1).err(),
        Some(ERROR_ZERO_VALIDATOR_ID),
        "a member was registered without a validator identity"
    );
}

/// Distinct keys, built with the production encoder, indexed for the probe to walk.
///
/// Distinct to the last byte. Keys sharing a tail share the cells that carry it, and a
/// book built from such keys measures the cell cache instead of the state — which is how
/// the first run of this test reported a third of the real size.
fn distinct_keys(count: usize) -> Cell {
    use chain_block::{BuilderData, HashmapE, IBitstring, SliceData};
    let mut dict = HashmapE::with_bit_len(32);
    for index in 0..count {
        let mut bytes = Vec::with_capacity(MLDSA44_PUBLIC_KEY_BYTES);
        let mut block = chain_block::sha256_digest(format!("elector-state-{index}").as_bytes());
        while bytes.len() < MLDSA44_PUBLIC_KEY_BYTES {
            bytes.extend_from_slice(&block);
            block = chain_block::sha256_digest(block);
        }
        bytes.truncate(MLDSA44_PUBLIC_KEY_BYTES);
        let mut key = BuilderData::new();
        key.append_u32(index as u32).expect("index");
        dict.setref(
            SliceData::load_builder(key).expect("key"),
            chain_block::pq_bytes::pack_pq_bytes(&bytes, chain_block::pq_bytes::PQ_BYTES_HARD_MAX)
                .expect("a key of admitted length"),
        )
        .expect("insert");
    }
    chain_block::HashmapType::data(&dict).expect("a non-empty dictionary").clone()
}

/// Unique cells, the way an account's state is counted.
fn cells(root: &Cell) -> u64 {
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![root.clone()];
    while let Some(cell) = stack.pop() {
        if !seen.insert(cell.repr_hash()) {
            continue;
        }
        for index in 0..cell.references_count() {
            stack.push(cell.reference(index).expect("a reference"));
        }
    }
    seen.len() as u64
}

#[test]
fn the_registration_book_is_the_size_the_design_was_approved_at() {
    let mut chain = chain_at_16();
    let probe = deploy(&mut chain);

    for (count, approved) in [(100usize, APPROVED_CELLS_AT_100), (400, APPROVED_CELLS_AT_400)] {
        let result = chain
            .run_get_method_with_gas(
                &probe,
                "probe_fill",
                vec![StackItem::Cell(distinct_keys(count)), StackItem::int(count as i64)],
                70_000_000,
            )
            .expect("the probe answers");
        assert_eq!(result.exit_code, 0, "filling {count} members failed: {}", result.exit_code);
        let key_owner =
            result.stack.last().expect("the reverse index").as_cell().expect("a cell").clone();
        let members = result.stack[result.stack.len() - 2].as_cell().expect("a cell").clone();
        let total = cells(&members) + cells(&key_owner);

        eprintln!("{count} registered members: {total} cells (approved at {approved})");
        // The measurement the design was approved with modelled the record in C++. This
        // is the record the contract actually writes, so it has to land on the same
        // number in both directions: larger means the shape that shipped is not the shape
        // that was sized, and much smaller means the keys were not distinct and the
        // measurement is of the cell cache.
        let margin = approved / 10;
        assert!(
            total <= approved + margin && total + margin >= approved,
            "the book at {count} members is {total} cells against the {approved} the design was approved at"
        );
    }
}
