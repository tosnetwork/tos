/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! The shared FunC post-quantum primitives, held to the node's own answers.
//!
//! `crypto/smartcont/pq-validator.fc` is what the elector and the configuration contract
//! will read and write descriptors with. Every rule in it has a counterpart in the node's
//! decoder, and the two must agree in both directions: a contract that accepts what the
//! node refuses writes a validator set every node then rejects, which halts the chain
//! rather than registering something bad, and a contract that refuses what the node
//! accepts cannot elect anyone.
//!
//! The verdicts in `test/pq-native/descriptor-verdict-vectors.tsv` are produced by running the
//! node's decoder over each descriptor, not by restating its rules.

use chain_block::{
    Cell, GetRepresentationHash, MsgAddressInt, Serializable, StateInit, derive_consensus_key_id,
    read_single_root_boc,
};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func_with_stdlib};
use tos_vm::stack::{StackItem, integer::IntegerData};

const TOS: u64 = 1_000_000_000;
const MLDSA44_PUBLIC_KEY_BYTES: usize = 1312;

/// The library's error codes, as a caller has to know them to tell one refusal from
/// another. A test that only checked "it threw" would pass for a setup mistake.
const ERROR_TAG: i32 = 60;
const ERROR_ALGORITHM: i32 = 61;
const ERROR_KEY_LENGTH: i32 = 62;
const ERROR_MALFORMED_KEY: i32 = 63;
const ERROR_KEY_ID: i32 = 64;
const ERROR_ZERO_VALIDATOR_ID: i32 = 65;
const ERROR_ZERO_ADNL: i32 = 66;
const ERROR_ZERO_WEIGHT: i32 = 67;

fn repo_root() -> std::path::PathBuf {
    std::env::var("TOS_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(4)
            .expect("repository root")
            .to_path_buf()
    })
}

/// A probe that exposes the library. The library itself is the production file, compiled
/// as the contracts will compile it.
fn probe_code() -> Cell {
    let probe = std::env::temp_dir().join(format!(
        "tos_pq_validator_probe-{}-{:?}.fc",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(
        &probe,
        r#"
int probe_key_id(int algorithm_id, cell stored) method_id {
  return pq::key_id(algorithm_id, stored);
}
(int, int, int, int, int) probe_parse(cell descriptor) method_id {
  (int validator_id, int algorithm_id, int key_id, cell public_key, int weight, int adnl) =
    pq::parse_descriptor(descriptor.begin_parse());
  return (validator_id, algorithm_id, key_id, weight, adnl);
}
cell probe_pack(int validator_id, int algorithm_id, cell public_key, int weight, int adnl) method_id {
  return pq::pack_descriptor(validator_id, algorithm_id, public_key, weight, adnl).end_cell();
}
cell probe_election_context() method_id {
  return pq::election_context();
}
cell probe_config_vote_context() method_id {
  return pq::config_vote_context();
}
cell probe_stake_preimage(int stake_at, int max_factor, int validator_id, int stake_owner,
                          int algorithm_id, int key_id, int adnl_addr) method_id {
  return pq::stake_preimage(stake_at, max_factor, validator_id, stake_owner, algorithm_id, key_id,
                            adnl_addr);
}
cell probe_config_vote_preimage(int validator_set_id, int validator_id, int idx,
                                int proposal_hash) method_id {
  return pq::config_vote_preimage(validator_set_id, validator_id, idx, proposal_hash);
}
cell probe_complaint_vote_preimage(int validator_set_id, int validator_id, int idx,
                                   int election_id, int complaint_hash) method_id {
  return pq::complaint_vote_preimage(validator_set_id, validator_id, idx, election_id,
                                     complaint_hash);
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
    let deployer = chain.treasury("pq-lib-funder", 1_000 * TOS).expect("funding");
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

fn vectors() -> Vec<(String, String, Cell)> {
    let path = repo_root().join("test/pq-native/descriptor-verdict-vectors.tsv");
    let text = std::fs::read_to_string(path).expect("the shared descriptor vectors");
    let mut cases = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 3, "malformed vector line");
        let cell =
            read_single_root_boc(hex::decode(fields[2]).expect("hex")).expect("a descriptor");
        cases.push((fields[0].to_string(), fields[1].to_string(), cell));
    }
    assert!(cases.len() >= 10, "the shared file lost cases");
    cases
}

fn key_bytes(seed: u8) -> Vec<u8> {
    vec![seed; MLDSA44_PUBLIC_KEY_BYTES]
}

fn stored_key(bytes: &[u8]) -> Cell {
    chain_block::pq_bytes::pack_pq_bytes(bytes, chain_block::pq_bytes::PQ_BYTES_HARD_MAX)
        .expect("a key of admitted length")
}

#[test]
fn the_library_reaches_the_same_verdict_as_the_node_on_every_descriptor() {
    let mut chain =
        Blockchain::with_global_version(16).expect("a chain at the post-quantum version");
    chain.set_workchain(-1);
    let probe = deploy(&mut chain);

    // Which rule each refusal is expected to come from. The shared file carries the
    // node's verdict; this carries which of the library's rules produced it, so a
    // refusal for the wrong reason is still a failure.
    let expected_error = |name: &str| -> i32 {
        match name {
            "key-id-of-another-key" => ERROR_KEY_ID,
            "unknown-algorithm" => ERROR_ALGORITHM,
            "short-key" => ERROR_KEY_LENGTH,
            "non-canonical-chunking" => ERROR_MALFORMED_KEY,
            "zero-validator-id" => ERROR_ZERO_VALIDATOR_ID,
            "zero-adnl" => ERROR_ZERO_ADNL,
            "zero-weight" => ERROR_ZERO_WEIGHT,
            "classical-tag" => ERROR_TAG,
            other => panic!("no expected rule recorded for {other}"),
        }
    };

    let (mut accepted, mut refused) = (0, 0);
    for (name, verdict, descriptor) in vectors() {
        let result = chain
            .run_get_method(&probe, "probe_parse", vec![StackItem::Cell(descriptor)])
            .expect("the probe answers");
        match verdict.as_str() {
            "accept" => {
                assert_eq!(
                    result.exit_code, 0,
                    "{name}: the library refused a descriptor the node accepts (code {})",
                    result.exit_code
                );
                accepted += 1;
            }
            "reject" => {
                assert_eq!(
                    result.exit_code,
                    expected_error(&name),
                    "{name}: refused for the wrong reason, or accepted"
                );
                refused += 1;
            }
            other => panic!("{name}: unknown verdict {other}"),
        }
    }
    assert!(accepted >= 2 && refused >= 8, "the vectors lost coverage: {accepted}/{refused}");
}

/// A stored key that declares `declared` bytes but attaches a chain carrying `carried`.
///
/// Both numbers are the sender's to choose, and only the walk can find out that they
/// disagree, so how long that walk runs is a cost the sender would otherwise pick.
fn overlong_stored_key(declared: u32, carried: usize) -> Cell {
    use chain_block::IBitstring;
    let chunks = carried.div_ceil(127);
    let mut chain: Option<Cell> = None;
    for index in (0..chunks).rev() {
        let bytes = if index + 1 == chunks { carried - index * 127 } else { 127 };
        let mut cell = chain_block::BuilderData::new();
        cell.append_raw(&vec![0xab; bytes], bytes * 8).expect("a chunk");
        if let Some(next) = chain.take() {
            cell.checked_append_reference(next).expect("the continuation");
        }
        chain = Some(cell.into_cell().expect("a chunk cell"));
    }
    let mut root = chain_block::BuilderData::new();
    root.append_u32(declared).expect("the declared length");
    root.checked_append_reference(chain.expect("a chain")).expect("the chain");
    root.into_cell().expect("a stored key")
}

/// What it costs to refuse a key is decided by the length it declares, not by the chain
/// it carries.
///
/// A key states its length in one cell and carries it in another, so a request may
/// declare the length of a real key and attach a chain of any size. If the walk ran to
/// the end of that chain before noticing, the work of refusing would be the sender's to
/// choose, and it would be paid for out of the block the request lands in.
#[test]
fn refusing_an_overlong_key_costs_what_the_declared_length_costs() {
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(-1);
    let probe = deploy(&mut chain);

    let cost = |carried: usize| -> i64 {
        let result = chain
            .run_get_method_with_gas(
                &probe,
                "probe_key_id",
                vec![
                    StackItem::int(1),
                    StackItem::Cell(overlong_stored_key(MLDSA44_PUBLIC_KEY_BYTES as u32, carried)),
                ],
                1_000_000_000,
            )
            .expect("the probe answers");
        assert_eq!(
            result.exit_code, ERROR_MALFORMED_KEY,
            "a key carrying {carried} bytes while declaring {MLDSA44_PUBLIC_KEY_BYTES} was not \
             refused as malformed"
        );
        result.gas_used
    };

    let barely = cost(12 * 127);
    let enormous = cost(2_000 * 127);
    assert!(
        enormous <= barely + 200,
        "refusing the same key cost {barely} gas over a chain of twelve chunks and {enormous} \
         over one of two thousand, so the walk runs to the end of what was attached"
    );
}

/// The same cell, presented as a reference into the library collection instead of as
/// itself. The virtual machine resolves it and parses what it finds; the node's decoder
/// has no library context and sees a special cell.
fn library_reference(root: &Cell) -> Cell {
    let mut data = vec![0x80u8; 34];
    data[0] = u8::from(chain_block::CellType::LibraryReference);
    data[1..33].copy_from_slice(root.repr_hash().as_slice());
    Cell::with_cell_impl(
        chain_block::DataCell::with_params(
            vec![],
            &data,
            chain_block::CellType::LibraryReference,
            0,
            None,
        )
        .expect("a library reference"),
    )
}

/// The probe, deployed with `library` in its own library collection, so a reference to it
/// resolves while the probe runs.
///
/// It is deployed in a basechain, because the masterchain refuses a state init that
/// carries libraries at all. That refusal is not the guard being tested: the elector
/// reads keys that reach it in messages, and the cell in a message is whatever its sender
/// built, whether or not the sending account could hold a library itself.
fn deploy_holding(chain: &mut Blockchain, library: &Cell) -> MsgAddressInt {
    let mut state = StateInit::with_code_and_data(probe_code(), Cell::default());
    let mut libraries = chain_block::StateInitLib::default();
    libraries
        .set(&library.repr_hash(), &chain_block::SimpleLib::new(library.clone(), true))
        .expect("a published library");
    state.library = libraries;
    let address = MsgAddressInt::with_params(
        0,
        state.write_to_new_cell().expect("state").into_cell().expect("state cell").hash(0),
    )
    .expect("address");
    let deployer = chain.treasury("pq-lib-library-funder", 100_000 * TOS).expect("funding");
    let deployment = chain
        .send_message(
            MessageBuilder::internal(deployer.address(), &address, 50_000 * TOS)
                .bounce(false)
                .state_init(state)
                .body(Cell::default())
                .build(),
        )
        .expect("deployment");
    let (_, transaction) = deployment.transactions.first().expect("a transaction");
    assert!(
        !transaction.read_description().expect("description").is_aborted(),
        "the probe could not be deployed holding a library: {:?}",
        transaction.read_description().expect("description")
    );
    address
}

/// A key that is not the bytes but a pointer to them.
///
/// Reading a cell resolves a library reference and continues with what it points at, so
/// such a key walks and hashes exactly as the key itself: same length, same chunking,
/// same identity. The node reads the same cell with no library context, sees a special
/// cell, and refuses it. Were the library to accept it, a stake would register a key that
/// every node then fails to decode, which is a halt and not a bad registration.
#[test]
fn a_key_that_is_only_a_reference_to_a_key_is_refused() {
    let key = key_bytes(0x5c);
    let stored = stored_key(&key);
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(0);
    let probe = deploy_holding(&mut chain, &stored);

    // The fixture is only meaningful if the reference really does resolve to the key.
    let direct = chain
        .run_get_method(
            &probe,
            "probe_key_id",
            vec![StackItem::int(1), StackItem::Cell(stored.clone())],
        )
        .expect("the probe answers");
    assert_eq!(direct.exit_code, 0, "the fixture's own key was refused");

    let reference = chain
        .run_get_method(
            &probe,
            "probe_key_id",
            vec![StackItem::int(1), StackItem::Cell(library_reference(&stored))],
        )
        .expect("the probe answers");
    // Under the reader this replaced, the reference was accepted and derived the very
    // same identity as the key itself, so nothing downstream could have told them apart.
    assert_eq!(
        reference.exit_code, ERROR_MALFORMED_KEY,
        "a key presented as a library reference was accepted, and the node cannot decode it"
    );
}

#[test]
fn the_library_derives_the_key_identity_the_node_derives() {
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(-1);
    let probe = deploy(&mut chain);

    for seed in [0x11u8, 0x22, 0xff] {
        let key = key_bytes(seed);
        let result = chain
            .run_get_method(
                &probe,
                "probe_key_id",
                vec![StackItem::int(1), StackItem::Cell(stored_key(&key))],
            )
            .expect("the probe answers");
        assert_eq!(result.exit_code, 0, "the library refused a well-formed key");
        assert_eq!(
            result.stack.last().expect("an identity").as_integer().expect("an integer").to_string(),
            IntegerData::from_unsigned_bytes_be(derive_consensus_key_id(1, &key).as_slice())
                .to_string(),
            "the library derived a different identity than the node does"
        );
    }
}

#[test]
fn a_descriptor_the_library_packs_is_one_the_node_accepts() {
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(-1);
    let probe = deploy(&mut chain);

    let key = key_bytes(0x11);
    let validator_id = IntegerData::from_unsigned_bytes_be(&[0xa0u8; 32]);
    let adnl = IntegerData::from_unsigned_bytes_be(&[0xc0u8; 32]);
    let packed = chain
        .run_get_method(
            &probe,
            "probe_pack",
            vec![
                StackItem::integer(validator_id),
                StackItem::int(1),
                StackItem::Cell(stored_key(&key)),
                StackItem::int(5),
                StackItem::integer(adnl),
            ],
        )
        .expect("the probe answers");
    assert_eq!(packed.exit_code, 0, "the library refused to pack a well-formed descriptor");
    let built = packed.stack.last().expect("a descriptor").as_cell().expect("a cell").clone();

    // The vectors' accepted descriptor is built from the same inputs, so the library must
    // produce those exact bytes rather than merely something parseable.
    let (_, _, expected) =
        vectors().into_iter().find(|(name, _, _)| name == "valid").expect("the accepted case");
    assert_eq!(
        built.repr_hash(),
        expected.repr_hash(),
        "the library packed different bytes than the node's encoder"
    );
}

/// The bytes the contract signs are the bytes the node and the tooling sign.
///
/// `test/pq-native/authorisation-preimage-vectors.tsv` is the shared lock: the node's C++ builders
/// and the Rust tooling are both held to it. The contract said in a comment that it was
/// held to it too, and nothing checked that. A contract that built a different preimage
/// would refuse every correctly signed request, and the failure would look like a bad
/// key rather than like a field in the wrong place.
///
/// The global id has to match the one the vectors were generated for, which is what the
/// fixture below sets the chain to.
#[test]
fn the_contract_builds_the_bytes_the_vectors_freeze() {
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(-1);
    set_global_id(&mut chain, -239);
    let probe = deploy(&mut chain);

    let vectors = std::fs::read_to_string(
        repo_root().join("test/pq-native/authorisation-preimage-vectors.tsv"),
    )
    .expect("the shared preimage vectors");
    let expected = |name: &str| -> String {
        vectors
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .find_map(|line| {
                let mut fields = line.split('\t');
                (fields.next()? == name).then(|| fields.nth(1).map(str::to_string))?
            })
            .unwrap_or_else(|| panic!("the vectors carry no case named {name}"))
    };

    // The same fixed inputs the C++ and Rust producers are checked against, chosen so
    // every field is distinguishable in the output.
    let fill = |byte: u8| IntegerData::from_unsigned_bytes_be([byte; 32]);
    let cases: Vec<(&str, &str, Vec<StackItem>)> = vec![
        (
            "stake",
            "probe_stake_preimage",
            vec![
                StackItem::integer(IntegerData::from_u32(1_789_434_000)),
                StackItem::integer(IntegerData::from_u32(0x10000)),
                StackItem::integer(fill(0xa1)),
                StackItem::integer(fill(0xd7)),
                StackItem::integer(IntegerData::from_u32(1)),
                StackItem::integer(fill(0xb2)),
                StackItem::integer(fill(0xc3)),
            ],
        ),
        (
            "config-vote",
            "probe_config_vote_preimage",
            vec![
                StackItem::integer(fill(0xd4)),
                StackItem::integer(fill(0xa1)),
                StackItem::integer(IntegerData::from_u32(7)),
                StackItem::integer(fill(0xe5)),
            ],
        ),
        (
            "complaint-vote",
            "probe_complaint_vote_preimage",
            vec![
                StackItem::integer(fill(0xd4)),
                StackItem::integer(fill(0xa1)),
                StackItem::integer(IntegerData::from_u32(7)),
                StackItem::integer(IntegerData::from_u32(1_789_434_000)),
                StackItem::integer(fill(0xf6)),
            ],
        ),
    ];

    for (name, method, arguments) in cases {
        let result = chain.run_get_method(&probe, method, arguments).expect("the probe answers");
        assert_eq!(result.exit_code, 0, "{method} failed");
        let cell = result.stack.last().expect("a preimage").as_cell().expect("a cell").clone();
        let bytes = canonical_chain(cell, name);
        assert_eq!(
            hex::encode(&bytes),
            expected(name),
            "the contract's {name} preimage is not the one the node and the tooling sign"
        );
    }
}

/// The bytes of a message, read the way the verifying instruction reads one.
///
/// A message is a canonical byte chain: whole bytes, at most one reference, and every
/// cell but the last holding exactly 127 of them. A preimage that outgrows a cell is
/// therefore two cells, and reading only the first would compare a prefix against the
/// whole and call them different for the wrong reason. The rules are re-stated here
/// rather than assumed, so a contract that built a chain the instruction would refuse
/// fails in this test instead of on chain.
fn canonical_chain(root: chain_block::Cell, name: &str) -> Vec<u8> {
    const CHUNK: usize = 127;
    let mut bytes = Vec::new();
    let mut cell = root;
    loop {
        let mut slice = chain_block::SliceData::load_cell(cell).expect("a chunk");
        let bits = slice.remaining_bits();
        assert_eq!(bits % 8, 0, "{name}: a chunk is not a whole number of bytes");
        assert!(slice.remaining_references() <= 1, "{name}: a chunk has more than one reference");
        let size = bits / 8;
        assert!(size <= CHUNK, "{name}: a chunk exceeds a cell's capacity");
        let more = slice.remaining_references() == 1;
        assert!(
            !more || size == CHUNK,
            "{name}: a chunk that is continued holds {size} bytes rather than {CHUNK}"
        );
        bytes.extend_from_slice(&slice.get_next_bits(bits).expect("the chunk's bytes"));
        if !more {
            return bytes;
        }
        cell = slice.checked_drain_reference().expect("the next chunk");
    }
}

/// The network the chain says it is, which every preimage is bound to.
///
/// The sandbox's default configuration carries neither this nor the fundamental-contract
/// list a full configuration is built from, so both are supplied here. Only the network
/// identity matters to what is measured; the other is what makes the configuration
/// complete enough to install.
fn set_global_id(chain: &mut Blockchain, global_id: i32) {
    let mut config = chain.config_params().clone();
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParam19(global_id as u32))
        .expect("the network identity is set");
    config
        .set_config(chain_block::ConfigParamEnum::ConfigParam31(chain_block::ConfigParam31 {
            fundamental_smc_addr: chain_block::FundamentalSmcAddresses::default(),
        }))
        .expect("the fundamental contracts are listed");
    chain.set_config(config).expect("the chain adopts it");
}

#[test]
fn the_signature_domains_are_the_frozen_ones() {
    let mut chain = Blockchain::with_global_version(16).expect("a chain");
    chain.set_workchain(-1);
    let probe = deploy(&mut chain);

    for (method, domain) in [
        ("probe_election_context", "TOS-VALIDATOR-ELECTION-v1"),
        ("probe_config_vote_context", "TOS-VALIDATOR-CONFIG-VOTE-v1"),
    ] {
        let result = chain.run_get_method(&probe, method, vec![]).expect("the probe answers");
        assert_eq!(result.exit_code, 0, "{method} failed");
        let cell = result.stack.last().expect("a context").as_cell().expect("a cell").clone();
        let mut slice = chain_block::SliceData::load_cell(cell).expect("context");
        let bytes = slice.get_next_bits(domain.len() * 8).expect("the domain bytes");
        assert_eq!(
            String::from_utf8(bytes).expect("ascii"),
            domain,
            "{method} carries a domain the rest of the protocol does not use"
        );
        assert_eq!(slice.remaining_bits(), 0, "{method} carries more than the domain");
    }
}
