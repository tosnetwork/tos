/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Section 13.2 and gate 22: the state a deployment ships.
//!
//! There is no admin key and no upgrade path here, so the genesis state is the
//! deployment: its hash is the address, and every number in it is fixed for
//! good the moment it is built. A generator that agrees only with itself would
//! be exactly the failure this is here to prevent -- a hand-built fixture
//! agrees with itself too.
//!
//! So the state is built twice. Once outside the VM by the generator, and once
//! inside it by the contract's own `state_genesis`, and the two cells have to
//! be the same cell. Then the contract is deployed with the generated state
//! and asked, through its own get-methods, what it thinks it holds.

mod support;

use chain_block::{Cell, MsgAddressInt, Serializable, StateInit};
use shielded_pool_circuit_crosscheck::{library_dir, stdlib_path};
use shielded_pool_genesis::{build, manifest, Parameters};
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};
use tos_vm::stack::StackItem;

const TOS: u64 = 1_000_000_000;
const ACTIVE_VERSION: u32 = 18;

fn root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// Section 13.1: line endings normalised to LF, nothing else touched.
fn normalise(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
            index += 1;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// The same parameters the frozen manifest was generated from.
fn parameters() -> Parameters {
    let root = root();
    let profile =
        std::fs::read(root.join("doc/shielded-pool-v1-profile.md")).expect("the profile copy");
    let fixture = std::fs::read_to_string(
        root.join("tools/shielded-pool-circuit/fixtures/groth16-development.json"),
    )
    .expect("the development fixture");
    let value: serde_json::Value = serde_json::from_str(&fixture).expect("the fixture is JSON");
    let hex = value["verifying_key"]["hex"].as_str().expect("the verifying key");
    let verifying_key: Vec<u8> = (0..hex.len() / 2)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect();

    Parameters {
        profile_bytes: normalise(&profile),
        poseidon_manifest_bytes: std::fs::read(root.join("crypto/poseidon2/manifest.bin"))
            .expect("the Poseidon2 manifest"),
        verifying_key,
        reserve_floor: shielded_pool_genesis::RESERVE_FLOOR,
        withdrawal_fee: shielded_pool_genesis::WITHDRAWAL_FEE,
        denominations: vec![1_000_000_000, 10_000_000_000, 100_000_000_000, 1_000_000_000_000],
    }
}

fn frozen() -> serde_json::Value {
    let text = std::fs::read_to_string(root().join("doc/shielded-pool/genesis-manifest.json"))
        .expect("the frozen manifest");
    serde_json::from_str(&text).expect("the manifest is JSON")
}

const PROBE: &str = r#"
cell g_genesis(int commit_root, int nullifier_root, int reserve, cell config, cell vk)
    method_id {
  return state_genesis(commit_root, nullifier_root, reserve, config, vk);
}
int g_empty_root() method_id { return empty_root_at(12); }
int g_imt_genesis() method_id { return imt_genesis_root(); }
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

struct Probe {
    bc: Blockchain,
    addr: MsgAddressInt,
}

impl Probe {
    fn deploy() -> Self {
        let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
            .expect("blockchain at version 17");
        bc.set_workchain(0);
        let payer = bc.treasury("genesis_probe", 1_000 * TOS).expect("treasury");
        let library = library_dir();
        let path = std::env::temp_dir().join("tos_shielded_genesis_probe.fc");
        std::fs::write(&path, PROBE).expect("write the probe");
        let code = compile_func(&[
            stdlib_path(),
            library.join("domains.fc"),
            library.join("empty-roots.fc"),
            library.join("notes.fc"),
            library.join("tree.fc"),
            library.join("imt.fc"),
            library.join("anchors.fc"),
            library.join("state.fc"),
            path,
        ])
        .expect("compile the probe");
        let si = StateInit::with_code_and_data(code, Cell::default());
        let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
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
        Self { bc, addr }
    }

    fn call(&self, method: &str, args: Vec<StackItem>) -> Vec<StackItem> {
        let result = self
            .bc
            .run_get_method(&self.addr, method, args)
            .unwrap_or_else(|error| panic!("{method}: {error}"));
        assert_eq!(result.exit_code, 0, "{method} exited {}", result.exit_code);
        result.stack
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The two roots the state starts from are derived, not configured, so the
/// generator and the contract must agree on them before anything else means
/// anything.
#[test]
fn the_generator_and_the_contract_agree_on_the_genesis_roots() {
    let probe = Probe::deploy();
    let genesis = build(parameters()).expect("build the genesis state");

    let empty = probe.call("g_empty_root", vec![]);
    let imt = probe.call("g_imt_genesis", vec![]);
    let top = |stack: &[StackItem]| {
        stack.last().expect("a result").as_integer().expect("integer").to_string()
    };
    assert_eq!(
        top(&empty),
        shielded_pool_circuit_crosscheck::pool::dec(genesis.commitment_root),
        "the empty commitment root differs between the generator and the contract"
    );
    assert_eq!(
        top(&imt),
        shielded_pool_circuit_crosscheck::pool::dec(genesis.nullifier_root),
        "the nullifier genesis root differs between the generator and the contract"
    );
}

/// The whole state cell, built twice. The generator assembles it outside the
/// VM; `state_genesis` assembles it inside. A single differing bit anywhere --
/// a field order, a coin encoding, an empty dictionary's holder -- gives a
/// different hash, and a different hash is a different deployment address.
#[test]
fn the_generator_builds_the_cell_the_contract_builds() {
    let probe = Probe::deploy();
    let parameters = parameters();
    let genesis = build(parameters.clone()).expect("build the genesis state");

    let integer = |value: &str| {
        StackItem::int(
            tos_vm::stack::integer::IntegerData::from_str_radix(value, 10).expect("a number"),
        )
    };
    let stack = probe.call(
        "g_genesis",
        vec![
            integer(&shielded_pool_circuit_crosscheck::pool::dec(genesis.commitment_root)),
            integer(&shielded_pool_circuit_crosscheck::pool::dec(genesis.nullifier_root)),
            integer(&parameters.reserve_floor.to_string()),
            StackItem::cell(
                shielded_pool_genesis::config_store(&parameters).expect("a config store"),
            ),
            StackItem::cell(
                shielded_pool_genesis::byte_chain(&parameters.verifying_key)
                    .expect("a verifying key chain"),
            ),
        ],
    );
    let built = stack.last().expect("a result").as_cell().expect("a cell").clone();

    assert_eq!(
        hex(&manifest::cell_hash(&built)),
        hex(&manifest::cell_hash(&genesis.state)),
        "the state the contract builds is not the state the generator builds"
    );
}

/// And it is the state the frozen manifest names. Section 13.2: "a deployment
/// fixture whose initial state hash differs from the frozen generated manifest
/// MUST fail."
#[test]
fn the_generated_state_is_the_state_the_frozen_manifest_names() {
    let genesis = build(parameters()).expect("build the genesis state");
    let frozen = frozen();

    assert_eq!(
        hex(&manifest::cell_hash(&genesis.state)),
        frozen["state"]["hash"].as_str().expect("a state hash"),
        "the genesis state has drifted from the frozen manifest"
    );
    assert_eq!(
        hex(&shielded_pool_genesis::profile_hash(&genesis.parameters.profile_bytes)),
        frozen["profile"]["profile_hash"].as_str().expect("a profile hash"),
        "the profile copy has drifted from the one the manifest was built against"
    );
    assert_eq!(
        hex(&shielded_pool_genesis::sha256(&genesis.parameters.poseidon_manifest_bytes)),
        frozen["poseidon2"]["manifest_sha256"].as_str().expect("a manifest hash"),
    );
    assert_eq!(
        hex(&shielded_pool_genesis::sha256(&genesis.parameters.verifying_key)),
        frozen["groth16"]["vk_sha256"].as_str().expect("a verifying key hash"),
    );
}

/// Deployed, the contract reads back what the manifest says it holds. The
/// generator could produce a cell the contract accepts and still have put the
/// fee where the reserve floor goes.
#[test]
fn a_pool_deployed_from_it_reads_back_what_the_manifest_says() {
    let genesis = build(parameters()).expect("build the genesis state");
    let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)
        .expect("blockchain at version 17");
    bc.set_workchain(0);
    let payer = bc.treasury("deployer", 1_000 * TOS).expect("treasury");
    let code = compile_func(&shielded_pool_circuit_crosscheck::pool::pool_sources())
        .expect("compile the pool");
    let si = StateInit::with_code_and_data(code, genesis.state.clone());
    let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    let addr = MsgAddressInt::with_params(0, hash).unwrap();
    bc.send_message(
        MessageBuilder::internal(
            payer.address(),
            &addr,
            // A deployment has to carry at least the reserve floor, or the
            // pool is unbacked from its first block and refuses everything.
            // Twenty TOS did until the floor was re-derived to fifty.
            u64::try_from(shielded_pool_genesis::RESERVE_FLOOR).expect("the floor fits")
                + 20 * TOS,
        )
            .bounce(false)
            .state_init(si)
            .body(Cell::default())
            .build(),
    )
    .expect("deploy")
    .expect_success();

    let get = |method: &str| {
        let result = bc.run_get_method(&addr, method, vec![]).expect("a get-method");
        assert_eq!(result.exit_code, 0, "{method} exited {}", result.exit_code);
        result.stack.last().expect("a result").as_integer().expect("integer").to_string()
    };
    let frozen = frozen();
    assert_eq!(
        get("commitment_root"),
        shielded_pool_circuit_crosscheck::pool::dec(genesis.commitment_root)
    );
    assert_eq!(get("commitment_next_index"), "0");
    assert_eq!(
        get("nullifier_root"),
        shielded_pool_circuit_crosscheck::pool::dec(genesis.nullifier_root)
    );
    assert_eq!(get("nullifier_next_index"), "1");
    assert_eq!(get("native_liability"), "0");
    assert_eq!(
        get("reserve_floor"),
        frozen["configuration"]["reserve_floor"].as_str().expect("a reserve floor"),
        "the deployed reserve floor is not the one the manifest names"
    );
    // A pool with no deposits owes nothing, so it is backed by anything at all.
    assert_eq!(
        get("backed"),
        "-1",
        "a pool funded above its reserve floor and owing nothing is unbacked"
    );
}

/// Every parameter section 13.2 constrains, refused before a state is built.
/// A state the contract would reject is not a state worth having a manifest
/// for, and finding that out at deployment time is too late.
#[test]
fn parameters_the_contract_would_refuse_are_refused_here() {
    let refuse = |mutate: &dyn Fn(&mut Parameters)| {
        let mut parameters = parameters();
        mutate(&mut parameters);
        build(parameters).err().map(|error| error.to_string())
    };

    assert!(refuse(&|p| p.reserve_floor = 0).is_some(), "a zero reserve floor was accepted");
    assert!(refuse(&|p| p.withdrawal_fee = 0).is_some(), "a zero withdrawal fee was accepted");
    assert!(
        refuse(&|p| p.denominations.clear()).is_some(),
        "an empty denomination list was accepted"
    );
    assert!(
        refuse(&|p| p.denominations = vec![2, 1]).is_some(),
        "an unsorted denomination list was accepted"
    );
    assert!(
        refuse(&|p| p.denominations = vec![1, 1]).is_some(),
        "a duplicated denomination was accepted"
    );
    assert!(refuse(&|p| p.denominations = vec![0]).is_some(), "a zero denomination was accepted");
    assert!(
        refuse(&|p| p.denominations = (1..=17u128).collect()).is_some(),
        "seventeen denominations were accepted"
    );
    assert!(
        refuse(&|p| p.verifying_key.truncate(1247)).is_some(),
        "a verifying key that is not 1248 bytes was accepted"
    );

    // And the unchanged parameters build, so the refusals above are about what
    // was changed rather than about the set as a whole.
    assert!(build(parameters()).is_ok(), "the frozen parameters no longer build");
}
