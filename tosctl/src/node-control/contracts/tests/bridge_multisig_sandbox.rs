/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! The bridge oracle multisigs (coin bridge, both networks, and token bridge) refuse owner keys
//! anyone can sign for: create_init_state will not build an owner set that holds one, and
//! check_query_signatures will not count a stored one as root. The signature-counting paths of
//! a live query are driven by crosschain/*/tvm/tests/weak-owner-key.js.

use chain_block::{
    BuilderData, Cell, IBitstring, MsgAddressInt, Serializable, SliceData, StateInit,
};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder, compile_func};
use tos_vm::stack::StackItem;

mod weak_ed25519;

const TOS: u64 = 1_000_000_000;
const WALLET_ID: u32 = 0x4554_4831;
const ERR_WEAK_OWNER: i32 = 45;

fn crosschain(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../crosschain").join(path)
}

/// Each bridge multisig and the sources its build compiles, in order.
fn bridges() -> Vec<(&'static str, Vec<std::path::PathBuf>)> {
    vec![
        (
            "coin-bridge/ethereum",
            vec![
                crosschain("coin-bridge/tvm/ethereum/stdlib.fc"),
                crosschain("coin-bridge/tvm/ethereum/multisig-code.fc"),
            ],
        ),
        (
            "coin-bridge/bsc",
            vec![
                crosschain("coin-bridge/tvm/bsc/stdlib.fc"),
                crosschain("coin-bridge/tvm/bsc/multisig-code.fc"),
            ],
        ),
        ("token-bridge", vec![crosschain("token-bridge/tvm/contracts/multisig.fc")]),
    ]
}

fn cell(build: impl FnOnce(&mut BuilderData)) -> Cell {
    let mut b = BuilderData::new();
    build(&mut b);
    b.into_cell().expect("cell")
}

fn owner_dict(keys: &[[u8; 32]]) -> Cell {
    let mut dict = chain_block::HashmapE::with_bit_len(8);
    for (index, key) in keys.iter().enumerate() {
        let index =
            SliceData::load_builder(BuilderData::with_raw(vec![index as u8], 8).unwrap()).unwrap();
        let value = SliceData::load_cell(cell(|b| {
            b.append_u256(key).unwrap();
            b.append_u8(0).unwrap();
        }))
        .unwrap();
        dict.set(index, &value).unwrap();
    }
    chain_block::HashmapType::data(&dict).cloned().expect("non-empty owner set")
}

/// wallet_id n k last_cleaned owners pending lock_until, as the bridge multisigs store it.
fn wallet_data(owners: &[[u8; 32]], k: u8) -> Cell {
    cell(|b| {
        b.append_u32(WALLET_ID).unwrap();
        b.append_u8(owners.len() as u8).unwrap();
        b.append_u8(k).unwrap();
        b.append_u64(0).unwrap();
        b.append_bit_one().unwrap();
        b.checked_append_reference(owner_dict(owners)).unwrap();
        b.append_bit_zero().unwrap();
        b.append_u32(0).unwrap();
    })
}

struct Deployed {
    bc: Blockchain,
    address: MsgAddressInt,
}

/// Deploys a multisig straight from a hand-built StateInit, as anyone can.
fn deploy(sources: &[std::path::PathBuf], owners: &[[u8; 32]]) -> Deployed {
    let mut bc = Blockchain::new().expect("blockchain");
    let code = compile_func(sources).expect("compile");
    let init = StateInit::with_code_and_data(code, wallet_data(owners, 2));
    let hash = init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    let address = MsgAddressInt::with_params(0, hash).unwrap();
    let funder = bc.treasury("funder", 1_000 * TOS).expect("funder");
    let message = MessageBuilder::internal(funder.address(), &address, 10 * TOS)
        .bounce(false)
        .state_init(init)
        .build();
    bc.send_message(message).expect("deploy").expect_success();
    Deployed { bc, address }
}

fn strong_keys() -> [SigningKey; 2] {
    [SigningKey::from_bytes(&[0x51; 32]), SigningKey::from_bytes(&[0x52; 32])]
}

/// The cell a root signs in a query with no co-signatures; only its hash matters here.
fn signed_root(root: u8) -> Cell {
    cell(|b| {
        b.append_u8(root).unwrap();
        b.append_bit_zero().unwrap();
        b.append_u32(WALLET_ID).unwrap();
        b.append_u64(7).unwrap();
    })
}

fn query(signature: [u8; 64], signed: &Cell) -> Cell {
    let rest = SliceData::load_cell(signed.clone()).unwrap();
    cell(|b| {
        b.append_raw(&signature, 512).unwrap();
        b.append_builder(&rest.as_builder().unwrap()).unwrap();
    })
}

#[test]
fn create_init_state_refuses_every_weak_owner_key() {
    let keys = strong_keys();
    let strong: Vec<[u8; 32]> = keys.iter().map(|key| key.verifying_key().to_bytes()).collect();
    for (bridge, sources) in bridges() {
        let deployed = deploy(&sources, &strong);
        let build = |owners: &[[u8; 32]]| {
            deployed
                .bc
                .run_get_method(
                    &deployed.address,
                    "create_init_state",
                    vec![
                        StackItem::int(i64::from(WALLET_ID)),
                        StackItem::int(owners.len() as i64),
                        StackItem::int(2),
                        StackItem::cell(owner_dict(owners)),
                        StackItem::int(0),
                    ],
                )
                .expect("create_init_state")
                .exit_code
        };
        assert_eq!(build(&strong), 0, "{bridge}: strong owners build");
        for (i, weak) in weak_ed25519::weak_keys().into_iter().enumerate() {
            assert_eq!(
                build(&[strong[0], strong[1], weak]),
                ERR_WEAK_OWNER,
                "{bridge}: weak key {i} accepted into an owner set"
            );
        }
    }
}

#[test]
fn check_query_signatures_refuses_a_forged_weak_root() {
    let keys = strong_keys();
    let [identity_alias, order2_alias] = weak_ed25519::sign_bit_aliases();
    let owners = [
        keys[0].verifying_key().to_bytes(),
        keys[1].verifying_key().to_bytes(),
        identity_alias,
        order2_alias,
    ];
    for (bridge, sources) in bridges() {
        let deployed = deploy(&sources, &owners);
        let check = |body: Cell| {
            deployed
                .bc
                .run_get_method(
                    &deployed.address,
                    "check_query_signatures",
                    vec![StackItem::cell(body)],
                )
                .expect("check_query_signatures")
        };
        let signed = signed_root(2);
        let forged = weak_ed25519::forge(&identity_alias, signed.hash(0).as_slice())
            .expect("the identity alias admits a forgery for every message");
        assert_eq!(check(query(forged, &signed)).exit_code, ERR_WEAK_OWNER, "{bridge}");

        let signed = signed_root(0);
        let result = check(query(keys[0].sign(signed.hash(0).as_slice()).to_bytes(), &signed));
        result.expect_success();
        assert_eq!(result.int_at(0), 1, "{bridge}: one valid signature");
    }
}
