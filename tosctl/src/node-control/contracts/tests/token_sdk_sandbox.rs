//! Execute the SDK's frozen code and SDK-produced messages, not compiler substitutes.

use std::str::FromStr;

use chain_block::{
    BuilderData, Deserializable, MsgAddressInt, Serializable, StateInit, read_single_root_boc,
};
use tos_sandbox::{Blockchain, MessageBuilder};
use tos_vm::stack::StackItem;

#[path = "fixtures/current_network.rs"]
mod current_network;

fn sdk_code(name: &str) -> chain_block::Cell {
    let source = include_str!("../../../../../sdk/js/packages/contracts/src/token/codes.ts");
    let value = source
        .split_once(&format!("export const {name} ="))
        .expect("SDK constant")
        .1
        .split(';')
        .next()
        .expect("constant terminator");
    let encoded: String =
        value.split('"').enumerate().filter(|(i, _)| i % 2 == 1).map(|(_, part)| part).collect();
    read_single_root_boc(hex::decode(encoded).expect("SDK hex")).expect("SDK BOC")
}

#[test]
fn sdk_code_executes_its_getter_mint_wallet_and_admin_messages() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../test/fixtures/token-sdk.json"))
            .expect("public SDK fixture");
    let address =
        |key: &str| MsgAddressInt::from_str(fixture[key].as_str().expect("address")).unwrap();
    let cell = |key: &str| {
        read_single_root_boc(hex::decode(fixture[key].as_str().unwrap()).unwrap()).unwrap()
    };
    let admin = address("admin");
    let owner = address("owner");
    let init = StateInit::with_code_and_data(sdk_code("TOKEN_MASTER_CODE_HEX"), cell("data"));
    let master = MsgAddressInt::with_params(
        0,
        init.write_to_new_cell().unwrap().into_cell().unwrap().hash(0),
    )
    .unwrap();
    let mut chain =
        Blockchain::with_global_version_and_base_workchain(current_network::global_version())
            .unwrap();
    chain
        .send_message(
            MessageBuilder::internal(&admin, &master, 5_000_000_000).state_init(init).build(),
        )
        .unwrap()
        .expect_success();
    let get = |chain: &Blockchain| chain.run_get_method(&master, "get_token_data", vec![]).unwrap();
    assert_eq!(get(&chain).expect_success().int_at(0), 0);
    assert_eq!(chain.run_get_method(&master, "get_jetton_data", vec![]).unwrap().exit_code, 11);
    chain
        .send_message(
            MessageBuilder::internal(&admin, &master, 1_000_000_000).body(cell("mint")).build(),
        )
        .unwrap()
        .expect_success();
    assert_eq!(get(&chain).expect_success().int_at(0), 17);
    let mut argument = BuilderData::new();
    owner.write_to(&mut argument).unwrap();
    let result = chain
        .run_get_method(
            &master,
            "get_wallet_address",
            vec![StackItem::Slice(chain_block::SliceData::load_builder(argument).unwrap())],
        )
        .unwrap();
    result.expect_success();
    let wallet = MsgAddressInt::construct_from(&mut result.slice_at(0)).unwrap();
    let balance = chain.run_get_method(&wallet, "get_wallet_data", vec![]).unwrap();
    assert_eq!(balance.expect_success().int_at(0), 17);
    assert_eq!(
        chain.get_account(&wallet).unwrap().get_code().unwrap().repr_hash(),
        sdk_code("TOKEN_WALLET_CODE_HEX").repr_hash()
    );
    chain
        .send_message(
            MessageBuilder::internal(&admin, &master, 1_000_000_000)
                .body(cell("changeAdmin"))
                .build(),
        )
        .unwrap()
        .expect_success();
    assert_eq!(
        MsgAddressInt::construct_from(&mut get(&chain).slice_at(2)).unwrap(),
        address("newAdmin")
    );
    chain
        .send_message(
            MessageBuilder::internal(&admin, &master, 1_000_000_000).body(cell("mint")).build(),
        )
        .unwrap()
        .expect_exit_code(73);
    assert_eq!(get(&chain).expect_success().int_at(0), 17);
}
