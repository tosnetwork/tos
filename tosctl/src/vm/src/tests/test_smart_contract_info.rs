/*
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::*;
use chain_block::{
    tos_method_id, Account, BuilderData, Coins, CurrencyCollection, InternalMessageHeader, Message,
    MsgAddressInt, ShardAccount, StateInit,
};

#[test]
fn test_smart_contract_info_serialization_default() {
    let sci = SmartContractInfo::default();
    sci.as_temp_data_item();
}

#[test]
fn test_smart_contract_info() {
    let sci = SmartContractInfo::default();
    let item = sci.as_temp_data_item();
    let result = item
        .as_tuple()
        .expect("result must be a tuple")
        .first()
        .expect("tuple must have at least one item")
        .as_tuple()
        .expect("SMCI list must be a tuple")
        .len();
    assert_eq!(result, 17);
}

#[test]
fn test_smart_contract_info_internal_message_info_uses_fwd_fee() {
    let src: MsgAddressInt =
        "0:cd9c066feaf8e26f56005510b510eebcf0b36e7527343b1cc9ae9286ee018ba7".parse().unwrap();
    let dst: MsgAddressInt =
        "0:448f07b4f2867fcf9aba8944ef9f697782d247e3872ef1cdbb72f5442e32bdd8".parse().unwrap();
    let mut hdr = InternalMessageHeader::with_addresses_and_bounce(
        src,
        dst,
        CurrencyCollection::with_coins(10_000_000),
        true,
    );
    hdr.fwd_fee = Coins::from(1_408_000u64);
    hdr.created_lt = 68978789000002;
    hdr.created_at = 1775439477;

    let sci = SmartContractInfo {
        in_msg: Some(Message::with_int_header(hdr)),
        incoming_value: CurrencyCollection::with_coins(10_000_000),
        ..Default::default()
    };

    let msg_info = sci.get_message_info();
    let info = msg_info.as_tuple().unwrap();
    assert_eq!(info[3].as_integer().unwrap().to_str_radix(10), "1408000");
    assert_eq!(info[6].as_integer().unwrap().to_str_radix(10), "10000000");
    assert_eq!(info[7].as_integer().unwrap().to_str_radix(10), "10000000");
}

#[test]
fn test_run_get_method_seqno_with_config() {
    let mc_state_name = "../block/src/tests/data/free-tos-mc-state-61884";
    let mc_state_cell = Cell::read_from_file(mc_state_name);
    let method_id = tos_method_id("seqno");
    assert_eq!(method_id, 0x14C97);

    let mc_state = ShardStateUnsplit::construct_from_cell(mc_state_cell.clone()).unwrap();
    let shard_account = mc_state.read_accounts().unwrap().get(&[0x55; 32].into()).unwrap().unwrap();
    let result = run_smc_method(
        &shard_account.read_account().unwrap(),
        mc_state_cell.clone(),
        method_id,
        Vec::new(),
        mc_state.gen_time(),
        mc_state.gen_lt(),
    )
    .unwrap()
    .into_run_result()
    .unwrap();
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.gas_used, 869);
    assert_eq!(result.stack.len(), 1);
    assert_eq!(result.stack[0].number().unwrap().number(), "0x0");
}

#[test]
fn test_run_get_method_seqno_with_elector() {
    let mc_state_name = "../block/src/tests/data/free-tos-mc-state-61884";
    let mc_state_cell = Cell::read_from_file(mc_state_name);
    let method_id = tos_method_id("seqno");
    assert_eq!(method_id, 0x14C97);

    let mc_state = ShardStateUnsplit::construct_from_cell(mc_state_cell.clone()).unwrap();
    let shard_account = mc_state.read_accounts().unwrap().get(&[0x33; 32].into()).unwrap().unwrap();
    // let account = "te6ccgECZwEAD6IAAnXP8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMyzpvVwAAAAAAAAAM4NVfTDcFHa5Cb1qbW0AECART/APSkE/S88sgLAwFXjgo7V9zG7TYAAAAAe4Fm5kSBgofP2oHReNV01a4lFkqDukMq9z9dipc1WZEMAgEgBAUCAUgGBwBRpf//GHaiaHoCegIRN0qs+BX5IE4qOBD4E3kgLPgU+SBxeBP5IHgVGEACAsUICQIBIElKAgHJCgsBKqqCMYIQTkNvZIIQzkNvZFlwgEDbPCsCASANDgIBSCwtAB9pGMWQaRilkGWvNMFQoAAQAgEgDxAE3/AL6RAGkk18Df+Ah12SDBr6TXwN94Ns8EDVfBQLTH1MTgCD0Dm+hk18GfuEg1wsf+COhIMEBk18HfOAi2zxsIjP4I9s8C4ML+UMygwmgWKgBpgJQC6gaoFAHqFAIoCCDHaAcuZNfC3vgVBQDVDm3J5jVWAWBH/YDoaYGAuNhJL4HwfSAYEOOAR0IYgO2ecADpj5DgAEdCLYDtnnBpn5FBCCc5uiXdR0KZCBHtnnARQQgjsroSXUERESEwAduwAf8GehpD+kP6Q/rhQ/BFTbPAf6RAGksSHAALGOiAWgEDVVEts84FMCgCD0Dm+hlDAFoAHjDRA1QUNjRBQVBMQj+kTtRND0BCFuBKQUsY6HEDVfBXDbPOAE0//TH9Mf0//UAdCDCNcZAdGCEGVMUHTIyx9SQMsfUjDLH1Jgy/9SIMv/ydBRFfkRjocQaF8Icds84SGDD7mOhxBoXwh22zzgBxsbGxkEeo6ENBPbPOAighBOQ29kuo8YNFRSRNs8loIQzkNvZJKEH+JAM3CAQNs84CKCEO52T0u6I4IQ7nZPb7pSELEeHysgAiDbPAygVQUL2zxUIFOAIPRDXTwBBNs8RASk2zzJAts8UbODB/QOb6GUXw6A+uGBAUDXIfoAMFIIqbQfGaBSB7yUXwyA+eBRW7uUXwuA+OBtcFMHVSDbPAb5AEYJgwf0U5RfCoD34UZQEDcQJxddKRgANIC8yMoHGMv/FswUyx8SywfL/wH6AgH6AssfAyLbPAKAIPRD2zwzEEUQNFjbPDxjRARW2zwxDYIQO5rKAKEgqgsjuY6HEL1fDXLbPOBRIqBRdb2OhxCsXwxz2zzgDGYbGxoEwI6HEJtfC3DbPOBTa4MH9A5voSCfMPoAWaAB0z8x0/8wUoC9kTHijocQm18LdNs84FMBuY6HEJtfC3XbPOAg8qz4APgjyFj6AssfFMsfFsv/GMv/QDiDB/RDEEVBMBZwcBsbGxwBGIIQ7m9FTFlwgEDbPCsCJts8yPQAWM8Wye1UII6DcNs84FtIHQEgghDzdEhMWYIQO5rKAHLbPCsC1jEh+kQBpI6OMIIQ/////kATcIBA2zzg7UTQ9AT0BFAzgwf0Zm+hjo9fBIIQ/////kATcIBA2zzhNgX6ANEByPQAFfQAAc8Wye1UghD5b3MkcIAYyMsFUATPFlAE+gISy2oSyx/LP8mAQPsAKysAbnD4MyBuk18EcODQ1wv/I/pEAaQCvbGTXwNw4PgAAdQh+wQgxwCSXwScAdDtHu1TAfEGgvIA4n8Elo6GMzRDANs84DAighBSZ0Nwuo6mVEMV8B+AQCGjIsL/l1t0+wJwgwaRMuIBghDyZ2NQoANERHAB2zzgNCGCEFZ0Q3C64wIzIIMesCErIiMCoDIC+kRw+DPQ1wv/7UTQ9AQEpFq9sSFusZJfBODbPGxRUhW9BLMUsZJfA+D4AAGRW46d9AT0BPoAQzTbPHDIygAT9AD0AFmg+gIBzxbJ7VTiZkMDoAODCNcYINMf0w/TH9P/0QOCEFZ0Q1C68qUh2zww0wcBgN+wwFPyqdMfAYIQjoEnirryqdP/0z8wRWb5EfKiVQLbPIIQ1nRSQKBAM3CAQNs8JCUrARyOiYQfQDNwgEDbPOFfAysBGNs8MlmAEPQOb6EwASgEQNs8U5OAIPQOb6GTXwt+4ds8TxNQ7ds8IMEBkmzx4CFuY10mJwPUUyODB/QOb6GUXwRtf+HbPDAB+QAC2zxTFb0hwQAhsJRfCm194JlfA20Cc6nUAAKSNDTiU1CAEPQOb6ExlF8HbXDg+CPIyx9AZoAQ9ENUIAShUTOyJFAzBNs8QDSDB/RDAcL/kzFtceABcihUKQNUkTGOjUrM2zxQmaBQ6KENUJviEEYQNRAkEDtNzNs8UIKAIPRDVSJGYNs8KjxEACyAIvgzINDTBwHAEvKogGDXIdM/9ATRAByALcjLBxTMEvQAy//KPwKg0Ns8NDQ0U0WDB/QOb6GUXwZwIOHT/9M/+gDSANFSFqm0HxagUlC2CFFVoQLIy//LPwH6AhLKAEBFgwf0QyOrAgKqAhK2CFQUIts8UiKhQwNVRwBEcIAYyMsFUAfPFlj6AhXLahPLH8s/IcL/kssfkTHiyQH7AAIBIC4vAgFIPj8AA/OEAgEgMDED91gBD4M9DTD9MPMdMP0XG2CXBtf45BKYMH9HxvpSCOMgL6ANMf0x/T/9P/0QOjBMjLfxTKH1JAy//J0FEatgjIyx8Ty//L/0AUgQGg9EEDpEMTkTLiAbPmMDRYtghTAbmXXwdtcG1TEeBtiuYzNKVckm8R5HAgiuY2NlsigyMzQCASA4OQBkA4EBoPSSb6UgjiEB039RGbYIAdMfMdcL/wPTH9P/MdcL/0EwFG8EUAVvAgSSbCHisxQBSAJvIgFvEASkU0i+jpBUZQbbPFMCvJRsIiICkTDikTTiUza+EzUBXsAAUkO5ErGXXwRtcG1TEeBTAaWSbxHkbxBvEHBTAG1tiuY0NDQ2UlW68rFQREMTNgA0cAKOEwJvIiFvEAJvESSoqw8StggSoFjkMDEB/gZvIgFvJFMdgwf0Dm+h8r36ADHTPzHXC/9TnLmOXVE6qKsPUkC2CFFEoSSqOy6pBFGVoFGJoIIQjoEniiOSgHOSgFPiyMsHyx9SQMv/UqDLPyOUE8v/ApEz4lQiqIAQ9ENwJMjL/xrLP1AF+gIYygBAGoMH9EMIEEUTFJJsMeI3ASIhjoVMANs8CpFb4gSkJG4VF0cD9QB2zw0+CMluZNfCHDgcPgzbpRfCPAj4IAR+DPQ+gD6APoA0x/RU2G5lF8M8CPgBJRfC/Aj4AaTXwpw4CMQSVEyUHfwJSDAACCzKwYQWxBKEDlN3ds8I44QMWxSyPQA9AABzxbJ7VTwI+HwDTL4IwGgpsQptgmAEPgz0IGZIOgOnNs8gCL4M/kAUwG6k18HcOAiji9TJIAg9A5voY4g0x8xINMf0/8wUAS68rn4I1ADoMjLH1jPFkAEgCD0QwKTE18D4pJsIeJ/iuYgbpIwcN4B2zx/gYz1EArqAENch1wsPUnC2CFMToIASyMsHUjDLH8sfGMsPF8sPGss/E/QAyXD4M9DXC/9TGNs8CfQEUFOgKKAJ+QAQSRA4QGVwbds8QDWAIPRDA8j0ABL0ABL0AAHPFsntVH87PABGghBOVlNUcIIAxP/IyxAVy/+DHfoCFMtqE8sfEss/zMlx+wAAKAbIyx8Vyx8Ty//0AAH6AgH6AvQAAJYjgCD0fG+lII48AtM/0/9TFbqOLjQD9AT6APoAKKsCUZmhUCmgBMjLPxbL/xL0AAH6AgH6AljPFlQgBYAg9EMDcAGSXwPikTLiAbMDk1Ads8bFGTXwNw4QL0BFExgCD0Dm+hk18EcOGAQNch1wv/gCL4MyHbPIAk+DNY2zyxjhNwyMoAEvQA9AABzxbJ7VTwJzB/4F8DcIZkBAAgEgQUIAGCFukltwlQH5AAG64gN5Ns8f48yJIAg9HxvpSCPIwLTHzD4I7tTFL2wjxUxVBVE2zwUoFR2E1RzWNs8A1BUcAHekTLiAbPmbGFus4GNDRAHdDGAJPgzbpJbcOFx+DPQ1wv/+Cj6RAGkAr2xkltw4IAi+DMgbpNfA3Dg8A0wMgLQgCjXIdcLH/gjUROhXLmTXwZw4FyhwTyRMZEw4oAR+DPQ+gAwA6BSAqFwbRA0ECNwcNs8yPQA9AABzxbJ7VR/gSANEAYAg9GZvoZIwcOHbPDBsMyDCAI6EEDTbPI6FMBAj2zziEl1FRgAoBcj0ABT0ABL0AAH6Assfy//J7VQBmHBTAH+OtyaDB/R8b6UgjqgC0//TPzH6ANIA0ZQxUTOgjpFUdwiphFFmoFIXoEuw2zwJA+JQU6AEkTLiAbPmMDUDulMhu7DyuxKgAaFHAXJwIH+OrSSDB/R8b6Ugjp4C0//TPzH6ANIA0ZQxUTOgjodUGIjbPAcD4lBDoAORMuIBs+YwMwG68rtHADJTEoMH9A5voZT6ADCgkTDiyAH6AgKDB/RDACoGyMsfFcsfUAP6AgH6AvQAygDKAMkCASBLTAIBIGFiAgEgTU4CASBWVwJTtkhbZ5Cf7bHTqiJQYP6PzfSkEdGAW2eKQg3gSgBt4EBSJlxANmJczYQwXFMCASBPUAJhsKI2zwQNV8Fgx9tjqBREoAg9H5vpSCOjwLbPF8EI0MTbwRQA28CApEy4gGzEuZsIYGNdAgEgUVICJ6wOgO2eQYP6BzfQx0FtnkkYNvFAXFMCXa9LbZ4IGq+CwY+2x08oiUAQej830pBHRoFtnhOqsDeEKAG3gQFImXEA2YlzNhDAY10CSts8bYMfjhIkgBD0fm+lMiGVUgNvAgLeAbPmMDMD0Ns8bwgDbwRUVQAe0wcBwC3yidT0BNP/0j/RAC7SBwHAvPKJ0//U0x/TB9P/+gD6ANMf0QIBalhZATO30/tngLBhNAA1AHTASgCVAlQANQA0EGO0EGACASBaWwFCqyztRND0BSBukltw4Ns8ECZfBoMH9A5voZP6ADCSMHDiZgEDp8lcAgFIXl8CKNs8EDVfBYAg9A5voZIwbeHbPGxhY10AHtMf0x/T//QE+gD6APQE0QAjuH7UTQ9AUgbpIwcJTQ1wsf4oAYe6rtRND0BSBumDBwVHAAbVMR4Ns8bYT/jickgwf0fm+lII4YAvoA0x8x0x/T/9P/0W8EUhBvAlADbwICkTLiAbPmMDOGYAPIAN+DMgbpYwgyNxgwif0NMHAcAa8on6APoA+gDR4gFJuYdds8EDVfBYMfbY4UURKAIPR+b6UyIZVSA28CAt4BsxLmbCGGMCAVhkZQAg7UTQ9AT0BPQE+gDTH9P/0QFtsKV7UTQ9AUgbpIwbeDbPBAmXwZthP+OGyKDB/R+b6UgnQL6ADBSEG8CUANvAgKRMuIBs+YwMYGYAM7PgO1E0PQEMfQEMIMH9A5voZP6ADCSMHDigACDQ0x/TH/oA+gD0BNIA0gDR";
    // let account = base64_decode(account).unwrap();
    // let account = chain_block::Account::construct_from_bytes(&account).unwrap();
    // let shard_account = ShardAccount::with_params(&account, Default::default(), 0).unwrap();
    let result = run_smc_method(
        &shard_account.read_account().unwrap(),
        mc_state_cell.clone(),
        method_id,
        Vec::new(),
        mc_state.gen_time(),
        mc_state.gen_lt(),
    )
    .unwrap()
    .into_run_result()
    .unwrap();
    assert_eq!(result.exit_code, 11);
    assert_eq!(result.gas_used, 770);
    assert_eq!(result.stack.len(), 1);
    assert_eq!(result.stack[0].number().unwrap().number(), "0x14c97");
}

/// The Elector as this repository's zerostate deploys it, and the same Elector holding one
/// accepted post-quantum stake. Both are produced from the real zerostate and kept current
/// by `vm_getter_fixtures_match_the_deployed_elector` in the contracts crate.
const ELECTOR_AT_ZEROSTATE: &str = "elector-zerostate.boc";
const ELECTOR_WITH_ONE_STAKE: &str = "elector-one-stake.boc";

fn load_elector_fixture(name: &str) -> ShardAccount {
    let path = format!("{}/src/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let account = chain_block::Account::construct_from_bytes(&bytes).unwrap();
    ShardAccount::with_params(&account, Default::default(), 0).unwrap()
}

fn load_mc_state_cell() -> Cell {
    let mc_state_name = "../block/src/tests/data/free-tos-mc-state-61884";
    Cell::read_from_file(mc_state_name)
}

fn run_elector_method(
    fixture: &str,
    method: &str,
    stack: Vec<tl_api::tos::tvm::StackEntry>,
) -> tl_api::tos::smc::runresult::RunResult {
    let shard_account = load_elector_fixture(fixture);
    let mc_state_cell = load_mc_state_cell();
    let mc_state = ShardStateUnsplit::construct_from_cell(mc_state_cell.clone()).unwrap();
    let method_id = tos_method_id(method);
    run_smc_method(
        &shard_account.read_account().unwrap(),
        mc_state_cell,
        method_id,
        stack,
        mc_state.gen_time(),
        mc_state.gen_lt(),
    )
    .unwrap()
    .into_run_result()
    .unwrap()
}

fn stack_number(value: i64) -> tl_api::tos::tvm::StackEntry {
    let items = convert_stack(&[StackItem::int(value)]).unwrap();
    items.into_iter().next().unwrap()
}

fn stack_number_from_str(value: &str) -> tl_api::tos::tvm::StackEntry {
    let number = parse_stack_number(value).unwrap();
    let items = convert_stack(&[StackItem::int(number)]).unwrap();
    items.into_iter().next().unwrap()
}

fn number(entry: &tl_api::tos::tvm::StackEntry) -> String {
    entry.number().expect("a number").number().to_owned()
}

/// `participant_list_extended` returns the election summary with the member list at index
/// 4. Each member is `[validator_id, [stake, max_factor, key_id, adnl_addr]]`: the upstream
/// shape, with the member's key identity where the sender address would be.
fn members(
    result: &tl_api::tos::smc::runresult::RunResult,
) -> Vec<(String, Vec<tl_api::tos::tvm::StackEntry>)> {
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stack.len(), 7, "the election summary has seven fields");
    let list = match &result.stack[4] {
        tl_api::tos::tvm::StackEntry::Tvm_StackEntryList(list) => list.list.elements(),
        other => panic!("expected the member list at stack[4], got {:?}", other),
    };
    list.iter()
        .map(|member| {
            let fields = match member {
                tl_api::tos::tvm::StackEntry::Tvm_StackEntryTuple(tuple) => tuple.tuple.elements(),
                other => panic!("expected a member tuple, got {:?}", other),
            };
            assert_eq!(fields.len(), 2, "a member is [validator_id, arguments]");
            let arguments = match &fields[1] {
                tl_api::tos::tvm::StackEntry::Tvm_StackEntryTuple(tuple) => tuple.tuple.elements(),
                other => panic!("expected the member arguments, got {:?}", other),
            };
            assert_eq!(arguments.len(), 4, "member arguments have four fields");
            (number(&fields[0]), arguments.to_vec())
        })
        .collect()
}

/// The one member of the staked fixture.
fn staked_member() -> (String, Vec<tl_api::tos::tvm::StackEntry>) {
    let result =
        run_elector_method(ELECTOR_WITH_ONE_STAKE, "participant_list_extended", Vec::new());
    let mut list = members(&result);
    assert_eq!(list.len(), 1, "the fixture holds exactly one stake");
    list.remove(0)
}

#[test]
fn test_run_get_method_participant_list_extended_empty_list() {
    let result = run_elector_method(ELECTOR_AT_ZEROSTATE, "participant_list_extended", Vec::new());
    assert!(members(&result).is_empty());
}

#[test]
fn test_run_get_method_elector_active_election_id() {
    let result = run_elector_method(ELECTOR_AT_ZEROSTATE, "active_election_id", Vec::new());
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stack.len(), 1);
    assert_eq!(number(&result.stack[0]), "0x0");

    // With a stake placed, the open election is the one the summary names.
    let summary =
        run_elector_method(ELECTOR_WITH_ONE_STAKE, "participant_list_extended", Vec::new());
    let open = run_elector_method(ELECTOR_WITH_ONE_STAKE, "active_election_id", Vec::new());
    assert_eq!(open.exit_code, 0);
    assert_ne!(number(&open.stack[0]), "0x0", "the staked fixture has an election open");
    assert_eq!(number(&open.stack[0]), number(&summary.stack[0]));
}

#[test]
fn test_run_get_method_elector_compute_returned_stake_zero_addr() {
    let result =
        run_elector_method(ELECTOR_AT_ZEROSTATE, "compute_returned_stake", vec![stack_number(0)]);
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stack.len(), 1);
    assert_eq!(number(&result.stack[0]), "0x0");
}

#[test]
fn test_run_get_method_elector_participates_in_zero_pubkey() {
    let result = run_elector_method(ELECTOR_AT_ZEROSTATE, "participates_in", vec![stack_number(0)]);
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stack.len(), 1);
    assert_eq!(number(&result.stack[0]), "0x0");
}

#[test]
fn test_run_get_method_participant_list_extended_one_stake_keeps_member_shape() {
    let (validator_id, arguments) = staked_member();
    assert_ne!(validator_id, "0x0");
    assert_ne!(number(&arguments[0]), "0x0", "the member's stake");
    assert_ne!(number(&arguments[1]), "0x0", "the member's weight factor");
    assert_ne!(number(&arguments[2]), "0x0", "the member's key id");
    assert_ne!(number(&arguments[2]), validator_id, "the key id is not the staking account");
    assert_ne!(number(&arguments[3]), "0x0", "the member's ADNL address");
}

#[test]
fn test_run_get_method_participates_in_one_stake_member() {
    let (validator_id, arguments) = staked_member();
    let result = run_elector_method(
        ELECTOR_WITH_ONE_STAKE,
        "participates_in",
        vec![stack_number_from_str(&validator_id)],
    );
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stack.len(), 1);
    assert_eq!(number(&result.stack[0]), number(&arguments[0]), "participates_in is the stake");
}

#[test]
fn test_run_get_method_compute_returned_stake_one_stake_member() {
    // A stake in an open election is not yet a credit the member could recover.
    let (validator_id, _) = staked_member();
    let result = run_elector_method(
        ELECTOR_WITH_ONE_STAKE,
        "compute_returned_stake",
        vec![stack_number_from_str(&validator_id)],
    );
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stack.len(), 1);
    assert_eq!(number(&result.stack[0]), "0x0");
}

#[test]
fn test_convert_stack() {
    let mut tuple = StackItem::None;
    for n in 0..3 {
        tuple = StackItem::tuple(vec![StackItem::int(n), tuple]);
    }
    let items = convert_stack(&[tuple.clone()]).unwrap();
    let result = convert_tos_stack(&items).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], tuple);
}

#[test]
fn test_convert_stack_none_is_empty_list() {
    let items = convert_stack(&[StackItem::None]).unwrap();
    assert_eq!(items.len(), 1);
    match &items[0] {
        tl_api::tos::tvm::StackEntry::Tvm_StackEntryList(list) => {
            assert!(list.list.elements().is_empty());
        }
        other => panic!("expected list, got {:?}", other),
    }
}

#[test]
fn test_convert_stack_tuple_pair_with_inner_tuple() {
    let tuple =
        StackItem::tuple(vec![StackItem::int(1), StackItem::tuple(vec![StackItem::int(2)])]);
    let items = convert_stack(&[tuple]).unwrap();
    assert_eq!(items.len(), 1);
    match &items[0] {
        tl_api::tos::tvm::StackEntry::Tvm_StackEntryTuple(outer) => {
            let outer = outer.tuple.elements();
            assert_eq!(outer.len(), 2);
            assert_eq!(outer[0].number().unwrap().number(), "0x1");
            match &outer[1] {
                tl_api::tos::tvm::StackEntry::Tvm_StackEntryTuple(inner) => {
                    let inner = inner.tuple.elements();
                    assert_eq!(inner.len(), 1);
                    assert_eq!(inner[0].number().unwrap().number(), "0x2");
                }
                other => panic!("expected inner tuple, got {:?}", other),
            }
        }
        other => panic!("expected tuple, got {:?}", other),
    }
}

#[test]
fn incoming_storage_context_is_versioned_and_optional() {
    use chain_block::{ConfigParam8, ConfigParamEnum, GlobalVersion};
    for version in [15, 16, 17, 18, 19] {
        let mut sci = SmartContractInfo::default();
        sci.config_params
            .set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 {
                global_version: GlobalVersion { version, capabilities: 0 },
            }))
            .unwrap();
        for present in [false, true] {
            sci.incoming_storage = present.then(|| ([0xabu8; 32].into(), 129, 131073));
            let item = sci.as_temp_data_item();
            let params = item.as_tuple().unwrap()[0].as_tuple().unwrap();
            assert_eq!(params.len(), if version < 16 { 18 } else { 19 });
            if version >= 16 {
                if present {
                    let stats = params[18].as_tuple().unwrap();
                    assert_eq!(stats.len(), 4);
                    assert_eq!(stats[0], StackItem::int(1));
                    assert_eq!(
                        stats[1],
                        StackItem::int(IntegerData::from_unsigned_bytes_be(&[0xab; 32]))
                    );
                    assert_eq!(stats[2], StackItem::int(129));
                    assert_eq!(stats[3], StackItem::int(131073));
                } else {
                    assert_eq!(params[18], StackItem::None);
                }
            }
        }
    }
}

/// The getter c7 shape shared with the C++ getter paths (liteserver, proof
/// verifier, emulator), which check the same record in `getter-context-c7-parity`.
#[test]
fn getter_context_shape_matches_the_cpp_getter_paths() {
    use chain_block::{ConfigParam8, ConfigParamEnum, GlobalVersion};
    let path =
        format!("{}/../../../test/validator/data/getter-c7-shape.tsv", env!("CARGO_MANIFEST_DIR"));
    let record = std::fs::read_to_string(&path).expect("getter c7 shape record");
    let mut rows = 0;
    for line in record.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 3, "malformed row {line:?}");
        let version: u32 = fields[0].parse().expect("version");
        let length: usize = fields[1].parse().expect("length");
        let mut sci = SmartContractInfo::default();
        sci.config_params
            .set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 {
                global_version: GlobalVersion { version, capabilities: 0 },
            }))
            .unwrap();
        // A get-method imports no external message.
        sci.incoming_storage = None;
        let item = sci.as_temp_data_item();
        let params = item.as_tuple().unwrap()[0].as_tuple().unwrap();
        assert_eq!(params.len(), length, "c7[0] length at version {version}");
        let slot = match params.get(18) {
            None => "absent",
            Some(StackItem::None) => "null",
            Some(_) => "value",
        };
        assert_eq!(slot, fields[2], "c7[18] at version {version}");
        rows += 1;
    }
    assert!(rows >= 3, "the shape record must cover versions 15, 16 and 17");
}

/// How a get-method ends, for code that ignores the method id. Each case gives the code, the
/// expected exit code and the expected final stack, bottom to top (`None` stands for the gas
/// consumed). The stacks are what the C++ VM leaves: out of gas keeps only the gas consumed, an
/// exception keeps its argument, and a program that jumps into the default exception handler
/// keeps everything below the exit code it chose. 13 chosen by a program is not out of gas.
const GET_METHOD_ENDINGS: &[(&str, &[u8], i32, &[Option<i64>])] = &[
    // PUSHINT 7, PUSHCONT {}, AGAIN
    ("out of gas", &[0x77, 0x90, 0xEA], -14, &[None]),
    // PUSHINT 7, THROW 6
    ("throw", &[0x77, 0xF2, 0x06], 6, &[Some(0)]),
    // PUSHINT 42, THROWARG 9
    ("throwarg", &[0x80, 42, 0xF2, 0xC8, 0x09], 9, &[Some(42)]),
    // PUSHINT 5, PUSHINT 7, PUSHINT 13, PUSH c2, JMPX
    (
        "jump into the default handler",
        &[0x75, 0x77, 0x80, 0x0D, 0xED, 0x42, 0xD9],
        13,
        &[Some(METHOD_ID), Some(5), Some(7)],
    ),
    // THROW 13
    ("throw 13", &[0xF2, 0x0D], 13, &[Some(0)]),
];

const METHOD_ID: i64 = 0x1_2345;

fn account_with_code(code: &[u8]) -> Account {
    let mut state_init = StateInit::default();
    state_init.set_code(
        BuilderData::with_raw(code.to_vec(), code.len() * 8).unwrap().into_cell().unwrap(),
    );
    state_init.set_data(Cell::default());
    Account::active_standard([0x11; 32], 1_000_000_000, 0, 0, state_init)
}

#[test]
fn get_method_reports_how_the_vm_ended() {
    let mc_state_cell = load_mc_state_cell();
    let mc_state = ShardStateUnsplit::construct_from_cell(mc_state_cell.clone()).unwrap();
    for (name, code, exit_code, stack) in GET_METHOD_ENDINGS {
        let result = run_smc_method(
            &account_with_code(code),
            mc_state_cell.clone(),
            METHOD_ID as u32,
            Vec::new(),
            mc_state.gen_time(),
            mc_state.gen_lt(),
        )
        .unwrap();
        assert_eq!(result.exit_code, *exit_code, "{name}");
        let actual: Vec<i64> =
            result.stack.iter().map(|x| x.as_integer_value(i64::MIN..=i64::MAX).unwrap()).collect();
        let expected: Vec<i64> = stack.iter().map(|x| x.unwrap_or(result.gas_used)).collect();
        assert_eq!(actual, expected, "{name}");
    }
}
