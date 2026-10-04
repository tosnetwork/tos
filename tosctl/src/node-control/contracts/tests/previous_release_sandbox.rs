/*
 * Copyright (C) 2025-2026 TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 */

//! Instances of the previous release are refused, not misread or signed for.
//!
//! `previous_release/*.boc.base64` is the frozen code of Task Escrow, Dispute,
//! Proof Attestation and Service Actor as the previous release shipped it
//! (main at 9d470d7cc). Each test deploys that code in the sandbox, reads the
//! code back from the account the way tosctl reads it from the chain, and
//! requires the version check every decode and signing path runs first to
//! refuse it while admitting an instance of the current code.

use chain_block::{
    BuilderData, Cell, Coins, IBitstring, MsgAddressInt, Serializable, StateInit, base64_decode,
    read_single_root_boc, write_boc,
};
use common::tvm_stack_parser::TvmStackParser;
use contracts::{
    DisputeContract, DisputeInit, ProofAttestationContract, ProofAttestationInit,
    ServiceActorContract, ServiceActorInit, TaskEscrowContract, TaskEscrowInit, VersionedContract,
};
use ed25519_dalek::{Signer, SigningKey};
use tos_sandbox::{Blockchain, MessageBuilder};

const TOS: u64 = 1_000_000_000;
/// Proof Attestation's refusal of a signature that does not verify.
const ERR_BAD_SIGNATURE: i32 = 2101;

fn previous_code(name: &str) -> Cell {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/previous_release")
        .join(format!("{name}.boc.base64"));
    let text = std::fs::read_to_string(&path).expect("a previous-release fixture");
    read_single_root_boc(base64_decode(text.trim()).expect("base64")).expect("a code boc")
}

fn chain() -> Blockchain {
    let mut bc = Blockchain::new().expect("blockchain");
    bc.set_workchain(-1);
    bc
}

fn deploy(bc: &mut Blockchain, code: Cell, data: Cell) -> MsgAddressInt {
    let funder = bc.treasury("funder", 1_000 * TOS).expect("funder");
    let init = StateInit::with_code_and_data(code, data);
    let hash = init.serialize().expect("a state init").repr_hash();
    let address = MsgAddressInt::with_params(-1, hash).expect("an address");
    let msg = MessageBuilder::internal(funder.address(), &address, 20 * TOS)
        .bounce(false)
        .state_init(init)
        .body(Cell::default())
        .build();
    bc.send_message(msg).expect("deploy").expect_success();
    address
}

/// The deployed code as an account query returns it: a BOC.
fn deployed_code_boc(bc: &Blockchain, address: &MsgAddressInt) -> Vec<u8> {
    let code = bc.get_account(address).and_then(|a| a.get_code()).expect("deployed code");
    write_boc(&code).expect("a code boc")
}

fn assert_refused(contract: VersionedContract, bc: &Blockchain, address: &MsgAddressInt) {
    let boc = deployed_code_boc(bc, address);
    let error = contract.require_supported_code_boc(Some(&boc)).unwrap_err().to_string();
    let deployed = read_single_root_boc(&boc).unwrap().repr_hash().as_hex_string();
    let supported = contract.supported_code().unwrap().repr_hash().as_hex_string();
    assert!(
        error.contains(&format!("unsupported {} contract version {deployed}", contract.name())),
        "{error}"
    );
    assert!(error.contains(&format!("this tosctl supports {supported}")), "{error}");
}

fn assert_admitted(contract: VersionedContract, bc: &Blockchain, address: &MsgAddressInt) {
    let boc = deployed_code_boc(bc, address);
    contract.require_supported_code_boc(Some(&boc)).unwrap();
}

fn stack_to_entries(stack: &[tos_vm::stack::StackItem]) -> Vec<tl_api::tos::tvm::StackEntry> {
    use tl_api::tos::tvm::{
        Number, StackEntry,
        numberdecimal::NumberDecimal,
        slice,
        stackentry::{StackEntryNumber, StackEntrySlice},
    };
    stack
        .iter()
        .map(|item| {
            if let Ok(int) = item.as_integer() {
                return StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
                    number: Number::Tvm_NumberDecimal(NumberDecimal { number: int.to_string() }),
                });
            }
            if let Ok(s) = item.as_slice() {
                let bytes = s.clone().get_bytestring(0);
                return StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
                    slice: slice::Slice { bytes },
                });
            }
            panic!("unsupported stack item: {item:?}");
        })
        .collect()
}

fn task_init(bc: &mut Blockchain) -> TaskEscrowInit {
    let creator = bc.treasury("creator", 1_000 * TOS).expect("creator");
    let agent = bc.treasury("agent", 1_000 * TOS).expect("agent");
    TaskEscrowInit {
        creator: creator.address().clone(),
        assigned_agent: Some(agent.address().clone()),
        verifier: Some(creator.address().clone()),
        budget: TOS,
        deadline: u64::from(bc.now()) + 3_600,
        review_period: 3_600,
        settlement_policy_hash: [0x11; 32],
        permission_hash: [0x22; 32],
        attestor_pubkey: None,
        dispute_fallback_agent_bps: TaskEscrowContract::DEFAULT_DISPUTE_FALLBACK_AGENT_BPS,
    }
}

/// The previous release's Task Escrow storage: its permission cell held the
/// permission and dispute hashes only, without the fallback split and the
/// dispute deadline.
fn previous_task_data(init: &TaskEscrowInit) -> Cell {
    let agent = init.assigned_agent.as_ref().unwrap_or(&init.creator);
    let verifier = init.verifier.as_ref().unwrap_or(&init.creator);
    let mut data = BuilderData::new();
    init.creator.write_to(&mut data).unwrap();
    data.append_bit_one().unwrap();
    agent.write_to(&mut data).unwrap();
    data.append_bit_one().unwrap();
    verifier.write_to(&mut data).unwrap();
    Coins::new(init.budget).write_to(&mut data).unwrap();
    data.append_u64(init.deadline).unwrap().append_u8(0).unwrap();
    let mut permission = BuilderData::new();
    permission.append_u256(&init.permission_hash).unwrap().append_u256(&[0; 32]).unwrap();
    let mut attestor = BuilderData::new();
    attestor.append_bit_zero().unwrap().append_raw(&[0; 32], 256).unwrap();
    let mut hashes = BuilderData::new();
    hashes
        .append_u256(&[0; 32])
        .unwrap()
        .append_u256(&[0; 32])
        .unwrap()
        .append_u256(&init.settlement_policy_hash)
        .unwrap()
        .append_u32(init.review_period)
        .unwrap()
        .append_u64(0)
        .unwrap()
        .checked_append_reference(permission.into_cell().unwrap())
        .unwrap()
        .checked_append_reference(attestor.into_cell().unwrap())
        .unwrap();
    data.checked_append_reference(hashes.into_cell().unwrap()).unwrap();
    data.into_cell().unwrap()
}

fn task_data_stack(bc: &Blockchain, address: &MsgAddressInt) -> TvmStackParser {
    let result = bc.run_get_method(address, "get_task_data", vec![]).expect("get_task_data");
    result.expect_success();
    TvmStackParser::new(stack_to_entries(&result.stack))
}

#[test]
fn a_previous_task_escrow_is_refused_before_decoding_or_signing() {
    let mut bc = chain();
    let init = task_init(&mut bc);
    let old = deploy(&mut bc, previous_code("task-escrow"), previous_task_data(&init));
    let current = deploy(
        &mut bc,
        TaskEscrowContract::code().unwrap(),
        TaskEscrowContract::build_data(&init).unwrap(),
    );

    assert_refused(VersionedContract::TaskEscrow, &bc, &old);
    assert_admitted(VersionedContract::TaskEscrow, &bc, &current);

    // Paths that decode without the code check (indexer, list views) still
    // refuse: the previous getter is narrower than the layout read here.
    let error = TaskEscrowContract::decode_data(&task_data_stack(&bc, &old)).unwrap_err();
    assert!(error.to_string().contains("unsupported Task Escrow contract version"), "{error}");
    let data = TaskEscrowContract::decode_data(&task_data_stack(&bc, &current)).unwrap();
    assert_eq!(data.budget, init.budget);
}

#[test]
fn a_previous_dispute_is_refused() {
    let mut bc = chain();
    let claimant = bc.treasury("claimant", 1_000 * TOS).expect("claimant");
    let respondent = bc.treasury("respondent", 1_000 * TOS).expect("respondent");
    let init = DisputeInit {
        claimant: claimant.address().clone(),
        respondent: respondent.address().clone(),
        reviewer: claimant.address().clone(),
        deadline: 1_800_000_000,
        subject_hash: [0x11; 32],
        claimant_evidence_hash: [0x22; 32],
        attestor_pubkey: None,
    };
    let data = DisputeContract::build_data(&init).unwrap();
    let old = deploy(&mut bc, previous_code("dispute"), data.clone());
    let current = deploy(&mut bc, DisputeContract::code().unwrap(), data);
    assert_refused(VersionedContract::Dispute, &bc, &old);
    assert_admitted(VersionedContract::Dispute, &bc, &current);
}

#[test]
fn a_previous_service_actor_is_refused() {
    let mut bc = chain();
    let owner = bc.treasury("owner", 1_000 * TOS).expect("owner");
    let init = ServiceActorInit {
        owner: owner.address().clone(),
        authorized_caller: None,
        open_access: true,
        price_per_call: TOS / 10,
        storage_fee: 200_000_000,
        cleanup_bounty: 100_000_000,
        rate_limit_per_day: 0,
        response_sla: 3_600,
        refund_claim_window: 3_600,
        metadata_hash: [0x11; 32],
        proof_scheme_hash: [0x22; 32],
        attestor_pubkey: None,
    };
    let data = ServiceActorContract::build_data(&init).unwrap();
    let old = deploy(&mut bc, previous_code("service-actor"), data.clone());
    let current = deploy(&mut bc, ServiceActorContract::code().unwrap(), data);
    assert_refused(VersionedContract::ServiceActor, &bc, &old);
    assert_admitted(VersionedContract::ServiceActor, &bc, &current);
}

/// Why signing is refused rather than attempted: a signature over this
/// release's attestation domain is one the previous code does not accept, so
/// tosctl would hand back a signature that looks usable and is not.
#[test]
fn a_previous_proof_attestation_is_refused_and_would_reject_a_current_signature() {
    let mut bc = chain();
    let owner = bc.treasury("owner", 1_000 * TOS).expect("owner");
    let relayer = bc.treasury("relayer", 1_000 * TOS).expect("relayer");
    let key = SigningKey::from_bytes(&[0x42; 32]);
    let init = ProofAttestationInit {
        owner: owner.address().clone(),
        public_key: key.verifying_key().to_bytes(),
        subject_hash: [0x11; 32],
    };
    let data = ProofAttestationContract::build_data(&init).unwrap();
    let old = deploy(&mut bc, previous_code("proof-attestation"), data.clone());
    let current = deploy(&mut bc, ProofAttestationContract::code().unwrap(), data);
    assert_refused(VersionedContract::ProofAttestation, &bc, &old);
    assert_admitted(VersionedContract::ProofAttestation, &bc, &current);

    let global_id = match bc.config_params().config(19).expect("parameter 19") {
        Some(chain_block::ConfigParamEnum::ConfigParam19(id)) => id as i32,
        other => panic!("parameter 19 is not the global id: {other:?}"),
    };
    let attested = [0xee; 32];
    for (address, accepted) in [(&current, true), (&old, false)] {
        let hash =
            ProofAttestationContract::attest_hash_to_sign(global_id, address, &attested).unwrap();
        let signature = key.sign(&hash).to_bytes();
        let body = ProofAttestationContract::attest(1, attested, &signature).unwrap();
        let msg = MessageBuilder::internal(relayer.address(), address, TOS / 10).body(body).build();
        let result = bc.send_message(msg).expect("send");
        if accepted {
            result.expect_success();
        } else {
            result.expect_exit_code(ERR_BAD_SIGNATURE);
        }
    }
}
