//! Same-chain service journey. Discovery and the attestation-to-escrow bridge
//! are explicit client checks; contracts do not call those adapters themselves.
use super::*;
use contracts::{
    AgentAccountContract, AgentAccountInit, AgentCheckedContractCallV2, ProofAttestationContract,
    ProofAttestationInit, TaskEscrowContract, TaskEscrowInit,
};

fn send(bc: &mut Blockchain, from: &MsgAddressInt, to: &MsgAddressInt, body: Cell) -> SendResult {
    recorded_send(bc, MessageBuilder::internal(from, to, TOS / 4).body(body).build(), to)
}

fn recorded_send(
    bc: &mut Blockchain,
    message: chain_block::Message,
    address: &MsgAddressInt,
) -> SendResult {
    use chain_block::{HashmapType, ShardAccount, UInt256, base64_encode, write_boc};
    let boc = |cell: Cell| base64_encode(write_boc(&cell).unwrap());
    let trace = std::env::var_os("SERVICE_JOURNEY_TRACE_DIR").map(|dir| {
        let before =
            ShardAccount::with_params(bc.get_account(address).unwrap(), UInt256::default(), 0)
                .unwrap();
        (
            dir,
            boc(HashmapType::data(&bc.config_params().config_params).unwrap().clone()),
            boc(before.serialize().unwrap()),
            boc(message.serialize().unwrap()),
        )
    });
    let result = bc.send_message(message).expect("service message");
    if let Some((dir, config, before, message)) = trace {
        let transactions = result.transactions_for(address);
        assert_eq!(transactions.len(), 1, "one primary transaction per trace");
        let transaction = transactions[0];
        let after =
            ShardAccount::with_params(bc.get_account(address).unwrap(), UInt256::default(), 0)
                .unwrap();
        let record = serde_json::json!({"unixtime": bc.now(),
            "lt": transaction.logical_time().to_string(), "config": config,
            "shard_account": before, "message": message,
            "rust_transaction": boc(transaction.serialize().unwrap()),
            "shard_account_after": boc(after.serialize().unwrap())});
        let thread = std::thread::current();
        let dir = std::path::PathBuf::from(dir).join(thread.name().unwrap().replace("::", "-"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{}.json", transaction.logical_time()));
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap();
        serde_json::to_writer(file, &record).unwrap();
    }
    result
}

fn deploy(
    bc: &mut Blockchain,
    from: &MsgAddressInt,
    to: &MsgAddressInt,
    init: StateInit,
    value: u64,
) {
    bc.send_message(
        MessageBuilder::internal(from, to, value)
            .bounce(false)
            .state_init(init)
            .body(Cell::default())
            .build(),
    )
    .expect("deploy")
    .expect_success();
}

fn balance(bc: &Blockchain, address: &MsgAddressInt) -> u64 {
    bc.get_account(address)
        .expect("account")
        .balance()
        .expect("balance")
        .coins
        .as_u64()
        .expect("coins")
}

fn task_status(bc: &Blockchain, address: &MsgAddressInt) -> i128 {
    bc.run_get_method(address, "get_task_data", vec![])
        .expect("task getter")
        .expect_success()
        .int_at(7)
}

/// Resolve the exact on-chain version entry, not the caller's advertised manifest.
fn resolve(f: &Fixture, cap: &CapabilityHandle, expected: &[u8; 32]) -> bool {
    let (owner_kind, owner_revoked, _, _) = state_header(&f.state());
    if owner_kind != 1 || owner_revoked {
        return false;
    }
    let state = f.state_at(&cap.address);
    if state_header(&state) != (2, false, 1, 1) || capability_owner(&state) != f.object_id {
        return false;
    }
    let mut versions = SliceData::load_cell(state.reference(0).expect("versions")).unwrap();
    assert_eq!(versions.get_next_u16().unwrap(), 1);
    let dict = chain_block::HashmapE::with_hashmap(256, versions.get_next_dictionary().unwrap());
    let mut key = BuilderData::new();
    key.append_u256(&cap.initial_version_hash).unwrap();
    let Some(mut entry) = dict.get(SliceData::load_builder(key).unwrap()).unwrap() else {
        return false;
    };
    let manifest = entry.get_next_bytes(32).unwrap();
    let revoked = entry.get_next_bit().unwrap();
    let text = entry.checked_drain_reference().unwrap();
    !revoked && manifest == expected && text == protocol_text(b"1.0.0")
}

fn signed_call(
    bc: &mut Blockchain,
    account: &MsgAddressInt,
    key: &SigningKey,
    seqno: u32,
    target: &MsgAddressInt,
    body: Cell,
) -> Cell {
    let payload = AgentAccountContract::build_checked_contract_call_v2_payload(
        42,
        0,
        seqno,
        bc.now().checked_add(300).unwrap(),
        &AgentCheckedContractCallV2 { target: target.clone(), value: TOS / 4, body },
    )
    .unwrap();
    let digest = AgentAccountContract::controller_hash_to_sign(account, 42, &payload).unwrap();
    let signed = AgentAccountContract::build_signed_controller_message(
        payload,
        &key.sign(&digest).to_bytes(),
    )
    .unwrap();
    let message = MessageBuilder::external(account)
        .body_slice(SliceData::load_cell(signed.clone()).unwrap())
        .build();
    let result = recorded_send(bc, message, account);
    result.expect_success();
    assert!(!result.transactions_for(target).is_empty(), "target delivery required");
    signed
}

fn journey(disputed: bool) {
    let mut f = Fixture::new();
    // Pin parameter43 explicitly. Native replay completes mandatory config;
    // leaving size limits absent here would execute the fallback branch only
    // in Rust and compare different instruction paths and gas totals.
    f.bc.set_size_limits_config(chain_block::SizeLimitsConfig::default()).unwrap();
    let buyer = f.bc.treasury("journey-buyer", 100 * TOS).unwrap();
    let verifier = f.bc.treasury("journey-verifier", 100 * TOS).unwrap();
    let outsider = f.bc.treasury("journey-outsider", 100 * TOS).unwrap();
    let controller = SigningKey::from_bytes(&[0x62; 32]);
    let attestor = SigningKey::from_bytes(&[0x63; 32]);
    let account_init = AgentAccountInit {
        owner: buyer.address().clone(),
        controller_pubkey: controller.verifying_key().to_bytes(),
        deployment_id: [0x64; 32],
        max_per_tx: TOS,
        daily_limit: 2 * TOS,
        default_task_timeout_secs: 3600,
        metadata_hash: Some(f.object_id),
        service_endpoint_hash: None,
    };
    let account = AgentAccountContract::calculate_address(-1, &account_init).unwrap();
    deploy(
        &mut f.bc,
        buyer.address(),
        &account,
        AgentAccountContract::build_state_init(&account_init).unwrap(),
        5 * TOS,
    );
    // Canonical fixture manifest binds execution address, code and authority.
    // Binding it into the registry does not grant that registry spending rights.
    let manifest_bytes = format!(
        "service-v1|{}|{}|{}|{}",
        account,
        AgentAccountContract::code().unwrap().repr_hash(),
        hex::encode(controller.verifying_key().to_bytes()),
        hex::encode(attestor.verifying_key().to_bytes())
    );
    let manifest = bytes_hash(manifest_bytes.as_bytes());
    let id = f.object_id;
    let registry = f.registry.clone();
    let registry_key = SigningKey::from_bytes(&[0x31; 32]);
    let cap = f.register_capability(&id, &registry, &registry_key, [0x65; 32], b"1.0.0", manifest);
    assert!(resolve(&f, &cap, &manifest));
    assert!(
        !resolve(&f, &cap, &bytes_hash(b"forged execution account")),
        "discovery must reject changed manifest"
    );
    let init = TaskEscrowInit {
        creator: buyer.address().clone(),
        assigned_agent: Some(account.clone()),
        verifier: Some(verifier.address().clone()),
        budget: 2 * TOS,
        deadline: u64::from(f.bc.now()).checked_add(3600).unwrap(),
        review_period: 3600,
        settlement_policy_hash: manifest,
        permission_hash: id,
        attestor_pubkey: Some(attestor.verifying_key().to_bytes()),
        dispute_fallback_agent_bps: TaskEscrowContract::DEFAULT_DISPUTE_FALLBACK_AGENT_BPS,
    };
    let escrow = TaskEscrowContract::calculate_address(-1, &init).unwrap();
    deploy(
        &mut f.bc,
        buyer.address(),
        &escrow,
        TaskEscrowContract::build_state_init(&init).unwrap(),
        3 * TOS,
    );
    let protected = f.bc.get_account(&escrow).unwrap().get_data_hash();
    send(&mut f.bc, outsider.address(), &escrow, TaskEscrowContract::accept(1).unwrap())
        .expect_aborted()
        .expect_exit_code(101);
    assert_eq!(f.bc.get_account(&escrow).unwrap().get_data_hash(), protected);
    signed_call(
        &mut f.bc,
        &account,
        &controller,
        0,
        &escrow,
        TaskEscrowContract::accept(2).unwrap(),
    );
    assert_eq!(task_status(&f.bc, &escrow), 1);
    let result_hash = bytes_hash(b"bounded service result");
    let evidence_hash = bytes_hash(b"bounded service evidence");
    let original = signed_call(
        &mut f.bc,
        &account,
        &controller,
        1,
        &escrow,
        TaskEscrowContract::result(3, result_hash, evidence_hash).unwrap(),
    );
    assert_eq!(task_status(&f.bc, &escrow), 2);
    let subject =
        bytes_hash(format!("{}|{}|{}", escrow, hex::encode(id), hex::encode(manifest)).as_bytes());
    let proof_init = ProofAttestationInit {
        owner: verifier.address().clone(),
        public_key: attestor.verifying_key().to_bytes(),
        subject_hash: subject,
    };
    let proof = ProofAttestationContract::calculate_address(-1, &proof_init).unwrap();
    deploy(
        &mut f.bc,
        verifier.address(),
        &proof,
        ProofAttestationContract::build_state_init(&proof_init).unwrap(),
        TOS,
    );
    let proof_domain =
        ProofAttestationContract::attest_hash_to_sign(42, &proof, 0, 1, &result_hash).unwrap();
    let proof_body = ProofAttestationContract::attest(
        4,
        1,
        result_hash,
        &attestor.sign(&proof_domain).to_bytes(),
    )
    .unwrap();
    send(&mut f.bc, verifier.address(), &proof, proof_body.clone()).expect_success();
    let protected = f.bc.get_account(&proof).unwrap().get_data_hash();
    send(&mut f.bc, verifier.address(), &proof, proof_body).expect_aborted().expect_exit_code(2105);
    assert_eq!(f.bc.get_account(&proof).unwrap().get_data_hash(), protected);
    assert!(verified_attestation(&f.bc, &proof, subject, result_hash));
    assert!(!verified_attestation(&f.bc, &proof, bytes_hash(b"other task"), result_hash));
    assert!(!verified_attestation(&f.bc, &proof, subject, bytes_hash(b"other result")));
    let dispute_hash = bytes_hash(b"buyer dispute");
    if disputed {
        send(
            &mut f.bc,
            buyer.address(),
            &escrow,
            TaskEscrowContract::dispute(5, dispute_hash).unwrap(),
        )
        .expect_success();
        assert_eq!(task_status(&f.bc, &escrow), 7);
    }
    let payout = if disputed { TOS / 2 } else { TOS };
    let digest = if disputed {
        contracts::resolve_domain_hash(42, &escrow, &result_hash, &dispute_hash, payout)
    } else {
        contracts::settle_domain_hash(42, &escrow, &result_hash, payout)
    }
    .unwrap();
    let signature = attestor.sign(&digest).to_bytes();
    let terminal = if disputed {
        TaskEscrowContract::resolve_signed(6, payout, &signature)
    } else {
        TaskEscrowContract::settle_signed(6, payout, &signature)
    }
    .unwrap();
    let wrong_signature = controller.sign(&digest).to_bytes();
    let wrong = if disputed {
        TaskEscrowContract::resolve_signed(6, payout, &wrong_signature)
    } else {
        TaskEscrowContract::settle_signed(6, payout, &wrong_signature)
    }
    .unwrap();
    let payer = if disputed { verifier.address() } else { buyer.address() };
    let protected = f.bc.get_account(&escrow).unwrap().get_data_hash();
    send(&mut f.bc, payer, &escrow, wrong).expect_aborted().expect_exit_code(if disputed {
        131
    } else {
        127
    });
    assert_eq!(f.bc.get_account(&escrow).unwrap().get_data_hash(), protected);
    let paid_before = balance(&f.bc, &account);
    let refund_before = balance(&f.bc, buyer.address());
    // Lose the client-side acknowledgement, retain finalized state, then restore
    // the executor snapshot into a fresh instance and reconcile without sending.
    send(&mut f.bc, payer, &escrow, terminal.clone()).expect_success();
    assert_eq!(task_status(&f.bc, &escrow), 3);
    let paid_after = balance(&f.bc, &account);
    assert!(paid_after > paid_before && paid_after - paid_before <= payout);
    assert!(paid_after - paid_before > payout - TOS / 100);
    assert!(balance(&f.bc, buyer.address()) > refund_before + TOS);
    assert!(balance(&f.bc, &escrow) < TOS / 100);
    let snapshot = f.bc.snapshot();
    let mut restarted = Blockchain::with_global_version(16).unwrap();
    restarted.set_workchain(-1);
    restarted.set_size_limits_config(chain_block::SizeLimitsConfig::default()).unwrap();
    restarted.restore(snapshot);
    assert_eq!(task_status(&restarted, &escrow), 3);
    assert_eq!(balance(&restarted, &account), paid_after);
    let settled = restarted.get_account(&escrow).unwrap().get_data_hash();
    send(&mut restarted, payer, &escrow, terminal).expect_aborted().expect_exit_code(if disputed {
        123
    } else {
        104
    });
    assert_eq!(restarted.get_account(&escrow).unwrap().get_data_hash(), settled);
    assert_eq!(balance(&restarted, &account), paid_after);
    let replay = MessageBuilder::external(&account)
        .body_slice(SliceData::load_cell(original).unwrap())
        .build();
    let error = match restarted.send_message(replay) {
        Ok(_) => panic!("controller replay accepted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("exit code: 1705"), "wrong replay rejection: {error}");
    assert_eq!(task_status(&restarted, &escrow), 3);
    assert_eq!(balance(&restarted, &account), paid_after);
    let revoke = f.build_action(REVOKE_AGENT, 1, 2, 99, Cell::default());
    f.send(submit_body(revoke.clone(), signature_set(&registry_key, &revoke), empty_signatures()))
        .expect_success();
    assert!(!resolve(&f, &cap, &manifest), "revoked owner must invalidate discovery");
}

fn verified_attestation(
    bc: &Blockchain,
    proof: &MsgAddressInt,
    subject: [u8; 32],
    result: [u8; 32],
) -> bool {
    let data = bc.run_get_method(proof, "get_proof_attestation_data", vec![]).unwrap();
    data.expect_success();
    let hash = |bytes: [u8; 32]| {
        tos_vm::stack::integer::IntegerData::from_str_radix(&hex::encode(bytes), 16)
            .unwrap()
            .to_string()
    };
    data.int_at(2) == 0
        && data.int_at(3) == 1
        && data.int_at(5) == 1
        && data.stack[7].as_integer().unwrap().to_string() == hash(subject)
        && data.stack[8].as_integer().unwrap().to_string() == hash(result)
}

#[test]
fn registry_discovery_account_attestation_settlement() {
    journey(false);
}
#[test]
fn registry_discovery_account_attestation_dispute_refund() {
    journey(true);
}
