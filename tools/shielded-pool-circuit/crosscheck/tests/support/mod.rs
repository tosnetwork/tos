/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! One whole withdrawal, proved and sent, with whatever the destination does
//! to it.
//!
//! Both the round-trip test and the dust measurement need the same thing: two
//! deposits, a proved withdrawal of one denomination, a destination that
//! either takes the money or refuses it, and a careful reading of what
//! happened. Two copies of that would drift, and the one that drifts is
//! always the one nobody ran.

use chain_block::{Cell, CommonMsgInfo, MsgAddressInt, Serializable, StateInit};
use shielded_pool_circuit::circuit::{HeldNote, ShieldedTransactionCircuit, TransactionBuilder};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::{groth16, imt, notes, wire};
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};

use shielded_pool_circuit_crosscheck::pool::{
    dec, development_vk_bytes, Pool, DENOMINATION, WITHDRAWAL_FEE,
};
use shielded_pool_circuit_crosscheck::transact::{Anchor, AuthKey, Recipient, Transact};
use shielded_pool_circuit_crosscheck::wire::byte_chain;

const TOS: u64 = 1_000_000_000;
const COMPUTE_FEE: u64 = 3 * TOS;

/// A destination that refuses anything with a body, so the payout it is sent
/// fails in the compute phase and the protocol bounces it. It accepts its own
/// deployment, which carries none.
pub const REFUSER: &str = r#"
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure {
  slice header = in_msg_full.begin_parse();
  int flags = header~load_uint(4);
  if (flags & 1) {
    return ();
  }
  if (in_msg_body.slice_empty?()) {
    return ();
  }
  throw(701);
}
() recv_external(slice in_msg) impure { }
"#;

/// A destination that takes the money, so the payout succeeds and nothing
/// bounces.
pub const ACCEPTER: &str = r#"
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

fn payload(seed: u8) -> Vec<u8> {
    (0..wire::OUTPUT_DATA_BYTES as u32).map(|i| (i as u8) ^ seed).collect()
}

fn deploy_destination(bc: &mut Blockchain, name: &str, source: &str) -> MsgAddressInt {
    // A directory of this call's own. These probes are written from several tests at
    // once, and a shared path is truncated under a concurrent `func` reading it.
    let probe_dir = tempfile::tempdir().expect("a directory for the probe");
    let path = probe_dir.path().join(format!("tos_shielded_round_trip_{name}.fc"));
    std::fs::write(&path, source).expect("write the destination");
    let stdlib = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../crypto/smartcont/stdlib.fc");
    let code = compile_func(&[stdlib, path]).expect("compile the destination");
    let si = StateInit::with_code_and_data(code, Cell::default());
    let hash = si.write_to_new_cell().unwrap().into_cell().unwrap().hash(0);
    let addr = MsgAddressInt::with_params(0, hash).unwrap();
    let payer = bc.treasury(name, 1_000 * TOS).expect("treasury");
    bc.send_message(
        MessageBuilder::internal(payer.address(), &addr, 100 * TOS)
            .bounce(false)
            .state_init(si)
            .body(Cell::default())
            .build(),
    )
    .expect("deploy the destination")
    .expect_success();
    addr
}

fn account_of(addr: &MsgAddressInt) -> [u8; 32] {
    let bytes = addr.address().get_bytestring(0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// One note the pool minted, with everything the prover needs to spend it.
struct Held {
    key: AuthKey,
    owner_nf_key: Fr,
    note_secret: Fr,
    data_hash: Fr,
    leaf_index: u64,
}

/// What a withdrawal left behind.
pub struct Outcome {
    pub pool_liability_before: u128,
    pub pool_liability_after: u128,
    pub commitment_next_index: String,
    pub nullifier_next_index: String,
    pub refused_at: Option<String>,
    pub bounced_from: Option<String>,
    pub destination: String,
    pub transactions: usize,
    /// How many messages the pool's own transaction sent.
    ///
    /// The positive control for the assertion a private transfer carries: a
    /// transfer must send nothing, and a claim that something counts zero is
    /// worth nothing until the same counter has been seen to count one.
    pub sent_by_the_pool: usize,
    /// What the transact itself cost, payout included.
    /// The transact's own exit code.
    pub exit: i32,
    /// The whole transact message body, in bytes, counting every cell in the
    /// tree. This is what the chain stores forever, and it is the
    /// denominator any proof-size comparison has to be read against.
    pub body_bytes: usize,
    /// Every persistent field, immediately before and after the transact.
    pub state_before: shielded_pool_circuit_crosscheck::pool::PoolState,
    pub state_after: shielded_pool_circuit_crosscheck::pool::PoolState,
    /// The transact's action-phase result code, if the phase ran, and
    /// whether the transaction was rolled back.
    pub action: Option<i32>,
    /// Which action in the list failed, counting from zero.
    pub failed_action: Option<i32>,
    pub aborted: bool,
    pub gas: i64,
    /// What the recovery cost, which is a transaction of its own. Zero when
    /// nothing bounced.
    pub recovery_gas: i64,
    pub recovery_exit: i32,
    /// The value the bounce actually carried back.
    pub bounced_value: u128,
    /// What the pool quotes for putting it back, section 15.4's
    /// `recovery_charge`, read from the same pool that ran the recovery and
    /// at the prices it ran under. The minted note is the two subtracted.
    pub recovery_charge: u128,
    pub holds: u128,
    pub reserve: u128,
}

/// What the withdrawal is for.
pub struct Withdrawal<'a> {
    /// The configured denominations, ascending. `amount` must be one of them.
    pub denominations: &'a [u64],
    pub amount: u64,
    pub destination_name: &'a str,
    pub destination_source: &'a str,
    /// The leaf index and anchor-ring occupancy the pool is moved to after
    /// its deposits and before the withdrawal, or `None` to leave the pool as
    /// freshly deployed.
    ///
    /// None of the eighteen public inputs mentions a leaf index -- the proof
    /// commits to note *bodies* and the contract pairs each with the index it
    /// assigns -- so moving the index does not invalidate the proof, and the
    /// anchor is the current root, which is left alone.
    pub age: Option<Age>,
    /// What to change about the world just before the transact is sent.
    ///
    /// Gate 11's remaining failures are not reachable by sending a different
    /// message: they are the chain granting less gas than the path needs, the
    /// pool holding less than the action phase will spend, and a state limit
    /// below what the compute phase produced. All three are outside the
    /// contract, which is the point -- a test that reached them by editing
    /// the contract would be testing the edit.
    pub before_transact: Perturbation,
}

/// Changes to the world around the pool, applied after its deposits and
/// before the transact.
#[derive(Default, Clone, Copy)]
pub struct Perturbation {
    /// Lower the gas this workchain grants one transaction.
    pub gas_limit: Option<u64>,
    /// Set the pool's balance, so that the transact's own value brings it to
    /// where the test wants it when the compute phase reads it.
    pub balance: Option<u64>,
    /// Send this much with the transact rather than the usual four fees.
    pub value: Option<u64>,
}

/// Where a pool is in its life: how many leaves it has taken, and how full
/// the two anchor rings are.
#[derive(Clone, Copy)]
pub struct Age {
    pub index: u64,
    pub recent: u64,
    pub epoch: u64,
}

/// Two deposits, then one proved withdrawal of `amount` to the destination.
pub fn run(withdrawal: &Withdrawal) -> Outcome {
    let mut frontier = shielded_pool_circuit::tree::Frontier::new();
    let nullifiers = imt::State::genesis();
    let mut pool =
        Pool::deploy_with_denominations(withdrawal.denominations).expect("deploy the pool");
    let destination = deploy_destination(
        &mut pool.bc,
        withdrawal.destination_name,
        withdrawal.destination_source,
    );

    let global_id = {
        let probe = shielded_pool_circuit_crosscheck::wire::WireProbe::deploy()
            .expect("deploy the wire probe");
        probe.domain_inputs().expect("the domain inputs").0
    };
    let domain = wire::execution_domain(global_id, &pool.account().expect("the pool's account"));

    // --- two notes, because a withdrawal has to cover its own fee ---------
    //
    // The denomination list holds one value, so two deposits are how the pool
    // comes to hold more than one of them. A withdrawal of one denomination
    // plus the configured fee cannot come out of a single note.
    let mut held = Vec::new();
    let mut root = frontier.empty_root();
    for (slot, seed) in [0x31u8, 0x32].into_iter().enumerate() {
        let key = AuthKey::generate().expect("an ML-DSA key");
        let owner_nf_key = Fr::from(0x1000_0000u64 + slot as u64);
        let note_secret = Fr::from(0x2000_0000u64 + slot as u64);
        let bytes = payload(seed);
        let data_hash = wire::output_data_hash(&bytes);
        let owner = notes::owner_commitment(
            notes::owner_nf_key_hash(owner_nf_key),
            key.hash(),
            note_secret,
        );
        pool.send(
            DENOMINATION + COMPUTE_FEE,
            Pool::deposit_body(DENOMINATION, owner, byte_chain(&bytes).expect("payload"))
                .expect("deposit body"),
        )
        .expect("deposit")
        .expect_success();

        let body =
            notes::note_body_commitment(owner, Fr::from(u128::from(DENOMINATION)), data_hash);
        let leaf_index = slot as u64;
        let leaf = notes::note_commitment(body, Fr::from(leaf_index));
        let (assigned, new_root) = frontier.append(leaf).expect("append");
        assert_eq!(assigned, leaf_index, "the contract assigned another index");
        held.push(Held { key, owner_nf_key, note_secret, data_hash, leaf_index });
        root = new_root;
    }
    assert_eq!(
        pool.get("commitment_root").expect("commitment root"),
        dec(root),
        "the prover's tree and the contract's disagree after two deposits"
    );

    // --- the withdrawal ---------------------------------------------------
    //
    // Two notes in, one denomination out to the refuser, the configured fee
    // leaving with it, and the change staying inside as three output notes.
    let change =
        u128::from(DENOMINATION) * 2 - u128::from(withdrawal.amount) - u128::from(WITHDRAWAL_FEE);
    let recipient_account = account_of(&destination);
    let recipient_hash = wire::public_recipient_hash(&recipient_account);

    let recovery_owner_commitment = Fr::from(0x5eedu64);
    let recovery_payload = payload(0x77);
    let recovery_template_hash = wire::recovery_template_hash(
        recovery_owner_commitment,
        wire::output_data_hash(&recovery_payload),
    );

    let now: u32 = pool.bc.now().try_into().expect("a unix time");
    let valid_until = now + 600;
    let output_payloads = [payload(1), payload(2), payload(3)];
    let output_data_hash = [
        wire::output_data_hash(&output_payloads[0]),
        wire::output_data_hash(&output_payloads[1]),
        wire::output_data_hash(&output_payloads[2]),
    ];

    let mut scenario = shielded_pool_circuit::scenario::Pool::new();
    let outputs = [
        scenario.real_output(Fr::from(change / 2)),
        scenario.real_output(Fr::from(change - change / 2)),
        scenario.dummy_output(),
    ];

    let inputs = |index: usize| HeldNote {
        is_phantom: false,
        owner_nf_key: held[index].owner_nf_key,
        note_secret: held[index].note_secret,
        amount: Fr::from(u128::from(DENOMINATION)),
        output_data_hash: held[index].data_hash,
        leaf_index: held[index].leaf_index,
    };

    let builder = TransactionBuilder {
        execution_domain: domain,
        valid_until,
        intent_nonce: Fr::from(0xfeed_face_u64),
        public_amount_out: Fr::from(u128::from(withdrawal.amount)),
        withdrawal_fee: Fr::from(u128::from(WITHDRAWAL_FEE)),
        public_recipient_hash: recipient_hash,
        recovery_template_hash,
        is_withdrawal: None,
        input_pq_auth_key_hash: [held[0].key.hash(), held[1].key.hash()],
        outputs,
        output_data_hash,
    };
    let (public, witness) =
        builder.build(&frontier, root, [inputs(0), inputs(1)]).expect("build the withdrawal");

    let keys = groth16::development_keys(ShieldedTransactionCircuit::blank(public))
        .expect("development keys");
    assert_eq!(
        groth16::canonical_verifying_key(&keys.verifying).expect("vk bytes").bytes,
        development_vk_bytes().expect("the fixture verifying key"),
        "the prover's verifying key is not the one the pool was deployed with"
    );
    let proof =
        groth16::prove(&keys, ShieldedTransactionCircuit::new(public, witness), 3).expect("prove");
    let canonical = groth16::CanonicalProof::from_proof(&proof).expect("canonical proof");

    let digest = public.transaction_intent_digest;
    let signatures = [
        held[0].key.sign(digest).expect("a signature"),
        held[1].key.sign(digest).expect("a signature"),
    ];

    let mut tree = nullifiers.clone();
    let (witness_0, after_first) = tree.witness_for(&public.nullifier_0).expect("first witness");
    tree.apply(after_first);
    let (witness_1, _) = tree.witness_for(&public.nullifier_1).expect("second witness");

    let body = Transact {
        public: &public,
        proof: &canonical,
        anchor_root: root,
        anchor: Anchor::Current,
        valid_until,
        output_payloads: &output_payloads,
        keys: [&held[0].key.public, &held[1].key.public],
        signatures: &signatures,
        witnesses: &[witness_0, witness_1],
        public_amount_out: withdrawal.amount,
        withdrawal_fee: WITHDRAWAL_FEE,
        recipient: Some(Recipient(recipient_account)),
        recovery_owner_commitment,
        recovery_payload: Some(recovery_payload),
    }
    .body()
    .expect("a transact body");

    // --- the whole cascade, in one message -------------------------------
    let liability_before: u128 =
        pool.get("native_liability").expect("liability").parse().expect("a number");
    assert_eq!(
        liability_before,
        u128::from(DENOMINATION) * 2,
        "two deposits did not leave the pool owing two denominations"
    );

    let perturb = withdrawal.before_transact;
    if let Some(age) = withdrawal.age {
        let frontier_store = shielded_pool_circuit_crosscheck::frontier_probe::FrontierProbe::deploy()
            .expect("frontier probe")
            .fill(age.index)
            .expect("a frontier");
        let anchors = shielded_pool_circuit_crosscheck::anchor_probe::AnchorProbe::deploy()
            .expect("anchor probe")
            .fill(age.recent, age.epoch)
            .expect("anchor rings");
        pool.age_to(age.index, frontier_store, anchors).expect("age the pool");
    }

    // Every cell of the body, counted once.
    fn weigh(cell: &Cell, seen: &mut std::collections::HashSet<[u8; 32]>) -> usize {
        let id: [u8; 32] = cell.repr_hash().inner();
        if !seen.insert(id) {
            return 0;
        }
        let mut total = cell.bit_length().div_ceil(8);
        for index in 0..cell.references_count() {
            if let Ok(child) = cell.reference(index) {
                total += weigh(&child, seen);
            }
        }
        total
    }
    let body_bytes = weigh(&body, &mut std::collections::HashSet::new());
    fn count(cell: &Cell, seen: &mut std::collections::HashSet<[u8; 32]>) -> usize {
        let id: [u8; 32] = cell.repr_hash().inner();
        if !seen.insert(id) {
            return 0;
        }
        let mut total = 1;
        for index in 0..cell.references_count() {
            if let Ok(child) = cell.reference(index) {
                total += count(&child, seen);
            }
        }
        total
    }
    let body_cells = count(&body, &mut std::collections::HashSet::new());
    eprintln!("transact body: {body_bytes} bytes in {body_cells} cells");

    if let Some(limit) = perturb.gas_limit {
        pool.bc.set_workchain_gas_limit(limit);
    }
    if let Some(balance) = perturb.balance {
        pool.set_balance(balance).expect("set the pool's balance");
    }
    let state_before = pool.state_snapshot().expect("the state before");
    let result =
        pool.send(perturb.value.unwrap_or(COMPUTE_FEE * 4), body).expect("the withdrawal");

    // The transact itself succeeded.
    let description = result.read_primary_description();
    let action = description.action.as_ref().map(|phase| phase.result_code);
    let failed_action = description.action.as_ref().and_then(|phase| phase.result_arg);
    let aborted = description.aborted;
    let (exit, gas) = match description.compute_ph {
        chain_block::TrComputePhase::Vm(vm) => {
            (vm.exit_code, vm.gas_used.to_string().parse::<i64>().expect("gas used"))
        }
        chain_block::TrComputePhase::Skipped(s) => panic!("compute skipped: {:?}", s.reason),
    };
    let perturbed =
        perturb.gas_limit.is_some() || perturb.balance.is_some() || perturb.value.is_some();
    assert!(
        exit == 0 || withdrawal.age.is_some() || perturbed,
        "the withdrawal was refused with exit {exit}"
    );

    // At least the relay's message into the pool and the pool's payout out of
    // it. Whether a third follows is what the two tests below differ on.
    assert!(
        result.transaction_count() >= 2 || withdrawal.age.is_some() || perturbed,
        "the pool sent no payout at all: {} transactions",
        result.transaction_count()
    );
    let transactions = result.transaction_count();
    let sent_by_the_pool = result
        .first_transaction()
        .expect("the pool ran")
        .out_msgs
        .len()
        .expect("counting what the pool sent");
    let mut refused_at = None;
    let mut bounced_from = None;
    let mut recovery_gas = 0i64;
    let mut bounced_value = 0u128;
    let mut recovery_exit = 0i32;
    for (addr, tx) in &result.transactions {
        if let Ok(Some(msg)) = tx.read_in_msg() {
            if let CommonMsgInfo::IntMsgInfo(info) = msg.header() {
                if info.bounced {
                    bounced_from = info.src_ref().map(std::string::ToString::to_string);
                    bounced_value = info.value.coins.as_u128();
                    if let Ok(chain_block::TransactionDescr::Ordinary(d)) = tx.read_description() {
                        if let chain_block::TrComputePhase::Vm(vm) = &d.compute_ph {
                            recovery_gas =
                                vm.gas_used.to_string().parse::<i64>().unwrap_or_default();
                            recovery_exit = vm.exit_code;
                        }
                    }
                }
            }
        }
        if let Ok(chain_block::TransactionDescr::Ordinary(d)) = tx.read_description() {
            if let chain_block::TrComputePhase::Vm(vm) = &d.compute_ph {
                if vm.exit_code == 701 {
                    refused_at = Some(addr.to_string());
                }
            }
        }
    }

    let liability_after: u128 =
        pool.get("native_liability").expect("liability").parse().expect("a number");
    let balance = pool.bc.get_account(&pool.addr).expect("the pool account");
    Outcome {
        sent_by_the_pool,
        pool_liability_before: liability_before,
        pool_liability_after: liability_after,
        commitment_next_index: pool.get("commitment_next_index").expect("next index"),
        nullifier_next_index: pool.get("nullifier_next_index").expect("nullifier next index"),
        refused_at,
        bounced_from,
        destination: destination.to_string(),
        transactions,
        exit,
        body_bytes,
        action,
        failed_action,
        aborted,
        state_before,
        state_after: pool.state_snapshot().expect("the state after"),
        gas,
        recovery_gas,
        recovery_exit,
        bounced_value,
        recovery_charge: pool
            .get("recovery_charge")
            .expect("the quoted recovery charge")
            .parse()
            .expect("a number"),
        holds: balance.balance().map(|value| value.coins.as_u128()).expect("a balance"),
        reserve: pool.get("reserve_floor").expect("reserve floor").parse().expect("a number"),
    }
}
