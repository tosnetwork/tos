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
#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::panic,
        reason = "Fixture setup failures and unexpected execution phases must fail the integration test"
    )
)]

use ark_ff::AdditiveGroup;
use chain_block::{Cell, CommonMsgInfo, MsgAddressInt, Serializable, StateInit};
use shielded_pool_circuit::circuit::{
    HeldNote, ShieldedTransactionCircuit, TransactionBuilder, TransactionWitness,
};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::public_inputs::PublicInputs;
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

pub fn deploy_destination(bc: &mut Blockchain, name: &str, source: &str) -> MsgAddressInt {
    // A directory of this call's own. These probes are written from several tests at
    // once, and a shared path is truncated under a concurrent `func` reading it.
    let probe_dir = tempfile::tempdir().expect("a directory for the probe");
    let path = probe_dir.path().join(format!("tos_shielded_round_trip_{name}.fc"));
    std::fs::write(&path, source).expect("write the destination");
    let stdlib = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../crypto/smartcont/stdlib.fc");
    let code = compile_func(&[stdlib, path]).expect("compile the destination");
    let si = StateInit::with_code_and_data(code, Cell::default());
    let hash = si
        .write_to_new_cell()
        .expect("destination state init")
        .into_cell()
        .expect("destination state cell")
        .hash(0);
    let addr = MsgAddressInt::with_params(0, hash).expect("destination address");
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
pub struct Held {
    key: AuthKey,
    owner_nf_key: Fr,
    note_secret: Fr,
    data_hash: Fr,
    leaf_index: u64,
}

/// What a withdrawal left behind.
pub struct RespendOutcome {
    pub recovered_amount: u128,
    pub liability_before: u128,
    pub liability_after: u128,
    pub commitment_next_index: String,
    pub nullifier_next_index: String,
    pub gas: i64,
    pub replay_exit: i32,
}

pub struct Outcome {
    pub respend: Option<RespendOutcome>,
    pub pool_liability_before: u128,
    pub pool_liability_after: u128,
    pub commitment_next_index: String,
    /// Recovery leaves the pool still holds back once the cascade is over:
    /// one per withdrawal whose payout never came back.
    pub reserved_recovery_leaves: String,
    pub nullifier_next_index: String,
    pub refused_at: Option<String>,
    pub bounced_from: Option<String>,
    pub destination: String,
    pub payout_value: Option<u128>,
    pub recipient_credit: Option<u128>,
    pub recipient_success: Option<bool>,
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
    let pool = Pool::deploy_with_denominations(withdrawal.denominations).expect("deploy the pool");
    let domain = execution_domain(&pool);
    run_with_pool(withdrawal, pool, domain, development_proof)
}

/// Run the same withdrawal cascade against an exact candidate and external prover.
/// The caller binds the candidate, chain configuration and proving key beforehand.
pub fn run_with_pool(
    withdrawal: &Withdrawal,
    pool: Pool,
    domain: Fr,
    prove: impl FnMut(PublicInputs, TransactionWitness, u32) -> groth16::CanonicalProof,
) -> Outcome {
    run_with_pool_mode(withdrawal, pool, domain, prove, false)
}

/// Recover to an owner whose synthetic keys are known, then spend that actual note.
pub fn run_with_pool_and_respend(
    withdrawal: &Withdrawal,
    pool: Pool,
    domain: Fr,
    prove: impl FnMut(PublicInputs, TransactionWitness, u32) -> groth16::CanonicalProof,
) -> Outcome {
    run_with_pool_mode(withdrawal, pool, domain, prove, true)
}

fn run_with_pool_mode(
    withdrawal: &Withdrawal,
    mut pool: Pool,
    domain: Fr,
    mut prove: impl FnMut(PublicInputs, TransactionWitness, u32) -> groth16::CanonicalProof,
    spend_recovery: bool,
) -> Outcome {
    let mut frontier = shielded_pool_circuit::tree::Frontier::new();
    let nullifiers = imt::State::genesis();
    let destination = deploy_destination(
        &mut pool.bc,
        withdrawal.destination_name,
        withdrawal.destination_source,
    );

    // --- two notes, because a withdrawal has to cover its own fee ---------
    //
    // The denomination list holds one value, so two deposits are how the pool
    // comes to hold more than one of them. A withdrawal of one denomination
    // plus the configured fee cannot come out of a single note.
    let (held, root) = deposit_notes(&mut pool, &mut frontier, &[0x31, 0x32]);

    // --- the withdrawal ---------------------------------------------------
    let mut tree = nullifiers.clone();
    let recovery = spend_recovery.then(|| Held {
        key: AuthKey::generate().expect("synthetic recovery signing key"),
        owner_nf_key: Fr::from(0x7eedu64),
        note_secret: Fr::from(0x8eedu64),
        data_hash: wire::output_data_hash(&payload(0x77)),
        leaf_index: 0,
    });
    let recovery_owner = recovery
        .as_ref()
        .map(|note| {
            notes::owner_commitment(
                notes::owner_nf_key_hash(note.owner_nf_key),
                note.key.hash(),
                note.note_secret,
            )
        })
        .unwrap_or_else(|| Fr::from(0x5eedu64));
    let (body, withdrawal_public) = prove_withdrawal_with(
        ProvedWithdrawal {
            pool: &pool,
            domain,
            frontier: &frontier,
            root,
            anchor: Anchor::Current,
            inputs: [&held[0], &held[1]],
            amount: withdrawal.amount,
            recipient: &destination,
            intent_nonce: 0xfeed_face,
            recovery_owner_commitment: recovery_owner,
            nullifiers: &mut tree,
        },
        &mut prove,
    );

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
        let frontier_store =
            shielded_pool_circuit_crosscheck::frontier_probe::FrontierProbe::deploy()
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
    let result = pool.send(perturb.value.unwrap_or(COMPUTE_FEE * 4), body).expect("the withdrawal");

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
    let mut payout_value = None;
    let mut recipient_credit = None;
    let mut recipient_success = None;
    let mut refused_at = None;
    let mut bounced_from = None;
    let mut recovery_gas = 0i64;
    let mut bounced_value = 0u128;
    let mut recovery_exit = 0i32;
    for (addr, tx) in &result.transactions {
        if addr == &destination {
            if let Ok(Some(msg)) = tx.read_in_msg() {
                if let CommonMsgInfo::IntMsgInfo(info) = msg.header() {
                    if info.src_ref() == Some(&pool.addr) {
                        payout_value = Some(info.value.coins.as_u128());
                    }
                }
            }
            if let Ok(chain_block::TransactionDescr::Ordinary(d)) = tx.read_description() {
                recipient_credit = d.credit_ph.as_ref().map(|phase| phase.credit.coins.as_u128());
                recipient_success = Some(
                    !d.aborted
                        && matches!(&d.compute_ph, chain_block::TrComputePhase::Vm(vm) if vm.success && vm.exit_code == 0)
                        && d.action.as_ref().is_none_or(|a| {
                            a.valid && a.success && !a.no_funds && a.result_code == 0
                        }),
                );
            }
        }
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
    let mut outcome = Outcome {
        respend: None,
        sent_by_the_pool,
        pool_liability_before: liability_before,
        pool_liability_after: liability_after,
        commitment_next_index: pool.get("commitment_next_index").expect("next index"),
        reserved_recovery_leaves: pool
            .get("reserved_recovery_leaves")
            .expect("the reserved recovery leaves"),
        nullifier_next_index: pool.get("nullifier_next_index").expect("nullifier next index"),
        refused_at,
        bounced_from,
        destination: destination.to_string(),
        payout_value,
        recipient_credit,
        recipient_success,
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
    };
    if let Some(recovery) = recovery {
        assert_eq!(outcome.recovery_exit, 0);
        assert_eq!(outcome.bounced_from.as_deref(), Some(outcome.destination.as_str()));
        outcome.respend = Some(respend_recovery(
            &mut pool,
            RecoverySpend {
                frontier,
                tree,
                withdrawal: withdrawal_public,
                recovered: recovery,
                domain,
                compute_credit: withdrawal.before_transact.value.unwrap_or(COMPUTE_FEE * 4),
            },
            &outcome,
            &mut prove,
        ));
    }
    outcome
}

/// The execution domain of section 8 for this pool, on this chain.
pub fn execution_domain(pool: &Pool) -> Fr {
    let global_id = {
        let probe = shielded_pool_circuit_crosscheck::wire::WireProbe::deploy()
            .expect("deploy the wire probe");
        probe.domain_inputs().expect("the domain inputs").0
    };
    wire::execution_domain(global_id, &pool.account().expect("the pool's account"))
}

/// One deposit of one denomination per seed, each checked against the
/// prover's own tree. Returns the notes and the root they leave.
pub fn deposit_notes(
    pool: &mut Pool,
    frontier: &mut shielded_pool_circuit::tree::Frontier,
    seeds: &[u8],
) -> (Vec<Held>, Fr) {
    let mut held = Vec::new();
    let mut root = frontier.empty_root();
    for seed in seeds {
        let key = AuthKey::generate().expect("an ML-DSA key");
        let owner_nf_key = Fr::from(0x1000_0000u64 + u64::from(*seed));
        let note_secret = Fr::from(0x2000_0000u64 + u64::from(*seed));
        let bytes = payload(*seed);
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
        let leaf_index = frontier.next_index();
        let leaf = notes::note_commitment(body, Fr::from(leaf_index));
        let (assigned, new_root) = frontier.append(leaf).expect("append");
        assert_eq!(assigned, leaf_index, "the prover's tree assigned another index");
        held.push(Held { key, owner_nf_key, note_secret, data_hash, leaf_index });
        root = new_root;
    }
    assert_eq!(
        pool.get("commitment_root").expect("commitment root"),
        dec(root),
        "the prover's tree and the contract's disagree after the deposits"
    );
    (held, root)
}

/// Everything one proved withdrawal is built from.
pub struct ProvedWithdrawal<'a> {
    pub pool: &'a Pool,
    pub domain: Fr,
    pub frontier: &'a shielded_pool_circuit::tree::Frontier,
    /// The root the proof is against, and how the pool is to find it.
    pub root: Fr,
    pub anchor: Anchor,
    /// The two notes spent, each worth one denomination.
    pub inputs: [&'a Held; 2],
    pub amount: u64,
    pub recipient: &'a MsgAddressInt,
    pub intent_nonce: u64,
    pub recovery_owner_commitment: Fr,
    /// The nullifier tree as the pool will hold it when this arrives. Both
    /// nullifiers are applied to it, so the next withdrawal's witnesses are
    /// against the tree this one leaves.
    pub nullifiers: &'a mut imt::State,
}

/// Two notes in, `amount` out to the recipient, the configured fee leaving
/// with it, and the change staying inside as three output notes.
pub fn prove_withdrawal(w: ProvedWithdrawal) -> Cell {
    prove_withdrawal_with(w, development_proof).0
}

fn development_proof(
    public: PublicInputs,
    witness: TransactionWitness,
    _now: u32,
) -> groth16::CanonicalProof {
    let keys = groth16::development_keys(ShieldedTransactionCircuit::blank(public))
        .expect("development keys");
    assert_eq!(
        groth16::canonical_verifying_key(&keys.verifying).expect("vk bytes").bytes,
        development_vk_bytes().expect("the fixture verifying key"),
        "the prover's verifying key is not the one the pool was deployed with"
    );
    let proof =
        groth16::prove(&keys, ShieldedTransactionCircuit::new(public, witness), 3).expect("prove");
    groth16::CanonicalProof::from_proof(&proof).expect("canonical proof")
}

fn prove_withdrawal_with(
    w: ProvedWithdrawal,
    mut prove: impl FnMut(PublicInputs, TransactionWitness, u32) -> groth16::CanonicalProof,
) -> (Cell, PublicInputs) {
    let change = u128::from(DENOMINATION) * 2 - u128::from(w.amount) - u128::from(WITHDRAWAL_FEE);
    let recipient_account = account_of(w.recipient);
    let recipient_hash = wire::public_recipient_hash(&recipient_account);

    let recovery_payload = payload(0x77);
    let recovery_template_hash = wire::recovery_template_hash(
        w.recovery_owner_commitment,
        wire::output_data_hash(&recovery_payload),
    );

    let now = w.pool.bc.now();
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

    let input = |note: &Held| HeldNote {
        is_phantom: false,
        owner_nf_key: note.owner_nf_key,
        note_secret: note.note_secret,
        amount: Fr::from(u128::from(DENOMINATION)),
        output_data_hash: note.data_hash,
        leaf_index: note.leaf_index,
    };

    let builder = TransactionBuilder {
        execution_domain: w.domain,
        valid_until,
        intent_nonce: Fr::from(w.intent_nonce),
        public_amount_out: Fr::from(u128::from(w.amount)),
        withdrawal_fee: Fr::from(u128::from(WITHDRAWAL_FEE)),
        public_recipient_hash: recipient_hash,
        recovery_template_hash,
        is_withdrawal: None,
        input_pq_auth_key_hash: [w.inputs[0].key.hash(), w.inputs[1].key.hash()],
        outputs,
        output_data_hash,
    };
    let (public, witness) = builder
        .build(w.frontier, w.root, [input(w.inputs[0]), input(w.inputs[1])])
        .expect("build the withdrawal");

    let canonical = prove(public, witness, w.pool.bc.now());

    let digest = public.transaction_intent_digest;
    let signatures = [
        w.inputs[0].key.sign(digest).expect("a signature"),
        w.inputs[1].key.sign(digest).expect("a signature"),
    ];

    let (witness_0, after_first) =
        w.nullifiers.witness_for(&public.nullifier_0).expect("first witness");
    w.nullifiers.apply(after_first);
    let (witness_1, after_second) =
        w.nullifiers.witness_for(&public.nullifier_1).expect("second witness");
    w.nullifiers.apply(after_second);

    let body = Transact {
        public: &public,
        proof: &canonical,
        anchor_root: w.root,
        anchor: w.anchor,
        valid_until,
        output_payloads: &output_payloads,
        keys: [&w.inputs[0].key.public, &w.inputs[1].key.public],
        signatures: &signatures,
        witnesses: &[witness_0, witness_1],
        public_amount_out: w.amount,
        withdrawal_fee: WITHDRAWAL_FEE,
        recipient: Some(Recipient(recipient_account)),
        recovery_owner_commitment: w.recovery_owner_commitment,
        recovery_payload: Some(recovery_payload),
    }
    .body()
    .expect("a transact body");
    (body, public)
}

/// Witness state and synthetic owner retained from the actual withdrawal cascade.
struct RecoverySpend {
    frontier: shielded_pool_circuit::tree::Frontier,
    tree: imt::State,
    withdrawal: PublicInputs,
    recovered: Held,
    domain: Fr,
    compute_credit: u64,
}

/// Spend the actual bounced recovery leaf, then retry against a still-valid anchor.
/// Every key/witness here belongs to an unfunded synthetic sandbox note.
fn respend_recovery(
    pool: &mut Pool,
    spend: RecoverySpend,
    outcome: &Outcome,
    prove: &mut impl FnMut(PublicInputs, TransactionWitness, u32) -> groth16::CanonicalProof,
) -> RespendOutcome {
    let RecoverySpend { mut frontier, mut tree, withdrawal, mut recovered, domain, compute_credit } =
        spend;
    assert_eq!(outcome.commitment_next_index, "6");
    assert_eq!(outcome.nullifier_next_index, "3");
    assert_eq!(outcome.reserved_recovery_leaves, "0");
    for note in [withdrawal.note_body_0, withdrawal.note_body_1, withdrawal.note_body_2] {
        let leaf = notes::note_commitment(note, Fr::from(frontier.next_index()));
        frontier.append(leaf).expect("withdrawal output frontier");
    }
    let amount = outcome
        .bounced_value
        .checked_sub(outcome.recovery_charge)
        .expect("recovery charge exceeds actual bounce value");
    assert!(amount > 0);
    let owner = notes::owner_commitment(
        notes::owner_nf_key_hash(recovered.owner_nf_key),
        recovered.key.hash(),
        recovered.note_secret,
    );
    let body = notes::note_body_commitment(owner, Fr::from(amount), recovered.data_hash);
    recovered.leaf_index = frontier.next_index();
    assert_eq!(recovered.leaf_index, 5);
    frontier
        .append(notes::note_commitment(body, Fr::from(recovered.leaf_index)))
        .expect("actual recovered note frontier");
    let root = frontier.recomputed_root();
    assert_eq!(
        pool.get("commitment_root").expect("recovered root"),
        dec(root),
        "actual recovery leaf does not match bounce value, charge, owner and payload"
    );
    assert_eq!(pool.get("nullifier_root").expect("withdrawal nullifier root"), dec(tree.root()));
    let version: u32 = frontier.next_index().try_into().expect("recent version");
    let phantom = AuthKey::generate().expect("synthetic phantom signing key");
    let output_payloads = [payload(0x81), payload(0x82), payload(0x83)];
    let output_data_hash = output_payloads.each_ref().map(|bytes| wire::output_data_hash(bytes));
    let mut scenario = shielded_pool_circuit::scenario::Pool::new();
    let outputs = [
        scenario.real_output(Fr::from(amount / 2)),
        scenario.real_output(Fr::from(amount - amount / 2)),
        scenario.dummy_output(),
    ];
    let valid_until = pool.bc.now().checked_add(600).expect("test expiry");
    let (public, witness) = TransactionBuilder {
        execution_domain: domain,
        valid_until,
        intent_nonce: Fr::from(0xfeed_f002u64),
        public_amount_out: Fr::ZERO,
        withdrawal_fee: Fr::ZERO,
        public_recipient_hash: Fr::ZERO,
        recovery_template_hash: Fr::ZERO,
        is_withdrawal: None,
        input_pq_auth_key_hash: [recovered.key.hash(), phantom.hash()],
        outputs,
        output_data_hash,
    }
    .build(
        &frontier,
        root,
        [
            HeldNote {
                is_phantom: false,
                owner_nf_key: recovered.owner_nf_key,
                note_secret: recovered.note_secret,
                amount: Fr::from(amount),
                output_data_hash: recovered.data_hash,
                leaf_index: recovered.leaf_index,
            },
            HeldNote {
                is_phantom: true,
                owner_nf_key: Fr::from(7u64),
                note_secret: Fr::from(9u64),
                amount: Fr::ZERO,
                output_data_hash: Fr::from(11u64),
                leaf_index: 0,
            },
        ],
    )
    .expect("build actual recovery-note spend");
    let canonical = prove(public, witness, pool.bc.now());
    let signatures = [
        recovered.key.sign(public.transaction_intent_digest).expect("recovery signature"),
        phantom.sign(public.transaction_intent_digest).expect("phantom signature"),
    ];
    let (first, after_first) =
        tree.witness_for(&public.nullifier_0).expect("recovery spend first witness");
    tree.apply(after_first);
    let (second, after_second) =
        tree.witness_for(&public.nullifier_1).expect("recovery spend second witness");
    tree.apply(after_second);
    let witnesses = [first, second];
    let encode = |anchor| {
        Transact {
            public: &public,
            proof: &canonical,
            anchor_root: root,
            anchor,
            valid_until,
            output_payloads: &output_payloads,
            keys: [&recovered.key.public, &phantom.public],
            signatures: &signatures,
            witnesses: &witnesses,
            public_amount_out: 0,
            withdrawal_fee: 0,
            recipient: None,
            recovery_owner_commitment: Fr::ZERO,
            recovery_payload: None,
        }
        .body()
        .expect("recovery spend body")
    };
    let body = encode(Anchor::Current);
    let replay_body = encode(Anchor::Recent(version));
    let before = pool.state_snapshot().expect("before recovery spend");
    let liability_before: u128 =
        pool.get("native_liability").expect("before spend liability").parse().expect("coins");
    let result = pool.send(compute_credit, body).expect("send actual recovery-note spend");
    result.expect_success();
    let description = result.read_primary_description();
    assert!(!description.aborted);
    assert!(description.action.as_ref().is_none_or(|a| a.valid
        && a.success
        && !a.no_funds
        && a.result_code == 0
        && a.skipped_actions == 0));
    let gas = match description.compute_ph {
        chain_block::TrComputePhase::Vm(vm) => {
            assert!(vm.success && vm.exit_code == 0);
            vm.gas_used.to_string().parse().expect("spend gas")
        }
        _ => panic!("recovery spend compute skipped"),
    };
    assert_eq!(result.transaction_count(), 1);
    assert_eq!(
        result
            .first_transaction()
            .expect("spend transaction")
            .out_msgs
            .len()
            .expect("output count"),
        0
    );
    for note in [public.note_body_0, public.note_body_1, public.note_body_2] {
        let leaf = notes::note_commitment(note, Fr::from(frontier.next_index()));
        frontier.append(leaf).expect("respend output frontier");
    }
    assert_eq!(
        pool.get("commitment_root").expect("respend root"),
        dec(frontier.recomputed_root()),
        "recovery note was not actually spent"
    );
    assert_eq!(pool.get("nullifier_root").expect("respend nullifier root"), dec(tree.root()));
    let commitment_next_index =
        pool.get("commitment_next_index").expect("respend commitment index");
    let nullifier_next_index = pool.get("nullifier_next_index").expect("respend nullifier index");
    assert_eq!(commitment_next_index, "9");
    assert_eq!(nullifier_next_index, "5");
    assert_ne!(before, pool.state_snapshot().expect("after recovery spend"));
    let liability_after =
        pool.get("native_liability").expect("after spend liability").parse().expect("coins");
    assert_eq!(liability_before, liability_after);
    assert_eq!(liability_after, outcome.pool_liability_after);
    assert_eq!(pool.get("reserved_recovery_leaves").expect("respend reservations"), "0");
    let balance = pool.bc.get_account(&pool.addr).expect("respend pool account");
    assert!(
        balance.balance().expect("respend balance").coins.as_u128()
            >= liability_after + outcome.reserve
    );
    let (recent, _) = pool.anchor_rings().expect("actual recent anchor ring");
    assert!(
        recent.iter().any(|entry| entry.version == u64::from(version)
            && entry.root == shielded_pool_circuit_crosscheck::pool::be(root)),
        "replay anchor is not actually preserved"
    );
    let before_replay = pool.state_snapshot().expect("before repeated spend");
    let replay = pool.send(compute_credit, replay_body).expect("repeat spent recovery note");
    let replay_exit = match replay.read_primary_description().compute_ph {
        chain_block::TrComputePhase::Vm(vm) => vm.exit_code,
        _ => panic!("replay compute skipped"),
    };
    assert_eq!(
        replay_exit, 115,
        "replay must reach the stale nullifier witness with a valid recent anchor"
    );
    assert_eq!(
        before_replay,
        pool.state_snapshot().expect("after repeated spend"),
        "rejected replay changed full persistent data"
    );
    // Refusing an inbound bounceable message returns the unused compute credit.
    // Require the one protocol bounce, never an application payout or a new note.
    let transaction = replay.first_transaction().expect("replay transaction");
    let inbound = transaction.read_in_msg().expect("replay inbound").expect("inbound present");
    let CommonMsgInfo::IntMsgInfo(input) = inbound.header() else {
        panic!("replay input is not internal");
    };
    let sender = input.src_ref().expect("replay sender");
    let mut refunds = 0;
    transaction
        .iterate_out_msgs(|message| {
            let CommonMsgInfo::IntMsgInfo(info) = message.header() else {
                panic!("replay emitted an external message");
            };
            assert!(info.bounced && !info.bounce, "replay emitted an application payout");
            assert_eq!(info.src_ref(), Some(&pool.addr));
            assert_eq!(&info.dst, sender, "refund recipient differs from original sender");
            assert!(info.value.coins.as_u128() <= u128::from(compute_credit));
            refunds += 1;
            Ok(true)
        })
        .expect("replay output decoding");
    assert_eq!(refunds, 1, "rejected replay did not return exactly one protocol refund");
    RespendOutcome {
        recovered_amount: amount,
        liability_before,
        liability_after,
        commitment_next_index,
        nullifier_next_index,
        gas,
        replay_exit,
    }
}
