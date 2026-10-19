/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The bytes a real node needs in order to hold a shielded pool, take two
//! deposits and pay a proved withdrawal out.
//!
//! Every gas figure, every root and every refusal in this project was measured
//! in a sandbox executor. That executor is the same code a validator runs, but
//! running it is not the same as running a chain: nothing measured there has
//! been through block production, a real message queue, real forward fees or a
//! real account balance.
//!
//! This writes the deployment and one whole scenario out so that it can be. It
//! is deliberately not a second implementation of anything: the code comes
//! from `pool_sources()`, the state from
//! `shielded_pool_genesis::development_parameters`, the message bodies from
//! `Pool::deposit_body` and `Transact::body`, and the roots the chain is
//! expected to reach from the circuit's own reference tree -- so every on-chain
//! check is a prediction made before the message is sent, not a read-back.
//! The same scenario is then run in the sandbox, so the two can be compared
//! for identical bytes.
//!
//! Two couplings decide whether a proof made here is valid there, and both are
//! recorded in the fixture rather than assumed:
//!
//!   * **the chain's `global_id`** goes into the execution domain, which is
//!     eight of the eighteen public inputs. A proof built for one chain is
//!     refused by another.
//!   * **`valid_until`** must be within section 9's one-hour intent window of
//!     the moment the transact executes. A fixture is perishable.
//!
//! Usage: `onchain-fixture <repo root> <output directory>`

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ark_ff::AdditiveGroup;
use chain_block::{write_boc, Cell, MsgAddressInt, Serializable, StateInit};
use shielded_pool_circuit::circuit::{HeldNote, ShieldedTransactionCircuit, TransactionBuilder};
use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::wire::{output_data_hash, OUTPUT_DATA_BYTES};
use shielded_pool_circuit::{groth16, imt, notes, scenario, tree, wire};
use shielded_pool_circuit_crosscheck::pool::{
    dec, development_vk_bytes, pool_sources, Pool, DENOMINATION, WITHDRAWAL_FEE,
};
use shielded_pool_circuit_crosscheck::transact::{Anchor, AuthKey, Recipient, Transact};
use shielded_pool_circuit_crosscheck::wire::byte_chain;
use shielded_pool_circuit_crosscheck::{stdlib_path, ACTIVE_VERSION};
use tos_sandbox::{compile_func, Blockchain, MessageBuilder};

/// Section 14.1's ceilings, which are what a sender funds -- not what the path
/// will use.
///
/// Read out of the contract rather than written down here. They were copies
/// until the ceilings were re-derived, and a copy is a number that agrees
/// with itself: this fixture would have gone on funding messages at the old
/// ceiling, the chain would have refused them at exit 203, and nothing in
/// this file would have said why.
fn gas_ceiling(name: &str) -> u64 {
    let value = shielded_pool_circuit_crosscheck::pool::contract_gas_ceiling(name)
        .unwrap_or_else(|error| panic!("the contract's {name}: {error}"));
    u64::try_from(value).unwrap_or_else(|_| panic!("{name} is not a positive gas figure"))
}

/// Section 9's intent window is an hour. Half of it leaves room for a build,
/// a chain to come up and three messages to land.
const INTENT_LIFETIME: u32 = 1_800;

/// This chain's ConfigParam 21, as the VM applies it: a flat 667 for the first
/// hundred gas, then 436,907 per 65,536 gas, the division rounded up.
fn compute_fee(gas: u64) -> u64 {
    const FLAT_LIMIT: u64 = 100;
    const FLAT_PRICE: u64 = 667;
    const GAS_PRICE: u64 = 436_907;
    if gas <= FLAT_LIMIT {
        FLAT_PRICE
    } else {
        FLAT_PRICE + ((gas - FLAT_LIMIT) * GAS_PRICE).div_ceil(65_536)
    }
}

/// A destination that takes the money, so the payout succeeds and nothing
/// bounces.
const ACCEPTER: &str = r#"
() recv_internal(int msg_value, cell in_msg_full, slice in_msg_body) impure { }
() recv_external(slice in_msg) impure { }
"#;

/// A destination that refuses a payout, so the message comes back and the
/// pool has to mint a recovery note for whatever survived the round trip.
///
/// It takes a bounce (flag bit 0) and an empty body, because refusing either
/// of those would be refusing the pool's own money coming home.
const REFUSER: &str = r#"
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

/// The owners this fixture deposits to. Fixed, so that two runs differ only
/// in the one thing that cannot be fixed: the ML-DSA keys, which have no
/// deterministic constructor here.
const OWNER_NF_KEY: [u64; 2] = [0x5348_5f4f_574e_4530, 0x5348_5f4f_574e_4531];
const NOTE_SECRET: [u64; 2] = [0x5348_5f53_4543_5230, 0x5348_5f53_4543_5231];
const PAYLOAD_SEED: [u8; 2] = [0x31, 0x32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn payload(seed: u8) -> Vec<u8> {
    (0..OUTPUT_DATA_BYTES as u32).map(|index| (index as u8) ^ seed).collect()
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(path, bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    eprintln!("wrote {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

fn write_cell(path: &Path, cell: &Cell) -> Result<(), Box<dyn std::error::Error>> {
    write(path, &write_boc(cell)?)
}

fn account_of(address: &MsgAddressInt) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = address.address().get_bytestring(0);
    if bytes.len() != 32 {
        return Err("an account id that is not 32 bytes".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn address_of(code: &Cell, data: &Cell) -> Result<MsgAddressInt, Box<dyn std::error::Error>> {
    let init = StateInit::with_code_and_data(code.clone(), data.clone());
    let hash = init.write_to_new_cell().and_then(|builder| builder.into_cell())?.hash(0);
    Ok(MsgAddressInt::with_params(0, hash)?)
}

/// One note the pool will mint, with everything the prover needs to spend it.
struct Note {
    key: AuthKey,
    owner_nf_key: Fr,
    note_secret: Fr,
    payload: Vec<u8>,
    data_hash: Fr,
    owner: Fr,
    leaf_index: u64,
}

impl Note {
    fn new(slot: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let key = AuthKey::generate()?;
        let owner_nf_key = Fr::from(OWNER_NF_KEY[slot]);
        let note_secret = Fr::from(NOTE_SECRET[slot]);
        let payload = payload(PAYLOAD_SEED[slot]);
        let data_hash = output_data_hash(&payload);
        let owner = notes::owner_commitment(
            notes::owner_nf_key_hash(owner_nf_key),
            key.hash(),
            note_secret,
        );
        Ok(Self {
            key,
            owner_nf_key,
            note_secret,
            payload,
            data_hash,
            owner,
            leaf_index: slot as u64,
        })
    }

    fn deposit_body(&self) -> Result<Cell, Box<dyn std::error::Error>> {
        Ok(Pool::deposit_body(DENOMINATION, self.owner, byte_chain(&self.payload)?)?)
    }

    /// The leaf the contract will commit for this note at its index.
    fn leaf(&self) -> Fr {
        let body =
            notes::note_body_commitment(self.owner, Fr::from(u128::from(DENOMINATION)), self.data_hash);
        notes::note_commitment(body, Fr::from(self.leaf_index))
    }

    fn held(&self) -> HeldNote {
        HeldNote {
            is_phantom: false,
            owner_nf_key: self.owner_nf_key,
            note_secret: self.note_secret,
            amount: Fr::from(u128::from(DENOMINATION)),
            output_data_hash: self.data_hash,
            leaf_index: self.leaf_index,
        }
    }
}

/// The three message bodies, and what each one must leave behind.
struct Scenario {
    deposits: [Cell; 2],
    roots_after_deposit: [Fr; 2],
    transact: Cell,
    nullifier_root_after: Fr,
    commitment_root_after: Fr,
    valid_until: u32,
    payout: u64,
    /// Everything needed to predict the recovery note, except the one number
    /// the chain decides: how much of the payout survived the round trip.
    /// Section 15.4 mints a note for what the bounce delivers *less the
    /// pool's charge for putting it back*, and the delivered part depends on
    /// forward fees no prover can know in advance.
    recovery: Recovery,
}

/// The recovery note's inputs, and the tree it lands in.
struct Recovery {
    owner_commitment: Fr,
    output_data_hash: Fr,
    leaf_index: u64,
    /// Every leaf the tree holds when the bounce arrives, in order, so the
    /// root can be recomputed once the recovered amount is known.
    leaves: Vec<Fr>,
}

#[allow(clippy::too_many_arguments)]
fn build_scenario(
    global_id: i32,
    pool_account: &[u8; 32],
    destination_account: &[u8; 32],
    the_notes: &[Note; 2],
    valid_until: u32,
    // A transfer pays nobody. It is the one money path never put on a chain:
    // the same handler takes a cheaper branch, which is an argument and not a
    // run. Everything below that concerns a recipient is switched off by it,
    // and the change keeps the whole input instead of what a payout left.
    transfer: bool,
) -> Result<Scenario, Box<dyn std::error::Error>> {
    let domain = wire::execution_domain(global_id, pool_account);

    // The tree, as the contract will build it: two deposits, in order.
    let mut frontier = tree::Frontier::new();
    let mut roots_after_deposit = [Fr::ZERO; 2];
    for (slot, note) in the_notes.iter().enumerate() {
        let (assigned, root) = frontier.append(note.leaf())?;
        if assigned != note.leaf_index {
            return Err("the reference tree assigned another index".into());
        }
        roots_after_deposit[slot] = root;
    }
    let anchor_root = roots_after_deposit[1];

    // Two notes in. On a withdrawal one denomination leaves for the
    // destination with the configured fee beside it, and the change stays
    // inside as three output notes. On a transfer nothing leaves at all, so
    // the change is the whole of what came in -- which is exactly the
    // property a transfer has to have and a withdrawal must not.
    let public_amount_out = if transfer { 0 } else { DENOMINATION };
    let withdrawal_fee = if transfer { 0 } else { WITHDRAWAL_FEE };
    let change =
        u128::from(DENOMINATION) * 2 - u128::from(public_amount_out) - u128::from(withdrawal_fee);
    // A transfer names no recipient, so it commits to no recovery template
    // either: there is no payout that could come back to be recovered.
    let recovery_owner_commitment = if transfer { Fr::ZERO } else { Fr::from(0x5eedu64) };
    let recovery_payload = payload(0x77);
    let recovery_data_hash = output_data_hash(&recovery_payload);
    let output_payloads = [payload(1), payload(2), payload(3)];
    let output_data_hashes = [
        output_data_hash(&output_payloads[0]),
        output_data_hash(&output_payloads[1]),
        output_data_hash(&output_payloads[2]),
    ];

    let mut outputs_of = scenario::Pool::new();
    let outputs = [
        outputs_of.real_output(Fr::from(change / 2)),
        outputs_of.real_output(Fr::from(change - change / 2)),
        outputs_of.dummy_output(),
    ];

    let builder = TransactionBuilder {
        execution_domain: domain,
        valid_until,
        intent_nonce: Fr::from(0xfeed_face_u64),
        public_amount_out: Fr::from(u128::from(public_amount_out)),
        withdrawal_fee: Fr::from(u128::from(withdrawal_fee)),
        public_recipient_hash: if transfer {
            Fr::ZERO
        } else {
            wire::public_recipient_hash(destination_account)
        },
        recovery_template_hash: if transfer {
            Fr::ZERO
        } else {
            wire::recovery_template_hash(recovery_owner_commitment, recovery_data_hash)
        },
        is_withdrawal: None,
        input_pq_auth_key_hash: [the_notes[0].key.hash(), the_notes[1].key.hash()],
        outputs,
        output_data_hash: output_data_hashes,
    };
    let (public, witness) = builder.build(
        &frontier,
        anchor_root,
        [the_notes[0].held(), the_notes[1].held()],
    )?;

    // The development keys. The pool was deployed with this verifying key's
    // hash inside its configuration, so a prover holding any other key
    // produces a proof the contract refuses -- checked here rather than
    // discovered on the chain.
    let keys = groth16::development_keys(ShieldedTransactionCircuit::blank(public))?;
    if groth16::canonical_verifying_key(&keys.verifying)?.bytes != development_vk_bytes()? {
        return Err("the prover's verifying key is not the one the pool was deployed with".into());
    }
    let proof = groth16::prove(&keys, ShieldedTransactionCircuit::new(public, witness), 3)?;
    let canonical = groth16::CanonicalProof::from_proof(&proof)?;

    let digest = public.transaction_intent_digest;
    let signatures = [the_notes[0].key.sign(digest)?, the_notes[1].key.sign(digest)?];

    // The two nullifier insertions, in the order the contract will do them:
    // the second witness is against the tree the first one left.
    let mut tree_state = imt::State::genesis();
    let (witness_0, after_first) = tree_state.witness_for(&public.nullifier_0)?;
    tree_state.apply(after_first);
    let (witness_1, after_second) = tree_state.witness_for(&public.nullifier_1)?;
    tree_state.apply(after_second);

    let transact = Transact {
        public: &public,
        proof: &canonical,
        anchor_root,
        anchor: Anchor::Current,
        valid_until,
        output_payloads: &output_payloads,
        keys: [&the_notes[0].key.public, &the_notes[1].key.public],
        signatures: &signatures,
        witnesses: &[witness_0, witness_1],
        public_amount_out,
        withdrawal_fee,
        recipient: if transfer { None } else { Some(Recipient(*destination_account)) },
        recovery_owner_commitment,
        recovery_payload: if transfer { None } else { Some(recovery_payload) },
    }
    .body()?;

    // Three outputs are appended after the two deposits, at indices 2, 3, 4.
    let mut after = frontier;
    let mut commitment_root_after = anchor_root;
    let mut leaves: Vec<Fr> =
        the_notes.iter().map(|note| note.leaf()).collect();
    let bodies = [public.note_body_0, public.note_body_1, public.note_body_2];
    for (slot, note) in bodies.iter().enumerate() {
        let index = 2 + slot as u64;
        let leaf = notes::note_commitment(*note, Fr::from(index));
        let (assigned, root) = after.append(leaf)?;
        if assigned != index {
            return Err("an output note landed at another index".into());
        }
        leaves.push(leaf);
        commitment_root_after = root;
    }

    Ok(Scenario {
        deposits: [the_notes[0].deposit_body()?, the_notes[1].deposit_body()?],
        roots_after_deposit,
        transact,
        nullifier_root_after: tree_state.root(),
        commitment_root_after,
        valid_until,
        payout: public_amount_out,
        recovery: Recovery {
            owner_commitment: recovery_owner_commitment,
            output_data_hash: recovery_data_hash,
            leaf_index: leaves.len() as u64,
            leaves,
        },
    })
}

/// What the sandbox charged for the three messages, and for the bounce if the
/// destination refused the payout.
struct SandboxRun {
    gas: [i64; 3],
    /// The bounce is a transaction of its own, and only happens when the
    /// destination refuses.
    bounce: Option<BounceRun>,
}

struct BounceRun {
    gas: i64,
    exit: i32,
    /// What the bounce actually delivered, which is what section 15.4 mints
    /// the recovery note for. The chain will decide a different number --
    /// this is the sandbox's, recorded so the two can be compared.
    recovered: u128,
    /// The tree the pool holds once the recovery note is in it, read back
    /// from the sandbox. It is what the offline predictor is checked against
    /// before the chain is asked to agree with it.
    commitment_root: String,
    commitment_next_index: String,
}

/// The gas the sandbox executor charges for each of the three messages.
///
/// The same bytes, the same state, the same code. Every gas figure this
/// project quotes comes from this executor on the understanding that it is
/// what a validator runs; recording it here lets the on-chain harness compare
/// the two directly.
fn sandbox_gas(
    code: &Cell,
    state: &Cell,
    destination_code: &Cell,
    scenario: &Scenario,
    now: u32,
) -> Result<SandboxRun, Box<dyn std::error::Error>> {
    let mut bc = Blockchain::with_global_version_and_base_workchain(ACTIVE_VERSION)?;
    bc.set_workchain(0);
    bc.set_now(now);
    let payer = bc.treasury("depositor", 1_000_000 * DENOMINATION)?;

    let deploy = |bc: &mut Blockchain, code: &Cell, data: &Cell, value: u64| {
        let init = StateInit::with_code_and_data(code.clone(), data.clone());
        let address = address_of(code, data)?;
        bc.send_message(
            MessageBuilder::internal(payer.address(), &address, value)
                .bounce(false)
                .state_init(init)
                .body(Cell::default())
                .build(),
        )?
        .expect_success();
        Ok::<MsgAddressInt, Box<dyn std::error::Error>>(address)
    };

    let pool = deploy(&mut bc, code, state, 100 * DENOMINATION)?;
    deploy(&mut bc, destination_code, &Cell::default(), 1 * DENOMINATION)?;

    let mut gas = [0i64; 3];
    let mut bounce: Option<BounceRun> = None;
    let steps: [(&Cell, u64); 3] = [
        (&scenario.deposits[0], DENOMINATION + compute_fee(gas_ceiling("deposit_gas_ceiling"))),
        (&scenario.deposits[1], DENOMINATION + compute_fee(gas_ceiling("deposit_gas_ceiling"))),
        (&scenario.transact, compute_fee(gas_ceiling("transact_gas_ceiling"))),
    ];
    for (index, (body, value)) in steps.into_iter().enumerate() {
        let result = bc.send_message(
            MessageBuilder::internal(payer.address(), &pool, value)
                .bounce(true)
                .body(body.clone())
                .build(),
        )?;
        result.expect_success();
        gas[index] = match result.read_primary_description().compute_ph {
            chain_block::TrComputePhase::Vm(phase) => phase
                .gas_used
                .to_string()
                .parse()
                .map_err(|error| format!("the gas the sandbox charged: {error}"))?,
            chain_block::TrComputePhase::Skipped(_) => {
                return Err("a message skipped its compute phase".into())
            }
        };

        // The transact is the last step, and it is the one whose payout can
        // come back. A bounce is a transaction of its own; the sandbox
        // delivers it inside the same send, so it is read out here.
        if index == 2 {
            for (_, transaction) in &result.transactions {
                let Ok(Some(message)) = transaction.read_in_msg() else { continue };
                let chain_block::CommonMsgInfo::IntMsgInfo(header) = message.header() else {
                    continue;
                };
                if !header.bounced {
                    continue;
                }
                let Ok(chain_block::TransactionDescr::Ordinary(description)) =
                    transaction.read_description()
                else {
                    continue;
                };
                if let chain_block::TrComputePhase::Vm(phase) = &description.compute_ph {
                    bounce = Some(BounceRun {
                        gas: phase
                            .gas_used
                            .to_string()
                            .parse()
                            .map_err(|error| format!("the gas the bounce cost: {error}"))?,
                        exit: phase.exit_code,
                        recovered: header.value.coins.as_u128(),
                        commitment_root: String::new(),
                        commitment_next_index: String::new(),
                    });
                }
            }
        }
    }

    if let Some(bounce) = bounce.as_mut() {
        let read = |method: &str| -> Result<String, Box<dyn std::error::Error>> {
            let result = bc.run_get_method(&pool, method, vec![])?;
            if result.exit_code != 0 {
                return Err(format!("{method} exited {}", result.exit_code).into());
            }
            Ok(result
                .stack
                .last()
                .ok_or_else(|| format!("{method} returned nothing"))?
                .as_integer()?
                .to_string())
        };
        bounce.commitment_root = read("commitment_root")?;
        bounce.commitment_next_index = read("commitment_next_index")?;
    }
    Ok(SandboxRun { gas, bounce })
}

/// The root the tree reaches once a recovery note is minted for `recovered`.
///
/// Section 15.4 mints the note for whatever the bounce delivered, which
/// depends on forward fees and so cannot be known before the message is sent.
/// The harness reads the amount off the chain and asks for the root here, so
/// the prediction still comes from the circuit's own tree rather than from
/// the pool's own report of what it did.
fn recovery_root(fixture: &Path, recovered: u128) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(fixture.join("fixture.json"))?;
    let field = |name: &str| -> Result<String, Box<dyn std::error::Error>> {
        let at = text.find(&format!("\"{name}\"")).ok_or(format!("no {name} in the fixture"))?;
        let rest = &text[at + name.len() + 2..];
        let open = rest.find(':').ok_or("malformed fixture")?;
        let tail = &rest[open + 1..];
        let start = tail.find('"').ok_or("malformed fixture")?;
        let body = &tail[start + 1..];
        let end = body.find('"').ok_or("malformed fixture")?;
        Ok(body[..end].to_string())
    };
    let owner = dec_to_fr(&field("recovery_owner_commitment")?)?;
    let data_hash = dec_to_fr(&field("recovery_output_data_hash")?)?;

    // Every leaf the tree held when the bounce arrived, in order.
    let list_at = text.find("\"recovery_leaves\"").ok_or("no recovery_leaves in the fixture")?;
    let list = &text[list_at..];
    let open = list.find('[').ok_or("malformed fixture")?;
    let close = list.find(']').ok_or("malformed fixture")?;
    let mut leaves = Vec::new();
    for item in list[open + 1..close].split(',') {
        let trimmed = item.trim().trim_matches('"');
        if trimmed.is_empty() {
            continue;
        }
        leaves.push(dec_to_fr(trimmed)?);
    }

    let (index, root, minted) = predict_recovery(owner, data_hash, &leaves, recovered)?;
    println!(
        "{{\"leaf_index\": {index}, \"commitment_root\": \"{}\", \"minted_nanotos\": {minted}}}",
        dec(root)
    );
    Ok(())
}

/// Section 15.4's recovery note, appended to the tree those leaves describe.
///
/// The only input not known before the payout is sent is `recovered`: the
/// note is minted for what the bounce delivered, and that depends on forward
/// fees. Everything else comes from the scenario, so this is still the
/// circuit's own tree computing the answer and not the pool reporting it.
///
/// Checked against a real bounce before it is used: the fixture runs the
/// scenario in the sandbox, reads the pool's root afterwards, and refuses to
/// write itself if this disagrees.
fn predict_recovery(
    owner_commitment: Fr,
    output_data_hash: Fr,
    leaves: &[Fr],
    // What the bounce *delivered*, not what the note is minted for. The pool
    // charges the recovery's own compute to the money it is recovering, so
    // the note is worth the remainder; minting the whole of it would pay for
    // the recovery out of the pool's reserve.
    //
    // The subtraction lives here because two callers need it -- the
    // generation-time check against the sandbox, and `--recovery-root` with
    // the value the chain reports -- and a subtraction each of them has to
    // remember is one that one of them will not. That is how this broke: the
    // charge was introduced, the contract's own suites moved with it, and the
    // predictor did not. Nothing failed, because no CI runs a localnet.
    delivered: u128,
) -> Result<(u64, Fr, u128), Box<dyn std::error::Error>> {
    let recovered = delivered.saturating_sub(u128::from(compute_fee(gas_ceiling("bounce_gas_ceiling"))));
    let mut frontier = tree::Frontier::new();
    for leaf in leaves {
        frontier.append(*leaf)?;
    }
    let index = leaves.len() as u64;
    let body = notes::note_body_commitment(owner_commitment, Fr::from(recovered), output_data_hash);
    let (assigned, root) = frontier.append(notes::note_commitment(body, Fr::from(index)))?;
    // The amount as well as the tree. The pool owes what the note is worth,
    // and a caller left to work that out for itself is a third place this
    // subtraction can be forgotten. It was already forgotten in two.
    Ok((assigned, root, recovered))
}

/// A canonical decimal field element, the way the fixture writes them.
fn dec_to_fr(value: &str) -> Result<Fr, Box<dyn std::error::Error>> {
    let mut out = Fr::ZERO;
    let ten = Fr::from(10u64);
    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return Err(format!("{value} is not a decimal field element").into());
        }
        out = out * ten + Fr::from(u64::from(byte - b'0'));
    }
    Ok(out)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.first().map(String::as_str) == Some("--recovery-root") {
        let fixture = PathBuf::from(
            arguments.get(1).ok_or("usage: onchain-fixture --recovery-root <dir> <recovered>")?,
        );
        let recovered: u128 = arguments
            .get(2)
            .ok_or("usage: onchain-fixture --recovery-root <dir> <recovered>")?
            .parse()?;
        return recovery_root(&fixture, recovered);
    }

    let refuses = arguments.iter().any(|argument| argument == "--refuse");
    let transfer = arguments.iter().any(|argument| argument == "--transfer");
    if refuses && transfer {
        return Err("--refuse and --transfer are different scenarios: a transfer has no \
                    payout, so there is nothing for a destination to refuse"
            .into());
    }
    let mut args = arguments.into_iter().filter(|argument| !argument.starts_with("--"));
    let root = PathBuf::from(args.next().ok_or("usage: onchain-fixture <repo root> <out dir>")?);
    let out = PathBuf::from(args.next().ok_or("usage: onchain-fixture <repo root> <out dir>")?);
    std::fs::create_dir_all(&out).map_err(|error| format!("{}: {error}", out.display()))?;

    // The contract, compiled from the same source list every suite compiles.
    let code = compile_func(&pool_sources())?;

    // The state the frozen manifest names. Not a fixture: the generator's own
    // parameters, read out of the repository.
    let genesis =
        shielded_pool_genesis::build(shielded_pool_genesis::development_parameters(&root)?)?;
    let state = genesis.state.clone();
    let pool_address = address_of(&code, &state)?;
    let pool_account = account_of(&pool_address)?;

    // Where the withdrawal goes. A contract that takes the money, deployed by
    // the harness at the address its own code hashes to.
    // A directory of this run's own. A fixed name under the shared temporary
    // directory is truncated by a second run of this tool while the first is
    // still compiling from it.
    let destination_dir = tempfile::tempdir()?;
    let destination_path = destination_dir.path().join(if refuses {
        "tos_shielded_onchain_refuser.fc"
    } else {
        "tos_shielded_onchain_accepter.fc"
    });
    std::fs::write(&destination_path, if refuses { REFUSER } else { ACCEPTER })?;
    let destination_code = compile_func(&[stdlib_path(), destination_path])?;
    let destination_address = address_of(&destination_code, &Cell::default())?;
    let destination_account = account_of(&destination_address)?;

    // The chain's global id goes into the execution domain, and the domain is
    // eight of the eighteen public inputs. It is read from the sandbox rather
    // than written down, and the harness sets the chain it builds to match --
    // a proof built for one chain is refused by another.
    let global_id = shielded_pool_circuit_crosscheck::wire::WireProbe::deploy()?.domain_inputs()?.0;

    let now = u32::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let valid_until = now + INTENT_LIFETIME;

    let the_notes = [Note::new(0)?, Note::new(1)?];
    eprintln!("proving the withdrawal for global_id {global_id} ...");
    let scenario =
        build_scenario(
            global_id,
            &pool_account,
            &destination_account,
            &the_notes,
            valid_until,
            transfer,
        )?;

    eprintln!("running the same three messages in the sandbox ...");
    let run = sandbox_gas(&code, &state, &destination_code, &scenario, now)?;
    let gas = run.gas;
    eprintln!("the sandbox charges {} / {} / {} gas", gas[0], gas[1], gas[2]);
    if refuses {
        let bounce = run
            .bounce
            .as_ref()
            .ok_or("the destination refused the payout and nothing bounced back")?;
        eprintln!(
            "the payout bounced: {} gas, exit {}, {} nanotos recovered",
            bounce.gas, bounce.exit, bounce.recovered
        );
        if bounce.exit != 0 {
            return Err(format!("the sandbox's recovery exited {}", bounce.exit).into());
        }
        // The predictor, checked against a bounce that really happened. The
        // chain's recovered amount will be its own, and the harness will ask
        // for the root that goes with it; this is what says the asking is
        // worth anything.
        let (index, root, _minted) = predict_recovery(
            scenario.recovery.owner_commitment,
            scenario.recovery.output_data_hash,
            &scenario.recovery.leaves,
            bounce.recovered,
        )?;
        if dec(root) != bounce.commitment_root
            || index.to_string() != bounce.commitment_next_index.parse::<u64>()
                .map(|next| (next - 1).to_string())
                .unwrap_or_default()
        {
            return Err(format!(
                "the recovery predictor says leaf {index} and root {}, the sandbox's pool holds \
                 root {} at next index {}. The chain would be asked to agree with a prediction \
                 that is already wrong.",
                dec(root),
                bounce.commitment_root,
                bounce.commitment_next_index
            )
            .into());
        }
        eprintln!("the recovery predictor agrees with the sandbox's own bounce");
    } else if run.bounce.is_some() {
        return Err("the payout bounced from a destination that was supposed to take it".into());
    }

    write_cell(&out.join("code.boc"), &code)?;
    write_cell(&out.join("data.boc"), &state)?;
    write_cell(&out.join("destination-code.boc"), &destination_code)?;
    write_cell(&out.join("deposit-0.boc"), &scenario.deposits[0])?;
    write_cell(&out.join("deposit-1.boc"), &scenario.deposits[1])?;
    write_cell(&out.join("transact.boc"), &scenario.transact)?;

    let deposit_value = DENOMINATION + compute_fee(gas_ceiling("deposit_gas_ceiling"));
    let transact_value = compute_fee(gas_ceiling("transact_gas_ceiling"));
    let fixture = format!(
        concat!(
            "{{\n",
            "  \"note\": \"Generated by tools/shielded-pool-circuit/crosscheck onchain-fixture.",
            " Do not edit by hand.\",\n",
            "  \"workchain\": 0,\n",
            "  \"global_id\": {global_id},\n",
            "  \"built_at\": {built_at},\n",
            "  \"valid_until\": {valid_until},\n",
            "  \"address\": \"0:{address}\",\n",
            "  \"state_hash\": \"{state_hash}\",\n",
            "  \"code_hash\": \"{code_hash}\",\n",
            "  \"deploy_value_nanotos\": {deploy},\n",
            "  \"destination\": {{\n",
            "    \"address\": \"0:{destination}\",\n",
            "    \"code\": \"destination-code.boc\",\n",
            "    \"deploy_value_nanotos\": {destination_deploy},\n",
            "    \"refuses\": {refuses},\n",
            "    \"expects_nanotos\": {payout}\n",
            "  }},\n",
            "  \"recovery_owner_commitment\": \"{recovery_owner}\",\n",
            "  \"recovery_output_data_hash\": \"{recovery_data_hash}\",\n",
            "  \"recovery_leaf_index\": {recovery_index},\n",
            "  \"recovery_sandbox\": {recovery_sandbox},\n",
            "  \"recovery_leaves\": [{recovery_leaves}],\n",
            "  \"expected_at_genesis\": {{\n",
            "    \"commitment_root\": \"{empty_root}\",\n",
            "    \"nullifier_root\": \"{nullifier_root}\",\n",
            "    \"commitment_next_index\": 0,\n",
            "    \"native_liability\": 0\n",
            "  }},\n",
            "  \"steps\": [\n",
            "    {{\n",
            "      \"name\": \"the first deposit\",\n",
            "      \"body\": \"deposit-0.boc\",\n",
            "      \"value_nanotos\": {deposit_value},\n",
            "      \"gas_ceiling\": {deposit_ceiling},\n",
            "      \"sandbox_gas_used\": {gas0},\n",
            "      \"expect\": {{\n",
            "        \"commitment_root\": \"{root0}\",\n",
            "        \"commitment_next_index\": 1,\n",
            "        \"native_liability\": {one}\n",
            "      }}\n",
            "    }},\n",
            "    {{\n",
            "      \"name\": \"the second deposit\",\n",
            "      \"body\": \"deposit-1.boc\",\n",
            "      \"value_nanotos\": {deposit_value},\n",
            "      \"gas_ceiling\": {deposit_ceiling},\n",
            "      \"sandbox_gas_used\": {gas1},\n",
            "      \"expect\": {{\n",
            "        \"commitment_root\": \"{root1}\",\n",
            "        \"commitment_next_index\": 2,\n",
            "        \"native_liability\": {two}\n",
            "      }}\n",
            "    }},\n",
            "    {{\n",
            "      \"name\": \"{transact_name}\",\n",
            "      \"body\": \"transact.boc\",\n",
            "      \"value_nanotos\": {transact_value},\n",
            "      \"gas_ceiling\": {transact_ceiling},\n",
            "      \"sandbox_gas_used\": {gas2},\n",
            "      \"expect\": {{\n",
            "{withdrawal_expect}",
            "        \"nullifier_root\": \"{nullifier_after}\",\n",
            "        \"nullifier_next_index\": 3\n",
            "      }}\n",
            "    }}{bounce_step}\n",
            "  ]\n",
            "}}\n"
        ),
        global_id = global_id,
        built_at = now,
        valid_until = scenario.valid_until,
        address = hex(pool_address.address().get_bytestring(0).as_slice()),
        state_hash = hex(&shielded_pool_genesis::manifest::cell_hash(&state)),
        code_hash = hex(code.repr_hash().as_slice()),
        deploy = 100u64 * DENOMINATION,
        destination = hex(destination_address.address().get_bytestring(0).as_slice()),
        destination_deploy = DENOMINATION,
        refuses = refuses,
        payout = scenario.payout,
        recovery_owner = dec(scenario.recovery.owner_commitment),
        recovery_data_hash = dec(scenario.recovery.output_data_hash),
        recovery_index = scenario.recovery.leaf_index,
        // What the sandbox's bounce delivered and cost. The chain will decide
        // a different amount -- its forward fees are its own -- so this is
        // recorded rather than asserted.
        recovery_sandbox = match run.bounce.as_ref() {
            Some(bounce) => format!(
                "{{\"gas_used\": {}, \"exit_code\": {}, \"recovered_nanotos\": {}}}",
                bounce.gas, bounce.exit, bounce.recovered
            ),
            None => "null".to_string(),
        },
        recovery_leaves = scenario
            .recovery
            .leaves
            .iter()
            .map(|leaf| format!("\"{}\"", dec(*leaf)))
            .collect::<Vec<_>>()
            .join(", "),
        empty_root = dec(genesis.commitment_root),
        nullifier_root = dec(genesis.nullifier_root),
        deposit_value = deposit_value,
        deposit_ceiling = gas_ceiling("deposit_gas_ceiling"),
        transact_value = transact_value,
        transact_ceiling = gas_ceiling("transact_gas_ceiling"),
        gas0 = gas[0],
        gas1 = gas[1],
        gas2 = gas[2],
        root0 = dec(scenario.roots_after_deposit[0]),
        root1 = dec(scenario.roots_after_deposit[1]),
        // What the withdrawal leaves behind depends on whether its payout
        // comes back. The tree and the liability move again when it does, and
        // the bounce lands a block or two later -- too fast to catch in
        // between -- so on the refusing run they are checked after it and not
        // before. The nullifier tree is not touched by a bounce, so it is
        // checked either way.
        transact_name = if transfer { "the transfer" } else { "the withdrawal" },
        withdrawal_expect = if refuses {
            String::new()
        } else {
            format!(
                "        \"commitment_root\": \"{}\",\n        \"commitment_next_index\": 5,\n        \"native_liability\": {},\n",
                dec(scenario.commitment_root_after),
                // The number that separates the two scenarios. A withdrawal
                // owes less afterwards because value left the pool; a
                // transfer owes exactly what it owed, because none did. If
                // this ever reads as a withdrawal's figure on a transfer run,
                // the pool paid somebody and the proof did not say so.
                2 * DENOMINATION - scenario.payout - if transfer { 0 } else { WITHDRAWAL_FEE }
            )
        },
        // A step with no body: the chain does this one by itself. What it
        // leaves cannot be written down here, because the note is minted for
        // whatever the bounce delivered -- so the harness reads that off the
        // chain and asks `--recovery-root` for the tree it implies.
        bounce_step = if refuses {
            format!(
                ",\n    {{\n      \"name\": \"the bounce and its recovery note\",\n      \"body\": null,\n      \"gas_ceiling\": {},\n      \"expect\": {{\n        \"commitment_next_index\": {},\n        \"nullifier_next_index\": 3,\n        \"liability_before_recovery\": {}\n      }}\n    }}",
                gas_ceiling("bounce_gas_ceiling"),
                scenario.recovery.leaf_index + 1,
                2 * DENOMINATION - DENOMINATION - WITHDRAWAL_FEE
            )
        } else {
            String::new()
        },
        nullifier_after = dec(scenario.nullifier_root_after),
        one = DENOMINATION,
        two = 2 * DENOMINATION,
    );
    write(&out.join("fixture.json"), fixture.as_bytes())?;

    eprintln!("pool address 0:{}", hex(pool_account.as_slice()));
    eprintln!("the intent is valid until {} ({INTENT_LIFETIME}s from now)", scenario.valid_until);
    Ok(())
}
