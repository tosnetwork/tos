/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! `shield withdraw` and `shield send`: spending from the pool.
//!
//! A spend is planned from the verified state, assembled and signed, proven
//! under the audited ceremony key, checked once more against a fresh head,
//! and broadcast from a configured wallet as one exact message. Every step
//! that commits this wallet to something -- the indices it seals with, the
//! inputs it holds, the message it sends -- is journalled before it happens,
//! so a stop at any point leaves a record the next command reads rather than
//! a note spent twice or an index reused.
//!
//! What the journal says about a spend is decided only from a verified state:
//! it is settled when the pool's accepted intents hold its digest, conflicted
//! when one of its nullifiers was published by another transaction, and
//! released when the contract's own clock -- the time of the shard block
//! holding the pool's state -- is past its deadline. Until then its inputs are
//! held from any other spend. Nothing is ever rebuilt or resent on this
//! wallet's own initiative.

use anyhow::Context;
use base64::Engine;
use chain_block::{Cell, MsgAddressInt, write_boc};
use chain_rpc_client::v2::data_models::AccountState;
use colored::Colorize;
use common::task_cancellation::CancellationCtx;
use contracts::shielded_pool::{
    self, ANCHOR_CURRENT, ANCHOR_RECENT, AUTH_KEY_BYTES, AUTH_SIGNATURE_BYTES, IMT_PATH_FIELDS,
    NullifierWitness, OUTPUT_DATA_BYTES, PROOF_A_BYTES, PROOF_B_BYTES, PROOF_C_BYTES, PoolState,
    TransactBody, auth_bundle, groth16_proof_cell, witness_bundle,
};
use contracts::wallet::send_fees;
use contracts::{DefaultChainProvider, Wallet};
use sha2::{Digest, Sha256};
use shielded_pool_ceremony::record::Directory;
use shielded_pool_circuit::field::{Fr, fr_to_be};
use shielded_pool_circuit::groth16::CanonicalProof;
use shielded_pool_circuit::imt;
use shielded_pool_circuit::tree::Frontier;
use shielded_pool_prover::{INTENT_VALIDITY_WINDOW_SECS, PublicClient};
use shielded_pool_wallet::descriptor::Descriptor;
use shielded_pool_wallet::ledger::Ledger;
use shielded_pool_wallet::plan::{self, Candidate, Plan, PoolTerms, RecipientKeys, Request};
use shielded_pool_wallet::spend::{self as assembly, Assembled, Terms};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::super::utils::{
    SEND_TIMEOUT, get_wallet_config, load_config_vault_rpc_client, make_wallet,
    wait_for_seqno_change, wallet_info,
};
use super::super::vote_cmd::{pinned_wallet_reserve, sender_can_pay};
use super::chain::Head;
use super::profile::{KeyClass, Network, word};
use super::store::{JournalRecord, Word, coins, coins_value};
use super::{
    EXPERIMENTAL, HeadRelation, Opened, ReadMode, confirm, open_instance, parse_tos,
    restore_ledger, restore_recovered, sync_instance, tos, utc,
};

/// A spend is not sent when the contract's clock is this close to its
/// deadline: the message still has to travel and be included.
const DEADLINE_MARGIN_SECS: u32 = 300;

#[derive(clap::Args, Clone)]
#[command(about = "Withdraw a denomination from the pool to an ordinary address")]
pub struct WithdrawCmd {
    #[arg(short = 'n', long)]
    name: String,
    /// Amount in TOS, exactly a pool denomination; the pool's withdrawal fee
    /// is taken from the notes on top
    #[arg(long, conflicts_with = "amount_nanotos")]
    amount: Option<String>,
    /// Amount in nanotos, exactly a pool denomination
    #[arg(long)]
    amount_nanotos: Option<u128>,
    /// The workchain-0 address the pool pays
    #[arg(long)]
    to: String,
    #[command(flatten)]
    broadcast: Broadcast,
}

#[derive(clap::Args, Clone)]
#[command(about = "Send to another shielded descriptor")]
pub struct SendCmd {
    #[arg(short = 'n', long)]
    name: String,
    /// Amount in TOS
    #[arg(long, conflicts_with = "amount_nanotos")]
    amount: Option<String>,
    /// Amount in nanotos
    #[arg(long)]
    amount_nanotos: Option<u128>,
    /// The recipient's descriptor, as `shield address` printed it
    #[arg(long)]
    to: String,
    /// Broadcast from the configured wallet directly. The wallet, the pool and
    /// the time are then visible on chain together; accepted only on an
    /// isolated local network
    #[arg(long)]
    direct: bool,
    #[command(flatten)]
    broadcast: Broadcast,
}

/// How a spend reaches the network: from a configured wallet, with the
/// ceremony transcript audited for its proving key.
#[derive(clap::Args, Clone)]
pub struct Broadcast {
    /// The configured wallet that broadcasts and pays the message
    #[arg(long)]
    from: String,
    /// The finished phase-2 ceremony directory the proving key is read from.
    /// Its whole transcript is audited on every spend
    #[arg(long)]
    ceremony_dir: PathBuf,
    /// Do not ask for confirmation
    #[arg(short = 'y', long)]
    yes: bool,
    #[command(flatten)]
    read: ReadMode,
}

impl WithdrawCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        let amount = amount_of(&self.amount, self.amount_nanotos)?;
        let recipient: MsgAddressInt = self.to.parse().context("the payout address")?;
        anyhow::ensure!(
            recipient.workchain_id() == 0,
            "the pool pays workchain 0 only; {} is on workchain {}",
            self.to,
            recipient.workchain_id()
        );
        let mut account = recipient.address().clone();
        let recipient_account: [u8; 32] = account
            .get_next_bytes(32)
            .context("the payout address account")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("the payout address is not 256 bits"))?;
        let target = Target::Withdraw { recipient: Box::new(recipient.clone()), recipient_account };
        run(&self.name, amount, target, &self.broadcast, config_path).await
    }
}

impl SendCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        let amount = amount_of(&self.amount, self.amount_nanotos)?;
        anyhow::ensure!(
            self.direct,
            "a send broadcast from a configured wallet shows that wallet, the pool and the time \
             together on chain; pass --direct to accept that on an isolated local network. A \
             relayed path that does not is not available yet"
        );
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(self.to.trim())
            .context("the descriptor is not base64")?;
        let descriptor = Descriptor::from_bytes(&bytes)
            .map_err(|error| anyhow::anyhow!("the descriptor: {error}"))?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let target = Target::Send { descriptor: Box::new(descriptor), descriptor_hash: digest };
        run(&self.name, amount, target, &self.broadcast, config_path).await
    }
}

fn amount_of(text: &Option<String>, nanotos: Option<u128>) -> anyhow::Result<u128> {
    let amount = match (text, nanotos) {
        (Some(text), None) => parse_tos(text)?,
        (None, Some(value)) => value,
        _ => anyhow::bail!("give exactly one of --amount and --amount-nanotos"),
    };
    anyhow::ensure!(amount > 0, "an amount of zero");
    Ok(amount)
}

enum Target {
    Withdraw { recipient: Box<MsgAddressInt>, recipient_account: [u8; 32] },
    Send { descriptor: Box<Descriptor>, descriptor_hash: [u8; 32] },
}

impl Target {
    fn is_withdrawal(&self) -> bool {
        matches!(self, Target::Withdraw { .. })
    }

    /// What the journal records as the recipient: the payout address, or
    /// the hash of the descriptor so the same descriptor is not paid twice
    /// from this instance.
    fn recipient_label(&self) -> String {
        match self {
            Target::Withdraw { recipient, .. } => recipient.to_string(),
            Target::Send { descriptor_hash, .. } => {
                format!("descriptor:{}", hex::encode(descriptor_hash))
            }
        }
    }
}

/// The ceremony key's pin, as the profile knows it.
fn ceremony_vk_pin() -> anyhow::Result<(&'static str, [u8; 32])> {
    let (_, pin) = super::profile::KNOWN_VERIFYING_KEYS
        .iter()
        .find(|(class, _)| *class == KeyClass::Ceremony)
        .context("no ceremony key is pinned")?;
    Ok((pin, word(pin)?))
}

async fn run(
    name: &str,
    amount: u128,
    target: Target,
    broadcast: &Broadcast,
    config_path: &Path,
) -> anyhow::Result<()> {
    eprintln!("{}", EXPERIMENTAL.yellow());
    let (config, vault, rpc) = load_config_vault_rpc_client(config_path).await?;
    let mut opened = open_instance(config_path, name, &vault).await?;
    let network = opened.network()?;
    anyhow::ensure!(
        network == Network::Local,
        "a spend broadcast from a configured wallet shows that wallet, the pool and the time \
         together on chain. This client does that only on an isolated local network; this \
         instance is on {}",
        network.label()
    );
    let pool = opened.pointer.profile.address()?;
    let head = broadcast.read.head(&config, &rpc, &pool).await?;
    require_current_verified_head(&opened, &head, name)?;

    // The pool must verify against the finished ceremony key, and the key
    // in the given directory must be that key: audited in full, every time.
    let (pin_hex, pin) = ceremony_vk_pin()?;
    anyhow::ensure!(
        head.state.config.groth16_vk_hash == pin,
        "this pool verifies proofs against a key other than the finished ceremony key ({}); \
         spends are made only against the ceremony key",
        hex::encode(head.state.config.groth16_vk_hash)
    );
    eprintln!(
        "{} auditing the ceremony transcript in {} (every spend pays for this)",
        "note:".bold(),
        broadcast.ceremony_dir.display()
    );
    let directory = Directory::at(&broadcast.ceremony_dir);
    let audited = shielded_pool_prover::audit_ceremony(&directory)
        .map_err(|error| anyhow::anyhow!("ceremony audit: {error}"))?;
    let client = PublicClient::load(
        &directory,
        &audited,
        pin_hex,
        head.global_id,
        &opened.pointer.profile.account_id()?,
    )
    .map_err(|error| anyhow::anyhow!("proving key: {error}"))?;
    anyhow::ensure!(
        client.verifying_key_bytes().map_err(|error| anyhow::anyhow!("{error}"))?
            == head.state.verifying_key,
        "the audited proving key's verifying key is not the one the pool stores"
    );
    anyhow::ensure!(
        client.execution_domain() == opened.domain,
        "the prover's execution domain is not this instance's"
    );

    // What this wallet may spend: its notes at known leaves, less those a
    // pending spend holds. One spend at a time.
    let ledger = restore_ledger(&opened.state.ledger)?;
    let recovered = restore_recovered(&opened.state)?;
    let shard_time = opened.state.cursor.as_ref().map(|cursor| cursor.shard_gen_utime);
    let pending = pending_spends(&opened.journal, &ledger, shard_time, true);
    if let Some(open) = pending.iter().find(|spend| spend.outcome.holds_inputs()) {
        anyhow::bail!(
            "a spend of {} TOS to {} is {} (deadline {}); one spend at a time: run `tosctl shield \
             sync --name {name}` until the verified state settles it or shows its deadline passed",
            tos(open.amount),
            open.recipient,
            open.outcome.describe(),
            utc(open.valid_until)
        );
    }
    let recipient_label = target.recipient_label();
    if let Some(paid) = pending
        .iter()
        .find(|spend| spend.recipient == recipient_label && spend.outcome != SpendOutcome::Released)
    {
        anyhow::ensure!(
            target.is_withdrawal(),
            "this instance already paid that descriptor ({}); a descriptor is paid once -- ask \
             the recipient for a fresh one",
            paid.outcome.describe()
        );
    }
    if let Target::Send { descriptor, .. } = &target {
        descriptor
            .require_domain(opened.domain)
            .map_err(|error| anyhow::anyhow!("the descriptor: {error}"))?;
        let own = opened
            .instance
            .owner_nf_key_hash(descriptor.note_key_index)
            .map_err(|error| anyhow::anyhow!("owner key: {error}"))?;
        anyhow::ensure!(
            own != descriptor.owner_nf_key_hash,
            "that descriptor was issued by this instance; a transfer to oneself only pays fees"
        );
    }
    let held = held_leaves(&pending);
    let candidates: Vec<Candidate> = recovered
        .notes
        .iter()
        .zip(recovered.leaves.iter())
        .filter_map(|(note, leaf)| {
            leaf.filter(|leaf| !held.contains(leaf))
                .map(|leaf_index| Candidate { note: *note, leaf_index })
        })
        .collect();
    let terms = PoolTerms {
        denominations: head.state.config.denominations.clone(),
        withdrawal_fee: head.state.config.withdrawal_fee,
    };
    let request = match &target {
        Target::Withdraw { recipient_account, .. } => {
            Request::Withdraw { amount, recipient_account: *recipient_account }
        }
        Target::Send { descriptor, .. } => {
            Request::Transfer { to: Box::new(RecipientKeys::of(descriptor)), amount }
        }
    };

    // The plan asks for indices only once every check has passed; they are
    // provisional until journalled below.
    let mut next = super::store::next_issuable_index(&opened.state, &opened.journal)?;
    let plan = plan::plan(&terms, &candidates, &request, &mut || {
        let index = next;
        next = next.checked_add(1).ok_or_else(|| {
            shielded_pool_wallet::error::Error::Planning("note key index exhausted".into())
        })?;
        Ok(index)
    })
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    let anchor = choose_anchor(&ledger, &head.state, &plan)?;

    // The message carries exactly the contract's fee; the wallet's own fees
    // are bounded over a body of the real shape before anything is signed.
    let value = head.transact_fee()?;
    let value_u64 = u64::try_from(value).context("the transact fee exceeds the message limit")?;
    let wallet_cfg =
        get_wallet_config(&broadcast.from, &config.wallets, config.master_wallet.as_ref())?;
    let (payer, payer_info, payer_secret) =
        wallet_info(rpc.clone(), wallet_cfg, vault.clone()).await?;
    anyhow::ensure!(
        payer_info.account_state == AccountState::Active,
        "wallet {:?} is not active",
        broadcast.from
    );
    let chain = DefaultChainProvider::new(rpc.clone());
    let placeholder = placeholder_body(plan.is_withdrawal())?;
    let (reserve, balance) = pinned_wallet_reserve(&chain, &payer, &placeholder).await?;
    sender_can_pay(&broadcast.from, balance, value_u64, reserve)?;
    let wallet = make_wallet(rpc.clone(), wallet_cfg, payer_secret, &broadcast.from).await?;

    print_summary(&plan, &target, &anchor, &broadcast.from, &payer, &pool, value, reserve);
    if anchor.kind == ANCHOR_CURRENT {
        println!(
            "{} no preserved root covers these inputs, so the proof is anchored to the pool's \
             current root. If any deposit or spend lands before this one, the pool refuses it \
             (exit 152); the inputs then stay held until the deadline passes and the spend has \
             to be planned again. Nothing is rebuilt or resent on its own.",
            "warning:".yellow().bold()
        );
        if !broadcast.yes && !confirm("Anchor to the current root anyway?")? {
            println!("{}", "Spend cancelled".yellow());
            return Ok(());
        }
    }
    if !broadcast.yes && !confirm("Confirm spend?")? {
        println!("{}", "Spend cancelled".yellow());
        return Ok(());
    }

    // The indices are on disk before anything is derived from them.
    let indices = plan.own_indices();
    opened.append_journal(&JournalRecord::IndicesReserved {
        indices: indices.clone(),
        purpose: if plan.is_withdrawal() { "withdraw".into() } else { "send".into() },
    })?;
    let high = indices.iter().max().copied().unwrap_or(0).checked_add(1);
    opened.state.issued_high_water =
        opened.state.issued_high_water.max(high.context("note key index exhausted")?);
    opened.save_state()?;

    // Assemble and sign. The deadline runs from the contract's clock, not
    // this machine's.
    let valid_until = head
        .shard_gen_utime
        .checked_add(INTENT_VALIDITY_WINDOW_SECS)
        .context("the deadline overflows")?;
    let intent_nonce = fresh()?;
    let assembled = assembly::assemble(
        &opened.instance,
        &plan,
        &anchor.frontier,
        &Terms { anchor_root: anchor.root, valid_until, intent_nonce },
        &mut || {
            fresh().map_err(|error| shielded_pool_wallet::error::Error::Encoding(error.to_string()))
        },
    )
    .map_err(|error| anyhow::anyhow!("assemble the spend: {error}"))?;
    let intent_digest = fr_to_be(&assembled.intent_digest());
    let nullifiers = assembled.nullifiers();
    opened.append_journal(&JournalRecord::SpendPlanned {
        intent_digest,
        nullifiers: [fr_to_be(&nullifiers[0]), fr_to_be(&nullifiers[1])],
        input_leaves: plan.input_leaves(),
        indices,
        amount: coins(amount),
        recipient: recipient_label,
        withdrawal: plan.is_withdrawal(),
        valid_until,
        anchor_kind: anchor.kind,
        anchor_id: anchor.id,
    })?;
    opened.save_state()?;

    eprintln!("{} proving; this takes a while", "note:".bold());
    let started = std::time::Instant::now();
    let Assembled { public, witness, .. } = &assembled;
    let proof = client
        .prove(*public, witness.clone(), head.shard_gen_utime)
        .map_err(|error| anyhow::anyhow!("prove: {error}"))?;
    eprintln!("{} proven in {:.1?}", "note:".bold(), started.elapsed());

    // The pool may have moved while proving. Read it again, bring the state
    // up to it, and require everything the proof assumed to still hold; the
    // nullifier witnesses are built only now, against the tree as it is.
    let fresh_head = broadcast.read.head(&config, &rpc, &pool).await?;
    require_verified_same_chain(&opened, &fresh_head)?;
    let moved = fresh_head.last_lt != head.last_lt || fresh_head.last_hash != head.last_hash;
    let ledger = if moved {
        eprintln!(
            "{} the pool moved while proving (lt {} to {}); replaying what landed",
            "note:".bold(),
            head.last_lt,
            fresh_head.last_lt
        );
        let report = sync_instance(&mut opened, &fresh_head, &rpc).await?;
        anyhow::ensure!(report.verified, "the replayed state is not verified");
        restore_ledger(&opened.state.ledger)?
    } else {
        ledger
    };
    check_still_valid(
        &ledger,
        &fresh_head.state,
        fresh_head.shard_gen_utime,
        &anchor,
        &nullifiers,
        valid_until,
        &intent_digest,
    )?;
    let witnesses = assembly::nullifier_witnesses(ledger.nullifier_state(), nullifiers)
        .map_err(|error| anyhow::anyhow!("nullifier witnesses: {error}"))?;

    let body = transact_body(&assembled, &proof, &witnesses, &anchor, valid_until, &target, &plan)?
        .build()?;
    let body_hash = *body.repr_hash().as_array();
    let (real_cells, real_bits) = send_fees::tree_size(&[&body])?;
    let (bound_cells, bound_bits) = send_fees::tree_size(&[&placeholder])?;
    anyhow::ensure!(
        real_cells <= bound_cells && real_bits <= bound_bits,
        "the spend body ({real_cells} cells, {real_bits} bits) is larger than the shape its fee \
         bound was taken over ({bound_cells} cells, {bound_bits} bits)"
    );
    // The prompt and the proof may have outlived the bound's storage horizon.
    let (reserve, balance) = pinned_wallet_reserve(&chain, &payer, &body).await?;
    sender_can_pay(&broadcast.from, balance, value_u64, reserve)?;

    let message =
        wallet.build_message(pool.clone(), value_u64, body, true, None, None, None).await?;
    let boc = write_boc(&message)?;
    let message_hash = *message.repr_hash().as_array();
    opened.append_journal(&JournalRecord::SpendSigned {
        intent_digest,
        body_hash,
        message_hash,
        payer: payer.to_string(),
        value: coins(value),
        boc: boc.clone(),
    })?;
    opened.save_state()?;

    match rpc.send_boc(&boc).await {
        Ok(()) => {
            opened.append_journal(&JournalRecord::SpendBroadcast { message_hash })?;
            opened.save_state()?;
        }
        Err(error) => {
            opened.append_journal(&JournalRecord::SpendUnknown {
                message_hash,
                error: error.to_string(),
            })?;
            opened.save_state()?;
            anyhow::bail!(
                "the broadcast of message {} failed: {error}. Whether it reached the network is \
                 unknown; it is journalled and will not be rebuilt. Its inputs stay held until \
                 `tosctl shield sync` shows the spend accepted or its deadline ({}) passed.",
                hex::encode(message_hash),
                utc(valid_until)
            );
        }
    }
    let seqno_moved = wait_for_seqno_change(
        rpc.clone(),
        &payer,
        payer_info.seqno,
        &CancellationCtx::default(),
        SEND_TIMEOUT,
    )
    .await
    .is_ok();
    println!(
        "{} spend message {} submitted{}",
        "OK".green().bold(),
        hex::encode(message_hash),
        if seqno_moved {
            "; the wallet's seqno advanced"
        } else {
            "; the wallet's seqno has not advanced yet"
        }
    );
    println!(
        "Submission is not pool execution: run `tosctl shield sync --name {name}` to see whether \
         the pool accepted intent {}. Its inputs are held until then, or until {} by the \
         contract's clock.",
        hex::encode(intent_digest),
        utc(valid_until)
    );
    Ok(())
}

fn fresh() -> anyhow::Result<Fr> {
    shielded_pool_prover::fresh_nonzero_field().map_err(|error| anyhow::anyhow!("{error}"))
}

/// A spend starts from a verified head the stored state is exactly at, so
/// the plan is made from the pool's current state and nothing else.
fn require_current_verified_head(opened: &Opened, head: &Head, name: &str) -> anyhow::Result<()> {
    require_verified_same_chain(opened, head)?;
    let cursor =
        opened.state.cursor.as_ref().with_context(|| {
            format!("never synced; run `tosctl shield sync --name {name}` first")
        })?;
    anyhow::ensure!(
        cursor.verified,
        "the stored state is UNVERIFIED; run `tosctl shield sync --name {name}` through the proof \
         verifier first"
    );
    anyhow::ensure!(
        cursor.lt == head.last_lt && cursor.hash == head.last_hash,
        "the stored state is at lt {} and the pool at lt {}; run `tosctl shield sync --name \
         {name}` first",
        cursor.lt,
        head.last_lt
    );
    Ok(())
}

fn require_verified_same_chain(opened: &Opened, head: &Head) -> anyhow::Result<()> {
    anyhow::ensure!(
        opened.check_head(head)? == HeadRelation::Same,
        "the state was built on an RPC endpoint's word and the verifier now answers; run `tosctl \
         shield sync` first"
    );
    anyhow::ensure!(
        head.verified,
        "a spend is built only on a head the proof verifier authenticated; drop --unverified-rpc"
    );
    Ok(())
}

/// The root a proof is anchored to and the tree the input paths are taken
/// from.
#[derive(Debug)]
struct AnchorChoice {
    kind: u8,
    id: u32,
    root: Fr,
    frontier: Frontier,
}

/// The newest preserved root that covers every input and that the ledger
/// reproduces from its own leaves; failing that, the current root. A
/// preserved root survives later deposits, the current one does not.
fn choose_anchor(ledger: &Ledger, state: &PoolState, plan: &Plan) -> anyhow::Result<AnchorChoice> {
    let highest_input = plan.input_leaves().into_iter().max().context("a plan without inputs")?;
    let leaves = ledger.leaves();
    let mut recent: Vec<_> = state.anchors.recent.iter().collect();
    recent.sort_by_key(|entry| std::cmp::Reverse(entry.id));
    for entry in recent {
        let version = u64::from(entry.id);
        if version <= highest_input || version > u64::try_from(leaves.len())? {
            continue;
        }
        let covered = leaves.get(..usize::try_from(version)?).context("the ledger's leaves")?;
        let (frontier, root) = rebuild(covered)?;
        if fr_to_be(&root) == entry.root {
            return Ok(AnchorChoice { kind: ANCHOR_RECENT, id: entry.id, root, frontier });
        }
    }
    let (frontier, root) = rebuild(leaves)?;
    anyhow::ensure!(
        fr_to_be(&root) == state.commitment_root,
        "the ledger does not reproduce the pool's current root; run `tosctl shield sync`"
    );
    Ok(AnchorChoice { kind: ANCHOR_CURRENT, id: 0, root, frontier })
}

/// The commitment tree holding exactly `leaves`, and its root.
fn rebuild(leaves: &[Fr]) -> anyhow::Result<(Frontier, Fr)> {
    let mut frontier = Frontier::new();
    let mut root = frontier.empty_root();
    for leaf in leaves {
        root = frontier.append(*leaf).map_err(|error| anyhow::anyhow!("rebuild: {error}"))?.1;
    }
    Ok((frontier, root))
}

/// After proving, against the re-read verified head: the inputs are still
/// unspent, the anchored root is still one the pool accepts, and the
/// contract's clock (`shard_gen_utime`) is not near the deadline.
fn check_still_valid(
    ledger: &Ledger,
    state: &PoolState,
    shard_gen_utime: u32,
    anchor: &AnchorChoice,
    nullifiers: &[Fr; 2],
    valid_until: u32,
    intent_digest: &Word,
) -> anyhow::Result<()> {
    let held = format!(
        "the spend (intent {}) is journalled as planned; its inputs stay held until a verified \
         sync shows it settled or its deadline {} passed by the contract's clock. Nothing is \
         rebuilt or resent on its own",
        hex::encode(intent_digest),
        utc(valid_until)
    );
    for nullifier in nullifiers {
        anyhow::ensure!(
            !ledger.published_nullifiers().contains(nullifier),
            "an input of this spend was spent by a transaction that landed while proving; {held}"
        );
    }
    let still_anchored = match anchor.kind {
        ANCHOR_CURRENT => state.commitment_root == fr_to_be(&anchor.root),
        _ => state.anchors.recent_root(anchor.id) == Some(fr_to_be(&anchor.root)),
    };
    anyhow::ensure!(
        still_anchored,
        "the root this spend is anchored to is no longer one the pool accepts (a deposit or \
         spend landed while proving); {held}"
    );
    anyhow::ensure!(
        shard_gen_utime.saturating_add(DEADLINE_MARGIN_SECS) < valid_until,
        "the contract's clock ({}) is within {DEADLINE_MARGIN_SECS} s of the deadline ({}); the \
         spend is not sent; {held}",
        utc(shard_gen_utime),
        utc(valid_until)
    );
    Ok(())
}

fn imt_witness(witness: &imt::Witness) -> NullifierWitness {
    NullifierWitness {
        low_index: witness.low_index,
        low_value: fr_to_be(&witness.low_value),
        low_next_index: witness.low_next_index,
        low_next_value: fr_to_be(&witness.low_next_value),
        low_path: witness.low_path.iter().map(fr_to_be).collect(),
        append_path: witness.append_path.iter().map(fr_to_be).collect(),
    }
}

/// The body the pool receives, from everything assembled and proven.
#[allow(clippy::too_many_arguments)]
fn transact_body(
    assembled: &Assembled,
    proof: &CanonicalProof,
    witnesses: &[imt::Witness; 2],
    anchor: &AnchorChoice,
    valid_until: u32,
    target: &Target,
    plan: &Plan,
) -> anyhow::Result<TransactBody> {
    let public = &assembled.public;
    let intent_digest = fr_to_be(&public.transaction_intent_digest);
    let query_id = u64::from_be_bytes(
        intent_digest[24..].try_into().map_err(|_| anyhow::anyhow!("a digest tail"))?,
    );
    let recipient = match target {
        Target::Withdraw { recipient, .. } => Some(recipient.as_ref().clone()),
        Target::Send { .. } => None,
    };
    let recovery_cell = match &assembled.recovery_payload {
        Some(payload) => shielded_pool::byte_chain(payload)?,
        None => Cell::default(),
    };
    Ok(TransactBody {
        query_id,
        anchor_kind: anchor.kind,
        anchor_id: anchor.id,
        valid_until,
        public_amount_out: plan.public_amount_out,
        withdrawal_fee: plan.withdrawal_fee,
        recipient,
        intent_digest,
        anchor_root: fr_to_be(&public.anchor_root),
        nullifiers: [fr_to_be(&public.nullifier_0), fr_to_be(&public.nullifier_1)],
        note_bodies: [
            fr_to_be(&public.note_body_0),
            fr_to_be(&public.note_body_1),
            fr_to_be(&public.note_body_2),
        ],
        payloads: assembled.payloads.clone(),
        groth16_proof: groth16_proof_cell(&proof.a, &proof.b, &proof.c)?,
        recovery_owner_commitment: fr_to_be(&assembled.recovery_owner_commitment),
        recovery_payload: assembled.recovery_payload.clone(),
        recovery_cell,
        auth_bundle: auth_bundle(
            [&assembled.input_keys[0], &assembled.input_keys[1]],
            [&assembled.signatures[0], &assembled.signatures[1]],
        )?,
        witness_bundle: witness_bundle(&[imt_witness(&witnesses[0]), imt_witness(&witnesses[1])])?,
    })
}

/// A body of the real shape whose every cell is distinct, so the fee bound
/// taken over it counts at least as many cells and bits as the real body: a
/// real body's cells may coincide (two paths sharing an empty subtree's
/// siblings) and are then counted once, a placeholder's never do.
fn placeholder_body(withdrawal: bool) -> anyhow::Result<Cell> {
    let mut stream = 0x9e37_79b9_7f4a_7c15_u64;
    placeholder_body_with(withdrawal, &mut move |out: &mut [u8]| {
        for byte in out.iter_mut() {
            stream = stream
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (stream >> 56) as u8;
        }
    })
}

type Fill<'a> = &'a mut dyn FnMut(&mut [u8]);

fn filled_word(fill: Fill<'_>) -> [u8; 32] {
    let mut out = [0u8; 32];
    fill(&mut out);
    out
}

fn filled_bytes(fill: Fill<'_>, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    fill(&mut out);
    out
}

fn filled_witness(fill: Fill<'_>) -> NullifierWitness {
    NullifierWitness {
        low_index: u32::MAX,
        low_value: filled_word(fill),
        low_next_index: u32::MAX,
        low_next_value: filled_word(fill),
        low_path: (0..IMT_PATH_FIELDS).map(|_| filled_word(fill)).collect(),
        append_path: (0..IMT_PATH_FIELDS).map(|_| filled_word(fill)).collect(),
    }
}

fn placeholder_body_with(withdrawal: bool, fill: Fill<'_>) -> anyhow::Result<Cell> {
    let witnesses = [filled_witness(fill), filled_witness(fill)];
    let recovery_payload = withdrawal.then(|| filled_bytes(fill, OUTPUT_DATA_BYTES));
    let recovery_cell = match &recovery_payload {
        Some(payload) => shielded_pool::byte_chain(payload)?,
        None => Cell::default(),
    };
    let recipient = withdrawal
        .then(|| MsgAddressInt::with_params(0, chain_block::UInt256::from(filled_word(fill))))
        .transpose()?;
    let (public_amount_out, withdrawal_fee) =
        if withdrawal { (shielded_pool::MAX_COINS, shielded_pool::MAX_COINS) } else { (0, 0) };
    let payloads = [
        filled_bytes(fill, OUTPUT_DATA_BYTES),
        filled_bytes(fill, OUTPUT_DATA_BYTES),
        filled_bytes(fill, OUTPUT_DATA_BYTES),
    ];
    let groth16_proof = groth16_proof_cell(
        &filled_bytes(fill, PROOF_A_BYTES),
        &filled_bytes(fill, PROOF_B_BYTES),
        &filled_bytes(fill, PROOF_C_BYTES),
    )?;
    let keys = [filled_bytes(fill, AUTH_KEY_BYTES), filled_bytes(fill, AUTH_KEY_BYTES)];
    let signatures =
        [filled_bytes(fill, AUTH_SIGNATURE_BYTES), filled_bytes(fill, AUTH_SIGNATURE_BYTES)];
    TransactBody {
        query_id: u64::MAX,
        anchor_kind: ANCHOR_RECENT,
        anchor_id: u32::MAX,
        valid_until: u32::MAX,
        public_amount_out,
        withdrawal_fee,
        recipient,
        intent_digest: filled_word(fill),
        anchor_root: filled_word(fill),
        nullifiers: [filled_word(fill), filled_word(fill)],
        note_bodies: [filled_word(fill), filled_word(fill), filled_word(fill)],
        payloads,
        groth16_proof,
        recovery_owner_commitment: filled_word(fill),
        recovery_payload,
        recovery_cell,
        auth_bundle: auth_bundle([&keys[0], &keys[1]], [&signatures[0], &signatures[1]])?,
        witness_bundle: witness_bundle(&witnesses)?,
    }
    .build()
}

#[allow(clippy::too_many_arguments)]
fn print_summary(
    plan: &Plan,
    target: &Target,
    anchor: &AnchorChoice,
    from: &str,
    payer: &MsgAddressInt,
    pool: &MsgAddressInt,
    value: u128,
    reserve: u128,
) {
    let inputs: Vec<String> = plan
        .inputs
        .iter()
        .filter_map(|input| match input {
            plan::PlannedInput::Note(candidate) => {
                Some(format!("{} TOS (leaf {})", tos(candidate.note.amount), candidate.leaf_index))
            }
            plan::PlannedInput::Phantom { .. } => None,
        })
        .collect();
    let change = plan
        .outputs
        .iter()
        .find_map(|output| match output {
            plan::PlannedOutput::Change { amount, .. } => Some(*amount),
            _ => None,
        })
        .unwrap_or(0);
    let (what, to, amount) = match target {
        Target::Withdraw { recipient, .. } => {
            ("Withdrawal", recipient.to_string(), plan.public_amount_out)
        }
        Target::Send { descriptor, .. } => (
            "Transfer",
            format!("descriptor index {}", descriptor.note_key_index),
            plan.outputs
                .iter()
                .find_map(|output| match output {
                    plan::PlannedOutput::Recipient { amount, .. } => Some(*amount),
                    _ => None,
                })
                .unwrap_or(0),
        ),
    };
    println!(
        "\n{}\n  Kind:        {what}\n  To:          {to}\n  Amount:      {} TOS\n  Pool fee:    {} \
         TOS (withdrawal fee, from the notes)\n  Inputs:      {}\n  Change:      {} TOS (back to \
         this instance)\n  Anchor:      {}\n  Broadcast:   {from} ({payer}) to pool {pool}\n  \
         Message:     {} TOS (transact gas at current prices)\n  Wallet fees: {} TOS (upper \
         bound, paid by the wallet on top)\n",
        "Spend summary:".cyan().bold(),
        tos(amount),
        tos(plan.withdrawal_fee),
        inputs.join(" + "),
        tos(change),
        if anchor.kind == ANCHOR_CURRENT {
            "the current root".to_owned()
        } else {
            format!("preserved root version {}", anchor.id)
        },
        tos(value),
        tos(reserve),
    );
    if target.is_withdrawal() {
        println!(
            "{} a withdrawal pays an ordinary address: the recipient, the amount and the time \
             are visible on chain.",
            "note:".bold()
        );
    }
}

/// What a verified state says about one planned spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SpendOutcome {
    /// The pool's accepted intents hold its digest.
    Settled,
    /// One of its nullifiers was published by a transaction that is not it:
    /// an input is gone; the spend can never land and is never released.
    Conflicted,
    /// Not accepted, no input spent, and the contract's clock past the
    /// deadline: the inputs are free again.
    Released,
    /// Nothing is known yet; the inputs are held. The text says how far the
    /// command got.
    Pending(&'static str),
}

impl SpendOutcome {
    pub(super) fn holds_inputs(self) -> bool {
        matches!(self, SpendOutcome::Pending(_) | SpendOutcome::Conflicted)
    }

    pub(super) fn describe(self) -> String {
        match self {
            SpendOutcome::Settled => "accepted by the pool".to_owned(),
            SpendOutcome::Conflicted => {
                "conflicted: an input was spent by another transaction".to_owned()
            }
            SpendOutcome::Released => "released: the deadline passed unspent".to_owned(),
            SpendOutcome::Pending(how_far) => format!("pending ({how_far})"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PendingSpend {
    pub intent_digest: Word,
    pub input_leaves: Vec<u64>,
    pub amount: u128,
    pub recipient: String,
    pub withdrawal: bool,
    pub valid_until: u32,
    pub outcome: SpendOutcome,
}

/// Every planned spend with what the state says about it. `shard_time` is
/// the contract's clock at the state's head; without a verified state
/// nothing is settled or released.
pub(super) fn pending_spends(
    journal: &[JournalRecord],
    ledger: &Ledger,
    shard_time: Option<u32>,
    verified: bool,
) -> Vec<PendingSpend> {
    let accepted: BTreeSet<Word> = ledger.accepted_intents().iter().map(fr_to_be).collect();
    let published: BTreeSet<Word> = ledger.published_nullifiers().iter().map(fr_to_be).collect();
    let mut spends = Vec::new();
    for record in journal {
        let JournalRecord::SpendPlanned {
            intent_digest,
            nullifiers,
            input_leaves,
            amount,
            recipient,
            withdrawal,
            valid_until,
            ..
        } = record
        else {
            continue;
        };
        let how_far = journal
            .iter()
            .filter_map(|later| match later {
                JournalRecord::SpendSigned { intent_digest: digest, message_hash, .. }
                    if digest == intent_digest =>
                {
                    Some(*message_hash)
                }
                _ => None,
            })
            .next_back()
            .map_or("planned; never signed", |message_hash| {
                journal
                    .iter()
                    .rev()
                    .find_map(|later| match later {
                        JournalRecord::SpendBroadcast { message_hash: hash }
                            if *hash == message_hash =>
                        {
                            Some("submitted")
                        }
                        JournalRecord::SpendUnknown { message_hash: hash, .. }
                            if *hash == message_hash =>
                        {
                            Some("broadcast failed, outcome unknown")
                        }
                        _ => None,
                    })
                    .unwrap_or(
                        "signed; outcome unknown (the command may have stopped after sending)",
                    )
            });
        let outcome = if !verified {
            SpendOutcome::Pending(how_far)
        } else if accepted.contains(intent_digest) {
            SpendOutcome::Settled
        } else if nullifiers.iter().any(|nullifier| published.contains(nullifier)) {
            SpendOutcome::Conflicted
        } else if shard_time.is_some_and(|now| now > *valid_until) {
            SpendOutcome::Released
        } else {
            SpendOutcome::Pending(how_far)
        };
        spends.push(PendingSpend {
            intent_digest: *intent_digest,
            input_leaves: input_leaves.clone(),
            amount: coins_value(amount),
            recipient: recipient.clone(),
            withdrawal: *withdrawal,
            valid_until: *valid_until,
            outcome,
        });
    }
    spends
}

/// The leaves no other spend may take.
pub(super) fn held_leaves(spends: &[PendingSpend]) -> BTreeSet<u64> {
    spends
        .iter()
        .filter(|spend| spend.outcome.holds_inputs())
        .flat_map(|spend| spend.input_leaves.iter().copied())
        .collect()
}

pub(super) fn print_pending_spends(spends: &[PendingSpend]) {
    let open: Vec<&PendingSpend> =
        spends.iter().filter(|spend| spend.outcome != SpendOutcome::Settled).collect();
    if open.is_empty() {
        println!("Pending spends: none");
        return;
    }
    for spend in open {
        println!(
            "  {} of {} TOS to {} (intent {}): {}; deadline {}",
            if spend.withdrawal { "withdrawal" } else { "transfer" },
            tos(spend.amount),
            spend.recipient,
            hex::encode(spend.intent_digest),
            spend.outcome.describe(),
            utc(spend.valid_until)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shielded_pool_wallet::ledger::{Event, Payout, Transact};

    fn planned(digest: u8, nullifiers: [u8; 2], leaves: &[u64], valid_until: u32) -> JournalRecord {
        JournalRecord::SpendPlanned {
            intent_digest: [digest; 32],
            nullifiers: [[nullifiers[0]; 32], [nullifiers[1]; 32]],
            input_leaves: leaves.to_vec(),
            indices: vec![],
            amount: coins(5),
            recipient: format!("r{digest}"),
            withdrawal: false,
            valid_until,
            anchor_kind: ANCHOR_CURRENT,
            anchor_id: 0,
        }
    }

    fn signed(digest: u8, message: u8) -> JournalRecord {
        JournalRecord::SpendSigned {
            intent_digest: [digest; 32],
            body_hash: [0; 32],
            message_hash: [message; 32],
            payer: "w".into(),
            value: coins(1),
            boc: vec![],
        }
    }

    /// A ledger that accepted one transact with `digest` and `nullifiers`.
    fn ledger_with(digest: Fr, nullifiers: [Fr; 2]) -> Ledger {
        let mut ledger = Ledger::genesis();
        for _ in 0..2 {
            ledger
                .apply(
                    &Event::Deposit {
                        amount: 1_000_000_000,
                        owner_commitment: Fr::from(7u64),
                        output_data: vec![1; OUTPUT_DATA_BYTES],
                    },
                    1,
                )
                .expect("deposit");
        }
        ledger
            .apply(
                &Event::Transact(Box::new(Transact {
                    intent_digest: digest,
                    nullifiers,
                    note_bodies: [Fr::from(11u64), Fr::from(12u64), Fr::from(13u64)],
                    payloads: [
                        vec![2; OUTPUT_DATA_BYTES],
                        vec![3; OUTPUT_DATA_BYTES],
                        vec![4; OUTPUT_DATA_BYTES],
                    ],
                    public_amount_out: 1_000_000_000,
                    withdrawal_fee: 1,
                    recovery_owner_commitment: Fr::from(9u64),
                    recovery_payload: Some(vec![5; OUTPUT_DATA_BYTES]),
                    payout: Some(Payout {
                        recipient: "0:00".into(),
                        value: 1_000_000_000,
                        body_hash: [0; 32],
                    }),
                })),
                1,
            )
            .expect("transact");
        ledger
    }

    fn fr(word: &Word) -> Fr {
        shielded_pool_circuit::field::fr_from_be(word).expect("field")
    }

    #[test]
    fn a_spend_settles_by_its_intent_conflicts_by_a_nullifier_and_releases_by_the_shard_clock() {
        // Spend 1 was accepted; spend 2 shares a nullifier with it and was
        // not; spend 3 is unknown to the chain.
        let accepted = ledger_with(fr(&[1; 32]), [fr(&[0x21; 32]), fr(&[0x22; 32])]);
        let journal = vec![
            planned(1, [0x21, 0x22], &[0, 1], 1000),
            signed(1, 0x11),
            JournalRecord::SpendBroadcast { message_hash: [0x11; 32] },
            planned(2, [0x22, 0x32], &[1, 2], 1000),
            signed(2, 0x22),
            JournalRecord::SpendUnknown { message_hash: [0x22; 32], error: "down".into() },
            planned(3, [0x41, 0x42], &[3], 1000),
        ];
        let spends = pending_spends(&journal, &accepted, Some(999), true);
        assert_eq!(spends[0].outcome, SpendOutcome::Settled);
        assert_eq!(spends[1].outcome, SpendOutcome::Conflicted);
        assert_eq!(spends[2].outcome, SpendOutcome::Pending("planned; never signed"));
        assert_eq!(held_leaves(&spends), BTreeSet::from([1, 2, 3]), "settled inputs are free");

        // The shard clock at the deadline releases nothing; one past it does,
        // and never a conflicted spend.
        let spends = pending_spends(&journal, &accepted, Some(1000), true);
        assert_eq!(spends[2].outcome, SpendOutcome::Pending("planned; never signed"));
        let spends = pending_spends(&journal, &accepted, Some(1001), true);
        assert_eq!(spends[1].outcome, SpendOutcome::Conflicted);
        assert_eq!(spends[2].outcome, SpendOutcome::Released);
        assert_eq!(held_leaves(&spends), BTreeSet::from([1, 2]));

        // An unverified state settles and releases nothing, whatever it holds.
        let spends = pending_spends(&journal, &accepted, Some(5000), false);
        assert!(spends.iter().all(|spend| matches!(spend.outcome, SpendOutcome::Pending(_))));
        assert_eq!(spends[0].outcome, SpendOutcome::Pending("submitted"));
        assert_eq!(spends[1].outcome, SpendOutcome::Pending("broadcast failed, outcome unknown"));
        assert_eq!(held_leaves(&spends), BTreeSet::from([0, 1, 2, 3]));

        // The crash window between sendBoc and its record.
        let crash = vec![planned(4, [0x51, 0x52], &[4], 1000), signed(4, 0x44)];
        let spends = pending_spends(&crash, &Ledger::genesis(), Some(10), true);
        assert!(matches!(
            spends[0].outcome,
            SpendOutcome::Pending(text) if text.contains("may have stopped after sending")
        ));
    }

    #[test]
    fn the_placeholder_bounds_a_real_body_only_because_its_cells_are_distinct() {
        // A real body whose witnesses share siblings, as real IMT paths do
        // (most levels of a small tree are empty subtrees), and whose coins
        // are short.
        let shared: Vec<[u8; 32]> = (0..IMT_PATH_FIELDS).map(|i| [(i % 7) as u8; 32]).collect();
        let witness = NullifierWitness {
            low_index: 1,
            low_value: [1; 32],
            low_next_index: 0,
            low_next_value: [0; 32],
            low_path: shared.clone(),
            append_path: shared,
        };
        let mut rng = 0x1234_5678_u64;
        let mut random = |len: usize| -> Vec<u8> {
            (0..len)
                .map(|_| {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    (rng >> 24) as u8
                })
                .collect()
        };
        let recovery = random(OUTPUT_DATA_BYTES);
        let real = TransactBody {
            query_id: 7,
            anchor_kind: ANCHOR_CURRENT,
            anchor_id: 0,
            valid_until: 1,
            public_amount_out: 1_000_000_000,
            withdrawal_fee: 10_000_000,
            recipient: Some(
                MsgAddressInt::with_params(0, chain_block::UInt256::from([3; 32])).expect("addr"),
            ),
            intent_digest: [2; 32],
            anchor_root: [1; 32],
            nullifiers: [[4; 32], [5; 32]],
            note_bodies: [[6; 32], [7; 32], [8; 32]],
            payloads: [
                random(OUTPUT_DATA_BYTES),
                random(OUTPUT_DATA_BYTES),
                random(OUTPUT_DATA_BYTES),
            ],
            groth16_proof: groth16_proof_cell(
                &random(PROOF_A_BYTES),
                &random(PROOF_B_BYTES),
                &random(PROOF_C_BYTES),
            )
            .expect("proof"),
            recovery_owner_commitment: [9; 32],
            recovery_cell: shielded_pool::byte_chain(&recovery).expect("chain"),
            recovery_payload: Some(recovery),
            auth_bundle: auth_bundle(
                [&random(AUTH_KEY_BYTES), &random(AUTH_KEY_BYTES)],
                [&random(AUTH_SIGNATURE_BYTES), &random(AUTH_SIGNATURE_BYTES)],
            )
            .expect("auth"),
            witness_bundle: witness_bundle(&[witness.clone(), witness]).expect("witnesses"),
        }
        .build()
        .expect("a real body");
        let (real_cells, real_bits) = send_fees::tree_size(&[&real]).expect("size");

        let bound = placeholder_body(true).expect("placeholder");
        let (bound_cells, bound_bits) = send_fees::tree_size(&[&bound]).expect("size");
        assert!(real_cells <= bound_cells, "{real_cells} cells against a bound of {bound_cells}");
        assert!(real_bits <= bound_bits, "{real_bits} bits against a bound of {bound_bits}");
        assert!(bound_cells > 100, "a transact is a large message: {bound_cells} cells");

        // The same shape filled with zeros is counted once per repeated cell
        // and falls short of the real body.
        let zeros = placeholder_body_with(true, &mut |out: &mut [u8]| out.fill(0))
            .expect("zero placeholder");
        let (zero_cells, _) = send_fees::tree_size(&[&zeros]).expect("size");
        assert!(zero_cells < real_cells, "{zero_cells} zero-filled cells would under-count");

        // A transfer's bound is a transfer's shape: smaller than a
        // withdrawal's, still above a transfer body.
        let transfer_bound = placeholder_body(false).expect("placeholder");
        let (transfer_cells, _) = send_fees::tree_size(&[&transfer_bound]).expect("size");
        assert!(transfer_cells < bound_cells);
    }

    #[test]
    fn the_anchor_is_the_newest_preserved_root_covering_the_inputs_else_the_current_one() {
        use contracts::shielded_pool::{AnchorEntry, AnchorStore, PoolConfig};
        let mut ledger = Ledger::genesis();
        let mut roots = vec![ledger.checkpoint().commitment_root];
        for i in 0..4u64 {
            ledger
                .apply(
                    &Event::Deposit {
                        amount: 1_000_000_000,
                        owner_commitment: Fr::from(100 + i),
                        output_data: vec![i as u8; OUTPUT_DATA_BYTES],
                    },
                    1,
                )
                .expect("deposit");
            roots.push(ledger.checkpoint().commitment_root);
        }
        // Versions 0..4 preserved, as four deposits leave the ring.
        let recent = (0..4u32)
            .map(|id| AnchorEntry { slot: id as u16, id, root: fr_to_be(&roots[id as usize]) })
            .collect();
        let state = PoolState {
            commitment_root: fr_to_be(&roots[4]),
            commitment_next_index: 4,
            reserved_recovery_leaves: 0,
            nullifier_root: [0; 32],
            nullifier_next_index: 1,
            last_anchor_epoch: 0,
            native_liability: 0,
            reserve_floor: 0,
            config: PoolConfig {
                profile_hash: [0; 32],
                poseidon_manifest_hash: [0; 32],
                groth16_vk_hash: [0; 32],
                withdrawal_fee: 1,
                denominations: vec![1_000_000_000],
            },
            verifying_key: vec![],
            anchors: AnchorStore { recent, epoch: vec![] },
        };
        let note = |leaf: u64| Candidate {
            note: shielded_pool_wallet::import::Imported {
                kind: shielded_pool_wallet::delivery::Kind::Ordinary,
                note_key_index: leaf,
                amount: 1_000_000_000,
                note_secret: Fr::from(1u64),
                owner_commitment: Fr::from(2u64),
                note_body: Fr::from(3 + leaf),
                output_data_hash: Fr::from(4u64),
                spendable: true,
                spent: false,
            },
            leaf_index: leaf,
        };
        let plan_with = |leaves: &[u64]| Plan {
            inputs: [
                plan::PlannedInput::Note(note(leaves[0])),
                leaves.get(1).map_or(plan::PlannedInput::Phantom { note_key_index: 50 }, |leaf| {
                    plan::PlannedInput::Note(note(*leaf))
                }),
            ],
            outputs: [
                plan::PlannedOutput::Change { note_key_index: 51, amount: 1 },
                plan::PlannedOutput::Dummy { note_key_index: 52 },
                plan::PlannedOutput::Dummy { note_key_index: 53 },
            ],
            public_amount_out: 0,
            withdrawal_fee: 0,
            recipient_account: None,
            recovery: None,
        };

        // Leaf 0 is covered by version 3 (leaves 0..2), the newest preserved.
        let choice = choose_anchor(&ledger, &state, &plan_with(&[0])).expect("anchor");
        assert_eq!((choice.kind, choice.id), (ANCHOR_RECENT, 3));
        assert_eq!(fr_to_be(&choice.root), fr_to_be(&roots[3]));
        assert_eq!(choice.frontier.next_index(), 3, "the tree the paths are taken from");
        // Leaves 0 and 2 need version 3 too; leaf 3 is in no preserved root.
        let choice = choose_anchor(&ledger, &state, &plan_with(&[0, 2])).expect("anchor");
        assert_eq!(choice.id, 3);
        let choice = choose_anchor(&ledger, &state, &plan_with(&[1, 3])).expect("anchor");
        assert_eq!((choice.kind, choice.id), (ANCHOR_CURRENT, 0));
        assert_eq!(fr_to_be(&choice.root), state.commitment_root);
        assert_eq!(choice.frontier.next_index(), 4);

        // A preserved root the ledger does not reproduce is skipped, and a
        // current root the ledger does not reproduce refuses.
        let mut foreign = state.clone();
        foreign.anchors.recent[3].root = [0xff; 32];
        let choice = choose_anchor(&ledger, &foreign, &plan_with(&[0])).expect("anchor");
        assert_eq!(choice.id, 2, "version 3 was not ours; version 2 still covers leaf 0");
        let choice = choose_anchor(&ledger, &foreign, &plan_with(&[2])).expect("anchor");
        assert_eq!(choice.kind, ANCHOR_CURRENT);
        foreign.commitment_root = [0xee; 32];
        let error = choose_anchor(&ledger, &foreign, &plan_with(&[3])).expect_err("refused");
        assert!(error.to_string().contains("does not reproduce"), "{error}");
    }

    /// The re-check after proving refuses, for its own reason, an input that
    /// was spent meanwhile, an anchor the pool no longer holds, and a
    /// contract clock inside the margin of the deadline; each refusal says
    /// the inputs stay held and nothing is resent.
    #[test]
    fn after_proving_a_spent_input_a_lost_anchor_or_a_near_deadline_refuses_the_send() {
        use contracts::shielded_pool::{AnchorEntry, AnchorStore, PoolConfig};
        let mut ledger = Ledger::genesis();
        let mut roots = vec![ledger.checkpoint().commitment_root];
        for i in 0..2u64 {
            ledger
                .apply(
                    &Event::Deposit {
                        amount: 1_000_000_000,
                        owner_commitment: Fr::from(200 + i),
                        output_data: vec![i as u8; OUTPUT_DATA_BYTES],
                    },
                    1,
                )
                .expect("deposit");
            roots.push(ledger.checkpoint().commitment_root);
        }
        let state = PoolState {
            commitment_root: fr_to_be(&roots[2]),
            commitment_next_index: 2,
            reserved_recovery_leaves: 0,
            nullifier_root: [0; 32],
            nullifier_next_index: 1,
            last_anchor_epoch: 0,
            native_liability: 0,
            reserve_floor: 0,
            config: PoolConfig {
                profile_hash: [0; 32],
                poseidon_manifest_hash: [0; 32],
                groth16_vk_hash: [0; 32],
                withdrawal_fee: 1,
                denominations: vec![1_000_000_000],
            },
            verifying_key: vec![],
            anchors: AnchorStore {
                recent: (0..2u32)
                    .map(|id| AnchorEntry {
                        slot: id as u16,
                        id,
                        root: fr_to_be(&roots[id as usize]),
                    })
                    .collect(),
                epoch: vec![],
            },
        };
        let (frontier, root) = rebuild(ledger.leaves()).expect("current tree");
        let current = AnchorChoice { kind: ANCHOR_CURRENT, id: 0, root, frontier };
        let (frontier, root) = rebuild(&ledger.leaves()[..1]).expect("version 1");
        let recent = AnchorChoice { kind: ANCHOR_RECENT, id: 1, root, frontier };
        let nullifiers = [Fr::from(0x71u64), Fr::from(0x72u64)];
        let valid_until = 10_000;
        let digest = [7; 32];
        let check = |ledger: &Ledger, state: &PoolState, clock: u32, anchor: &AnchorChoice| {
            check_still_valid(ledger, state, clock, anchor, &nullifiers, valid_until, &digest)
        };
        let refused = |result: anyhow::Result<()>, reason: &str| {
            let error = result.expect_err(reason).to_string();
            assert!(error.contains(reason), "{error}");
            assert!(error.contains("stay held"), "{error}");
        };

        check(&ledger, &state, 1000, &current).expect("nothing moved");
        check(&ledger, &state, 1000, &recent).expect("the preserved root holds");

        // An input spent by what landed while proving.
        let spent = ledger_with(Fr::from(5u64), [Fr::from(0x99u64), nullifiers[1]]);
        refused(check(&spent, &state, 1000, &current), "spent by a transaction that landed");

        // A deposit moved the current root; the preserved one is unaffected
        // until the ring drops it.
        let mut moved = state.clone();
        moved.commitment_root = [0xaa; 32];
        refused(check(&ledger, &moved, 1000, &current), "no longer one the pool accepts");
        check(&ledger, &moved, 1000, &recent).expect("still in the ring");
        moved.anchors.recent.retain(|entry| entry.id != 1);
        refused(check(&ledger, &moved, 1000, &recent), "no longer one the pool accepts");

        // The contract's clock must be clear of the deadline by the margin.
        let clear = valid_until - DEADLINE_MARGIN_SECS - 1;
        check(&ledger, &state, clear, &current).expect("just clear");
        refused(check(&ledger, &state, clear + 1, &current), "within");
        refused(check(&ledger, &state, valid_until + 1, &current), "within");
    }

    #[test]
    fn the_ceremony_pin_is_the_profiles() {
        let (hex_pin, pin) = ceremony_vk_pin().expect("pinned");
        assert_eq!(hex::encode(pin), hex_pin);
    }

    /// An assembled spend becomes the body the codec reads back as the same
    /// spend: every public value in its place, the query id the digest's
    /// tail, the recovery material present exactly for a withdrawal.
    #[test]
    fn an_assembled_spend_becomes_the_body_the_codec_reads_back() {
        use shielded_pool_circuit::notes;
        use shielded_pool_wallet::delivery::{self, Kind, Plaintext};
        use shielded_pool_wallet::keys::PoolInstance;

        let domain = Fr::from(0x5e5e_0001u64);
        let alice = PoolInstance::new(&[0x51; 32], domain);
        let bob = PoolInstance::new(&[0x52; 32], domain);
        let mut ledger = Ledger::genesis();
        let mut deposit = |index: u64, amount: u128| {
            let plaintext = Plaintext {
                slot: 0,
                kind: Kind::Ordinary,
                amount,
                note_secret: Fr::from(0x5ec2e7u64 + index),
                owner_nf_key_hash: alice.owner_nf_key_hash(index).expect("owner"),
                note_key_index: index,
                pq_auth_key_hash: alice.pq_auth_key_hash(index).expect("pq"),
            };
            let output_data =
                delivery::seal(&alice.mlkem_encapsulation_key().expect("key"), domain, &plaintext)
                    .expect("seal");
            ledger
                .apply(
                    &Event::Deposit {
                        amount,
                        owner_commitment: notes::owner_commitment(
                            plaintext.owner_nf_key_hash,
                            plaintext.pq_auth_key_hash,
                            plaintext.note_secret,
                        ),
                        output_data,
                    },
                    1,
                )
                .expect("deposit");
        };
        deposit(0, 2_000_000_000);
        deposit(1, 2_000_000_000);
        let outputs = ledger.take_outputs();
        let notes = shielded_pool_wallet::scan::recover_indexed(&alice, &outputs).expect("scan");
        let candidates: Vec<Candidate> = notes
            .spendable_with_leaves()
            .into_iter()
            .map(|(note, leaf)| Candidate { note: *note, leaf_index: leaf.expect("leaf") })
            .collect();
        let mut counter = 0u64;
        let mut fresh = || {
            counter += 1;
            Ok(Fr::from(0xf00d_0000u64 + counter))
        };
        let mut next = 10u64;
        let mut indices = || {
            next += 1;
            Ok(next)
        };
        let proof = CanonicalProof { a: [1; 48], b: [2; 96], c: [3; 48] };

        // A withdrawal of one denomination plus the fee, from both notes.
        let terms = PoolTerms { denominations: vec![3_000_000_000], withdrawal_fee: 7 };
        let recipient =
            MsgAddressInt::with_params(0, chain_block::UInt256::from([0xcc; 32])).expect("addr");
        let target = Target::Withdraw {
            recipient: Box::new(recipient.clone()),
            recipient_account: [0xcc; 32],
        };
        let request = Request::Withdraw { amount: 3_000_000_000, recipient_account: [0xcc; 32] };
        let plan = plan::plan(&terms, &candidates, &request, &mut indices).expect("plan");
        let anchor = choose_anchor(
            &ledger,
            &PoolState {
                commitment_root: fr_to_be(&ledger.checkpoint().commitment_root),
                commitment_next_index: 2,
                reserved_recovery_leaves: 0,
                nullifier_root: [0; 32],
                nullifier_next_index: 1,
                last_anchor_epoch: 0,
                native_liability: 0,
                reserve_floor: 0,
                config: contracts::shielded_pool::PoolConfig {
                    profile_hash: [0; 32],
                    poseidon_manifest_hash: [0; 32],
                    groth16_vk_hash: [0; 32],
                    withdrawal_fee: 7,
                    denominations: vec![3_000_000_000],
                },
                verifying_key: vec![],
                anchors: Default::default(),
            },
            &plan,
        )
        .expect("anchor");
        let valid_until = 1_800_000_600;
        let assembled = assembly::assemble(
            &alice,
            &plan,
            &anchor.frontier,
            &Terms { anchor_root: anchor.root, valid_until, intent_nonce: Fr::from(77u64) },
            &mut fresh,
        )
        .expect("assemble");
        let witnesses =
            assembly::nullifier_witnesses(ledger.nullifier_state(), assembled.nullifiers())
                .expect("witnesses");
        let body =
            transact_body(&assembled, &proof, &witnesses, &anchor, valid_until, &target, &plan)
                .expect("a body");
        let cell = body.build().expect("built");
        let mut slice = chain_block::SliceData::load_cell(cell).expect("slice");
        assert_eq!(slice.get_next_u32().expect("op"), contracts::shielded_pool::OP_TRANSACT);
        let parsed = TransactBody::parse(&mut slice).expect("the codec reads it back");
        let digest = fr_to_be(&assembled.intent_digest());
        assert_eq!(parsed.intent_digest, digest);
        assert_eq!(parsed.query_id.to_be_bytes(), digest[24..]);
        assert_eq!((parsed.anchor_kind, parsed.anchor_id), (ANCHOR_CURRENT, 0));
        assert_eq!(parsed.anchor_root, fr_to_be(&anchor.root));
        assert_eq!(parsed.valid_until, valid_until);
        assert_eq!(parsed.public_amount_out, 3_000_000_000);
        assert_eq!(parsed.withdrawal_fee, 7);
        assert_eq!(parsed.recipient, Some(recipient));
        let nullifiers = assembled.nullifiers();
        assert_eq!(parsed.nullifiers, [fr_to_be(&nullifiers[0]), fr_to_be(&nullifiers[1])]);
        assert_eq!(parsed.note_bodies[2], fr_to_be(&assembled.public.note_body_2));
        assert_eq!(parsed.payloads, assembled.payloads);
        assert_eq!(parsed.recovery_payload, assembled.recovery_payload);
        assert_eq!(
            parsed.recovery_owner_commitment,
            fr_to_be(&assembled.recovery_owner_commitment)
        );
        assert_eq!(
            contracts::shielded_pool::read_byte_chain(
                &parsed.auth_bundle.reference(2).expect("key 1"),
                AUTH_KEY_BYTES
            )
            .expect("key"),
            assembled.input_keys[1].to_vec()
        );
        assert_eq!(parsed.groth16_proof, groth16_proof_cell(&[1; 48], &[2; 96], &[3; 48]).unwrap());

        // A transfer of the same notes: no recipient, no recovery material.
        let to = Descriptor::issue(&bob, 3).expect("descriptor");
        let digest: [u8; 32] = Sha256::digest(to.to_bytes()).into();
        let target = Target::Send { descriptor: Box::new(to.clone()), descriptor_hash: digest };
        let request =
            Request::Transfer { to: Box::new(RecipientKeys::of(&to)), amount: 1_000_000_000 };
        let plan = plan::plan(&terms, &candidates, &request, &mut indices).expect("plan");
        let assembled = assembly::assemble(
            &alice,
            &plan,
            &anchor.frontier,
            &Terms { anchor_root: anchor.root, valid_until, intent_nonce: Fr::from(78u64) },
            &mut fresh,
        )
        .expect("assemble");
        let witnesses =
            assembly::nullifier_witnesses(ledger.nullifier_state(), assembled.nullifiers())
                .expect("witnesses");
        let recent = AnchorChoice {
            kind: ANCHOR_RECENT,
            id: 4097,
            root: anchor.root,
            frontier: anchor.frontier.clone(),
        };
        let body =
            transact_body(&assembled, &proof, &witnesses, &recent, valid_until, &target, &plan)
                .expect("a body");
        let mut slice = chain_block::SliceData::load_cell(body.build().expect("built")).unwrap();
        slice.get_next_u32().expect("op");
        let parsed = TransactBody::parse(&mut slice).expect("the codec reads it back");
        assert_eq!((parsed.anchor_kind, parsed.anchor_id), (ANCHOR_RECENT, 4097));
        assert_eq!(parsed.recipient, None);
        assert_eq!(parsed.recovery_payload, None);
        assert_eq!(parsed.recovery_owner_commitment, [0; 32]);
        assert_eq!(parsed.public_amount_out, 0);
        assert!(!parsed.is_withdrawal());
    }
}
