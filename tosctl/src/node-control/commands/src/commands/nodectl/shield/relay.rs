/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! `shield send --relayer`: a transfer that reaches the pool through a bonded
//! relayer, and `shield status`: what the chain and the relayer say about it.
//!
//! A relayed spend is the same spend as a direct one -- planned from the
//! verified state, reserved, signed, proven, checked again -- with two
//! differences. No configured wallet signs anything: the relayer funds the
//! message from its Bond and is paid inside the spend, by a note to the
//! descriptor its quote named, in output slot 2. And the wallet never
//! touches the network except through the local Tor daemon: every chain read
//! it makes is to a loopback address, and the quote, the submission and any
//! later question go to the onion endpoint the authenticated Bond declared,
//! under one SOCKS isolation identity minted for the session and kept in
//! the journal.
//!
//! What is sent is journalled before it is sent, byte for byte, and never
//! rebuilt. A quote that is not followed by a submission burned the
//! relayer's note index for nothing; it is not reused and not asked for
//! again. A submission with no well-formed acknowledgement is unknown, not
//! failed: the request identity and the status capability are in the
//! journal, and `shield status` asks about exactly that request. The
//! relayer's answer is a claim; only a verified sync settles the spend.

use anyhow::Context;
use base64::Engine;
use br1_client::client::{Client, ClientError, Quote, Status, random_token};
use br1_client::quote::DESCRIPTOR_BYTES;
use br1_client::request::{Candidate as RelayCandidate, MAX_BODY_BYTES, Request as RelayRequest};
use br1_client::socks::{Isolation, TorProxy};
use br1_client::wire;
use chain_block::write_boc;
use colored::Colorize;
use common::app_config::ProofVerifierConfig;
use contracts::proven_getters::ProvenGetterProvider;
use contracts::relayer_bond::BondInit;
use contracts::shielded_pool::ANCHOR_CURRENT;
use rand::RngCore;
use shielded_pool_circuit::field::fr_to_be;
use shielded_pool_prover::INTENT_VALIDITY_WINDOW_SECS;
use shielded_pool_wallet::descriptor::Descriptor;
use shielded_pool_wallet::plan::{self, Fee, Plan, PoolTerms, RecipientKeys, Request};
use shielded_pool_wallet::spend::{self as assembly, Assembled, Terms};
use std::path::{Path, PathBuf};

use super::chain::{self, Head};
use super::relayer::{BondRead, BondReading, RelayerProfile};
use super::spend::{
    self, AnchorChoice, PlannedSpend, Proving, Target, audited_prover, check_still_valid,
    choose_anchor, held_leaves, pending_spends, refuse_unless_spendable,
    require_current_verified_head, require_verified_same_chain, reserve_spend,
    spendable_candidates, transact_body,
};
use super::store::{JournalRecord, Word, coins};
use super::{
    EXPERIMENTAL, Opened, confirm, load_config_vault_rpc_client, open_instance, restore_ledger,
    restore_recovered, sync_instance, tos, unix_now, utc,
};

/// A relayed spend is not submitted when either clock -- the contract's or
/// this machine's -- is this close to the quote's window end or the intent's
/// deadline. The request still has to cross Tor and be funded and included.
pub(super) const RELAY_DEADLINE_MARGIN_SECS: u32 = 60;
/// The output slot the relayer's fee note takes.
pub(super) const FEE_SLOT: u8 = 2;
/// How often the pool and the Bond are re-read until both land on one
/// authenticated checkpoint.
const CHECKPOINT_ATTEMPTS: u8 = 3;

#[derive(clap::Args, Clone)]
pub struct RelayOptions {
    /// The local Tor daemon's SOCKS port
    #[arg(long, default_value_t = 9050)]
    pub(super) tor_port: u16,
    /// Seconds one exchange with the relayer may take, connect to answer
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=60))]
    pub(super) relay_timeout: u64,
    /// Seconds the quote is asked to stay open. The whole spend, proving
    /// included, happens inside this window
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(61..=300))]
    pub(super) quote_lifetime: u64,
    /// Act on the public testnet pool, which is reset without notice
    #[arg(long)]
    pub(super) allow_testnet_pool: bool,
}

/// Where the quote and the request go. The Tor client is the command's
/// relay; a test's records what reaches it.
#[allow(async_fn_in_trait)]
pub(super) trait Relay {
    async fn quote(&self, slot: u8, lifetime: u64, token: &str) -> Result<Quote, ClientError>;
    async fn submit(&self, request: &RelayRequest, quote: &Quote) -> Result<Status, ClientError>;
}

impl Relay for Client {
    async fn quote(&self, slot: u8, lifetime: u64, token: &str) -> Result<Quote, ClientError> {
        Client::quote(self, slot, lifetime, token).await
    }

    async fn submit(&self, request: &RelayRequest, quote: &Quote) -> Result<Status, ClientError> {
        Client::submit(self, request, quote).await
    }
}

/// The contract's clock as last read, and this machine's clock at that
/// moment. Between a read and the moment a request leaves, serialization and
/// durable writes take time; both clocks run at the same rate, so the
/// contract's is projected forward by what this machine's has advanced.
pub(super) struct ShardClock {
    pub local_at_read: u64,
    pub shard_at_read: u32,
}

impl ShardClock {
    fn projected(&self, local_now: u64) -> u32 {
        let elapsed = local_now.saturating_sub(self.local_at_read);
        u32::try_from(u64::from(self.shard_at_read).saturating_add(elapsed)).unwrap_or(u32::MAX)
    }
}

/// Both clocks leave at least `margin` seconds before `window_end`, the end
/// of the quote's window by the relayer's clock. The contract's clock is
/// what the pool judges the intent by; this machine's is what the relayer's
/// window is judged by; neither is trusted to agree with the other.
pub(super) fn require_window_open(
    local_now: u64,
    shard_time: u32,
    window_end: u64,
    margin: u32,
) -> anyhow::Result<()> {
    let margin = u64::from(margin);
    anyhow::ensure!(
        local_now.saturating_add(margin) < window_end,
        "this machine's clock ({}) is within {margin} s of the quote window's end ({})",
        utc(u32::try_from(local_now).unwrap_or(u32::MAX)),
        utc(u32::try_from(window_end).unwrap_or(u32::MAX))
    );
    anyhow::ensure!(
        u64::from(shard_time).saturating_add(margin) < window_end,
        "the contract's clock ({}) is within {margin} s of the quote window's end ({})",
        utc(shard_time),
        utc(u32::try_from(window_end).unwrap_or(u32::MAX))
    );
    Ok(())
}

/// The pool and the Bond at one authenticated checkpoint. The masterchain
/// may move between the two reads; then both are read again.
async fn read_pool_and_bond(
    verifier: &ProofVerifierConfig,
    pool: &chain_block::MsgAddressInt,
    profile: &RelayerProfile,
    init: &BondInit,
) -> anyhow::Result<(Head, BondReading)> {
    let provider = ProvenGetterProvider::new(verifier)?;
    for _ in 0..CHECKPOINT_ATTEMPTS {
        let head = chain::read_head_verified(verifier, pool).await?;
        match super::relayer::read_bond(&provider, &head, profile, init).await? {
            BondRead::AtCheckpoint(bond) => return Ok((head, *bond)),
            BondRead::OtherCheckpoint => {
                eprintln!(
                    "{} the masterchain moved between the pool read and the Bond read; reading \
                     both again",
                    "note:".bold()
                );
            }
        }
    }
    anyhow::bail!(
        "the pool and the Bond were never read at one checkpoint in {CHECKPOINT_ATTEMPTS} \
         attempts; the chain is moving faster than the verifier answers"
    )
}

/// The relayer's fee descriptor, from the authenticated terms: a descriptor
/// of this pool at the index the terms name, and not the recipient's.
fn fee_descriptor(quote: &Quote, opened: &Opened, target: &Target) -> anyhow::Result<Descriptor> {
    let bytes = wire::decode_exact(&quote.terms.descriptor_b64, DESCRIPTOR_BYTES)
        .context("the quote's descriptor encoding")?;
    let descriptor = Descriptor::from_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("the quote's descriptor: {error}"))?;
    descriptor
        .require_domain(opened.domain)
        .map_err(|error| anyhow::anyhow!("the quote's descriptor: {error}"))?;
    anyhow::ensure!(
        descriptor.note_key_index == quote.terms.note_index,
        "the quote's descriptor is at index {} but its terms name {}",
        descriptor.note_key_index,
        quote.terms.note_index
    );
    if let Target::Send { descriptor: recipient, .. } = target {
        anyhow::ensure!(
            recipient.to_bytes() != bytes,
            "the quote's fee descriptor is the recipient's descriptor"
        );
    }
    Ok(descriptor)
}

/// A relay session: the status capability the quote will be bound to and
/// the Tor isolation this session alone uses.
pub(super) struct Session {
    pub tag: Word,
    pub status_token: String,
    pub isolation: Isolation,
}

/// Opens a session: its capability and its isolation are on disk before the
/// daemon is spoken to, so a restart asks about the same request through
/// the same circuit identity and never mints a second capability for it.
pub(super) fn open_session(
    opened: &mut Opened,
    options: &RelayOptions,
    profile: &RelayerProfile,
    endpoint: &br1_client::onion::OnionEndpoint,
    scope: &str,
) -> anyhow::Result<Session> {
    let mut tag: Word = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut tag);
    let status_token = random_token();
    let isolation = Isolation::random();
    opened.append_journal(&JournalRecord::RelayQuoteRequested {
        tag,
        status_token: status_token.clone(),
        isolation_user: isolation.user.clone(),
        isolation_password: isolation.password.clone(),
        tor_port: options.tor_port,
        bond: profile.release.bond.clone(),
        endpoint: endpoint.origin(),
        release_scope: scope.to_owned(),
    })?;
    opened.save_state()?;
    Ok(Session { tag, status_token, isolation })
}

/// Asks the relay for a quote under the session's capability and holds it
/// to the spend: its funding must cover the pool's transact fee, it must
/// name a fee descriptor of this pool that is not the recipient's, and it
/// must leave the margin on both clocks, `now` being this machine's. The
/// authenticated quote is journalled before anything is planned under it; a
/// quote that fails these checks is not.
#[allow(clippy::too_many_arguments)]
pub(super) async fn take_quote<R: Relay>(
    opened: &mut Opened,
    relay: &R,
    session: &Session,
    options: &RelayOptions,
    head: &Head,
    target: &Target,
    transact_fee: u128,
    now: u64,
) -> anyhow::Result<(Quote, Descriptor, u128)> {
    let transact_fee_u64 =
        u64::try_from(transact_fee).context("the transact fee exceeds the message limit")?;
    let quote = relay
        .quote(FEE_SLOT, options.quote_lifetime, &session.status_token)
        .await
        .map_err(|error| anyhow::anyhow!("the relayer's quote: {error}"))?;
    anyhow::ensure!(
        quote.terms.funding_cap >= transact_fee_u64,
        "the relayer's funding cap ({} TOS) is below the pool's transact fee ({} TOS); it would \
         not fund this message",
        tos(u128::from(quote.terms.funding_cap)),
        tos(transact_fee)
    );
    let fee = u128::from(quote.terms.amount);
    let fee_to = fee_descriptor(&quote, opened, target)?;
    require_window_open(
        now,
        head.shard_gen_utime,
        quote.terms.valid_until,
        RELAY_DEADLINE_MARGIN_SECS,
    )?;
    opened.append_journal(&JournalRecord::RelayQuoted {
        tag: session.tag,
        quote_id: quote.identity.clone(),
        envelope: quote.envelope.clone(),
        note_index: quote.terms.note_index,
        fee: coins(fee),
        funding_cap: coins(u128::from(quote.terms.funding_cap)),
        valid_until: u32::try_from(quote.terms.valid_until).context("the quote window end")?,
    })?;
    opened.save_state()?;
    Ok((quote, fee_to, fee))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    name: &str,
    amount: u128,
    target: Target,
    relayer_path: &Path,
    options: &RelayOptions,
    proving: &Proving,
    config_path: &Path,
) -> anyhow::Result<()> {
    eprintln!("{}", EXPERIMENTAL.yellow());
    anyhow::ensure!(!target.is_withdrawal(), "a withdrawal is never relayed");
    let (config, vault, rpc) = load_config_vault_rpc_client(config_path).await?;
    let mut opened = open_instance(config_path, name, &vault).await?;
    opened.network()?.gate(options.allow_testnet_pool)?;
    anyhow::ensure!(
        !proving.read.unverified_rpc,
        "a relayed spend is built only on heads the proof verifier authenticated; drop \
         --unverified-rpc"
    );
    super::relayer::require_loopback_reads(&config)?;
    let verifier = config.proof_verifier.as_ref().context("proof_verifier is not configured")?;

    let profile = RelayerProfile::load(relayer_path)?;
    let init = profile.validate()?;
    let scope = profile.scope()?;
    let endpoint = br1_client::onion::OnionEndpoint::parse(&init.endpoint)?;
    let pool = opened.pointer.profile.address()?;
    let (head, bond) = read_pool_and_bond(verifier, &pool, &profile, &init).await?;
    require_current_verified_head(&opened, &head, name)?;
    profile.bind(&opened.pointer.profile, &head)?;
    bond.require_eligible()?;
    let client = audited_prover(&opened, &head, &proving.ceremony_dir)?;

    // What this wallet may spend: its notes at known leaves, less those a
    // pending spend holds. One spend at a time.
    let ledger = restore_ledger(&opened.state.ledger)?;
    let recovered = restore_recovered(&opened.state)?;
    let shard_time = opened.state.cursor.as_ref().map(|cursor| cursor.shard_gen_utime);
    let pending = pending_spends(&opened.journal, &ledger, shard_time, true);
    refuse_unless_spendable(&opened, name, &target, &pending)?;
    let recipient_label = target.recipient_label();
    let candidates = spendable_candidates(&recovered, &held_leaves(&pending));
    anyhow::ensure!(!candidates.is_empty(), "this instance has no spendable note");

    // The relayer funds the message from its own wallet, with the amount it
    // quoted as its funding cap; that amount must cover the pool's fee.
    let transact_fee = head.transact_fee()?;

    let session = open_session(&mut opened, options, &profile, &endpoint, &scope)?;
    let proxy = TorProxy::new(options.tor_port, session.isolation.clone())?;
    let relay = Client::from_identity(&profile.release, &init, proxy, options.relay_timeout)
        .map_err(|error| anyhow::anyhow!("the relayer client: {error}"))?;
    eprintln!(
        "{} asking {} for a quote through the Tor daemon on port {}",
        "note:".bold(),
        endpoint.authority(),
        options.tor_port
    );
    let (quote, fee_to, fee) = take_quote(
        &mut opened,
        &relay,
        &session,
        options,
        &head,
        &target,
        transact_fee,
        unix_now(),
    )
    .await?;
    let tag = session.tag;

    let Target::Send { descriptor, .. } = &target else {
        anyhow::bail!("a withdrawal is never relayed");
    };
    let terms = PoolTerms {
        denominations: head.state.config.denominations.clone(),
        withdrawal_fee: head.state.config.withdrawal_fee,
    };
    let request = Request::Transfer {
        to: Box::new(RecipientKeys::of(descriptor)),
        amount,
        fee: Some(Fee { to: Box::new(RecipientKeys::of(&fee_to)), amount: fee }),
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

    print!(
        "{}",
        summary_text(&plan, descriptor, &anchor, &profile, &endpoint, &quote, transact_fee)
    );
    if anchor.kind == ANCHOR_CURRENT {
        println!(
            "{} no preserved root covers these inputs, so the proof is anchored to the pool's \
             current root. If any deposit or spend lands before this one, the pool refuses it \
             (exit 152); the inputs then stay held until the deadline passes and the spend has \
             to be planned again. Nothing is rebuilt or resent on its own.",
            "warning:".yellow().bold()
        );
        if !proving.yes && !confirm("Anchor to the current root anyway?")? {
            println!("{}", "Spend cancelled".yellow());
            return Ok(());
        }
    }
    if !proving.yes && !confirm("Confirm relayed spend?")? {
        println!("{}", "Spend cancelled".yellow());
        return Ok(());
    }

    // The window is checked again at the moment the wallet commits itself.
    require_window_open(
        unix_now(),
        head.shard_gen_utime,
        quote.terms.valid_until,
        RELAY_DEADLINE_MARGIN_SECS,
    )?;
    let indices = plan.own_indices();
    opened.append_journal(&JournalRecord::IndicesReserved {
        indices: indices.clone(),
        purpose: "send (relayed)".into(),
    })?;
    let high = indices.iter().max().copied().unwrap_or(0).checked_add(1);
    opened.state.issued_high_water =
        opened.state.issued_high_water.max(high.context("note key index exhausted")?);
    opened.save_state()?;

    // The intent's deadline runs from the contract's clock and never past
    // the quote's window: a request the relayer would refuse as expired is
    // one the pool has given up on too.
    let valid_until = head
        .shard_gen_utime
        .checked_add(INTENT_VALIDITY_WINDOW_SECS)
        .context("the deadline overflows")?
        .min(u32::try_from(quote.terms.valid_until).context("the quote window end")?);
    let intent_nonce = spend::fresh()?;
    let prepared = assembly::prepare(
        &opened.instance,
        &plan,
        &anchor.frontier,
        &Terms { anchor_root: anchor.root, valid_until, intent_nonce },
        &mut || {
            spend::fresh()
                .map_err(|error| shielded_pool_wallet::error::Error::Encoding(error.to_string()))
        },
    )
    .map_err(|error| anyhow::anyhow!("prepare the spend: {error}"))?;
    let intent_digest = fr_to_be(&prepared.intent_digest());
    let nullifiers = prepared.nullifiers();
    let reserved = reserve_spend(
        &mut opened,
        prepared,
        PlannedSpend {
            intent_digest,
            nullifiers: [fr_to_be(&nullifiers[0]), fr_to_be(&nullifiers[1])],
            input_leaves: plan.input_leaves(),
            indices,
            amount,
            recipient: recipient_label,
            withdrawal: false,
            valid_until,
            anchor_kind: anchor.kind,
            anchor_id: anchor.id,
        },
    )?;
    let assembled = reserved.sign(|prepared| {
        prepared.sign(&opened.instance).map_err(|error| anyhow::anyhow!("sign the spend: {error}"))
    })?;

    eprintln!("{} proving; this takes a while", "note:".bold());
    let started = std::time::Instant::now();
    let Assembled { public, witness, .. } = &assembled;
    let proof = client
        .prove(*public, witness.clone(), head.shard_gen_utime)
        .map_err(|error| anyhow::anyhow!("prove: {error}"))?;
    eprintln!("{} proven in {:.1?}", "note:".bold(), started.elapsed());

    // The pool, the Bond and the clocks may have moved while proving. Read
    // the pool and the Bond again at one checkpoint, bring the state up to
    // it, and require everything the proof and the quote assumed to still
    // hold; the nullifier witnesses are built only then, against the tree as
    // it is.
    let (fresh_head, fresh_bond) = read_pool_and_bond(verifier, &pool, &profile, &init).await?;
    let clocks =
        ShardClock { local_at_read: unix_now(), shard_at_read: fresh_head.shard_gen_utime };
    require_verified_same_chain(&opened, &fresh_head)?;
    if fresh_head.last_lt != head.last_lt || fresh_head.last_hash != head.last_hash {
        eprintln!(
            "{} the pool moved while proving (lt {} to {}); replaying what landed",
            "note:".bold(),
            head.last_lt,
            fresh_head.last_lt
        );
        let report = sync_instance(&mut opened, &fresh_head, &rpc).await?;
        anyhow::ensure!(report.verified, "the replayed state is not verified");
    }
    let ledger = restore_ledger(&opened.state.ledger)?;
    let held = format!(
        "the spend (intent {}) is journalled as planned; its inputs stay held until a verified \
         sync shows it settled or its deadline {} passed by the contract's clock. Nothing is \
         rebuilt or resent on its own",
        hex::encode(intent_digest),
        utc(valid_until)
    );
    check_still_valid(
        &ledger,
        &fresh_head.state,
        fresh_head.shard_gen_utime,
        &anchor,
        &nullifiers,
        valid_until,
        &intent_digest,
        RELAY_DEADLINE_MARGIN_SECS,
    )?;
    require_window_open(
        unix_now(),
        fresh_head.shard_gen_utime,
        quote.terms.valid_until,
        RELAY_DEADLINE_MARGIN_SECS,
    )
    .with_context(|| format!("the quote's window closed while proving; {held}"))?;
    fresh_bond
        .require_eligible()
        .with_context(|| format!("the relayer's Bond changed while proving; {held}"))?;
    let fresh_fee = fresh_head.transact_fee()?;
    anyhow::ensure!(
        u64::try_from(fresh_fee).is_ok_and(|fee| fee <= quote.terms.funding_cap),
        "the pool's transact fee rose to {} TOS while proving, above the quote's funding cap of \
         {} TOS; {held}",
        tos(fresh_fee),
        tos(u128::from(quote.terms.funding_cap))
    );
    let witnesses = assembly::nullifier_witnesses(ledger.nullifier_state(), nullifiers)
        .map_err(|error| anyhow::anyhow!("nullifier witnesses: {error}"))?;

    let body = transact_body(&assembled, &proof, &witnesses, &anchor, valid_until, &target, &plan)?
        .build()?;
    let body_hash = *body.repr_hash().as_array();
    let body_bytes = write_boc(&body)?;
    anyhow::ensure!(
        body_bytes.len() <= MAX_BODY_BYTES,
        "the spend body ({} bytes) exceeds what a relayer accepts ({MAX_BODY_BYTES})",
        body_bytes.len()
    );
    let relay_request = RelayRequest {
        release: scope.clone(),
        intent: hex::encode(intent_digest),
        body_b64: base64::engine::general_purpose::STANDARD.encode(&body_bytes),
        body_sha256: wire::hash(&body_bytes),
        nullifiers: [hex::encode(fr_to_be(&nullifiers[0])), hex::encode(fr_to_be(&nullifiers[1]))],
        quote_hash: quote.identity.clone(),
        fee_note_body: hex::encode(fr_to_be(&public.note_body_2)),
        fee_slot: FEE_SLOT,
        fee_note_index: quote.terms.note_index,
        valid_until,
        // The relayer funds the exact amount it quoted and refuses a request
        // whose cap is below it; the cap is the quoted one, no lower.
        funding_cap: quote.terms.funding_cap,
    };
    // The request as the relayer will check it, checked here first.
    let value = serde_json::to_value(&relay_request)?;
    RelayCandidate::check(&value, &scope, &quote.terms_value)
        .map_err(|error| anyhow::anyhow!("the request as the relayer will check it: {error}"))?;

    let journalled =
        journal_request(&mut opened, tag, intent_digest, body_hash, relay_request, quote)?;
    let status = submit_relayed(&mut opened, journalled, &relay, &clocks, unix_now()).await?;
    println!(
        "{} request {} submitted; the relayer claims it is {}{}",
        "OK".green().bold(),
        status.request_id,
        status.status,
        status
            .message_hash
            .as_deref()
            .map_or_else(String::new, |hash| format!(" (message {hash})"))
    );
    println!(
        "A claim is not pool execution: run `tosctl shield sync --name {name}` to see whether the \
         pool accepted intent {}. Its inputs are held until then, or until {} by the contract's \
         clock. `tosctl shield status --name {name} --relayer {} --request {}` asks the relayer \
         again through the same Tor circuit identity.",
        hex::encode(intent_digest),
        utc(valid_until),
        relayer_path.display(),
        status.request_id
    );
    Ok(())
}

/// A request the journal holds, byte for byte, with the quote it answers.
/// Only [`journal_request`] builds one, so nothing is submitted that is not
/// journalled first, and nothing is ever rebuilt.
pub(super) struct JournalledRequest {
    request: RelayRequest,
    request_id: String,
    quote: Quote,
    valid_until: u32,
}

pub(super) fn journal_request(
    opened: &mut Opened,
    tag: Word,
    intent_digest: Word,
    body_hash: Word,
    request: RelayRequest,
    quote: Quote,
) -> anyhow::Result<JournalledRequest> {
    let wire_bytes = request.wire()?;
    let request_id = br1_client::request::identity_of(&wire_bytes);
    opened.append_journal(&JournalRecord::RelayRequestPrepared {
        tag,
        intent_digest,
        request_id: request_id.clone(),
        quote_id: quote.identity.clone(),
        body_hash,
        wire: wire_bytes,
    })?;
    opened.save_state()?;
    let valid_until = request.valid_until;
    Ok(JournalledRequest { request, request_id, quote, valid_until })
}

/// Submits the journalled request once and records what happened. The
/// window is checked with the margin on both clocks at the moment the
/// request is about to leave; a request withheld here, or one the client
/// refuses before connecting, never left this machine and is journalled as
/// withheld. Anything after the request may have left is an unknown
/// outcome, journalled as such. Nothing is retried.
pub(super) async fn submit_relayed<R: Relay>(
    opened: &mut Opened,
    journalled: JournalledRequest,
    relay: &R,
    clocks: &ShardClock,
    now: u64,
) -> anyhow::Result<Status> {
    let JournalledRequest { request, request_id, quote, valid_until } = journalled;
    let window_end = quote.terms.valid_until.min(u64::from(valid_until));
    if let Err(closed) =
        require_window_open(now, clocks.projected(now), window_end, RELAY_DEADLINE_MARGIN_SECS)
    {
        return Err(withhold(opened, &request_id, valid_until, &closed.to_string())?);
    }
    match relay.submit(&request, &quote).await {
        Ok(status) => {
            opened.append_journal(&JournalRecord::RelaySubmitted {
                request_id: request_id.clone(),
                status: status.status.clone(),
                message_hash: status.message_hash.clone(),
            })?;
            opened.save_state()?;
            Ok(status)
        }
        Err(ClientError::Rejected(what)) => Err(withhold(opened, &request_id, valid_until, &what)?),
        Err(error) => {
            opened.append_journal(&JournalRecord::RelayUnknown {
                request_id: request_id.clone(),
                error: error.to_string(),
            })?;
            opened.save_state()?;
            anyhow::bail!(
                "the submission of request {request_id} returned no acknowledgement: {error}. \
                 Whether it reached the relayer is unknown; it is journalled and will not be \
                 rebuilt. Its inputs stay held until `tosctl shield sync` shows the spend \
                 accepted or its deadline ({}) passed; `tosctl shield status` asks the relayer \
                 about exactly this request",
                utc(valid_until)
            )
        }
    }
}

/// Journals that the prepared request was never sent, and says so.
fn withhold(
    opened: &mut Opened,
    request_id: &str,
    valid_until: u32,
    reason: &str,
) -> anyhow::Result<anyhow::Error> {
    opened.append_journal(&JournalRecord::RelayWithheld {
        request_id: request_id.to_owned(),
        reason: reason.to_owned(),
    })?;
    opened.save_state()?;
    Ok(anyhow::anyhow!(
        "the request {request_id} was not submitted: {reason}. Nothing left this machine; the \
         spend is journalled as prepared and withheld, and its inputs stay held until `tosctl \
         shield sync` shows them free or the deadline ({}) passed",
        utc(valid_until)
    ))
}

fn summary_text(
    plan: &Plan,
    recipient: &Descriptor,
    anchor: &AnchorChoice,
    profile: &RelayerProfile,
    endpoint: &br1_client::onion::OnionEndpoint,
    quote: &Quote,
    transact_fee: u128,
) -> String {
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
    format!(
        "\n{}\n  Kind:        Transfer, relayed\n  To:          descriptor index {}\n  Amount:      \
         {} TOS\n  Relayer fee: {} TOS (a note to the relayer's descriptor index {}, slot \
         {FEE_SLOT}, from the notes)\n  Inputs:      {}\n  Change:      {} TOS (back to this \
         instance)\n  Anchor:      {}\n  Relayer:     Bond {} via {}\n  Funding:     {} TOS from \
         the relayer's wallet, as quoted (the pool's transact fee is {} TOS)\n  Quote:       {}, \
         window ends {}\n",
        "Spend summary:".cyan().bold(),
        recipient.note_key_index,
        tos(plan.outputs[0].amount()),
        tos(plan.outputs[2].amount()),
        quote.terms.note_index,
        inputs.join(" + "),
        tos(change),
        if anchor.kind == ANCHOR_CURRENT {
            "the current root".to_owned()
        } else {
            format!("preserved root version {}", anchor.id)
        },
        profile.release.bond,
        endpoint.authority(),
        tos(u128::from(quote.terms.funding_cap)),
        tos(transact_fee),
        quote.identity,
        utc(u32::try_from(quote.terms.valid_until).unwrap_or(u32::MAX)),
    )
}

#[derive(clap::Args, Clone)]
#[command(about = "What the chain and the relayer say about this instance's relayed spends")]
pub struct StatusCmd {
    #[arg(short = 'n', long)]
    name: String,
    /// The relayer profile the spends were relayed through
    #[arg(long)]
    relayer: PathBuf,
    /// One request identity, as `shield send` printed it; all of this
    /// relayer's requests otherwise
    #[arg(long)]
    request: Option<String>,
    /// The local Tor daemon's SOCKS port
    #[arg(long, default_value_t = 9050)]
    tor_port: u16,
    /// Seconds one exchange with the relayer may take, connect to answer
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=60))]
    relay_timeout: u64,
}

/// One relayed request as the journal remembers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RelayedRequest {
    pub request_id: String,
    pub intent_digest: Word,
    pub status_token: String,
    pub isolation: Isolation,
    pub bond: String,
    pub endpoint: String,
    pub release_scope: String,
    /// What the journal recorded of the submission, if it got that far.
    pub submission: Option<String>,
    /// Whether this client withheld the request: it never left this machine
    /// and the relayer is not asked about it.
    pub withheld: bool,
}

/// Every prepared relayed request with the session it belongs to. A request
/// whose session record is missing is a journal this client did not write
/// and is reported, not asked about.
pub(super) fn relayed_requests(journal: &[JournalRecord]) -> anyhow::Result<Vec<RelayedRequest>> {
    let mut requests = Vec::new();
    for record in journal {
        let JournalRecord::RelayRequestPrepared { tag, intent_digest, request_id, .. } = record
        else {
            continue;
        };
        let session = journal
            .iter()
            .find_map(|earlier| match earlier {
                JournalRecord::RelayQuoteRequested {
                    tag: session,
                    status_token,
                    isolation_user,
                    isolation_password,
                    bond,
                    endpoint,
                    release_scope,
                    ..
                } if session == tag => Some((
                    status_token.clone(),
                    Isolation {
                        user: isolation_user.clone(),
                        password: isolation_password.clone(),
                    },
                    bond.clone(),
                    endpoint.clone(),
                    release_scope.clone(),
                )),
                _ => None,
            })
            .with_context(|| {
                format!("request {request_id} has no session record in the journal")
            })?;
        let submission = journal.iter().rev().find_map(|later| match later {
            JournalRecord::RelaySubmitted { request_id: id, status, message_hash }
                if id == request_id =>
            {
                Some((
                    format!(
                        "acknowledged as {status}{}",
                        message_hash
                            .as_deref()
                            .map_or_else(String::new, |hash| format!(" (message {hash})"))
                    ),
                    false,
                ))
            }
            JournalRecord::RelayUnknown { request_id: id, error } if id == request_id => {
                Some((format!("no acknowledgement: {error}"), false))
            }
            JournalRecord::RelayWithheld { request_id: id, reason } if id == request_id => {
                Some((format!("never sent: {reason}"), true))
            }
            _ => None,
        });
        let (submission, withheld) = match submission {
            Some((text, withheld)) => (Some(text), withheld),
            None => (None, false),
        };
        let (status_token, isolation, bond, endpoint, release_scope) = session;
        requests.push(RelayedRequest {
            request_id: request_id.clone(),
            intent_digest: *intent_digest,
            status_token,
            isolation,
            bond,
            endpoint,
            release_scope,
            submission,
            withheld,
        });
    }
    Ok(requests)
}

/// The requests relayed through the relayer a profile describes, and the
/// rest: a request is asked about only under the release scope, Bond and
/// endpoint it was relayed under.
pub(super) fn through_this_relayer(
    all: Vec<RelayedRequest>,
    scope: &str,
    bond: &str,
    endpoint_origin: &str,
) -> (Vec<RelayedRequest>, Vec<RelayedRequest>) {
    all.into_iter().partition(|request| {
        request.release_scope == scope
            && request.bond == bond
            && request.endpoint == endpoint_origin
    })
}

impl StatusCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        eprintln!("{}", EXPERIMENTAL.yellow());
        let (_config, vault, _rpc) = load_config_vault_rpc_client(config_path).await?;
        let opened = open_instance(config_path, &self.name, &vault).await?;
        let profile = RelayerProfile::load(&self.relayer)?;
        let init = profile.validate()?;
        let scope = profile.scope()?;
        let endpoint = br1_client::onion::OnionEndpoint::parse(&init.endpoint)?;

        let ledger = restore_ledger(&opened.state.ledger)?;
        let cursor = opened.state.cursor.as_ref();
        let shard_time = cursor.map(|cursor| cursor.shard_gen_utime);
        let verified = cursor.is_some_and(|cursor| cursor.verified);
        let pending = pending_spends(&opened.journal, &ledger, shard_time, verified);
        let all = relayed_requests(&opened.journal)?;
        let (ours, others) =
            through_this_relayer(all, &scope, &profile.release.bond, &endpoint.origin());
        if let Some(wanted) = &self.request {
            anyhow::ensure!(
                ours.iter().any(|request| &request.request_id == wanted),
                "no request {wanted} was relayed through this relayer from this instance"
            );
        }
        if !others.is_empty() {
            println!(
                "{} request(s) were relayed under another release, Bond or endpoint and are not \
                 asked about with this profile",
                others.len()
            );
        }
        let selected: Vec<&RelayedRequest> = ours
            .iter()
            .filter(|request| self.request.as_ref().is_none_or(|id| id == &request.request_id))
            .collect();
        if selected.is_empty() {
            println!("Relayed requests through this relayer: none");
            return Ok(());
        }
        match cursor {
            Some(cursor) => println!(
                "Chain-side outcomes are as of the last sync (lt {}, {}); run `tosctl shield sync \
                 --name {}` for the current state.",
                cursor.lt,
                if cursor.verified { "verified" } else { "UNVERIFIED" },
                self.name
            ),
            None => println!(
                "This instance was never synced; chain-side outcomes are unknown until `tosctl \
                 shield sync --name {}` runs.",
                self.name
            ),
        }
        for request in selected {
            println!("Request {}", request.request_id);
            println!("  Intent:   {}", hex::encode(request.intent_digest));
            match pending.iter().find(|spend| spend.intent_digest == request.intent_digest) {
                Some(spend) => println!(
                    "  Chain:    {} ({} TOS to {}; deadline {})",
                    spend.outcome.describe(),
                    tos(spend.amount),
                    spend.recipient,
                    utc(spend.valid_until)
                ),
                None => println!("  Chain:    no planned spend carries this intent"),
            }
            println!(
                "  Journal:  {}",
                request.submission.as_deref().unwrap_or("prepared; no submission record")
            );
            if request.withheld {
                println!("  Relayer:  not asked; this request never left this machine");
                continue;
            }
            // The relayer is asked through the session's own circuit identity,
            // never a fresh one, and is answered with a claim.
            let proxy = TorProxy::new(self.tor_port, request.isolation.clone())?;
            let client = Client::from_identity(&profile.release, &init, proxy, self.relay_timeout)
                .map_err(|error| anyhow::anyhow!("the relayer client: {error}"))?;
            match client.status(&request.request_id, &request.status_token).await {
                Ok(status) => {
                    println!(
                        "  Relayer:  claims {}{}{}",
                        status.status,
                        status
                            .message_hash
                            .as_deref()
                            .map_or_else(String::new, |hash| format!(", message {hash}")),
                        status.finality.as_ref().map_or_else(String::new, |finality| {
                            format!(
                                ", finality checkpoint {} proof {}",
                                finality.checkpoint_root, finality.proof_digest
                            )
                        })
                    );
                    println!(
                        "            (a claim; only a verified sync settles the spend{})",
                        if status.is_terminal() { "; the relayer considers it final" } else { "" }
                    );
                }
                Err(error) => println!("  Relayer:  did not answer: {error}"),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_needs_the_margin_on_both_clocks() {
        require_window_open(1_000, 1_000, 1_061, 60).expect("61 s left on both");
        assert!(require_window_open(1_000, 1_000, 1_060, 60).is_err(), "exactly the margin");
        assert!(require_window_open(1_001, 1_000, 1_061, 60).is_err(), "the local clock is ahead");
        assert!(require_window_open(1_000, 1_001, 1_061, 60).is_err(), "the contract's clock is");
        assert!(require_window_open(u64::MAX, 0, u64::MAX, 60).is_err(), "no overflow");
        assert!(
            require_window_open(0, u32::MAX, u64::from(u32::MAX) + 60, 60).is_err(),
            "a contract clock past 2106 still gets no more than the margin"
        );
    }

    fn session(tag: u8) -> JournalRecord {
        JournalRecord::RelayQuoteRequested {
            tag: [tag; 32],
            status_token: format!("t{tag}"),
            isolation_user: format!("u{tag}"),
            isolation_password: format!("p{tag}"),
            tor_port: 9050,
            bond: "0:bond".into(),
            endpoint: "http://relayer.onion".into(),
            release_scope: "scope".into(),
        }
    }

    fn prepared(tag: u8, request: &str) -> JournalRecord {
        JournalRecord::RelayRequestPrepared {
            tag: [tag; 32],
            intent_digest: [tag; 32],
            request_id: request.into(),
            quote_id: "q".into(),
            body_hash: [0; 32],
            wire: vec![],
        }
    }

    #[test]
    fn relayed_requests_carry_their_session_and_last_submission_record() {
        let journal = vec![
            session(1),
            prepared(1, "r1"),
            JournalRecord::RelayUnknown { request_id: "r1".into(), error: "lost".into() },
            session(2),
            prepared(2, "r2"),
            JournalRecord::RelaySubmitted {
                request_id: "r2".into(),
                status: "broadcast".into(),
                message_hash: Some("ab".into()),
            },
            session(3),
            prepared(3, "r3"),
        ];
        let requests = relayed_requests(&journal).expect("every request has its session");
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].status_token, "t1");
        assert_eq!(requests[0].isolation, Isolation { user: "u1".into(), password: "p1".into() });
        assert_eq!(requests[0].submission.as_deref(), Some("no acknowledgement: lost"));
        assert_eq!(requests[1].isolation.user, "u2");
        assert_eq!(
            requests[1].submission.as_deref(),
            Some("acknowledged as broadcast (message ab)")
        );
        assert_eq!(requests[2].submission, None);
        assert_eq!(requests[2].intent_digest, [3; 32]);

        let orphan = vec![prepared(9, "r9")];
        assert!(relayed_requests(&orphan).is_err(), "a request without its session record");
    }

    use super::super::spend::tests::opened_for_tests;
    use br1_client::quote::{self as quote_rules, Terms as QuoteTerms};
    use serde_json::json;
    use shielded_pool_circuit::field::Fr;
    use shielded_pool_circuit::groth16::CanonicalProof;
    use shielded_pool_circuit::notes;
    use shielded_pool_wallet::delivery::{self, Kind, Plaintext};
    use shielded_pool_wallet::keys::PoolInstance;
    use shielded_pool_wallet::ledger::{Event, Ledger};
    use shielded_pool_wallet::plan::Candidate;
    use shielded_pool_wallet::scan;
    use std::cell::RefCell;

    const DOMAIN: u64 = 0x5e5e_0001;
    const SCOPE_BYTE: &str = "ab";
    /// This machine's clock in the tests: every window is relative to it.
    const NOW: u64 = 1_800_000_000;
    const TOKEN: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

    /// Alice with two notes of 2 TOS in a ledger, as the scan finds them.
    fn alice_with_two_notes() -> (PoolInstance, Ledger, Vec<Candidate>) {
        let domain = Fr::from(DOMAIN);
        let alice = PoolInstance::new(&[0x51; 32], domain);
        let mut ledger = Ledger::genesis();
        for index in 0..2u64 {
            let plaintext = Plaintext {
                slot: 0,
                kind: Kind::Ordinary,
                amount: 2_000_000_000,
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
                        amount: 2_000_000_000,
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
        }
        let recovered = scan::recover_indexed(&alice, &ledger.take_outputs()).expect("scan");
        let candidates = spendable_candidates(&recovered, &std::collections::BTreeSet::new());
        (alice, ledger, candidates)
    }

    fn pool_state(ledger: &Ledger) -> contracts::shielded_pool::PoolState {
        contracts::shielded_pool::PoolState {
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
        }
    }

    /// The quote's terms for a fee of `fee` to `descriptor`, and the typed
    /// quote the wallet would hold after authenticating them.
    fn quoted(descriptor: &Descriptor, fee: u64, valid_until: u64) -> Quote {
        let terms_value = json!({
            "schema": quote_rules::TERMS_SCHEMA,
            "release": SCOPE_BYTE.repeat(32),
            "nonce": "11".repeat(32),
            "note_index": descriptor.note_key_index,
            "issued_at": valid_until - 300,
            "valid_until": valid_until,
            "slot": FEE_SLOT,
            "amount": fee,
            "funding_cap": 5_000_000_000u64,
            "descriptor_b64": base64::engine::general_purpose::STANDARD.encode(descriptor.to_bytes()),
            "status_hash": quote_rules::status_hash(TOKEN).expect("hash"),
            "success": quote_rules::SUCCESS,
        });
        let terms: QuoteTerms = serde_json::from_value(terms_value.clone()).expect("terms");
        Quote {
            identity: quote_rules::identity(&terms_value).expect("identity"),
            terms,
            terms_value,
            envelope: Vec::new(),
            status_token: TOKEN.into(),
        }
    }

    /// A real relayed spend body and the request the wallet builds for it.
    fn relayed_request(fee_slot: u8) -> (RelayRequest, Quote, Assembled, Ledger, PoolInstance) {
        let (alice, ledger, candidates) = alice_with_two_notes();
        let domain = Fr::from(DOMAIN);
        let bob = PoolInstance::new(&[0x52; 32], domain);
        let relayer = PoolInstance::new(&[0x53; 32], domain);
        let to = Descriptor::issue(&bob, 7).expect("bob's descriptor");
        let quoted_descriptor = Descriptor::issue(&relayer, 9).expect("the relayer's descriptor");
        let fee = 100_000_000u64;
        let valid_until: u32 = 1_800_000_200;
        let quote = quoted(&quoted_descriptor, fee, 1_800_000_300);
        let request = Request::Transfer {
            to: Box::new(RecipientKeys::of(&to)),
            amount: 1_500_000_000,
            fee: Some(Fee {
                to: Box::new(RecipientKeys::of(&quoted_descriptor)),
                amount: fee.into(),
            }),
        };
        let terms = PoolTerms { denominations: vec![3_000_000_000], withdrawal_fee: 7 };
        let mut next = 10u64;
        let plan = plan::plan(&terms, &candidates, &request, &mut || {
            next += 1;
            Ok(next)
        })
        .expect("plan");
        assert_eq!(plan.outputs[2].amount(), u128::from(fee));
        let anchor = choose_anchor(&ledger, &pool_state(&ledger), &plan).expect("anchor");
        let mut counter = 0u64;
        let assembled = assembly::assemble(
            &alice,
            &plan,
            &anchor.frontier,
            &Terms { anchor_root: anchor.root, valid_until, intent_nonce: Fr::from(77u64) },
            &mut || {
                counter += 1;
                Ok(Fr::from(0xf00d_0000u64 + counter))
            },
        )
        .expect("assemble");
        let witnesses =
            assembly::nullifier_witnesses(ledger.nullifier_state(), assembled.nullifiers())
                .expect("witnesses");
        let proof = CanonicalProof { a: [1; 48], b: [2; 96], c: [3; 48] };
        let target = Target::Send { descriptor: Box::new(to), descriptor_hash: [0; 32] };
        let body =
            transact_body(&assembled, &proof, &witnesses, &anchor, valid_until, &target, &plan)
                .expect("a body")
                .build()
                .expect("built");
        let body_bytes = write_boc(&body).expect("boc");
        let nullifiers = assembled.nullifiers();
        let relay_request = RelayRequest {
            release: SCOPE_BYTE.repeat(32),
            intent: hex::encode(fr_to_be(&assembled.intent_digest())),
            body_b64: base64::engine::general_purpose::STANDARD.encode(&body_bytes),
            body_sha256: wire::hash(&body_bytes),
            nullifiers: [
                hex::encode(fr_to_be(&nullifiers[0])),
                hex::encode(fr_to_be(&nullifiers[1])),
            ],
            quote_hash: quote.identity.clone(),
            fee_note_body: hex::encode(fr_to_be(&assembled.public.note_body_2)),
            fee_slot,
            fee_note_index: 9,
            valid_until,
            funding_cap: quote.terms.funding_cap,
        };
        (relay_request, quote, assembled, ledger, relayer)
    }

    #[test]
    fn the_wallets_request_passes_the_checks_a_relayer_makes_and_pays_the_quoted_index() {
        let (request, quote, assembled, mut ledger, relayer) = relayed_request(FEE_SLOT);
        let scope = SCOPE_BYTE.repeat(32);
        let value = serde_json::to_value(&request).expect("json");
        let candidate =
            RelayCandidate::check(&value, &scope, &quote.terms_value).expect("the real body");
        assert_eq!(candidate.identity, request.identity().expect("identity"));
        assert_eq!(candidate.fee_body, assembled.public.note_body_2);
        assert_eq!(candidate.fee_payload, assembled.payloads[2]);

        // The relayer finds its fee at the quoted index once the spend lands.
        ledger
            .apply(
                &Event::Transact(Box::new(shielded_pool_wallet::ledger::Transact {
                    intent_digest: assembled.intent_digest(),
                    nullifiers: assembled.nullifiers(),
                    note_bodies: [
                        assembled.public.note_body_0,
                        assembled.public.note_body_1,
                        assembled.public.note_body_2,
                    ],
                    payloads: assembled.payloads.clone(),
                    public_amount_out: 0,
                    withdrawal_fee: 0,
                    recovery_owner_commitment: assembled.recovery_owner_commitment,
                    recovery_payload: None,
                    payout: None,
                })),
                1,
            )
            .expect("the transfer lands");
        let found = scan::recover_indexed(&relayer, &ledger.take_outputs()).expect("scan");
        assert_eq!(found.notes.len(), 1);
        assert_eq!((found.notes[0].amount, found.notes[0].note_key_index), (100_000_000, 9));
        assert!(found.notes[0].spendable);

        // Every binding the relayer checks is one the wallet cannot get wrong
        // silently: the slot, the index, the quote, the body bytes.
        let (other_slot, ..) = relayed_request(1);
        let value = serde_json::to_value(&other_slot).expect("json");
        assert!(RelayCandidate::check(&value, &scope, &quote.terms_value).is_err(), "slot");
        let mut other_index = request.clone();
        other_index.fee_note_index = 8;
        let value = serde_json::to_value(&other_index).expect("json");
        assert!(RelayCandidate::check(&value, &scope, &quote.terms_value).is_err(), "index");
        let mut other_quote = request.clone();
        other_quote.quote_hash = "cd".repeat(32);
        let value = serde_json::to_value(&other_quote).expect("json");
        assert!(RelayCandidate::check(&value, &scope, &quote.terms_value).is_err(), "quote");
        let mut altered_body = request.clone();
        let mut bytes =
            base64::engine::general_purpose::STANDARD.decode(&altered_body.body_b64).expect("b64");
        if let Some(last) = bytes.last_mut() {
            *last ^= 1;
        }
        altered_body.body_b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        let value = serde_json::to_value(&altered_body).expect("json");
        assert!(RelayCandidate::check(&value, &scope, &quote.terms_value).is_err(), "bytes");
        // The cap is the quoted one: the relayer funds that exact amount and
        // refuses a request whose cap is below it, after the wallet signed
        // and proved; the client refuses one above it before connecting.
        assert_eq!(request.funding_cap, quote.terms.funding_cap);
        let mut late = request.clone();
        late.valid_until = 1_800_000_301;
        let value = serde_json::to_value(&late).expect("json");
        assert!(RelayCandidate::check(&value, &scope, &quote.terms_value).is_err(), "expiry");
    }

    #[test]
    fn a_fee_descriptor_must_be_this_pools_at_the_quoted_index_and_not_the_recipients() {
        let domain = Fr::from(DOMAIN);
        let (_root, opened) = opened_for_tests(domain);
        let relayer = PoolInstance::new(&[0x53; 32], domain);
        let quoted_descriptor = Descriptor::issue(&relayer, 9).expect("descriptor");
        let bob = Descriptor::issue(&PoolInstance::new(&[0x52; 32], domain), 7).expect("bob");
        let target = Target::Send { descriptor: Box::new(bob.clone()), descriptor_hash: [0; 32] };
        let quote = quoted(&quoted_descriptor, 5, 1_800_000_300);
        let found = fee_descriptor(&quote, &opened, &target).expect("the quoted descriptor");
        assert_eq!(found.to_bytes(), quoted_descriptor.to_bytes());

        let mut other_index = quote.clone();
        other_index.terms.note_index = 8;
        assert!(fee_descriptor(&other_index, &opened, &target).is_err(), "index mismatch");

        let foreign =
            Descriptor::issue(&PoolInstance::new(&[0x53; 32], Fr::from(0x5e5e_0002u64)), 9)
                .expect("descriptor");
        let other_pool = quoted(&foreign, 5, 1_800_000_300);
        assert!(fee_descriptor(&other_pool, &opened, &target).is_err(), "another pool");

        let self_paid = quoted(&bob, 5, 1_800_000_300);
        let error = fee_descriptor(&self_paid, &opened, &target).err().expect("the recipient's");
        assert!(error.to_string().contains("recipient"), "{error}");
    }

    /// A relay that answers as told and records what reached it.
    struct Recorder {
        quote: RefCell<Option<Result<Quote, ClientError>>>,
        answer: RefCell<Option<Result<Status, ClientError>>>,
        /// The capability tokens quotes were asked under.
        tokens: RefCell<Vec<String>>,
        /// The request bytes submitted.
        seen: RefCell<Vec<Vec<u8>>>,
    }

    impl Recorder {
        fn answering(answer: Result<Status, ClientError>) -> Self {
            Self {
                quote: RefCell::new(None),
                answer: RefCell::new(Some(answer)),
                tokens: RefCell::new(Vec::new()),
                seen: RefCell::new(Vec::new()),
            }
        }

        fn quoting(quote: Result<Quote, ClientError>) -> Self {
            Self {
                quote: RefCell::new(Some(quote)),
                answer: RefCell::new(None),
                tokens: RefCell::new(Vec::new()),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl Relay for Recorder {
        async fn quote(&self, slot: u8, _lifetime: u64, token: &str) -> Result<Quote, ClientError> {
            assert_eq!(slot, FEE_SLOT);
            self.tokens.borrow_mut().push(token.to_owned());
            self.quote.borrow_mut().take().expect("one quote")
        }

        async fn submit(
            &self,
            request: &RelayRequest,
            _quote: &Quote,
        ) -> Result<Status, ClientError> {
            self.seen.borrow_mut().push(request.wire().expect("wire"));
            self.answer.borrow_mut().take().expect("one submission")
        }
    }

    fn options() -> RelayOptions {
        RelayOptions {
            tor_port: 9050,
            relay_timeout: 60,
            quote_lifetime: 300,
            allow_testnet_pool: false,
        }
    }

    /// The relayer profile of the relayer tests, and its endpoint and scope.
    fn relayer_profile() -> (RelayerProfile, br1_client::onion::OnionEndpoint, String) {
        let (profile, init) = super::super::relayer::tests::fixture();
        let endpoint = br1_client::onion::OnionEndpoint::parse(&init.endpoint).expect("onion");
        let scope = profile.scope().expect("scope");
        (profile, endpoint, scope)
    }

    /// Clocks read together at `at`, by both the contract and this machine.
    fn clocks(at: u64) -> ShardClock {
        ShardClock { local_at_read: at, shard_at_read: u32::try_from(at).expect("fits") }
    }

    /// A session is on disk, with the capability the relayer is then asked
    /// under, before the relayer is spoken to; the quote is on disk once it
    /// passed every check, and not otherwise.
    #[tokio::test]
    async fn the_session_is_on_disk_before_the_relayer_is_asked_and_the_quote_once_it_passes() {
        let domain = Fr::from(DOMAIN);
        let (_root, mut opened) = opened_for_tests(domain);
        let (profile, endpoint, scope) = relayer_profile();
        let mut head = super::super::chain::tests::head_for_tests();
        head.shard_gen_utime = 1_800_000_000;
        let bob = Descriptor::issue(&PoolInstance::new(&[0x52; 32], domain), 7).expect("bob");
        let target = Target::Send { descriptor: Box::new(bob), descriptor_hash: [0; 32] };
        let relayer = PoolInstance::new(&[0x53; 32], domain);
        let quoted_descriptor = Descriptor::issue(&relayer, 9).expect("descriptor");
        let before = super::super::store::next_issuable_index(&opened.state, &opened.journal)
            .expect("an index");

        // The relayer does not answer: the session is on disk all the same,
        // under the very token it was asked with, and no quote is.
        let session =
            open_session(&mut opened, &options(), &profile, &endpoint, &scope).expect("a session");
        let relay = Recorder::quoting(Err(ClientError::Unavailable("no circuit".into())));
        let error = take_quote(
            &mut opened,
            &relay,
            &session,
            &options(),
            &head,
            &target,
            2_500_000_000,
            NOW,
        )
        .await
        .err()
        .expect("no quote");
        assert!(error.to_string().contains("no circuit"), "{error}");
        let on_disk = opened.store.read_journal().expect("the journal on disk");
        assert_eq!(*relay.tokens.borrow(), vec![session.status_token.clone()]);
        assert!(matches!(
            on_disk.last(),
            Some(JournalRecord::RelayQuoteRequested { tag, status_token, isolation_user, isolation_password, bond, endpoint: origin, release_scope, .. })
                if *tag == session.tag
                    && *status_token == session.status_token
                    && *isolation_user == session.isolation.user
                    && *isolation_password == session.isolation.password
                    && *bond == profile.release.bond
                    && *origin == endpoint.origin()
                    && *release_scope == scope
        ));
        assert!(!on_disk.iter().any(|record| matches!(record, JournalRecord::RelayQuoted { .. })));

        // A quote that does not fund the pool's fee is refused and not kept.
        let relay = Recorder::quoting(Ok(quoted(&quoted_descriptor, 100_000_000, 1_800_000_300)));
        let error = take_quote(
            &mut opened,
            &relay,
            &session,
            &options(),
            &head,
            &target,
            6_000_000_000,
            NOW,
        )
        .await
        .err()
        .expect("too small a cap");
        assert!(error.to_string().contains("funding cap"), "{error}");
        assert!(
            !opened
                .journal
                .iter()
                .any(|record| matches!(record, JournalRecord::RelayQuoted { .. }))
        );

        // A quote that passes is on disk before anything is planned under it.
        let relay = Recorder::quoting(Ok(quoted(&quoted_descriptor, 100_000_000, 1_800_000_300)));
        let (quote, fee_to, fee) = take_quote(
            &mut opened,
            &relay,
            &session,
            &options(),
            &head,
            &target,
            2_500_000_000,
            NOW,
        )
        .await
        .expect("a quote");
        assert_eq!((fee, fee_to.note_key_index), (100_000_000, 9));
        let on_disk = opened.store.read_journal().expect("the journal on disk");
        assert!(matches!(
            on_disk.last(),
            Some(JournalRecord::RelayQuoted { tag, quote_id, note_index, fee, valid_until, .. })
                if *tag == session.tag && *quote_id == quote.identity && *note_index == 9
                    && *fee == coins(100_000_000) && *valid_until == 1_800_000_300
        ));
        // The relayer's index is the relayer's; this instance issued none.
        assert_eq!(
            super::super::store::next_issuable_index(&opened.state, &opened.journal)
                .expect("an index"),
            before
        );

        // A run that stops here holds nothing and asks about nothing.
        let ledger = Ledger::genesis();
        assert!(pending_spends(&opened.journal, &ledger, Some(1_800_000_000), true).is_empty());
        assert!(relayed_requests(&opened.journal).expect("sessions").is_empty());
    }

    /// Just before the request leaves, both clocks must still leave the
    /// margin; a request that would arrive inside it is withheld, journalled
    /// as such, and never reaches the relay.
    #[tokio::test]
    async fn a_request_whose_window_closed_while_journalling_is_withheld_unsent() {
        let (request, quote, assembled, _, _) = relayed_request(FEE_SLOT);
        let request_id = request.identity().expect("identity");
        let intent = fr_to_be(&assembled.intent_digest());
        let (_root, mut opened) = opened_for_tests(Fr::from(DOMAIN));
        let (profile, endpoint, scope) = relayer_profile();
        let session =
            open_session(&mut opened, &options(), &profile, &endpoint, &scope).expect("a session");
        let journalled =
            journal_request(&mut opened, session.tag, intent, [1; 32], request, quote.clone())
                .expect("journalled");
        // Read at 1_800_000_000 on both clocks; the window ends at the
        // intent's 1_800_000_200. Journalling took 150 s: 50 s are left,
        // under the 60 s margin, on the contract's clock as projected.
        let relay = Recorder::answering(Ok(claimed(&request_id, "broadcast")));
        let error =
            submit_relayed(&mut opened, journalled, &relay, &clocks(1_800_000_000), 1_800_000_150)
                .await
                .expect_err("withheld");
        assert!(error.to_string().contains("Nothing left this machine"), "{error}");
        assert!(relay.seen.borrow().is_empty(), "nothing was submitted");
        assert!(relay.answer.borrow().is_some(), "the relay was never asked");
        let on_disk = opened.store.read_journal().expect("the journal on disk");
        assert!(matches!(
            on_disk.last(),
            Some(JournalRecord::RelayWithheld { request_id: id, reason })
                if *id == request_id && reason.contains("within 60 s")
        ));
        let requests = relayed_requests(&on_disk).expect("sessions");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].withheld);
        assert!(requests[0].submission.as_deref().is_some_and(|s| s.starts_with("never sent: ")));

        // The same request with 61 s left on both clocks goes out.
        let (request, quote, assembled, _, _) = relayed_request(FEE_SLOT);
        let request_id = request.identity().expect("identity");
        let intent = fr_to_be(&assembled.intent_digest());
        let journalled = journal_request(&mut opened, session.tag, intent, [1; 32], request, quote)
            .expect("journalled");
        let relay = Recorder::answering(Ok(claimed(&request_id, "broadcast")));
        submit_relayed(&mut opened, journalled, &relay, &clocks(1_800_000_000), 1_800_000_139)
            .await
            .expect("sent");
        assert_eq!(relay.seen.borrow().len(), 1);
    }

    /// `status` asks only about requests relayed under this profile's
    /// release scope, Bond and endpoint; the rest are counted, not asked.
    #[test]
    fn status_asks_only_about_requests_relayed_through_this_relayer() {
        let mut other_scope = session(1);
        if let JournalRecord::RelayQuoteRequested { release_scope, .. } = &mut other_scope {
            *release_scope = "other".into();
        }
        let mut other_bond = session(2);
        if let JournalRecord::RelayQuoteRequested { bond, .. } = &mut other_bond {
            *bond = "0:other".into();
        }
        let mut other_endpoint = session(3);
        if let JournalRecord::RelayQuoteRequested { endpoint, .. } = &mut other_endpoint {
            *endpoint = "http://other.onion".into();
        }
        let journal = vec![
            other_scope,
            prepared(1, "r1"),
            other_bond,
            prepared(2, "r2"),
            other_endpoint,
            prepared(3, "r3"),
            session(4),
            prepared(4, "r4"),
        ];
        let all = relayed_requests(&journal).expect("sessions");
        let (ours, others) = through_this_relayer(all, "scope", "0:bond", "http://relayer.onion");
        assert_eq!(ours.iter().map(|r| r.request_id.as_str()).collect::<Vec<_>>(), ["r4"]);
        assert_eq!(others.len(), 3, "a mismatched release, Bond or endpoint each");
    }

    fn claimed(request_id: &str, status: &str) -> Status {
        Status {
            schema: br1_client::client::STATUS_SCHEMA.into(),
            request_id: request_id.into(),
            release: SCOPE_BYTE.repeat(32),
            status: status.into(),
            message_hash: Some("0c".repeat(32)),
            acceptance_b64: None,
            finality: None,
            requires_independent_verification: true,
        }
    }

    #[tokio::test]
    async fn a_request_is_journalled_byte_for_byte_before_it_is_submitted_and_its_outcome_after() {
        let (request, quote, assembled, _, _) = relayed_request(FEE_SLOT);
        let wire_bytes = request.wire().expect("wire");
        let request_id = request.identity().expect("identity");
        let intent = fr_to_be(&assembled.intent_digest());
        let (_root, mut opened) = opened_for_tests(Fr::from(DOMAIN));
        let (profile, endpoint, scope) = relayer_profile();
        let session =
            open_session(&mut opened, &options(), &profile, &endpoint, &scope).expect("a session");
        let tag = session.tag;
        let at = clocks(1_800_000_000);

        // Acknowledged: the exact journalled bytes went out, once.
        let journalled =
            journal_request(&mut opened, tag, intent, [1; 32], request.clone(), quote.clone())
                .expect("journalled");
        assert_eq!(journalled.request_id, request_id);
        assert!(matches!(
            opened.journal.last(),
            Some(JournalRecord::RelayRequestPrepared { request_id: id, wire, intent_digest, .. })
                if *id == request_id && *wire == wire_bytes && *intent_digest == intent
        ));
        let relay = Recorder::answering(Ok(claimed(&request_id, "broadcast")));
        let status = submit_relayed(&mut opened, journalled, &relay, &at, 1_800_000_100)
            .await
            .expect("acknowledged");
        assert_eq!(status.status, "broadcast");
        assert_eq!(*relay.seen.borrow(), vec![wire_bytes.clone()]);
        assert!(matches!(
            opened.journal.last(),
            Some(JournalRecord::RelaySubmitted { request_id: id, status, message_hash })
                if *id == request_id && status == "broadcast" && message_hash.as_deref() == Some("0c".repeat(32).as_str())
        ));

        // Unknown: journalled as such, with the error, and reported. Every
        // run prepares a fresh request, so a second attempt has its own id.
        let mut second = request.clone();
        second.intent = "e2".repeat(32);
        let second_id = second.identity().expect("identity");
        let journalled = journal_request(&mut opened, tag, intent, [1; 32], second, quote.clone())
            .expect("journalled");
        let relay = Recorder::answering(Err(ClientError::SubmissionUnknown {
            request_id: second_id.clone(),
            cause: "the circuit closed".into(),
        }));
        let error = submit_relayed(&mut opened, journalled, &relay, &at, 1_800_000_100)
            .await
            .expect_err("unknown");
        assert!(error.to_string().contains("unknown"), "{error}");
        assert!(matches!(
            opened.journal.last(),
            Some(JournalRecord::RelayUnknown { request_id: id, error })
                if *id == second_id && error.contains("the circuit closed")
        ));

        // Refused by the client before connecting: journalled as withheld,
        // never as an outcome.
        let before = opened.journal.len();
        let mut third = request.clone();
        third.intent = "e3".repeat(32);
        let third_id = third.identity().expect("identity");
        let journalled = journal_request(&mut opened, tag, intent, [1; 32], third, quote.clone())
            .expect("journalled");
        let relay = Recorder::answering(Err(ClientError::Rejected("slot".into())));
        let error = submit_relayed(&mut opened, journalled, &relay, &at, 1_800_000_100)
            .await
            .expect_err("rejected");
        assert!(error.to_string().contains("Nothing left this machine"), "{error}");
        assert_eq!(opened.journal.len(), before + 2, "the prepared record and the withheld one");
        assert!(matches!(
            opened.journal.last(),
            Some(JournalRecord::RelayWithheld { request_id: id, reason })
                if *id == third_id && reason == "slot"
        ));

        // A restart reads the same session, capability and bytes back from
        // disk: the status command asks about exactly this request through
        // exactly this circuit identity.
        let reread = opened.store.read_journal().expect("the journal on disk");
        assert_eq!(reread, opened.journal);
        let requests = relayed_requests(&reread).expect("sessions");
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests.iter().map(|r| r.request_id.clone()).collect::<Vec<_>>(),
            vec![request_id.clone(), second_id.clone(), third_id]
        );
        for found in &requests {
            assert_eq!(found.status_token, session.status_token);
            assert_eq!(found.isolation, session.isolation);
            assert_eq!(found.intent_digest, intent);
            assert_eq!(
                (found.release_scope.as_str(), found.bond.as_str()),
                (scope.as_str(), profile.release.bond.as_str())
            );
        }
        assert_eq!(
            requests.iter().map(|r| r.submission.clone()).collect::<Vec<_>>(),
            vec![
                Some(format!("acknowledged as broadcast (message {})", "0c".repeat(32))),
                Some(
                    "no acknowledgement: submission result unavailable; reconcile request \
                      {} (the circuit closed)"
                        .replace("{}", &second_id)
                ),
                Some("never sent: slot".to_owned()),
            ]
        );
        assert_eq!(requests.iter().map(|r| r.withheld).collect::<Vec<_>>(), [false, false, true]);
        let stored_wire = reread
            .iter()
            .find_map(|record| match record {
                JournalRecord::RelayRequestPrepared { wire, .. } => Some(wire.clone()),
                _ => None,
            })
            .expect("the wire bytes");
        assert_eq!(RelayRequest::parse(&stored_wire).expect("parses back"), request);

        // And the pending view of the spend reads the relay records.
        let planned = JournalRecord::SpendPlanned {
            intent_digest: intent,
            nullifiers: [[1; 32], [2; 32]],
            input_leaves: vec![0],
            indices: vec![11, 12],
            amount: coins(1_500_000_000),
            recipient: "descriptor:bob".into(),
            withdrawal: false,
            valid_until: 1_800_000_200,
            anchor_kind: ANCHOR_CURRENT,
            anchor_id: 0,
        };
        let mut journal = vec![planned.clone()];
        journal.extend(reread.iter().cloned());
        let spends = pending_spends(&journal, &Ledger::genesis(), Some(1_800_000_000), true);
        assert_eq!(spends.len(), 1);
        assert!(spends[0].outcome.holds_inputs());
        assert_eq!(
            spends[0].outcome.describe(),
            "pending (prepared for the relayer but never sent; held until the deadline)",
            "the last prepared request was withheld"
        );
        let mut stopped = vec![planned.clone()];
        stopped.extend(reread.iter().take(reread.len() - 1).cloned());
        let spends = pending_spends(&stopped, &Ledger::genesis(), Some(1_800_000_000), true);
        assert_eq!(
            spends[0].outcome.describe(),
            "pending (prepared for the relayer; outcome unknown (the command may have stopped \
             after submitting))",
            "a run that stopped after preparing"
        );
        let mut submitted = vec![planned];
        submitted.extend(reread.iter().take(3).cloned());
        let spends = pending_spends(&submitted, &Ledger::genesis(), Some(1_800_000_000), true);
        assert_eq!(spends[0].outcome.describe(), "pending (submitted to the relayer)");
    }
}
