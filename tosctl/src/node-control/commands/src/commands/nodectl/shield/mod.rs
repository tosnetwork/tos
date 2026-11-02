/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! `tosctl shield`: a client for the shielded pool.
//!
//! The pool publishes no events and keeps no index, so a client is its own
//! indexer: it replays the pool's history into a local ledger, scans the
//! outputs for payloads it can open, and keeps what it found under a key
//! only the pool master derives. This release initialises an instance,
//! synchronises it, shows its balance, issues receiving descriptors and
//! deposits. Spending comes later and will require verified state.
//!
//! The pool master is a separate Vault secret derived from the mnemonic. It
//! derives every shielded key and cannot sign an ordinary transaction, so a
//! shielded instance never needs the wallet's signing key and the wallet
//! never needs to give it up.

mod chain;
mod profile;
mod store;

use anyhow::Context;
use base64::Engine;
use chain_block::{MsgAddressInt, write_boc};
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use chain_rpc_client::v2::data_models::AccountState;
use colored::Colorize;
use common::app_config::AppConfig;
use common::task_cancellation::CancellationCtx;
use contracts::Wallet;
use contracts::shielded_pool::{DepositBody, OUTPUT_DATA_BYTES};
use rand::RngCore;
use secrets_vault::crypto::factory::{AutoCryptoFactory, CryptoFactory};
use secrets_vault::types::secret_id::SecretId;
use secrets_vault::vault::SecretVault;
use shielded_pool_circuit::field::{Fr, fr_from_be, fr_to_be, is_canonical};
use shielded_pool_circuit::{imt, notes, wire};
use shielded_pool_wallet::delivery::{self, Kind, Plaintext};
use shielded_pool_wallet::descriptor::Descriptor;
use shielded_pool_wallet::import::Imported;
use shielded_pool_wallet::keys::{PoolInstance, fr_be32, pool_master};
use shielded_pool_wallet::ledger::{Ledger, Payout, PendingRecovery, Snapshot};
use shielded_pool_wallet::scan::{self, Recovered};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

use super::utils::{
    SEND_TIMEOUT, get_wallet_config, load_config_vault_rpc_client, make_wallet,
    wait_for_seqno_change, wallet_info,
};
use chain::Head;
use profile::{Network, ObservedPool, Profile};
use store::{
    Binding, Cursor, JournalRecord, Keys, PersistedDiagnostic, PersistedLedger, PersistedNote,
    PersistedNullifierLeaf, PersistedPayout, PersistedPendingRecovery, PersistedPoolConfig,
    PersistedState, Pointer, STATE_FORMAT_VERSION, Store, coins, coins_value,
};

const EXPERIMENTAL: &str = "EXPERIMENTAL: the shielded client has not passed its end-to-end gate; use it on an isolated \
     network or at your own risk";
const NANOTOS_PER_TOS: u128 = 1_000_000_000;
/// Diagnostics kept in the state, newest last.
const MAX_DIAGNOSTICS: usize = 256;
/// What a deposit leaves in the paying wallet for its own fees.
const PAYER_MARGIN_NANOTOS: u128 = 50_000_000;

#[derive(clap::Args, Clone)]
#[command(about = "Shielded pool: private balances and transfers (experimental)")]
pub struct ShieldCmd {
    #[arg(
        short = 'c',
        long = "config",
        help = "Path to the configuration file",
        default_value = "tosctl-config.json",
        env = "CONFIG_PATH",
        global = true
    )]
    config: String,

    #[command(subcommand)]
    action: ShieldAction,
}

#[derive(clap::Subcommand, Clone)]
pub enum ShieldAction {
    /// Create a shielded instance for one pool from a mnemonic
    Init(InitCmd),
    /// Replay the pool's history and scan it for this instance's notes
    Sync(SyncCmd),
    /// Show the balance and the state of pending deposits
    Balance(BalanceCmd),
    /// Issue a receiving descriptor at the next unused index
    Address(AddressCmd),
    /// Deposit from an ordinary wallet into a new shielded note
    Deposit(DepositCmd),
}

impl ShieldCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let config_path = Path::new(&self.config);
        match &self.action {
            ShieldAction::Init(cmd) => cmd.run(config_path).await,
            ShieldAction::Sync(cmd) => cmd.run(config_path).await,
            ShieldAction::Balance(cmd) => cmd.run(config_path).await,
            ShieldAction::Address(cmd) => cmd.run(config_path).await,
            ShieldAction::Deposit(cmd) => cmd.run(config_path).await,
        }
    }
}

/// How the pool is read: through the local proof verifier, or from an RPC
/// endpoint without proof.
#[derive(clap::Args, Clone)]
pub struct ReadMode {
    /// Read the pool from the RPC endpoint without proof. For isolated local
    /// testing only: the state is marked UNVERIFIED and spends will refuse it.
    #[arg(long)]
    unverified_rpc: bool,
}

impl ReadMode {
    async fn head(
        &self,
        config: &AppConfig,
        rpc: &ClientJsonRpc,
        pool: &MsgAddressInt,
    ) -> anyhow::Result<Head> {
        if self.unverified_rpc {
            eprintln!(
                "{} the pool is read from the RPC endpoint without proof; the result is UNVERIFIED",
                "warning:".yellow().bold()
            );
            return chain::read_head_unverified(rpc, pool).await;
        }
        let verifier = config.proof_verifier.as_ref().context(
            "proof_verifier is not configured; configure the local proof verifier, or pass \
             --unverified-rpc for isolated local testing",
        )?;
        chain::read_head_verified(verifier, pool).await
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Create a shielded instance for one pool from a mnemonic")]
pub struct InitCmd {
    /// Name of the instance; also names the Vault secret `shield-<name>`
    #[arg(short = 'n', long)]
    name: String,
    /// Profile file naming the network, the pool and its code hash
    #[arg(long)]
    profile: PathBuf,
    /// Read the mnemonic from a file you own with mode 0600
    #[arg(long)]
    mnemonic_file: Option<PathBuf>,
    /// Read the mnemonic from an inherited descriptor (0 for standard input)
    #[arg(long)]
    mnemonic_fd: Option<i32>,
    /// Allow a pool on the public testnet (global id 2)
    #[arg(long)]
    allow_testnet_pool: bool,
    #[command(flatten)]
    read: ReadMode,
}

impl InitCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        eprintln!("{}", EXPERIMENTAL.yellow());
        let profile = Profile::load(&self.profile)?;
        let network = Network::of(profile.global_id)?;
        network.gate(self.allow_testnet_pool)?;
        if network == Network::Testnet {
            eprintln!(
                "{} the testnet pool is gated and may be reset without notice",
                "note:".bold()
            );
        }
        let pool = profile.address()?;
        let root = store::shield_root(config_path);
        let pointer_path = store::pointer_path(&root, &self.name)?;
        anyhow::ensure!(
            !pointer_path.exists(),
            "an instance named {:?} already exists ({})",
            self.name,
            pointer_path.display()
        );

        let (config, vault, rpc) = load_config_vault_rpc_client(config_path).await?;
        let head = self.read.head(&config, &rpc, &pool).await?;
        anyhow::ensure!(
            head.global_id == profile.global_id,
            "the chain reports global id {} but the profile names {}",
            head.global_id,
            profile.global_id
        );
        profile::check_pins(
            &profile,
            network,
            &ObservedPool { code_hash: head.code_hash, state: &head.state },
        )?;

        let master = read_pool_master(self.mnemonic_file.as_deref(), self.mnemonic_fd)?;
        let domain = wire::execution_domain(profile.global_id, &profile.account_id()?);
        let keys = Keys::derive(&master, &fr_be32(domain));
        let binding = Binding {
            global_id: profile.global_id,
            pool_address: pool.to_string(),
            chain: head.chain.clone(),
        };
        let store = Store::open(&root, &keys, binding.clone())?;
        anyhow::ensure!(
            !store.has_state(),
            "this mnemonic already has an instance on this pool ({}); one instance per mnemonic \
             and pool, whatever it is named",
            store.directory().display()
        );

        store_pool_master(&vault, &self.name, &master).await?;
        drop(master);

        let state = PersistedState {
            version: STATE_FORMAT_VERSION,
            binding: binding.clone(),
            instance_id: *keys.instance_id(),
            profile: profile.clone(),
            pool_config: pool_config_of(&head),
            cursor: None,
            ledger: persist_ledger(&Ledger::genesis()),
            notes: Vec::new(),
            diagnostics: Vec::new(),
            scan_next_index: 0,
            reused_indices: Vec::new(),
            issued_high_water: 0,
            journal_records: 0,
        };
        store.save_state(&state)?;
        Pointer {
            schema: store::POINTER_SCHEMA.to_owned(),
            profile,
            binding,
            directory: keys.directory_name(),
        }
        .save(&pointer_path)?;
        println!(
            "{} shielded instance {:?} created for pool {} on {} (global id {}); state in {}",
            "OK".green().bold(),
            self.name,
            pool,
            network.label(),
            head.global_id,
            store.directory().display()
        );
        println!("Run `tosctl shield sync --name {}` to replay the pool's history.", self.name);
        Ok(())
    }
}

/// Reads the mnemonic through a protected channel and derives the pool
/// master. Nothing of the mnemonic or the seed survives the call.
fn read_pool_master(file: Option<&Path>, fd: Option<i32>) -> anyhow::Result<Zeroizing<[u8; 64]>> {
    let source = secrets_vault::secret_input::select_source(
        file,
        fd,
        "--mnemonic-file",
        "--mnemonic-fd",
        "Mnemonic (hidden): ",
    )?;
    let text = secrets_vault::secret_input::read_secret(&source)?;
    let trimmed = secrets_vault::secret_input::trim_ascii(&text);
    let phrase =
        std::str::from_utf8(trimmed).map_err(|_| anyhow::anyhow!("mnemonic is not valid UTF-8"))?;
    let mut seed = Zeroizing::new(super::tos_mnemonic::private_seed(phrase, "")?);
    let master = Zeroizing::new(pool_master(&seed));
    seed.zeroize();
    Ok(master)
}

fn secret_id(name: &str) -> SecretId {
    SecretId::from(format!("shield-{name}"))
}

async fn store_pool_master(
    vault: &SecretVault,
    name: &str,
    master: &[u8; 64],
) -> anyhow::Result<()> {
    let id = secret_id(name);
    let metadata = secrets_vault::types::metadata::Metadata::new(
        Some(&id),
        secrets_vault::types::algorithm::Algorithm::None,
        true,
    );
    let secret = secrets_vault::types::secret::Secret::from_raw_data(
        master,
        metadata,
        AutoCryptoFactory {}.new_crypto()?,
    )
    .await?;
    vault
        .put(&secret, secrets_vault::types::store_mode::StoreMode::NewOnly)
        .await
        .with_context(|| format!("store the shield secret shield-{name}"))?;
    vault.flush().await?;
    Ok(())
}

async fn load_pool_master(vault: &SecretVault, name: &str) -> anyhow::Result<Zeroizing<[u8; 64]>> {
    let id = secret_id(name);
    let secret =
        vault.get(&id).await.with_context(|| format!("read the shield secret shield-{name}"))?;
    let blob = secret.as_blob()?;
    anyhow::ensure!(
        blob.metadata().algorithm == secrets_vault::types::algorithm::Algorithm::None,
        "shield-{name} is not a shield secret"
    );
    let data = blob.data().await?;
    let guard = data.lock().await?;
    anyhow::ensure!(guard.len() == 64, "shield-{name} is not a pool master");
    let mut master = Zeroizing::new([0u8; 64]);
    master.copy_from_slice(&guard[..]);
    Ok(master)
}

/// An opened instance: its public pointer, its keys and its locked store.
struct Opened {
    pointer: Pointer,
    instance: PoolInstance,
    domain: Fr,
    store: Store,
    state: PersistedState,
    journal: Vec<JournalRecord>,
}

async fn open_instance(
    config_path: &Path,
    name: &str,
    vault: &SecretVault,
) -> anyhow::Result<Opened> {
    let root = store::shield_root(config_path);
    let pointer = Pointer::load(&store::pointer_path(&root, name)?)?;
    let master = load_pool_master(vault, name).await?;
    let domain = wire::execution_domain(pointer.profile.global_id, &pointer.profile.account_id()?);
    let keys = Keys::derive(&master, &fr_be32(domain));
    let instance = PoolInstance::from_pool_master(&master, domain);
    drop(master);
    anyhow::ensure!(
        keys.directory_name() == pointer.directory,
        "the pointer for {name:?} names another instance directory"
    );
    let store = Store::open(&root, &keys, pointer.binding.clone())?;
    let state = store.load_state()?.with_context(|| format!("instance {name:?} has no state"))?;
    anyhow::ensure!(
        state.instance_id == *keys.instance_id(),
        "the state belongs to another instance"
    );
    anyhow::ensure!(state.profile == pointer.profile, "the state was written for another profile");
    let journal = store.read_journal()?;
    anyhow::ensure!(
        u64::try_from(journal.len()).unwrap_or(u64::MAX) >= state.journal_records,
        "the journal holds {} records but the state remembers {}: restore both files from the same \
         backup",
        journal.len(),
        state.journal_records
    );
    Ok(Opened { pointer, instance, domain, store, state, journal })
}

impl Opened {
    fn network(&self) -> anyhow::Result<Network> {
        Network::of(self.pointer.profile.global_id)
    }

    /// Requires the head to be the pool this instance was initialised on,
    /// on the chain it was initialised against, still matching the pins.
    fn check_head(&self, head: &Head) -> anyhow::Result<()> {
        anyhow::ensure!(
            head.global_id == self.pointer.profile.global_id,
            "the chain reports global id {} but this instance is on {}",
            head.global_id,
            self.pointer.profile.global_id
        );
        anyhow::ensure!(
            head.chain == self.pointer.binding.chain,
            "the chain identity ({} {}) is not the one this instance was initialised against ({} {})",
            head.chain.source,
            hex::encode(head.chain.root_hash),
            self.pointer.binding.chain.source,
            hex::encode(self.pointer.binding.chain.root_hash)
        );
        profile::check_pins(
            &self.pointer.profile,
            self.network()?,
            &ObservedPool { code_hash: head.code_hash, state: &head.state },
        )
    }

    fn append_journal(&mut self, record: &JournalRecord) -> anyhow::Result<()> {
        let sequence = u64::try_from(self.journal.len()).context("journal length")?;
        self.store.append_journal(sequence, record)?;
        self.journal.push(record.clone());
        self.state.journal_records = sequence.checked_add(1).context("journal count overflow")?;
        Ok(())
    }

    fn save_state(&self) -> anyhow::Result<()> {
        self.store.save_state(&self.state)
    }

    /// Reserves the next index: journalled, then recorded in the state, both
    /// on disk before the index is used for anything.
    fn reserve_index(&mut self, purpose: &str) -> anyhow::Result<u64> {
        let index = store::next_issuable_index(&self.state, &self.journal)?;
        self.append_journal(&JournalRecord::IndexReserved { index, purpose: purpose.to_owned() })?;
        self.state.issued_high_water = self
            .state
            .issued_high_water
            .max(index.checked_add(1).context("note key index exhausted")?);
        self.save_state()?;
        Ok(index)
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Replay the pool's history and scan it for this instance's notes")]
pub struct SyncCmd {
    #[arg(short = 'n', long)]
    name: String,
    #[command(flatten)]
    read: ReadMode,
}

impl SyncCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        let (config, vault, rpc) = load_config_vault_rpc_client(config_path).await?;
        let mut opened = open_instance(config_path, &self.name, &vault).await?;
        let pool = opened.pointer.profile.address()?;
        let head = self.read.head(&config, &rpc, &pool).await?;
        opened.check_head(&head)?;

        // An unverified prefix is never promoted by an authenticated suffix:
        // when the verifier is available the history is rebuilt from the start.
        let base = match (&opened.state.cursor, head.verified) {
            (Some(cursor), true) if !cursor.verified => {
                eprintln!(
                    "{} the stored state is unverified; rebuilding it from the pool's first \
                     transaction through the proof verifier",
                    "note:".bold()
                );
                None
            }
            (Some(cursor), _) => Some(cursor.clone()),
            (None, _) => None,
        };
        let (ledger, mut recovered, cursor) = match &base {
            Some(cursor) => (
                restore_ledger(&opened.state.ledger)?,
                restore_recovered(&opened.state)?,
                Some((cursor.lt, cursor.hash)),
            ),
            None => (Ledger::genesis(), Recovered::default(), None),
        };
        let replayed_before = base.as_ref().map_or(0, |cursor| cursor.transactions_replayed);

        let history = chain::fetch_history(&rpc, &pool, &head, cursor).await?;
        let steps = u64::try_from(history.steps.len()).context("history length")?;
        let mut replay = chain::replay(ledger, &history, &head)?;

        let outputs = replay.ledger.take_outputs();
        let found = scan::recover_indexed(&opened.instance, &outputs)
            .map_err(|error| anyhow::anyhow!("scan: {error}"))?;
        let new_notes = found.notes.len();
        recovered.merge(found);
        recovered
            .reconcile_spent(&opened.instance, replay.ledger.published_nullifiers())
            .map_err(|error| anyhow::anyhow!("reconcile: {error}"))?;

        let verified = head.verified && base.as_ref().is_none_or(|cursor| cursor.verified);
        let (seqno, root_hash, file_hash) = match &head.checkpoint {
            Some(checkpoint) => {
                (checkpoint.seqno, checkpoint.root_hash.clone(), checkpoint.file_hash.clone())
            }
            None => (0, String::new(), String::new()),
        };
        let state = &mut opened.state;
        state.cursor = Some(Cursor {
            lt: head.last_lt,
            hash: head.last_hash,
            verified,
            checkpoint_seqno: seqno,
            checkpoint_root_hash: root_hash,
            checkpoint_file_hash: file_hash,
            block_gen_utime: head.block_gen_utime,
            transactions_replayed: replayed_before.saturating_add(steps),
        });
        state.ledger = persist_ledger(&replay.ledger);
        state.pool_config = pool_config_of(&head);
        persist_recovered(state, &recovered);
        opened.save_state()?;

        println!(
            "{} {} at masterchain {} ({}): {} transactions replayed ({} applied, {} without state \
             change), {} new notes, {} notes in all",
            "OK".green().bold(),
            if verified {
                "verified".green().to_string()
            } else {
                "UNVERIFIED".yellow().bold().to_string()
            },
            seqno,
            utc(head.block_gen_utime),
            steps,
            replay.applied,
            replay.skipped,
            new_notes,
            recovered.notes.len(),
        );
        print_balance(&recovered, verified);
        Ok(())
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Show the balance and the state of pending deposits")]
pub struct BalanceCmd {
    #[arg(short = 'n', long)]
    name: String,
    /// List each note: amount, leaf, kind and whether it is spent
    #[arg(long)]
    notes: bool,
}

impl BalanceCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        let (_, vault) = super::utils::load_config_vault(config_path).await?;
        let opened = open_instance(config_path, &self.name, &vault).await?;
        let recovered = restore_recovered(&opened.state)?;
        println!(
            "Instance {:?}: pool {} on {} (global id {})",
            self.name,
            opened.pointer.profile.pool_address,
            opened.network()?.label(),
            opened.pointer.profile.global_id
        );
        match &opened.state.cursor {
            Some(cursor) => println!(
                "Synced: {} to lt {} at masterchain {} ({}), {} transactions replayed",
                if cursor.verified {
                    "verified".green().to_string()
                } else {
                    "UNVERIFIED".yellow().bold().to_string()
                },
                cursor.lt,
                cursor.checkpoint_seqno,
                utc(cursor.block_gen_utime),
                cursor.transactions_replayed
            ),
            None => println!("Synced: never; run `tosctl shield sync --name {}`", self.name),
        }
        let verified = opened.state.cursor.as_ref().is_some_and(|cursor| cursor.verified);
        print_balance(&recovered, verified);
        println!(
            "Indices: next {}, {} reused; diagnostics: {}",
            store::next_issuable_index(&opened.state, &opened.journal)?,
            opened.state.reused_indices.len(),
            opened.state.diagnostics.len()
        );
        print_pending(&opened.journal, &recovered);
        if self.notes {
            let leaves = recovered.leaves.iter().copied().chain(std::iter::repeat(None));
            let mut seen = BTreeSet::new();
            for (note, leaf) in recovered.notes.iter().zip(leaves) {
                let duplicate = !seen.insert(fr_to_be(&note.note_body));
                println!(
                    "  index {:>6}  leaf {:>10}  {:<9} {:>22} TOS{}{}",
                    note.note_key_index,
                    leaf.map_or_else(|| "-".to_owned(), |leaf| leaf.to_string()),
                    kind_label(note.kind),
                    tos(note.amount),
                    if note.spent { "  spent" } else { "" },
                    if duplicate { "  duplicate body" } else { "" },
                );
            }
        }
        Ok(())
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Issue a receiving descriptor at the next unused index")]
pub struct AddressCmd {
    #[arg(short = 'n', long)]
    name: String,
}

impl AddressCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        let (_, vault) = super::utils::load_config_vault(config_path).await?;
        let mut opened = open_instance(config_path, &self.name, &vault).await?;
        let index = opened.reserve_index("address")?;
        let descriptor = Descriptor::issue(&opened.instance, index)
            .map_err(|error| anyhow::anyhow!("issue a descriptor: {error}"))?;
        println!(
            "Descriptor for index {index} (valid only for this pool on this network; give it to \
             the payer):"
        );
        println!("{}", base64::engine::general_purpose::STANDARD.encode(descriptor.to_bytes()));
        Ok(())
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Deposit from an ordinary wallet into a new shielded note")]
pub struct DepositCmd {
    #[arg(short = 'n', long)]
    name: String,
    /// Amount in TOS, exactly a pool denomination (for example 10 or 100)
    #[arg(long, conflicts_with = "amount_nanotos")]
    amount: Option<String>,
    /// Amount in nanotos, exactly a pool denomination
    #[arg(long)]
    amount_nanotos: Option<u128>,
    /// The configured wallet that pays
    #[arg(long)]
    from: String,
    /// Do not ask for confirmation
    #[arg(short = 'y', long)]
    yes: bool,
    #[command(flatten)]
    read: ReadMode,
}

impl DepositCmd {
    pub async fn run(&self, config_path: &Path) -> anyhow::Result<()> {
        eprintln!("{}", EXPERIMENTAL.yellow());
        let amount = match (&self.amount, self.amount_nanotos) {
            (Some(text), None) => parse_tos(text)?,
            (None, Some(value)) => value,
            _ => anyhow::bail!("give exactly one of --amount and --amount-nanotos"),
        };
        anyhow::ensure!(amount > 0, "a deposit of zero");

        let (config, vault, rpc) = load_config_vault_rpc_client(config_path).await?;
        let mut opened = open_instance(config_path, &self.name, &vault).await?;
        let pool = opened.pointer.profile.address()?;
        let head = self.read.head(&config, &rpc, &pool).await?;
        opened.check_head(&head)?;
        anyhow::ensure!(
            head.state.config.has_denomination(amount),
            "{} TOS is not a pool denomination; the pool accepts {}",
            tos(amount),
            head.state.config.denominations.iter().map(|d| tos(*d)).collect::<Vec<_>>().join(", ")
        );
        let fee = head.deposit_fee()?;
        let value = amount.checked_add(fee).context("deposit value overflow")?;
        let value_u64 = u64::try_from(value).context("deposit value exceeds the message limit")?;

        let wallet_cfg =
            get_wallet_config(&self.from, &config.wallets, config.master_wallet.as_ref())?;
        let (payer, payer_info, payer_secret) =
            wallet_info(rpc.clone(), wallet_cfg, vault.clone()).await?;
        anyhow::ensure!(
            payer_info.account_state == AccountState::Active,
            "wallet {:?} is not active",
            self.from
        );
        anyhow::ensure!(
            u128::from(payer_info.balance)
                >= value.checked_add(PAYER_MARGIN_NANOTOS).context("overflow")?,
            "wallet {:?} holds {} TOS; the deposit needs {} TOS plus fees",
            self.from,
            tos(u128::from(payer_info.balance)),
            tos(value)
        );
        let wallet = make_wallet(rpc.clone(), wallet_cfg, payer_secret, &self.from).await?;

        println!(
            "\n{}\n  From:        {} ({})\n  Pool:        {}\n  Note amount: {} TOS\n  Pool fee:    {} TOS \
             (deposit gas at current prices)\n  Message:     {} TOS\n",
            "Deposit summary:".cyan().bold(),
            self.from,
            payer,
            pool,
            tos(amount),
            tos(fee),
            tos(value),
        );
        println!(
            "{} a deposit is a public transaction: the paying wallet, the amount and the time are \
             visible on chain and link that wallet to this pool.",
            "note:".bold()
        );
        if !self.yes && !confirm("Confirm deposit?")? {
            println!("{}", "Deposit cancelled".yellow());
            return Ok(());
        }

        // The index is reserved and on disk before anything is derived from it.
        let index = opened.reserve_index("deposit")?;
        let instance = &opened.instance;
        let note_secret = random_field_element()?;
        let owner_nf_key_hash = instance
            .owner_nf_key_hash(index)
            .map_err(|error| anyhow::anyhow!("owner key: {error}"))?;
        let pq_auth_key_hash = instance
            .pq_auth_key_hash(index)
            .map_err(|error| anyhow::anyhow!("auth key: {error}"))?;
        let plaintext = Plaintext {
            slot: 0,
            kind: Kind::Ordinary,
            amount,
            note_secret,
            owner_nf_key_hash,
            note_key_index: index,
            pq_auth_key_hash,
        };
        let owner_commitment =
            notes::owner_commitment(owner_nf_key_hash, pq_auth_key_hash, note_secret);
        let encapsulation_key = instance
            .mlkem_encapsulation_key()
            .map_err(|error| anyhow::anyhow!("encapsulation key: {error}"))?;
        let output_data = delivery::seal(&encapsulation_key, opened.domain, &plaintext)
            .map_err(|error| anyhow::anyhow!("seal the payload: {error}"))?;
        anyhow::ensure!(
            output_data.len() == OUTPUT_DATA_BYTES,
            "a sealed payload of the wrong size"
        );
        let body = DepositBody {
            query_id: unix_now(),
            amount,
            owner_commitment: fr_to_be(&owner_commitment),
            output_data,
        }
        .build()?;
        let body_hash = *body.repr_hash().as_array();

        // Build once, journal the exact bytes, send those bytes.
        let message =
            wallet.build_message(pool.clone(), value_u64, body, true, None, None, None).await?;
        let boc = write_boc(&message)?;
        let message_hash = *message.repr_hash().as_array();
        opened.append_journal(&JournalRecord::DepositPrepared {
            index,
            amount: coins(amount),
            value: coins(value),
            payer: payer.to_string(),
            body_hash,
            message_hash,
            boc: boc.clone(),
        })?;
        opened.save_state()?;

        match rpc.send_boc(&boc).await {
            Ok(()) => {
                opened.append_journal(&JournalRecord::DepositBroadcast { message_hash })?;
                opened.save_state()?;
            }
            Err(error) => {
                opened.append_journal(&JournalRecord::DepositUnknown {
                    message_hash,
                    error: error.to_string(),
                })?;
                opened.save_state()?;
                anyhow::bail!(
                    "the broadcast of message {} failed: {error}. Whether it reached the network \
                     is unknown; it is journalled and will not be rebuilt. Run `tosctl shield \
                     sync` later to see whether the pool minted the note at index {index}.",
                    hex::encode(message_hash)
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
            "{} deposit message {} submitted{}",
            "OK".green().bold(),
            hex::encode(message_hash),
            if seqno_moved {
                "; the wallet's seqno advanced"
            } else {
                "; the wallet's seqno has not advanced yet"
            }
        );
        println!(
            "Submission is not pool execution: run `tosctl shield sync --name {}` to see whether \
             the pool minted the note at index {index}.",
            self.name
        );
        Ok(())
    }
}

fn confirm(prompt: &str) -> anyhow::Result<bool> {
    print!("{prompt} [y/N]: ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn utc(seconds: u32) -> String {
    // Civil time from days since the epoch, Howard Hinnant's algorithm.
    let days = i64::from(seconds) / 86_400;
    let rem = i64::from(seconds) % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3_600, (rem % 3_600) / 60, rem % 60)
}

/// A uniformly random non-zero field element, by rejection on canonical
/// 32-byte strings.
fn random_field_element() -> anyhow::Result<Fr> {
    for _ in 0..1_000 {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(bytes.as_mut());
        if *bytes == [0u8; 32] || !is_canonical(&bytes) {
            continue;
        }
        return fr_from_be(&bytes).map_err(|error| anyhow::anyhow!("field element: {error:?}"));
    }
    anyhow::bail!("the random source never produced a canonical field element")
}

/// Exact decimal TOS to nanotos: digits, an optional point, at most nine
/// fractional digits.
pub(crate) fn parse_tos(text: &str) -> anyhow::Result<u128> {
    let text = text.trim();
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    anyhow::ensure!(
        !(whole.is_empty() && fraction.is_empty())
            && whole.bytes().all(|b| b.is_ascii_digit())
            && fraction.bytes().all(|b| b.is_ascii_digit())
            && fraction.len() <= 9,
        "{text:?} is not an amount in TOS (digits, optionally a point and up to nine decimals)"
    );
    let whole: u128 =
        if whole.is_empty() { 0 } else { whole.parse().context("amount too large")? };
    let mut nanos: u128 =
        if fraction.is_empty() { 0 } else { fraction.parse().context("amount")? };
    for _ in fraction.len()..9 {
        nanos = nanos.checked_mul(10).context("amount")?;
    }
    whole
        .checked_mul(NANOTOS_PER_TOS)
        .and_then(|v| v.checked_add(nanos))
        .context("amount too large")
}

pub(crate) fn tos(nanotos: u128) -> String {
    let whole = nanotos / NANOTOS_PER_TOS;
    let fraction = nanotos % NANOTOS_PER_TOS;
    if fraction == 0 {
        return whole.to_string();
    }
    let digits = format!("{fraction:09}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Ordinary => "ordinary",
        Kind::Dummy => "dummy",
        Kind::Recovery => "recovery",
    }
}

fn kind_code(kind: Kind) -> u8 {
    match kind {
        Kind::Ordinary => 0,
        Kind::Dummy => 1,
        Kind::Recovery => 2,
    }
}

fn kind_of(code: u8) -> anyhow::Result<Kind> {
    match code {
        0 => Ok(Kind::Ordinary),
        1 => Ok(Kind::Dummy),
        2 => Ok(Kind::Recovery),
        other => anyhow::bail!("a note of kind {other}"),
    }
}

fn print_balance(recovered: &Recovered, verified: bool) {
    let spendable = recovered.spendable_notes().count();
    println!(
        "Balance: {} TOS in {} spendable notes{}{}",
        tos(recovered.balance()).bold(),
        spendable,
        if recovered.duplicates() > 0 {
            format!(" ({} duplicate bodies not counted)", recovered.duplicates())
        } else {
            String::new()
        },
        if verified { "" } else { "  [UNVERIFIED]" }
    );
}

/// What the journal says about deposits whose outcome the state may not show.
fn print_pending(journal: &[JournalRecord], recovered: &Recovered) {
    let known: BTreeSet<u64> = recovered.notes.iter().map(|note| note.note_key_index).collect();
    let mut pending = 0usize;
    for record in journal {
        let JournalRecord::DepositPrepared { index, amount, message_hash, .. } = record else {
            continue;
        };
        let outcome = journal.iter().rev().find_map(|later| match later {
            JournalRecord::DepositBroadcast { message_hash: hash } if hash == message_hash => {
                Some("submitted")
            }
            JournalRecord::DepositUnknown { message_hash: hash, .. } if hash == message_hash => {
                Some("broadcast failed, outcome unknown")
            }
            _ => None,
        });
        let landed = known.contains(index);
        if landed {
            continue;
        }
        pending = pending.saturating_add(1);
        println!(
            "  deposit of {} TOS at index {} ({}): no note at this index yet; sync to check",
            tos(coins_value(amount)),
            index,
            outcome.unwrap_or("prepared, never broadcast")
        );
    }
    if pending == 0 {
        println!("Pending deposits: none");
    }
}

fn pool_config_of(head: &Head) -> PersistedPoolConfig {
    PersistedPoolConfig {
        withdrawal_fee: coins(head.state.config.withdrawal_fee),
        denominations: head.state.config.denominations.iter().map(|d| coins(*d)).collect(),
    }
}

fn persist_ledger(ledger: &Ledger) -> PersistedLedger {
    let snapshot = ledger.snapshot();
    PersistedLedger {
        leaves: snapshot.leaves.iter().map(fr_to_be).collect(),
        nullifiers: snapshot.nullifiers.iter().map(fr_to_be).collect(),
        nullifier_tree: snapshot
            .nullifier_tree
            .iter()
            .map(|(index, leaf)| PersistedNullifierLeaf {
                index: *index,
                value: fr_to_be(&leaf.value),
                next_index: leaf.next_index,
                next_value: fr_to_be(&leaf.next_value),
            })
            .collect(),
        nullifier_next_index: snapshot.nullifier_next_index,
        native_liability: coins(snapshot.native_liability),
        reserved_recovery_leaves: snapshot.reserved_recovery_leaves,
        pending: snapshot
            .pending
            .iter()
            .map(|pending| PersistedPendingRecovery {
                payout: PersistedPayout {
                    recipient: pending.payout.recipient.clone(),
                    value: coins(pending.payout.value),
                    body_hash: pending.payout.body_hash,
                },
                owner_commitment: fr_to_be(&pending.owner_commitment),
                payload: pending.payload.clone(),
                consumed: pending.consumed,
            })
            .collect(),
    }
}

fn restore_ledger(persisted: &PersistedLedger) -> anyhow::Result<Ledger> {
    let fr = |word: &[u8; 32]| {
        fr_from_be(word).map_err(|error| anyhow::anyhow!("stored field element: {error:?}"))
    };
    let snapshot = Snapshot {
        leaves: persisted.leaves.iter().map(fr).collect::<anyhow::Result<_>>()?,
        nullifiers: persisted.nullifiers.iter().map(fr).collect::<anyhow::Result<_>>()?,
        nullifier_tree: persisted
            .nullifier_tree
            .iter()
            .map(|leaf| {
                Ok((
                    leaf.index,
                    imt::Leaf {
                        value: fr(&leaf.value)?,
                        next_index: leaf.next_index,
                        next_value: fr(&leaf.next_value)?,
                    },
                ))
            })
            .collect::<anyhow::Result<_>>()?,
        nullifier_next_index: persisted.nullifier_next_index,
        native_liability: coins_value(&persisted.native_liability),
        reserved_recovery_leaves: persisted.reserved_recovery_leaves,
        pending: persisted
            .pending
            .iter()
            .map(|pending| {
                Ok(PendingRecovery {
                    payout: Payout {
                        recipient: pending.payout.recipient.clone(),
                        value: coins_value(&pending.payout.value),
                        body_hash: pending.payout.body_hash,
                    },
                    owner_commitment: fr(&pending.owner_commitment)?,
                    payload: pending.payload.clone(),
                    consumed: pending.consumed,
                })
            })
            .collect::<anyhow::Result<_>>()?,
    };
    Ledger::restore(snapshot).map_err(|error| anyhow::anyhow!("restore the ledger: {error}"))
}

fn persist_recovered(state: &mut PersistedState, recovered: &Recovered) {
    let leaves = recovered.leaves.iter().copied().chain(std::iter::repeat(None));
    state.notes = recovered
        .notes
        .iter()
        .zip(leaves)
        .map(|(note, leaf)| PersistedNote {
            kind: kind_code(note.kind),
            note_key_index: note.note_key_index,
            amount: coins(note.amount),
            note_secret: fr_to_be(&note.note_secret),
            owner_commitment: fr_to_be(&note.owner_commitment),
            note_body: fr_to_be(&note.note_body),
            spendable: note.spendable,
            spent: note.spent,
            leaf,
        })
        .collect();
    let mut diagnostics: Vec<PersistedDiagnostic> = recovered
        .diagnostics
        .iter()
        .map(|diagnostic| PersistedDiagnostic {
            slot: diagnostic.slot,
            why: format!("{:?}", diagnostic.why),
        })
        .collect();
    if diagnostics.len() > MAX_DIAGNOSTICS {
        diagnostics.drain(..diagnostics.len() - MAX_DIAGNOSTICS);
    }
    state.diagnostics = diagnostics;
    state.scan_next_index = recovered.next_note_key_index;
    state.reused_indices = recovered.reused.iter().copied().collect();
    state.issued_high_water = state.issued_high_water.max(recovered.next_note_key_index);
}

fn restore_recovered(state: &PersistedState) -> anyhow::Result<Recovered> {
    let fr = |word: &[u8; 32]| {
        fr_from_be(word).map_err(|error| anyhow::anyhow!("stored field element: {error:?}"))
    };
    let mut notes = Vec::with_capacity(state.notes.len());
    let mut leaves = Vec::with_capacity(state.notes.len());
    for note in &state.notes {
        notes.push(Imported {
            kind: kind_of(note.kind)?,
            note_key_index: note.note_key_index,
            amount: coins_value(&note.amount),
            note_secret: fr(&note.note_secret)?,
            owner_commitment: fr(&note.owner_commitment)?,
            note_body: fr(&note.note_body)?,
            spendable: note.spendable,
            spent: note.spent,
        });
        leaves.push(note.leaf);
    }
    let mut recovered = Recovered::default();
    recovered.merge(Recovered { notes, leaves, ..Recovered::default() });
    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_parse_exactly_and_print_back() {
        assert_eq!(parse_tos("10").expect("10"), 10 * NANOTOS_PER_TOS);
        assert_eq!(parse_tos("0.5").expect("0.5"), 500_000_000);
        assert_eq!(parse_tos("1.000000001").expect("nine decimals"), 1_000_000_001);
        assert_eq!(parse_tos(".25").expect("leading point"), 250_000_000);
        assert!(parse_tos("1.0000000001").is_err(), "ten decimals");
        assert!(parse_tos("-1").is_err());
        assert!(parse_tos("1e9").is_err());
        assert!(parse_tos("").is_err());
        assert!(parse_tos(".").is_err());
        assert_eq!(tos(10 * NANOTOS_PER_TOS), "10");
        assert_eq!(tos(1_000_000_001), "1.000000001");
        assert_eq!(tos(500_000_000), "0.5");
    }

    #[test]
    fn a_ledger_survives_persistence() {
        let mut ledger = Ledger::genesis();
        let instance = PoolInstance::from_pool_master(&[1u8; 64], Fr::from(7u64));
        let owner = instance.owner_nf_key_hash(0).expect("owner");
        let auth = instance.pq_auth_key_hash(0).expect("auth");
        let commitment = notes::owner_commitment(owner, auth, Fr::from(9u64));
        ledger
            .apply(
                &shielded_pool_wallet::ledger::Event::Deposit {
                    amount: NANOTOS_PER_TOS,
                    owner_commitment: commitment,
                    output_data: vec![0x5a; OUTPUT_DATA_BYTES],
                },
                1,
            )
            .expect("deposit");
        let persisted = persist_ledger(&ledger);
        let restored = restore_ledger(&persisted).expect("restore");
        assert_eq!(restored.checkpoint(), ledger.checkpoint());
        assert_eq!(persist_ledger(&restored), persisted);
    }

    #[test]
    fn notes_survive_persistence_and_the_scan_counters_follow() {
        let note = Imported {
            kind: Kind::Ordinary,
            note_key_index: 4,
            amount: 3,
            note_secret: Fr::from(1u64),
            owner_commitment: Fr::from(2u64),
            note_body: Fr::from(3u64),
            spendable: true,
            spent: false,
        };
        let mut recovered = Recovered::default();
        recovered.merge(Recovered {
            notes: vec![note, note],
            leaves: vec![Some(8), None],
            ..Default::default()
        });
        let mut state = PersistedState {
            version: STATE_FORMAT_VERSION,
            binding: Binding {
                global_id: 3,
                pool_address: String::new(),
                chain: store::ChainIdentity {
                    source: String::new(),
                    root_hash: [0; 32],
                    file_hash: [0; 32],
                },
            },
            instance_id: [0; 32],
            profile: Profile {
                schema: profile::PROFILE_SCHEMA.into(),
                global_id: 3,
                pool_address: String::new(),
                pool_code_hash: String::new(),
            },
            pool_config: PersistedPoolConfig { withdrawal_fee: coins(0), denominations: vec![] },
            cursor: None,
            ledger: persist_ledger(&Ledger::genesis()),
            notes: vec![],
            diagnostics: vec![],
            scan_next_index: 0,
            reused_indices: vec![],
            issued_high_water: 2,
            journal_records: 0,
        };
        persist_recovered(&mut state, &recovered);
        assert_eq!(state.notes.len(), 2);
        assert_eq!(state.notes[0].leaf, Some(8));
        assert_eq!(state.scan_next_index, 5);
        assert_eq!(state.issued_high_water, 5, "issuing never falls below the scan");
        assert!(state.reused_indices.is_empty(), "two copies of one body are one use");
        let back = restore_recovered(&state).expect("restore");
        assert_eq!(back.notes, recovered.notes);
        assert_eq!(back.leaves, vec![Some(8), None]);
        assert_eq!(back.balance(), 3, "a duplicate body is counted once");
    }

    #[test]
    fn random_field_elements_are_canonical_and_distinct() {
        let a = random_field_element().expect("a");
        let b = random_field_element().expect("b");
        assert_ne!(a, b);
        assert!(is_canonical(&fr_to_be(&a)));
    }

    #[test]
    fn the_command_line_is_consistent() {
        use clap::Args;
        ShieldCmd::augment_args(clap::Command::new("shield")).debug_assert();
    }

    #[test]
    fn times_print_as_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_793_534_400), "2026-11-01 12:00:00 UTC");
    }
}
