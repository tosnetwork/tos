// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use secrets_vault::{
    crypto::{factory::AutoCryptoFactory, key_material::KeyMaterial, master_key::MasterKey},
    events::null_handler::NullEventHandler,
    memory::protected_memory::ProtectedMemory,
    secret_input,
    storage::file_json::FileJsonStorage,
    types::secret_id::SecretId,
    vault::SecretVault,
};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use wallet_pq_signer::{Role, kdf::DerivationContext};
use zeroize::Zeroizing;

#[derive(Clone, Copy, clap::ValueEnum)]
enum PqRole {
    Primary,
    Rescue,
}
impl PqRole {
    fn native(self) -> Role {
        match self {
            Self::Primary => Role::Primary,
            Self::Rescue => Role::Rescue,
        }
    }
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Restore an enrolled PQ key; this does not deploy a wallet or establish readiness"
)]
pub struct PqRestoreKeyCmd {
    #[arg(long)]
    vault_file: PathBuf,
    #[arg(long)]
    record_id: String,
    #[arg(long, value_enum)]
    role: PqRole,
    /// Public key from independently authenticated enrollment, in hex.
    #[arg(long)]
    expected_public_key: String,
    /// Public 32-byte network tag in hex, from the recovery manifest.
    #[arg(long)]
    network_tag: String,
    #[arg(long, allow_hyphen_values = true)]
    global_id: i32,
    #[arg(long)]
    account_index: u32,
    #[arg(long)]
    key_generation: u32,
    /// Protected mnemonic file; without a file/fd, prompt without echo.
    #[arg(long, conflicts_with = "mnemonic_fd")]
    mnemonic_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "mnemonic_file")]
    mnemonic_fd: Option<i32>,
    /// Exact UTF-8 password bytes, including whitespace/newlines; absent means empty.
    #[arg(long, conflicts_with = "password_fd")]
    password_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "password_file")]
    password_fd: Option<i32>,
    /// Protected file containing the Vault encryption key as 32-byte hex.
    #[arg(long, conflicts_with = "vault_key_fd")]
    vault_key_file: Option<PathBuf>,
    /// Without a file/fd, prompt for the Vault encryption key without echo.
    #[arg(long, conflicts_with = "vault_key_file")]
    vault_key_fd: Option<i32>,
}

impl PqRestoreKeyCmd {
    fn enrollment(&self) -> anyhow::Result<(DerivationContext, Vec<u8>)> {
        anyhow::ensure!(!self.record_id.trim().is_empty(), "record ID must not be empty");
        let key = hex::decode(&self.expected_public_key)
            .map_err(|_| anyhow::anyhow!("expected public key must be hex"))?;
        anyhow::ensure!(
            key.len() == self.role.native().public_key_bytes(),
            "wrong public-key width for PQ role"
        );
        let network = hex::decode(&self.network_tag)
            .map_err(|_| anyhow::anyhow!("network tag must be hex"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("network tag must be 32 bytes"))?;
        // One descriptor cannot independently supply multiple EOF-delimited secrets.
        let fds = [self.mnemonic_fd, self.password_fd, self.vault_key_fd];
        for i in 0..fds.len() {
            for j in 0..i {
                anyhow::ensure!(
                    fds[i].is_none() || fds[i] != fds[j],
                    "secret inputs require distinct file descriptors"
                );
            }
        }
        Ok((
            DerivationContext {
                network,
                global_id: self.global_id,
                account_index: self.account_index,
                key_generation: self.key_generation,
            },
            key,
        ))
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        self.run_with_manifest(None).await
    }

    async fn run_with_manifest(
        &self,
        manifest: Option<&contracts::wallet_v5r2_manifest::InitialRecoveryManifest>,
    ) -> anyhow::Result<()> {
        let (context, expected_key) = self.enrollment()?;
        let phrase_source = secret_input::select_source(
            self.mnemonic_file.as_deref(),
            self.mnemonic_fd,
            "--mnemonic-file",
            "--mnemonic-fd",
            "TOS mnemonic (hidden): ",
        )?;
        let phrase = secret_input::read_secret(&phrase_source)?;
        let phrase =
            std::str::from_utf8(&phrase).map_err(|_| anyhow::anyhow!("mnemonic is not UTF-8"))?;
        let password = match (&self.password_file, self.password_fd) {
            (None, None) => Zeroizing::new(Vec::new()),
            _ => secret_input::read_secret_exact(&secret_input::select_source(
                self.password_file.as_deref(),
                self.password_fd,
                "--password-file",
                "--password-fd",
                "Password (hidden): ",
            )?)?,
        };
        let password =
            std::str::from_utf8(&password).map_err(|_| anyhow::anyhow!("password is not UTF-8"))?;
        // Validate the mnemonic before creating/opening persistent custody.
        let mut master = Zeroizing::new(
            tos_native_mnemonic::private_seed(phrase, password)
                .map_err(|_| anyhow::anyhow!("native mnemonic or password rejected"))?,
        );
        if let Some(manifest) = manifest {
            let mut checked = Zeroizing::new(*master);
            manifest.verify_initial_master_and_wipe(
                &mut *checked,
                self.role.native(),
                contracts::wallet_v5r2_manifest::SeedProfile::NativeMnemonic,
            )?;
        }
        let derived = wallet_pq_signer::kdf::derive_signer_and_wipe(
            &mut *master,
            context,
            self.role.native(),
        )?;
        anyhow::ensure!(
            derived.public_key() == expected_key,
            "derived PQ key does not match enrolled public key"
        );
        drop(derived);
        let vault = self.open_vault().await?;
        let id = SecretId::new(self.record_id.as_str());
        let signer = wallet_pq_signer::vault::restore_mnemonic(
            &vault,
            &id,
            self.role.native(),
            phrase,
            password,
            context,
            &expected_key,
        )
        .await?;
        self.report(signer.public_key(), "key_record_restored");
        Ok(())
    }

    async fn open_vault(&self) -> anyhow::Result<SecretVault> {
        open_vault_file(&self.vault_file, self.vault_key_file.as_deref(), self.vault_key_fd).await
    }

    fn report(&self, public_key: &[u8], status: &str) {
        println!(
            "{}",
            serde_json::json!({"status":status, "record_id":self.record_id,
            "role":wallet_pq_signer::vault::role_tag(self.role.native()), "public_key":hex::encode(public_key),
            "network_tag":self.network_tag, "global_id":self.global_id, "account_index":self.account_index,
            "key_generation":self.key_generation})
        );
    }
}

#[derive(clap::Args, Clone)]
#[command(about = "Create one PQ key with a new 24-word recovery backup; no wallet deployment")]
pub struct PqCreateKeyCmd {
    #[arg(long)]
    vault_file: PathBuf,
    #[arg(long)]
    record_id: String,
    #[arg(long, value_enum)]
    role: PqRole,
    /// Write a new mode-0600 plaintext recovery backup; keep it offline. Never overwritten.
    #[arg(long)]
    mnemonic_backup_file: PathBuf,
    #[arg(long)]
    network_tag: String,
    #[arg(long, allow_hyphen_values = true)]
    global_id: i32,
    #[arg(long)]
    account_index: u32,
    #[arg(long)]
    key_generation: u32,
    #[arg(long, conflicts_with = "vault_key_fd")]
    vault_key_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "vault_key_file")]
    vault_key_fd: Option<i32>,
}

fn save_new_backup(path: &Path, phrase: &str) -> anyhow::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(phrase.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(path)?;
    std::fs::File::open(parent)?.sync_all()?;
    let saved = secret_input::read_secret(&secret_input::SecretSource::File(path.to_path_buf()))?;
    anyhow::ensure!(saved.as_slice() == phrase.as_bytes(), "mnemonic backup readback mismatch");
    Ok(())
}

impl PqCreateKeyCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let mut restore = PqRestoreKeyCmd {
            vault_file: self.vault_file.clone(),
            record_id: self.record_id.clone(),
            role: self.role,
            expected_public_key: "00".repeat(self.role.native().public_key_bytes()),
            network_tag: self.network_tag.clone(),
            global_id: self.global_id,
            account_index: self.account_index,
            key_generation: self.key_generation,
            mnemonic_file: None,
            mnemonic_fd: None,
            password_file: None,
            password_fd: None,
            vault_key_file: self.vault_key_file.clone(),
            vault_key_fd: self.vault_key_fd,
        };
        let (context, _) = restore.enrollment()?;
        let vault = restore.open_vault().await?;
        let id = SecretId::new(self.record_id.as_str());
        anyhow::ensure!(
            !vault.exists(&id).await?,
            "PQ record already exists; no new backup generated"
        );
        let words = Zeroizing::new(tos_native_mnemonic::generate(24)?);
        let phrase = Zeroizing::new(words.join(" "));
        let mut master = Zeroizing::new(tos_native_mnemonic::private_seed(&phrase, "")?);
        let derived = wallet_pq_signer::kdf::derive_signer_and_wipe(
            &mut *master,
            context,
            self.role.native(),
        )?;
        let public_key = derived.public_key().to_vec();
        drop(derived);
        restore.expected_public_key = hex::encode(&public_key);
        // Persist and verify the recovery material before storing a derived key.
        // Any later uncertainty preserves the backup and any possibly written record.
        save_new_backup(&self.mnemonic_backup_file, &phrase)?;
        let saved = secret_input::read_secret(&secret_input::SecretSource::File(
            self.mnemonic_backup_file.clone(),
        ))?;
        let saved =
            std::str::from_utf8(&saved).map_err(|_| anyhow::anyhow!("backup is not UTF-8"))?;
        let signer = wallet_pq_signer::vault::restore_mnemonic(
            &vault,
            &id,
            self.role.native(),
            saved,
            "",
            context,
            &public_key,
        )
        .await?;
        restore.report(signer.public_key(), "key_record_created");
        Ok(())
    }
}

/// Initial recovery is offline custody reconstruction, not current chain authority.
#[derive(clap::Args, Clone)]
#[command(about = "Restore an initial PQ key after independent code and wallet identity checks")]
pub struct PqRestoreInitialCmd {
    #[command(flatten)]
    key: PqRestoreKeyCmd,
    #[arg(long)]
    recovery_manifest: PathBuf,
    /// Independently authenticated basechain wallet account ID (32-byte hex).
    #[arg(long)]
    expected_wallet: String,
    #[command(flatten)]
    code: InitialCodeArgs,
}

#[derive(clap::Args, Clone)]
struct InitialCodeArgs {
    #[arg(long)]
    wallet_code: PathBuf,
    #[arg(long)]
    module_code: PathBuf,
    #[arg(long)]
    vault_code: PathBuf,
    /// Release code hashes must be authenticated separately from the manifest.
    #[arg(long)]
    wallet_code_hash: String,
    #[arg(long)]
    module_code_hash: String,
    #[arg(long)]
    vault_code_hash: String,
}

fn bounded_public_file(path: &Path, limit: usize) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(std::fs::metadata(path)?.is_file(), "public recovery input must be a file");
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take((limit as u64) + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= limit, "public recovery input size limit");
    Ok(bytes)
}
fn public_hash(text: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(text)?.try_into().map_err(|_| anyhow::anyhow!("expected 32-byte public hash"))
}
impl PqRestoreInitialCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use contracts::wallet_v5r2_manifest::{InitialRecoveryManifest, MAX_MANIFEST_BYTES};
        self.key.enrollment()?;
        let expected = public_hash(&self.expected_wallet)?;
        let encoded = bounded_public_file(&self.recovery_manifest, MAX_MANIFEST_BYTES)?;
        let code = self.code.load()?;
        let (manifest, _) =
            InitialRecoveryManifest::parse_and_reconstruct(&encoded, code, expected)?;
        self.key.run_with_manifest(Some(&manifest)).await
    }
}

impl InitialCodeArgs {
    fn load(&self) -> anyhow::Result<contracts::wallet_v5r2_genesis::CodeBundle> {
        use contracts::wallet_v5r2_genesis::{CodeBundle, CodeHashes};
        let pins = CodeHashes {
            wallet: public_hash(&self.wallet_code_hash)?,
            module: public_hash(&self.module_code_hash)?,
            vault: public_hash(&self.vault_code_hash)?,
        };
        CodeBundle::new(
            chain_block::read_single_root_boc(bounded_public_file(&self.wallet_code, 256 * 1024)?)?,
            chain_block::read_single_root_boc(bounded_public_file(&self.module_code, 256 * 1024)?)?,
            chain_block::read_single_root_boc(bounded_public_file(&self.vault_code, 256 * 1024)?)?,
            pins,
        )
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialEnrollment {
    global_id: i32,
    network: String,
    wallet_id: u32,
    primary_key: String,
    rescue_key: String,
    policy: String,
    fee_tree_id: String,
    fee_public_key: String,
    fee_epoch0: u32,
    derivation: contracts::wallet_v5r2_manifest::RecoveryDerivation,
}

#[derive(clap::Args, Clone)]
#[command(
    about = "Prepare initial PQ wallet identities and public recovery files; no deployment or readiness"
)]
pub struct PqPrepareInitialCmd {
    #[command(flatten)]
    code: InitialCodeArgs,
    /// Strict public enrollment JSON; never include private signing material.
    #[arg(long)]
    enrollment_file: PathBuf,
    /// A new directory. Existing or partially written bundles are never overwritten.
    #[arg(long)]
    output_dir: PathBuf,
}
fn public_bytes<const N: usize>(text: &str) -> anyhow::Result<[u8; N]> {
    hex::decode(text)?.try_into().map_err(|_| anyhow::anyhow!("public enrollment field width"))
}
impl PqPrepareInitialCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        use contracts::{
            wallet_v5r2_genesis::GenesisParameters,
            wallet_v5r2_manifest::{InitialRecoveryManifest, MAX_MANIFEST_BYTES},
            wallet_v5r2_pop::RescuePolicy,
        };
        let enrollment: InitialEnrollment = serde_json::from_slice(&bounded_public_file(
            &self.enrollment_file,
            MAX_MANIFEST_BYTES,
        )?)
        .map_err(|_| anyhow::anyhow!("invalid public enrollment encoding"))?;
        let policy = match enrollment.policy.as_str() {
            "RESCUE_READY" => RescuePolicy::Ready,
            "SLH_REQUIRED" => RescuePolicy::Required,
            _ => anyhow::bail!("unsupported initial rescue policy"),
        };
        let (manifest, genesis) = InitialRecoveryManifest::prepare(
            self.code.load()?,
            GenesisParameters {
                global_id: enrollment.global_id,
                network: public_bytes(&enrollment.network)?,
                wallet_id: enrollment.wallet_id,
                primary_key: public_bytes(&enrollment.primary_key)?,
                rescue_key: public_bytes(&enrollment.rescue_key)?,
                policy,
                fee_tree_id: public_bytes(&enrollment.fee_tree_id)?,
                fee_public_key: public_bytes(&enrollment.fee_public_key)?,
                epoch0: enrollment.fee_epoch0,
            },
            enrollment.derivation,
        )?;
        let mut files = Vec::new();
        for (name, cell) in [
            ("wallet-state-init.boc", genesis.wallet_init()),
            ("module-state-init.boc", genesis.module_init()),
            ("vault-state-init.boc", genesis.vault_init()),
        ] {
            files.push((name, chain_block::write_boc(cell)?));
        }
        // The public manifest is last. Any uncertain partial directory is retained.
        files.push(("recovery-manifest.json", manifest.to_json()?));
        std::fs::create_dir(&self.output_dir)?;
        for (name, bytes) in &files {
            let path = self.output_dir.join(name);
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            anyhow::ensure!(
                bounded_public_file(&path, bytes.len())? == *bytes,
                "prepared bundle readback mismatch"
            );
        }
        std::fs::File::open(&self.output_dir)?.sync_all()?;
        let parent = self
            .output_dir
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::File::open(parent)?.sync_all()?;
        println!(
            "{}",
            serde_json::json!({"status":"initial_wallet_prepared", "workchain":0,
            "wallet":hex::encode(genesis.wallet_init().repr_hash().as_array()),
            "module":hex::encode(genesis.module_init().repr_hash().as_array()),
            "vault":hex::encode(genesis.vault_init().repr_hash().as_array()),
            "fee_config_hash":hex::encode(genesis.config_hash())})
        );
        Ok(())
    }
}

async fn open_vault_file(
    vault_file: &Path,
    key_file: Option<&Path>,
    key_fd: Option<i32>,
) -> anyhow::Result<SecretVault> {
    // Retain no plaintext Vault encryption key after constructing protected memory.
    let source = secret_input::select_source(
        key_file,
        key_fd,
        "--vault-key-file",
        "--vault-key-fd",
        "Vault encryption key, hex (hidden): ",
    )?;
    let encryption_key = {
        let text = secret_input::read_secret(&source)?;
        let bytes = secret_input::decode_hex(&text)?;
        anyhow::ensure!(bytes.len() == 32, "Vault encryption key must be 32 bytes");
        ProtectedMemory::from_slice(&bytes).await?
    };
    let encryption_key =
        MasterKey::from_key_material(KeyMaterial::new_symmetric_key(encryption_key).await?).await?;
    let storage =
        FileJsonStorage::new(encryption_key, vault_file, Box::new(AutoCryptoFactory {}), false)
            .await?;
    let vault = SecretVault::new(Arc::new(storage), Arc::new(NullEventHandler {}));
    Ok(vault)
}

#[path = "wallet_pq_fee_cmd.rs"]
mod fee;
pub use fee::PqRestoreFeeInitialCmd;

#[path = "wallet_pq_inspect_cmd.rs"]
mod inspect;
pub use inspect::PqInspectInitialCmd;
