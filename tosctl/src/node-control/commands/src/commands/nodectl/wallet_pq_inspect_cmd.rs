// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::{InitialCodeArgs, PathBuf, bounded_public_file, public_hash};
use common::app_config::ProofVerifierConfig;
use contracts::{
    proven_getters::{ProvenAccountState, ProvenGetterProvider, ReadPolicy},
    wallet_v5r2_genesis::{SuccessorDeployment, WalletGenesis},
    wallet_v5r2_manifest::{InitialRecoveryManifest, MAX_MANIFEST_BYTES},
    wallet_v5r2_state::ProvenFeeVault,
    wallet_v5r2_wallet_state::ProvenWalletState,
};

#[derive(clap::Args, Clone)]
#[command(
    about = "Inspect the proven initial PQ wallet/module pair; no signing or readiness claim"
)]
pub struct PqInspectInitialCmd {
    #[command(flatten)]
    proof: InitialProofArgs,
}

#[derive(clap::Args, Clone)]
pub(super) struct InitialProofArgs {
    #[arg(long)]
    recovery_manifest: PathBuf,
    /// Enrolled successor template that must match the actually installed tuple.
    #[arg(long, requires_all = ["expected_installed_template_wallet", "fee_history"])]
    installed_successor_manifest: Option<PathBuf>,
    #[arg(long, requires = "installed_successor_manifest")]
    expected_installed_template_wallet: Option<String>,
    /// Retained public history of this wallet's used fee keys; never an LMS journal.
    #[arg(long)]
    fee_history: Option<PathBuf>,
    #[arg(skip)]
    captured_fee_history: Vec<[u8; 32]>,
    /// Independently authenticated basechain wallet account ID, in hex.
    #[arg(long)]
    expected_wallet: String,
    #[command(flatten)]
    code: InitialCodeArgs,
    /// Local ProofVerifierConfig JSON: trusted executable, anchor and proof source.
    #[arg(long)]
    proof_config: PathBuf,
    /// Local bound on masterchain and both account observation ages, in seconds.
    #[arg(long, default_value = "60", value_parser = clap::value_parser!(u32).range(1..3600))]
    max_age_seconds: u32,
}

const MAX_FEE_HISTORY: usize = 64;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FeeHistory {
    schema: String,
    wallet: String,
    used_fee_public_key_hashes: Vec<String>,
}

fn fee_key_hash(metadata: &chain_block::Cell) -> anyhow::Result<[u8; 32]> {
    let key = chain_block::SliceData::load_cell(metadata.clone())?.checked_drain_reference()?;
    Ok(*key.repr_hash().as_array())
}

pub(super) fn absolute_path_argument(path: &std::path::Path) -> anyhow::Result<String> {
    // Resolve the original command's working directory without requiring the
    // referenced file to exist or changing symlink semantics via canonicalize.
    let absolute = std::path::absolute(path)?;
    Ok(absolute.to_str().ok_or_else(|| anyhow::anyhow!("export path is not UTF-8"))?.into())
}

pub(super) fn now() -> anyhow::Result<u32> {
    Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs().try_into()?)
}

pub(super) struct InitialProof {
    pub wallet: ProvenAccountState,
    pub module: ProvenAccountState,
    pub view: ProvenWalletState,
    pub observed_at: u32,
}

pub(super) struct InitialContext {
    genesis: WalletGenesis,
    installed: Option<SuccessorDeployment>,
    successor: Option<SuccessorDeployment>,
    provider: ProvenGetterProvider,
    max_age_seconds: u32,
    known_fee_keys: Vec<[u8; 32]>,
}

impl InitialProofArgs {
    pub(super) fn successor(
        &self,
        manifest: &std::path::Path,
        expected_template_wallet: &str,
    ) -> anyhow::Result<contracts::wallet_v5r2_genesis::SuccessorDeployment> {
        // The template's wallet is a reconstruction pin, never the destination
        // of recovery. Pair its module and fee tree with the existing wallet.
        let (_, template) = InitialRecoveryManifest::parse_and_reconstruct(
            &bounded_public_file(manifest, MAX_MANIFEST_BYTES)?,
            self.code.load()?,
            public_hash(expected_template_wallet)?,
        )?;
        let successor = contracts::wallet_v5r2_genesis::SuccessorDeployment::new(
            template,
            public_hash(&self.expected_wallet)?,
        )?;
        let context = self.context()?;
        context.require_fee_history_capacity()?;
        successor.require_fresh_fee_key(context.current_metadata())?;
        let current_key = fee_key_hash(context.current_metadata())?;
        let proposed_key = fee_key_hash(successor.metadata())?;
        anyhow::ensure!(
            !context.known_fee_keys.iter().any(|key| *key != current_key && *key == proposed_key),
            "successor reuses a retained LMS public key"
        );
        Ok(successor)
    }

    pub(super) fn context(&self) -> anyhow::Result<InitialContext> {
        let (_, genesis) = InitialRecoveryManifest::parse_and_reconstruct(
            &bounded_public_file(&self.recovery_manifest, MAX_MANIFEST_BYTES)?,
            self.code.load()?,
            public_hash(&self.expected_wallet)?,
        )?;
        let installed =
            match (&self.installed_successor_manifest, &self.expected_installed_template_wallet) {
                (Some(path), Some(pin)) => {
                    let (_, template) = InitialRecoveryManifest::parse_and_reconstruct(
                        &bounded_public_file(path, MAX_MANIFEST_BYTES)?,
                        self.code.load()?,
                        public_hash(pin)?,
                    )?;
                    Some(SuccessorDeployment::new(template, public_hash(&self.expected_wallet)?)?)
                }
                (None, None) => None,
                _ => anyhow::bail!(
                    "installed enrollment requires manifest and independent template pin"
                ),
            };
        let mut known_fee_keys = self.captured_fee_history.clone();
        if let Some(path) = &self.fee_history {
            let history: FeeHistory =
                serde_json::from_slice(&bounded_public_file(path, 16 * 1024)?)?;
            anyhow::ensure!(
                history.schema == "TOS-WALLET-V5R2-FEE-HISTORY-v1"
                    && public_hash(&history.wallet)? == public_hash(&self.expected_wallet)?
                    && !history.used_fee_public_key_hashes.is_empty()
                    && history.used_fee_public_key_hashes.len() <= MAX_FEE_HISTORY,
                "fee history identity or size mismatch"
            );
            for value in history.used_fee_public_key_hashes {
                let key = public_hash(&value)?;
                anyhow::ensure!(hex::encode(key) == value, "fee history hash must be canonical");
                known_fee_keys.push(key);
            }
        }
        anyhow::ensure!(
            installed.is_none() || !known_fee_keys.is_empty(),
            "installed enrollment requires retained fee history"
        );
        known_fee_keys.push(fee_key_hash(genesis.metadata())?);
        if let Some(installed) = &installed {
            known_fee_keys.push(fee_key_hash(installed.metadata())?);
        }
        known_fee_keys.sort_unstable();
        known_fee_keys.dedup();
        anyhow::ensure!(
            known_fee_keys.len() <= MAX_FEE_HISTORY,
            "fee history limit reached; retain history for recovery review"
        );
        let config: ProofVerifierConfig =
            serde_json::from_slice(&bounded_public_file(&self.proof_config, 64 * 1024)?)?;
        anyhow::ensure!(
            config.live_max_age_seconds.is_some_and(|age| age <= self.max_age_seconds),
            "proof configuration needs a live age no greater than the wallet age policy"
        );
        let provider = ProvenGetterProvider::new(&config)?;
        Ok(InitialContext {
            genesis,
            installed,
            successor: None,
            provider,
            max_age_seconds: self.max_age_seconds,
            known_fee_keys,
        })
    }
    pub(super) async fn read(&self, config_params: &[u32]) -> anyhow::Result<InitialProof> {
        self.context()?.read(config_params).await
    }
    pub(super) fn require_fee_history_capacity(&self) -> anyhow::Result<()> {
        self.context()?.require_fee_history_capacity()
    }
    pub(super) fn retain_fee_history(&mut self, context: &InitialContext) -> anyhow::Result<()> {
        self.captured_fee_history.extend_from_slice(&context.known_fee_keys);
        self.captured_fee_history.sort_unstable();
        self.captured_fee_history.dedup();
        anyhow::ensure!(
            self.captured_fee_history.len() <= MAX_FEE_HISTORY,
            "fee history limit reached; retain history for recovery review"
        );
        Ok(())
    }
    pub(super) fn with_installed(&self, manifest: PathBuf, pin: String) -> anyhow::Result<Self> {
        let mut next = self.clone();
        next.retain_fee_history(&self.context()?)?;
        next.installed_successor_manifest = Some(manifest);
        next.expected_installed_template_wallet = Some(pin);
        Ok(next)
    }

    /// Freeze the public birth and installed enrollment before changing the
    /// active signer. Neither the manifest nor the exported proof arguments
    /// assert current authority; every restored command still reads live proof.
    pub(super) fn installed_export(
        &self,
        context: &InitialContext,
        directory: &std::path::Path,
    ) -> anyhow::Result<(Self, Vec<(&'static str, Vec<u8>)>)> {
        let (birth, birth_genesis) = InitialRecoveryManifest::parse_and_reconstruct(
            &bounded_public_file(&self.recovery_manifest, MAX_MANIFEST_BYTES)?,
            self.code.load()?,
            public_hash(&self.expected_wallet)?,
        )?;
        let manifest = self
            .installed_successor_manifest
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("installed enrollment is missing"))?;
        let pin = self
            .expected_installed_template_wallet
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("installed template pin is missing"))?;
        let (installed, template) = InitialRecoveryManifest::parse_and_reconstruct(
            &bounded_public_file(manifest, MAX_MANIFEST_BYTES)?,
            self.code.load()?,
            public_hash(pin)?,
        )?;
        let successor = SuccessorDeployment::new(template, public_hash(&self.expected_wallet)?)?;
        let expected = context
            .installed
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("cannot export a proposed route as installed"))?;
        anyhow::ensure!(
            birth_genesis.wallet_init().repr_hash() == context.genesis.wallet_init().repr_hash()
                && successor.module_init().repr_hash() == expected.module_init().repr_hash()
                && successor.metadata().repr_hash() == expected.metadata().repr_hash()
                && successor.vault_init().repr_hash() == expected.vault_init().repr_hash(),
            "enrollment changed during installed export"
        );
        let mut next = self.clone();
        next.recovery_manifest = directory.join("recovery-manifest.json");
        next.installed_successor_manifest =
            Some(directory.join("installed-successor-manifest.json"));
        next.code.wallet_code = directory.join("wallet-code.boc");
        next.code.module_code = directory.join("module-code.boc");
        next.code.vault_code = directory.join("vault-code.boc");
        next.fee_history = Some(directory.join("fee-history.json"));
        // The public file can be re-read, but cannot shrink this process's
        // already observed history after another local actor edits it.
        next.retain_fee_history(context)?;
        // Reading the exact StateInit references retains the already pinned
        // release code; an exported hash is never substituted for an input pin.
        let mut files = vec![
            ("recovery-manifest.json", birth.to_json()?),
            ("installed-successor-manifest.json", installed.to_json()?),
            (
                "fee-history.json",
                serde_json::to_vec_pretty(&FeeHistory {
                    schema: "TOS-WALLET-V5R2-FEE-HISTORY-v1".into(),
                    wallet: hex::encode(public_hash(&self.expected_wallet)?),
                    used_fee_public_key_hashes: context
                        .known_fee_keys
                        .iter()
                        .map(hex::encode)
                        .collect(),
                })?,
            ),
        ];
        for (name, init) in [
            ("wallet-code.boc", birth_genesis.wallet_init()),
            ("module-code.boc", successor.module_init()),
            ("vault-code.boc", successor.vault_init()),
        ] {
            let cell =
                chain_block::SliceData::load_cell(init.clone())?.checked_drain_reference()?;
            files.push((name, chain_block::write_boc(&cell)?));
        }
        Ok((next, files))
    }

    pub(super) fn proof_arguments(&self) -> anyhow::Result<Vec<String>> {
        let mut args = vec![
            "--recovery-manifest".into(),
            absolute_path_argument(&self.recovery_manifest)?,
            "--expected-wallet".into(),
            self.expected_wallet.clone(),
            "--wallet-code".into(),
            absolute_path_argument(&self.code.wallet_code)?,
            "--module-code".into(),
            absolute_path_argument(&self.code.module_code)?,
            "--vault-code".into(),
            absolute_path_argument(&self.code.vault_code)?,
            "--wallet-code-hash".into(),
            self.code.wallet_code_hash.clone(),
            "--module-code-hash".into(),
            self.code.module_code_hash.clone(),
            "--vault-code-hash".into(),
            self.code.vault_code_hash.clone(),
            "--proof-config".into(),
            absolute_path_argument(&self.proof_config)?,
            "--max-age-seconds".into(),
            self.max_age_seconds.to_string(),
        ];
        match (&self.installed_successor_manifest, &self.expected_installed_template_wallet) {
            (Some(manifest), Some(pin)) => args.extend([
                "--installed-successor-manifest".into(),
                absolute_path_argument(manifest)?,
                "--expected-installed-template-wallet".into(),
                pin.clone(),
            ]),
            (None, None) => (),
            _ => {
                anyhow::bail!("installed enrollment requires manifest and independent template pin")
            }
        }
        if let Some(history) = &self.fee_history {
            args.extend(["--fee-history".into(), absolute_path_argument(history)?]);
        }
        Ok(args)
    }
}

impl InitialContext {
    fn require_fee_history_capacity(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.known_fee_keys.len() < MAX_FEE_HISTORY,
            "fee history has no capacity for another route"
        );
        Ok(())
    }
    pub(super) fn with_successor(mut self, successor: SuccessorDeployment) -> Self {
        self.successor = Some(successor);
        self
    }
    pub(super) fn successor(&self) -> Option<&SuccessorDeployment> {
        self.successor.as_ref()
    }
    pub(super) fn installed(&self) -> Option<&SuccessorDeployment> {
        self.installed.as_ref()
    }
    pub(super) fn pop_enrollment(&self) -> Option<&SuccessorDeployment> {
        self.successor.as_ref().or(self.installed.as_ref())
    }
    pub(super) fn current_metadata(&self) -> &chain_block::Cell {
        self.installed.as_ref().map_or_else(|| self.genesis.metadata(), |x| x.metadata())
    }
    fn fee_init(&self) -> &chain_block::Cell {
        match self.pop_enrollment() {
            Some(successor) => successor.vault_init(),
            None => self.genesis.vault_init(),
        }
    }
    pub(super) async fn pop_module_at(
        &self,
        checkpoint: contracts::MasterchainCheckpoint,
    ) -> anyhow::Result<ProvenAccountState> {
        use chain_block::{Deserializable, StateInit};
        let init = match self.pop_enrollment() {
            Some(successor) => successor.module_init(),
            None => self.genesis.module_init(),
        };
        let address = format!("0:{}", init.repr_hash().to_hex_string());
        let account = self
            .provider
            .read_account(&address.parse()?, &ReadPolicy::Historical(checkpoint))
            .await?;
        let expected = StateInit::construct_from_cell(init.clone())?;
        anyhow::ensure!(
            account.evidence().account.address == address
                && account.account().get_code() == expected.code
                && account.account().get_data() == expected.data,
            "POP module differs from enrolled deployment"
        );
        let observed = now()?;
        for time in [account.evidence().block_gen_utime, account.evidence().account.gen_utime] {
            let age = observed
                .checked_sub(time)
                .ok_or_else(|| anyhow::anyhow!("POP module proof is in the future"))?;
            anyhow::ensure!(age <= self.max_age_seconds, "stale POP module proof");
        }
        Ok(account)
    }
    pub(super) fn enrollment(&self) -> &WalletGenesis {
        &self.genesis
    }
    pub(super) async fn fee(&self) -> anyhow::Result<ProvenFeeVault> {
        Ok(self.fee_snapshot().await?.1)
    }
    pub(super) async fn fee_snapshot(
        &self,
    ) -> anyhow::Result<(ProvenAccountState, ProvenFeeVault)> {
        let address = format!("0:{}", self.fee_init().repr_hash().to_hex_string()).parse()?;
        let account = self.provider.read_account(&address, &ReadPolicy::Live).await?;
        let view = match self.pop_enrollment() {
            Some(successor) => {
                ProvenFeeVault::bind_successor(&account, successor, now()?, self.max_age_seconds)?
            }
            None => ProvenFeeVault::bind(&account, &self.genesis, now()?, self.max_age_seconds)?,
        };
        Ok((account, view))
    }
    pub(super) async fn fee_at(
        &self,
        checkpoint: contracts::MasterchainCheckpoint,
    ) -> anyhow::Result<ProvenAccountState> {
        let address = format!("0:{}", self.fee_init().repr_hash().to_hex_string()).parse()?;
        self.provider.read_account(&address, &ReadPolicy::Historical(checkpoint)).await
    }
    pub(super) async fn fee_at_live_wallet(
        &self,
        wallet: &ProvenAccountState,
    ) -> anyhow::Result<(ProvenAccountState, ProvenFeeVault)> {
        let account = self.fee_at(wallet.evidence().checkpoint.clone()).await?;
        let view = match self.pop_enrollment() {
            Some(successor) => ProvenFeeVault::bind_successor_at_live_checkpoint(
                &account,
                wallet,
                successor,
                now()?,
                self.max_age_seconds,
            )?,
            None => ProvenFeeVault::bind_at_live_checkpoint(
                &account,
                wallet,
                &self.genesis,
                now()?,
                self.max_age_seconds,
            )?,
        };
        Ok((account, view))
    }
    pub(super) async fn read(&self, config_params: &[u32]) -> anyhow::Result<InitialProof> {
        let genesis = &self.genesis;
        let provider = &self.provider;
        let wallet_address = format!("0:{}", genesis.wallet_init().repr_hash().to_hex_string());
        let module_init =
            self.installed.as_ref().map_or_else(|| genesis.module_init(), |x| x.module_init());
        let module_address = format!("0:{}", module_init.repr_hash().to_hex_string());
        let wallet = provider
            .read_account_with_config(&wallet_address.parse()?, config_params, &ReadPolicy::Live)
            .await?;
        let module = provider
            .read_account(
                &module_address.parse()?,
                &ReadPolicy::Historical(wallet.evidence().checkpoint.clone()),
            )
            .await?;
        // Recheck the local clock after both asynchronous proof acquisitions.
        let observed_at = now()?;
        let view = match &self.installed {
            Some(installed) => ProvenWalletState::bind_successor(
                &wallet,
                &module,
                genesis,
                installed,
                observed_at,
                self.max_age_seconds,
            )?,
            None => ProvenWalletState::bind_initial(
                &wallet,
                &module,
                genesis,
                observed_at,
                self.max_age_seconds,
            )?,
        };
        Ok(InitialProof { wallet, module, view, observed_at })
    }
}

impl PqInspectInitialCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let context = self.proof.context()?;
        let InitialProof { wallet, module, view, observed_at } = context.read(&[]).await?;
        let wallet_address = &wallet.evidence().account.address;
        let module_address = &module.evidence().account.address;
        let checkpoint = &wallet.evidence().checkpoint;
        println!(
            "{}",
            serde_json::json!({
                "status": if context.installed().is_some() {
                    "installed_wallet_pair_proven"
                } else { "initial_wallet_pair_proven" },
                "observed_at": observed_at,
                "checkpoint": {"seqno": checkpoint.seqno,
                    "root_hash": checkpoint.root_hash, "file_hash": checkpoint.file_hash},
                "wallet": wallet_address,
                "module": module_address,
                "wallet_balance_nanotos": wallet.evidence().account.balance,
                "module_balance_nanotos": module.evidence().account.balance,
                "wallet_state_hash": wallet.evidence().account.state_hash,
                "module_state_hash": module.evidence().account.state_hash,
                "seqno": view.seqno(),
                "wallet_id": view.wallet_id(),
                "epoch": view.epoch(),
                "primary_nonce": view.primary_nonce(),
                "rescue_nonce": view.rescue_nonce(),
                "retired": view.retired(),
                "primary_locally_enabled": view.primary_locally_enabled(),
                "scope": "identity and current counters only; global policy, fee vault, POP, custody and delivery are not checked"
            })
        );
        Ok(())
    }
}
