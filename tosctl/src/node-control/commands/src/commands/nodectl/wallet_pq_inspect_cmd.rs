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
    successor: Option<SuccessorDeployment>,
    provider: ProvenGetterProvider,
    max_age_seconds: u32,
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
        successor.require_fresh_fee_key(self.context()?.enrollment().metadata())?;
        Ok(successor)
    }

    pub(super) fn context(&self) -> anyhow::Result<InitialContext> {
        let (_, genesis) = InitialRecoveryManifest::parse_and_reconstruct(
            &bounded_public_file(&self.recovery_manifest, MAX_MANIFEST_BYTES)?,
            self.code.load()?,
            public_hash(&self.expected_wallet)?,
        )?;
        let config: ProofVerifierConfig =
            serde_json::from_slice(&bounded_public_file(&self.proof_config, 64 * 1024)?)?;
        anyhow::ensure!(
            config.live_max_age_seconds.is_some_and(|age| age <= self.max_age_seconds),
            "proof configuration needs a live age no greater than the wallet age policy"
        );
        let provider = ProvenGetterProvider::new(&config)?;
        Ok(InitialContext {
            genesis,
            successor: None,
            provider,
            max_age_seconds: self.max_age_seconds,
        })
    }
    pub(super) async fn read(&self, config_params: &[u32]) -> anyhow::Result<InitialProof> {
        self.context()?.read(config_params).await
    }
}

impl InitialContext {
    pub(super) fn with_successor(mut self, successor: SuccessorDeployment) -> Self {
        self.successor = Some(successor);
        self
    }
    pub(super) fn successor(&self) -> Option<&SuccessorDeployment> {
        self.successor.as_ref()
    }
    fn fee_init(&self) -> &chain_block::Cell {
        match &self.successor {
            Some(successor) => successor.vault_init(),
            None => self.genesis.vault_init(),
        }
    }
    pub(super) async fn pop_module_at(
        &self,
        checkpoint: contracts::MasterchainCheckpoint,
    ) -> anyhow::Result<ProvenAccountState> {
        use chain_block::{Deserializable, StateInit};
        let init = match &self.successor {
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
        let view = match &self.successor {
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
    pub(super) async fn read(&self, config_params: &[u32]) -> anyhow::Result<InitialProof> {
        let genesis = &self.genesis;
        let provider = &self.provider;
        let wallet_address = format!("0:{}", genesis.wallet_init().repr_hash().to_hex_string());
        let module_address = format!("0:{}", genesis.module_init().repr_hash().to_hex_string());
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
        let view = ProvenWalletState::bind_initial(
            &wallet,
            &module,
            genesis,
            observed_at,
            self.max_age_seconds,
        )?;
        Ok(InitialProof { wallet, module, view, observed_at })
    }
}

impl PqInspectInitialCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let InitialProof { wallet, module, view, observed_at } = self.proof.read(&[]).await?;
        let wallet_address = &wallet.evidence().account.address;
        let module_address = &module.evidence().account.address;
        let checkpoint = &wallet.evidence().checkpoint;
        println!(
            "{}",
            serde_json::json!({
                "status": "initial_wallet_pair_proven",
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
