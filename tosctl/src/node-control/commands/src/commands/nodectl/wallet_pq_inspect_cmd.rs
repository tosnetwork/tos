// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::{InitialCodeArgs, PathBuf, bounded_public_file, public_hash};
use common::app_config::ProofVerifierConfig;
use contracts::{
    proven_getters::{ProvenGetterProvider, ReadPolicy},
    wallet_v5r2_manifest::{InitialRecoveryManifest, MAX_MANIFEST_BYTES},
    wallet_v5r2_wallet_state::ProvenWalletState,
};

#[derive(clap::Args, Clone)]
#[command(
    about = "Inspect the proven initial PQ wallet/module pair; no signing or readiness claim"
)]
pub struct PqInspectInitialCmd {
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

fn now() -> anyhow::Result<u32> {
    Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs().try_into()?)
}

impl PqInspectInitialCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
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
        let wallet_address = format!("0:{}", genesis.wallet_init().repr_hash().to_hex_string());
        let module_address = format!("0:{}", genesis.module_init().repr_hash().to_hex_string());
        let wallet = provider.read_account(&wallet_address.parse()?, &ReadPolicy::Live).await?;
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
            &genesis,
            observed_at,
            self.max_age_seconds,
        )?;
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
