// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Read-only, message-bound funded POP receipts from authenticated history.
use super::{
    PathBuf, bounded_public_file,
    inspect::{InitialContext, InitialProofArgs},
};
use chain_block::Cell;
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use contracts::{
    proven_getters::ProvenAccountState,
    proven_transactions::ProvenTransaction,
    wallet_v5r2::AuthRole,
    wallet_v5r2_pop::{FundedPopReceipts, PopRequest},
};
use std::time::Duration;

#[derive(clap::Args, Clone)]
#[command(
    about = "Verify exact initial funded POP execution from proven account history; no signing or broadcast"
)]
pub struct PqVerifyPopInitialCmd {
    #[command(flatten)]
    proof: InitialProofArgs,
    /// Verify POPs through this enrolled successor before wallet migration.
    #[arg(long, requires = "expected_template_wallet")]
    successor_manifest: Option<PathBuf>,
    #[arg(long, requires = "successor_manifest")]
    expected_template_wallet: Option<String>,
    #[command(flatten)]
    retained: RetainedPopFiles,
    #[command(flatten)]
    history: PopHistoryOptions,
}

/// Local request and exact pre-states retained by the signing/execution flow.
/// These files remain untrusted until matched against authenticated history.
#[derive(clap::Args, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedPopFiles {
    /// Locally retained POP3 challenge, not a challenge chosen by the RPC server.
    #[arg(long)]
    pop_request: PathBuf,
    /// Exact external Message BOC previously submitted to the fee vault.
    #[arg(long)]
    external_message: PathBuf,
    /// Raw Account BOC before the actual fee transaction; observed snapshots may be stale.
    #[arg(long)]
    fee_before_account: PathBuf,
    /// Raw Account BOC before the actual module transaction.
    #[arg(long)]
    module_before_account: PathBuf,
}

#[derive(clap::Args, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PopHistoryOptions {
    /// Untrusted read-only transaction source; BOCs are checked against proven history.
    #[arg(long)]
    transaction_rpc_url: String,
    #[arg(long, default_value = "64", value_parser = clap::value_parser!(u32).range(1..=1024))]
    history_limit: u32,
    /// Per-account history lookup deadline.
    #[arg(long, default_value = "30", value_parser = clap::value_parser!(u64).range(1..=300))]
    timeout_seconds: u64,
}

fn read_cell(path: &std::path::Path) -> anyhow::Result<Cell> {
    chain_block::read_single_root_boc(bounded_public_file(path, 4 * 1024 * 1024)?)
}

/// Owns the exact verified requests/transactions so migration can borrow both
/// role receipts simultaneously without rereading mutable local files.
pub(super) struct VerifiedFundedPop {
    pub request: PopRequest,
    pub external: Cell,
    pub fee: ProvenTransaction,
    pub module: ProvenTransaction,
    fee_before: Cell,
    module_before: Cell,
}

impl VerifiedFundedPop {
    pub fn receipts(&self) -> FundedPopReceipts<'_> {
        FundedPopReceipts {
            fee: &self.fee,
            module: &self.module,
            fee_before: self.fee_before.clone(),
            module_before: self.module_before.clone(),
        }
    }
}

impl RetainedPopFiles {
    pub(super) async fn verify_at(
        &self,
        context: &InitialContext,
        fee_account: &ProvenAccountState,
        pop_module: &ProvenAccountState,
        history: &PopHistoryOptions,
    ) -> anyhow::Result<VerifiedFundedPop> {
        anyhow::ensure!(
            (1..=1024).contains(&history.history_limit),
            "POP history limit out of range"
        );
        anyhow::ensure!(
            (1..=300).contains(&history.timeout_seconds),
            "POP history timeout out of range"
        );
        let retained = read_cell(&self.pop_request)?;
        let external = read_cell(&self.external_message)?;
        let fee_before = read_cell(&self.fee_before_account)?;
        let module_before = read_cell(&self.module_before_account)?;
        let rpc = ClientJsonRpc::connect(history.transaction_rpc_url.clone(), None)?;
        let timeout = Duration::from_secs(history.timeout_seconds);
        let fee = ProvenTransaction::find_inbound_rpc(
            fee_account,
            &external,
            history.history_limit,
            timeout,
            &rpc,
        )
        .await?;
        let module_address = pop_module
            .account()
            .get_addr()
            .ok_or_else(|| anyhow::anyhow!("proven module address missing"))?;
        let mut delivered = None;
        fee.transaction().iterate_out_msgs_with_cells(|message, cell| {
            if message.is_internal() && message.dst_ref() == Some(module_address) {
                anyhow::ensure!(delivered.is_none(), "ambiguous POP delivery to module");
                delivered = Some(cell);
            }
            Ok(true)
        })?;
        let delivered = delivered
            .ok_or_else(|| anyhow::anyhow!("fee transaction emitted no module message"))?;
        let module = ProvenTransaction::find_inbound_rpc(
            pop_module,
            &delivered,
            history.history_limit,
            timeout,
            &rpc,
        )
        .await?;
        let request = match context.pop_enrollment() {
            Some(successor) => {
                PopRequest::from_successor_cell(retained, successor, module.transaction().now())?
            }
            None => PopRequest::from_initial_cell(
                retained,
                context.enrollment(),
                module.transaction().now(),
            )?,
        };
        let receipts = FundedPopReceipts { fee: &fee, module: &module, fee_before, module_before };
        match context.pop_enrollment() {
            Some(successor) => {
                request.require_successor_funded_receipt(&receipts, &external, successor)?
            }
            None => request.require_initial_funded_receipt(
                &receipts,
                &external,
                context.enrollment(),
            )?,
        }
        let FundedPopReceipts { fee_before, module_before, .. } = receipts;
        Ok(VerifiedFundedPop { request, external, fee, module, fee_before, module_before })
    }
}

impl PqVerifyPopInitialCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let context = self.proof.context()?;
        let context = match (&self.successor_manifest, &self.expected_template_wallet) {
            (Some(manifest), Some(pin)) => {
                context.with_successor(self.proof.successor(manifest, pin)?)
            }
            (None, None) => context,
            _ => anyhow::bail!("successor receipt requires manifest and independent template pin"),
        };
        let proof = context.read(&[]).await?;
        let pop_module = context.pop_module_at(proof.wallet.evidence().checkpoint.clone()).await?;
        let fee_account = context.fee_at(proof.wallet.evidence().checkpoint.clone()).await?;
        let verified =
            self.retained.verify_at(&context, &fee_account, &pop_module, &self.history).await?;
        let request = &verified.request;
        let external = &verified.external;
        let receipts = verified.receipts();
        let fee = receipts.fee;
        let module = receipts.module;
        let checkpoint = &proof.wallet.evidence().checkpoint;
        let role = match request.role() {
            AuthRole::Primary => "primary",
            AuthRole::Rescue => "rescue",
        };
        println!(
            "{}",
            serde_json::json!({
                "status": if context.successor().is_some() {
                    "successor_funded_pop_proven_at_checkpoint"
                } else if context.installed().is_some() {
                    "installed_funded_pop_proven_at_checkpoint"
                } else { "initial_funded_pop_proven_at_checkpoint" }, "role": role,
                "wallet": proof.wallet.evidence().account.address,
                "module": pop_module.evidence().account.address,
                "vault": fee_account.evidence().account.address,
                "checkpoint": {"seqno": checkpoint.seqno, "root_hash": checkpoint.root_hash,
                    "file_hash": checkpoint.file_hash},
                "request_hash": request.cell().repr_hash().to_hex_string(),
                "message_hash": external.repr_hash().to_hex_string(),
                "fee_transaction_hash": fee.root().repr_hash().to_hex_string(),
                "module_transaction_hash": module.root().repr_hash().to_hex_string(),
                "scope": "historical execution of this retained possession challenge; not wallet authority, current readiness or completed migration"
            })
        );
        Ok(())
    }
}
