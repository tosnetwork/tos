// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Read-only, message-bound initial funded POP receipts from authenticated history.
use super::{PathBuf, bounded_public_file, inspect::InitialProofArgs};
use chain_block::Cell;
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use contracts::{
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

impl PqVerifyPopInitialCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let retained = read_cell(&self.pop_request)?;
        let external = read_cell(&self.external_message)?;
        let fee_before = read_cell(&self.fee_before_account)?;
        let module_before = read_cell(&self.module_before_account)?;
        let context = self.proof.context()?;
        let proof = context.read(&[]).await?;
        let fee_account = context.fee_at(proof.wallet.evidence().checkpoint.clone()).await?;
        let rpc = ClientJsonRpc::connect(self.transaction_rpc_url.clone(), None)?;
        let timeout = Duration::from_secs(self.timeout_seconds);
        let fee = ProvenTransaction::find_inbound_rpc(
            &fee_account,
            &external,
            self.history_limit,
            timeout,
            &rpc,
        )
        .await?;
        let module_address = proof
            .module
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
            &proof.module,
            &delivered,
            self.history_limit,
            timeout,
            &rpc,
        )
        .await?;
        let request = PopRequest::from_initial_cell(
            retained,
            context.enrollment(),
            module.transaction().now(),
        )?;
        request.require_initial_funded_receipt(
            &FundedPopReceipts { fee: &fee, module: &module, fee_before, module_before },
            &external,
            context.enrollment(),
        )?;
        let checkpoint = &proof.wallet.evidence().checkpoint;
        let role = match request.role() {
            AuthRole::Primary => "primary",
            AuthRole::Rescue => "rescue",
        };
        println!(
            "{}",
            serde_json::json!({
                "status": "initial_funded_pop_proven_at_checkpoint", "role": role,
                "wallet": proof.wallet.evidence().account.address,
                "module": proof.module.evidence().account.address,
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
