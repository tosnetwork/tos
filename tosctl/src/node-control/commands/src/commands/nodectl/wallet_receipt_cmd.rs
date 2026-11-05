// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Read-only ledger evidence. Application acceptance and send authorization are
//! deliberately outside this command. A public original-message hash suffices.
use anyhow::Context as _;
use chain_block::{Cell, CurrencyCollection, Deserializable, Message, MsgAddressInt};
use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
use common::app_config::ProofVerifierConfig;
use contracts::{
    proven_getters::{ProvenAccountState, ProvenGetterProvider, ReadPolicy},
    proven_transactions::{PaymentExpectation, ProvenTransaction},
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{
    io::Read as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(clap::Args, Clone)]
pub struct WalletReceiptCmd {
    /// Locally approved public intent, not values inferred from RPC replies.
    #[arg(long)]
    intent: PathBuf,
    /// Public Account preimages retained before this original operation.
    #[arg(long)]
    sender_pre_state: PathBuf,
    #[arg(long)]
    recipient_pre_state: PathBuf,
    #[arg(long)]
    proof_config: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    operation: String,
    genesis_root: String,
    genesis_file: String,
    sender: String,
    sender_code_hash: String,
    recipient: String,
    recipient_code_hash: String,
    external_message_hash: String,
    body_hash: String,
    value_nanotos: u64,
    credited_nanotos: u64,
    bounce: bool,
    rpc: [String; 2],
    history_limit: u32,
    max_age_seconds: u32,
    timeout_seconds: u32,
}

fn digest(text: &str) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(
        text.len() == 64 && text.bytes().all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
        "canonical lowercase digest required"
    );
    Ok(hex::decode(text)?.try_into().map_err(|_| anyhow::anyhow!("digest width"))?)
}

fn bounded(path: &Path, limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("cannot open receipt input")?;
    let meta = file.metadata()?;
    anyhow::ensure!(meta.is_file() && meta.len() <= limit as u64, "receipt input bound");
    let mut bytes = Vec::new();
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() as u64 == meta.len(), "receipt input changed or exceeded bound");
    Ok(bytes)
}

fn cell(bytes: &[u8]) -> anyhow::Result<Cell> {
    chain_block::BocReader::new()
        .set_max_cell_depth(1024)
        .read(&mut std::io::Cursor::new(bytes))
        .and_then(|value| value.withdraw_single_root())
        .map_err(|_| anyhow::anyhow!("invalid receipt input BOC"))
}

impl Intent {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.schema == "tos.operation-delivery-intent/1", "intent schema");
        anyhow::ensure!(
            !self.operation.is_empty()
                && self.operation.len() <= 128
                && self
                    .operation
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || b"-_:.".contains(&v)),
            "operation identity bound"
        );
        for hash in [
            &self.genesis_root,
            &self.genesis_file,
            &self.sender_code_hash,
            &self.recipient_code_hash,
            &self.external_message_hash,
            &self.body_hash,
        ] {
            digest(hash)?;
        }
        let sender: MsgAddressInt = self.sender.parse()?;
        let recipient: MsgAddressInt = self.recipient.parse()?;
        anyhow::ensure!(sender != recipient, "distinct sender and recipient required");
        anyhow::ensure!(
            self.value_nanotos > 0 && self.credited_nanotos <= self.value_nanotos,
            "intent amount bound"
        );
        anyhow::ensure!((1..=1024).contains(&self.history_limit), "history limit bound");
        anyhow::ensure!((1..=300).contains(&self.timeout_seconds), "timeout bound");
        anyhow::ensure!((1..=3600).contains(&self.max_age_seconds), "live age bound");
        let mut endpoints = Vec::new();
        for endpoint in &self.rpc {
            let url = reqwest::Url::parse(endpoint)?;
            anyhow::ensure!(
                matches!(url.scheme(), "http" | "https")
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "plain public RPC endpoint required"
            );
            endpoints.push(url.to_string());
        }
        anyhow::ensure!(endpoints[0] != endpoints[1], "two distinct RPC endpoints required");
        Ok(())
    }

    fn matches(&self, message: &Message) -> anyhow::Result<bool> {
        let Some(header) = message.int_header() else { return Ok(false) };
        let expected_body = digest(&self.body_hash)?;
        // The wire decoder represents an empty inline body as None. It has the
        // same canonical empty-cell body hash as an explicit empty slice.
        let body = message.body().cloned().map(|v| v.into_cell()).transpose()?.unwrap_or_default();
        Ok(header.src_ref() == Some(&self.sender.parse()?)
            && header.dst == self.recipient.parse()?
            && header.value == CurrencyCollection::with_coins(self.value_nanotos)
            && header.bounce == self.bounce
            && !header.bounced
            && message.state_init().is_none()
            && body.repr_hash().as_array() == &expected_body)
    }
}

fn approved_outgoing(
    transaction: &chain_block::Transaction,
    intent: &Intent,
) -> anyhow::Result<Cell> {
    let mut selected = None;
    let mut count = 0;
    transaction.iterate_out_msgs_with_cells(|message, root| {
        count += 1;
        anyhow::ensure!(count <= 1, "single outgoing action required");
        if intent.matches(&message)? {
            selected = Some(root);
        }
        Ok(true)
    })?;
    selected.context("approved outgoing action missing")
}

fn pre_code(receipt: &ProvenTransaction, preimage: Cell, code: &str) -> anyhow::Result<()> {
    let account = receipt.pre_account(preimage)?;
    let expected = digest(code)?;
    anyhow::ensure!(
        account.get_code_hash().is_some_and(|v| v.as_array() == &expected),
        "executed code differs from intent"
    );
    Ok(())
}

fn fresh(account: &ProvenAccountState, age: u32) -> anyhow::Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    for stamp in [account.evidence().block_gen_utime, account.evidence().account.gen_utime] {
        anyhow::ensure!(
            u64::from(stamp) <= now + 60 && now.saturating_sub(u64::from(stamp)) <= u64::from(age),
            "receipt checkpoint became stale"
        );
    }
    Ok(())
}

impl WalletReceiptCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let raw = bounded(&self.intent, 64 << 10)?;
        let intent: Intent = serde_json::from_slice(&raw).context("invalid receipt intent")?;
        intent.validate()?;
        let config: ProofVerifierConfig =
            serde_json::from_slice(&bounded(&self.proof_config, 64 << 10)?)?;
        anyhow::ensure!(
            config.live_max_age_seconds.is_some_and(|v| v <= intent.max_age_seconds),
            "live proof age policy required"
        );
        let anchor: serde_json::Value =
            serde_json::from_slice(&bounded(&config.anchor_file, 64 << 10)?)?;
        anyhow::ensure!(
            anchor["kind"] == "zerostate"
                && anchor["seqno"] == 0
                && anchor["root_hash"] == intent.genesis_root
                && anchor["file_hash"] == intent.genesis_file,
            "intent genesis differs from local proof anchor"
        );
        let sender_pre = cell(&bounded(&self.sender_pre_state, 1 << 20)?)?;
        let recipient_pre = cell(&bounded(&self.recipient_pre_state, 1 << 20)?)?;
        let result = tokio::time::timeout(Duration::from_secs(u64::from(intent.timeout_seconds)), async {
            let provider = ProvenGetterProvider::new(&config)?;
            let sender = provider.read_account(&intent.sender.parse()?, &ReadPolicy::Live).await?;
            let recipient = provider.read_account(&intent.recipient.parse()?, &ReadPolicy::Historical(sender.evidence().checkpoint.clone())).await?;
            sender.require_same_checkpoint(&recipient)?;
            anyhow::ensure!(sender.evidence().account.code_hash == intent.sender_code_hash
                && recipient.evidence().account.code_hash == intent.recipient_code_hash, "current code differs from intent");
            let mut receipts = Vec::new();
            for endpoint in &intent.rpc {
                let rpc = ClientJsonRpc::connect(endpoint.clone(), None)?;
                let timeout = Duration::from_secs(u64::from(intent.timeout_seconds));
                let source = ProvenTransaction::find_inbound_hash_rpc(&sender, digest(&intent.external_message_hash)?, intent.history_limit, timeout, &rpc).await?;
                let request = source.transaction().in_msg_cell().context("proven original request missing")?;
                let message = Message::construct_from_cell(request.clone())?;
                anyhow::ensure!(message.is_inbound_external() && message.dst_ref() == Some(&intent.sender.parse()?), "original request sender mismatch");
                pre_code(&source, sender_pre.clone(), &intent.sender_code_hash)?;
                let outgoing = approved_outgoing(source.transaction(), &intent)?;
                let delivery = ProvenTransaction::find_inbound_rpc(&recipient, &outgoing, intent.history_limit, timeout, &rpc).await?;
                pre_code(&delivery, recipient_pre.clone(), &intent.recipient_code_hash)?;
                let decoded = Message::construct_from_cell(outgoing.clone())?;
                let expected = PaymentExpectation { recipient: intent.recipient.parse()?,
                    value: CurrencyCollection::with_coins(intent.value_nanotos), credited: CurrencyCollection::with_coins(intent.credited_nanotos),
                    bounce: intent.bounce, body: decoded.body().cloned().map(|v|v.into_cell()).transpose()?, state_init: None };
                source.require_payment(&delivery, &request, outgoing.repr_hash().as_array(), &expected)?;
                receipts.push((source.root().repr_hash(), delivery.root().repr_hash(), outgoing.repr_hash()));
            }
            anyhow::ensure!(receipts[0] == receipts[1], "RPC authenticated receipts differ");
            fresh(&sender, intent.max_age_seconds)?;
            fresh(&recipient, intent.max_age_seconds)?;
            Ok::<_, anyhow::Error>(serde_json::json!({"schema":"tos.operation-delivery-receipt/1",
                "status":"AUTHENTICATED_REQUEST_AND_DELIVERY", "operation":intent.operation,
                "intent_sha256":hex::encode(Sha256::digest(&raw)), "checkpoint":{"seqno":sender.evidence().checkpoint.seqno,"root_hash":sender.evidence().checkpoint.root_hash,"file_hash":sender.evidence().checkpoint.file_hash},
                "sender_transaction":receipts[0].0.to_hex_string(), "recipient_transaction":receipts[0].1.to_hex_string(),
                "delivery_message":receipts[0].2.to_hex_string(), "business_acceptance":false,"authorizes_send":false}))
        }).await.map_err(|_| anyhow::anyhow!("receipt deadline exceeded; original operation remains unknown"))??;
        println!("{}", serde_json::to_string(&result)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "Invalid synthetic fixtures must fail the test")]
    use super::*;
    use chain_block::{InternalMessageHeader, Serializable, SliceData, StateInit, Transaction};

    fn intent() -> Intent {
        serde_json::from_value(serde_json::json!({
            "schema":"tos.operation-delivery-intent/1", "operation":"synthetic-1",
            "genesis_root":"11".repeat(32), "genesis_file":"22".repeat(32),
            "sender":format!("0:{}", "33".repeat(32)),
            "recipient":format!("-1:{}", "44".repeat(32)),
            "sender_code_hash":"55".repeat(32), "recipient_code_hash":"66".repeat(32),
            "external_message_hash":"77".repeat(32),
            "body_hash":Cell::default().repr_hash().to_hex_string(),
            "value_nanotos":100, "credited_nanotos":100, "bounce":true,
            "rpc":["http://127.0.0.1:28081/jsonRPC", "http://127.0.0.1:28083/jsonRPC"],
            "history_limit":128, "max_age_seconds":60, "timeout_seconds":60
        }))
        .expect("synthetic intent")
    }

    fn message(intent: &Intent) -> Message {
        let header = InternalMessageHeader::with_addresses_and_bounce(
            intent.sender.parse().expect("source"),
            intent.recipient.parse().expect("destination"),
            CurrencyCollection::with_coins(intent.value_nanotos),
            intent.bounce,
        );
        let mut message = Message::with_int_header(header);
        message.set_body(SliceData::load_cell(Cell::default()).expect("synthetic body"));
        message
    }

    #[test]
    fn receipt_cli_requires_public_inputs_and_has_no_carrier_argument() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            wallet: super::super::wallet_cmd::WalletCmd,
        }
        let args = [
            "wallet",
            "receipt",
            "--intent",
            "intent.json",
            "--sender-pre-state",
            "sender.boc",
            "--recipient-pre-state",
            "recipient.boc",
            "--proof-config",
            "proof.json",
        ];
        assert!(Cli::try_parse_from(args).is_ok());
        assert_eq!(
            Cli::try_parse_from(["wallet", "receipt"]).err().expect("missing inputs").kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        let mut with_carrier = args.to_vec();
        with_carrier.extend(["--request-file", "never-opened.boc"]);
        assert_eq!(
            Cli::try_parse_from(with_carrier).err().expect("no carrier option").kind(),
            clap::error::ErrorKind::UnknownArgument
        );
    }

    #[test]
    fn receipt_refuses_an_extra_unapproved_outgoing_action() {
        let intent = intent();
        let approved = message(&intent);
        let decoded = Message::construct_from_cell(approved.serialize().expect("wire cell"))
            .expect("wire message");
        assert!(intent.matches(&decoded).expect("empty body survives wire roundtrip"));
        let mut transaction = Transaction::default();
        transaction.add_out_message(&approved).expect("approved action");
        assert_eq!(
            approved_outgoing(&transaction, &intent).expect("single action").repr_hash(),
            approved.serialize().expect("approved cell").repr_hash()
        );
        let mut extra = message(&intent);
        extra.int_header_mut().expect("internal").dst =
            format!("0:{}", "99".repeat(32)).parse().expect("unapproved destination");
        assert!(!intent.matches(&extra).expect("different action"));
        transaction.add_out_message(&extra).expect("extra action");
        assert!(
            approved_outgoing(&transaction, &intent)
                .expect_err("single-action refusal")
                .to_string()
                .contains("single outgoing")
        );
    }

    #[test]
    fn receipt_delivery_requires_each_approved_field() {
        for changed in ["source", "destination", "value", "bounce", "bounced", "body", "init"] {
            let mut intent = intent();
            intent.validate().expect("valid intent");
            let mut message = message(&intent);
            assert!(intent.matches(&message).expect("positive match"));
            match changed {
                "source" => intent.sender = format!("0:{}", "88".repeat(32)),
                "destination" => intent.recipient = format!("-1:{}", "88".repeat(32)),
                "value" => intent.value_nanotos += 1,
                "bounce" => intent.bounce = false,
                "bounced" => message.int_header_mut().expect("internal").bounced = true,
                "body" => intent.body_hash = "88".repeat(32),
                "init" => message.set_state_init(StateInit::default()),
                _ => unreachable!(),
            }
            assert!(!intent.matches(&message).expect("match result"), "accepted changed {changed}");
        }
    }

    #[test]
    fn receipt_intent_refuses_unbounded_or_ambiguous_lookup() {
        for changed in
            ["schema", "history", "timeout", "age", "operation", "digest", "rpc", "credit"]
        {
            let mut intent = intent();
            intent.validate().expect("positive intent");
            let expected = match changed {
                "schema" => {
                    intent.schema.clear();
                    "intent schema"
                }
                "history" => {
                    intent.history_limit = 1025;
                    "history limit bound"
                }
                "timeout" => {
                    intent.timeout_seconds = 301;
                    "timeout bound"
                }
                "age" => {
                    intent.max_age_seconds = 3601;
                    "live age bound"
                }
                "operation" => {
                    intent.operation = "x".repeat(129);
                    "operation identity bound"
                }
                "digest" => {
                    intent.external_message_hash = "AA".repeat(32);
                    "canonical lowercase digest"
                }
                "rpc" => {
                    intent.rpc[1] = intent.rpc[0].clone();
                    "two distinct RPC endpoints"
                }
                "credit" => {
                    intent.credited_nanotos = 101;
                    "intent amount bound"
                }
                _ => unreachable!(),
            };
            let error = intent.validate().expect_err("intended refusal");
            assert!(error.to_string().contains(expected), "wrong refusal for {changed}: {error}");
        }
    }

    #[test]
    fn receipt_input_refuses_symlink_nonregular_and_oversize() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("synthetic.boc");
        std::fs::write(&path, [1, 2, 3]).expect("synthetic bytes");
        assert_eq!(bounded(&path, 3).expect("bounded file"), [1, 2, 3]);
        assert!(bounded(&path, 2).expect_err("byte bound").to_string().contains("input bound"));
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(bounded(&link, 3).is_err());
        assert!(
            bounded(dir.path(), 3).expect_err("regular file").to_string().contains("input bound")
        );
    }
}
