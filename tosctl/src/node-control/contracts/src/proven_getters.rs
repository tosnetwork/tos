/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Get-method results proven from an authenticated masterchain block.
//!
//! An RPC endpoint that reports a block identity and a get-method stack in
//! the same response proves nothing: it can return any stack under the
//! expected identity. This module never asks an endpoint for a stack. It hands
//! the read to the locally installed `tos-proof-verify` executable, which
//!
//! * authenticates the target masterchain block through a continuous chain of
//!   post-quantum finality proofs from the locally provisioned anchor,
//! * proves the requested account's state from that block (through the shard
//!   block for a basechain account), and
//! * runs every requested get-method locally on that one proven state, with
//!   an execution context built only from proven inputs.
//!
//! The verifier's answer is then bound back to this request: the anchor, the
//! target, the request digest, the account and every method and argument must
//! match what was asked, and live reads must be fresh by the local clock.
//! Anything else -- a refusal, a nonzero exit, a timeout, malformed or partial
//! output, or any mismatch -- yields no result. There is no fallback to an
//! endpoint-reported stack.
//!
//! Which executable runs, which anchor it starts from and how old a live read
//! may be all come from local configuration ([`ProofVerifierConfig`]); nothing
//! an endpoint returns can choose them.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use base64::Engine as _;
use chain_block::{Account, Cell, Deserializable, MsgAddressInt, read_single_root_boc};
use common::app_config::{PROOF_VERIFIER_MAX_LIVE_AGE_SECONDS, ProofVerifierConfig};
use common::tvm_stack_parser::TvmStackParser;
use serde::Deserialize;
use sha2::Digest as _;
use tl_api::tos::tvm::{
    Number, StackEntry, Tuple, cell,
    numberdecimal::NumberDecimal,
    slice,
    stackentry::{StackEntryCell, StackEntryNumber, StackEntrySlice, StackEntryTuple},
    tuple,
};
use tokio::io::AsyncReadExt as _;

use crate::MasterchainCheckpoint;

/// The only verifier interface this module accepts.
pub const PROOF_VERIFIER_INTERFACE: &str = "tos-proof-verify/1";

const MASTERCHAIN_SHARD: &str = "8000000000000000";
/// Bounds on what is read back from the verifier.
const MAX_VERIFIER_OUTPUT_BYTES: u64 = 64 << 20;
const MAX_REFUSAL_REASON_CHARS: usize = 512;
const MAX_STACK_NESTING: usize = 16;
const MAX_STACK_ENTRIES: usize = 4096;
/// Bounds the verifier itself applies to a request.
const MAX_GET_METHODS: usize = 16;
const MAX_GET_METHOD_ARGS: usize = 64;
const MAX_METHOD_NAME_CHARS: usize = 127;
/// A target dated further ahead of the local clock than this is refused,
/// matching the verifier's own allowance.
const MAX_FUTURE_SKEW_SECONDS: i64 = 60;

/// Which block a proven read is taken at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadPolicy {
    /// Exactly this masterchain block, of any age. The read is explicitly
    /// historical: it says nothing about whether newer blocks exist.
    Historical(MasterchainCheckpoint),
    /// The newest block the endpoint offers, authenticated, no older than the
    /// locally configured maximum age, and neither below nor in conflict with
    /// the newest block this verifier already authenticated. Proofs establish
    /// finality, not recency: an endpoint can still withhold newer blocks up to
    /// that age.
    Live,
}

/// One get-method argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GetMethodArg {
    Null,
    /// A decimal integer in canonical form (no sign on zero, no leading zeros).
    Int(String),
}

/// One get-method to run on the proven account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetMethodCall {
    pub method: String,
    /// Bottom first, in the order the method takes them.
    pub args: Vec<GetMethodArg>,
}

impl GetMethodCall {
    pub fn new(method: &str) -> Self {
        Self { method: method.to_owned(), args: Vec::new() }
    }
}

/// The proven account the get-methods ran on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenAccount {
    /// `workchain:hex`, lowercase.
    pub address: String,
    pub state_hash: String,
    /// Decimal nanotos.
    pub balance: String,
    pub code_hash: String,
    pub data_hash: String,
    pub last_trans_lt: u64,
    /// Time of the shard block that holds the account state.
    pub gen_utime: u32,
}

/// One get-method result, computed locally on the proven account.
#[derive(Debug)]
pub struct ProvenGetMethod {
    pub method: String,
    pub exit_code: i32,
    pub gas_used: u64,
    /// Bottom first: entry 0 is the first value the method returned.
    pub stack: TvmStackParser,
}

/// Everything a proven read returns.
#[derive(Debug)]
pub struct ProvenGetterResults {
    pub live: bool,
    /// The authenticated masterchain block the read was taken at.
    pub checkpoint: MasterchainCheckpoint,
    pub block_gen_utime: u32,
    pub account: ProvenAccount,
    /// In request order.
    pub results: Vec<ProvenGetMethod>,
    /// SHA-256 of the request the verifier answered.
    pub request_sha256: String,
}

/// Raw account state authenticated by the configured local proof verifier.
/// Fields are private so unverified RPC data cannot construct this capability.
/// A historical read proves no freshness; live freshness is bounded by policy.
pub struct ProvenAccountState {
    evidence: ProvenGetterResults,
    root: Cell,
    account: Account,
}

impl ProvenAccountState {
    pub fn evidence(&self) -> &ProvenGetterResults {
        &self.evidence
    }
    pub fn root(&self) -> &Cell {
        &self.root
    }
    pub fn account(&self) -> &Account {
        &self.account
    }
}

/// The local clock, in Unix seconds.
pub type LocalClock = Arc<dyn Fn() -> i64 + Send + Sync>;

fn system_clock() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Runs get-methods on proven account state through the trusted verifier.
pub struct ProvenGetterProvider {
    config: ProofVerifierConfig,
    anchor: AnchorRecord,
    clock: LocalClock,
}

impl std::fmt::Debug for ProvenGetterProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvenGetterProvider")
            .field("executable", &self.config.executable)
            .field("anchor", &self.anchor)
            .finish()
    }
}

/// The anchor exactly as provisioned locally.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorRecord {
    kind: String,
    workchain: i32,
    shard: String,
    seqno: u32,
    root_hash: String,
    file_hash: String,
}

impl AnchorRecord {
    fn validate(&self) -> anyhow::Result<()> {
        match self.kind.as_str() {
            "zerostate" => anyhow::ensure!(self.seqno == 0, "a zerostate anchor has seqno 0"),
            "key_block" => anyhow::ensure!(self.seqno > 0, "a key block anchor has seqno > 0"),
            other => anyhow::bail!("unknown anchor kind {other}"),
        }
        anyhow::ensure!(
            self.workchain == -1 && self.shard == MASTERCHAIN_SHARD,
            "the anchor must be a masterchain block"
        );
        ensure_digest(&self.root_hash, "anchor root hash")?;
        ensure_digest(&self.file_hash, "anchor file hash")?;
        Ok(())
    }
}

impl ProvenGetterProvider {
    /// Loads the locally provisioned anchor and checks the configuration. The
    /// executable is not trusted to exist yet; a missing one refuses each read.
    pub fn new(config: &ProofVerifierConfig) -> anyhow::Result<Self> {
        config.validate()?;
        let text = std::fs::read(&config.anchor_file).with_context(|| {
            format!("cannot read proof anchor {}", config.anchor_file.display())
        })?;
        anyhow::ensure!(text.len() <= 1 << 16, "proof anchor file is too large");
        let anchor: AnchorRecord =
            serde_json::from_slice(&text).context("proof anchor file is malformed")?;
        anchor.validate().context("proof anchor file is invalid")?;
        Ok(Self { config: config.clone(), anchor, clock: Arc::new(system_clock) })
    }

    /// Replaces the local clock live reads are judged against.
    pub fn with_clock(mut self, clock: LocalClock) -> Self {
        self.clock = clock;
        self
    }

    /// Runs `calls` on the proven state of `address` at the block `policy`
    /// names. Either every result is proven and bound to this request, or
    /// there is no result.
    pub async fn run(
        &self,
        address: &MsgAddressInt,
        calls: &[GetMethodCall],
        policy: &ReadPolicy,
    ) -> anyhow::Result<ProvenGetterResults> {
        anyhow::ensure!(!calls.is_empty(), "a proven read needs at least one get-method");
        let account = canonical_address(address)?;
        let request = Request::build(&account, calls, policy, &self.config)?;
        let output = self.invoke(&request.bytes, policy).await?;
        check_verified(&output, &request, &self.anchor, (self.clock)())
    }

    /// Authenticate raw state without executing a get-method. The material
    /// directory must contain account/chain proofs only, without execution config.
    pub async fn read_account(
        &self,
        address: &MsgAddressInt,
        policy: &ReadPolicy,
    ) -> anyhow::Result<ProvenAccountState> {
        let address = canonical_address(address)?;
        let request = Request::build(&address, &[], policy, &self.config)?;
        let output = self.invoke(&request.bytes, policy).await?;
        let evidence = check_verified(&output, &request, &self.anchor, (self.clock)())?;
        let wire: VerifiedOutput = serde_json::from_slice(&output)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(wire.account.state_boc.context("proof verifier omitted raw account state")?)
            .context("invalid account state base64")?;
        let root = read_single_root_boc(&bytes).context("invalid account state BOC")?;
        anyhow::ensure!(
            root.repr_hash().to_hex_string() == evidence.account.state_hash,
            "raw account state hash mismatch"
        );
        let account = Account::construct_from_cell(root.clone())?;
        anyhow::ensure!(
            canonical_address(account.get_addr().context("raw account has no address")?)?
                == address,
            "raw account address mismatch"
        );
        anyhow::ensure!(
            account.get_code_hash().context("raw account has no code")?.to_hex_string()
                == evidence.account.code_hash
                && account.get_data_hash().context("raw account has no data")?.to_hex_string()
                    == evidence.account.data_hash,
            "raw account code/data mismatch"
        );
        anyhow::ensure!(
            account.get_balance().context("raw account has no balance")?.coins.to_string()
                == evidence.account.balance,
            "raw account balance mismatch"
        );
        Ok(ProvenAccountState { evidence, root, account })
    }

    async fn invoke(&self, request: &[u8], policy: &ReadPolicy) -> anyhow::Result<Vec<u8>> {
        let workdir = tempfile::Builder::new()
            .prefix("tos-proof-read-")
            .tempdir()
            .context("cannot create a private directory for the proof request")?;
        let request_path = workdir.path().join("request.json");
        std::fs::write(&request_path, request).context("cannot write the proof request")?;

        let mut command = tokio::process::Command::new(&self.config.executable);
        command
            .arg("verify")
            .arg("--anchor")
            .arg(&self.config.anchor_file)
            .arg("--request")
            .arg(&request_path);
        match (&self.config.liteserver_config, &self.config.material_dir) {
            (Some(liteserver), None) => {
                command.arg("--liteserver").arg(liteserver);
            }
            (None, Some(material)) => {
                command.arg("--material").arg(material);
            }
            _ => anyhow::bail!("proof verifier needs exactly one material source"),
        }
        if *policy == ReadPolicy::Live {
            let state = self
                .config
                .live_state_file
                .as_deref()
                .context("live proven reads need a configured live state file")?;
            command.arg("--state").arg(state);
        }
        command
            .arg("--min-interval-ms")
            .arg(self.config.min_interval_ms.to_string())
            .arg("--timeout-seconds")
            .arg(self.config.timeout_seconds.min(600).to_string())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            // Diagnostics are not read: an undrained pipe could stall the
            // verifier, and only the machine-readable answer is evidence.
            .stderr(Stdio::null())
            .kill_on_drop(true);

        let mut child = command.spawn().with_context(|| {
            format!("cannot start the proof verifier {}", self.config.executable.display())
        })?;
        let mut stdout = child.stdout.take().context("proof verifier has no output pipe")?;
        let deadline = Duration::from_secs(u64::from(self.config.timeout_seconds));
        let run = async {
            let mut buffer = Vec::new();
            (&mut stdout)
                .take(MAX_VERIFIER_OUTPUT_BYTES.saturating_add(1))
                .read_to_end(&mut buffer)
                .await
                .context("cannot read the proof verifier's answer")?;
            anyhow::ensure!(
                u64::try_from(buffer.len()).unwrap_or(u64::MAX) <= MAX_VERIFIER_OUTPUT_BYTES,
                "proof verifier answer exceeds {MAX_VERIFIER_OUTPUT_BYTES} bytes"
            );
            let status = child.wait().await.context("cannot wait for the proof verifier")?;
            Ok::<_, anyhow::Error>((status, buffer))
        };
        let (status, buffer) = tokio::time::timeout(deadline, run)
            .await
            .map_err(|_| anyhow::anyhow!("proof verifier did not answer within {deadline:?}"))??;
        match status.code() {
            Some(0) => Ok(buffer),
            Some(code) => {
                anyhow::bail!("proof verifier refused (exit {code}): {}", refusal_reason(&buffer))
            }
            None => anyhow::bail!("proof verifier was terminated by a signal"),
        }
    }

    pub fn executable(&self) -> &Path {
        &self.config.executable
    }

    pub fn anchor_file(&self) -> &PathBuf {
        &self.config.anchor_file
    }
}

fn refusal_reason(output: &[u8]) -> String {
    #[derive(Deserialize)]
    struct Refusal {
        reason: String,
    }
    match serde_json::from_slice::<Refusal>(output) {
        Ok(refusal) => refusal.reason.chars().take(MAX_REFUSAL_REASON_CHARS).collect(),
        Err(_) => "no readable refusal".to_owned(),
    }
}

/// `workchain:hex` for a standard address on a workchain the verifier serves.
fn canonical_address(address: &MsgAddressInt) -> anyhow::Result<String> {
    let MsgAddressInt::AddrStd(std) = address else {
        anyhow::bail!("proven reads need a standard address");
    };
    anyhow::ensure!(std.anycast.is_none(), "proven reads do not accept anycast addresses");
    anyhow::ensure!(
        std.workchain_id == -1 || std.workchain_id == 0,
        "proven reads serve the masterchain and the basechain only"
    );
    anyhow::ensure!(std.address.remaining_bits() == 256, "account address must be 256 bits");
    let bytes = std.address.get_bytestring(0);
    anyhow::ensure!(bytes.len() == 32, "account address must be 32 bytes");
    Ok(format!("{}:{}", std.workchain_id, hex::encode(bytes)))
}

fn ensure_digest(value: &str, what: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        value.len() == 64 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "{what} must be 32 bytes of lowercase hex"
    );
    Ok(())
}

fn ensure_canonical_decimal(value: &str) -> anyhow::Result<()> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    anyhow::ensure!(
        !digits.is_empty()
            && digits.len() <= 80
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'))
            && value != "-0",
        "get-method integer argument {value:?} is not a canonical decimal"
    );
    Ok(())
}

fn render_arg(arg: &GetMethodArg) -> anyhow::Result<serde_json::Value> {
    Ok(match arg {
        GetMethodArg::Null => serde_json::json!({"type": "null"}),
        GetMethodArg::Int(value) => {
            ensure_canonical_decimal(value)?;
            serde_json::json!({"type": "int", "value": value})
        }
    })
}

/// The exact request handed to the verifier, and what its answer must echo.
struct Request {
    bytes: Vec<u8>,
    sha256: String,
    account: String,
    policy: ReadPolicy,
    max_age_seconds: Option<u32>,
    methods: Vec<(String, Vec<serde_json::Value>)>,
}

impl Request {
    fn build(
        account: &str,
        calls: &[GetMethodCall],
        policy: &ReadPolicy,
        config: &ProofVerifierConfig,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(calls.len() <= MAX_GET_METHODS, "at most {MAX_GET_METHODS} get-methods");
        let mut methods = Vec::with_capacity(calls.len());
        let mut rendered_calls = Vec::with_capacity(calls.len());
        for call in calls {
            anyhow::ensure!(
                !call.method.is_empty()
                    && call.method.len() <= MAX_METHOD_NAME_CHARS
                    && call.method.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "get-method name {:?} is not valid",
                call.method
            );
            anyhow::ensure!(
                call.args.len() <= MAX_GET_METHOD_ARGS,
                "get-method {} takes at most {MAX_GET_METHOD_ARGS} arguments",
                call.method
            );
            let args = call.args.iter().map(render_arg).collect::<anyhow::Result<Vec<_>>>()?;
            rendered_calls.push(serde_json::json!({"method": call.method, "args": args}));
            methods.push((call.method.clone(), args));
        }
        let mut request = serde_json::Map::new();
        request.insert("account".to_owned(), account.into());
        if !calls.is_empty() {
            request.insert("get_methods".to_owned(), rendered_calls.into());
        }
        let max_age_seconds = match policy {
            ReadPolicy::Historical(checkpoint) => {
                anyhow::ensure!(checkpoint.seqno > 0, "a historical read needs a non-zero block");
                ensure_digest(&checkpoint.root_hash, "checkpoint root hash")?;
                ensure_digest(&checkpoint.file_hash, "checkpoint file hash")?;
                request.insert("mode".to_owned(), "historical".into());
                request.insert(
                    "target".to_owned(),
                    serde_json::json!({
                        "seqno": checkpoint.seqno,
                        "root_hash": checkpoint.root_hash,
                        "file_hash": checkpoint.file_hash,
                    }),
                );
                None
            }
            ReadPolicy::Live => {
                let age = config
                    .live_max_age_seconds
                    .context("live proven reads need a configured maximum age")?;
                anyhow::ensure!(
                    (1..=PROOF_VERIFIER_MAX_LIVE_AGE_SECONDS).contains(&age),
                    "live maximum age is out of range"
                );
                anyhow::ensure!(
                    config.live_state_file.is_some(),
                    "live proven reads need a configured live state file"
                );
                request.insert("mode".to_owned(), "live".into());
                request.insert("max_age_seconds".to_owned(), age.into());
                Some(age)
            }
        };
        let bytes = serde_json::to_vec(&serde_json::Value::Object(request))?;
        let sha256 = hex::encode(sha2::Sha256::digest(&bytes));
        Ok(Self {
            bytes,
            sha256,
            account: account.to_owned(),
            policy: policy.clone(),
            max_age_seconds,
            methods,
        })
    }
}

#[derive(Deserialize)]
struct VerifiedOutput {
    status: String,
    interface: String,
    mode: String,
    anchor: AnchorRecord,
    target: TargetBlock,
    #[serde(default)]
    live: Option<LiveOutput>,
    request_sha256: String,
    account: AccountOutput,
    #[serde(default)]
    execution_context: serde_json::Value,
    #[serde(default)]
    get_methods: Vec<MethodOutput>,
}

#[derive(Deserialize)]
struct TargetBlock {
    workchain: i32,
    shard: String,
    seqno: u32,
    root_hash: String,
    file_hash: String,
    gen_utime: u32,
}

#[derive(Deserialize)]
struct BlockId {
    workchain: i32,
    shard: String,
    seqno: u32,
    root_hash: String,
    file_hash: String,
}

#[derive(Deserialize)]
struct LiveOutput {
    now: i64,
    age_seconds: i64,
    max_age_seconds: i64,
}

#[derive(Deserialize)]
struct AccountOutput {
    #[serde(default)]
    state_boc: Option<String>,
    address: String,
    shard_block: BlockId,
    exists: bool,
    active: bool,
    state_hash: String,
    balance: String,
    code_hash: String,
    data_hash: String,
    last_trans_lt: u64,
    gen_utime: u32,
}

#[derive(Deserialize)]
struct MethodOutput {
    method: String,
    method_id: i64,
    args: Vec<serde_json::Value>,
    exit_code: i32,
    gas_used: u64,
    stack: Vec<serde_json::Value>,
}

/// Get-method id as the VM computes it from the method name.
fn method_id(name: &str) -> i64 {
    let mut crc: u16 = 0;
    for byte in name.bytes() {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    i64::from(crc) | 0x10000
}

/// Binds the verifier's answer to the request it was given. Every field the
/// caller relies on is checked; a missing one is a refusal.
fn check_verified(
    output: &[u8],
    request: &Request,
    anchor: &AnchorRecord,
    now: i64,
) -> anyhow::Result<ProvenGetterResults> {
    let text = std::str::from_utf8(output).context("proof verifier answer is not UTF-8")?;
    let body = text.strip_suffix('\n').context("proof verifier answer is not one line")?;
    anyhow::ensure!(!body.contains('\n'), "proof verifier answer is not one JSON object");
    let value: serde_json::Value =
        serde_json::from_str(body).context("proof verifier answer is malformed or incomplete")?;
    if !request.methods.is_empty() {
        anyhow::ensure!(
            value.get("get_methods").is_some() && value.get("execution_context").is_some(),
            "proof verifier answer is malformed or incomplete"
        );
    }
    let verified: VerifiedOutput = serde_json::from_value(value)
        .context("proof verifier answer is malformed or incomplete")?;

    anyhow::ensure!(verified.status == "verified", "proof verifier did not verify the read");
    anyhow::ensure!(
        verified.interface == PROOF_VERIFIER_INTERFACE,
        "proof verifier speaks another interface"
    );
    anyhow::ensure!(verified.anchor == *anchor, "proof verifier started from another anchor");
    anyhow::ensure!(
        verified.request_sha256 == request.sha256,
        "proof verifier answered another request"
    );

    let target = &verified.target;
    anyhow::ensure!(
        target.workchain == -1 && target.shard == MASTERCHAIN_SHARD && target.seqno > 0,
        "proven target is not a masterchain block"
    );
    ensure_digest(&target.root_hash, "proven target root hash")?;
    ensure_digest(&target.file_hash, "proven target file hash")?;
    anyhow::ensure!(
        i64::from(target.gen_utime) <= now.saturating_add(MAX_FUTURE_SKEW_SECONDS),
        "proven target is dated in the future of the local clock"
    );
    let checkpoint = MasterchainCheckpoint {
        seqno: target.seqno,
        root_hash: target.root_hash.clone(),
        file_hash: target.file_hash.clone(),
    };
    let live = match &request.policy {
        ReadPolicy::Historical(expected) => {
            anyhow::ensure!(verified.mode == "historical", "proof verifier did a live read");
            anyhow::ensure!(verified.live.is_none(), "historical read carries live evidence");
            anyhow::ensure!(checkpoint == *expected, "proof verifier answered for another block");
            false
        }
        ReadPolicy::Live => {
            anyhow::ensure!(verified.mode == "live", "proof verifier did a historical read");
            let max_age = i64::from(request.max_age_seconds.context("live read without age")?);
            let live = verified.live.as_ref().context("live read carries no live evidence")?;
            anyhow::ensure!(
                live.max_age_seconds == max_age,
                "proof verifier applied another maximum age"
            );
            anyhow::ensure!(
                (0..=max_age).contains(&live.age_seconds)
                    && live.now.saturating_sub(i64::from(target.gen_utime)) == live.age_seconds,
                "proof verifier reported an inconsistent age"
            );
            let local_age = now.saturating_sub(i64::from(target.gen_utime));
            anyhow::ensure!(
                local_age <= max_age,
                "proven block is {local_age} s old by the local clock, above {max_age} s"
            );
            true
        }
    };

    let account = &verified.account;
    anyhow::ensure!(account.address == request.account, "proof verifier read another account");
    anyhow::ensure!(account.exists && account.active, "proven account is not active");
    let shard = &account.shard_block;
    let account_workchain: i32 = if request.account.starts_with("-1:") { -1 } else { 0 };
    anyhow::ensure!(
        shard.workchain == account_workchain,
        "account was proven from a block of another workchain"
    );
    if account_workchain == -1 {
        anyhow::ensure!(
            shard.shard == target.shard
                && shard.seqno == target.seqno
                && shard.root_hash == target.root_hash
                && shard.file_hash == target.file_hash,
            "masterchain account was proven from another block"
        );
    }
    for (value, what) in [
        (&account.state_hash, "account state hash"),
        (&account.code_hash, "account code hash"),
        (&account.data_hash, "account data hash"),
        (&shard.root_hash, "shard block root hash"),
        (&shard.file_hash, "shard block file hash"),
    ] {
        ensure_digest(value, what)?;
    }
    anyhow::ensure!(
        !account.balance.is_empty() && account.balance.bytes().all(|b| b.is_ascii_digit()),
        "proven balance is not a decimal"
    );
    anyhow::ensure!(
        request.methods.is_empty() || verified.execution_context.is_object(),
        "proof verifier reported no execution context"
    );

    anyhow::ensure!(
        verified.get_methods.len() == request.methods.len(),
        "proof verifier ran {} get-methods, {} were requested",
        verified.get_methods.len(),
        request.methods.len()
    );
    let mut results = Vec::with_capacity(request.methods.len());
    for (method, (name, args)) in verified.get_methods.iter().zip(&request.methods) {
        anyhow::ensure!(method.method == *name, "proof verifier ran {} for {name}", method.method);
        anyhow::ensure!(
            method.method_id == method_id(name),
            "proof verifier ran another method id for {name}"
        );
        anyhow::ensure!(method.args == *args, "proof verifier ran {name} with other arguments");
        anyhow::ensure!(
            method.exit_code == 0 || method.exit_code == 1,
            "get-method {name} exited with {}",
            method.exit_code
        );
        let mut budget = MAX_STACK_ENTRIES;
        let stack = method
            .stack
            .iter()
            .map(|entry| stack_entry(entry, 0, &mut budget))
            .collect::<anyhow::Result<Vec<_>>>()
            .with_context(|| format!("get-method {name} result"))?;
        results.push(ProvenGetMethod {
            method: name.clone(),
            exit_code: method.exit_code,
            gas_used: method.gas_used,
            stack: TvmStackParser::new(stack),
        });
    }

    Ok(ProvenGetterResults {
        live,
        block_gen_utime: target.gen_utime,
        checkpoint,
        account: ProvenAccount {
            address: account.address.clone(),
            state_hash: account.state_hash.clone(),
            balance: account.balance.clone(),
            code_hash: account.code_hash.clone(),
            data_hash: account.data_hash.clone(),
            last_trans_lt: account.last_trans_lt,
            gen_utime: account.gen_utime,
        },
        results,
        request_sha256: request.sha256.clone(),
    })
}

/// Converts one verifier stack entry into the stack representation the
/// contract decoders read. A TVM null becomes the unsupported entry, which is
/// what those decoders treat as null.
fn stack_entry(
    value: &serde_json::Value,
    depth: usize,
    budget: &mut usize,
) -> anyhow::Result<StackEntry> {
    anyhow::ensure!(depth <= MAX_STACK_NESTING, "stack nesting exceeds {MAX_STACK_NESTING}");
    *budget = budget.checked_sub(1).context("stack has too many entries")?;
    let object = value.as_object().context("stack entry is not an object")?;
    let kind = object.get("type").and_then(|v| v.as_str()).context("stack entry has no type")?;
    let boc = || -> anyhow::Result<Vec<u8>> {
        let text = object.get("boc").and_then(|v| v.as_str()).context("stack entry has no boc")?;
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .context("stack entry boc is not base64")
    };
    Ok(match kind {
        "null" => StackEntry::Tvm_StackEntryUnsupported,
        "int" => {
            let decimal =
                object.get("value").and_then(|v| v.as_str()).context("integer has no value")?;
            ensure_canonical_decimal(decimal)?;
            StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
                number: Number::Tvm_NumberDecimal(NumberDecimal { number: decimal.to_owned() }),
            })
        }
        "cell" => {
            StackEntry::Tvm_StackEntryCell(StackEntryCell { cell: cell::Cell { bytes: boc()? } })
        }
        "slice" => StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
            slice: slice::Slice { bytes: boc()? },
        }),
        "tuple" => {
            let items =
                object.get("items").and_then(|v| v.as_array()).context("tuple has no items")?;
            let elements = items
                .iter()
                .map(|item| stack_entry(item, depth.saturating_add(1), budget))
                .collect::<anyhow::Result<Vec<_>>>()?;
            StackEntry::Tvm_StackEntryTuple(StackEntryTuple {
                tuple: Tuple::Tvm_Tuple(tuple::Tuple { elements }),
            })
        }
        other => anyhow::bail!("get-method returned a {other} value, which no decoder accepts"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_ids_match_the_vm() {
        // Values the verifier reported for these names on a real chain.
        assert_eq!(method_id("active_election_id"), 86535);
        assert_eq!(method_id("past_election_ids"), 104565);
        assert_eq!(method_id("compute_returned_stake"), 130944);
    }

    #[test]
    fn non_canonical_integers_are_refused() {
        for bad in ["", "-", "-0", "007", "1.5", "+1", "0x10"] {
            assert!(ensure_canonical_decimal(bad).is_err(), "{bad:?}");
        }
        for good in ["0", "5", "-5", "123456789012345678901234567890"] {
            assert!(ensure_canonical_decimal(good).is_ok(), "{good:?}");
        }
    }
}

#[cfg(test)]
mod fee_state_tests {
    use super::*;
    use crate::wallet_v5r2_genesis::{CodeBundle, CodeHashes, GenesisParameters, WalletGenesis};
    use crate::wallet_v5r2_pop::RescuePolicy;
    use crate::wallet_v5r2_state::ProvenInitialFeeVault;
    use chain_block::{BuilderData, CurrencyCollection, IBitstring, Serializable, StateInit};

    // Synthetic account, deliberately not evidence of a cryptographic proof.
    fn fixture() -> (WalletGenesis, ProvenAccountState) {
        let code = Cell::default();
        let hash = *code.repr_hash().as_array();
        let bundle = CodeBundle::new(
            code.clone(),
            code.clone(),
            code,
            CodeHashes { wallet: hash, module: hash, vault: hash },
        )
        .unwrap();
        let mut key = [0; 60];
        key[..4].copy_from_slice(&1u32.to_be_bytes());
        key[4..8].copy_from_slice(&8u32.to_be_bytes());
        key[8..12].copy_from_slice(&3u32.to_be_bytes());
        let genesis = WalletGenesis::new(
            bundle,
            GenesisParameters {
                global_id: 42,
                network: [1; 32],
                wallet_id: 42,
                primary_key: [2; 1312],
                rescue_key: [3; 32],
                policy: RescuePolicy::Required,
                fee_tree_id: [4; 32],
                fee_public_key: key,
                epoch0: 1000,
            },
        )
        .unwrap();
        let address = format!("0:{}", genesis.vault_init().repr_hash().to_hex_string());
        let account = Account::active(
            address.parse().unwrap(),
            CurrencyCollection::with_coins(100),
            0,
            4600,
            StateInit::construct_from_cell(genesis.vault_init().clone()).unwrap(),
            0,
        )
        .unwrap();
        let root = account.serialize().unwrap();
        let state = ProvenAccountState {
            root: root.clone(),
            account,
            evidence: ProvenGetterResults {
                live: true,
                checkpoint: MasterchainCheckpoint {
                    seqno: 1,
                    root_hash: "00".repeat(32),
                    file_hash: "00".repeat(32),
                },
                block_gen_utime: 4610,
                account: ProvenAccount {
                    address,
                    state_hash: root.repr_hash().to_hex_string(),
                    balance: "100".into(),
                    code_hash: hex::encode(hash),
                    data_hash: genesis.vault_data().repr_hash().to_hex_string(),
                    last_trans_lt: 0,
                    gen_utime: 4600,
                },
                results: vec![],
                request_sha256: "00".repeat(32),
            },
        };
        (genesis, state)
    }

    fn account_proof(mut proof: ProvenAccountState, init: &Cell) -> ProvenAccountState {
        let address = format!("0:{}", init.repr_hash().to_hex_string());
        proof.account = Account::active(
            address.parse().unwrap(),
            CurrencyCollection::with_coins(100),
            0,
            4600,
            StateInit::construct_from_cell(init.clone()).unwrap(),
            0,
        )
        .unwrap();
        proof.evidence.account.address = address;
        refresh_proof_data(&mut proof);
        proof
    }
    fn refresh_proof_data(proof: &mut ProvenAccountState) {
        proof.root = proof.account.serialize().unwrap();
        proof.evidence.account.state_hash = proof.root.repr_hash().to_hex_string();
        proof.evidence.account.data_hash = proof.account.get_data_hash().unwrap().to_hex_string();
        proof.evidence.account.code_hash = proof.account.get_code_hash().unwrap().to_hex_string();
    }
    fn wallet_pair() -> (WalletGenesis, ProvenAccountState, ProvenAccountState) {
        let (g, proof) = fixture();
        let wallet = account_proof(proof, g.wallet_init());
        let (_, proof) = fixture();
        let mut module = account_proof(proof, g.module_init());
        module.evidence.live = false; // Historical at the wallet's live checkpoint.
        (g, wallet, module)
    }
    fn set_wallet_counters(
        g: &WalletGenesis,
        wallet: &mut ProvenAccountState,
        seqno: u32,
        epoch: u64,
        primary: u64,
        rescue: u64,
    ) {
        let mut a = BuilderData::new();
        a.append_u8(4).unwrap();
        a.append_raw(&[0x80], 2).unwrap();
        a.append_u16(0).unwrap();
        a.append_u64(epoch).unwrap();
        a.append_u64(primary).unwrap();
        a.append_u64(rescue).unwrap();
        a.checked_append_reference(g.module_init().clone()).unwrap();
        a.checked_append_reference(g.metadata().clone()).unwrap();
        let mut w = BuilderData::new();
        w.append_bit_zero().unwrap();
        w.append_u32(seqno).unwrap();
        w.append_u32(42).unwrap();
        w.append_u256(&[0; 32]).unwrap();
        w.append_bit_zero().unwrap();
        w.checked_append_reference(a.into_cell().unwrap()).unwrap();
        assert!(wallet.account.set_data(w.into_cell().unwrap()));
        refresh_proof_data(wallet);
    }
    #[test]
    fn proven_wallet_snapshot_binds_rescue_request() {
        use crate::wallet_v5r2::{AuthAction, AuthBinding, AuthRequest, AuthRole};
        use crate::wallet_v5r2_wallet_state::ProvenWalletState;
        let (g, mut w, m) = wallet_pair();
        set_wallet_counters(&g, &mut w, 7, 9, 10, 11);
        let view = ProvenWalletState::bind_initial(&w, &m, &g, 4620, 30).unwrap();
        assert_eq!(
            (
                view.seqno(),
                view.wallet_id(),
                view.epoch(),
                view.primary_nonce(),
                view.rescue_nonce()
            ),
            (7, 42, 9, 10, 11)
        );
        assert_eq!(view.retired(), 0);
        assert!(!view.primary_locally_enabled()); // REQUIRED policy in fixture.
        let actual = view.rescue_request(4620, 4700, AuthAction::LockPrimary).unwrap();
        let expected = AuthRequest::new(
            AuthBinding {
                global_id: 42,
                network: [1; 32],
                account: *g.wallet_init().repr_hash().as_array(),
                module: *g.module_init().repr_hash().as_array(),
                epoch: 9,
                nonce: 11,
                valid_until: 4700,
            },
            AuthRole::Rescue,
            AuthAction::LockPrimary,
            4600,
        )
        .unwrap();
        assert_eq!(actual.digest(), expected.digest(), "wallet counters/parties not bound");
        assert!(view.rescue_request(4631, 4700, AuthAction::LockPrimary).is_err());
        assert!(view.rescue_request(4620, 4620, AuthAction::LockPrimary).is_err());
    }
    #[test]
    fn proven_wallet_rejects_unbound_observations() {
        use crate::wallet_v5r2_wallet_state::ProvenWalletState;
        for case in [
            "live",
            "checkpoint",
            "wallet_address",
            "module_address",
            "code",
            "module_data",
            "stale_module",
            "stale_wallet",
            "classic",
        ] {
            let (g, mut w, mut m) = wallet_pair();
            let reason = match case {
                "live" => {
                    w.evidence.live = false;
                    "live proof"
                }
                "checkpoint" => {
                    m.evidence.checkpoint.seqno += 1;
                    "checkpoints"
                }
                "wallet_address" => {
                    w.evidence.account.address = format!("0:{}", "ab".repeat(32));
                    "wallet address"
                }
                "module_address" => {
                    m.evidence.account.address = format!("0:{}", "ab".repeat(32));
                    "module address"
                }
                "code" => {
                    w.evidence.account.code_hash = "ab".repeat(32);
                    "code mismatch"
                }
                "module_data" => {
                    m.evidence.account.data_hash = "ab".repeat(32);
                    "module data"
                }
                "stale_module" => {
                    m.evidence.account.gen_utime = 4500;
                    "stale"
                }
                "stale_wallet" => {
                    w.evidence.account.gen_utime = 4500;
                    "stale"
                }
                _ => {
                    let mut rest =
                        chain_block::SliceData::load_cell(g.wallet_data().clone()).unwrap();
                    rest.move_by(1).unwrap();
                    let mut b = BuilderData::new();
                    b.append_bit_one().unwrap();
                    b.append_builder(&rest.as_builder().unwrap()).unwrap();
                    assert!(w.account.set_data(b.into_cell().unwrap()));
                    refresh_proof_data(&mut w);
                    "classic authorization"
                }
            };
            match ProvenWalletState::bind_initial(&w, &m, &g, 4620, 30) {
                Ok(_) => panic!("accepted bad wallet observation {case}"),
                Err(e) => assert!(e.to_string().contains(reason), "{case}: {e}"),
            }
        }
    }
    #[test]
    fn proven_wallet_control_operations_survive_execute_exhaustion() {
        use crate::wallet_v5r2::AuthAction;
        use crate::wallet_v5r2_wallet_state::ProvenWalletState;
        let (g, mut w, m) = wallet_pair();
        set_wallet_counters(&g, &mut w, u32::MAX, 9, u64::MAX, u64::MAX);
        let view = ProvenWalletState::bind_initial(&w, &m, &g, 4620, 30).unwrap();
        assert!(
            view.rescue_request(4620, 4700, AuthAction::Execute { actions: Cell::default() })
                .is_err()
        );
        assert!(
            view.rescue_request(4620, 4700, AuthAction::Configure { fee_replacement: None })
                .is_err()
        );
        assert!(
            view.rescue_request(4620, 4700, AuthAction::LockPrimary).is_ok(),
            "lock must survive execute exhaustion"
        );
        assert!(
            view.rescue_request(
                4620,
                4700,
                AuthAction::Migrate {
                    module_init: g.module_init().clone(),
                    metadata: g.metadata().clone(),
                    vault_init: g.vault_init().clone()
                }
            )
            .is_ok()
        );
        set_wallet_counters(&g, &mut w, 0, u64::MAX, 0, 0);
        let view = ProvenWalletState::bind_initial(&w, &m, &g, 4620, 30).unwrap();
        assert!(
            view.rescue_request(4620, 4700, AuthAction::Execute { actions: Cell::default() })
                .is_ok()
        );
        assert!(view.rescue_request(4620, 4700, AuthAction::LockPrimary).is_err());
    }

    #[test]
    fn proven_wallet_requires_installed_successor() {
        use crate::wallet_v5r2_genesis::SuccessorDeployment;
        use crate::wallet_v5r2_wallet_state::ProvenWalletState;
        let (g, mut wallet, old_module) = wallet_pair();
        let code = Cell::default();
        let hash = *code.repr_hash().as_array();
        let bundle = CodeBundle::new(
            code.clone(),
            code.clone(),
            code,
            CodeHashes { wallet: hash, module: hash, vault: hash },
        )
        .unwrap();
        let mut key = [0; 60];
        key[..4].copy_from_slice(&1u32.to_be_bytes());
        key[4..8].copy_from_slice(&8u32.to_be_bytes());
        key[8..12].copy_from_slice(&3u32.to_be_bytes());
        let template = WalletGenesis::new(
            bundle,
            GenesisParameters {
                global_id: 42,
                network: [1; 32],
                wallet_id: 42,
                primary_key: [8; 1312],
                rescue_key: [9; 32],
                policy: RescuePolicy::Required,
                fee_tree_id: [7; 32],
                fee_public_key: key,
                epoch0: 1000,
            },
        )
        .unwrap();
        let successor =
            SuccessorDeployment::new(template, *g.wallet_init().repr_hash().as_array()).unwrap();
        let module = account_proof(old_module, successor.module_init());
        match ProvenWalletState::bind_successor(&wallet, &module, &g, &successor, 4620, 30) {
            Ok(_) => panic!("accepted uninstalled successor"),
            Err(e) => assert!(e.to_string().contains("installed module/fee tuple"), "{e}"),
        }
        set_wallet_counters(&g, &mut wallet, 0, 2, 0, 0);
        let mut ws = chain_block::SliceData::load_cell(wallet.account.get_data().unwrap()).unwrap();
        let bits = ws.get_next_bits(322).unwrap();
        let mut auth =
            chain_block::SliceData::load_cell(ws.checked_drain_reference().unwrap()).unwrap();
        let mut a = BuilderData::new();
        a.append_raw(&auth.get_next_bits(218).unwrap(), 218).unwrap();
        a.checked_append_reference(successor.module_init().clone()).unwrap();
        a.checked_append_reference(successor.metadata().clone()).unwrap();
        let mut w = BuilderData::new();
        w.append_raw(&bits, 322).unwrap();
        w.checked_append_reference(a.into_cell().unwrap()).unwrap();
        assert!(wallet.account.set_data(w.into_cell().unwrap()));
        refresh_proof_data(&mut wallet);
        let view =
            ProvenWalletState::bind_successor(&wallet, &module, &g, &successor, 4620, 30).unwrap();
        assert_eq!(view.epoch(), 2);
        assert!(ProvenWalletState::bind_initial(&wallet, &module, &g, 4620, 30).is_err());
    }

    #[test]
    fn proven_wallet_execute_exhaustion_is_independent() {
        use crate::wallet_v5r2::AuthAction;
        use crate::wallet_v5r2_wallet_state::ProvenWalletState;
        for (seq, nonce, reason) in
            [(0, u64::MAX, "nonce exhausted"), (u32::MAX, 0, "seqno exhausted")]
        {
            let (g, mut w, m) = wallet_pair();
            set_wallet_counters(&g, &mut w, seq, 9, 0, nonce);
            let view = ProvenWalletState::bind_initial(&w, &m, &g, 4620, 30).unwrap();
            match view.rescue_request(4620, 4700, AuthAction::Execute { actions: Cell::default() })
            {
                Ok(_) => panic!("accepted exhausted execute counter"),
                Err(e) => assert!(e.to_string().contains(reason), "{e}"),
            }
            assert!(view.rescue_request(4620, 4700, AuthAction::LockPrimary).is_ok());
        }
    }

    #[cfg(unix)]
    #[test]
    fn proven_fee_signing_uses_journal_and_bound_key() {
        use crate::lms_fee_journal::FeeJournal;
        use crate::wallet_v5r2::AuthRole;
        use crate::wallet_v5r2_fee::{FeeBinding, FeeClass, FeeIntent, FeePayload};
        use crate::wallet_v5r2_pop::{PopBinding, PopRequest};
        use std::os::unix::fs::PermissionsExt;
        // Framing-only backend: this tests ordering/binding, not LMS crypto.
        fn signature(leaf: u32) -> Vec<u8> {
            let mut bytes = vec![0; 2832];
            bytes[4..8].copy_from_slice(&leaf.to_be_bytes());
            bytes[8..12].copy_from_slice(&3u32.to_be_bytes());
            bytes[2188..2192].copy_from_slice(&8u32.to_be_bytes());
            bytes
        }
        fn payload(g: &WalletGenesis) -> FeePayload {
            let pop = PopRequest::new(
                PopBinding {
                    global_id: 42,
                    network: [1; 32],
                    account: *g.wallet_init().repr_hash().as_array(),
                    module: *g.module_init().repr_hash().as_array(),
                    challenge: [6; 32],
                    valid_until: 8300,
                },
                AuthRole::Rescue,
                RescuePolicy::Required,
                [2; 32],
                [3; 32],
                8200,
            )
            .unwrap();
            FeePayload::from_submission(
                FeeClass::Pop,
                pop.encode_submission(&vec![0; 7856]).unwrap(),
            )
            .unwrap()
        }
        let (g, mut state) = fixture();
        let initial = ProvenInitialFeeVault::bind(&state, &g, 4620, 30).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut journal = FeeJournal::open_proven(dir.path(), &initial, 4620).unwrap();
        assert!(
            journal
                .sign_proven_fee(
                    &initial,
                    4620,
                    4700,
                    100,
                    payload(&g),
                    |_, _| panic!("restore barrier bypassed"),
                    |_, _, _, _| panic!("unexpected verification")
                )
                .is_err()
        );
        state.evidence.block_gen_utime = 8210;
        state.evidence.account.gen_utime = 8200;
        let view = ProvenInitialFeeVault::bind(&state, &g, 8220, 30).unwrap();
        let key = view.fee_public_key();
        assert_eq!(&key[..12], &[0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 3]);
        let verifies = std::cell::Cell::new(0);
        let signed = journal
            .sign_proven_fee(
                &view,
                8220,
                8300,
                100,
                payload(&g),
                |leaf, digest| {
                    let record = std::fs::read(dir.path().join("fee-reservations")).unwrap();
                    assert_eq!(record.len(), 112 + 72, "signer ran before reservation");
                    assert_eq!(&record[120..152], digest, "reservation digest mismatch");
                    assert_eq!(leaf, 8);
                    Ok(signature(leaf))
                },
                |bound, leaf, _, bytes| {
                    assert_eq!(bound, key, "verification key substitution");
                    assert_eq!(bytes, signature(leaf));
                    verifies.set(verifies.get() + 1);
                    Ok(true)
                },
            )
            .unwrap();
        assert_eq!(verifies.get(), 2, "cache was not reverified before export");
        assert_eq!(signed.vault(), &view.route().vault);
        assert_eq!(signed.intent().leaf(), 8);
        let expected_intent = FeeIntent::new(
            FeeBinding {
                vault: view.route().vault,
                config_hash: *view.config_hash(),
                epoch0: view.route().epoch0,
                leaf: 8,
                valid_until: 8300,
                value: 100,
            },
            payload(&g),
            8200,
        )
        .unwrap();
        assert_eq!(
            signed.intent().digest(),
            expected_intent.digest(),
            "proven fee intent mismatch"
        );
        assert_eq!(
            signed.body().repr_hash(),
            signed.intent().encode_external(&signature(8)).unwrap().repr_hash()
        );
        assert_eq!(journal.cached_signature(8, *signed.intent().digest()).unwrap(), signature(8));
        for (now, deadline, reason) in [(8231, 8300, "stale"), (8220, 8220, "expired")] {
            match journal.sign_proven_fee(
                &view,
                now,
                deadline,
                100,
                payload(&g),
                |_, _| panic!("preflight invoked signer"),
                |_, _, _, _| panic!("preflight invoked verifier"),
            ) {
                Ok(_) => panic!("accepted invalid preflight"),
                Err(error) => assert!(error.to_string().contains(reason), "{error}"),
            }
        }
        assert!(
            journal
                .sign_proven_fee(
                    &view,
                    8220,
                    8300,
                    100,
                    payload(&g),
                    |leaf, _| Ok(signature(leaf)),
                    |_, _, _, _| Ok(false)
                )
                .is_err()
        );
        assert_eq!(journal.preview(8200, 0).unwrap().leaf, 10, "failed verification released leaf");
        let mut checks = 0;
        match journal.sign_proven_fee(
            &view,
            8220,
            8300,
            100,
            payload(&g),
            |leaf, _| Ok(signature(leaf)),
            |_, _, _, _| {
                checks += 1;
                Ok(checks == 1)
            },
        ) {
            Ok(_) => panic!("exported bytes after failed cache verification"),
            Err(error) => assert!(error.to_string().contains("export verification"), "{error}"),
        }
        assert_eq!(journal.preview(8200, 0).unwrap().leaf, 11);
        let mut suffix = chain_block::SliceData::load_cell(g.vault_data().clone()).unwrap();
        suffix.move_by(40).unwrap();
        let mut ahead = BuilderData::new();
        ahead.append_u8(3).unwrap();
        ahead.append_u32(12).unwrap();
        ahead.append_builder(&suffix.as_builder().unwrap()).unwrap();
        assert!(state.account.set_data(ahead.into_cell().unwrap()));
        state.root = state.account.serialize().unwrap();
        state.evidence.account.state_hash = state.root.repr_hash().to_hex_string();
        state.evidence.account.data_hash = state.account.get_data_hash().unwrap().to_hex_string();
        let ahead_view = ProvenInitialFeeVault::bind(&state, &g, 8220, 30).unwrap();
        match journal.sign_proven_fee(
            &ahead_view,
            8220,
            8300,
            100,
            payload(&g),
            |_, _| panic!("chain counter ignored"),
            |_, _, _, _| panic!("chain counter ignored"),
        ) {
            Ok(_) => panic!("accepted future chain counter"),
            Err(error) => assert!(error.to_string().contains("WaitUntil"), "{error}"),
        }
        let other = tempfile::tempdir().unwrap();
        std::fs::set_permissions(other.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut wrong_route = view.route();
        wrong_route.tree_id = [9; 32];
        let mut wrong = FeeJournal::open(other.path(), wrong_route, 4600).unwrap();
        match wrong.sign_proven_fee(
            &view,
            8220,
            8300,
            100,
            payload(&g),
            |_, _| panic!("wrong route invoked signer"),
            |_, _, _, _| panic!("wrong route invoked verifier"),
        ) {
            Ok(_) => panic!("accepted wrong journal route"),
            Err(error) => assert!(error.to_string().contains("route mismatch"), "{error}"),
        }
    }

    #[test]
    fn successor_fee_state_binding() {
        use crate::wallet_v5r2_genesis::SuccessorDeployment;
        use crate::wallet_v5r2_state::ProvenFeeVault;
        let (template, mut state) = fixture();
        let successor = SuccessorDeployment::new(template, [7; 32]).unwrap();
        assert!(ProvenFeeVault::bind_successor(&state, &successor, 4620, 30).is_err());
        let address = format!("0:{}", successor.vault_init().repr_hash().to_hex_string());
        state.account = Account::active(
            address.parse().unwrap(),
            CurrencyCollection::with_coins(100),
            0,
            4600,
            StateInit::construct_from_cell(successor.vault_init().clone()).unwrap(),
            0,
        )
        .unwrap();
        state.root = state.account.serialize().unwrap();
        state.evidence.account.address = address;
        state.evidence.account.state_hash = state.root.repr_hash().to_hex_string();
        state.evidence.account.data_hash = successor.vault_data().repr_hash().to_hex_string();
        let view = ProvenFeeVault::bind_successor(&state, &successor, 4620, 30).unwrap();
        assert_eq!(view.route().vault, *successor.vault_init().repr_hash().as_array());
        assert_eq!(view.route().tree_id, [4; 32]);
        assert_eq!(view.config_hash(), successor.config_hash());
        let (other, _) = fixture();
        let wrong_wallet = SuccessorDeployment::new(other, [8; 32]).unwrap();
        match ProvenFeeVault::bind_successor(&state, &wrong_wallet, 4620, 30) {
            Ok(_) => panic!("accepted another wallet's recovery vault"),
            Err(error) => assert!(error.to_string().contains("address"), "{error}"),
        }
    }

    #[test]
    fn initial_fee_state_binding() {
        let (g, s) = fixture();
        let view = ProvenInitialFeeVault::bind(&s, &g, 4620, 30).unwrap();
        assert_eq!(view.next_leaf(), 0);
        assert_eq!(view.route().global_id, 42);
        assert_eq!(view.route().network, [1; 32]);
        assert_eq!(view.route().tree_id, [4; 32]);
        assert_eq!(view.config_hash(), g.config_hash());
        let continuity =
            crate::lms_fee_schedule::Continuity::Intact(crate::lms_fee_schedule::IntactState {
                route: view.route(),
                next_unreserved: 0,
                last_proven_time: 4600,
            });
        assert_eq!(view.plan(4620, continuity).unwrap().leaf, 4);
        assert!(view.plan(4631, continuity).is_err(), "expired view reused");
        for case in ["live", "address", "code", "counter", "config", "version"] {
            let (g, mut s) = fixture();
            let reason = match case {
                "live" => {
                    s.evidence.live = false;
                    "live proof"
                }
                "address" => {
                    s.evidence.account.address = format!("0:{}", "aa".repeat(32));
                    "address"
                }
                "code" => {
                    s.evidence.account.code_hash = "aa".repeat(32);
                    "code"
                }
                _ => {
                    let mut old =
                        chain_block::SliceData::load_cell(g.vault_data().clone()).unwrap();
                    old.move_by(40).unwrap();
                    let mut b = BuilderData::new();
                    b.append_u8(if case == "version" { 2 } else { 3 }).unwrap();
                    b.append_u32(if case == "counter" { (1 << 20) + 1 } else { 0 }).unwrap();
                    if case == "config" {
                        old.move_by(256).unwrap();
                        b.append_u256(&[9; 32]).unwrap();
                    }
                    b.append_builder(&old.as_builder().unwrap()).unwrap();
                    assert!(s.account.set_data(b.into_cell().unwrap()));
                    match case {
                        "counter" => "counter",
                        "config" => "configuration",
                        _ => "version",
                    }
                }
            };
            match ProvenInitialFeeVault::bind(&s, &g, 4620, 30) {
                Ok(_) => panic!("accepted bad {case}"),
                Err(error) => assert!(error.to_string().contains(reason), "{case}: {error}"),
            }
        }
    }
}
