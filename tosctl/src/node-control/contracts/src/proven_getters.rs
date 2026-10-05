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
