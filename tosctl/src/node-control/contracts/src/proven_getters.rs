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

use std::collections::BTreeMap;
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
    config_params: BTreeMap<u32, Cell>,
    last_transaction_hash: [u8; 32],
    anchor_id: [u8; 32],
}

impl ProvenAccountState {
    pub fn last_transaction_hash(&self) -> &[u8; 32] {
        &self.last_transaction_hash
    }
    pub(crate) fn anchor_id(&self) -> &[u8; 32] {
        &self.anchor_id
    }

    /// Only explicitly requested parameters proven at this account checkpoint.
    pub fn config_param(&self, index: u32) -> Option<&Cell> {
        self.config_params.get(&index)
    }

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
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, serde::Serialize)]
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
        self.read_account_with_config(address, &[], policy).await
    }

    /// Prove an account and selected configuration parameters at one target.
    /// Nonempty `params` requires configuration proof material (`config.tl`).
    /// Missing parameters refuse the entire read; absence is never approval.
    pub async fn read_account_with_config(
        &self,
        address: &MsgAddressInt,
        params: &[u32],
        policy: &ReadPolicy,
    ) -> anyhow::Result<ProvenAccountState> {
        let address = canonical_address(address)?;
        let request = Request::build(&address, &[], policy, &self.config)?.with_config(params)?;
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
        let config_params = checked_config_params(&wire.config_params, &request.config_params)?;
        let last_hash =
            wire.account.last_trans_hash.context("proof verifier omitted last transaction hash")?;
        ensure_digest(&last_hash, "last transaction hash")?;
        let last_transaction_hash = hex::decode(last_hash)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("last transaction hash width"))?;
        let anchor_id = sha2::Sha256::digest(serde_json::to_vec(&self.anchor)?).into();
        Ok(ProvenAccountState {
            evidence,
            root,
            account,
            config_params,
            last_transaction_hash,
            anchor_id,
        })
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
    config_params: Vec<u32>,
}

impl Request {
    fn with_config(mut self, params: &[u32]) -> anyhow::Result<Self> {
        anyhow::ensure!(params.len() <= 16, "at most 16 configuration parameters");
        let unique: std::collections::BTreeSet<_> = params.iter().collect();
        anyhow::ensure!(
            unique.len() == params.len() && params.iter().all(|p| *p <= i32::MAX as u32),
            "configuration indices must be distinct nonnegative int32 values"
        );
        if !params.is_empty() {
            let mut value: serde_json::Value = serde_json::from_slice(&self.bytes)?;
            value["config_params"] = serde_json::to_value(params)?;
            self.bytes = serde_json::to_vec(&value)?;
            self.sha256 = hex::encode(sha2::Sha256::digest(&self.bytes));
            self.config_params = params.to_vec();
        }
        Ok(self)
    }

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
            config_params: Vec::new(),
        })
    }
}

#[derive(Deserialize)]
struct VerifiedOutput {
    #[serde(default)]
    config_params: Vec<ConfigParamOutput>,
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
struct ConfigParamOutput {
    index: u32,
    cell_hash: String,
    boc: String,
}

fn checked_config_params(
    params: &[ConfigParamOutput],
    expected: &[u32],
) -> anyhow::Result<BTreeMap<u32, Cell>> {
    anyhow::ensure!(
        params.len() == expected.len(),
        "proven configuration parameter count mismatch"
    );
    let mut cells = BTreeMap::new();
    for (param, index) in params.iter().zip(expected) {
        anyhow::ensure!(param.index == *index, "proven configuration parameter index mismatch");
        ensure_digest(&param.cell_hash, "configuration cell hash")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&param.boc)
            .context("invalid configuration BOC base64")?;
        let cell = read_single_root_boc(&bytes).context("invalid configuration BOC")?;
        anyhow::ensure!(
            cell.repr_hash().to_hex_string() == param.cell_hash,
            "proven configuration BOC hash mismatch"
        );
        cells.insert(*index, cell);
    }
    Ok(cells)
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
    last_trans_hash: Option<String>,
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

    checked_config_params(&verified.config_params, &request.config_params)?;

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
        fixture_with_policy(RescuePolicy::Required)
    }
    fn fixture_with_policy(policy: RescuePolicy) -> (WalletGenesis, ProvenAccountState) {
        fixture_with_keys(policy, [2; 1312], [3; 32])
    }
    fn fixture_with_keys(
        policy: RescuePolicy,
        primary_key: [u8; 1312],
        rescue_key: [u8; 32],
    ) -> (WalletGenesis, ProvenAccountState) {
        fixture_with_parameters(
            policy,
            primary_key,
            rescue_key,
            Cell::default(),
            Cell::default(),
            (42, [1; 32]),
        )
    }
    fn fixture_with_parameters(
        policy: RescuePolicy,
        primary_key: [u8; 1312],
        rescue_key: [u8; 32],
        module_code: Cell,
        vault_code: Cell,
        namespace: (i32, [u8; 32]),
    ) -> (WalletGenesis, ProvenAccountState) {
        let code = Cell::default();
        let hash = *vault_code.repr_hash().as_array();
        let hashes = CodeHashes {
            wallet: *code.repr_hash().as_array(),
            module: *module_code.repr_hash().as_array(),
            vault: hash,
        };
        let bundle = CodeBundle::new(code, module_code, vault_code, hashes).unwrap();
        let mut key = [0; 60];
        key[..4].copy_from_slice(&1u32.to_be_bytes());
        key[4..8].copy_from_slice(&8u32.to_be_bytes());
        key[8..12].copy_from_slice(&3u32.to_be_bytes());
        let genesis = WalletGenesis::new(
            bundle,
            GenesisParameters {
                global_id: namespace.0,
                network: namespace.1,
                wallet_id: 42,
                primary_key,
                rescue_key,
                policy,
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
            last_transaction_hash: [0; 32],
            anchor_id: [0; 32],
            config_params: BTreeMap::new(),
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
    #[cfg(feature = "native-wallet-vault")]
    async fn public_vault_fixture(
        role: wallet_pq_signer::Role,
    ) -> (
        tempfile::TempDir,
        secrets_vault::vault::SecretVault,
        secrets_vault::types::secret_id::SecretId,
    ) {
        use secrets_vault::{
            crypto::{
                factory::{AutoCryptoFactory, CryptoFactory},
                key_material::KeyMaterial,
                master_key::MasterKey,
            },
            events::null_handler::NullEventHandler,
            memory::protected_memory::ProtectedMemory,
            storage::file_json::FileJsonStorage,
            types::{
                algorithm::Algorithm, metadata::Metadata, secret::Secret, secret_id::SecretId,
                store_mode::StoreMode,
            },
            vault::SecretVault,
        };
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let master = MasterKey::from_key_material(
            KeyMaterial::new_symmetric_key(ProtectedMemory::from_slice(&[0x77; 32]).await.unwrap())
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        let storage = FileJsonStorage::new(
            master,
            &dir.path().join("rescue.json"),
            Box::new(AutoCryptoFactory {}),
            false,
        )
        .await
        .unwrap();
        let vault = SecretVault::new(Arc::new(storage), Arc::new(NullEventHandler {}));
        let id = SecretId::new("public.test.rescue");
        let metadata = Metadata::new(Some(&id), Algorithm::None, true)
            .with_tag(wallet_pq_signer::vault::PROFILE_TAG, wallet_pq_signer::vault::PROFILE_V1)
            .with_tag(wallet_pq_signer::vault::ROLE_TAG, wallet_pq_signer::vault::role_tag(role));
        let secret = Secret::from_protected_data(
            ProtectedMemory::from_slice(match role {
                wallet_pq_signer::Role::Primary => &[0x11; 32],
                wallet_pq_signer::Role::Rescue => &[0x22; 48],
            })
            .await
            .unwrap(),
            metadata,
            AutoCryptoFactory {}.new_crypto().unwrap(),
        )
        .await
        .unwrap();
        vault.put(&secret, StoreMode::NewOnly).await.unwrap();
        vault.flush().await.unwrap();
        (dir, vault, id)
    }

    #[cfg(feature = "native-wallet-vault")]
    #[tokio::test]
    async fn vault_wallet_signing_rechecks_proofs_after_loading() {
        use crate::wallet_v5r2::AuthAction;
        use crate::wallet_v5r2_policy::tests::policy;
        use crate::wallet_v5r2_vault::VaultKey;
        use crate::wallet_v5r2_wallet_state::ProvenWalletState;
        use secrets_vault::{
            crypto::{
                factory::AutoCryptoFactory, key_material::KeyMaterial, master_key::MasterKey,
            },
            events::null_handler::NullEventHandler,
            memory::protected_memory::ProtectedMemory,
            storage::file_json::FileJsonStorage,
            types::secret_id::SecretId,
            vault::SecretVault,
        };
        use std::{path::Path, sync::Arc};
        use wallet_pq_signer::{Role, vault::create_new};
        async fn vault(path: &Path) -> SecretVault {
            let key = ProtectedMemory::from_slice(&[0x77; 32]).await.unwrap();
            let master =
                MasterKey::from_key_material(KeyMaterial::new_symmetric_key(key).await.unwrap())
                    .await
                    .unwrap();
            let storage = FileJsonStorage::new(master, path, Box::new(AutoCryptoFactory {}), false)
                .await
                .unwrap();
            SecretVault::new(Arc::new(storage), Arc::new(NullEventHandler {}))
        }
        let dir = tempfile::tempdir().unwrap();
        let primary_vault = vault(&dir.path().join("primary.json")).await;
        let rescue_vault = vault(&dir.path().join("rescue.json")).await;
        let id = SecretId::new("wallet.key");
        let primary = create_new(&primary_vault, &id, Role::Primary).await.unwrap();
        let rescue = create_new(&rescue_vault, &id, Role::Rescue).await.unwrap();
        let (g, proof) = fixture_with_keys(
            RescuePolicy::Ready,
            primary.public_key().try_into().unwrap(),
            rescue.public_key().try_into().unwrap(),
        );
        drop(primary);
        drop(rescue);
        let mut wallet = account_proof(proof, g.wallet_init());
        let (_, proof) = fixture();
        let module = account_proof(proof, g.module_init());
        let view = ProvenWalletState::bind_initial(&wallet, &module, &g, 4620, 30).unwrap();
        let pkey = VaultKey { vault: &primary_vault, id: &id };
        let rkey = VaultKey { vault: &rescue_vault, id: &id };
        let missing = SecretId::new("missing.record");
        let missing_key = VaultKey { vault: &primary_vault, id: &missing };
        let expected_error =
            view.primary_request(&wallet, 4620, 4700, Cell::default()).err().unwrap().to_string();
        let error = missing_key
            .sign_primary(&view, &wallet, || Ok(4620), 4700, Cell::default())
            .await
            .err()
            .unwrap()
            .to_string();
        assert_eq!(error, expected_error, "opened custody before policy validation");
        let expected_error =
            view.rescue_request(4631, 4700, AuthAction::LockPrimary).err().unwrap().to_string();
        let error = missing_key
            .sign_rescue(&view, || Ok(4631), 4700, AuthAction::LockPrimary)
            .await
            .err()
            .unwrap()
            .to_string();
        assert_eq!(error, expected_error, "opened custody before rescue validation");
        wallet.config_params.insert(48, policy([1; 32], 0, &[], true));
        let signed =
            pkey.sign_primary(&view, &wallet, || Ok(4620), 4700, Cell::default()).await.unwrap();
        assert_eq!(
            signed.reference(0).unwrap().repr_hash(),
            view.primary_request(&wallet, 4620, 4700, Cell::default()).unwrap().cell().repr_hash()
        );
        let signed =
            rkey.sign_rescue(&view, || Ok(4620), 4700, AuthAction::LockPrimary).await.unwrap();
        assert_eq!(
            signed.reference(0).unwrap().repr_hash(),
            view.rescue_request(4620, 4700, AuthAction::LockPrimary).unwrap().cell().repr_hash()
        );
        assert!(pkey.sign_rescue(&view, || Ok(4620), 4700, AuthAction::LockPrimary).await.is_err());
        for (after, deadline, label) in [
            (4619, 4700, "regressed clock"),
            (4631, 4700, "stale proof"),
            (4621, 4621, "expired request"),
        ] {
            let mut calls = 0;
            let result = pkey
                .sign_primary(
                    &view,
                    &wallet,
                    || {
                        calls += 1;
                        Ok(if calls == 1 { 4620 } else { after })
                    },
                    deadline,
                    Cell::default(),
                )
                .await;
            assert!(result.is_err(), "accepted {label} after custody load");
            assert_eq!(calls, 2);
            let mut calls = 0;
            let result = rkey
                .sign_rescue(
                    &view,
                    || {
                        calls += 1;
                        Ok(if calls == 1 { 4620 } else { after })
                    },
                    deadline,
                    AuthAction::LockPrimary,
                )
                .await;
            assert!(result.is_err(), "accepted rescue {label} after custody load");
            assert_eq!(calls, 2);
        }
        let error = missing_key
            .sign_rescue(
                &view,
                || Ok(4620),
                4700,
                AuthAction::Migrate {
                    module_init: g.module_init().clone(),
                    metadata: g.metadata().clone(),
                    vault_init: g.vault_init().clone(),
                },
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert_eq!(
            error, "migration signing requires both funded POPs",
            "opened custody for ungated migration"
        );
    }

    #[cfg(feature = "native-wallet-signer")]
    #[test]
    fn native_wallet_signing_binds_proven_keys_and_policy() {
        use crate::wallet_v5r2::AuthAction;
        use crate::wallet_v5r2_policy::tests::policy;
        use crate::wallet_v5r2_wallet_state::ProvenWalletState;
        use chain_block::SliceData;
        use fips204::traits::{SerDes, Verifier};
        use wallet_pq_signer::{Role, Signer};
        let mut primary = Signer::import_and_wipe(Role::Primary, &mut [0x11; 32]).unwrap();
        let mut rescue = Signer::import_and_wipe(Role::Rescue, &mut [0x22; 48]).unwrap();
        let (g, proof) = fixture_with_keys(
            RescuePolicy::Ready,
            primary.public_key().try_into().unwrap(),
            rescue.public_key().try_into().unwrap(),
        );
        let mut w = account_proof(proof, g.wallet_init());
        let (_, proof) = fixture();
        let m = account_proof(proof, g.module_init());
        let view = ProvenWalletState::bind_initial(&w, &m, &g, 4620, 30).unwrap();
        assert_eq!(view.primary_public_key(), primary.public_key());
        assert_eq!(view.rescue_public_key(), rescue.public_key());
        assert!(
            view.sign_primary_submission(&w, 4620, 4700, Cell::default(), &mut primary).is_err()
        );
        w.config_params.insert(48, policy([1; 32], 0, &[], true));
        let expected = view.primary_request(&w, 4620, 4700, Cell::default()).unwrap();
        let body =
            view.sign_primary_submission(&w, 4620, 4700, Cell::default(), &mut primary).unwrap();
        let mut body = SliceData::load_cell(body).unwrap();
        assert_eq!(body.get_next_u32().unwrap(), 0x53554233);
        assert_eq!(
            body.checked_drain_reference().unwrap().repr_hash(),
            expected.cell().repr_hash()
        );
        let mut cell = body.checked_drain_reference().unwrap();
        let mut signature = Vec::new();
        loop {
            let mut s = SliceData::load_cell(cell).unwrap();
            signature.extend(s.get_bytestring(0));
            if s.remaining_references() == 0 {
                break;
            }
            cell = s.checked_drain_reference().unwrap();
        }
        let key = fips204::ml_dsa_44::PublicKey::try_from_bytes(
            view.primary_public_key().try_into().unwrap(),
        )
        .unwrap();
        assert!(key.verify(
            expected.digest(),
            &signature.try_into().unwrap(),
            expected.signing_context()
        ));
        let mut wrong = Signer::import_and_wipe(Role::Primary, &mut [0x99; 32]).unwrap();
        assert!(view.sign_primary_submission(&w, 4620, 4700, Cell::default(), &mut wrong).is_err());
        assert!(
            view.sign_primary_submission(&w, 4620, 4700, Cell::default(), &mut rescue).is_err()
        );
        assert!(
            view.sign_primary_submission(&w, 4700, 4750, Cell::default(), &mut primary).is_err()
        );
        w.config_params.insert(48, policy([1; 32], 2, &[], true));
        assert!(
            view.sign_primary_submission(&w, 4620, 4700, Cell::default(), &mut primary).is_err()
        );
        assert!(
            view.sign_rescue_submission(4620, 4700, AuthAction::LockPrimary, &mut primary).is_err()
        );
        let expected = view.rescue_request(4620, 4700, AuthAction::LockPrimary).unwrap();
        let body =
            view.sign_rescue_submission(4620, 4700, AuthAction::LockPrimary, &mut rescue).unwrap();
        assert_eq!(body.reference(0).unwrap().repr_hash(), expected.cell().repr_hash());
    }

    #[cfg(feature = "native-wallet-signer")]
    #[tokio::test]
    async fn native_migration_requires_both_funded_pops() {
        use crate::lms_fee_schedule::{Continuity, IntactState, RestoreBarrier};
        use crate::proven_transactions::ProvenTransaction;
        use crate::wallet_v5r2::{AuthAction, AuthRole};
        use crate::wallet_v5r2_genesis::SuccessorDeployment;
        use crate::wallet_v5r2_pop::{FundedPopReceipts, PopRequest};
        use crate::wallet_v5r2_wallet_state::{MigrationEvidence, ProvenWalletState};
        use chain_block::{HashUpdate, Message, SliceData, Transaction};
        use wallet_pq_signer::{Role, Signer};
        let mut signer = Signer::import_and_wipe(Role::Rescue, &mut [0x22; 48]).unwrap();
        let (birth, proof) = fixture_with_keys(
            RescuePolicy::Required,
            [2; 1312],
            signer.public_key().try_into().unwrap(),
        );
        let mut wallet = account_proof(proof, birth.wallet_init());
        let (_, proof) = fixture();
        let module = account_proof(proof, birth.module_init());
        set_wallet_counters(&birth, &mut wallet, u32::MAX, 9, u64::MAX, u64::MAX);
        let view = ProvenWalletState::bind_initial(&wallet, &module, &birth, 4620, 30).unwrap();
        let (template, _) = fixture_with_keys(RescuePolicy::Required, [8; 1312], [9; 32]);
        let successor =
            SuccessorDeployment::new(template, *birth.wallet_init().repr_hash().as_array())
                .unwrap();
        let (_, proof) = fixture();
        let vault = account_proof(proof, successor.vault_init());
        // Synthetic successful executions isolate client gates. These are NOT
        // evidence that the zero signatures below execute in either VM.
        let make = |role, time, checkpoint, anchor| {
            let request = PopRequest::fresh_successor(&successor, role, 4700, 4600).unwrap();
            let (_, root) = super::transaction_receipt_tests::fixture("successor-pop-module");
            let module_template = Transaction::construct_from_cell(root).unwrap();
            let (_, root) = super::transaction_receipt_tests::fixture("successor-pop-fee");
            let fee_template = Transaction::construct_from_cell(root).unwrap();
            let (_, p) = fixture();
            let mp = account_proof(p, successor.module_init());
            let (_, p) = fixture();
            let fp = account_proof(p, successor.vault_init());
            let mut delivered = module_template.read_in_msg().unwrap().unwrap();
            delivered.int_header_mut().unwrap().set_src(fp.account.get_addr().unwrap().clone());
            delivered.int_header_mut().unwrap().set_dst(mp.account.get_addr().unwrap().clone());
            delivered.set_body(
                SliceData::load_cell(
                    request.encode_submission(&vec![0; role.signature_bytes()]).unwrap(),
                )
                .unwrap(),
            );
            let mut external = fee_template.read_in_msg().unwrap().unwrap();
            external.ext_in_header_mut().unwrap().dst = fp.account.get_addr().unwrap().clone();
            let receipt = |mut p: ProvenAccountState,
                           msg: &Message,
                           out: Option<&Message>,
                           template: &Transaction,
                           lt| {
                let mut tx = Transaction::with_account_and_message(&p.account, msg, lt).unwrap();
                tx.set_now(time);
                tx.write_description(&template.read_description().unwrap()).unwrap();
                tx.write_state_update(&HashUpdate::with_hashes(
                    p.root.repr_hash(),
                    p.root.repr_hash(),
                ))
                .unwrap();
                if let Some(out) = out {
                    tx.add_out_message(out).unwrap();
                }
                p.evidence.checkpoint.seqno = checkpoint;
                p.anchor_id = anchor;
                let root = tx.serialize().unwrap();
                p.last_transaction_hash = *root.repr_hash().as_array();
                p.evidence.account.last_trans_lt = lt;
                ProvenTransaction::latest(&p, root).unwrap()
            };
            let before_fee = fp.root.clone();
            let before_module = mp.root.clone();
            let fee = receipt(fp, &external, Some(&delivered), &fee_template, 100);
            let module = receipt(mp, &delivered, None, &module_template, 101);
            (request, fee, module, before_fee, before_module, external.serialize().unwrap())
        };
        let primary = make(AuthRole::Primary, 4600, 1, [0; 32]);
        let rescue = make(AuthRole::Rescue, 4600, 1, [0; 32]);
        fn funded(
            case: &(PopRequest, ProvenTransaction, ProvenTransaction, Cell, Cell, Cell),
        ) -> FundedPopReceipts<'_> {
            FundedPopReceipts {
                fee: &case.1,
                module: &case.2,
                fee_before: case.3.clone(),
                module_before: case.4.clone(),
            }
        }
        let p = funded(&primary);
        let r = funded(&rescue);
        // Synthetic custody fixture, independent of the chain's accepted counter.
        let local = IntactState {
            route: crate::wallet_v5r2_state::ProvenFeeVault::bind_successor(
                &vault, &successor, 4620, 30,
            )
            .unwrap()
            .route(),
            next_unreserved: 0,
            last_proven_time: 4600,
        };
        let mut evidence = MigrationEvidence {
            primary_request: &primary.0,
            primary_receipts: &p,
            primary_external: &primary.5,
            rescue_request: &rescue.0,
            rescue_receipts: &r,
            rescue_external: &rescue.5,
            vault: &vault,
            fee_continuity: Continuity::Intact(local),
            policy: None,
        };
        let expected = view.migration_request(4620, 4700, &successor, &evidence).unwrap();
        #[cfg(feature = "native-wallet-vault")]
        {
            use crate::wallet_v5r2_vault::VaultKey;
            let (_dir, custody, id) = public_vault_fixture(wallet_pq_signer::Role::Rescue).await;
            let key = VaultKey { vault: &custody, id: &id };
            let signed =
                key.sign_migration(&view, || Ok(4620), 4700, &successor, &evidence).await.unwrap();
            assert_eq!(signed.reference(0).unwrap().repr_hash(), expected.cell().repr_hash());
            let missing_id = secrets_vault::types::secret_id::SecretId::new("missing");
            let missing = VaultKey { vault: &custody, id: &missing_id };
            evidence.primary_request = &rescue.0;
            let expected_error = view
                .migration_request(4620, 4700, &successor, &evidence)
                .err()
                .unwrap()
                .to_string();
            let error = missing
                .sign_migration(&view, || Ok(4620), 4700, &successor, &evidence)
                .await
                .err()
                .unwrap()
                .to_string();
            assert_eq!(
                error, expected_error,
                "migration opened custody before funded POP validation"
            );
            evidence.primary_request = &primary.0;
            for (after, deadline, label) in [
                (4619, 4700, "regressed clock"),
                (4631, 4700, "stale proof"),
                (4621, 4621, "expired request"),
            ] {
                let mut calls = 0;
                let result = key
                    .sign_migration(
                        &view,
                        || {
                            calls += 1;
                            Ok(if calls == 1 { 4620 } else { after })
                        },
                        deadline,
                        &successor,
                        &evidence,
                    )
                    .await;
                assert!(result.is_err(), "Vault migration accepted {label} after loading");
                assert_eq!(calls, 2);
            }
        }
        let signed =
            view.sign_migration_submission(4620, 4700, &successor, &evidence, &mut signer).unwrap();
        assert_eq!(signed.reference(0).unwrap().repr_hash(), expected.cell().repr_hash());
        let action = AuthAction::Migrate {
            module_init: successor.module_init().clone(),
            metadata: successor.metadata().clone(),
            vault_init: successor.vault_init().clone(),
        };
        assert!(
            view.sign_rescue_submission(4620, 4700, action, &mut signer).is_err(),
            "ungated migration signed"
        );
        evidence.primary_request = &rescue.0;
        evidence.primary_receipts = &r;
        evidence.primary_external = &rescue.5;
        assert!(
            view.migration_request(4620, 4700, &successor, &evidence).is_err(),
            "accepted duplicate rescue POPs"
        );
        evidence.primary_request = &primary.0;
        evidence.primary_receipts = &p;
        evidence.primary_external = &primary.5;
        let wrong = Cell::default();
        evidence.primary_external = &wrong;
        assert!(
            view.migration_request(4620, 4700, &successor, &evidence).is_err(),
            "primary funded POP bypassed"
        );
        evidence.primary_external = &primary.5;
        evidence.rescue_external = &wrong;
        assert!(
            view.migration_request(4620, 4700, &successor, &evidence).is_err(),
            "rescue funded POP bypassed"
        );
        evidence.rescue_external = &rescue.5;
        for (time, checkpoint, anchor, reason) in [
            (4580, 1, [0; 32], "stale migration POP"),
            (4600, 2, [0; 32], "checkpoint or trust anchor"),
            (4600, 1, [1; 32], "checkpoint or trust anchor"),
        ] {
            let case = make(AuthRole::Primary, time, checkpoint, anchor);
            let receipts = funded(&case);
            let e = MigrationEvidence {
                primary_request: &case.0,
                primary_receipts: &receipts,
                primary_external: &case.5,
                ..evidence
            };
            let error = view
                .migration_request(4620, 4700, &successor, &e)
                .err()
                .expect("accepted stale or unrelated POP");
            assert!(error.to_string().contains(reason), "{error}");
        }
        for (counter, reason) in [
            (crate::lms_fee_schedule::LEAF_COUNT, "accepted exhausted successor fee tree"),
            (8, "accepted exhausted successor slot"),
        ] {
            let (_, proof) = fixture();
            let mut exhausted = account_proof(proof, successor.vault_init());
            let mut data = SliceData::load_cell(exhausted.account.get_data().unwrap()).unwrap();
            let mut b = BuilderData::new();
            b.append_u8(data.get_next_byte().unwrap()).unwrap();
            data.move_by(32).unwrap();
            b.append_u32(counter).unwrap();
            b.append_raw(&data.get_bytestring(0), data.remaining_bits()).unwrap();
            while data.remaining_references() > 0 {
                b.checked_append_reference(data.checked_drain_reference().unwrap()).unwrap();
            }
            assert!(exhausted.account.set_data(b.into_cell().unwrap()));
            refresh_proof_data(&mut exhausted);
            let e = MigrationEvidence { vault: &exhausted, ..evidence };
            assert!(view.migration_request(4620, 4700, &successor, &e).is_err(), "{reason}");
        }
        let mut wrong_route = local.route;
        wrong_route.tree_id[0] ^= 1;
        for (continuity, reason) in [
            (
                Continuity::Intact(IntactState { next_unreserved: 8, ..local }),
                "migration ignored local reservations",
            ),
            (
                Continuity::Intact(IntactState { route: wrong_route, ..local }),
                "migration accepted wrong custody route",
            ),
            (
                Continuity::Intact(IntactState { last_proven_time: 4601, ..local }),
                "migration accepted regressed custody time",
            ),
            (
                Continuity::Restored(RestoreBarrier::new(local.route, 4600).unwrap()),
                "migration ignored custody restore barrier",
            ),
        ] {
            let e = MigrationEvidence { fee_continuity: continuity, ..evidence };
            assert!(view.migration_request(4620, 4700, &successor, &e).is_err(), "{reason}");
        }
        for stale_checkpoint in [false, true] {
            let (_, proof) = fixture();
            let mut bad_vault = account_proof(proof, successor.vault_init());
            if stale_checkpoint {
                bad_vault.evidence.checkpoint.seqno = 2;
            } else {
                bad_vault.evidence.live = false;
            }
            let e = MigrationEvidence { vault: &bad_vault, ..evidence };
            let error = view
                .migration_request(4620, 4700, &successor, &e)
                .err()
                .expect("accepted unproven successor vault");
            assert!(
                error.to_string().contains(if stale_checkpoint {
                    "vault checkpoint"
                } else {
                    "live proof"
                }),
                "{error}"
            );
        }
    }

    #[cfg(feature = "native-wallet-signer")]
    #[tokio::test]
    async fn native_preparation_signing_binds_successor_and_current_rescue() {
        use crate::wallet_v5r2_genesis::SuccessorDeployment;
        use crate::wallet_v5r2_policy::tests::policy;
        use crate::wallet_v5r2_prepare::PreparationAmounts;
        use crate::wallet_v5r2_wallet_state::ProvenWalletState;
        use chain_block::SliceData;
        use tos_vm as _;
        use wallet_pq_signer::{Role, Signer}; // Link the VM verifier shim, separately from the signer.
        unsafe extern "C" {
            fn tos_rust_slhdsa128s_verify(
                m: *const u8,
                m_sz: usize,
                sig: *const u8,
                sig_sz: usize,
                ctx: *const u8,
                ctx_sz: usize,
                pk: *const u8,
            ) -> i32;
        }
        let mut primary = Signer::import_and_wipe(Role::Primary, &mut [0x11; 32]).unwrap();
        let mut rescue = Signer::import_and_wipe(Role::Rescue, &mut [0x22; 48]).unwrap();
        let mut next = Signer::import_and_wipe(Role::Rescue, &mut [0x33; 48]).unwrap();
        let (g, proof) = fixture_with_keys(
            RescuePolicy::Required,
            primary.public_key().try_into().unwrap(),
            rescue.public_key().try_into().unwrap(),
        );
        let mut w = account_proof(proof, g.wallet_init());
        let (_, proof) = fixture();
        let m = account_proof(proof, g.module_init());
        set_wallet_counters(&g, &mut w, u32::MAX, u64::MAX, u64::MAX, u64::MAX);
        w.config_params.insert(48, policy([1; 32], 2, &[], true));
        let view = ProvenWalletState::bind_initial(&w, &m, &g, 4620, 30).unwrap();
        let target = |policy, wallet| {
            let (template, _) = fixture_with_keys(
                policy,
                primary.public_key().try_into().unwrap(),
                next.public_key().try_into().unwrap(),
            );
            SuccessorDeployment::new(template, wallet).unwrap()
        };
        let successor = target(RescuePolicy::Required, *g.wallet_init().repr_hash().as_array());
        let other = target(RescuePolicy::Required, [9; 32]);
        let ready = target(RescuePolicy::Ready, *g.wallet_init().repr_hash().as_array());
        let amounts = PreparationAmounts { module: 100, vault: 200 };
        let different_code = {
            let mut b = BuilderData::new();
            b.append_u8(1).unwrap();
            b.into_cell().unwrap()
        };
        for (module_code, vault_code, namespace, expected_error) in [
            (
                different_code.clone(),
                Cell::default(),
                (42, [1; 32]),
                "successor module code mismatch",
            ),
            (Cell::default(), different_code, (42, [1; 32]), "successor vault code mismatch"),
            (Cell::default(), Cell::default(), (43, [1; 32]), "successor namespace mismatch"),
            (Cell::default(), Cell::default(), (42, [2; 32]), "successor namespace mismatch"),
        ] {
            let (template, _) = fixture_with_parameters(
                RescuePolicy::Required,
                primary.public_key().try_into().unwrap(),
                next.public_key().try_into().unwrap(),
                module_code,
                vault_code,
                namespace,
            );
            let target =
                SuccessorDeployment::new(template, *g.wallet_init().repr_hash().as_array())
                    .unwrap();
            let result = view.preparation_request(4620, 4700, &target, amounts, None);
            assert_eq!(
                result.err().expect("foreign successor accepted").to_string(),
                expected_error
            );
        }
        let request = view.preparation_request(4620, 4700, &successor, amounts, None).unwrap();
        assert_eq!(request.deployment_value(), 300);
        let targets = request.cell().reference(0).unwrap();
        for (i, cell) in [successor.module_init(), successor.metadata(), successor.vault_init()]
            .iter()
            .enumerate()
        {
            assert_eq!(targets.reference(i).unwrap().repr_hash(), cell.repr_hash());
        }
        assert_ne!(
            request.digest(),
            view.preparation_request(
                4620,
                4700,
                &successor,
                PreparationAmounts { module: 101, vault: 200 },
                None
            )
            .unwrap()
            .digest()
        );
        assert!(view.preparation_request(4620, 4700, &other, amounts, None).is_err());
        assert!(view.preparation_request(4620, 4620, &successor, amounts, None).is_err());
        assert!(view.preparation_request(4700, 4750, &successor, amounts, None).is_err());
        assert!(view.preparation_request(4620, 4700, &ready, amounts, None).is_err());
        assert!(view.preparation_request(4620, 4700, &ready, amounts, Some(&w)).is_err());
        w.config_params.insert(48, policy([1; 32], 0, &[], true));
        assert!(view.preparation_request(4620, 4700, &ready, amounts, Some(&w)).is_ok());
        w.evidence.block_gen_utime += 1;
        assert!(view.preparation_request(4620, 4700, &ready, amounts, Some(&w)).is_err());
        assert!(
            view.sign_preparation_submission(4620, 4700, &successor, amounts, None, &mut primary)
                .is_err()
        );
        assert!(
            view.sign_preparation_submission(4620, 4700, &successor, amounts, None, &mut next)
                .is_err()
        );
        let body = view
            .sign_preparation_submission(4620, 4700, &successor, amounts, None, &mut rescue)
            .unwrap();

        #[cfg(feature = "native-wallet-vault")]
        let body = {
            use crate::wallet_v5r2_vault::VaultKey;
            let (_dir, custody, id) = public_vault_fixture(wallet_pq_signer::Role::Rescue).await;
            let key = VaultKey { vault: &custody, id: &id };
            let signed = key
                .sign_preparation(&view, || Ok(4620), 4700, &successor, amounts, None)
                .await
                .unwrap();
            assert_eq!(
                signed.reference(0).unwrap().repr_hash(),
                body.reference(0).unwrap().repr_hash()
            );
            let missing_id = secrets_vault::types::secret_id::SecretId::new("missing");
            let missing = VaultKey { vault: &custody, id: &missing_id };
            let expected_error = view
                .preparation_request(4620, 4700, &other, amounts, None)
                .err()
                .unwrap()
                .to_string();
            let error = missing
                .sign_preparation(&view, || Ok(4620), 4700, &other, amounts, None)
                .await
                .err()
                .unwrap()
                .to_string();
            assert_eq!(
                error, expected_error,
                "preparation opened custody before successor validation"
            );
            for (after, deadline, label) in [
                (4619, 4700, "regressed clock"),
                (4631, 4700, "stale proof"),
                (4621, 4621, "expired request"),
            ] {
                let mut calls = 0;
                let result = key
                    .sign_preparation(
                        &view,
                        || {
                            calls += 1;
                            Ok(if calls == 1 { 4620 } else { after })
                        },
                        deadline,
                        &successor,
                        amounts,
                        None,
                    )
                    .await;
                assert!(result.is_err(), "Vault preparation accepted {label} after loading");
                assert_eq!(calls, 2);
            }
            signed
        };
        let mut body = SliceData::load_cell(body).unwrap();
        assert_eq!(body.get_next_u32().unwrap(), 0x46505233);
        assert_eq!(body.checked_drain_reference().unwrap().repr_hash(), request.cell().repr_hash());
        let mut cell = body.checked_drain_reference().unwrap();
        let mut signature = Vec::new();
        loop {
            let mut s = SliceData::load_cell(cell).unwrap();
            signature.extend(s.get_bytestring(0));
            if s.remaining_references() == 0 {
                break;
            }
            cell = s.checked_drain_reference().unwrap();
        }
        assert_eq!(signature.len(), 7856);
        let verify = |digest: &[u8; 32], context: &[u8]| {
            // All buffers remain live for the call; signature and public key
            // have the exact suite widths required by the VM verifier shim.
            unsafe {
                tos_rust_slhdsa128s_verify(
                    digest.as_ptr(),
                    digest.len(),
                    signature.as_ptr(),
                    signature.len(),
                    context.as_ptr(),
                    context.len(),
                    rescue.public_key().as_ptr(),
                )
            }
        };
        assert_eq!(verify(request.digest(), request.signing_context()), 1);
        assert_eq!(verify(request.digest(), b"TOS-RESCUE-POP-v1"), 0);
        assert_eq!(verify(&[0; 32], request.signing_context()), 0);
    }

    #[cfg(feature = "native-wallet-vault")]
    #[tokio::test]
    async fn vault_pop_signing_binds_enrollment_and_time() {
        use crate::wallet_v5r2::AuthRole;
        use crate::wallet_v5r2_genesis::{SuccessorDeployment, WalletGenesis};
        use crate::wallet_v5r2_pop::PopRequest;
        use crate::wallet_v5r2_vault::VaultKey;
        use chain_block::SliceData;
        use fips204::traits::{SerDes, Verifier};
        use secrets_vault::types::secret_id::SecretId;
        use wallet_pq_signer::{Role, Signer};
        unsafe extern "C" {
            fn tos_rust_slhdsa128s_verify(
                msg: *const u8,
                msg_len: usize,
                sig: *const u8,
                sig_len: usize,
                ctx: *const u8,
                ctx_len: usize,
                pk: *const u8,
            ) -> i32;
        }
        async fn submit(
            key: &VaultKey<'_>,
            request: &PopRequest,
            genesis: &WalletGenesis,
            successor: &SuccessorDeployment,
            successor_route: bool,
            clock: impl FnMut() -> anyhow::Result<u32>,
        ) -> anyhow::Result<Cell> {
            if successor_route {
                key.sign_pop_successor(request, successor, clock).await
            } else {
                key.sign_pop_initial(request, genesis, clock).await
            }
        }
        let primary = Signer::import_and_wipe(Role::Primary, &mut [0x11; 32]).unwrap();
        let rescue = Signer::import_and_wipe(Role::Rescue, &mut [0x22; 48]).unwrap();
        let enrollment = || {
            fixture_with_keys(
                RescuePolicy::Required,
                primary.public_key().try_into().unwrap(),
                rescue.public_key().try_into().unwrap(),
            )
            .0
        };
        let genesis = enrollment();
        let successor = SuccessorDeployment::new(enrollment(), [0x44; 32]).unwrap();
        let wrong = fixture().0;
        let wrong_successor = SuccessorDeployment::new(fixture().0, [0x45; 32]).unwrap();
        for (role, native_role, public_key) in [
            (AuthRole::Primary, Role::Primary, primary.public_key()),
            (AuthRole::Rescue, Role::Rescue, rescue.public_key()),
        ] {
            let (_dir, vault, id) = public_vault_fixture(native_role).await;
            let key = VaultKey { vault: &vault, id: &id };
            let missing_id = SecretId::new("missing");
            let missing = VaultKey { vault: &vault, id: &missing_id };
            for successor_route in [false, true] {
                let route = if successor_route { "successor" } else { "initial" };
                let req = if successor_route {
                    PopRequest::fresh_successor(&successor, role, 4700, 4620).unwrap()
                } else {
                    PopRequest::fresh_initial(&genesis, role, 4700, 4620).unwrap()
                };
                let body = submit(&key, &req, &genesis, &successor, successor_route, || Ok(4620))
                    .await
                    .unwrap();
                let mut header = SliceData::load_cell(body.clone()).unwrap();
                assert_eq!(header.get_next_u32().unwrap(), 0x50505333);
                assert_eq!(body.reference(0).unwrap().repr_hash(), req.cell().repr_hash());
                let mut cell = body.reference(1).unwrap();
                let mut signature = Vec::new();
                loop {
                    let mut slice = SliceData::load_cell(cell).unwrap();
                    signature.extend(slice.get_bytestring(0));
                    if slice.remaining_references() == 0 {
                        break;
                    }
                    cell = slice.checked_drain_reference().unwrap();
                }
                assert_eq!(signature.len(), role.signature_bytes());
                if role == AuthRole::Primary {
                    let pk = fips204::ml_dsa_44::PublicKey::try_from_bytes(
                        public_key.try_into().unwrap(),
                    )
                    .unwrap();
                    assert!(pk.verify(
                        req.digest(),
                        &signature.try_into().unwrap(),
                        req.signing_context()
                    ));
                } else {
                    // Exact public-key/signature widths and live buffers for the independent verifier.
                    assert_eq!(
                        unsafe {
                            tos_rust_slhdsa128s_verify(
                                req.digest().as_ptr(),
                                req.digest().len(),
                                signature.as_ptr(),
                                signature.len(),
                                req.signing_context().as_ptr(),
                                req.signing_context().len(),
                                public_key.as_ptr(),
                            )
                        },
                        1
                    );
                }
                let error =
                    submit(&missing, &req, &wrong, &wrong_successor, successor_route, || Ok(4620))
                        .await
                        .unwrap_err()
                        .to_string();
                assert_eq!(
                    error, "POP enrollment binding mismatch",
                    "{route} POP opened custody before enrollment validation"
                );
                let error =
                    submit(&missing, &req, &genesis, &successor, successor_route, || Ok(4700))
                        .await
                        .unwrap_err()
                        .to_string();
                assert_eq!(
                    error, "POP TTL must be 1..=3600 seconds",
                    "{route} POP opened custody before deadline validation"
                );
                for (after, label) in [(4619, "regressed clock"), (4700, "expired request")] {
                    let mut calls = 0;
                    let result = submit(&key, &req, &genesis, &successor, successor_route, || {
                        calls += 1;
                        Ok(if calls == 1 { 4620 } else { after })
                    })
                    .await;
                    assert!(result.is_err(), "{route} POP accepted {label} after loading");
                    assert_eq!(calls, 2);
                }
            }
        }
    }

    #[cfg(feature = "native-wallet-signer")]
    #[test]
    fn native_pop_signing_binds_initial_and_successor_enrollment() {
        use crate::wallet_v5r2::AuthRole;
        use crate::wallet_v5r2_genesis::SuccessorDeployment;
        use crate::wallet_v5r2_pop::{PopBinding, PopRequest};
        use chain_block::SliceData;
        use fips204::traits::{SerDes, Verifier};
        use wallet_pq_signer::{Role, Signer};
        let mut primary = Signer::import_and_wipe(Role::Primary, &mut [0x11; 32]).unwrap();
        let mut rescue = Signer::import_and_wipe(Role::Rescue, &mut [0x22; 48]).unwrap();
        // Required policy deliberately permits per-key primary POP, not AUTH.
        let (g, _) = fixture_with_keys(
            RescuePolicy::Required,
            primary.public_key().try_into().unwrap(),
            rescue.public_key().try_into().unwrap(),
        );
        let binding = || PopBinding {
            global_id: 42,
            network: [1; 32],
            account: *g.wallet_init().repr_hash().as_array(),
            module: *g.module_init().repr_hash().as_array(),
            challenge: [0x55; 32],
            valid_until: 4700,
        };
        let primary_hash = *g.module_data().reference(0).unwrap().repr_hash().as_array();
        let rescue_key: [u8; 32] = rescue.public_key().try_into().unwrap();
        for role in [AuthRole::Primary, AuthRole::Rescue] {
            let req = PopRequest::fresh_initial(&g, role, 4700, 4600).unwrap();
            let another = PopRequest::fresh_initial(&g, role, 4700, 4600).unwrap();
            assert_ne!(req.digest(), another.digest());
            let mut encoded = SliceData::load_cell(req.cell().clone()).unwrap();
            encoded.move_by(32 + 32 + 256 + 8).unwrap();
            let mut expected_binding = binding();
            expected_binding.challenge = *encoded.get_next_hash().unwrap().as_array();
            let expected = PopRequest::new(
                expected_binding,
                role,
                RescuePolicy::Required,
                primary_hash,
                rescue_key,
                4600,
            )
            .unwrap();
            assert_eq!(req.cell().repr_hash(), expected.cell().repr_hash());
            assert!(PopRequest::fresh_initial(&g, role, 4600, 4600).is_err());
            assert!(PopRequest::fresh_initial(&g, role, 8201, 4600).is_err());
            let signer = if role == AuthRole::Primary { &mut primary } else { &mut rescue };
            let submission = req.sign_initial(&g, 4620, signer).unwrap();
            let mut header = SliceData::load_cell(submission.clone()).unwrap();
            assert_eq!(header.get_next_u32().unwrap(), 0x50505333);
            assert_eq!(submission.reference(0).unwrap().repr_hash(), req.cell().repr_hash());
            let mut cell = submission.reference(1).unwrap();
            let mut signature = Vec::new();
            loop {
                let mut s = SliceData::load_cell(cell).unwrap();
                signature.extend(s.get_bytestring(0));
                if s.remaining_references() == 0 {
                    break;
                }
                cell = s.checked_drain_reference().unwrap();
            }
            assert_eq!(signature.len(), role.signature_bytes());
            if role == AuthRole::Primary {
                let key = fips204::ml_dsa_44::PublicKey::try_from_bytes(
                    signer.public_key().try_into().unwrap(),
                )
                .unwrap();
                assert!(key.verify(
                    req.digest(),
                    &signature.try_into().unwrap(),
                    b"TOS-RESCUE-POP-v1"
                ));
            }
            assert!(req.sign_initial(&g, 4700, signer).is_err());
            for wrong in 0..6 {
                let mut b = binding();
                let mut key_hash = primary_hash;
                let mut slh_key = rescue_key;
                let mut policy = RescuePolicy::Required;
                match wrong {
                    0 => b.account[0] ^= 1,
                    1 => b.module[0] ^= 1,
                    2 => b.network[0] ^= 1,
                    3 => key_hash[0] ^= 1,
                    4 => slh_key[0] ^= 1,
                    _ => policy = RescuePolicy::Ready,
                }
                let changed = PopRequest::new(b, role, policy, key_hash, slh_key, 4600).unwrap();
                let error = changed.sign_initial(&g, 4620, signer).unwrap_err();
                assert!(error.to_string().contains("POP enrollment binding mismatch"), "{error}");
            }
        }
        let mut next = Signer::import_and_wipe(Role::Rescue, &mut [0x33; 48]).unwrap();
        let (template, _) = fixture_with_keys(
            RescuePolicy::Required,
            primary.public_key().try_into().unwrap(),
            next.public_key().try_into().unwrap(),
        );
        let successor =
            SuccessorDeployment::new(template, *g.wallet_init().repr_hash().as_array()).unwrap();
        let req = PopRequest::fresh_successor(&successor, AuthRole::Rescue, 4700, 4600).unwrap();
        let another =
            PopRequest::fresh_successor(&successor, AuthRole::Rescue, 4700, 4600).unwrap();
        assert_ne!(req.digest(), another.digest());
        assert!(PopRequest::fresh_successor(&successor, AuthRole::Rescue, 4600, 4600).is_err());
        assert!(req.sign_successor(&successor, 4620, &mut rescue).is_err());
        assert!(req.sign_successor(&successor, 4620, &mut primary).is_err());
        assert!(req.sign_initial(&g, 4620, &mut next).is_err());
        let signed = req.sign_successor(&successor, 4620, &mut next).unwrap();
        assert_eq!(signed.reference(0).unwrap().repr_hash(), req.cell().repr_hash());
    }

    #[test]
    fn primary_request_requires_current_proven_policy() {
        use crate::wallet_v5r2::{AuthAction, AuthBinding, AuthRequest, AuthRole};
        use crate::wallet_v5r2_policy::tests::policy;
        use crate::wallet_v5r2_wallet_state::ProvenWalletState;
        let (g, p) = fixture_with_policy(RescuePolicy::Ready);
        let mut w = account_proof(p, g.wallet_init());
        let (_, p) = fixture();
        let m = account_proof(p, g.module_init());
        set_wallet_counters(&g, &mut w, 7, 9, 10, 11);
        let view = ProvenWalletState::bind_initial(&w, &m, &g, 4620, 30).unwrap();
        assert!(view.primary_locally_enabled());
        match view.primary_request(&w, 4620, 4700, Cell::default()) {
            Ok(_) => panic!("accepted missing policy"),
            Err(e) => assert!(e.to_string().contains("missing"), "{e}"),
        }
        w.config_params.insert(48, policy([1; 32], 0, &[], true));
        let req = view.primary_request(&w, 4620, 4700, Cell::default()).unwrap();
        let expected = AuthRequest::new(
            AuthBinding {
                global_id: 42,
                network: [1; 32],
                account: *g.wallet_init().repr_hash().as_array(),
                module: *g.module_init().repr_hash().as_array(),
                epoch: 9,
                nonce: 10,
                valid_until: 4700,
            },
            AuthRole::Primary,
            AuthAction::Execute { actions: Cell::default() },
            4600,
        )
        .unwrap();
        assert_eq!(req.digest(), expected.digest(), "primary request binding mismatch");
        w.evidence.checkpoint.seqno += 1;
        match view.primary_request(&w, 4620, 4700, Cell::default()) {
            Ok(_) => panic!("accepted policy at another checkpoint"),
            Err(e) => assert!(e.to_string().contains("checkpoint mismatch"), "{e}"),
        }
        w.evidence.checkpoint.seqno -= 1;
        w.config_params.insert(48, policy([1; 32], 2, &[], true));
        assert!(
            view.primary_request(&w, 4620, 4700, Cell::default()).is_err(),
            "accepted retired primary"
        );
        assert!(
            view.rescue_request(4620, 4700, AuthAction::LockPrimary).is_ok(),
            "retirement blocked rescue"
        );
        w.config_params.insert(48, policy([1; 32], 0, &[], true));
        for (seq, nonce) in [(0, u64::MAX), (u32::MAX, 0)] {
            set_wallet_counters(&g, &mut w, seq, 9, nonce, 0);
            let exhausted = ProvenWalletState::bind_initial(&w, &m, &g, 4620, 30).unwrap();
            assert!(
                exhausted.primary_request(&w, 4620, 4700, Cell::default()).is_err(),
                "accepted exhausted primary counter"
            );
        }
        let (required, rw, rm) = wallet_pair();
        let required = ProvenWalletState::bind_initial(&rw, &rm, &required, 4620, 30).unwrap();
        assert!(
            required.primary_request(&w, 4620, 4700, Cell::default()).is_err(),
            "accepted REQUIRED primary"
        );
    }

    #[test]
    fn config_response_cells_are_bound_to_requested_indices_and_hashes() {
        let cell = Cell::default();
        let make = || ConfigParamOutput {
            index: 48,
            cell_hash: cell.repr_hash().to_hex_string(),
            boc: base64::engine::general_purpose::STANDARD
                .encode(chain_block::write_boc(&cell).unwrap()),
        };
        assert_eq!(
            checked_config_params(&[make()], &[48]).unwrap()[&48].repr_hash(),
            cell.repr_hash()
        );
        assert!(checked_config_params(&[], &[48]).is_err(), "accepted missing config output");
        let mut wrong = make();
        wrong.index = 47;
        assert!(checked_config_params(&[wrong], &[48]).is_err(), "accepted wrong config index");
        let mut wrong = make();
        wrong.cell_hash = "ab".repeat(32);
        assert!(checked_config_params(&[wrong], &[48]).is_err(), "accepted wrong config hash");
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
    fn proven_fee_preview_binds_custody_and_snapshot() {
        use crate::lms_fee_journal::FeeJournal;
        use std::os::unix::fs::PermissionsExt;
        let (g, mut state) = fixture();
        let initial = ProvenInitialFeeVault::bind(&state, &g, 4620, 30).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut journal = FeeJournal::open_proven(dir.path(), &initial, 4620).unwrap();
        assert!(
            journal.observed_continuity(4600).is_err(),
            "exported continuity before restore barrier"
        );
        assert!(
            journal.preview_proven(&initial, 4620).is_err(),
            "preview bypassed restore barrier"
        );
        state.evidence.block_gen_utime = 8210;
        state.evidence.account.gen_utime = 8200;
        let view = ProvenInitialFeeVault::bind(&state, &g, 8220, 30).unwrap();
        let before = std::fs::read(dir.path().join("fee-reservations")).unwrap();
        assert_eq!(journal.preview_proven(&view, 8220).unwrap().leaf, 8);
        assert_eq!(journal.preview_proven(&view, 8220).unwrap().leaf, 8);
        assert_eq!(std::fs::read(dir.path().join("fee-reservations")).unwrap(), before);
        assert!(journal.preview_proven(&view, 8231).is_err(), "preview accepted stale proof");
        for leaf in 8..12 {
            let local = journal.observed_continuity(8200).unwrap();
            assert_eq!(local.route, view.route());
            assert_eq!(local.last_proven_time, 8200);
            assert_eq!(local.next_unreserved, if leaf == 8 { 0 } else { leaf });
            assert_eq!(
                journal.preview_proven(&view, 8220).unwrap().leaf,
                leaf,
                "preview ignored local high water"
            );
            journal.reserve(8200, view.next_leaf(), leaf, [6; 32]).unwrap();
        }
        assert_eq!(view.chain_leaf_candidate(8220).unwrap(), 8);
        assert!(journal.observed_continuity(8200).is_err(), "exported exhausted continuity");
        assert!(
            journal.preview_proven(&view, 8220).is_err(),
            "preview reused locally reserved leaf"
        );
        let other = tempfile::tempdir().unwrap();
        std::fs::set_permissions(other.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut route = view.route();
        route.tree_id = [9; 32];
        let wrong = FeeJournal::open(other.path(), route, 4600).unwrap();
        assert!(wrong.preview_proven(&view, 8220).is_err(), "preview accepted wrong journal route");
    }

    #[cfg(unix)]
    #[cfg(feature = "native-wallet-signer")]
    #[test]
    fn native_fee_signing_preserves_proof_reservation_and_seed_cleanup() {
        use crate::{
            lms_fee_journal::FeeJournal,
            wallet_v5r2::AuthRole,
            wallet_v5r2_fee::{FeeClass, FeePayload},
            wallet_v5r2_pop::{PopBinding, PopRequest},
        };
        use std::os::unix::fs::PermissionsExt;
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../wallet-pq-signer/tests/fixtures/lms-fee-signature.json"
        ))
        .unwrap();
        let key: [u8; 60] =
            hex::decode(v["public_key"].as_str().unwrap()).unwrap().try_into().unwrap();
        let old = hex::decode(v["signature"].as_str().unwrap()).unwrap();
        let path: [u8; 640] = old[2192..].try_into().unwrap();
        let code = Cell::default();
        let hash = *code.repr_hash().as_array();
        let g = WalletGenesis::new(
            CodeBundle::new(
                code.clone(),
                code.clone(),
                code,
                CodeHashes { wallet: hash, module: hash, vault: hash },
            )
            .unwrap(),
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
        let (_, state) = fixture();
        let mut state = account_proof(state, g.vault_init());
        let early = ProvenInitialFeeVault::bind(&state, &g, 4620, 30).unwrap();
        // Synthetic proof metadata and framing-only inner POP: no chain execution claim.
        fn payload(g: &WalletGenesis) -> FeePayload {
            let pop = PopRequest::new(
                PopBinding {
                    global_id: 42,
                    network: [1; 32],
                    account: *g.wallet_init().repr_hash().as_array(),
                    module: *g.module_init().repr_hash().as_array(),
                    challenge: [6; 32],
                    valid_until: 11900,
                },
                AuthRole::Rescue,
                RescuePolicy::Required,
                [2; 32],
                [3; 32],
                11800,
            )
            .unwrap();
            FeePayload::from_submission(
                FeeClass::Pop,
                pop.encode_submission(&vec![0; 7856]).unwrap(),
            )
            .unwrap()
        }
        fn seed() -> [u8; 48] {
            let mut s = [0x44; 48];
            s[32..].fill(0x55);
            s
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut journal = FeeJournal::open_proven(dir.path(), &early, 4620).unwrap();
        let mut secret = seed();
        assert!(
            journal
                .sign_proven_fee_with_seed_and_wipe(
                    &early,
                    4620,
                    4700,
                    100,
                    payload(&g),
                    &mut secret,
                    &path
                )
                .is_err()
        );
        assert_eq!(secret, [0; 48], "native fee preflight retained seed");
        state.evidence.block_gen_utime = 11810;
        state.evidence.account.gen_utime = 11800;
        let view = ProvenInitialFeeVault::bind(&state, &g, 11820, 30).unwrap();
        for kind in 0..4 {
            let mut secret = seed().to_vec();
            let mut now = 11820;
            let mut deadline = 11900;
            match kind {
                0 => {
                    secret.pop();
                }
                1 => secret[32] ^= 1,
                2 => deadline = 11810,
                _ => now = 11831,
            }
            let result = journal.sign_proven_fee_with_seed_and_wipe(
                &view,
                now,
                deadline,
                100,
                payload(&g),
                &mut secret,
                &path,
            );
            assert!(result.is_err(), "native fee accepted invalid preflight {kind}");
            assert!(secret.iter().all(|b| *b == 0), "native fee rejected input retained seed");
            assert_eq!(
                std::fs::metadata(dir.path().join("fee-reservations")).unwrap().len(),
                112,
                "native fee preflight consumed a leaf {kind}"
            );
        }
        let mut secret = seed();
        let signed = journal
            .sign_proven_fee_with_seed_and_wipe(
                &view,
                11820,
                11900,
                100,
                payload(&g),
                &mut secret,
                &path,
            )
            .unwrap();
        assert_eq!(secret, [0; 48]);
        assert_eq!(signed.intent().leaf(), 12);
        let record = std::fs::read(dir.path().join("fee-reservations")).unwrap();
        assert_eq!(record.len(), 184);
        assert_eq!(&record[120..152], signed.intent().digest());
        let signature =
            journal.cached_signature_verified(&key, 12, *signed.intent().digest()).unwrap();
        assert_eq!(
            signed.body().repr_hash(),
            signed.intent().encode_external(&signature).unwrap().repr_hash()
        );
        #[cfg(feature = "native-wallet-vault")]
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(
            async {
                use crate::lms_fee_vault::{restore_seed_and_wipe, tests::open};
                use secrets_vault::types::secret_id::SecretId;
                let vault_dir = tempfile::tempdir().unwrap();
                let vault_file = vault_dir.path().join("vault.json");
                let id = SecretId::new("fee");
                let vault = open(&vault_file).await;
                let mut input = seed();
                restore_seed_and_wipe(&vault, &id, &mut input, &key, 12, &path).await.unwrap();
                assert_eq!(input, [0; 48]);
                drop(vault);
                let vault = open(&vault_file).await;
                let journal_dir = tempfile::tempdir().unwrap();
                std::fs::set_permissions(
                    journal_dir.path(),
                    std::fs::Permissions::from_mode(0o700),
                )
                .unwrap();
                let mut j = FeeJournal::open_proven(journal_dir.path(), &early, 4620).unwrap();
                let mut reads = 0;
                let stale = j
                    .sign_proven_fee_from_vault(
                        &vault,
                        &id,
                        &view,
                        || {
                            reads += 1;
                            if reads == 1 { 11820 } else { 11831 }
                        },
                        11900,
                        100,
                        payload(&g),
                        &path,
                    )
                    .await;
                assert!(stale.is_err(), "fee vault signed after proof expired during load");
                assert_eq!(reads, 2, "fee vault failed to refresh local clock");
                assert_eq!(
                    std::fs::metadata(journal_dir.path().join("fee-reservations")).unwrap().len(),
                    112,
                    "fee vault consumed leaf on stale loaded proof"
                );
                let from_vault = j
                    .sign_proven_fee_from_vault(
                        &vault,
                        &id,
                        &view,
                        || 11820,
                        11900,
                        100,
                        payload(&g),
                        &path,
                    )
                    .await
                    .unwrap();
                assert_eq!(from_vault.body().repr_hash(), signed.body().repr_hash());
                assert_eq!(
                    j.cached_signature_verified(&key, 12, *signed.intent().digest()).unwrap(),
                    signature
                );
            },
        );
        drop(journal);
        let mut reopened = FeeJournal::open_proven(dir.path(), &view, 11820).unwrap();
        assert_eq!(
            reopened.cached_signature_verified(&key, 12, *signed.intent().digest()).unwrap(),
            signature
        );
        let mut secret = seed();
        assert!(
            reopened
                .sign_proven_fee_with_seed_and_wipe(
                    &view,
                    11820,
                    11900,
                    100,
                    payload(&g),
                    &mut secret,
                    &path
                )
                .is_err()
        );
        assert_eq!(secret, [0; 48]);
        assert_eq!(std::fs::read(dir.path().join("fee-reservations")).unwrap(), record);
        for corrupt_seed in [true, false] {
            let d = tempfile::tempdir().unwrap();
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let mut j = FeeJournal::open_proven(d.path(), &early, 4620).unwrap();
            let mut secret = seed();
            let mut bad_path = path;
            if corrupt_seed {
                secret[0] ^= 1;
            } else {
                bad_path[0] ^= 1;
            }
            assert!(
                j.sign_proven_fee_with_seed_and_wipe(
                    &view,
                    11820,
                    11900,
                    100,
                    payload(&g),
                    &mut secret,
                    &bad_path
                )
                .is_err()
            );
            assert_eq!(secret, [0; 48]);
            assert_eq!(
                j.preview_proven(&view, 11820).unwrap().leaf,
                13,
                "native failure reused reserved leaf"
            );
            assert!(
                !d.path().join("fee-signature-0000000c").exists(),
                "native failure cached signature"
            );
        }
    }

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

#[cfg(test)]
pub(crate) mod transaction_receipt_tests {
    use super::*;
    use crate::proven_transactions::ProvenTransaction;
    use chain_block::{Serializable, ShardAccount, TrComputePhase, Transaction, TransactionDescr};

    // Actual native-executor transactions/account states, wrapped in synthetic
    // proof metadata. Real finality proof plumbing is tested separately.
    pub(crate) fn fixture(name: &str) -> (ProvenAccountState, Cell) {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/v5r2/receipt-transactions.json"))
                .unwrap();
        let item = &cases["cases"][name];
        let decode = |field: &str| {
            read_single_root_boc(
                base64::engine::general_purpose::STANDARD
                    .decode(item[field].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap()
        };
        let root = decode("transaction");
        let tx = Transaction::construct_from_cell(root.clone()).unwrap();
        let shard = ShardAccount::construct_from_cell(decode("shard_account")).unwrap();
        let account = shard.read_account().unwrap();
        let time = tx.now().checked_add(10).unwrap();
        let proof = ProvenAccountState {
            evidence: ProvenGetterResults {
                live: true,
                checkpoint: MasterchainCheckpoint {
                    seqno: 1,
                    root_hash: "00".repeat(32),
                    file_hash: "00".repeat(32),
                },
                block_gen_utime: time,
                account: ProvenAccount {
                    address: canonical_address(account.get_addr().unwrap()).unwrap(),
                    state_hash: shard.account_cell().repr_hash().to_hex_string(),
                    balance: account.get_balance().unwrap().coins.to_string(),
                    code_hash: account.get_code_hash().unwrap().to_hex_string(),
                    data_hash: account.get_data_hash().unwrap().to_hex_string(),
                    last_trans_lt: shard.last_trans_lt(),
                    gen_utime: time,
                },
                results: vec![],
                request_sha256: "00".repeat(32),
            },
            root: shard.account_cell(),
            account,
            config_params: BTreeMap::new(),
            last_transaction_hash: *shard.last_trans_hash().as_array(),
            anchor_id: [0; 32],
        };
        (proof, root)
    }
    #[tokio::test]
    async fn bounded_history_fetch_authenticates_each_step() {
        let (proof, head) = fixture("payment-wallet");
        let (_, prior) = fixture("migrate-wallet");
        let prior_tx = Transaction::construct_from_cell(prior.clone()).unwrap();
        let expected = prior_tx.in_msg_cell().unwrap();
        let mut calls = 0;
        let receipt = ProvenTransaction::find_inbound(&proof, &expected, 2, |addr, lt, hash| {
            calls += 1;
            assert_eq!(&addr, proof.account().get_addr().unwrap());
            let cell = if calls == 1 { head.clone() } else { prior.clone() };
            let tx = Transaction::construct_from_cell(cell.clone()).unwrap();
            assert_eq!(lt, tx.logical_time());
            assert_eq!(&hash, cell.repr_hash().as_array());
            std::future::ready(Ok(cell))
        })
        .await
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(receipt.root().repr_hash(), prior.repr_hash());
        // Finding a transaction is separate from interpreting execution success.
        receipt.require_complete_execution().unwrap();
        let mut calls = 0;
        let error = ProvenTransaction::find_inbound(&proof, &expected, 1, |_, _, _| {
            calls += 1;
            std::future::ready(Ok(if calls == 1 { head.clone() } else { prior.clone() }))
        })
        .await
        .err()
        .expect("accepted an over-budget history");
        assert_eq!(calls, 1);
        assert!(error.to_string().contains("budget exhausted"));
        let error = ProvenTransaction::find_inbound(&proof, &expected, 2, |_, _, _| {
            std::future::ready(Ok(prior.clone()))
        })
        .await
        .err()
        .expect("accepted unauthenticated matching transaction");
        assert!(error.to_string().contains("transaction hash mismatch"));
        for maximum in [1025, 0] {
            let error = ProvenTransaction::find_inbound(&proof, &expected, maximum, |_, _, _| {
                panic!("invalid budget invoked transport");
                #[allow(unreachable_code)]
                std::future::ready(Ok(head.clone()))
            })
            .await
            .err()
            .expect("accepted invalid history budget");
            assert!(error.to_string().contains("invalid receipt history budget"));
        }
    }

    async fn receipt_rpc_server(
        replies: Vec<serde_json::Value>,
        delay: std::time::Duration,
    ) -> (String, tokio::task::JoinHandle<Vec<serde_json::Value>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = vec![];
            for reply in replies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = vec![];
                let request = loop {
                    let mut chunk = [0; 4096];
                    let count = socket.read(&mut chunk).await.unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&chunk[..count]);
                    if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..at]).to_lowercase();
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                line.strip_prefix("content-length:")
                                    .map(|v| v.trim().parse().unwrap())
                            })
                            .unwrap();
                        if bytes.len() >= at + 4 + length {
                            break serde_json::from_slice::<serde_json::Value>(
                                &bytes[at + 4..at + 4 + length],
                            )
                            .unwrap();
                        }
                    }
                };
                let body = serde_json::json!({"ok":true,"jsonrpc":"2.0", "id":request["id"], "result":reply})
                    .to_string();
                requests.push(request);
                tokio::time::sleep(delay).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                // Timeout tests deliberately close the client before this write.
                let _ = socket.write_all(response.as_bytes()).await;
            }
            requests
        });
        (url, task)
    }

    fn rpc_transaction(cell: &Cell) -> serde_json::Value {
        // Deliberately false metadata: only the authenticated BOC is evidence.
        serde_json::json!({"lt":"1", "hash":"untrusted", "utime":0,
            "data":base64::engine::general_purpose::STANDARD.encode(chain_block::write_boc(cell).unwrap())})
    }

    #[tokio::test]
    async fn receipt_rpc_fetches_authenticated_history() {
        use crate::proven_transactions::ProvenTransaction;
        use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
        use std::time::Duration;
        let (proof, head) = fixture("payment-wallet");
        let (_, prior) = fixture("migrate-wallet");
        let tx = Transaction::construct_from_cell(prior.clone()).unwrap();
        let (url, server) = receipt_rpc_server(
            vec![
                serde_json::json!([rpc_transaction(&head)]),
                serde_json::json!([rpc_transaction(&prior)]),
            ],
            Duration::ZERO,
        )
        .await;
        let rpc = ClientJsonRpc::connect(url, None).unwrap();
        let result = ProvenTransaction::find_inbound_rpc(
            &proof,
            &tx.in_msg_cell().unwrap(),
            2,
            Duration::from_secs(3),
            &rpc,
        )
        .await
        .unwrap();
        assert_eq!(result.root().repr_hash(), prior.repr_hash());
        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 2);
        for (request, cell) in requests.iter().zip([head, prior]) {
            assert_eq!(request["method"], "getTransactions");
            assert_eq!(request["params"]["limit"], 1);
            assert_eq!(
                request["params"]["address"],
                proof.account().get_addr().unwrap().to_string()
            );
            assert_eq!(
                request["params"]["lt"],
                Transaction::construct_from_cell(cell.clone()).unwrap().logical_time().to_string()
            );
            assert_eq!(
                request["params"]["hash"],
                base64::engine::general_purpose::STANDARD.encode(cell.repr_hash().as_array())
            );
        }
    }

    #[tokio::test]
    async fn receipt_rpc_rejects_bad_responses_and_deadline() {
        use chain_rpc_client::v2::client_json_rpc::ClientJsonRpc;
        use std::time::Duration;
        let (proof, head) = fixture("payment-wallet");
        let (_, wrong) = fixture("migrate-wallet");
        let input = Transaction::construct_from_cell(head.clone()).unwrap().in_msg_cell().unwrap();
        for (response, delay, timeout, reason) in [
            (
                serde_json::json!([rpc_transaction(&head), rpc_transaction(&head)]),
                Duration::ZERO,
                Duration::from_secs(3),
                "one transaction",
            ),
            (serde_json::json!([]), Duration::ZERO, Duration::from_secs(3), "one transaction"),
            (
                serde_json::json!([rpc_transaction(&wrong)]),
                Duration::ZERO,
                Duration::from_secs(3),
                "transaction hash mismatch",
            ),
            (
                serde_json::json!([rpc_transaction(&head)]),
                Duration::from_millis(100),
                Duration::from_millis(20),
                "deadline exceeded",
            ),
        ] {
            let (url, server) = receipt_rpc_server(vec![response], delay).await;
            let rpc = ClientJsonRpc::connect(url, None).unwrap();
            let error = ProvenTransaction::find_inbound_rpc(&proof, &input, 1, timeout, &rpc)
                .await
                .err()
                .expect("accepted invalid RPC receipt");
            assert!(error.to_string().contains(reason), "{error}");
            server.await.unwrap();
        }
    }

    #[test]
    fn receipt_pop_binds_challenge_and_executed_code() {
        use crate::wallet_v5r2::AuthRole;
        use crate::wallet_v5r2_pop::{PopBinding, PopRequest, RescuePolicy};
        use chain_block::{BuilderData, IBitstring, SliceData, StateInit};
        let (proof, root) = fixture("successor-pop-module");
        let receipt = ProvenTransaction::latest(&proof, root).unwrap();
        let (before, _) = fixture("deploy-module");
        let pre = before.root().clone();
        let init = StateInit {
            code: before.account().get_code(),
            data: before.account().get_data(),
            ..Default::default()
        }
        .serialize()
        .unwrap();
        let message = receipt.transaction().read_in_msg().unwrap().unwrap();
        let mut submission = message.body().unwrap().clone();
        assert_eq!(submission.get_next_u32().unwrap(), 0x50505333);
        let request = submission.checked_drain_reference().unwrap();
        let mut s = SliceData::load_cell(request.clone()).unwrap();
        assert_eq!(s.get_next_u32().unwrap(), 0x504f5033);
        let global_id = s.get_next_int(32).unwrap() as i32;
        let network = *s.get_next_hash().unwrap().as_array();
        let role = match s.get_next_byte().unwrap() {
            1 => AuthRole::Primary,
            2 => AuthRole::Rescue,
            _ => panic!(),
        };
        let challenge = *s.get_next_hash().unwrap().as_array();
        let valid_until = s.get_next_u32().unwrap();
        let mut parties = SliceData::load_cell(s.checked_drain_reference().unwrap()).unwrap();
        parties.move_by(11).unwrap();
        let account = *parties.get_next_hash().unwrap().as_array();
        let module = *parties.get_next_hash().unwrap().as_array();
        let mut keys = SliceData::load_cell(s.checked_drain_reference().unwrap()).unwrap();
        assert_eq!(keys.get_next_byte().unwrap(), 1);
        let primary = *keys.get_next_hash().unwrap().as_array();
        let rescue = *keys.get_next_hash().unwrap().as_array();
        let policy = match keys.get_next_byte().unwrap() {
            1 => RescuePolicy::Ready,
            2 => RescuePolicy::Required,
            _ => panic!(),
        };
        let make_request = |challenge| {
            PopRequest::new(
                PopBinding { global_id, network, account, module, challenge, valid_until },
                role,
                policy,
                primary,
                rescue,
                valid_until - 1,
            )
            .unwrap()
        };
        let expected = make_request(challenge);
        assert_eq!(expected.cell().repr_hash(), request.repr_hash());
        expected.require_receipt(&receipt, pre.clone(), &init, account).unwrap();
        let mut wrong_wallet = account;
        wrong_wallet[0] ^= 1;
        let error = expected
            .require_receipt(&receipt, pre.clone(), &init, wrong_wallet)
            .err()
            .expect("accepted POP for another enrolled wallet");
        assert!(error.to_string().contains("receipt enrollment binding mismatch"));

        use crate::wallet_v5r2_pop::FundedPopReceipts;
        let (fee_proof, fee_root) = fixture("successor-pop-fee");
        let fee_receipt = ProvenTransaction::latest(&fee_proof, fee_root).unwrap();
        let (vault_before, _) = fixture("deploy-vault");
        let vault_init = StateInit {
            code: vault_before.account().get_code(),
            data: vault_before.account().get_data(),
            ..Default::default()
        }
        .serialize()
        .unwrap();
        let submitted = fee_receipt.transaction().in_msg_cell().unwrap();
        let funded = FundedPopReceipts {
            fee: &fee_receipt,
            module: &receipt,
            fee_before: vault_before.root().clone(),
            module_before: pre.clone(),
        };
        expected.require_funded_receipt(&funded, &submitted, &init, &vault_init, account).unwrap();
        assert!(
            expected
                .require_funded_receipt(&funded, &Cell::default(), &init, &vault_init, account)
                .is_err()
        );
        let mut other_init = StateInit::construct_from_cell(vault_init.clone()).unwrap();
        other_init.special = Some(chain_block::TickTock::with_values(true, false));
        let other_init = other_init.serialize().unwrap();
        let error = expected
            .require_funded_receipt(&funded, &submitted, &init, &other_init, account)
            .err()
            .expect("accepted another POP funding vault");
        assert!(error.to_string().contains("funding vault address mismatch"));
        // Synthetic anchors let us isolate validation from signature execution.
        // The positive pair above retains the actual native transaction cells.
        for changed in ["code", "config"] {
            let mut before = vault_before.account().clone();
            if changed == "code" {
                assert!(before.set_code(Cell::default()));
            } else {
                let mut data = SliceData::load_cell(before.get_data().unwrap()).unwrap();
                let mut b = BuilderData::new();
                b.append_raw(&data.get_next_bits(8 + 32).unwrap(), 40).unwrap();
                data.move_by(256).unwrap();
                b.append_u256(&[9; 32]).unwrap();
                b.append_raw(&data.get_bytestring(0), data.remaining_bits()).unwrap();
                while data.remaining_references() > 0 {
                    b.checked_append_reference(data.checked_drain_reference().unwrap()).unwrap();
                }
                assert!(before.set_data(b.into_cell().unwrap()));
            }
            let before = before.serialize().unwrap();
            let mut tx = fee_receipt.transaction().clone();
            let mut update = tx.read_state_update().unwrap();
            update.old_hash = before.repr_hash();
            tx.write_state_update(&update).unwrap();
            let (fee_anchor, _) = fixture("successor-pop-fee");
            let forged = reanchor(fee_anchor, tx);
            let inputs = FundedPopReceipts {
                fee: &forged,
                module: &receipt,
                fee_before: before,
                module_before: pre.clone(),
            };
            let error = expected
                .require_funded_receipt(&inputs, &submitted, &init, &vault_init, account)
                .err()
                .expect("accepted altered POP funding pre-state");
            assert!(error.to_string().contains(if changed == "code" {
                "funding vault code mismatch"
            } else {
                "vault immutable configuration mismatch"
            }));
        }
        let mut tx = fee_receipt.transaction().clone();
        tx.write_in_msg(Some(&message)).unwrap();
        let (fee_anchor, _) = fixture("successor-pop-fee");
        let forged = reanchor(fee_anchor, tx);
        let inputs = FundedPopReceipts {
            fee: &forged,
            module: &receipt,
            fee_before: vault_before.root().clone(),
            module_before: pre.clone(),
        };
        let error = expected
            .require_funded_receipt(
                &inputs,
                &forged.transaction().in_msg_cell().unwrap(),
                &init,
                &vault_init,
                account,
            )
            .err()
            .expect("accepted internal POP funding input");
        assert!(error.to_string().contains("requires external input"));
        let mut tx = fee_receipt.transaction().clone();
        tx.out_msgs = Default::default();
        let (fee_anchor, _) = fixture("successor-pop-fee");
        let forged = reanchor(fee_anchor, tx);
        let inputs = FundedPopReceipts {
            fee: &forged,
            module: &receipt,
            fee_before: vault_before.root().clone(),
            module_before: pre.clone(),
        };
        let error = expected
            .require_funded_receipt(&inputs, &submitted, &init, &vault_init, account)
            .err()
            .expect("accepted undelivered POP funding");
        assert!(error.to_string().contains("did not emit expected message"));

        let error = make_request([9; 32])
            .require_receipt(&receipt, pre.clone(), &init, account)
            .err()
            .expect("accepted unrelated POP challenge");
        assert!(error.to_string().contains("challenge differs"));
        let error = expected
            .require_receipt(&receipt, proof.root().clone(), &init, account)
            .err()
            .expect("accepted substituted POP pre-state");
        assert!(error.to_string().contains("pre-state hash mismatch"));
        let mut altered = before.account().clone();
        assert!(altered.set_code(Cell::default()));
        let altered = altered.serialize().unwrap();
        let mut tx = receipt.transaction().clone();
        let mut update = tx.read_state_update().unwrap();
        update.old_hash = altered.repr_hash();
        tx.write_state_update(&update).unwrap();
        let (proof, _) = fixture("successor-pop-module");
        let forged = reanchor(proof, tx);
        let error = expected
            .require_receipt(&forged, altered, &init, account)
            .err()
            .expect("accepted POP under other code");
        assert!(error.to_string().contains("code or keys differ"));
        let mut bounced = message;
        bounced.int_header_mut().unwrap().bounced = true;
        let mut tx = receipt.transaction().clone();
        tx.write_in_msg(Some(&bounced)).unwrap();
        let (proof, _) = fixture("successor-pop-module");
        let forged = reanchor(proof, tx);
        let error = expected
            .require_receipt(&forged, pre, &init, account)
            .err()
            .expect("accepted bounced POP input");
        assert!(error.to_string().contains("bounced message"));
    }

    fn sent_message(tx: &ProvenTransaction) -> Cell {
        let mut cells = vec![];
        tx.transaction()
            .iterate_out_msgs_with_cells(|_, c| {
                cells.push(c);
                Ok(true)
            })
            .unwrap();
        assert_eq!(cells.len(), 1);
        cells.remove(0)
    }
    fn reanchor(mut proof: ProvenAccountState, tx: Transaction) -> ProvenTransaction {
        let root = tx.serialize().unwrap();
        proof.last_transaction_hash = *root.repr_hash().as_array();
        proof.evidence.account.last_trans_lt = tx.logical_time();
        ProvenTransaction::latest(&proof, root).unwrap()
    }
    #[test]
    fn receipt_incomplete_execution_is_not_completion() {
        for case in [
            "aborted",
            "destroyed",
            "compute",
            "exit",
            "action",
            "valid",
            "funds",
            "result",
            "skipped",
        ] {
            let (proof, root) = fixture("payment-wallet");
            let mut tx = Transaction::construct_from_cell(root).unwrap();
            let TransactionDescr::Ordinary(mut d) = tx.read_description().unwrap() else {
                panic!("ordinary fixture")
            };
            let reason = match case {
                "aborted" => {
                    d.aborted = true;
                    "aborted"
                }
                "destroyed" => {
                    d.destroyed = true;
                    "destroyed"
                }
                "compute" | "exit" => {
                    let TrComputePhase::Vm(ref mut vm) = d.compute_ph else { panic!("VM fixture") };
                    if case == "compute" {
                        vm.success = false
                    } else {
                        vm.exit_code = 42
                    };
                    "compute failed"
                }
                _ => {
                    let a = d.action.as_mut().unwrap();
                    match case {
                        "action" => a.success = false,
                        "valid" => a.valid = false,
                        "funds" => a.no_funds = true,
                        "result" => a.result_code = 37,
                        _ => a.skipped_actions = 1,
                    };
                    "actions incomplete"
                }
            };
            tx.write_description(&TransactionDescr::Ordinary(d)).unwrap();
            let receipt = reanchor(proof, tx);
            match receipt.require_complete_execution() {
                Ok(_) => panic!("accepted incomplete execution {case}"),
                Err(e) => assert!(e.to_string().contains(reason), "{case}: {e}"),
            }
        }
    }
    #[test]
    fn receipt_history_state_chain_is_bound() {
        let (proof, root) = fixture("payment-wallet");
        let mut tx = Transaction::construct_from_cell(root).unwrap();
        let mut update = tx.read_state_update().unwrap();
        update.old_hash = chain_block::UInt256::from([9; 32]);
        tx.write_state_update(&update).unwrap();
        let current = reanchor(proof, tx);
        let (_, previous) = fixture("migrate-wallet");
        match current.previous(previous) {
            Ok(_) => panic!("accepted broken transaction state chain"),
            Err(e) => assert!(e.to_string().contains("state chain mismatch"), "{e}"),
        }
    }
    #[test]
    fn receipt_delivery_requires_exact_inbound_message() {
        let (p, c) = fixture("payment-wallet");
        let sent = ProvenTransaction::latest(&p, c).unwrap();
        let message = sent_message(&sent);
        let (proof, root) = fixture("recipient");
        let mut tx = Transaction::construct_from_cell(root).unwrap();
        let mut unrelated = tx.read_in_msg().unwrap().unwrap();
        unrelated.set_body(
            chain_block::SliceData::load_builder(
                chain_block::BuilderData::with_raw(vec![0x80], 1).unwrap(),
            )
            .unwrap(),
        );
        tx.write_in_msg(Some(&unrelated)).unwrap();
        let wrong = reanchor(proof, tx);
        match sent.require_internal_delivery(&wrong, message.repr_hash().as_array()) {
            Ok(_) => panic!("accepted unrelated recipient input"),
            Err(e) => assert!(e.to_string().contains("inbound message mismatch"), "{e}"),
        }
    }

    #[test]
    fn receipt_native_payment_and_history() {
        let (proof, root) = fixture("payment-wallet");
        let sent = ProvenTransaction::latest(&proof, root).unwrap();
        let (proof, root) = fixture("recipient");
        let received = ProvenTransaction::latest(&proof, root).unwrap();
        let message = sent_message(&sent);
        sent.require_internal_delivery(&received, message.repr_hash().as_array()).unwrap();
        let (_, previous) = fixture("migrate-wallet");
        let previous = sent.previous(previous).unwrap();
        previous.require_complete_execution().unwrap();
        sent.require_inbound(&sent.transaction().in_msg_cell().unwrap()).unwrap();
        assert!(
            sent.require_inbound(&Cell::default()).is_err(),
            "accepted another inbound message"
        );
        assert!(
            sent.require_internal_delivery(&received, &[9; 32]).is_err(),
            "accepted message absent from sender"
        );
    }
    #[test]
    fn receipt_payment_matches_approved_intent_and_credit() {
        use crate::proven_transactions::PaymentExpectation;
        let (proof, root) = fixture("payment-wallet");
        let sent = ProvenTransaction::latest(&proof, root).unwrap();
        let (proof, root) = fixture("recipient");
        let received = ProvenTransaction::latest(&proof, root).unwrap();
        let emitted = sent_message(&sent);
        let input = sent.transaction().in_msg_cell().unwrap();
        let message = received.transaction().read_in_msg().unwrap().unwrap();
        let header = message.int_header().unwrap();
        let TransactionDescr::Ordinary(description) =
            received.transaction().read_description().unwrap()
        else {
            panic!()
        };
        let credit = description.credit_ph.unwrap().credit;
        let make_intent = || PaymentExpectation {
            recipient: header.dst.clone(),
            value: header.value.clone(),
            credited: credit.clone(),
            bounce: header.bounce,
            body: message.body().cloned().map(|slice| slice.into_cell().unwrap()),
            state_init: message.state_init().cloned(),
        };
        sent.require_payment(&received, &input, emitted.repr_hash().as_array(), &make_intent())
            .unwrap();
        for case in ["recipient", "value", "credit", "bounce", "body", "state init"] {
            let mut intent = make_intent();
            match case {
                "recipient" => intent.recipient = format!("0:{}", "ab".repeat(32)).parse().unwrap(),
                "value" => intent.value = chain_block::CurrencyCollection::with_coins(1),
                "credit" => intent.credited = chain_block::CurrencyCollection::with_coins(1),
                "bounce" => intent.bounce = !intent.bounce,
                "body" => {
                    intent.body = Some(
                        chain_block::BuilderData::with_raw(vec![0x80], 1)
                            .unwrap()
                            .into_cell()
                            .unwrap(),
                    )
                }
                "state init" => intent.state_init = Some(chain_block::StateInit::default()),
                _ => unreachable!(),
            }
            let error = sent
                .require_payment(&received, &input, emitted.repr_hash().as_array(), &intent)
                .err()
                .unwrap_or_else(|| panic!("accepted mismatched payment {case}"));
            assert!(error.to_string().contains(case), "{case}: {error}");
        }
        assert!(
            sent.require_payment(
                &received,
                &Cell::default(),
                emitted.repr_hash().as_array(),
                &make_intent()
            )
            .is_err(),
            "accepted payment for unrelated request"
        );
    }

    #[test]
    fn receipt_latest_rejects_substitutions() {
        for case in ["hash", "lt", "account", "post_state", "future"] {
            let (mut proof, mut root) = fixture("payment-wallet");
            let reason = match case {
                "hash" => {
                    let mut altered = Transaction::construct_from_cell(root.clone()).unwrap();
                    altered.set_prev_trans_hash(chain_block::UInt256::from([9; 32]));
                    root = altered.serialize().unwrap();
                    "hash mismatch"
                }
                "lt" => {
                    proof.evidence.account.last_trans_lt += 1;
                    "logical time"
                }
                "account" => {
                    proof.account.set_addr(format!("0:{}", "ab".repeat(32)).parse().unwrap());
                    "account mismatch"
                }
                "post_state" => {
                    proof.root = Cell::default();
                    "post-state"
                }
                _ => {
                    proof.evidence.account.gen_utime = 0;
                    "newer than account"
                }
            };
            match ProvenTransaction::latest(&proof, root) {
                Ok(_) => panic!("accepted receipt substitution {case}"),
                Err(e) => assert!(e.to_string().contains(reason), "{case}: {e}"),
            }
        }
    }
    #[test]
    fn receipt_delivery_rejects_other_anchor_and_recipient() {
        let (p, c) = fixture("payment-wallet");
        let sent = ProvenTransaction::latest(&p, c).unwrap();
        let message = sent_message(&sent);
        let (mut p, c) = fixture("recipient");
        p.anchor_id = [1; 32];
        let other = ProvenTransaction::latest(&p, c).unwrap();
        match sent.require_internal_delivery(&other, message.repr_hash().as_array()) {
            Ok(_) => panic!("accepted receipt from another trust anchor"),
            Err(e) => assert!(e.to_string().contains("trust anchors"), "{e}"),
        }
        match sent.require_internal_delivery(&sent, message.repr_hash().as_array()) {
            Ok(_) => panic!("accepted wrong delivery recipient"),
            Err(e) => assert!(e.to_string().contains("parties mismatch"), "{e}"),
        }
    }
}

#[cfg(all(test, feature = "native-wallet-signer"))]
#[path = "wallet_v5r2_recorded_migration_tests.rs"]
mod recorded_migration_tests;
