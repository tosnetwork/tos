use anyhow::{Context, Result, ensure};
use chain_block::{BlockIdExt, ShardIdent, UInt256};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, str::FromStr};

pub const MANIFEST_LIMIT: u64 = 32 << 20;
pub const FILE_COUNT_LIMIT: usize = 100_000;
pub const RAW_LIMIT: u64 = 80 << 30;
pub const TRANSFER_LIMIT: u64 = 24 << 30;
pub const FREE_FLOOR: u64 = 200 << 30;
pub const TASK_LIMIT: u64 = 320 << 30;
const DOMAIN: &[u8] = b"TOS_NODE_DUMP_V1";

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn hash(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical SHA-256"
    );
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct FullId {
    pub workchain: i32,
    pub shard: i64,
    pub seqno: u32,
    pub root_hash: String,
    pub file_hash: String,
}
impl FullId {
    pub fn from_config(value: &serde_json::Value) -> Result<Self> {
        use base64::Engine;
        let field =
            |key: &str| value.get(key).with_context(|| format!("missing block field {key}"));
        let digest = |key: &str| -> Result<String> {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(field(key)?.as_str().context("invalid config block hash")?)?;
            ensure!(raw.len() == 32, "invalid config hash length");
            Ok(hex::encode(raw))
        };
        let id = FullId {
            workchain: i32::try_from(field("workchain")?.as_i64().context("invalid workchain")?)?,
            shard: field("shard")?.as_i64().context("invalid config shard")?,
            seqno: u32::try_from(field("seqno")?.as_u64().context("invalid config seqno")?)?,
            root_hash: digest("root_hash")?,
            file_hash: digest("file_hash")?,
        };
        id.masterchain()?;
        Ok(id)
    }

    pub fn native(&self) -> Result<BlockIdExt> {
        hash(&self.root_hash)?;
        hash(&self.file_hash)?;
        Ok(BlockIdExt::with_params(
            ShardIdent::with_tagged_prefix(
                self.workchain,
                u64::from_le_bytes(self.shard.to_le_bytes()),
            )?,
            self.seqno,
            UInt256::from_str(&self.root_hash)?,
            UInt256::from_str(&self.file_hash)?,
        ))
    }
    pub fn masterchain(&self) -> Result<()> {
        self.native()?;
        ensure!(
            self.workchain == -1 && self.shard == i64::MIN,
            "expected a full masterchain block id"
        );
        ensure!(
            self.root_hash != "0".repeat(64) && self.file_hash != "0".repeat(64),
            "empty block hashes"
        );
        Ok(())
    }
    pub fn from_native(id: &BlockIdExt) -> Self {
        Self {
            workchain: id.shard().workchain_id(),
            shard: i64::from_le_bytes(id.shard().shard_prefix_with_tag().to_le_bytes()),
            seqno: id.seq_no(),
            root_hash: hex::encode(id.root_hash().as_slice()),
            file_hash: hex::encode(id.file_hash().as_slice()),
        }
    }
    pub fn from_stats(text: &str) -> Result<Self> {
        let mut fields = text.split(':');
        let location = fields.next().context("missing block location")?;
        let root_hash = fields.next().context("missing root hash")?.to_ascii_lowercase();
        let file_hash = fields.next().context("missing file hash")?.to_ascii_lowercase();
        ensure!(fields.next().is_none(), "extra block-id fields");
        let inner = location
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .context("invalid native block location")?;
        let parts = inner.split(',').collect::<Vec<_>>();
        ensure!(parts.len() == 3, "invalid native block location");
        let shard = u64::from_str_radix(parts[1], 16)?;
        let id = Self {
            workchain: parts[0].parse()?,
            shard: i64::from_le_bytes(shard.to_le_bytes()),
            seqno: parts[2].parse()?,
            root_hash,
            file_hash,
        };
        id.native()?;
        Ok(id)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub global_id: i32,
    pub zero: FullId,
    pub init: FullId,
}
impl Network {
    pub fn from_global(bytes: &[u8], global_id: i32) -> Result<Self> {
        ensure!(bytes.len() as u64 <= MANIFEST_LIMIT, "global config byte limit");
        let global: serde_json::Value = serde_json::from_slice(bytes)?;
        let validator = global.get("validator").context("global config has no validator anchor")?;
        let parse = |name: &str| -> Result<FullId> {
            FullId::from_config(validator.get(name).with_context(|| format!("missing {name}"))?)
        };
        let zero = parse("zero_state")?;
        let init = match validator.get("init_block") {
            None | Some(serde_json::Value::Null) => zero.clone(),
            Some(value) => FullId::from_config(value)?,
        };
        let network = Self { global_id, zero, init };
        network.validate()?;
        Ok(network)
    }
    pub fn validate(&self) -> Result<()> {
        self.zero.masterchain()?;
        self.init.masterchain()?;
        ensure!(self.zero.seqno == 0, "zero-state seqno is not zero");
        ensure!(
            self.init.seqno != 0 || self.init == self.zero,
            "zero-height init block differs from zero-state anchor"
        );
        Ok(())
    }
}

pub fn approved_forks(global: &[u8]) -> Result<Vec<FullId>> {
    ensure!(global.len() as u64 <= MANIFEST_LIMIT, "global policy byte limit");
    let value: serde_json::Value = serde_json::from_slice(global)?;
    let validator = value.get("validator").context("missing validator policy")?;
    let Some(forks) = validator.get("hardforks") else {
        return Ok(vec![]);
    };
    let forks = forks.as_array().context("invalid approved fork list")?;
    ensure!(forks.len() <= 1024, "fork policy count limit");
    let result = forks.iter().map(FullId::from_config).collect::<Result<Vec<_>>>()?;
    ensure!(
        result.windows(2).all(|pair| pair[0].seqno < pair[1].seqno),
        "unordered approved fork policy"
    );
    Ok(result)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    RegularFile,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    #[serde(rename = "type")]
    pub kind: ObjectKind,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub compressed_size: u64,
    pub compressed_sha256: String,
    pub codec: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeValidation {
    pub engine_sha256: String,
    pub policy_sha256: String,
    pub frontier: FullId,
    pub passes: u8,
    pub permanent_cells: bool,
    pub recovery_resolved: bool,
    pub monitored_states_readable: bool,
    pub elapsed_millis: u64,
    pub recovery_context_sha256: String,
    pub started_utc: u64,
    pub finished_utc: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureReceipt {
    pub method: String,
    pub started_utc: u64,
    pub finished_utc: u64,
    pub copied_bytes: u64,
    pub elapsed_millis: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u16,
    pub network: Network,
    pub frontier: FullId,
    pub frontier_utime: u64,
    pub created_utc: u64,
    pub source_build: String,
    pub database_version: u32,
    pub retained_from: FullId,
    pub permanent_cells: bool,
    pub coverage: Vec<String>,
    pub approved_forks: Vec<FullId>,
    pub validation: NativeValidation,
    pub capture: CaptureReceipt,
    pub files: Vec<Object>,
}
impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == 1 && self.database_version == 2,
            "unsupported generation format or database schema"
        );
        self.network.validate()?;
        ensure!(
            self.capture.method == "cold_copy"
                && self.capture.started_utc <= self.capture.finished_utc
                && self.capture.finished_utc <= self.validation.started_utc
                && self.capture.copied_bytes <= RAW_LIMIT,
            "capture receipt is inconsistent"
        );
        self.frontier.masterchain()?;
        self.retained_from.masterchain()?;
        ensure!(
            self.retained_from.seqno <= self.frontier.seqno,
            "retained range starts beyond frontier"
        );
        ensure!(
            self.frontier.seqno >= self.network.init.seqno,
            "frontier precedes the held init block"
        );
        ensure!(
            self.frontier_utime <= self.created_utc,
            "frontier time is in the future at capture"
        );
        ensure!(
            self.source_build == self.validation.engine_sha256,
            "missing or oversized source build identity"
        );
        ensure!(!self.coverage.is_empty() && self.coverage.len() <= 1024, "invalid shard coverage");
        let mut coverage = BTreeSet::new();
        for shard in &self.coverage {
            let parsed = ShardIdent::from_str(shard)?;
            ensure!(coverage.insert(parsed.to_string()), "duplicate shard coverage");
        }
        hash(&self.validation.engine_sha256)?;
        hash(&self.validation.policy_sha256)?;
        hash(&self.validation.recovery_context_sha256)?;
        ensure!(
            self.validation.started_utc <= self.validation.finished_utc
                && self.validation.finished_utc <= self.created_utc,
            "native validation times are inconsistent"
        );
        ensure!(
            self.validation.frontier == self.frontier
                && self.validation.permanent_cells == self.permanent_cells
                && self.validation.passes == 2
                && self.validation.recovery_resolved
                && self.validation.monitored_states_readable,
            "generation lacks complete native recovery/reopen validation"
        );
        ensure!(
            !self.files.is_empty() && self.files.len() <= FILE_COUNT_LIMIT,
            "generation file count limit"
        );
        let mut paths = BTreeSet::new();
        let mut raw = 0_u64;
        let mut compressed = 0_u64;
        let mut previous_path: Option<&str> = None;
        for file in &self.files {
            ensure!(
                previous_path.is_none_or(|previous| previous < file.path.as_str()),
                "manifest paths are not strictly sorted"
            );
            previous_path = Some(&file.path);
            ensure!(file.compressed_size > 0, "empty compressed object");
            super::paths::public_path(&file.path)?;
            ensure!(paths.insert(&file.path), "duplicate generation path");
            hash(&file.sha256)?;
            hash(&file.compressed_sha256)?;
            ensure!(file.codec == "zstd", "unsupported object codec");
            raw = raw.checked_add(file.size).context("generation size overflow")?;
            compressed =
                compressed.checked_add(file.compressed_size).context("transfer size overflow")?;
        }
        ensure!(
            raw <= RAW_LIMIT && compressed <= TRANSFER_LIMIT,
            "generation byte budget exceeded"
        );
        for required in ["state-records.cbor", "metadata/zero-state.boc", "metadata/tip-block.boc"]
        {
            ensure!(paths.contains(&required.to_owned()), "generation missing {required}");
        }
        let mut previous = None;
        for fork in &self.approved_forks {
            fork.masterchain()?;
            ensure!(
                fork.seqno <= self.frontier.seqno,
                "approved fork is ahead of coherent frontier"
            );
            if let Some(seqno) = previous {
                ensure!(fork.seqno > seqno, "fork policy order is not strictly increasing");
            }
            previous = Some(fork.seqno);
        }
        Ok(())
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() as u64 <= MANIFEST_LIMIT, "manifest byte limit");
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    pub manifest: Manifest,
    pub signature: String,
}
impl SignedManifest {
    pub fn sign(manifest: Manifest, key: &SigningKey) -> Result<Self> {
        let mut message = DOMAIN.to_vec();
        message.extend(manifest.bytes()?);
        Ok(Self { manifest, signature: hex::encode(key.sign(&message).to_bytes()) })
    }
    pub fn verify(&self, trusted: &[u8; 32]) -> Result<String> {
        let bytes = self.manifest.bytes()?;
        let mut message = DOMAIN.to_vec();
        message.extend(&bytes);
        let sig = Signature::from_slice(&hex::decode(&self.signature)?)?;
        VerifyingKey::from_bytes(trusted)?
            .verify_strict(&message, &sig)
            .context("untrusted generation signature")?;
        Ok(sha256(&bytes))
    }
    pub fn parse(bytes: &[u8], trusted: &[u8; 32]) -> Result<Self> {
        ensure!(bytes.len() as u64 <= MANIFEST_LIMIT, "manifest byte limit");
        let result: Self = serde_json::from_slice(bytes)?;
        result.verify(trusted)?;
        ensure!(serde_json::to_vec(&result)? == bytes, "manifest envelope is not canonical");
        Ok(result)
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() as u64 <= MANIFEST_LIMIT, "signed manifest byte limit");
        Ok(bytes)
    }
}
