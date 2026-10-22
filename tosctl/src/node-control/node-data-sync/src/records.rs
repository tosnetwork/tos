use crate::model::{FullId, MANIFEST_LIMIT};
use anyhow::{Context, Result, ensure};
use node_store::StateKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use tl_api::{BoxedDeserialize, BoxedSerialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", content = "parameter", rename_all = "snake_case", deny_unknown_fields)]
pub enum Key {
    Version,
    Init,
    Gc,
    ShardClient,
    Hardforks,
    AsyncSerializer,
    PersistentDescriptions,
    PersistentShards(u32),
    DestroyedSessions,
    PendingObserverCleanup,
    PendingValidatorCleanup([u8; 32]),
}
impl Key {
    pub fn native(&self) -> StateKey {
        match self {
            Self::Version => StateKey::Version,
            Self::Init => StateKey::Init,
            Self::Gc => StateKey::Gc,
            Self::ShardClient => StateKey::ShardClient,
            Self::Hardforks => StateKey::Hardforks,
            Self::AsyncSerializer => StateKey::AsyncSerializer,
            Self::PersistentDescriptions => StateKey::PersistentDescriptions,
            Self::PersistentShards(n) => StateKey::PersistentShards(*n),
            Self::DestroyedSessions => StateKey::DestroyedSessions,
            Self::PendingObserverCleanup => StateKey::PendingObserverCleanup,
            Self::PendingValidatorCleanup(id) => StateKey::PendingValidatorCleanup(*id),
        }
    }
    pub fn local(&self) -> bool {
        matches!(
            self,
            Self::DestroyedSessions
                | Self::PendingObserverCleanup
                | Self::PendingValidatorCleanup(_)
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub key: Key,
    pub value: Option<Vec<u8>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainRecords {
    pub records: Vec<Record>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalRecords {
    pub records: Vec<Record>,
}

fn decode<T: BoxedDeserialize + BoxedSerialize>(value: &[u8]) -> Result<T> {
    let result = T::boxed_deserialized_from_bytes(value)?;
    ensure!(tl_api::serialize_boxed(&result)? == value, "noncanonical or trailing StateDb value");
    Ok(result)
}
fn index(records: &[Record]) -> Result<BTreeMap<Key, Option<Vec<u8>>>> {
    ensure!(records.len() <= 100_000, "StateDb record count limit");
    let mut result = BTreeMap::new();
    let mut bytes = 0_u64;
    for record in records {
        if let Some(value) = &record.value {
            bytes = bytes.checked_add(value.len() as u64).context("StateDb size overflow")?;
        }
        ensure!(bytes <= MANIFEST_LIMIT, "StateDb value byte limit");
        ensure!(
            result.insert(record.key.clone(), record.value.clone()).is_none(),
            "duplicate StateDb record"
        );
    }
    Ok(result)
}
impl ChainRecords {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out)?;
        ensure!(out.len() as u64 <= MANIFEST_LIMIT, "StateDb stream limit");
        Ok(out)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() as u64 <= MANIFEST_LIMIT, "StateDb stream limit");
        let value: Self = ciborium::from_reader(bytes)?;
        ensure!(value.bytes()? == bytes, "noncanonical StateDb stream");
        Ok(value)
    }
    pub fn value(&self, key: &Key) -> Result<&[u8]> {
        self.records
            .iter()
            .find(|r| &r.key == key)
            .and_then(|r| r.value.as_deref())
            .context("required chain StateDb value absent")
    }
    pub fn frontier(&self) -> Result<FullId> {
        let value: tl_api::tos::db::state::ShardClient = decode(self.value(&Key::ShardClient)?)?;
        Ok(FullId::from_native(value.block()))
    }
    pub fn gc(&self) -> Result<FullId> {
        let value: tl_api::tos::db::state::GcBlockId = decode(self.value(&Key::Gc)?)?;
        Ok(FullId::from_native(value.block()))
    }
    pub fn init(&self) -> Result<FullId> {
        let value: tl_api::tos::db::state::InitBlockId = decode(self.value(&Key::Init)?)?;
        Ok(FullId::from_native(value.block()))
    }
    pub fn forks(&self) -> Result<Vec<FullId>> {
        let Some(value) =
            self.records.iter().find(|r| r.key == Key::Hardforks).and_then(|r| r.value.as_deref())
        else {
            return Ok(vec![]);
        };
        let value: tl_api::tos::db::state::Hardforks = decode(value)?;
        Ok(value.blocks().iter().map(FullId::from_native).collect())
    }
    pub fn validate(&self) -> Result<()> {
        let records = index(&self.records)?;
        ensure!(records.keys().all(|k| !k.local()), "donor contains node-local StateDb metadata");
        let version: tl_api::tos::db::state::DbVersion = decode(self.value(&Key::Version)?)?;
        ensure!(*version.version() == 2, "unsupported StateDb version");
        let tip = self.frontier()?;
        tip.masterchain()?;
        let gc = self.gc()?;
        gc.masterchain()?;
        let init = self.init()?;
        init.masterchain()?;
        ensure!(
            gc.seqno <= tip.seqno && init.seqno <= tip.seqno,
            "incoherent chain StateDb frontiers"
        );
        self.forks()?;
        let mut required_shards = BTreeSet::new();
        if let Some(Some(value)) = records.get(&Key::PersistentDescriptions) {
            let list: tl_api::tos::db::state::PersistentStateDescriptionsList = decode(value)?;
            for header in list.list() {
                let id = FullId::from_native(&header.masterchain_id);
                id.masterchain()?;
                ensure!(required_shards.insert(id.seqno), "duplicate persistent-state description");
                ensure!(
                    u32::from_le_bytes(header.start_time.to_le_bytes())
                        < u32::from_le_bytes(header.end_time.to_le_bytes()),
                    "invalid persistent-state lifetime"
                );
                let shards = records
                    .get(&Key::PersistentShards(id.seqno))
                    .and_then(Option::as_deref)
                    .context("persistent-state description dependency missing")?;
                let _: tl_api::tos::db::state::PersistentStateDescriptionShards = decode(shards)?;
            }
        }
        for (key, value) in &records {
            match key {
                Key::AsyncSerializer => {
                    if let Some(value) = value {
                        let _: tl_api::tos::db::state::AsyncSerializer = decode(value)?;
                    }
                }
                Key::PersistentShards(seqno) => ensure!(
                    required_shards.contains(seqno),
                    "unreferenced persistent-state shard record"
                ),
                _ => {}
            }
        }
        Ok(())
    }
}
impl LocalRecords {
    pub fn validate(&self) -> Result<()> {
        let records = index(&self.records)?;
        ensure!(records.keys().all(Key::local), "non-local key in preservation inventory");
        Ok(())
    }
}

/// Never overwrite imported fork history with an old target record.
pub fn reconcile_forks(
    policy: &[FullId],
    donor: &ChainRecords,
    local_old: &[FullId],
    ancestors: &BTreeSet<FullId>,
) -> Result<()> {
    donor.validate()?;
    ensure!(donor.forks()? == policy, "imported fork record differs from locally approved policy");
    ensure!(policy.starts_with(local_old), "target fork history contradicts approved policy");
    let tip = donor.frontier()?;
    let mut previous = None;
    for fork in policy {
        fork.masterchain()?;
        ensure!(fork.seqno <= tip.seqno, "approved fork is ahead of imported frontier");
        if let Some(old) = previous {
            ensure!(fork.seqno > old, "unordered fork policy");
        }
        previous = Some(fork.seqno);
        ensure!(ancestors.contains(fork), "approved fork has no full-id ancestry evidence");
    }
    Ok(())
}

#[cfg(feature = "native")]
pub fn export(store: &node_store::OfflineStore) -> Result<(ChainRecords, LocalRecords)> {
    let mut keys = vec![
        Key::Version,
        Key::Init,
        Key::Gc,
        Key::ShardClient,
        Key::Hardforks,
        Key::AsyncSerializer,
        Key::PersistentDescriptions,
        Key::DestroyedSessions,
        Key::PendingObserverCleanup,
    ];
    if let Some(value) = store.get(&StateKey::PersistentDescriptions)? {
        let list: tl_api::tos::db::state::PersistentStateDescriptionsList = decode(&value)?;
        for entry in list.list() {
            keys.push(Key::PersistentShards(entry.masterchain_id.seq_no()));
        }
    }
    let inventory = store.inventory_keys()?;
    for raw in &inventory {
        if let Some(suffix) = raw.strip_prefix(b"tos.state.pending_validator_consensus_db_cleanup.")
        {
            let text = std::str::from_utf8(suffix)?;
            ensure!(text.len() == 64, "invalid local retirement key");
            let id: [u8; 32] = hex::decode(text)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid retirement id"))?;
            let key = Key::PendingValidatorCleanup(id);
            ensure!(key.native().bytes()? == *raw, "noncanonical native retirement key");
            keys.push(key);
        }
    }
    let known = keys.iter().map(|key| key.native().bytes()).collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        inventory.iter().all(|key| known.contains(key)),
        "unknown StateDb key: schema review required"
    );
    let mut chain = Vec::new();
    let mut local = Vec::new();
    for key in keys {
        let value = store.get(&key.native())?;
        let is_local = key.local();
        let record = Record { key, value };
        if is_local {
            local.push(record);
        } else {
            chain.push(record);
        }
    }
    let chain = ChainRecords { records: chain };
    let local = LocalRecords { records: local };
    chain.validate()?;
    local.validate()?;
    Ok((chain, local))
}
#[cfg(feature = "native")]
pub fn install(path: &std::path::Path, chain: &ChainRecords, local: &LocalRecords) -> Result<()> {
    chain.validate()?;
    local.validate()?;
    let mut store = node_store::OfflineStore::create_staging(path)?;
    let changes = chain
        .records
        .iter()
        .chain(&local.records)
        .map(|r| (r.key.native(), r.value.clone()))
        .collect::<Vec<_>>();
    store.write(&changes)?;
    for (key, value) in changes {
        ensure!(store.get(&key)? == value, "StateDb reconstruction changed preserved bytes");
    }
    Ok(())
}

impl LocalRecords {
    /// Decode safety evidence separately from preserving its original bytes.
    pub fn safety_anchors(&self) -> Result<BTreeSet<FullId>> {
        self.validate()?;
        let mut anchors = BTreeSet::new();
        for record in &self.records {
            let Some(value) = &record.value else {
                continue;
            };
            match &record.key {
                Key::DestroyedSessions => {
                    let _: tl_api::tos::db::state::DestroyedSessions = decode(value)?;
                }
                Key::PendingObserverCleanup => {
                    let text = std::str::from_utf8(value)?;
                    for name in text.lines().filter(|name| !name.is_empty()) {
                        validate_consensus_name(name, None, true)?;
                    }
                }
                Key::PendingValidatorCleanup(id) => {
                    ensure!(
                        value.len() >= 113 && value[0] == 1,
                        "unknown validator retirement record schema"
                    );
                    ensure!(
                        value.get(1..33) == Some(id.as_slice()),
                        "retirement key and value identify different sessions"
                    );
                    let workchain = i32::from_le_bytes(
                        value.get(33..37).context("retirement workchain")?.try_into()?,
                    );
                    let shard = i64::from_le_bytes(
                        value.get(37..45).context("retirement shard")?.try_into()?,
                    );
                    let seqno = u32::from_le_bytes(
                        value.get(45..49).context("retirement seqno")?.try_into()?,
                    );
                    let checkpoint = FullId {
                        workchain,
                        shard,
                        seqno,
                        root_hash: hex::encode(value.get(49..81).context("retirement root hash")?),
                        file_hash: hex::encode(value.get(81..113).context("retirement file hash")?),
                    };
                    checkpoint.masterchain()?;
                    validate_consensus_name(
                        std::str::from_utf8(value.get(113..).context("retirement directory")?)?,
                        Some(id),
                        false,
                    )?;
                    anchors.insert(checkpoint);
                }
                _ => anyhow::bail!("non-local key in safety inventory"),
            }
        }
        Ok(anchors)
    }
}
fn validate_consensus_name(name: &str, session: Option<&[u8; 32]>, observer: bool) -> Result<()> {
    ensure!(name.len() <= 255, "consensus directory name limit");
    let fields: Vec<_> = name.split('.').collect();
    ensure!(fields.len() == if observer { 7 } else { 5 }, "unsupported consensus directory layout");
    ensure!(fields[0] == "consensus", "unknown consensus directory prefix");
    let wc: i32 = fields[1].parse()?;
    let shard: u64 = fields[2].parse()?;
    let cc: u32 = fields[3].parse()?;
    let id: [u8; 32] = hex::decode(fields[4])?
        .try_into()
        .map_err(|_| anyhow::anyhow!("consensus session hash length"))?;
    if let Some(expected) = session {
        ensure!(id == *expected, "consensus directory belongs to another session");
    }
    let mut canonical = format!("consensus.{wc}.{shard}.{cc}.{}", hex::encode_upper(id));
    if observer {
        ensure!(fields[5] == "observer", "unknown consensus directory suffix");
        let public: [u8; 32] = hex::decode(fields[6])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("observer identity length"))?;
        canonical.push_str(&format!(".observer.{}", hex::encode_upper(public)));
    }
    ensure!(canonical == name, "noncanonical consensus directory");
    Ok(())
}
pub fn reconcile_anchors(
    donor: &ChainRecords,
    anchors: &BTreeSet<FullId>,
    evidence: &BTreeSet<FullId>,
) -> Result<()> {
    donor.validate()?;
    let frontier = donor.frontier()?;
    for anchor in anchors {
        anchor.masterchain()?;
        ensure!(anchor.seqno <= frontier.seqno, "generation predates a target safety anchor");
        ensure!(
            anchor == &frontier || evidence.contains(anchor),
            "target safety anchor has no imported full-id ancestry evidence"
        );
    }
    Ok(())
}
