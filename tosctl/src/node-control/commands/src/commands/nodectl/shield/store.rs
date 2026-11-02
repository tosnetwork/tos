/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! What the client keeps between runs, and how.
//!
//! One directory per shielded instance -- one mnemonic on one pool on one
//! network -- holding a state file, a journal and a lock. Both files are
//! encrypted under a key derived from the pool master, so the directory on
//! its own says nothing about the notes in it, and both are bound by their
//! authenticated data to the network, the pool and the chain identity they
//! were written for, so a file copied from another instance, another pool or
//! another chain does not open.
//!
//! The state is replaced whole, atomically. The journal only grows, one
//! sealed record at a time, each record numbered in its authenticated data so
//! a reordered, repeated or truncated journal is noticed. What goes in the
//! journal is whatever must survive a crash between deciding and doing: an
//! index about to be shown, a message about to be sent.

use anyhow::Context;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use super::profile::Profile;

/// The format of the sealed state and journal. A client reads its own format
/// only: this tool is pre-release and carries no state across formats. An
/// instance written in an earlier format is re-initialised from its mnemonic.
pub const STATE_FORMAT_VERSION: u32 = 2;
const AAD_PREFIX: &[u8] = b"TOS-SHIELD-CLI-v1";
const KEY_LABEL: &[u8] = b"TOS-SHIELD-CLI-STATE-KEY-v1";
const INSTANCE_LABEL: &[u8] = b"TOS-SHIELD-CLI-INSTANCE-v1";
const SEALED_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
/// The largest state or journal record this tool reads back.
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;
const KIND_STATE: u8 = 1;
const KIND_JOURNAL: u8 = 2;

/// Which chain the state was built against: the identity of the block the
/// proof verifier anchors on, or, in unverified mode, the init block the RPC
/// endpoint reports.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainIdentity {
    pub source: String,
    pub root_hash: [u8; 32],
    pub file_hash: [u8; 32],
}

/// What every sealed record is bound to: the network and the pool. The chain
/// identity is kept inside the state and compared there, so an instance can
/// move from the RPC endpoint's word to the proof verifier's without its
/// journal becoming unreadable.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Binding {
    pub global_id: i32,
    pub pool_address: String,
}

impl Binding {
    fn aad(&self, kind: u8, version: u32, sequence: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(AAD_PREFIX);
        out.push(kind);
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&self.global_id.to_be_bytes());
        push_text(&mut out, &self.pool_address);
        out
    }
}

fn push_text(out: &mut Vec<u8>, text: &str) {
    let bytes = text.as_bytes();
    out.extend_from_slice(&(bytes.len().min(u16::MAX as usize) as u16).to_be_bytes());
    out.extend_from_slice(&bytes[..bytes.len().min(u16::MAX as usize)]);
}

/// The key material one instance's files are sealed with, and the public
/// name of its directory. Both come from the pool master and the execution
/// domain alone, so the same mnemonic on the same pool always finds the same
/// directory, whatever the profile file is called.
pub struct Keys {
    key: Zeroizing<[u8; 32]>,
    instance_id: [u8; 32],
}

impl Keys {
    pub fn derive(pool_master: &[u8; 64], execution_domain: &[u8; 32]) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        shake(&[KEY_LABEL, pool_master, execution_domain], key.as_mut());
        let mut instance_id = [0u8; 32];
        shake(&[INSTANCE_LABEL, pool_master, execution_domain], &mut instance_id);
        Self { key, instance_id }
    }

    pub fn instance_id(&self) -> &[u8; 32] {
        &self.instance_id
    }

    /// The directory name: half the instance id, which is plenty to keep two
    /// instances apart and reveals nothing an observer could use.
    pub fn directory_name(&self) -> String {
        hex::encode(&self.instance_id[..16])
    }
}

fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut hasher = Shake256::default();
    for part in parts {
        hasher.update(part);
    }
    XofReader::read(&mut hasher.finalize_xof(), out);
}

/// A pointer from the operator's chosen name to the instance: the profile and
/// the binding, which are public, and the directory the sealed files live in.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Pointer {
    pub schema: String,
    pub profile: Profile,
    pub binding: Binding,
    /// The chain the instance was last synchronised against. Public, and
    /// repeated inside the sealed state, which is the copy that is trusted.
    pub chain: ChainIdentity,
    pub directory: String,
}

pub const POINTER_SCHEMA: &str = "tosctl-shield-pointer-v1";

/// Opens, or creates, a private lock file and takes it exclusively without
/// waiting. The lock is held for as long as the file stays open.
fn take_lock(path: &Path, what: &str) -> anyhow::Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open the {what} lock"))?;
    check_private_file(&lock, "lock")?;
    // SAFETY: flock on a descriptor this process owns and keeps open.
    let taken = unsafe {
        libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX | libc::LOCK_NB)
    };
    anyhow::ensure!(taken == 0, "the {what} lock is held by another shield command");
    Ok(lock)
}

/// The lock an initialisation holds on an instance name, so that two
/// initialisations of the same name -- which may be on different pools and so
/// hold different instance locks -- cannot both publish a pointer under it.
pub struct NameLock {
    _lock: File,
}

impl NameLock {
    pub fn take(root: &Path, name: &str) -> anyhow::Result<Self> {
        let pointer = pointer_path(root, name)?;
        let prepared = secrets_vault::private_file::prepare_parent(&pointer)?;
        let lock = take_lock(&prepared.join(format!("{name}.lock")), "name")
            .with_context(|| format!("another initialisation of {name:?} may be running"))?;
        Ok(Self { _lock: lock })
    }
}

/// The name of another pointer in `root` that already names `directory`, if
/// any. A pointer that does not load is an error: it may be one.
pub fn other_pointer_naming(
    root: &Path,
    directory: &str,
    except: &str,
) -> anyhow::Result<Option<String>> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("read the shield root"),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.context("read the shield root")?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str().and_then(|n| n.strip_suffix(".json")) else {
            continue;
        };
        if name == except || pointer_path(root, name).is_err() {
            continue;
        }
        names.push(name.to_owned());
    }
    names.sort();
    for name in names {
        let pointer = Pointer::load(&pointer_path(root, &name)?)
            .with_context(|| format!("the pointer {name:?} does not load"))?;
        if pointer.directory == directory {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

/// Where a tosctl configuration keeps its shielded instances.
pub fn shield_root(config_path: &Path) -> PathBuf {
    let parent =
        config_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    parent.join("shield")
}

pub fn pointer_path(root: &Path, name: &str) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "an instance name is 1 to 64 letters, digits, '-' or '_'"
    );
    Ok(root.join(format!("{name}.json")))
}

impl Pointer {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = secrets_vault::private_file::read_regular(path)
            .with_context(|| format!("read {}", path.display()))?;
        let pointer: Self =
            serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        anyhow::ensure!(
            pointer.schema == POINTER_SCHEMA,
            "{} is not a shield pointer",
            path.display()
        );
        pointer.profile.validate()?;
        anyhow::ensure!(
            pointer.binding.global_id == pointer.profile.global_id
                && pointer.binding.pool_address == pointer.profile.address()?.to_string(),
            "{} binds a different pool than its profile names",
            path.display()
        );
        Ok(pointer)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        secrets_vault::private_file::write_private_atomic(path, text.as_bytes())
    }
}

/// One instance's directory, locked for the life of this value.
pub struct Store {
    dir: PathBuf,
    binding: Binding,
    cipher: XChaCha20Poly1305,
    /// The largest state file, and the largest journal, this store writes or
    /// reads. A write that would cross it is refused with the old file intact.
    limit: usize,
    _lock: File,
}

impl Store {
    /// Opens, or creates, the instance directory and takes its lock. The
    /// lock is per instance, so two commands on the same mnemonic and pool
    /// never interleave, whatever profile files they were started from.
    pub fn open(root: &Path, keys: &Keys, binding: Binding) -> anyhow::Result<Self> {
        let dir = root.join(keys.directory_name());
        let prepared = secrets_vault::private_file::prepare_parent(&dir.join("state"))?;
        let lock = take_lock(&prepared.join("lock"), "instance").with_context(|| {
            format!("another shield command may be running on {}", prepared.display())
        })?;
        let cipher = XChaCha20Poly1305::new_from_slice(&keys.key[..])
            .map_err(|_| anyhow::anyhow!("a state key of the wrong size"))?;
        Ok(Self { dir: prepared, binding, cipher, limit: MAX_RECORD_BYTES, _lock: lock })
    }

    #[cfg(test)]
    pub(super) fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// A second handle on the same directory that reads what is on disk and
    /// does not take the lock: for a test that must look at the journal
    /// while the locked handle is in use.
    #[cfg(test)]
    pub(super) fn unlocked_reader(&self) -> anyhow::Result<Self> {
        let lock = File::open(self.dir.join("lock")).context("open the lock for reading")?;
        Ok(Self {
            dir: self.dir.clone(),
            binding: self.binding.clone(),
            cipher: self.cipher.clone(),
            limit: self.limit,
            _lock: lock,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.dir
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join("state")
    }

    fn journal_path(&self) -> PathBuf {
        self.dir.join("journal")
    }

    fn seal(
        &self,
        kind: u8,
        version: u32,
        sequence: u64,
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = self.binding.aad(kind, version, sequence);
        let sealed = self
            .cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| anyhow::anyhow!("seal a record"))?;
        let mut out = Vec::with_capacity(1 + NONCE_BYTES + sealed.len());
        out.push(SEALED_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    fn open_sealed(
        &self,
        kind: u8,
        version: u32,
        sequence: u64,
        bytes: &[u8],
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        anyhow::ensure!(
            bytes.len() >= 1 + NONCE_BYTES + TAG_BYTES && bytes[0] == SEALED_VERSION,
            "a sealed record of the wrong shape"
        );
        let aad = self.binding.aad(kind, version, sequence);
        let opened = self
            .cipher
            .decrypt(
                XNonce::from_slice(&bytes[1..1 + NONCE_BYTES]),
                Payload { msg: &bytes[1 + NONCE_BYTES..], aad: &aad },
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "a sealed record does not open: it was altered, or written for another \
                     instance, pool or chain"
                )
            })?;
        Ok(Zeroizing::new(opened))
    }

    /// Opens a record of the current format. A record that opens under an
    /// earlier format is named as such, so the message says what to do
    /// instead of reporting a record that does not open.
    fn open_current(
        &self,
        kind: u8,
        sequence: u64,
        bytes: &[u8],
        what: &str,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        match self.open_sealed(kind, STATE_FORMAT_VERSION, sequence, bytes) {
            Ok(plain) => Ok(plain),
            Err(error) => {
                for version in 1..STATE_FORMAT_VERSION {
                    if self.open_sealed(kind, version, sequence, bytes).is_ok() {
                        anyhow::bail!(
                            "the {what} was written in format {version} by an earlier pre-release \
                             client; this client reads format {STATE_FORMAT_VERSION} only and \
                             carries nothing across formats. Remove the instance directory ({}) \
                             and run `tosctl shield init` again: the mnemonic recovers every note",
                            self.dir.display()
                        );
                    }
                }
                Err(error)
            }
        }
    }

    /// Replaces the state atomically: the new file is complete and synced
    /// before it takes the old one's name.
    pub fn save_state(&self, state: &PersistedState) -> anyhow::Result<()> {
        anyhow::ensure!(state.version == STATE_FORMAT_VERSION, "a state of another version");
        anyhow::ensure!(state.binding == self.binding, "a state bound elsewhere");
        let mut plain = Zeroizing::new(Vec::new());
        ciborium::into_writer(state, &mut *plain).context("encode the state")?;
        let sealed = self.seal(KIND_STATE, STATE_FORMAT_VERSION, 0, &plain)?;
        anyhow::ensure!(
            sealed.len() <= self.limit,
            "the state would be {} bytes, above this client's limit of {}; the previous state is \
             kept",
            sealed.len(),
            self.limit
        );
        secrets_vault::private_file::write_private_atomic(&self.state_path(), &sealed)
    }

    pub fn load_state(&self) -> anyhow::Result<Option<PersistedState>> {
        let path = self.state_path();
        let mut file = match open_private_for_read(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
        };
        check_private_file(&file, "state")?;
        let mut bytes = Vec::new();
        (&mut file).take(self.limit as u64 + 1).read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= self.limit, "the state file is too large");
        let plain = self.open_current(KIND_STATE, 0, &bytes, "state")?;
        let state: PersistedState =
            ciborium::from_reader(plain.as_slice()).context("decode the state")?;
        anyhow::ensure!(state.version == STATE_FORMAT_VERSION, "a state of another version");
        anyhow::ensure!(
            state.binding == self.binding,
            "the state is bound to another pool or chain"
        );
        Ok(Some(state))
    }

    /// Appends one record and does not return until it is on disk. `sequence`
    /// must be the number of records already in the journal.
    pub fn append_journal(&self, sequence: u64, record: &JournalRecord) -> anyhow::Result<()> {
        let mut plain = Zeroizing::new(Vec::new());
        ciborium::into_writer(record, &mut *plain).context("encode a journal record")?;
        let sealed = self.seal(KIND_JOURNAL, STATE_FORMAT_VERSION, sequence, &plain)?;
        let length = u32::try_from(sealed.len()).context("a journal record too large")?;
        let mut frame = Vec::with_capacity(4 + sealed.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&sealed);
        let path = self.journal_path();
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        check_private_file(&file, "journal")?;
        let existing = file.metadata()?.len();
        anyhow::ensure!(
            count_frames_up_to(&path, existing)? == sequence,
            "the journal holds a different number of records than this command believes"
        );
        let after = usize::try_from(existing)
            .ok()
            .and_then(|existing| existing.checked_add(frame.len()))
            .context("journal size overflow")?;
        anyhow::ensure!(
            after <= self.limit,
            "the journal would grow to {after} bytes, above this client's limit of {}; the record \
             is not written",
            self.limit
        );
        file.write_all(&frame)?;
        file.sync_all()?;
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Every record, in order. A journal that does not open in full is an
    /// error: a record that fails to authenticate, a frame cut short, or a
    /// record out of sequence each stops the command.
    pub fn read_journal(&self) -> anyhow::Result<Vec<JournalRecord>> {
        let path = self.journal_path();
        let mut file = match open_private_for_read(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
        };
        check_private_file(&file, "journal")?;
        let mut bytes = Vec::new();
        (&mut file).take(self.limit as u64 + 1).read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= self.limit, "the journal is too large");
        let mut records = Vec::new();
        let mut at = 0usize;
        let mut sequence = 0u64;
        while at < bytes.len() {
            let Some(header) = bytes.get(at..at + 4) else {
                anyhow::bail!("the journal ends inside a record header (record {sequence})");
            };
            let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
            let start = at + 4;
            let end = start.checked_add(length).context("journal frame overflow")?;
            let Some(frame) = bytes.get(start..end) else {
                anyhow::bail!(
                    "the journal ends inside record {sequence}: an append was interrupted, or \
                     the file was cut"
                );
            };
            let plain = self
                .open_current(KIND_JOURNAL, sequence, frame, "journal")
                .with_context(|| format!("journal record {sequence}"))?;
            let record: JournalRecord =
                ciborium::from_reader(plain.as_slice()).context("decode a journal record")?;
            records.push(record);
            at = end;
            sequence = sequence.checked_add(1).context("journal sequence overflow")?;
        }
        Ok(records)
    }
}

/// How many whole frames the first `limit` bytes of the journal hold. Used to
/// confirm the sequence number an append is about to claim.
fn count_frames_up_to(path: &Path, limit: u64) -> anyhow::Result<u64> {
    let mut file = open_private_for_read(path)?;
    check_private_file(&file, "journal")?;
    let mut bytes = Vec::new();
    (&mut file).take(limit).read_to_end(&mut bytes)?;
    let mut at = 0usize;
    let mut count = 0u64;
    while at < bytes.len() {
        let header = bytes.get(at..at + 4).context("the journal ends inside a record header")?;
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        at = at.checked_add(4).and_then(|v| v.checked_add(length)).context("journal overflow")?;
        anyhow::ensure!(at <= bytes.len(), "the journal ends inside a record");
        count = count.checked_add(1).context("journal count overflow")?;
    }
    Ok(count)
}

fn open_private_for_read(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)
}

/// A file this tool wrote: a regular file, ours, with one name and no access
/// for anyone else.
fn check_private_file(file: &File, what: &str) -> anyhow::Result<()> {
    let meta = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    anyhow::ensure!(meta.is_file(), "the {what} is not a regular file");
    anyhow::ensure!(meta.uid() == euid, "the {what} is owned by uid {}, not {euid}", meta.uid());
    anyhow::ensure!(meta.nlink() == 1, "the {what} has {} links; expected one", meta.nlink());
    anyhow::ensure!(
        meta.mode() & 0o077 == 0,
        "the {what} is readable by others (mode {:04o})",
        meta.mode() & 0o7777
    );
    Ok(())
}

/// A field element or hash as 32 bytes, and a coin amount as 16, so the
/// encoding never depends on how a serializer handles wide integers.
pub type Word = [u8; 32];
pub type Coins = [u8; 16];

pub fn coins(value: u128) -> Coins {
    value.to_be_bytes()
}

pub fn coins_value(bytes: &Coins) -> u128 {
    u128::from_be_bytes(*bytes)
}

/// Where the replay stopped, and how far it can be trusted.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cursor {
    pub lt: u64,
    pub hash: Word,
    /// True only if every transaction up to here was authenticated through
    /// the proof verifier. Replaying more history never turns this on.
    pub verified: bool,
    pub checkpoint_seqno: u32,
    pub checkpoint_root_hash: String,
    pub checkpoint_file_hash: String,
    /// Time of the masterchain block the head was read at.
    pub block_gen_utime: u32,
    /// Time of the shard block holding the pool's state: the contract's own
    /// clock, the only one a spend's deadline is judged against.
    pub shard_gen_utime: u32,
    pub transactions_replayed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedPayout {
    pub recipient: String,
    pub value: Coins,
    pub body_hash: Word,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedPendingRecovery {
    pub payout: PersistedPayout,
    pub owner_commitment: Word,
    pub payload: Vec<u8>,
    pub consumed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedNullifierLeaf {
    pub index: u64,
    pub value: Word,
    pub next_index: u32,
    pub next_value: Word,
}

/// The ledger as plain bytes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedLedger {
    pub leaves: Vec<Word>,
    pub nullifiers: Vec<Word>,
    /// The intent digest of every accepted transact, in order.
    pub intents: Vec<Word>,
    pub nullifier_tree: Vec<PersistedNullifierLeaf>,
    pub nullifier_next_index: u64,
    pub native_liability: Coins,
    pub reserved_recovery_leaves: u64,
    pub pending: Vec<PersistedPendingRecovery>,
}

/// One of this wallet's notes, as the scan found it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedNote {
    /// 0 ordinary, 1 dummy, 2 recovery.
    pub kind: u8,
    pub note_key_index: u64,
    pub amount: Coins,
    pub note_secret: Word,
    pub owner_commitment: Word,
    pub note_body: Word,
    /// The hash the chain computed over the sealed payload; a spend witness
    /// needs it.
    pub output_data_hash: Word,
    pub spendable: bool,
    pub spent: bool,
    pub leaf: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedDiagnostic {
    pub slot: u8,
    pub why: String,
}

/// The pool's frozen configuration, as last read.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedPoolConfig {
    pub withdrawal_fee: Coins,
    pub denominations: Vec<Coins>,
}

/// Everything in the state file.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedState {
    pub version: u32,
    pub binding: Binding,
    /// The chain this state was built against. Compared on every read of the
    /// head; a different chain refuses.
    pub chain: ChainIdentity,
    pub instance_id: Word,
    pub profile: Profile,
    pub pool_config: PersistedPoolConfig,
    pub cursor: Option<Cursor>,
    pub ledger: PersistedLedger,
    pub notes: Vec<PersistedNote>,
    pub diagnostics: Vec<PersistedDiagnostic>,
    /// The next index the scan would issue, and the indices it found used
    /// more than once.
    pub scan_next_index: u64,
    pub reused_indices: Vec<u64>,
    /// One past the highest index this client has issued or prepared.
    pub issued_high_water: u64,
    /// How many journal records the state had seen when it was written. A
    /// shorter journal than this is a rollback.
    pub journal_records: u64,
}

/// What the journal records.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum JournalRecord {
    /// An index is about to be shown or sealed into a payload.
    IndexReserved { index: u64, purpose: String },
    /// A deposit message is built and about to be broadcast. `boc` is the
    /// exact external message; it is never rebuilt.
    DepositPrepared {
        index: u64,
        amount: Coins,
        value: Coins,
        payer: String,
        /// The owner commitment the note was built with; the note the chain
        /// later shows at this index must carry the same one.
        owner_commitment: Word,
        body_hash: Word,
        message_hash: Word,
        boc: Vec<u8>,
    },
    /// The endpoint accepted the exact message.
    DepositBroadcast { message_hash: Word },
    /// The broadcast returned an error; whether the message reached the
    /// network is not known.
    DepositUnknown { message_hash: Word, error: String },
    /// The indices one spend will seal and sign with, reserved before any of
    /// them is used for anything.
    IndicesReserved { indices: Vec<u64>, purpose: String },
    /// A spend is assembled and about to be proven. Its input notes are held
    /// from any other spend until a verified sync shows the intent accepted,
    /// shows an input spent by something else, or shows the contract's clock
    /// past the deadline.
    SpendPlanned {
        intent_digest: Word,
        nullifiers: [Word; 2],
        input_leaves: Vec<u64>,
        indices: Vec<u64>,
        amount: Coins,
        /// The payout address of a withdrawal, or the hash of the descriptor
        /// a transfer pays.
        recipient: String,
        withdrawal: bool,
        valid_until: u32,
        anchor_kind: u8,
        anchor_id: u32,
    },
    /// The exact external message of a spend, built and about to be
    /// broadcast. It is never rebuilt.
    SpendSigned {
        intent_digest: Word,
        body_hash: Word,
        message_hash: Word,
        payer: String,
        value: Coins,
        boc: Vec<u8>,
    },
    /// The endpoint accepted the exact spend message.
    SpendBroadcast { message_hash: Word },
    /// The broadcast of a spend returned an error; whether the message
    /// reached the network is not known.
    SpendUnknown { message_hash: Word, error: String },
}

/// The next index this client may issue: past everything the state knows,
/// everything the journal reserved and everything the scan found, and not
/// an index the chain shows used twice.
pub fn next_issuable_index(
    state: &PersistedState,
    journal: &[JournalRecord],
) -> anyhow::Result<u64> {
    let journal_next = journal
        .iter()
        .flat_map(|record| match record {
            JournalRecord::IndexReserved { index, .. }
            | JournalRecord::DepositPrepared { index, .. } => vec![*index],
            JournalRecord::IndicesReserved { indices, .. }
            | JournalRecord::SpendPlanned { indices, .. } => indices.clone(),
            _ => Vec::new(),
        })
        .map(|index| index.checked_add(1))
        .try_fold(0u64, |best, next| next.map(|next| best.max(next)))
        .context("note key index exhausted")?;
    let mut index = state.issued_high_water.max(journal_next).max(state.scan_next_index);
    while state.reused_indices.contains(&index) {
        index = index.checked_add(1).context("note key index exhausted")?;
    }
    anyhow::ensure!(index < u64::MAX, "note key index exhausted");
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn keys() -> Keys {
        Keys::derive(&[7u8; 64], &[3u8; 32])
    }

    fn binding() -> Binding {
        Binding {
            global_id: 3,
            pool_address: "0:aa76950cf26cb74c1d1b1a977d17bd3c96c6c9f28cb259fca297cdc8d33429fe"
                .into(),
        }
    }

    fn chain() -> ChainIdentity {
        ChainIdentity { source: "test".into(), root_hash: [1; 32], file_hash: [2; 32] }
    }

    fn state(binding: &Binding) -> PersistedState {
        PersistedState {
            version: STATE_FORMAT_VERSION,
            binding: binding.clone(),
            chain: chain(),
            instance_id: *keys().instance_id(),
            profile: Profile {
                schema: super::super::profile::PROFILE_SCHEMA.into(),
                global_id: 3,
                pool_address: binding.pool_address.clone(),
                pool_code_hash: super::super::profile::KNOWN_CODE_HASHES[0].into(),
            },
            pool_config: PersistedPoolConfig {
                withdrawal_fee: coins(1),
                denominations: vec![coins(10)],
            },
            cursor: None,
            ledger: PersistedLedger {
                leaves: vec![[9; 32]],
                nullifiers: Vec::new(),
                intents: Vec::new(),
                nullifier_tree: vec![PersistedNullifierLeaf {
                    index: 0,
                    value: [0; 32],
                    next_index: 0,
                    next_value: [0; 32],
                }],
                nullifier_next_index: 1,
                native_liability: coins(10),
                reserved_recovery_leaves: 0,
                pending: Vec::new(),
            },
            notes: Vec::new(),
            diagnostics: Vec::new(),
            scan_next_index: 0,
            reused_indices: Vec::new(),
            issued_high_water: 0,
            journal_records: 0,
        }
    }

    fn private_root() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("tempdir")
    }

    #[test]
    fn the_state_round_trips_and_a_foreign_binding_does_not_open() {
        let root = private_root();
        let keys = keys();
        let store = Store::open(root.path(), &keys, binding()).expect("open");
        assert!(store.load_state().expect("empty").is_none());
        let state = state(&binding());
        store.save_state(&state).expect("save");
        assert_eq!(store.load_state().expect("load"), Some(state.clone()));
        drop(store);

        let mut other = binding();
        other.global_id = 2;
        let store = Store::open(root.path(), &keys, other).expect("open");
        assert!(store.load_state().is_err(), "another network's binding");
        drop(store);

        let store = Store::open(root.path(), &Keys::derive(&[8u8; 64], &[3u8; 32]), binding())
            .expect("open");
        assert!(store.load_state().expect("another key's directory").is_none());
    }

    /// A state or journal of an earlier format is refused by name, with the
    /// way out, rather than as a record that does not open.
    #[test]
    fn an_earlier_format_is_refused_by_name() {
        let root = private_root();
        let store = Store::open(root.path(), &keys(), binding()).expect("open");
        let old_state = store.seal(KIND_STATE, 1, 0, b"a state of the first format").expect("seal");
        secrets_vault::private_file::write_private_atomic(&store.state_path(), &old_state)
            .expect("write");
        let error = store.load_state().expect_err("refused").to_string();
        assert!(error.contains("written in format 1"), "{error}");
        assert!(error.contains("tosctl shield init"), "{error}");

        let frame = store.seal(KIND_JOURNAL, 1, 0, b"a record of the first format").expect("seal");
        let mut bytes = (frame.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(&frame);
        secrets_vault::private_file::write_private_atomic(&store.journal_path(), &bytes)
            .expect("write");
        let error = format!("{:#}", store.read_journal().expect_err("refused"));
        assert!(error.contains("written in format 1"), "{error}");

        // A record that opens under no format is still what it was.
        let garbage = store.seal(KIND_STATE, 7, 0, b"nothing this client wrote").expect("seal");
        secrets_vault::private_file::write_private_atomic(&store.state_path(), &garbage)
            .expect("write");
        let error = store.load_state().expect_err("refused").to_string();
        assert!(error.contains("does not open"), "{error}");
    }

    #[test]
    fn a_tampered_byte_and_a_swapped_kind_are_refused() {
        let root = private_root();
        let keys = keys();
        let store = Store::open(root.path(), &keys, binding()).expect("open");
        store.save_state(&state(&binding())).expect("save");
        let path = store.state_path();
        let mut bytes = std::fs::read(&path).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, &bytes).expect("write");
        assert!(store.load_state().is_err(), "a flipped bit");

        // A journal record moved into the state file's place.
        store
            .append_journal(0, &JournalRecord::IndexReserved { index: 0, purpose: "t".into() })
            .expect("append");
        let journal = std::fs::read(store.journal_path()).expect("journal");
        std::fs::write(&path, &journal[4..]).expect("swap");
        assert!(store.load_state().is_err(), "a journal record as the state");
    }

    #[test]
    fn the_journal_keeps_order_and_notices_a_cut_or_a_repeat() {
        let root = private_root();
        let store = Store::open(root.path(), &keys(), binding()).expect("open");
        let first = JournalRecord::IndexReserved { index: 0, purpose: "address".into() };
        let second = JournalRecord::DepositBroadcast { message_hash: [4; 32] };
        store.append_journal(0, &first).expect("first");
        assert!(store.append_journal(0, &second).is_err(), "a stale sequence");
        store.append_journal(1, &second).expect("second");
        assert_eq!(store.read_journal().expect("read"), vec![first.clone(), second.clone()]);

        let path = store.journal_path();
        let bytes = std::fs::read(&path).expect("read");
        let mut repeated = bytes.clone();
        repeated.extend_from_slice(&bytes[bytes.len() - 4 - frame_len(&bytes, 1)..]);
        std::fs::write(&path, &repeated).expect("write");
        assert!(store.read_journal().is_err(), "a repeated record is out of sequence");

        std::fs::write(&path, &bytes[..bytes.len() - 3]).expect("write");
        assert!(store.read_journal().is_err(), "a cut record");
    }

    fn frame_len(bytes: &[u8], which: usize) -> usize {
        let mut at = 0;
        for _ in 0..which {
            let len = u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
            at += 4 + len as usize;
        }
        u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as usize
    }

    #[test]
    fn a_symlinked_or_shared_file_is_refused() {
        let root = private_root();
        let keys = keys();
        let store = Store::open(root.path(), &keys, binding()).expect("open");
        store.save_state(&state(&binding())).expect("save");
        let real = root.path().join("elsewhere");
        std::fs::copy(store.state_path(), &real).expect("copy");
        std::fs::remove_file(store.state_path()).expect("remove");
        std::os::unix::fs::symlink(&real, store.state_path()).expect("symlink");
        assert!(store.load_state().is_err(), "a symlinked state");
        std::fs::remove_file(store.state_path()).expect("remove");
        std::fs::hard_link(&real, store.state_path()).expect("link");
        assert!(store.load_state().is_err(), "a hard-linked state");
        std::fs::remove_file(store.state_path()).expect("remove");
        std::fs::copy(&real, store.state_path()).expect("copy back");
        std::fs::set_permissions(store.state_path(), std::fs::Permissions::from_mode(0o640))
            .expect("chmod");
        assert!(store.load_state().is_err(), "a group-readable state");
    }

    #[test]
    fn the_lock_is_exclusive_per_instance() {
        let root = private_root();
        let keys = keys();
        let first = Store::open(root.path(), &keys, binding()).expect("open");
        assert!(Store::open(root.path(), &keys, binding()).is_err(), "a second holder");
        drop(first);
        Store::open(root.path(), &keys, binding()).expect("after release");
    }

    #[test]
    fn a_group_writable_directory_is_refused() {
        let root = private_root();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o770))
            .expect("chmod");
        assert!(Store::open(root.path(), &keys(), binding()).is_err());
    }

    #[test]
    fn the_next_index_is_past_state_journal_and_scan_and_skips_reused() {
        let mut state = state(&binding());
        state.issued_high_water = 3;
        state.scan_next_index = 5;
        state.reused_indices = vec![5, 6];
        let journal = vec![
            JournalRecord::IndexReserved { index: 2, purpose: "address".into() },
            JournalRecord::DepositPrepared {
                index: 4,
                amount: coins(1),
                value: coins(1),
                payer: "w".into(),
                owner_commitment: [0; 32],
                body_hash: [0; 32],
                message_hash: [0; 32],
                boc: vec![],
            },
        ];
        assert_eq!(next_issuable_index(&state, &journal).expect("next"), 7);
        state.scan_next_index = 0;
        state.reused_indices.clear();
        assert_eq!(next_issuable_index(&state, &journal).expect("next"), 5, "the journal wins");
        state.issued_high_water = u64::MAX;
        assert!(next_issuable_index(&state, &journal).is_err(), "exhausted");
    }

    #[test]
    fn a_write_past_the_limit_is_refused_and_the_old_file_stays_readable() {
        let root = private_root();
        let keys = keys();
        let store = Store::open(root.path(), &keys, binding()).expect("open").with_limit(2_000);
        let small = state(&binding());
        store.save_state(&small).expect("a small state fits");
        let mut large = small.clone();
        large.ledger.leaves = vec![[7; 32]; 200];
        match store.save_state(&large) {
            Ok(()) => panic!("a state past the limit was written"),
            Err(error) => assert!(error.to_string().contains("previous state is kept"), "{error}"),
        }
        assert_eq!(store.load_state().expect("the old state"), Some(small));

        let record = JournalRecord::DepositPrepared {
            index: 0,
            amount: coins(1),
            value: coins(1),
            payer: "w".into(),
            owner_commitment: [0; 32],
            body_hash: [0; 32],
            message_hash: [0; 32],
            boc: vec![0x5a; 300],
        };
        store.append_journal(0, &record).expect("the first record fits");
        store.append_journal(1, &record).expect("the second record fits");
        assert!(store.append_journal(2, &record).is_err(), "the third would cross the limit");
        assert_eq!(store.read_journal().expect("still readable").len(), 2);
    }

    #[test]
    fn another_pointer_naming_the_same_directory_is_found_and_garbage_fails_closed() {
        let root = private_root();
        assert_eq!(other_pointer_naming(root.path(), "dir-a", "main").expect("empty"), None);
        let pointer = |directory: &str| Pointer {
            schema: POINTER_SCHEMA.to_owned(),
            profile: state(&binding()).profile,
            binding: binding(),
            chain: chain(),
            directory: directory.to_owned(),
        };
        pointer("dir-a").save(&pointer_path(root.path(), "main").expect("path")).expect("save");
        pointer("dir-b").save(&pointer_path(root.path(), "other").expect("path")).expect("save");
        // Its own name is not another instance; another name on its directory is.
        assert_eq!(other_pointer_naming(root.path(), "dir-a", "main").expect("scan"), None);
        assert_eq!(
            other_pointer_naming(root.path(), "dir-a", "alias").expect("scan"),
            Some("main".to_owned())
        );
        assert_eq!(other_pointer_naming(root.path(), "dir-c", "main").expect("scan"), None);
        // A pointer that does not load stops the scan rather than being skipped.
        std::fs::write(root.path().join("broken.json"), b"{").expect("write");
        assert!(other_pointer_naming(root.path(), "dir-c", "main").is_err());
    }

    #[test]
    fn the_name_lock_is_exclusive() {
        let root = private_root();
        let first = NameLock::take(root.path(), "main").expect("take");
        assert!(NameLock::take(root.path(), "main").is_err(), "a second holder");
        NameLock::take(root.path(), "other").expect("another name");
        drop(first);
        NameLock::take(root.path(), "main").expect("after release");
    }

    #[test]
    fn the_pointer_name_is_restricted() {
        let root = private_root();
        assert!(pointer_path(root.path(), "main-1").is_ok());
        assert!(pointer_path(root.path(), "../x").is_err());
        assert!(pointer_path(root.path(), "").is_err());
    }
}
