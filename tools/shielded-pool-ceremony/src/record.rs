/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! What a ceremony leaves behind, on disk.
//!
//! A ceremony is a thing several people do on different machines over days,
//! so its state has to survive being copied, mailed, published and read back
//! by somebody who was not there. Three files:
//!
//! ```text
//!   key.bin            the proving key as it now stands
//!   contributions.bin  every published contribution, 672 bytes each, in order
//!   ceremony.json      what each step was, and the digests to compare
//! ```
//!
//! The division is deliberate. `contributions.bin` and `ceremony.json` are the
//! **record** -- small, publishable, and everything an auditor needs besides
//! the phase-1 slice this repository already commits. `key.bin` is the
//! **artifact**: it is what the next participant works on and what the final
//! verifying key is extracted from, and it is not evidence of anything by
//! itself.
//!
//! No intermediate key is kept. That is not a space saving, it is the shape of
//! the audit: [`crate::contribution::verify_chain`] reconstructs nothing and
//! needs nothing but the starting key, the record and the finished key, so
//! keeping the intermediates would create a second source of truth that
//! nobody checks.
//!
//! # What is deliberately absent
//!
//! Any participant's scalar. There is no field for it, no optional file, and
//! no debug mode that writes one. A ceremony directory can be published whole
//! the moment it exists, and that is the intended use.

use std::path::{Path, PathBuf};

use ark_bls12_381::Bls12_381;
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use crate::contribution::{Contribution, Transcript, CONTRIBUTION_BYTES};
use crate::error::{Error, Result};

pub const KEY_FILE: &str = "key.bin";
pub const CONTRIBUTIONS_FILE: &str = "contributions.bin";
pub const RECORD_FILE: &str = "ceremony.json";
/// The beacon output a ceremony was finalised with.
///
/// Stored so the directory audits on its own: recomputing the finalising step
/// needs the bytes, not their digest. It is public by definition, and an
/// auditor still has to compare `beacon_sha256` against whatever the beacon
/// actually published -- a copy in the directory proves the ceremony is
/// self-consistent, not that it used the beacon it said it would.
pub const BEACON_FILE: &str = "beacon.bin";

/// The protocol string, so a record from some other ceremony is refused rather
/// than half-understood.
pub const PROTOCOL: &str = "tos-shielded-pool-v1-phase2";

/// What one step was.
///
/// `Participant` carries no name. Attribution is a social artifact -- a signed
/// statement a contributor publishes elsewhere, naming the digests below --
/// and putting an unverified name in the record would make the record look
/// like it had checked one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Step {
    /// A scalar somebody drew and destroyed.
    Participant,
    /// A scalar determined by published bytes. The digest is of the beacon
    /// output itself, so an auditor can confirm they are recomputing from the
    /// same bytes before they start.
    Beacon { beacon_sha256: String },
}

/// One line of the record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// One-based, so it reads the way people count participants.
    pub index: usize,
    #[serde(flatten)]
    pub step: Step,
    /// SHA-256 of this contribution's 672 bytes.
    pub sha256: String,
    /// The transcript after absorbing it. This is what a participant
    /// publishes: it names their position in a way nobody can move.
    pub transcript_after: String,
}

/// The record a ceremony publishes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub protocol: String,
    /// Which published phase-1 ceremony this deployment inherits, and the
    /// slice it was taken from. Without these the starting key cannot be
    /// rebuilt, and an audit that cannot rebuild the starting key is an audit
    /// of whatever it was handed.
    pub phase1_transcript: String,
    pub phase1_slice_sha256: String,
    /// The circuit, measured rather than configured.
    pub constraints: usize,
    pub instance_variables: usize,
    /// SHA-256 of the starting key, which is a deterministic function of the
    /// two fields above plus the circuit -- so a mismatch here says the
    /// ceremony was begun over something else.
    pub starting_key_sha256: String,
    pub entries: Vec<Entry>,
    /// The key as it now stands.
    pub key_sha256: String,
    /// The transcript as it now stands, which is `entries.last()`'s
    /// `transcript_after`, or the opening digest when there are none.
    pub transcript: String,
}

impl Record {
    pub fn is_finished(&self) -> bool {
        matches!(self.entries.last().map(|entry| &entry.step), Some(Step::Beacon { .. }))
    }

    /// The position of a beacon step that is not the last one, if there is
    /// one.
    ///
    /// This is a worse state than an unfinished ceremony and reads exactly
    /// like it: `is_finished` is false either way. The difference is that a
    /// contribution *after* the beacon was drawn by someone who already knew
    /// the beacon's value, so the final `delta` no longer depends on anything
    /// nobody could predict -- which is the entire property a beacon supplies.
    /// A ceremony in this state has to be re-run, not finished.
    ///
    /// `phase2-contribute` refuses to produce it. A record can still be
    /// assembled by hand, so it is detected rather than assumed away.
    pub fn beacon_out_of_place(&self) -> Option<usize> {
        let last = self.entries.len().saturating_sub(1);
        self.entries
            .iter()
            .enumerate()
            .find(|(position, entry)| {
                *position != last && matches!(entry.step, Step::Beacon { .. })
            })
            .map(|(position, _)| position + 1)
    }
}

/// A ceremony directory.
pub struct Directory {
    path: PathBuf,
}

impl Directory {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn exists(&self) -> bool {
        self.file(RECORD_FILE).exists()
    }

    /// Creates the directory, refusing to write over a ceremony already in it.
    ///
    /// A ceremony that can be restarted in place is one whose participants
    /// cannot tell whether their contribution is still in the chain. Refusing
    /// is the whole behaviour.
    pub fn create(&self) -> Result<()> {
        if self.exists() {
            return Err(Error::Structure(format!(
                "{} already holds a ceremony; begin a new one somewhere else rather than \
                 overwriting a record somebody may already have contributed to",
                self.path.display()
            )));
        }
        std::fs::create_dir_all(&self.path)?;
        Ok(())
    }

    pub fn read_record(&self) -> Result<Record> {
        let record: Record = serde_json::from_slice(&std::fs::read(self.file(RECORD_FILE))?)?;
        if record.protocol != PROTOCOL {
            return Err(Error::Structure(format!(
                "this record is for {:?}, not {PROTOCOL:?}",
                record.protocol
            )));
        }
        Ok(record)
    }

    pub fn write_record(&self, record: &Record) -> Result<()> {
        let mut json = serde_json::to_vec_pretty(record)?;
        json.push(b'\n');
        write_atomically(&self.file(RECORD_FILE), &json)
    }

    pub fn read_key(&self) -> Result<ProvingKey<Bls12_381>> {
        let bytes = std::fs::read(self.file(KEY_FILE))?;
        let key = ProvingKey::<Bls12_381>::deserialize_compressed(&bytes[..])
            .map_err(|error| Error::Structure(format!("reading {KEY_FILE}: {error}")))?;
        let recorded = self.read_record()?.key_sha256;
        let actual = digest_of(&bytes);
        if actual != recorded {
            return Err(Error::Structure(format!(
                "{KEY_FILE} hashes to {actual} and the record says {recorded}; the two files do \
                 not describe the same ceremony"
            )));
        }
        Ok(key)
    }

    /// Writes the key and returns its digest.
    ///
    /// Deserialization is **checked** on the way out: arkworks' compressed
    /// form recovers a coordinate by solving the curve equation, so a key that
    /// serializes is not automatically a key that reads back the same. A
    /// ceremony that discovered this at the end would have to be run again.
    pub fn write_key(&self, key: &ProvingKey<Bls12_381>) -> Result<String> {
        let mut bytes = Vec::new();
        key.serialize_compressed(&mut bytes)
            .map_err(|error| Error::Structure(format!("writing {KEY_FILE}: {error}")))?;
        let read_back = ProvingKey::<Bls12_381>::deserialize_compressed(&bytes[..])
            .map_err(|error| Error::Structure(format!("the key did not read back: {error}")))?;
        if &read_back != key {
            return Err(Error::Structure(
                "the key did not survive its own encoding, so the ceremony cannot be handed on"
                    .into(),
            ));
        }
        write_atomically(&self.file(KEY_FILE), &bytes)?;
        Ok(digest_of(&bytes))
    }

    pub fn read_beacon(&self) -> Result<Vec<u8>> {
        Ok(std::fs::read(self.file(BEACON_FILE))?)
    }

    pub fn write_beacon(&self, beacon: &[u8]) -> Result<()> {
        write_atomically(&self.file(BEACON_FILE), beacon)
    }

    pub fn read_contributions(&self) -> Result<Vec<Contribution>> {
        let path = self.file(CONTRIBUTIONS_FILE);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let bytes = std::fs::read(path)?;
        if bytes.len() % CONTRIBUTION_BYTES != 0 {
            return Err(Error::Structure(format!(
                "{CONTRIBUTIONS_FILE} is {} bytes, which is not a whole number of {CONTRIBUTION_BYTES}-byte contributions",
                bytes.len()
            )));
        }
        bytes.chunks_exact(CONTRIBUTION_BYTES).map(Contribution::from_bytes).collect()
    }

    pub fn write_contributions(&self, contributions: &[Contribution]) -> Result<()> {
        let mut bytes = Vec::with_capacity(contributions.len() * CONTRIBUTION_BYTES);
        for contribution in contributions {
            bytes.extend_from_slice(&contribution.to_bytes());
        }
        write_atomically(&self.file(CONTRIBUTIONS_FILE), &bytes)
    }
}

/// Written to a neighbouring temporary file and renamed.
///
/// A ceremony directory is copied between machines while it is being worked
/// on. A half-written `key.bin` from an interrupted run is indistinguishable
/// from a corrupted one, and the participant who finds it has no way back.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("partial");
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(&temporary, path)?;
    Ok(())
}

/// A digest field from a record, held to being one before anything indexes it.
///
/// Every `[..16]` in a message below used to run straight off an unchecked
/// string: a record carrying `"x"` panicked instead of refusing, and a
/// multi-byte character could land a byte index inside a UTF-8 code point.
/// A malformed directory has to produce a refusal with a reason, not a crash
/// -- a panic tells whoever is auditing nothing about what was wrong with the
/// thing they were handed.
pub fn checked_digest<'a>(value: &'a str, field: &str) -> Result<&'a str> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Structure(format!(
            "{field} is not a SHA-256 digest: {} characters, {:?}",
            value.len(),
            value.chars().take(24).collect::<String>()
        )));
    }
    Ok(value)
}

/// The first 16 characters of a digest, for a message, after it has been
/// checked to be one.
pub fn short<'a>(value: &'a str, field: &str) -> Result<&'a str> {
    Ok(&checked_digest(value, field)?[..16])
}

pub fn digest_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn digest_of_transcript(transcript: &Transcript) -> String {
    hex::encode(transcript.digest())
}

/// A key's digest, computed the way [`Directory::write_key`] computes it.
///
/// Here rather than in each caller because the digest is only meaningful if
/// the encoding is the same one the record was written from, and two places
/// that both "just serialize it" are two chances to differ.
pub fn key_digest(key: &ProvingKey<Bls12_381>) -> Result<String> {
    let mut bytes = Vec::new();
    key.serialize_compressed(&mut bytes)
        .map_err(|error| Error::Structure(format!("encoding a key: {error}")))?;
    Ok(digest_of(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_round_trips_through_json() {
        let record = Record {
            protocol: PROTOCOL.into(),
            phase1_transcript: "zcash".into(),
            phase1_slice_sha256: "00".repeat(32),
            constraints: 18_107,
            instance_variables: 19,
            starting_key_sha256: "11".repeat(32),
            entries: vec![
                Entry {
                    index: 1,
                    step: Step::Participant,
                    sha256: "22".repeat(32),
                    transcript_after: "33".repeat(32),
                },
                Entry {
                    index: 2,
                    step: Step::Beacon { beacon_sha256: "44".repeat(32) },
                    sha256: "55".repeat(32),
                    transcript_after: "66".repeat(32),
                },
            ],
            key_sha256: "77".repeat(32),
            transcript: "66".repeat(32),
        };
        let json = serde_json::to_vec(&record).expect("serialize");
        let read: Record = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(read, record);
        assert!(read.is_finished(), "a record ending in a beacon is finished");
    }

    #[test]
    fn a_record_that_has_not_reached_its_beacon_is_not_finished() {
        let mut record = Record {
            protocol: PROTOCOL.into(),
            phase1_transcript: "zcash".into(),
            phase1_slice_sha256: "00".repeat(32),
            constraints: 1,
            instance_variables: 1,
            starting_key_sha256: "11".repeat(32),
            entries: Vec::new(),
            key_sha256: "77".repeat(32),
            transcript: "88".repeat(32),
        };
        assert!(!record.is_finished(), "a ceremony with no steps is not finished");
        record.entries.push(Entry {
            index: 1,
            step: Step::Participant,
            sha256: "22".repeat(32),
            transcript_after: "33".repeat(32),
        });
        assert!(!record.is_finished(), "a ceremony with no beacon is not finished");
    }

    /// A beacon with contributions after it is not an unfinished ceremony,
    /// it is a broken one: whoever contributed next already knew the value the
    /// beacon was supposed to supply.
    #[test]
    fn a_beacon_that_is_not_last_is_spotted() {
        let mut record = Record {
            protocol: PROTOCOL.into(),
            phase1_transcript: "zcash".into(),
            phase1_slice_sha256: "00".repeat(32),
            constraints: 1,
            instance_variables: 1,
            starting_key_sha256: "11".repeat(32),
            entries: vec![
                Entry {
                    index: 1,
                    step: Step::Beacon { beacon_sha256: "aa".repeat(32) },
                    sha256: "22".repeat(32),
                    transcript_after: "33".repeat(32),
                },
                Entry {
                    index: 2,
                    step: Step::Participant,
                    sha256: "44".repeat(32),
                    transcript_after: "55".repeat(32),
                },
            ],
            key_sha256: "77".repeat(32),
            transcript: "55".repeat(32),
        };
        assert_eq!(record.beacon_out_of_place(), Some(1));
        assert!(!record.is_finished(), "a trailing participant is not a finished ceremony");

        // The same steps the right way round are fine, and `is_finished`
        // alone cannot tell the two apart -- which is why this exists.
        record.entries.swap(0, 1);
        record.entries[0].index = 1;
        record.entries[1].index = 2;
        assert_eq!(record.beacon_out_of_place(), None);
        assert!(record.is_finished());
    }

    /// A ceremony with no beacon at all has none out of place either.
    #[test]
    fn no_beacon_is_not_a_misplaced_beacon() {
        let record = Record {
            protocol: PROTOCOL.into(),
            phase1_transcript: "zcash".into(),
            phase1_slice_sha256: "00".repeat(32),
            constraints: 1,
            instance_variables: 1,
            starting_key_sha256: "11".repeat(32),
            entries: vec![Entry {
                index: 1,
                step: Step::Participant,
                sha256: "22".repeat(32),
                transcript_after: "33".repeat(32),
            }],
            key_sha256: "77".repeat(32),
            transcript: "33".repeat(32),
        };
        assert_eq!(record.beacon_out_of_place(), None);
        assert!(!record.is_finished());
    }

    /// A scratch directory that cleans itself up.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "phase2-record-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn a_record() -> Record {
        Record {
            protocol: PROTOCOL.into(),
            phase1_transcript: "zcash".into(),
            phase1_slice_sha256: "00".repeat(32),
            constraints: 18_107,
            instance_variables: 19,
            starting_key_sha256: "11".repeat(32),
            entries: Vec::new(),
            key_sha256: "77".repeat(32),
            transcript: "88".repeat(32),
        }
    }

    /// A ceremony that can be restarted in place is one whose participants
    /// cannot tell whether their contribution is still in the chain.
    #[test]
    fn beginning_over_an_existing_ceremony_is_refused() {
        let scratch = Scratch::new("occupied");
        let directory = Directory::at(&scratch.0);
        directory.create().expect("the first create");
        directory.write_record(&a_record()).expect("a record");

        let error = directory.create().expect_err("a second ceremony was allowed in place");
        assert!(format!("{error}").contains("already holds a ceremony"), "{error}");
    }

    /// An empty directory is not an occupied one, so a fresh ceremony in a
    /// path that happens to exist is fine.
    #[test]
    fn an_empty_directory_is_not_a_ceremony() {
        let scratch = Scratch::new("empty");
        std::fs::create_dir_all(&scratch.0).expect("mkdir");
        Directory::at(&scratch.0).create().expect("an empty directory should be usable");
    }

    /// A structurally valid key. Meaningless -- every point is a generator --
    /// but it serializes and reads back, which is exactly what the digest
    /// check needs in order to be the thing that objects.
    fn a_key() -> ProvingKey<Bls12_381> {
        use ark_ec::AffineRepr;
        let g1 = ark_bls12_381::G1Affine::generator();
        let g2 = ark_bls12_381::G2Affine::generator();
        ProvingKey {
            vk: ark_groth16::VerifyingKey {
                alpha_g1: g1,
                beta_g2: g2,
                gamma_g2: g2,
                delta_g2: g2,
                gamma_abc_g1: vec![g1],
            },
            beta_g1: g1,
            delta_g1: g1,
            a_query: vec![g1],
            b_g1_query: vec![g1],
            b_g2_query: vec![g2],
            h_query: vec![g1],
            l_query: vec![g1],
        }
    }

    /// The record and the key are two files that travel together and can be
    /// separated by a copy that went wrong. A key whose digest is not the one
    /// the record states is refused rather than used.
    ///
    /// The key here is **valid and reads back**: only the digest disagrees.
    /// An earlier version wrote nine bytes of text, which fails in
    /// `deserialize_compressed` long before any digest is compared -- so the
    /// digest check was untested, and removing it left this green. The
    /// mutation battery is what found that.
    #[test]
    fn a_key_that_does_not_match_its_record_is_refused() {
        let scratch = Scratch::new("mismatch");
        let directory = Directory::at(&scratch.0);
        directory.create().expect("create");

        let digest = directory.write_key(&a_key()).expect("a key on disk");
        let mut record = a_record();
        record.key_sha256 = digest;
        directory.write_record(&record).expect("a record");

        // The baseline: with the digest agreeing, this reads. Without it the
        // test below could pass for a `read_key` that refuses everything.
        directory.read_key().expect("a key that matches its record must read");

        record.key_sha256 = "99".repeat(32);
        directory.write_record(&record).expect("a record");
        let error = directory.read_key().expect_err("a mismatched key was accepted");
        assert!(
            format!("{error}").contains("do not describe the same ceremony"),
            "refused, but not by the digest check: {error}"
        );
    }

    #[test]
    fn a_contributions_file_of_the_wrong_length_is_refused() {
        let scratch = Scratch::new("ragged");
        let directory = Directory::at(&scratch.0);
        directory.create().expect("create");
        std::fs::write(scratch.0.join(CONTRIBUTIONS_FILE), vec![0u8; CONTRIBUTION_BYTES + 5])
            .expect("write");

        let error = directory.read_contributions().expect_err("a ragged file was accepted");
        assert!(format!("{error}").contains("not a whole number"), "{error}");
    }

    /// A directory with no contributions file yet is a ceremony nobody has
    /// contributed to, not a broken one.
    #[test]
    fn a_missing_contributions_file_reads_as_none() {
        let scratch = Scratch::new("none-yet");
        let directory = Directory::at(&scratch.0);
        directory.create().expect("create");
        assert!(directory.read_contributions().expect("read").is_empty());
    }

    /// A record from some other protocol is refused rather than read as far as
    /// its fields happen to line up.
    #[test]
    fn a_record_for_another_protocol_is_refused() {
        let scratch = Scratch::new("foreign");
        let directory = Directory::at(&scratch.0);
        directory.create().expect("create");
        let mut record = a_record();
        record.protocol = "some-other-ceremony-v9".into();
        directory.write_record(&record).expect("write");

        let error = directory.read_record().expect_err("a foreign record was accepted");
        assert!(format!("{error}").contains("some-other-ceremony-v9"), "{error}");
    }

    /// The `kind` tag is what tells an auditor which steps they must recompute
    /// from published bytes and which they can only check pairings on.
    #[test]
    fn the_step_kind_is_in_the_json() {
        let json = serde_json::to_string(&Entry {
            index: 3,
            step: Step::Beacon { beacon_sha256: "ab".repeat(32) },
            sha256: "cd".repeat(32),
            transcript_after: "ef".repeat(32),
        })
        .expect("serialize");
        assert!(json.contains("\"kind\":\"beacon\""), "{json}");
        assert!(json.contains("beacon_sha256"), "{json}");
    }
}
