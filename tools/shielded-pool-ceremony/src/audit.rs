/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The audit `phase2-verify` runs, and the finalising step `phase2-finalise`
//! takes, as functions a second program can call.
//!
//! A genesis that carries a ceremony's verifying key has to know that key is
//! the one an audited, finished ceremony produced -- not merely that somebody
//! typed a transcript digest beside it. Re-implementing the audit there would
//! be a second audit to keep in step with this one, so the audit lives here
//! and both callers use it.
//!
//! [`Audited`] can only be produced by [`audit`]. Its fields are private and
//! it has no other constructor, so a value of that type is evidence that the
//! checks below ran against the directory it names.

use ark_bls12_381::Bls12_381;
use ark_groth16::ProvingKey;
use shielded_pool_circuit::groth16;

use crate::contribution::{
    finalise, verify_beacon_step, verify_chain, Transcript, MINIMUM_BEACON_BYTES,
};
use crate::entropy::{Entropy, OperatingSystem};
use crate::error::{Error, Result};
use crate::record::{
    checked_digest, digest_of, digest_of_transcript, key_digest, short, Directory, Entry, Record,
    Step,
};
use crate::{committed, shape, slice};

/// The key every ceremony over this circuit starts from, rebuilt from the
/// slice this checkout commits.
///
/// Rebuilt, never read: an audit that took its starting key from the ceremony
/// directory would be an audit of whatever it was handed. Fields are private
/// so the only way to hold one is [`StartingKey::rebuild`].
pub struct StartingKey {
    key: ProvingKey<Bls12_381>,
    provenance: slice::Provenance,
    digest: String,
}

impl StartingKey {
    /// Parse, verify and transform the committed slice, then set up the
    /// circuit over it. Minutes, on purpose.
    pub fn rebuild() -> Result<Self> {
        let mut seed = [0u8; 32];
        OperatingSystem.fill(&mut seed)?;
        let (key, provenance) = committed::starting_key(&committed::artifacts_directory(), seed)?;
        let digest = key_digest(&key)?;
        Ok(Self { key, provenance, digest })
    }

    pub fn key(&self) -> &ProvingKey<Bls12_381> {
        &self.key
    }

    pub fn provenance(&self) -> &slice::Provenance {
        &self.provenance
    }

    /// SHA-256 of the key's compressed encoding, as a record states it.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// What a ceremony directory was found to be by [`audit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Audited {
    record: Record,
    verifying_key: Vec<u8>,
    ic_count: usize,
    vk_sha256: String,
    beacon_sha256: Option<String>,
}

impl Audited {
    /// The record, every field of which the audit held to the contributions,
    /// the rebuilt starting key and the measured circuit.
    pub fn record(&self) -> &Record {
        &self.record
    }

    /// The canonical verifying key extracted from the audited final key.
    pub fn verifying_key(&self) -> &[u8] {
        &self.verifying_key
    }

    pub fn ic_count(&self) -> usize {
        self.ic_count
    }

    /// SHA-256 of [`Audited::verifying_key`].
    pub fn vk_sha256(&self) -> &str {
        &self.vk_sha256
    }

    /// The transcript the contributions actually produce; the audit refused
    /// a record whose summary said anything else.
    pub fn transcript(&self) -> &str {
        &self.record.transcript
    }

    /// Closed by a beacon that the audit recomputed, as the last step.
    pub fn is_finished(&self) -> bool {
        self.record.is_finished() && self.beacon_sha256.is_some()
    }

    /// The digest of the beacon bytes the finalising step was recomputed from.
    pub fn beacon_sha256(&self) -> Option<&str> {
        self.beacon_sha256.as_deref()
    }

    pub fn steps(&self) -> usize {
        self.record.entries.len()
    }
}

/// The checks that need nothing but the directory, so a malformed ceremony is
/// refused before minutes are spent rebuilding a starting key.
pub fn preflight(directory: &Directory) -> Result<()> {
    read_checked(directory).map(|_| ())
}

type Read = (Record, ProvingKey<Bls12_381>, Vec<crate::contribution::Contribution>);

fn read_checked(directory: &Directory) -> Result<Read> {
    let record = directory.read_record()?;
    let key = directory.read_key()?;
    let contributions = directory.read_contributions()?;
    if contributions.len() != record.entries.len() {
        return Err(Error::Structure(format!(
            "the record lists {} steps and the file holds {} contributions",
            record.entries.len(),
            contributions.len()
        )));
    }
    if contributions.is_empty() {
        return Err(Error::Structure(
            "this ceremony has no contributions; its delta is one and known to everyone".into(),
        ));
    }
    if let Some(position) = record.beacon_out_of_place() {
        return Err(Error::Structure(format!(
            "step {position} is the beacon and it is not the last one. Whoever contributed after \
             it already knew the value the beacon was there to supply, so the final delta \
             depends on nothing unpredictable. This ceremony has to be run again, not finished"
        )));
    }

    // Every digest in the record is held to being a digest before any of the
    // messages below index into it.
    for (field, value) in [
        ("phase1_slice_sha256", &record.phase1_slice_sha256),
        ("starting_key_sha256", &record.starting_key_sha256),
        ("key_sha256", &record.key_sha256),
        ("transcript", &record.transcript),
    ] {
        checked_digest(value, field)?;
    }
    for entry in &record.entries {
        checked_digest(&entry.sha256, "an entry's sha256")?;
        checked_digest(&entry.transcript_after, "an entry's transcript_after")?;
        if let Step::Beacon { beacon_sha256 } = &entry.step {
            checked_digest(beacon_sha256, "a beacon's sha256")?;
        }
    }
    Ok((record, key, contributions))
}

/// Everything `phase2-verify` checks, against a starting key rebuilt by the
/// caller.
///
/// An unfinished ceremony audits -- its chain is sound -- and says so through
/// [`Audited::is_finished`]; whether that is acceptable is the caller's
/// decision, and a genesis refuses it.
pub fn audit(directory: &Directory, start: &StartingKey) -> Result<Audited> {
    let (record, key, contributions) = read_checked(directory)?;

    // --- the starting key, rebuilt not read -------------------------------
    let initial = start.key();
    let provenance = start.provenance();
    if provenance.slice_sha256 != record.phase1_slice_sha256 {
        return Err(Error::Structure(format!(
            "this checkout holds the {} slice {} and the ceremony was begun over {}",
            provenance.transcript,
            short(&provenance.slice_sha256, "the committed slice")?,
            &record.phase1_slice_sha256[..16]
        )));
    }
    if start.digest() != record.starting_key_sha256 {
        return Err(Error::Structure(format!(
            "the starting key this checkout builds is {} and the record says {}",
            short(start.digest(), "the rebuilt key")?,
            short(&record.starting_key_sha256, "starting_key_sha256")?
        )));
    }

    // The record's descriptive fields, held against what was reconstructed
    // rather than printed as facts.
    //
    // The digests above already bind the real slice and the real circuit, so
    // a record that lies here cannot substitute a different circuit -- but it
    // can put a false ceremony name and a false constraint count in front of
    // whoever reads the audit, and an audit that prints unchecked strings in
    // its own voice is the wrong place to learn that.
    let measured = shape(committed::the_circuit()?)?;
    if record.phase1_transcript != provenance.transcript {
        return Err(Error::Structure(format!(
            "the record says this ceremony inherits {:?} and the slice it was begun over is \
             from {:?}",
            record.phase1_transcript, provenance.transcript
        )));
    }
    if record.constraints != measured.constraints
        || record.instance_variables != measured.instance_variables
    {
        return Err(Error::Structure(format!(
            "the record says {} constraints and {} instance variables; this circuit has {} and {}",
            record.constraints,
            record.instance_variables,
            measured.constraints,
            measured.instance_variables
        )));
    }

    // --- the chain --------------------------------------------------------
    verify_chain(initial, &key, &contributions, &mut OperatingSystem)?;

    // --- the record agrees with the contributions -------------------------
    let mut transcript = Transcript::begin(initial)?;
    let mut beacon_sha256 = None;
    for (position, (entry, contribution)) in record.entries.iter().zip(&contributions).enumerate() {
        if entry.index != position + 1 {
            return Err(Error::Structure(format!(
                "record entry {} is numbered {}",
                position + 1,
                entry.index
            )));
        }
        if entry.sha256 != digest_of(&contribution.to_bytes()) {
            return Err(Error::Structure(format!(
                "step {}'s digest does not match the contribution beside it",
                entry.index
            )));
        }

        // The beacon step, recomputed from the published bytes and the
        // previous step's published delta. No intermediate key is involved --
        // a ceremony keeps none, so an audit that needed one would be an audit
        // nobody could repeat.
        if let Step::Beacon { beacon_sha256: recorded } = &entry.step {
            let beacon = directory.read_beacon()?;
            let actual = digest_of(&beacon);
            if &actual != recorded {
                return Err(Error::Structure(format!(
                    "the stored beacon hashes to {} and the record says {recorded}",
                    &actual[..16]
                )));
            }
            let (previous_g1, previous_g2) = match position.checked_sub(1) {
                Some(earlier) => {
                    let earlier = contributions.get(earlier).ok_or_else(|| {
                        Error::Structure("the step before the beacon is missing".into())
                    })?;
                    (earlier.delta_g1, earlier.delta_g2)
                }
                None => (initial.delta_g1, initial.vk.delta_g2),
            };
            verify_beacon_step(previous_g1, previous_g2, &transcript, &beacon, contribution)?;
            beacon_sha256 = Some(actual);
        }

        transcript = transcript.extend(contribution);
        if digest_of_transcript(&transcript) != entry.transcript_after {
            return Err(Error::Structure(format!(
                "step {}'s transcript is not the one the record states, so a participant's \
                 published position does not match this record",
                entry.index
            )));
        }
    }

    // The summary the record publishes has to be the transcript the chain
    // actually produced. Every entry's `transcript_after` was checked above,
    // but a record could still carry a summary digest belonging to nothing,
    // and the summary is what a reader quotes.
    let ending = digest_of_transcript(&transcript);
    if ending != record.transcript {
        return Err(Error::Structure(format!(
            "the chain ends at transcript {} and the record summarises it as {}",
            short(&ending, "the computed transcript")?,
            short(&record.transcript, "the record's transcript")?
        )));
    }

    // --- the bytes --------------------------------------------------------
    let encoded = groth16::canonical_verifying_key(&key.vk)
        .map_err(|error| Error::Structure(format!("encoding the verifying key: {error}")))?;
    let vk_sha256 = digest_of(&encoded.bytes);
    Ok(Audited {
        record,
        verifying_key: encoded.bytes,
        ic_count: encoded.ic_count,
        vk_sha256,
        beacon_sha256,
    })
}

/// Closes a ceremony with a public random beacon, after auditing what it is
/// closing. What `phase2-finalise` does, returning the record it wrote.
///
/// Refuses a beacon shorter than [`MINIMUM_BEACON_BYTES`], a ceremony already
/// closed or broken by a misplaced beacon, one nobody has contributed to, and
/// one whose chain does not audit against the rebuilt starting key.
pub fn close(directory: &Directory, start: &StartingKey, beacon: &[u8]) -> Result<Record> {
    if beacon.len() < MINIMUM_BEACON_BYTES {
        return Err(Error::Structure(format!(
            "the beacon output is {} bytes; {MINIMUM_BEACON_BYTES} is the minimum, because a \
             shorter one can be ground out in advance",
            beacon.len()
        )));
    }

    let mut record = directory.read_record()?;
    if let Some(position) = record.beacon_out_of_place() {
        return Err(Error::Structure(format!(
            "step {position} is the beacon and it is not the last one; this ceremony is already \
             broken and adding to it cannot repair it"
        )));
    }
    if record.is_finished() {
        return Err(Error::Structure(
            "this ceremony has already been finalised; finalising twice would replace the \
             beacon everyone contributed under"
                .into(),
        ));
    }
    if record.entries.is_empty() {
        return Err(Error::Structure(
            "no participant has contributed, so finalising would produce a key whose delta is a \
             hash of public bytes -- forgeable by anyone who can read the beacon"
                .into(),
        ));
    }
    let mut key = directory.read_key()?;
    let mut contributions = directory.read_contributions()?;

    // --- audit before closing --------------------------------------------
    let initial = start.key();
    if start.provenance().slice_sha256 != record.phase1_slice_sha256
        || start.digest() != record.starting_key_sha256
    {
        return Err(Error::Structure(
            "this checkout does not rebuild the key this ceremony was begun over".into(),
        ));
    }
    verify_chain(initial, &key, &contributions, &mut OperatingSystem)?;

    let mut transcript = Transcript::begin(initial)?;
    for contribution in &contributions {
        transcript = transcript.extend(contribution);
    }
    if digest_of_transcript(&transcript) != record.transcript {
        return Err(Error::Structure(
            "the transcript the contributions produce is not the one the record states".into(),
        ));
    }

    // --- close it ---------------------------------------------------------
    let previous_g1 = key.delta_g1;
    let previous_g2 = key.vk.delta_g2;
    let ending = finalise(&mut key, &transcript, beacon)?;

    // Recomputed and compared, here as well as in the audit: this is the one
    // place the beacon's bytes and the ceremony meet, and a step that is not
    // the one those bytes determine should never reach the directory.
    verify_beacon_step(previous_g1, previous_g2, &transcript, beacon, &ending)?;
    transcript = transcript.extend(&ending);

    let index = contributions.len().checked_add(1).ok_or_else(|| {
        Error::Structure("the step count does not fit in this machine's word".into())
    })?;
    let contribution_sha256 = digest_of(&ending.to_bytes());
    let beacon_sha256 = digest_of(beacon);
    contributions.push(ending);

    let key_sha256 = directory.write_key(&key)?;
    directory.write_contributions(&contributions)?;
    directory.write_beacon(beacon)?;
    record.entries.push(Entry {
        index,
        step: Step::Beacon { beacon_sha256 },
        sha256: contribution_sha256,
        transcript_after: digest_of_transcript(&transcript),
    });
    record.key_sha256 = key_sha256;
    record.transcript = digest_of_transcript(&transcript);
    directory.write_record(&record)?;
    Ok(record)
}
