/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Which phase-1 ceremony, and where in its file this circuit's parameters
//! are.
//!
//! Two published BLS12-381 powers-of-tau ceremonies are big enough for this
//! circuit, and the choice between them is a **custody** decision rather than
//! a technical one: whichever is chosen, the deployment inherits that
//! ceremony's participants and nothing else. So the transcript is a described
//! thing with its provenance attached, not a constant somebody once typed.
//!
//! Both store the same five sections in the same order and the same
//! uncompressed encoding. They differ in where the accumulator sits:
//!
//! * Filecoin publishes a **challenge file** -- a 64-byte digest chaining it
//!   to the previous entry, then one accumulator;
//! * Zcash publishes the **whole transcript** -- 89 records of (accumulator,
//!   public key), so the final accumulator is the last record's.
//!
//! Either way a degree-2^15 slice is a prefix of *every section* rather than
//! a prefix of the file, because the sections store their powers in ascending
//! order. Five ranges, about eighteen megabytes.
//!
//! Getting an offset wrong is the worst error available here: the bytes would
//! parse, the points would be on the curve and in the subgroup, and
//! verification would fail with nothing to say about why. Two independent
//! facts guard it, per transcript.
//!
//! **The total.** Each layout below implies an exact file size and each host
//! publishes one, and they agree to the byte. That pins the element counts,
//! the uncompressed point widths, and the framing -- the 64-byte prefix in
//! one case, the 1,152-byte public keys in the other.
//!
//! **The order.** A total is the same whatever order the sections are in, so
//! it pins nothing about which comes first. The order is the one
//! `Accumulator::serialize` writes; what actually catches an order mistake is
//! `verify`, because sections read in the wrong order are not powers of the
//! same tau and no pairing check holds.

use crate::error::{Error, Result};

/// An uncompressed G1 point in the IETF encoding: big-endian x then y.
pub const G1_UNCOMPRESSED: u64 = 96;
/// An uncompressed G2 point: the two Fp2 coordinates, c1 before c0.
pub const G2_UNCOMPRESSED: u64 = 192;

/// A published phase-1 ceremony, and how to find an accumulator in its file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transcript {
    /// What to call it on a command line and in a provenance record.
    pub name: &'static str,
    pub url: &'static str,
    /// The exponent the ceremony was run to. Ours needs 2^15; both of these
    /// are far larger, and the surplus costs nothing because a slice is a
    /// prefix.
    pub power: u32,
    /// Where the accumulator this slice comes from begins.
    pub accumulator_offset: u64,
    /// What the whole file must measure. If it does not, every offset here is
    /// for a different file and nothing below means anything.
    pub file_bytes: u64,
    /// Whether the file carries a 64-byte digest before its first accumulator.
    /// Filecoin's challenge file does; Zcash's transcript does not, and its
    /// records carry a 1,152-byte public key *after* each accumulator instead.
    pub head_digest: bool,
    /// What a deployment is actually inheriting, in one line, because this is
    /// the sentence section 20 has to contain.
    pub custody: &'static str,
    /// How the host identifies the file, for the provenance record.
    pub published_checksums: &'static str,
}

/// The Zcash Sapling powers of tau, 2017-2018.
///
/// The default. It is the ceremony every later BLS12-381 one references, it is
/// served by an archive that answers a range request in seconds rather than
/// twenty-five minutes, and its contribution chain is **auditable from
/// published material** -- two links of it were re-computed against PGP
/// signatures from 2017 before this was made the default.
///
/// It is 2^21, which is sixty-four times this circuit's domain.
pub const ZCASH: Transcript = Transcript {
    name: "zcash",
    url: "https://archive.org/download/transcript_201804/transcript",
    power: 21,
    // The last of 89 records. Each record is an uncompressed accumulator
    // followed by a 1,152-byte public key, and there is no digest at the head
    // of the file -- `ebfull/powersoftau`'s own verifier keeps the initial
    // all-generators accumulator in memory rather than storing it.
    accumulator_offset: 106_300_550_400,
    file_bytes: 107_508_511_200,
    head_digest: false,
    custody: "87 attested human contributions and a public random beacon, out of an 89-round \
              chain; one round carries no published attestation and its position is undetermined",
    published_checksums: "archive.org md5 7890b89f08397269f331ff34ed7a539d, \
                          sha1 da57abe02c34991b5dac659b53a9d77c61565d6d",
};

/// Filecoin's powers of tau, completed end of 2019.
///
/// A separate ceremony, not a continuation of Zcash's -- Zcash's 2^21 was too
/// small for Filecoin's hundred-million-gate circuits, so they ran their own.
/// Kept as an alternative: two independent sources are a hedge on
/// availability, and one of them has already lost its original host.
///
/// Its only advantage over Zcash's is headroom this circuit does not need.
pub const FILECOIN: Transcript = Transcript {
    name: "filecoin",
    url: "https://trusted-setup.filecoin.io/phase1/challenge_19",
    power: 27,
    // A challenge file: the 64-byte digest chaining it to the previous entry,
    // then one accumulator.
    accumulator_offset: 64,
    file_bytes: 77_309_411_488,
    head_digest: true,
    custody: "Filecoin's own 2019 ceremony; its contribution chain has not been re-verified here",
    published_checksums: "the 64-byte BLAKE2b digest at offset 0, recorded per fetch",
};

/// The ceremony a deployment inherits unless told otherwise.
pub const DEFAULT: &Transcript = &ZCASH;

pub const ALL: [&Transcript; 2] = [&ZCASH, &FILECOIN];

pub fn by_name(name: &str) -> Result<&'static Transcript> {
    ALL.iter().copied().find(|transcript| transcript.name == name).ok_or_else(|| {
        Error::Layout(format!(
            "no transcript called {name}; known: {}",
            ALL.iter().map(|t| t.name).collect::<Vec<_>>().join(", ")
        ))
    })
}

/// The bytes one accumulator occupies at `power`, section by section in the
/// order they are written.
fn sections(power: u32) -> [(&'static str, u64, u64); 5] {
    // A QAP of degree n needs tau^0..tau^(2n-2) in G1 -- the numerator of the
    // quotient polynomial reaches degree 2n-2 -- and only tau^0..tau^(n-1) in
    // G2. That asymmetry is why the first section is twice the length of the
    // others, and why the h query is buildable at all.
    let n: u64 = 1u64 << power;
    [
        ("tau_g1", 2 * n - 1, G1_UNCOMPRESSED),
        ("tau_g2", n, G2_UNCOMPRESSED),
        ("alpha_tau_g1", n, G1_UNCOMPRESSED),
        ("beta_tau_g1", n, G1_UNCOMPRESSED),
        ("beta_g2", 1, G2_UNCOMPRESSED),
    ]
}

/// One accumulator's size at `power`.
pub fn accumulator_size(power: u32) -> u64 {
    sections(power).iter().map(|(_, count, width)| count * width).sum()
}

/// The public key `ebfull/powersoftau` writes after each accumulator in a
/// transcript: three ratios, each two G1 and one G2, uncompressed.
pub const PUBLIC_KEY_BYTES: u64 = 3 * (G2_UNCOMPRESSED + 2 * G1_UNCOMPRESSED);

/// One contiguous run of bytes to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub name: &'static str,
    pub offset: u64,
    pub length: u64,
    pub points: u64,
    pub point_bytes: u64,
}

impl Range {
    pub fn end(&self) -> u64 {
        self.offset + self.length
    }
}

/// The five ranges holding a degree-`2^wanted` prefix of `transcript`'s
/// accumulator.
///
/// The sections sit at offsets fixed by the *ceremony's* power, not by ours,
/// which is the whole reason this cannot be done by reading the first N bytes.
pub fn slice_ranges(transcript: &Transcript, wanted: u32) -> Result<Vec<Range>> {
    if wanted > transcript.power {
        return Err(Error::Layout(format!(
            "this circuit needs a domain of 2^{wanted} and {} was run to 2^{}; a larger circuit \
             needs a larger ceremony, not a different slice",
            transcript.name, transcript.power
        )));
    }
    let want: u64 = 1u64 << wanted;
    let mut ranges = Vec::with_capacity(5);
    let mut offset = transcript.accumulator_offset;
    for (name, count, width) in sections(transcript.power) {
        let take = match name {
            "tau_g1" => 2 * want - 1,
            "beta_g2" => 1,
            _ => want,
        };
        if take > count {
            return Err(Error::Layout(format!(
                "{name}: the slice wants {take} elements and the transcript has {count}"
            )));
        }
        ranges.push(Range { name, offset, length: take * width, points: take, point_bytes: width });
        offset += count * width;
    }
    Ok(ranges)
}

/// What a slice at `wanted` occupies once fetched: the ranges end to end, with
/// nothing added, so the file stays a copy of parts of the transcript rather
/// than a re-encoding of them.
pub fn slice_size(transcript: &Transcript, wanted: u32) -> Result<u64> {
    Ok(slice_ranges(transcript, wanted)?.iter().map(|range| range.length).sum())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each layout implies a file size and each host publishes one. This is
    /// the check that says the two describe the same object -- and it is
    /// computed from the structure rather than restated, so a wrong structure
    /// cannot agree with itself.
    #[test]
    fn each_layout_reproduces_the_published_file_size() {
        // Filecoin: a challenge file is a 64-byte digest then one accumulator.
        assert_eq!(
            64 + accumulator_size(FILECOIN.power),
            FILECOIN.file_bytes,
            "the Filecoin challenge layout no longer produces the size it is published with"
        );
        assert_eq!(FILECOIN.accumulator_offset, 64);

        // Zcash: 89 records of accumulator then public key, no head digest.
        let record = accumulator_size(ZCASH.power) + PUBLIC_KEY_BYTES;
        assert_eq!(
            89 * record,
            ZCASH.file_bytes,
            "the Zcash transcript layout no longer produces the size it is published with"
        );
        assert_eq!(
            ZCASH.accumulator_offset,
            88 * record,
            "the final accumulator is not where 88 whole records would end"
        );
        assert_eq!(
            ZCASH.accumulator_offset + record,
            ZCASH.file_bytes,
            "the accumulator we slice is not the last record's"
        );
    }

    /// And the arithmetic has to be able to disagree, or the assertions above
    /// are two copies of one mistake.
    #[test]
    fn a_layout_at_the_wrong_power_does_not_match() {
        assert_ne!(64 + accumulator_size(FILECOIN.power - 1), FILECOIN.file_bytes);
        assert_ne!(64 + accumulator_size(FILECOIN.power + 1), FILECOIN.file_bytes);
        assert_ne!(89 * (accumulator_size(ZCASH.power - 1) + PUBLIC_KEY_BYTES), ZCASH.file_bytes);
        assert_ne!(89 * (accumulator_size(ZCASH.power + 1) + PUBLIC_KEY_BYTES), ZCASH.file_bytes);
    }

    /// A public key that were not 1,152 bytes would make the Zcash total come
    /// out somewhere else, so this constant is load-bearing rather than
    /// decorative.
    #[test]
    fn the_public_key_size_is_what_makes_the_zcash_total_land() {
        assert_eq!(PUBLIC_KEY_BYTES, 1_152);
        for wrong in [0u64, 96, 576, 1_151, 1_153, 1_248] {
            assert_ne!(
                89 * (accumulator_size(ZCASH.power) + wrong),
                ZCASH.file_bytes,
                "a public key of {wrong} bytes also fits the published size"
            );
        }
    }

    #[test]
    fn the_ranges_lie_inside_the_file_and_do_not_overlap() {
        for transcript in ALL {
            let ranges = slice_ranges(transcript, 15).expect("ranges");
            assert_eq!(ranges.len(), 5, "{}", transcript.name);
            let mut previous_end = transcript.accumulator_offset;
            for range in &ranges {
                assert!(
                    range.offset >= previous_end,
                    "{}: {} starts at {} inside the previous section",
                    transcript.name,
                    range.name,
                    range.offset
                );
                assert!(
                    range.end() <= transcript.file_bytes,
                    "{}: {} runs to {} past the end of the file",
                    transcript.name,
                    range.name,
                    range.end()
                );
                assert_eq!(range.length, range.points * range.point_bytes);
                previous_end = range.end();
            }
        }
    }

    /// The last section's offset depends on every other section's size, so it
    /// is where an arithmetic slip would land.
    #[test]
    fn beta_g2_ends_where_the_accumulator_ends() {
        for transcript in ALL {
            let ranges = slice_ranges(transcript, 15).expect("ranges");
            let beta = ranges.last().expect("five ranges");
            assert_eq!(beta.name, "beta_g2");
            assert_eq!(
                beta.end(),
                transcript.accumulator_offset + accumulator_size(transcript.power),
                "{}: beta_g2 is not the accumulator's last 192 bytes",
                transcript.name
            );
        }
    }

    /// Both slices are the same size, because the slice's size depends on the
    /// circuit and not on the ceremony.
    #[test]
    fn a_slice_is_eighteen_megabytes_from_either_ceremony() {
        for transcript in ALL {
            let size = slice_size(transcript, 15).expect("size");
            assert_eq!(size, 18_874_464, "{}", transcript.name);
            assert!(
                size * 4000 < transcript.file_bytes,
                "{}: the slice should be a tiny fraction of the file",
                transcript.name
            );
        }
    }

    #[test]
    fn a_circuit_larger_than_the_ceremony_is_refused() {
        assert!(slice_ranges(&ZCASH, ZCASH.power + 1).is_err());
        assert!(slice_ranges(&FILECOIN, FILECOIN.power + 1).is_err());
        // And 2^15 fits both, which is the point of either being usable.
        assert!(slice_ranges(&ZCASH, 15).is_ok());
        assert!(slice_ranges(&FILECOIN, 15).is_ok());
    }

    #[test]
    fn transcripts_are_reachable_by_name_and_the_default_is_one_of_them() {
        assert_eq!(by_name("zcash").expect("zcash").power, 21);
        assert_eq!(by_name("filecoin").expect("filecoin").power, 27);
        assert!(by_name("bn254").is_err());
        assert!(ALL.iter().any(|t| t.name == DEFAULT.name));
    }

    /// The two ceremonies are independent, so their slices must come from
    /// different places. If these ever agreed, one of the descriptors would be
    /// a copy of the other.
    #[test]
    fn the_two_ceremonies_are_not_the_same_bytes() {
        assert_ne!(ZCASH.url, FILECOIN.url);
        assert_ne!(ZCASH.file_bytes, FILECOIN.file_bytes);
        assert_ne!(ZCASH.accumulator_offset, FILECOIN.accumulator_offset);
        assert_ne!(
            slice_ranges(&ZCASH, 15).expect("z")[0].offset,
            slice_ranges(&FILECOIN, 15).expect("f")[0].offset
        );
    }
}
