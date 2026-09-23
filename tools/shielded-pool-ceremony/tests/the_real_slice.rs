/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The slice actually fetched from the published transcript.
//!
//! Every other test here builds its own powers-of-tau from secrets it chose,
//! which is what lets them be broken on purpose -- and means none of them has
//! ever seen the real thing. This one has.
//!
//! **These run by default**, which they did not until the slices were stored
//! in `artifacts/phase1/`. While the bytes had to be fetched, the choice was
//! between failing for everyone who had not fetched them and skipping quietly
//! -- and a test that passes while doing nothing is the failure this
//! repository's `CLAUDE.md` opens with, so they were `#[ignore]`d and hardly
//! ever ran. Committing eighteen megabytes bought the strongest evidence here
//! running on every invocation instead. It costs about twenty seconds.
//!
//! A slice can still be re-fetched, and the result must be identical:
//!
//!     uv run python scripts/shielded-pool-phase1-slice.py --out artifacts/phase1
//!     # --transcript filecoin for the other ceremony

use std::path::PathBuf;

use shielded_pool_ceremony::{lagrange, slice, verify};

const EXPONENT: u32 = 15;

/// What each ceremony's degree-2^15 slice is, by the hashes it produced when
/// it was fetched on 2026-09-21.
///
/// Both are pinned, not only the default's, because "the real slice verifies"
/// has to be a statement about specific bytes — and because a deployment that
/// switches ceremony should have to move a pin rather than discover later that
/// nothing had been checking.
struct Pinned {
    transcript: &'static str,
    /// SHA-256 of the eighteen megabytes.
    slice: &'static str,
    /// The reference string the Lagrange transform produces from it: a
    /// function of the slice and of nothing else.
    srs: &'static str,
}

const PINNED: [Pinned; 2] = [
    Pinned {
        transcript: "zcash",
        slice: "1bfd7acdb3ecbfaaa695ab159a7a643a2eb58203a4d93361040c6bd4c2aa3d6e",
        srs: "d4e6d28ef16ad12fd1102a64b9fbb8a8eeb4ddaef542635122c44af813b08097",
    },
    Pinned {
        transcript: "filecoin",
        slice: "d161614630b0504bd02075a9f57e7ca18d24f0c7c911c5cda5a686e91b8ced75",
        srs: "b30791cf1925a9184e90d9088acbc8299ae172fd3ef9958d892065368325baba",
    },
];

fn pinned_for(transcript: &str) -> &'static Pinned {
    PINNED
        .iter()
        .find(|entry| entry.transcript == transcript)
        .unwrap_or_else(|| panic!("no pinned hashes for the {transcript} ceremony"))
}

/// Whichever slice's **bytes** are on disk. Either ceremony's is acceptable
/// here; what is not acceptable is a slice nobody pinned.
///
/// The records are committed and the bytes are not, so the ordinary state of a
/// fresh checkout is "every record present, no bytes at all". That is why this
/// looks for a record *with a file beside it* rather than taking the first
/// record it finds: otherwise a developer who fetched only Zcash would be told
/// that `phase1-filecoin-2m15.bin` is missing, which is true and useless.
fn load() -> (Vec<u8>, slice::Provenance) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = root.join("artifacts/phase1");
    let how_to_fetch = "\n\nFetch one:\n  uv run python \
                        scripts/shielded-pool-phase1-slice.py --out artifacts/phase1\n  \
                        (add --transcript filecoin for the other ceremony)";

    let mut records: Vec<PathBuf> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}{how_to_fetch}", directory.display()))
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|extension| extension == "json"))
        .collect();
    records.sort();
    if records.is_empty() {
        panic!("no provenance record in {}{how_to_fetch}", directory.display());
    }

    let Some(json) = records.iter().find(|json| json.with_extension("bin").exists()) else {
        let named: Vec<String> = records
            .iter()
            .filter_map(|path| path.file_stem().map(|stem| stem.to_string_lossy().into_owned()))
            .collect();
        panic!(
            "{} holds records for {} but the bytes for none of them. The records are committed \
             and the slices are not, which is deliberate -- they are public, reproducible and \
             identified by the hashes in the record.{how_to_fetch}",
            directory.display(),
            named.join(", ")
        );
    };

    let record: slice::Provenance = serde_json::from_slice(
        &std::fs::read(json).unwrap_or_else(|error| panic!("{}: {error}", json.display())),
    )
    .unwrap_or_else(|error| panic!("{}: {error}", json.display()));
    let bin = json.with_extension("bin");
    let bytes = std::fs::read(&bin).unwrap_or_else(|error| panic!("{}: {error}", bin.display()));
    (bytes, record)
}

#[test]
fn the_fetched_slice_is_the_one_that_was_checked() {
    let (bytes, record) = load();
    let pinned = pinned_for(&record.transcript);
    eprintln!("the {} slice, {} bytes", record.transcript, bytes.len());
    eprintln!("inheriting: {}", record.custody);
    assert_eq!(bytes.len(), 18_874_464, "the slice is not the size the layout gives");
    assert_eq!(
        record.slice_sha256, pinned.slice,
        "this is not the {} slice these hashes were recorded from",
        record.transcript
    );
    // The descriptor decides the URL, and `check_against_layout` holds the
    // record to it, so this is the record agreeing with itself only if the
    // ceremony is one we describe.
    assert_eq!(record.source_url, record.transcript().expect("a described ceremony").url);
}

#[test]
fn the_fetched_slice_is_a_powers_of_tau_string() {
    let (bytes, record) = load();
    let parsed = slice::parse(&bytes, &record, EXPONENT).expect("the real slice must parse");
    assert_eq!(parsed.tau_g1.len(), 65_535);
    assert_eq!(parsed.tau_g2.len(), 32_768);
    verify::verify(&parsed, [0x5au8; 32]).expect("the real slice must verify");
}

/// And it can fail on the real thing, which is the only version of this claim
/// worth making.
///
/// Two *genuine* powers from the transcript, swapped. Every point is still a
/// point, still in the prime-order subgroup, and the sections still hash to
/// their record -- a corruption that survives everything except the pairing
/// checks. A flipped bit would be caught earlier and more cheaply by blst
/// refusing a point that is no longer on the curve, which proves the decoder
/// rather than the mathematics.
#[test]
fn two_real_powers_swapped_are_refused() {
    let (bytes, mut record) = load();
    let mut tampered = bytes.clone();
    let (i, j) = (40_000usize, 40_001usize);
    tampered[96 * i..96 * (i + 1)].copy_from_slice(&bytes[96 * j..96 * (j + 1)]);
    tampered[96 * j..96 * (j + 1)].copy_from_slice(&bytes[96 * i..96 * (i + 1)]);

    // Re-hash, so the cheap checks pass and only the mathematics can refuse.
    let rehashed = slice::describe(
        &tampered,
        record.transcript().expect("a described ceremony"),
        record.transcript_hash.clone(),
        record.slice_power,
    )
    .expect("a record for the tampered bytes");
    record = rehashed;

    let parsed = slice::parse(&tampered, &record, EXPONENT)
        .expect("swapped genuine points still parse, which is the point");
    let error =
        verify::verify(&parsed, [0x5au8; 32]).expect_err("two powers out of order must be refused");
    assert!(
        format!("{error}").contains("not consecutive powers of one tau"),
        "refused for the wrong reason: {error}"
    );
}

/// The real 2^15 Lagrange basis, computed from the real slice and checked
/// against it.
///
/// About five seconds to transform 131,839 points and a second and a half to
/// check the result -- which is why this is a step in the ceremony rather than
/// an artifact to store.
#[test]
fn the_real_slice_becomes_the_lagrange_basis_it_should() {
    let (bytes, record) = load();
    let parsed = slice::parse(&bytes, &record, EXPONENT).expect("the real slice must parse");
    let srs = lagrange::transform(&parsed).expect("the transform");

    assert_eq!(srs.degree(), 32_768, "the basis is not the circuit's domain");
    assert_eq!(srs.h.len(), 32_767, "the h query is not n-1 long");
    lagrange::verify(&parsed, &srs, [0xa5u8; 32]).expect("the real transform must verify");
    assert_eq!(
        lagrange::digest(&srs),
        pinned_for(&record.transcript).srs,
        "the reference string phase 2 would start from, for the {} ceremony, has moved",
        record.transcript
    );
}

/// And the checks bite on the real thing too.
///
/// Two elements of the real basis swapped **in both groups**: the sum is
/// unchanged, the two groups still agree with each other, every point is
/// genuine and in the right subgroup. Only going back to the powers it was
/// built from can see it.
#[test]
fn a_permuted_real_basis_is_refused() {
    let (bytes, record) = load();
    let parsed = slice::parse(&bytes, &record, EXPONENT).expect("the real slice must parse");
    let mut srs = lagrange::transform(&parsed).expect("the transform");

    srs.coeffs_g1.swap(11_111, 22_222);
    srs.coeffs_g2.swap(11_111, 22_222);

    let error = lagrange::verify(&parsed, &srs, [0xa5u8; 32])
        .expect_err("a permuted real basis must be refused");
    assert!(
        format!("{error}").contains("disagrees with the powers it was built from"),
        "refused for the wrong reason: {error}"
    );
}
