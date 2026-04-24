//! §10.3 60 / 25 / 15 genesis-distribution builder (K-genesis-distribution).
//!
//! This is the **builder** side of the zerostate genesis file. It takes
//! three recipient lists (airdrop / treasury / team), validates the 60/25/15
//! split sums to the §10.3 fixed supply, sorts each list by address hash,
//! concatenates in canonical order (airdrop → treasury → team), assigns
//! `rseed[i] = BLAKE2b-256("uno-genesis-rseed-v1" || u32_be(i))` per note,
//! computes `cm[i]` via `compute_rcm` + `compute_note_commitment` from
//! `crate::transfer`, and serializes to the same JSON schema the C++ loader
//! accepts (`uno/core/genesis.cpp::load_genesis_distribution`).
//!
//! The byte output is cross-checked against the C++ builder via the golden
//! fixture `uno/test/golden/genesis-distribution-v1.json`.
//!
//! # Canonical constants (§10.3)
//!
//! | Category        | UNO        | nano-UNO            |
//! |-----------------|------------|---------------------|
//! | Airdrop (60%)   | 12,600,000 | 12_600_000e9        |
//! | Treasury (25%)  | 5,250,000  |  5_250_000e9        |
//! | Team (15%)      | 3,150,000  |  3_150_000e9        |
//! | **Total**       | 21,000,000 | 21_000_000e9 = 2.1e16 |
//!
//! # Output JSON schema
//!
//! ```json
//! {
//!   "chain_id": <u32 decimal>,
//!   "total_supply_nano": "<u64 decimal string>",
//!   "notes": [
//!     {
//!       "recipient": {
//!         "d":              "<hex 11 B>",
//!         "pk_d":           "<hex 32 B>",
//!         "ivk_commitment": "<hex 32 B>",
//!         "pk_mlkem":       "<hex 1184 B>"
//!       },
//!       "value": "<u64 decimal string>",
//!       "rseed": "<hex 32 B>",
//!       "cm":    "<hex 32 B>"
//!     },
//!     ...
//!   ]
//! }
//! ```
//!
//! Note: the dumper emits the loader-accepted minimal schema — hex
//! `recipient` block, no top-level `scheme_id` field, no per-note `address`
//! envelope. The loader on the C++ side accepts envelopes additionally but
//! does not require them; keeping the hex block only makes byte-equality
//! reproduction trivial across hosts.

use anyhow::{anyhow, Result};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use crate::address::Address;
use crate::sizes::{DIVERSIFIER, IVK_COMMITMENT, MLKEM768_PK, RISTRETTO_POINT};
use crate::transfer::{compute_note_commitment, compute_rcm, NoteCommitmentInputs};

// ---------------------------------------------------------------------------
// Canonical §10.3 constants — MUST match `uno/core/genesis.h`.
// ---------------------------------------------------------------------------

/// 21,000,000 UNO × 10^9 nano-units/UNO = 2.1e16 nano-UNO.
/// Matches Bitcoin / Zcash 21 M cap — UNO positions as the privacy-coin
/// peer of ZEC/XMR. Sister tokens TOS (wc=0, 100 M) and eTOS (wc=1, 100 M)
/// are economically independent of UNO; no on-chain bridge between any
/// pair (privacy preservation requirement, uno-workchain.md §1.5).
pub const GENESIS_TOTAL_SUPPLY_NANO: u64 = 21_000_000 * 1_000_000_000;

/// 60% = 12,600,000 UNO.
pub const GENESIS_AIRDROP_NANO: u64 = 12_600_000 * 1_000_000_000;

/// 25% = 5,250,000 UNO.
pub const GENESIS_TREASURY_NANO: u64 = 5_250_000 * 1_000_000_000;

/// 15% = 3,150,000 UNO.
pub const GENESIS_TEAM_NANO: u64 = 3_150_000 * 1_000_000_000;

/// Domain-separation tag for per-note rseed derivation. Byte-identical to
/// the C++ `kGenesisRseedTagV1` constant.
pub const GENESIS_RSEED_TAG_V1: &[u8] = b"uno-genesis-rseed-v1";

/// ASCII "UNOT" — 0x554E4F54. Default chain_id for testnet zerostates.
pub const CHAIN_ID_TESTNET: u32 = 0x554E4F54;

/// ASCII "UNOM" — 0x554E4F4D.
pub const CHAIN_ID_MAINNET: u32 = 0x554E4F4D;

const ADDRESS_PAYLOAD_BYTES: usize = DIVERSIFIER + RISTRETTO_POINT + IVK_COMMITMENT + MLKEM768_PK; // 1259

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// One (address, nano-UNO value) input pair. Addresses are validated by
/// `Address::from_bytes` (canonical Ristretto pk_d, correct lengths); no
/// cryptographic commitment is computed yet — the builder fills in `cm`
/// and `rseed` after assigning the canonical index.
#[derive(Clone, Debug)]
pub struct DistributionRecipient {
    pub address: Address,
    pub value_nano: u64,
}

/// Three-category input for the §10.3 distribution builder. Instantiated
/// by the CLI from airdrop.csv / treasury.csv / team.csv.
#[derive(Clone, Debug)]
pub struct GenesisDistributionInputs {
    pub chain_id: u32,
    pub airdrop: Vec<DistributionRecipient>,
    pub treasury: Vec<DistributionRecipient>,
    pub team: Vec<DistributionRecipient>,
}

impl GenesisDistributionInputs {
    /// Convenience: testnet chain_id, everything else empty.
    pub fn testnet() -> Self {
        Self {
            chain_id: CHAIN_ID_TESTNET,
            airdrop: Vec::new(),
            treasury: Vec::new(),
            team: Vec::new(),
        }
    }
}

/// One canonicalized output entry. Exposed so tests can inspect the
/// per-index rseed/cm derivation directly.
#[derive(Clone, Debug)]
pub struct CanonicalNote {
    pub address: Address,
    pub value_nano: u64,
    pub rseed: [u8; 32],
    pub cm: [u8; 32],
}

/// Full intermediate result of the builder. Exposed for test cross-checks;
/// `build_genesis_notes_json` serializes this to JSON.
#[derive(Clone, Debug)]
pub struct GenesisDistributionOutput {
    pub chain_id: u32,
    pub total_supply_nano: u64,
    pub notes: Vec<CanonicalNote>,
}

/// Validate, canonicalize, and emit the `zerostate-genesis-notes.json`
/// string. The returned string is byte-identical to what the C++
/// `build_genesis_notes_json` emits for equivalent input.
pub fn build_genesis_notes_json(inputs: &GenesisDistributionInputs) -> Result<String> {
    let out = build_genesis_distribution(inputs)?;
    Ok(serialize_output(&out))
}

/// Run validation + canonicalization WITHOUT serializing. Useful for tests
/// that want to assert on individual entries.
pub fn build_genesis_distribution(
    inputs: &GenesisDistributionInputs,
) -> Result<GenesisDistributionOutput> {
    // --- Step 1: per-category validation + sums -----------------------------
    if inputs.airdrop.is_empty() {
        return Err(anyhow!("uno/genesis: airdrop list is empty"));
    }
    let airdrop_sum = sum_category(&inputs.airdrop, "airdrop")?;
    let treasury_sum = sum_category(&inputs.treasury, "treasury")?;
    let team_sum = sum_category(&inputs.team, "team")?;

    if airdrop_sum != GENESIS_AIRDROP_NANO {
        return Err(anyhow!(
            "uno/genesis: airdrop sum {} != §10.3 target {} (12,600,000 × 10^9 nano-UNO)",
            airdrop_sum,
            GENESIS_AIRDROP_NANO
        ));
    }
    if treasury_sum != GENESIS_TREASURY_NANO {
        return Err(anyhow!(
            "uno/genesis: treasury sum {} != §10.3 target {} (5,250,000 × 10^9 nano-UNO)",
            treasury_sum,
            GENESIS_TREASURY_NANO
        ));
    }
    if team_sum != GENESIS_TEAM_NANO {
        return Err(anyhow!(
            "uno/genesis: team sum {} != §10.3 target {} (3,150,000 × 10^9 nano-UNO)",
            team_sum,
            GENESIS_TEAM_NANO
        ));
    }
    let total = airdrop_sum + treasury_sum + team_sum;
    if total != GENESIS_TOTAL_SUPPLY_NANO {
        return Err(anyhow!(
            "uno/genesis: total supply {} != §10.3 fixed supply {}",
            total,
            GENESIS_TOTAL_SUPPLY_NANO
        ));
    }

    // --- Step 2: duplicate-address check across all three lists -------------
    {
        let mut seen: std::collections::BTreeSet<[u8; ADDRESS_PAYLOAD_BYTES]> =
            std::collections::BTreeSet::new();
        let all = inputs
            .airdrop
            .iter()
            .chain(inputs.treasury.iter())
            .chain(inputs.team.iter());
        for (i, r) in all.enumerate() {
            let flat = flatten_address(&r.address);
            if !seen.insert(flat) {
                return Err(anyhow!(
                    "uno/genesis: duplicate address detected at canonical-input position {}",
                    i
                ));
            }
        }
    }

    // --- Step 3 + 4: sort each list by address hash, concatenate ------------
    let airdrop_sorted = sort_by_address_hash(inputs.airdrop.clone());
    let treasury_sorted = sort_by_address_hash(inputs.treasury.clone());
    let team_sorted = sort_by_address_hash(inputs.team.clone());

    let mut canonical: Vec<DistributionRecipient> =
        Vec::with_capacity(airdrop_sorted.len() + treasury_sorted.len() + team_sorted.len());
    canonical.extend(airdrop_sorted);
    canonical.extend(treasury_sorted);
    canonical.extend(team_sorted);

    // --- Step 5: assign rseed + cm per canonical index ----------------------
    let mut notes = Vec::with_capacity(canonical.len());
    for (i, r) in canonical.into_iter().enumerate() {
        let rseed = derive_genesis_rseed(i as u32);
        let rcm = compute_rcm(&rseed);
        let cm = compute_note_commitment(&NoteCommitmentInputs {
            d: &r.address.d,
            pk_d_bytes: &r.address.pk_d,
            ivk_commitment: &r.address.ivk_commitment,
            value: r.value_nano,
            rcm: &rcm,
        });
        notes.push(CanonicalNote {
            address: r.address,
            value_nano: r.value_nano,
            rseed,
            cm,
        });
    }

    Ok(GenesisDistributionOutput {
        chain_id: inputs.chain_id,
        total_supply_nano: total,
        notes,
    })
}

/// Canonical sort key: BLAKE2b-256 over the 1259-byte address payload.
/// Exported for test parity against `uno/core/genesis.cpp::canonical_address_hash`.
pub fn canonical_address_hash(addr: &Address) -> [u8; 32] {
    let flat = flatten_address(addr);
    let mut h = Blake2b::<U32>::new();
    h.update(flat);
    let out = h.finalize();
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&out);
    fixed
}

/// Canonical rseed derivation. Exported for test parity against
/// `uno/core/genesis.cpp::derive_genesis_rseed`.
pub fn derive_genesis_rseed(address_index: u32) -> [u8; 32] {
    let idx_be = address_index.to_be_bytes();
    let mut h = Blake2b::<U32>::new();
    h.update(GENESIS_RSEED_TAG_V1);
    h.update(idx_be);
    let out = h.finalize();
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&out);
    fixed
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn sum_category(list: &[DistributionRecipient], list_name: &'static str) -> Result<u64> {
    let mut total: u64 = 0;
    for (i, r) in list.iter().enumerate() {
        if r.address.pk_mlkem.len() != MLKEM768_PK {
            return Err(anyhow!(
                "uno/genesis: {}[{}] pk_mlkem length {} != {} (§2.6)",
                list_name,
                i,
                r.address.pk_mlkem.len(),
                MLKEM768_PK
            ));
        }
        if r.value_nano == 0 {
            return Err(anyhow!(
                "uno/genesis: {}[{}] value_nano == 0 (rejected — zero-value \
                 notes pollute the commitment tree without funding anyone)",
                list_name,
                i
            ));
        }
        total = total
            .checked_add(r.value_nano)
            .ok_or_else(|| anyhow!("uno/genesis: {} sum overflow at index {}", list_name, i))?;
    }
    Ok(total)
}

fn sort_by_address_hash(mut list: Vec<DistributionRecipient>) -> Vec<DistributionRecipient> {
    // Precompute keys so the sort is stable without hashing per comparison.
    let mut keyed: Vec<([u8; 32], DistributionRecipient)> = list
        .drain(..)
        .map(|r| (canonical_address_hash(&r.address), r))
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.into_iter().map(|(_, r)| r).collect()
}

fn flatten_address(addr: &Address) -> [u8; ADDRESS_PAYLOAD_BYTES] {
    let mut out = [0u8; ADDRESS_PAYLOAD_BYTES];
    out[0..11].copy_from_slice(&addr.d);
    out[11..43].copy_from_slice(&addr.pk_d);
    out[43..75].copy_from_slice(&addr.ivk_commitment);
    // pk_mlkem length MUST be 1184 — checked upstream; short slabs would
    // panic on the slice copy below, so we guard defensively.
    if addr.pk_mlkem.len() == MLKEM768_PK {
        out[75..].copy_from_slice(&addr.pk_mlkem);
    }
    out
}

// ---------------------------------------------------------------------------
// Canonical JSON serializer — byte-identical to C++ `dump_genesis_distribution`.
// ---------------------------------------------------------------------------

fn serialize_output(out: &GenesisDistributionOutput) -> String {
    // Format mirrors `uno/core/genesis.cpp::dump_genesis_distribution`:
    // single line, hex byte fields, decimal-string large numbers, notes in
    // canonical order.
    let mut s = String::with_capacity(128 + out.notes.len() * 2048);
    s.push_str("{\"chain_id\":");
    s.push_str(&out.chain_id.to_string());
    s.push_str(",\"total_supply_nano\":\"");
    s.push_str(&out.total_supply_nano.to_string());
    s.push_str("\",\"notes\":[");
    for (i, note) in out.notes.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"recipient\":{\"d\":\"");
        s.push_str(&hex::encode(note.address.d));
        s.push_str("\",\"pk_d\":\"");
        s.push_str(&hex::encode(note.address.pk_d));
        s.push_str("\",\"ivk_commitment\":\"");
        s.push_str(&hex::encode(note.address.ivk_commitment));
        s.push_str("\",\"pk_mlkem\":\"");
        s.push_str(&hex::encode(&note.address.pk_mlkem));
        s.push_str("\"},\"value\":\"");
        s.push_str(&note.value_nano.to_string());
        s.push_str("\",\"rseed\":\"");
        s.push_str(&hex::encode(note.rseed));
        s.push_str("\",\"cm\":\"");
        s.push_str(&hex::encode(note.cm));
        s.push_str("\"}");
    }
    s.push_str("]}");
    s
}

// ---------------------------------------------------------------------------
// CSV parse helper for `tosctl uno genesis build` — `address_bytes_hex,value_nano`
// per line. Lines starting with `#` are skipped (comments).
// ---------------------------------------------------------------------------

/// Parse a CSV of `<address_wire_bytes_hex>,<value_nano>` into a recipient
/// list. `address_wire_bytes_hex` is exactly 1259 × 2 hex chars (the 1259-byte
/// §2.6 payload — same format emitted by `tosctl uno address --out -`).
///
/// Comment lines (first non-whitespace char is `#`) and blank lines are
/// skipped. Any parse error is fatal.
pub fn parse_recipient_csv(text: &str, source_name: &str) -> Result<Vec<DistributionRecipient>> {
    let mut out = Vec::new();
    for (lineno, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, ',');
        let addr_hex = parts
            .next()
            .ok_or_else(|| anyhow!("{}:{}: missing address column", source_name, lineno + 1))?
            .trim();
        let value_str = parts
            .next()
            .ok_or_else(|| anyhow!("{}:{}: missing value column", source_name, lineno + 1))?
            .trim();

        let addr_bytes = hex::decode(addr_hex)
            .map_err(|e| anyhow!("{}:{}: hex-decode address: {}", source_name, lineno + 1, e))?;
        let address = Address::from_bytes(&addr_bytes).map_err(|e| {
            anyhow!(
                "{}:{}: parse address wire bytes: {}",
                source_name,
                lineno + 1,
                e
            )
        })?;
        let value_nano: u64 = value_str.parse().map_err(|e| {
            anyhow!(
                "{}:{}: parse value_nano ({}): {}",
                source_name,
                lineno + 1,
                value_str,
                e
            )
        })?;

        out.push(DistributionRecipient {
            address,
            value_nano,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::derive_fvk;

    fn mk_fvk_and_address(seed_byte: u8, d_byte: u8) -> Address {
        let mut seed = [0u8; 32];
        for i in 0..32 {
            seed[i] = seed_byte.wrapping_add(i as u8);
        }
        let fvk = derive_fvk(&seed).unwrap();
        Address::build(&fvk, &[d_byte; 11]).unwrap()
    }

    fn mk_inputs(
        airdrop_values: &[u64],
        treasury_values: &[u64],
        team_values: &[u64],
    ) -> GenesisDistributionInputs {
        let mut counter: u8 = 1;
        let mut next = |v: u64| {
            let a = mk_fvk_and_address(counter, counter);
            counter = counter.wrapping_add(1);
            DistributionRecipient {
                address: a,
                value_nano: v,
            }
        };
        GenesisDistributionInputs {
            chain_id: CHAIN_ID_TESTNET,
            airdrop: airdrop_values.iter().map(|v| next(*v)).collect(),
            treasury: treasury_values.iter().map(|v| next(*v)).collect(),
            team: team_values.iter().map(|v| next(*v)).collect(),
        }
    }

    #[test]
    fn rseed_derivation_matches_canonical_tag_u32_be() {
        // Spot-check the formula: rseed[0] = BLAKE2b-256("uno-genesis-rseed-v1" || 0x00000000).
        let r0 = derive_genesis_rseed(0);
        let r1 = derive_genesis_rseed(1);
        assert_ne!(r0, r1);
        // Independent recomputation using the blake2 crate.
        let mut h = Blake2b::<U32>::new();
        h.update(b"uno-genesis-rseed-v1");
        h.update(&[0u8, 0, 0, 0]);
        let expect: [u8; 32] = h.finalize().into();
        assert_eq!(r0, expect);

        // big-endian index: 257 → [0, 0, 1, 1].
        let r257 = derive_genesis_rseed(257);
        let mut h = Blake2b::<U32>::new();
        h.update(b"uno-genesis-rseed-v1");
        h.update(&[0u8, 0, 1, 1]);
        let expect_257: [u8; 32] = h.finalize().into();
        assert_eq!(r257, expect_257);
    }

    #[test]
    fn builder_rejects_sum_mismatch() {
        // Airdrop short by 1 nano.
        let inp = mk_inputs(
            &[GENESIS_AIRDROP_NANO - 1],
            &[GENESIS_TREASURY_NANO],
            &[GENESIS_TEAM_NANO],
        );
        let err = build_genesis_distribution(&inp).unwrap_err().to_string();
        assert!(err.contains("airdrop sum"), "unexpected: {err}");
    }

    #[test]
    fn builder_rejects_empty_airdrop() {
        let inp = mk_inputs(&[], &[GENESIS_TREASURY_NANO], &[GENESIS_TEAM_NANO]);
        let err = build_genesis_distribution(&inp).unwrap_err().to_string();
        assert!(err.contains("airdrop"), "unexpected: {err}");
    }

    #[test]
    fn builder_rejects_zero_value() {
        let mut inp = mk_inputs(
            &[GENESIS_AIRDROP_NANO],
            &[GENESIS_TREASURY_NANO],
            &[GENESIS_TEAM_NANO],
        );
        inp.airdrop[0].value_nano = 0;
        let err = build_genesis_distribution(&inp).unwrap_err().to_string();
        assert!(err.contains("value_nano == 0"), "unexpected: {err}");
    }

    #[test]
    fn builder_rejects_duplicate_address() {
        let mut inp = mk_inputs(
            &[GENESIS_AIRDROP_NANO / 2, GENESIS_AIRDROP_NANO / 2],
            &[GENESIS_TREASURY_NANO],
            &[GENESIS_TEAM_NANO],
        );
        // Clone the first airdrop address into the second slot.
        inp.airdrop[1].address = inp.airdrop[0].address.clone();
        let err = build_genesis_distribution(&inp).unwrap_err().to_string();
        assert!(err.contains("duplicate address"), "unexpected: {err}");
    }

    #[test]
    fn builder_assigns_canonical_rseed_and_sort() {
        // 3-airdrop + 2-treasury + 1-team, values summing to §10.3 targets.
        let inp = mk_inputs(
            &[
                GENESIS_AIRDROP_NANO / 2,
                GENESIS_AIRDROP_NANO / 4,
                GENESIS_AIRDROP_NANO / 4,
            ],
            &[GENESIS_TREASURY_NANO / 2, GENESIS_TREASURY_NANO / 2],
            &[GENESIS_TEAM_NANO],
        );
        let out = build_genesis_distribution(&inp).unwrap();
        assert_eq!(out.notes.len(), 6);
        assert_eq!(out.total_supply_nano, GENESIS_TOTAL_SUPPLY_NANO);

        // Airdrop section [0..3] must be sorted by canonical_address_hash.
        for i in 1..3 {
            let h_prev = canonical_address_hash(&out.notes[i - 1].address);
            let h_curr = canonical_address_hash(&out.notes[i].address);
            assert!(
                h_prev < h_curr,
                "airdrop section not sorted at index {i}: prev={h_prev:?}, curr={h_curr:?}"
            );
        }
        // Treasury section [3..5] must be sorted too.
        let h_prev = canonical_address_hash(&out.notes[3].address);
        let h_curr = canonical_address_hash(&out.notes[4].address);
        assert!(h_prev < h_curr, "treasury not sorted");

        // Every rseed matches the canonical derivation.
        for (i, n) in out.notes.iter().enumerate() {
            assert_eq!(n.rseed, derive_genesis_rseed(i as u32));
        }

        // JSON is valid serde.
        let json = build_genesis_notes_json(&inp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["chain_id"], CHAIN_ID_TESTNET);
        assert_eq!(parsed["notes"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn parse_recipient_csv_basic() {
        let fvk = derive_fvk(&[7u8; 32]).unwrap();
        let addr = Address::build(&fvk, &[0x42u8; 11]).unwrap();
        let csv = format!(
            "# leading comment\n\n{},1000000\n",
            hex::encode(addr.to_bytes())
        );
        let parsed = parse_recipient_csv(&csv, "test.csv").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].value_nano, 1_000_000);
        assert_eq!(parsed[0].address, addr);
    }
}
