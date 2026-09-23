//! The one source list the shielded pool is built from.
//!
//! Two suites deploy the same contract. When each kept its own list they
//! drifted: the deposit suite went on compiling a pool without the transact
//! libraries, so it was testing a contract that no longer existed. A suite
//! that deploys the pool must deploy the pool, not a subset of it, so the
//! list lives here and both suites call this.

use std::path::PathBuf;

/// The deployment's configured withdrawal fee, read out of the generated
/// manifest.
///
/// A copy here is a number that reports headroom for a fee nobody deploys.
/// This file carried 50,000,000 for a day after the fee was re-derived to
/// 20,000,000, and printed a multiple of the wrong one.
pub fn configured_withdrawal_fee() -> i128 {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../doc/shielded-pool/genesis-manifest.json"
    ));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let needle = "\"withdrawal_fee\": \"";
    let start = text.find(needle).expect("the manifest names a withdrawal fee") + needle.len();
    let end = start + text[start..].find('"').expect("the fee is quoted");
    text[start..end].parse().expect("the fee is a number")
}

/// The directory the pool's sources live in.
fn smartcont() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../crypto/smartcont")
}

/// A section 14.1 gas ceiling, read out of the contract that enforces it.
///
/// A test that keeps its own copy of a ceiling asserts a relationship between
/// two numbers in the same file, and says nothing about the contract. That is
/// not hypothetical here. One suite checked that a deposit ceiling was the one
/// the production rule gives by comparing 220,000 written in the test against
/// 220,000 computed in the test, and passed against a contract declaring
/// 180,000. Another reported a recovery at 61% of a 280,000 ceiling the
/// contract has never granted.
///
/// Panics rather than returning an error: a suite that cannot read the
/// contract's ceiling has nothing to test.
pub fn gas_ceiling(name: &str) -> i64 {
    let path = PathBuf::from(format!("{}/tos-shielded-pool-v1.fc", smartcont()));
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let needle = format!("int {name}() asm \"");
    let at = source.find(&needle).unwrap_or_else(|| panic!("{name} is not declared in the pool"));
    let rest = &source[at + needle.len()..];
    let end = rest.find(" PUSHINT").unwrap_or_else(|| panic!("{name} is not a PUSHINT constant"));
    rest[..end].trim().parse().unwrap_or_else(|error| panic!("{name}: {error}"))
}

/// Every FunC source of the shielded pool, in dependency order, ending with
/// the contract itself.
pub fn pool_sources() -> Vec<PathBuf> {
    let library = smartcont();
    [
        "shielded/domains.fc",
        "shielded/empty-roots.fc",
        "shielded/notes.fc",
        "shielded/tree.fc",
        "shielded/imt.fc",
        "shielded/auth.fc",
        "shielded/payload.fc",
        "shielded/domain.fc",
        "shielded/anchors.fc",
        "shielded/state.fc",
        "shielded/transact.fc",
        "shielded/groth16.fc",
        "shielded/payout.fc",
        "shielded/recovery.fc",
        "tos-shielded-pool-v1.fc",
    ]
    .into_iter()
    .map(|name| PathBuf::from(format!("{library}/{name}")))
    .collect()
}

/// The frontier store section 13.2 deploys a pool with, in the §13.1 shape:
/// twelve level nodes, level 0 first, each three cells holding 3 + 3 + 1 zero
/// field elements, the last level carrying no successor.
///
/// Three suites build a genesis state by hand. While the store was a HashmapE
/// they could each write an absent maybe-ref and be right; a chain has to be
/// built, and a fixture that builds it slightly differently is a fixture that
/// agrees with itself and with nothing else. So it is built once, here.
pub fn frontier_genesis() -> chain_block::Cell {
    use chain_block::{BuilderData, IBitstring};

    let zero = [0u8; 32];
    let mut chain: Option<chain_block::Cell> = None;
    for level in (0..12usize).rev() {
        let mut third = BuilderData::new();
        third.append_raw(&zero, 256).expect("a third cell");
        let third = third.into_cell().expect("a third cell");

        let mut second = BuilderData::new();
        for _ in 0..3 {
            second.append_raw(&zero, 256).expect("a second cell");
        }
        second.checked_append_reference(third).expect("the third reference");
        let second = second.into_cell().expect("a second cell");

        let mut node = BuilderData::new();
        for _ in 0..3 {
            node.append_raw(&zero, 256).expect("a level node");
        }
        node.checked_append_reference(second).expect("the second reference");
        if level != 11 {
            let next = chain.take().expect("the level below has been built");
            node.checked_append_reference(next).expect("the next reference");
        }
        chain = Some(node.into_cell().expect("a level node"));
    }
    chain.expect("a frontier chain")
}

/// The same store inside section 13's `Maybe ^Cell` holder, which is the
/// reference the state root carries.
pub fn frontier_holder() -> chain_block::Cell {
    use chain_block::{BuilderData, IBitstring};

    let mut holder = BuilderData::new();
    holder.append_bit_one().expect("the maybe bit");
    holder.checked_append_reference(frontier_genesis()).expect("the frontier reference");
    holder.into_cell().expect("the frontier holder")
}
