/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! What each variable cost can be, over the whole of its own domain.
//!
//! Section 14.1 asks a ceiling to cover the worst legal path for the life of
//! the pool. The worst legal path is not a transaction anybody can be asked
//! to build: it would need the dearest denomination, the dearest anchor kind,
//! both rings full, the epoch turning over, the leaf index whose base-seven
//! digits are all zero and the nullifier order whose second predecessor is
//! not the leaf just inserted -- and some of those cannot hold at once. A
//! measurement of the worst *reachable* transaction is therefore not
//! available, and every figure the contract has carried so far has been the
//! largest of a handful of reachable ones with the word maximum in front of
//! it.
//!
//! An upper bound is available, and it does not need the corner to be
//! reachable. Each handler is a straight line whose variable calls read only
//! their own arguments, so its cost is a constant plus one term per call, and
//!
//! ```text
//! cost(anything) <= cost(one measured transaction)
//!                   + sum over calls of (that call's worst - its best)
//! ```
//!
//! holds whatever the measured transaction was. Every term on the right is
//! the span of one function over one domain, and those domains are small
//! enough to exhaust: four denominations, three anchor kinds, 4,096 and 2,880
//! ring slots, twelve levels of seven digits, two nullifier orders.
//!
//! The bound is loose on purpose. A ceiling set too high charges a sender for
//! gas nobody spent; a ceiling set too low strands a withdrawal in a contract
//! whose code hash is its address and cannot be patched. The asymmetry is the
//! whole argument for erring high.

use chain_block::Cell;

use crate::anchor_probe::{AnchorProbe, EPOCH_SLOTS, RECENT_SLOTS};
use crate::components::ComponentProbe;
use crate::frontier_probe::FrontierProbe;
use crate::{CrossCheckError, Result};

/// The commitment tree's capacity, section 5.1's thirty-two bits.
pub const COMMITMENT_CAPACITY: u64 = 4_294_967_296;

/// The tree's depth and arity, which decide how many (level, digit) pairs
/// there are to exhaust.
pub const TREE_DEPTH: u32 = 12;
pub const TREE_ARITY: u64 = 7;

/// What one variable call can cost, over the whole of its own domain, and how
/// many times a path makes it.
#[derive(Clone, Debug)]
pub struct Span {
    pub name: &'static str,
    /// How the domain was covered, in words, for the report the derivation
    /// prints. A span whose domain was sampled rather than exhausted says so
    /// here, and the reader can weigh it.
    pub domain: String,
    pub calls: i64,
    pub worst: i64,
    pub best: i64,
}

impl Span {
    /// What this call can add to a transaction beyond what the measured one
    /// already paid for it.
    pub fn slack(&self) -> i64 {
        self.calls * (self.worst - self.best)
    }
}

/// Section 14.1's rule, applied to a bound rather than to a sample.
pub fn ceiling_for(bound: i64) -> i64 {
    let with_margin = (bound * 5 + 3) / 4;
    (((with_margin + 9_999) / 10_000) * 10_000).max(10_000)
}

/// The denomination walk, over every denomination the pool is deployed with.
///
/// The walk stops at the first match, so the dearest amount is the last one
/// in the list and the cheapest is the first. Until this was measured the
/// contract's figure came from a withdrawal of the *first* denomination:
/// the list had been corrected to the deployed one and the position in it
/// had not.
pub fn denomination_span(
    probe: &ComponentProbe,
    config: &Cell,
    denominations: &[u64],
    calls: i64,
) -> Result<Span> {
    if denominations.is_empty() {
        return Err(CrossCheckError::Fixture("a pool with no denominations".to_string()));
    }
    let mut worst = i64::MIN;
    let mut best = i64::MAX;
    for &amount in denominations {
        let gas = probe.denomination_gas(config, amount)?;
        worst = worst.max(gas);
        best = best.min(gas);
    }
    Ok(Span {
        name: "denomination walk",
        domain: format!("all {} configured denominations", denominations.len()),
        calls,
        worst,
        best,
    })
}

/// What one `frontier_append` can cost, over every leaf index the tree has.
///
/// Four billion indices cannot be measured, and they do not have to be. The
/// append walks twelve levels and each level reads its own base-seven digit,
/// so the cost is a sum of twelve independent terms with seven values each --
/// eighty-four measurements rather than 2^32. The worst is the sum of the
/// twelve worst terms and the best the sum of the twelve best, and neither
/// has to be an index anybody can reach.
///
/// The separability is not assumed. `append_additivity_error` puts the
/// composed prediction against real appends at multi-digit indices, and the
/// bound is only usable while that stays at zero.
pub fn append_span(
    probe: &ComponentProbe,
    frontier: &FrontierProbe,
    calls: i64,
) -> Result<(Span, Vec<Vec<i64>>)> {
    let leaf = "123456789012345678901234567890123456789012345678901234567890";
    let mut table: Vec<Vec<i64>> = Vec::new();
    let mut place = 1u64;
    for _ in 0..TREE_DEPTH {
        let mut row = Vec::new();
        for digit in 0..TREE_ARITY {
            let index = digit * place;
            if index >= COMMITMENT_CAPACITY {
                break;
            }
            let store = frontier.fill(index)?;
            row.push(probe.append_gas(&store, index, leaf)?);
        }
        table.push(row);
        if place < COMMITMENT_CAPACITY / TREE_ARITY {
            place *= TREE_ARITY;
        }
    }

    // The all-zero index is the common baseline: at digit zero a level costs
    // the same whichever level it is, and a table where that is not true is
    // not separable and cannot be composed.
    let zero = table[0][0];
    for (level, row) in table.iter().enumerate() {
        if row[0] != zero {
            return Err(CrossCheckError::Fixture(format!(
                "level {level} costs {} at digit zero and level 0 costs {zero}: the levels are \
                 not interchangeable, so the composition below is not valid",
                row[0]
            )));
        }
    }

    let mut worst = zero;
    let mut best = zero;
    for row in &table {
        let level_worst = row.iter().copied().max().unwrap_or(zero) - zero;
        let level_best = row.iter().copied().min().unwrap_or(zero) - zero;
        worst += level_worst;
        best += level_best;
    }

    // A genuinely fresh pool holds the genesis store, which is not the store
    // `fill(0)` builds: nothing has been written into it at all. It is one
    // more point in the same domain and it is priced like the rest.
    let genesis = probe.append_gas(&frontier.genesis()?, 0, leaf)?;
    worst = worst.max(genesis);
    best = best.min(genesis);

    Ok((
        Span {
            name: "frontier append",
            domain: format!(
                "every base-seven digit at every one of the {TREE_DEPTH} levels, composed, \
                 plus the genesis store"
            ),
            calls,
            worst,
            best,
        },
        table,
    ))
}

/// The composed prediction against the real thing, at indices whose digits
/// are not all the same.
///
/// Returns the largest difference in gas. Anything but zero means a level's
/// cost depends on something other than its own digit, and the bound above
/// is then a sum of terms that do not add.
pub fn append_additivity_error(
    probe: &ComponentProbe,
    frontier: &FrontierProbe,
    table: &[Vec<i64>],
    indices: &[u64],
) -> Result<(i64, Vec<(u64, i64, i64)>)> {
    let leaf = "123456789012345678901234567890123456789012345678901234567890";
    let zero = table[0][0];
    let mut worst = 0;
    let mut rows = Vec::new();
    for &index in indices {
        let mut predicted = zero;
        let mut remaining = index;
        for row in table.iter() {
            let digit = (remaining % TREE_ARITY) as usize;
            remaining /= TREE_ARITY;
            let Some(cost) = row.get(digit) else {
                return Err(CrossCheckError::Fixture(format!(
                    "index {index} needs digit {digit} at a level the table does not price"
                )));
            };
            predicted += cost - zero;
        }
        let store = frontier.fill(index)?;
        let measured = probe.append_gas(&store, index, leaf)?;
        worst = worst.max((measured - predicted).abs());
        rows.push((index, measured, predicted));
    }
    Ok((worst, rows))
}

/// What one nullifier insert can cost.
///
/// The two things that move it are the order the owner chose -- whether the
/// second nullifier's predecessor is the head sentinel or the leaf the first
/// insert just added -- and the leaf index the append lands on. The index
/// turns out not to move it at all, because the path fold is one native
/// instruction whose tariff is fixed by the depth, but that is a measurement
/// here and not an assumption.
pub fn insert_span(probe: &ComponentProbe, calls: i64) -> Result<Span> {
    use crate::imt_probe::encode_witness;
    use crate::pool::dec;
    use shielded_pool_circuit::field::Fr;
    use shielded_pool_circuit::imt;

    let mut worst = i64::MIN;
    let mut best = i64::MAX;

    // Ascending: every predecessor is the leaf just inserted. Descending:
    // every predecessor is the head sentinel. Those are the two branches
    // section 7.1 step 3 can take, and which one a transaction takes is the
    // owner's choice of which nullifier goes in first.
    //
    // Full-width field elements as well as small ones, so that the width of
    // the values being compared is covered rather than assumed away.
    let big = Fr::from(u128::MAX) * Fr::from(7u64);
    for order in [
        vec![Fr::from(1_000u64), Fr::from(2_000u64), Fr::from(3_000u64), big],
        vec![big, Fr::from(3_000u64), Fr::from(2_000u64), Fr::from(1_000u64)],
    ] {
        let mut state = imt::State::genesis();
        for value in order {
            let (witness, after) = state
                .witness_for(&value)
                .map_err(|error| CrossCheckError::Fixture(format!("witness: {error}")))?;
            let cell = encode_witness(&witness)?;
            let gas =
                probe.insert_gas(&dec(state.root()), state.next_index, &dec(value), &cell)?;
            worst = worst.max(gas);
            best = best.min(gas);
            state.apply(after);
        }
    }

    // And deep in the tree, where the index the append lands on has several
    // base-seven digits set rather than none.
    let mut state = imt::State::genesis();
    for step in 1..=400u64 {
        let value = Fr::from(step * 1_000);
        let (witness, after) = state
            .witness_for(&value)
            .map_err(|error| CrossCheckError::Fixture(format!("witness: {error}")))?;
        if step > 390 {
            let cell = encode_witness(&witness)?;
            let gas =
                probe.insert_gas(&dec(state.root()), state.next_index, &dec(value), &cell)?;
            worst = worst.max(gas);
            best = best.min(gas);
        }
        state.apply(after);
    }

    Ok(Span {
        name: "nullifier insert",
        domain: "both predecessor branches, small and full-width values, shallow and deep \
                 indices"
            .to_string(),
        calls,
        worst,
        best,
    })
}

/// What checking an anchor can cost, over all three kinds and every slot of
/// both rings.
///
/// A ring is a `HashmapE` on twelve-bit keys, so no lookup can walk more than
/// twelve edges and a ring holding every key walks exactly twelve for every
/// one of them -- the occupancy that makes the trie complete is the occupancy
/// that makes every lookup as long as a lookup can be. That is the argument;
/// the sweeps are what stop it from being only an argument. Occupancy is
/// walked one entry at a time from empty to full, and at full every key is
/// priced.
pub fn check_span(probe: &ComponentProbe, anchors: &AnchorProbe, calls: i64) -> Result<Span> {
    let far = "98765432109876543210987654321098765432109876543210";
    let mut worst = i64::MIN;
    let mut best = i64::MAX;

    // ANCHOR_CURRENT reads no store at all; it is the floor of the domain.
    let empty = anchors.empty()?;
    let current = probe.check_gas(&empty, 0, 0, far, far, 1_000_000)?;
    worst = worst.max(current);
    best = best.min(current);

    // The recent ring, every occupancy it passes through, then every key it
    // holds once it is full.
    let mut store = empty.clone();
    for occupancy in 1..=RECENT_SLOTS {
        store = anchors.extend_recent(store, occupancy - 1, occupancy)?;
        let root = (0x5eed_0000u64).to_string();
        let gas = probe.check_gas(&store, 1, 0, &root, far, 1_000_000)?;
        worst = worst.max(gas);
        best = best.min(gas);
    }
    for id in 0..RECENT_SLOTS {
        let root = (0x5eed_0000u64 + id).to_string();
        let gas = probe.check_gas(&store, 1, id, &root, far, 1_000_000)?;
        worst = worst.max(gas);
        best = best.min(gas);
    }

    // The epoch ring, the same way. Its retention rule refuses an entry a
    // whole ring behind the clock, so the clock is set to the epoch the
    // occupancy corresponds to rather than to a fixed late time.
    let mut store = empty;
    for occupancy in 1..=EPOCH_SLOTS {
        store = anchors.extend_epoch(store, occupancy - 1, occupancy)?;
        let root = (0x5eed_0000u64).to_string();
        let gas = probe.check_gas(&store, 2, 0, &root, far, 30 * (occupancy - 1))?;
        worst = worst.max(gas);
        best = best.min(gas);
    }
    let now = 30 * (EPOCH_SLOTS - 1);
    for id in 0..EPOCH_SLOTS {
        let root = (0x5eed_0000u64 + id).to_string();
        let gas = probe.check_gas(&store, 2, id, &root, far, now)?;
        worst = worst.max(gas);
        best = best.min(gas);
    }

    Ok(Span {
        name: "anchor check",
        domain: format!(
            "the current root, and every key at every occupancy of both rings \
             ({RECENT_SLOTS} recent, {EPOCH_SLOTS} epoch)"
        ),
        calls,
        worst,
        best,
    })
}

/// What preserving a root can cost.
///
/// Two writes rather than one: the recent slot always, the epoch slot only
/// for the first mutation of a new epoch. The keys are independent of each
/// other -- one is the leaf counter modulo 4,096, the other the clock modulo
/// 2,880 -- so the worst is composed from each sweep's worst rather than
/// taken from a sweep of the pair, which would be twelve million points.
pub fn preserve_span(probe: &ComponentProbe, anchors: &AnchorProbe, calls: i64) -> Result<Span> {
    let far = "98765432109876543210987654321098765432109876543210";
    let empty = anchors.empty()?;

    // Every point measured below feeds both ends of the span. The floor has
    // to be at or under what the call costs in whatever state the measured
    // transaction happened to be in, and a floor taken from one chosen corner
    // rather than from everything seen is a floor that can sit too high --
    // which shrinks the bound rather than widening it.
    let mut worst = i64::MIN;
    let mut best = i64::MAX;

    // Empty rings with the epoch already checkpointed, so only the recent
    // slot is written: the cheapest shape the call has.
    let now = 30 * (EPOCH_SLOTS - 1);
    for key in [0u64, 1, 2_047, 4_095] {
        let gas = probe.preserve_gas(&empty, key, far, now, now / 30)?;
        worst = worst.max(gas);
        best = best.min(gas);
    }

    // Occupancy, one entry at a time, for each ring in turn.
    let mut store = empty;
    for occupancy in 1..=RECENT_SLOTS {
        store = anchors.extend_recent(store, occupancy - 1, occupancy)?;
        let gas = probe.preserve_gas(&store, 0, far, now, now / 30 - 1)?;
        worst = worst.max(gas);
        best = best.min(gas);
    }
    for occupancy in 1..=EPOCH_SLOTS {
        store = anchors.extend_epoch(store, occupancy - 1, occupancy)?;
        let gas = probe.preserve_gas(&store, 0, far, now, now / 30 - 1)?;
        worst = worst.max(gas);
        best = best.min(gas);
    }
    let full = store;

    // Both rings full and the epoch turning over: the dearest branch. Every
    // recent key, then every epoch key, and the two marginals added, because
    // the pair's product is twelve million points and the sum of the
    // marginals is an upper bound on it.
    let reference = probe.preserve_gas(&full, 0, far, now, now / 30 - 1)?;
    let mut recent_worst = reference;
    for key in 0..RECENT_SLOTS {
        let gas = probe.preserve_gas(&full, key, far, now, now / 30 - 1)?;
        recent_worst = recent_worst.max(gas);
        best = best.min(gas);
    }
    let mut epoch_worst = reference;
    for epoch in 0..EPOCH_SLOTS {
        let clock = 30 * epoch;
        // `last_epoch` one behind the clock, so the checkpoint is written.
        let last = if epoch == 0 { u64::from(u32::MAX) } else { epoch - 1 };
        let gas = probe.preserve_gas(&full, 0, far, clock, last)?;
        epoch_worst = epoch_worst.max(gas);
        best = best.min(gas);
    }
    worst = worst.max(reference + (recent_worst - reference) + (epoch_worst - reference));

    Ok(Span {
        name: "anchor preserve",
        domain: format!(
            "both branches, every occupancy of both rings, and every key of each \
             ({RECENT_SLOTS} recent, {EPOCH_SLOTS} epoch) with the two marginals added"
        ),
        calls,
        worst,
        best,
    })
}

/// What writing the state cell and reading it back can cost.
///
/// Two of its fields are `Coins`, which is a variable-length encoding, so the
/// question is whether a pool owing a thousand nanotos writes itself down
/// more cheaply than one owing the supply. It does not -- the instructions
/// are fixed-price and the cell does not overflow -- but that is what the
/// span is for.
#[allow(clippy::too_many_arguments)]
pub fn state_span(
    probe: &ComponentProbe,
    frontier: &FrontierProbe,
    anchors: &AnchorProbe,
    config: &Cell,
    vk: &Cell,
    calls: i64,
) -> Result<Span> {
    // The largest a `Coins` field can hold, and the smallest.
    let max_coins = (1u128 << 120) - 1;
    let stores = [frontier.genesis()?, frontier.fill(1)?, frontier.fill(COMMITMENT_CAPACITY - 1)?];
    let rings = [anchors.empty()?, anchors.fill(RECENT_SLOTS, EPOCH_SLOTS)?];

    let mut worst = i64::MIN;
    let mut best = i64::MAX;
    for store in &stores {
        for ring in &rings {
            for (liability, floor) in
                [("0", "0"), (&max_coins.to_string()[..], &max_coins.to_string()[..])]
            {
                for index in [0u64, COMMITMENT_CAPACITY - 1] {
                    let gas = probe
                        .state_round_trip_gas(liability, floor, index, store, ring, config, vk)?;
                    worst = worst.max(gas);
                    best = best.min(gas);
                }
            }
        }
    }

    Ok(Span {
        name: "state round trip",
        domain: "empty and full rings, three frontier stores, both ends of the Coins range \
                 and of the leaf counter"
            .to_string(),
        calls,
        worst,
        best,
    })
}

/// The bound, and the table that shows where it came from.
pub fn derive(path: &str, measured: i64, spans: &[Span]) -> (i64, String) {
    let mut report = format!("\n{path}: a measured transaction cost {measured} gas.\n");
    let mut bound = measured;
    for span in spans {
        report.push_str(&format!(
            "  {:<18} x{}  {:>8} .. {:>8}  adds {:>7}   [{}]\n",
            span.name,
            span.calls,
            span.best,
            span.worst,
            span.slack(),
            span.domain
        ));
        bound += span.slack();
    }
    report.push_str(&format!(
        "  {:<18}      {:>8} -> bound {}, ceiling by section 14.1 {}\n",
        "total",
        measured,
        bound,
        ceiling_for(bound)
    ));
    (bound, report)
}
