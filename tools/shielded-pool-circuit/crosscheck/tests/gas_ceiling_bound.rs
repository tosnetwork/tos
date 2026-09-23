/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Every gas ceiling against a derived upper bound rather than a sampled
//! maximum.
//!
//! What was here before -- and in the contract's own comment -- was the
//! largest figure a handful of built transactions had produced, called a
//! maximum. It never was one. A transact ranges over a leaf index with four
//! billion values, two ring occupancies, three anchor kinds, four
//! denominations and two nullifier orders, and no number of points in that
//! product proves anything about the points not visited. The evidence for
//! that is in the repository's own history: the ceilings were first set from
//! a pool that had just been deployed, and a pool refused its thirty-fifth
//! deposit; they were re-set from a pool with one denomination, and the
//! figure was 4,305 low; they were re-set from the two ends of a pool's life,
//! and the dearest state turned out to be neither end.
//!
//! This derives a bound instead. Each handler is a straight line whose
//! variable calls read only their own arguments, so
//!
//!     cost(any legal path) <= cost(one measured transaction)
//!                             + sum over calls of (worst - best)
//!
//! and each (worst, best) is the span of one function over one domain small
//! enough to walk end to end. The corner the sum describes is reachable by
//! nobody, which is the point: it is an upper bound, and the asymmetry of
//! being wrong says to take it. A ceiling too high charges a sender for gas
//! nobody spent. A ceiling too low strands a withdrawal in a contract whose
//! code hash is its address.
//!
//! Two things the bound rests on are checked rather than assumed. The
//! twelve-level append is composed from its levels, and the composition is
//! put against real appends at indices whose digits differ -- if the levels
//! were not independent the prediction would miss. And the spread between
//! every whole transaction this suite measures must fit inside the spread the
//! spans predict; a variable cost nobody enumerated would show up there as a
//! transaction moving further than the parts allow.

mod support;

use shielded_pool_circuit::field::Fr;
use shielded_pool_circuit::wire;
use shielded_pool_circuit_crosscheck::anchor_probe::{AnchorProbe, EPOCH_SLOTS, RECENT_SLOTS};
use shielded_pool_circuit_crosscheck::ceiling::{
    append_additivity_error, append_span, ceiling_for, check_span, denomination_span, derive,
    insert_span, preserve_span, state_span, Span,
};
use shielded_pool_circuit_crosscheck::components::ComponentProbe;
use shielded_pool_circuit_crosscheck::frontier_probe::FrontierProbe;
use shielded_pool_circuit_crosscheck::pool::{
    contract_gas_ceiling, Pool, DENOMINATION, DEPLOYED_DENOMINATIONS,
};
use shielded_pool_circuit_crosscheck::wire::byte_chain;

use support::{Age, Withdrawal};

/// Far above anything a path may spend, so what stops a measured transaction
/// is the contract's own ceiling and not the credit its message carried.
const COMPUTE_FEE: u64 = 2_000_000_000;

fn ceiling(name: &str) -> i64 {
    contract_gas_ceiling(name).unwrap_or_else(|error| panic!("the contract's {name}: {error}"))
}

/// Every span, measured once, because filling both rings entry by entry is
/// the expensive part of this file and no path needs it twice.
struct Spans {
    denomination: Span,
    append: Span,
    insert: Span,
    check: Span,
    preserve: Span,
    state: Span,
}

/// The same span with a different call count, for a path that makes the call
/// a different number of times.
fn times(span: &Span, calls: i64) -> Span {
    Span { calls, ..span.clone() }
}

fn measure_spans() -> Spans {
    let probe = ComponentProbe::deploy().expect("the component probe");
    let frontier = FrontierProbe::deploy().expect("the frontier probe");
    let anchors = AnchorProbe::deploy().expect("the anchor probe");
    let pool = Pool::deploy_with_denominations(&DEPLOYED_DENOMINATIONS).expect("a pool");
    let config = pool.config_cell().expect("the config");
    let vk = pool.vk_cell().expect("the verifying key");

    let denomination = denomination_span(&probe, &config, &DEPLOYED_DENOMINATIONS, 1)
        .expect("the denomination span");
    let (append, table) = append_span(&probe, &frontier, 1).expect("the append span");

    // The composition is only usable while it predicts. These indices have
    // digits that differ from each other and from the ones the table was
    // built at: the capacity's last index, a run of sixes, a mixture.
    let (error, rows) = append_additivity_error(
        &probe,
        &frontier,
        &table,
        &[1, 48, 342, 2_400, 16_807, 1_000_000, 3_954_653_485, 4_294_967_295],
    )
    .expect("the additivity check");
    for (index, measured, predicted) in &rows {
        eprintln!("append at {index:>12}: {measured} measured, {predicted} composed");
    }
    assert_eq!(
        error, 0,
        "composing the append from its twelve levels is off by {error} gas, so a level's cost \
         depends on something other than its own digit and the bound below is a sum of terms \
         that do not add. Nothing here is usable until that is understood."
    );

    // The reading the old ceiling rested on -- that a higher leaf index is
    // always a cheaper append, so the two ends of a pool's life bracket
    // everything between them -- is false, and the same rows say so. Branch
    // selection is by base-seven digit, and a digit goes back to zero at
    // every power of seven; digit zero is the dearest of the seven, because
    // it is the one case the chain of comparisons resolves last. So 16,807 is
    // 7^5, one digit set and eleven zeros, and it costs more than 342, which
    // is forty-nine times smaller and three sixes.
    let at = |index: u64| {
        rows.iter().find(|(i, _, _)| *i == index).map(|(_, measured, _)| *measured).expect("a row")
    };
    assert!(
        at(16_807) > at(342),
        "appending at index 16,807 costs {} and at 342 it costs {}. If a higher index really \
         were always cheaper, a ceiling taken from the two ends of a pool's life would bracket \
         everything between them, and the composition below would be answering a question \
         nobody needs to ask.",
        at(16_807),
        at(342)
    );

    let insert = insert_span(&probe, 1).expect("the insert span");
    let check = check_span(&probe, &anchors, 1).expect("the anchor check span");
    let preserve = preserve_span(&probe, &anchors, 1).expect("the preserve span");
    let state = state_span(&probe, &frontier, &anchors, &config, &vk, 1).expect("the state span");

    Spans { denomination, append, insert, check, preserve, state }
}

/// One deposit into a pool with the deployed configuration.
fn measured_deposit() -> i64 {
    let mut pool = Pool::deploy_with_denominations(&DEPLOYED_DENOMINATIONS).expect("a pool");
    let bytes: Vec<u8> = vec![0x5a; wire::OUTPUT_DATA_BYTES];
    let body = Pool::deposit_body(
        DENOMINATION,
        Fr::from(0x1234_5678u64),
        byte_chain(&bytes).expect("a payload"),
    )
    .expect("a deposit body");
    let (exit, gas) = pool.run(DENOMINATION + COMPUTE_FEE, body).expect("the deposit");
    assert_eq!(exit, 0, "the deposit the bound is measured from was refused");
    gas
}

/// One top-up, which reads no state at all.
fn measured_topup() -> i64 {
    let mut pool = Pool::deploy_with_denominations(&DEPLOYED_DENOMINATIONS).expect("a pool");
    let (exit, gas) =
        pool.run(COMPUTE_FEE, Pool::topup_body(1).expect("a top-up body")).expect("the top-up");
    assert_eq!(exit, 0, "the top-up the bound is measured from was refused");
    gas
}

/// A withdrawal and the bounce that follows it, at one age of the pool.
fn measured_withdrawal(age: Option<Age>) -> support::Outcome {
    let outcome = support::run(&Withdrawal {
        denominations: &DEPLOYED_DENOMINATIONS,
        amount: DENOMINATION,
        destination_name: "bound_refuser",
        destination_source: support::REFUSER,
        age,
        before_transact: Default::default(),
    });
    assert_eq!(outcome.exit, 0, "the withdrawal the bound is measured from was refused");
    assert_eq!(outcome.recovery_exit, 0, "the bounce the bound is measured from was refused");
    outcome
}

/// The whole derivation, in one test, because the spans cost minutes to
/// measure and all four ceilings are read off the same set.
///
/// The transact bound is derived from a withdrawal rather than a transfer.
/// The two modes are the same code but for the bodies of two
/// `if (public_amount_out > 0)` blocks -- the denomination walk and the
/// payout -- so a withdrawal costs everything a transfer costs and more, and
/// a bound that covers the withdrawal covers both. `valid_proof_e2e`
/// measures the transfer against the same ceiling.
#[test]
fn the_ceilings_cover_a_derived_upper_bound() {
    let spans = measure_spans();

    // --- the spans are spans ----------------------------------------------
    //
    // Section 14.1's rule rounds to ten thousand gas, so a span worth a few
    // hundred can be dropped from the sum below without moving any ceiling.
    // That would leave the cheap domains -- the two nullifier orders, the
    // four denominations -- covered by nothing at all. So each is required to
    // have found more than one price: a sweep reduced to a single point
    // reports `worst == best` and is caught here rather than nowhere.
    for span in [
        &spans.denomination,
        &spans.append,
        &spans.insert,
        &spans.check,
        &spans.preserve,
    ] {
        assert!(
            span.worst > span.best,
            "the {} span priced everything at {} gas. Its domain has more than one point in \
             it, so either the sweep no longer walks the domain or the cost stopped depending \
             on it -- and the first is a hole the ceilings would not show.",
            span.name,
            span.worst
        );
    }
    // The state cell is the exception, and it is a result rather than an
    // omission: two of its fields are `Coins`, a variable-length encoding, so
    // the question was real. The instructions are fixed-price and the cell
    // does not overflow, so a pool owing the supply writes itself down for
    // exactly what a pool owing nothing does. If that ever stops being true
    // this is where it shows.
    assert_eq!(
        spans.state.worst, spans.state.best,
        "the state round trip now costs between {} and {} gas depending on what is in it. It \
         used to be flat, and the ceilings were derived on the strength of that.",
        spans.state.best, spans.state.worst
    );

    // --- the reserve top-up ----------------------------------------------
    //
    // No state is read, no dictionary is touched and no tree moves: its
    // domain is the query id, which is a fixed sixty-four bits. There is
    // nothing to span, so the bound is the measurement.
    let topup = measured_topup();
    let (topup_bound, report) = derive("top-up", topup, &[]);
    eprint!("{report}");

    // --- the deposit ------------------------------------------------------
    let deposit = measured_deposit();
    let deposit_spans = [
        times(&spans.denomination, 1),
        times(&spans.preserve, 1),
        times(&spans.append, 1),
        times(&spans.state, 1),
    ];
    let (deposit_bound, report) = derive("deposit", deposit, &deposit_spans);
    eprint!("{report}");

    // --- the transact and its bounce --------------------------------------
    let fresh = measured_withdrawal(None);
    let aged = measured_withdrawal(Some(Age {
        index: RECENT_SLOTS,
        recent: RECENT_SLOTS,
        epoch: EPOCH_SLOTS,
    }));

    // Any measured transaction makes the inequality hold, so the tightest
    // bound comes from the cheapest one measured.
    let transact = fresh.gas.min(aged.gas);
    let transact_spans = [
        times(&spans.denomination, 1),
        times(&spans.check, 1),
        times(&spans.preserve, 1),
        times(&spans.append, 3),
        times(&spans.insert, 2),
        times(&spans.state, 1),
    ];
    let (transact_bound, report) = derive("transact (withdrawal)", transact, &transact_spans);
    eprint!("{report}");

    let bounce = fresh.recovery_gas.min(aged.recovery_gas);
    let bounce_spans =
        [times(&spans.preserve, 1), times(&spans.append, 1), times(&spans.state, 1)];
    let (bounce_bound, report) = derive("bounce", bounce, &bounce_spans);
    eprint!("{report}");

    // --- the instrument ----------------------------------------------------
    //
    // A cost that moves with the pool's state and is not in the spans above
    // would let a whole transaction move further than the parts allow. Both
    // withdrawals here are real, at opposite ends of what a pool can be, and
    // the distance between them has to fit.
    let predicted_spread: i64 = transact_spans.iter().map(Span::slack).sum();
    let observed_spread = (fresh.gas - aged.gas).abs();
    eprintln!(
        "two real withdrawals are {observed_spread} gas apart; the spans allow {predicted_spread}"
    );
    assert!(
        observed_spread <= predicted_spread,
        "two whole withdrawals differ by {observed_spread} gas and the spans only account for \
         {predicted_spread}. Something whose cost depends on the pool's state is not in the \
         decomposition, and the bound is not a bound."
    );

    // And the bound has to hold against every whole transaction here, not
    // only against the one it was derived from. The line above implies this,
    // but an implication is not an instrument: this is the assertion that
    // goes red if a real transaction ever climbs past the bound.
    for (name, measured, bound) in [
        ("the fresh withdrawal", fresh.gas, transact_bound),
        ("the aged withdrawal", aged.gas, transact_bound),
        ("the fresh bounce", fresh.recovery_gas, bounce_bound),
        ("the aged bounce", aged.recovery_gas, bounce_bound),
    ] {
        assert!(
            measured <= bound,
            "{name} cost {measured} gas and the derived bound is {bound}. A bound a real \
             transaction exceeds is not a bound."
        );
    }

    // --- and the ceilings --------------------------------------------------
    for (name, measured, bound) in [
        ("topup_gas_ceiling", topup, topup_bound),
        ("deposit_gas_ceiling", deposit, deposit_bound),
        ("transact_gas_ceiling", transact, transact_bound),
        ("bounce_gas_ceiling", bounce, bounce_bound),
    ] {
        let frozen = ceiling(name);
        let required = ceiling_for(bound);
        eprintln!(
            "{name}: {measured} measured, {bound} bound, {required} required, {frozen} frozen"
        );
        // Section 14.1 states the rule as an equality, and it is read as one
        // here. Below it a legal path can be cut off in a contract whose
        // code hash is its address; above it every sender on the path pays
        // `get_compute_fee(ceiling)` for compute nobody spends. Reading it
        // as an inequality would also leave the derivation toothless: with
        // ten thousand gas of slack in either direction, a term dropped from
        // the sum would change no verdict here.
        assert_eq!(
            frozen, required,
            "{name} is {frozen}; section 14.1's rule applied to the derived bound of {bound} \
             gives {required}. Measured {measured}."
        );
    }
}
