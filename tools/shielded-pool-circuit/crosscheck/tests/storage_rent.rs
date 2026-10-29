//! What the pool costs to keep, and how long its reserve floor pays for that.
//!
//! Section 14.3's `reserve_floor` is the balance a pool must hold above what it
//! owes note-holders. Its job is to absorb what the chain takes whether or not
//! anybody uses the pool: this workchain charges storage rent per cell and per
//! bit per second, so a pool nobody touches is losing money the whole time.
//!
//! The floor is 5 TOS and nobody has ever derived that number. This measures
//! the two halves of the derivation -- what the account actually occupies, and
//! what the zerostate charges for occupying it -- and reports how long the
//! floor lasts.

use shielded_pool_circuit_crosscheck::anchor_probe::{AnchorProbe, EPOCH_SLOTS, RECENT_SLOTS};
use shielded_pool_circuit_crosscheck::frontier_probe::FrontierProbe;
use shielded_pool_circuit_crosscheck::pool::{Pool, DEPLOYED_DENOMINATIONS};

/// The basechain `(bit_price_ps, cell_price_ps)` of the one non-comment
/// `config.storage_prices!` line in `gen-zerostate.fif`: bit_price_ps,
/// cell_price_ps, then the masterchain pair. The pool is a basechain contract,
/// so the first two are its prices. Both are per unit per second, scaled by
/// 2^16. Read from the template, so the sizing follows the genesis it reports on.
fn basechain_storage_prices() -> (u128, u128) {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../crypto/smartcont/gen-zerostate.fif"
    ));
    let mut lines = source.lines().map(str::trim).filter_map(|line| {
        if line.starts_with("//") {
            return None;
        }
        line.strip_suffix(" config.storage_prices!")
    });
    let line = lines.next().expect("Genesis must set ConfigParam 18");
    assert!(lines.next().is_none(), "Genesis ConfigParam 18 must be unambiguous");
    let mut values = line
        .split_whitespace()
        .map(|word| word.parse::<u128>().expect("storage prices must be explicit integers"));
    let bit = values.next().expect("basechain bit price");
    let cell = values.next().expect("basechain cell price");
    (bit, cell)
}
const SCALE: u128 = 1 << 16;

const TOS: u128 = 1_000_000_000;

/// Read from the crate that puts it in the genesis store. A copy here would
/// report how long a floor this file invented lasts.
fn reserve_floor() -> u128 {
    shielded_pool_genesis::RESERVE_FLOOR
}

fn report(what: &str, pool: &Pool) -> u128 {
    // The cached `storage_info` is written by the executor when a transaction
    // touches the account, so on a state substituted underneath it, it is the
    // *previous* state's size. Recomputing it is the difference between
    // measuring the pool and measuring what the pool used to be -- the first
    // version of this test reported the genesis figure for a full-ring pool
    // and the two lines agreed to the bit, which is what gave it away.
    let mut account =
        pool.bc.get_account(&pool.addr).expect("the pool has an account").clone();
    account.update_storage_stat(0).expect("recompute the account's storage stat");
    let info = account.storage_info().expect("an active account has storage info");
    let cells = u128::from(info.used().cells());
    let bits = u128::from(info.used().bits());

    // The price is per unit per second scaled by 2^16, so the unscaled rate is
    // this over 65,536.
    let (bit_price_ps, cell_price_ps) = basechain_storage_prices();
    let per_second_scaled = cells * cell_price_ps + bits * bit_price_ps;
    let per_day = per_second_scaled * 86_400 / SCALE;
    let per_year = per_second_scaled * 31_557_600 / SCALE;

    eprintln!(
        "{what}:\n  {cells} cells, {bits} bits\n  {per_day} nanotos/day  ({:.6} TOS)\n  \
         {per_year} nanotos/year ({:.6} TOS)",
        per_day as f64 / TOS as f64,
        per_year as f64 / TOS as f64,
    );
    if per_year > 0 {
        // Seconds the floor buys, then the same number in years.
        let seconds = reserve_floor() * SCALE / per_second_scaled;
        eprintln!(
            "  a {} TOS floor pays for {seconds} seconds = {:.1} days = {:.1} years",
            reserve_floor() / TOS,
            seconds as f64 / 86_400.0,
            seconds as f64 / 31_557_600.0,
        );
    }
    per_year
}

#[test]
#[ignore = "storage sizing; run it when the reserve floor is being set"]
fn how_long_the_reserve_floor_pays_the_rent() {
    let mut pool = Pool::deploy_with_denominations(&DEPLOYED_DENOMINATIONS).expect("a pool");
    let genesis = report("a pool at genesis", &pool);

    // The largest a pool's state gets: both anchor rings full, which is where
    // they stay for the rest of its life. The frontier does not grow.
    let frontier = FrontierProbe::deploy().expect("frontier probe").fill(RECENT_SLOTS).expect("f");
    let anchors = AnchorProbe::deploy()
        .expect("anchor probe")
        .fill(RECENT_SLOTS, EPOCH_SLOTS)
        .expect("full rings");
    pool.age_to(RECENT_SLOTS, frontier, anchors).expect("age the pool");
    let full = report("a pool with both rings full (its steady state)", &pool);

    assert!(full > 0, "the account was priced at nothing, so nothing was measured");
    assert!(
        full > genesis,
        "a pool with both anchor rings full was priced at {full} nanotos a year and one at \
         genesis at {genesis}. Filling 4,096 and 2,880 dictionary slots cannot leave the \
         account the same size, so the figure being read is not this pool's."
    );
}
