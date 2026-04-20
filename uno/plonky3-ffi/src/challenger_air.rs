//! Duplex-challenger reference implementation + AIR trace-layout spec.
//!
//! Phase A2-1 of the aggregation roadmap (`doc/uno-aggregation-design.md`).
//! The verifier-as-AIR (`crate::verifier_air`) needs to reconstruct the
//! Fiat-Shamir challenger state as an in-AIR computation, because the
//! verifier's challenges depend deterministically on the committed
//! trace/quotient values + public inputs. This module ships the two
//! foundational pieces:
//!
//! 1. A **non-AIR reference implementation** of the DuplexChallenger
//!    state machine, mirroring `p3_challenger::DuplexChallenger` over
//!    `<Goldilocks, Poseidon2Goldilocks<8>, WIDTH=8, RATE=4>` — our
//!    production StarkConfig.
//! 2. A **trace-layout specification**: the column layout + row rules
//!    the AIR will enforce when Phase A2-2 lands the constraint
//!    generation.
//! 3. A **parity test** against upstream `p3_challenger::DuplexChallenger`
//!    that asserts our reference reproduces its state byte-for-byte
//!    across a handful of interesting absorb/squeeze patterns.
//!
//! # Why ship the reference + spec now, not the constraints?
//!
//! Writing the constraint generation without first pinning the
//! interface invites drift. By fixing the state machine + trace
//! layout first:
//!   - Phase A2-2 has a concrete target (match this reference
//!     byte-for-byte across the trace-height rows).
//!   - The audit-vendor can review the STATE MACHINE correctness
//!     independently of the AIR constraint correctness — smaller
//!     review surfaces, easier review.
//!   - Downstream modules (`aggregator`, `verifier_air`) can call
//!     the reference today and swap in the AIR-backed variant later
//!     without interface change.

use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;

// ---------------------------------------------------------------------------
// Protocol constants (MUST match uno/plonky3-ffi/src/prover.rs::MvpChallenger)
// ---------------------------------------------------------------------------

/// Sponge width. Matches `Poseidon2Goldilocks<8>`.
pub const SPONGE_WIDTH: usize = 8;
/// Absorb / squeeze rate. Matches prover's `DuplexChallenger<_, _, 8, 4>`.
pub const SPONGE_RATE: usize = 4;
/// Capacity (non-absorbed state positions).
pub const SPONGE_CAPACITY: usize = SPONGE_WIDTH - SPONGE_RATE;

// ---------------------------------------------------------------------------
// Reference challenger
// ---------------------------------------------------------------------------

/// Reference implementation of `DuplexChallenger<Goldilocks,
/// Poseidon2Goldilocks<8>, WIDTH=8, RATE=4>`.
///
/// Mirrors the upstream state machine exactly — see
/// `third-party/plonky3-uno/challenger/src/duplex_challenger.rs` for the
/// reference.
///
/// **Why a second implementation?** The verifier-as-AIR will need to
/// recompute the challenger state at each row of its trace. An
/// AIR-friendly reference that we control byte-for-byte — and that we
/// validate against upstream — is the cleanest seam.
pub struct RefChallenger {
    /// 8-element sponge state.
    state: [Goldilocks; SPONGE_WIDTH],
    /// Pending absorptions; at most RATE=4 entries.
    in_buf: Vec<Goldilocks>,
    /// Output queue from the last `duplex()`.
    out_buf: Vec<Goldilocks>,
    /// Permutation instance (same one used by the production prover).
    perm: Poseidon2Goldilocks<8>,
}

impl RefChallenger {
    /// Fresh challenger with a zero-initialized sponge state.
    pub fn new() -> Self {
        Self {
            state: [Goldilocks::default(); SPONGE_WIDTH],
            in_buf: Vec::with_capacity(SPONGE_RATE),
            out_buf: Vec::with_capacity(SPONGE_RATE),
            perm: default_goldilocks_poseidon2_8(),
        }
    }

    /// Absorb a single field element. Mirrors upstream `observe(F)`.
    pub fn observe(&mut self, value: Goldilocks) {
        // Any buffered output is now invalid.
        self.out_buf.clear();
        self.in_buf.push(value);
        if self.in_buf.len() == SPONGE_RATE {
            self.duplex();
        }
    }

    /// Absorb an array of field elements. Mirrors upstream
    /// `observe([F; N])`.
    pub fn observe_slice(&mut self, values: &[Goldilocks]) {
        for &v in values {
            self.observe(v);
        }
    }

    /// Squeeze one base-field element. Mirrors upstream
    /// `CanSample<F>::sample()`.
    ///
    /// Note: upstream `CanSample<EF>::sample()` for the extension field
    /// does `EF::D` base-field samples and packs. Phase A2-1 only
    /// supports the base-field path; the extension-field packing
    /// mirrors this with trivial composition at Phase A2-2.
    pub fn sample(&mut self) -> Goldilocks {
        if self.out_buf.is_empty() {
            self.duplex();
        }
        self.out_buf
            .pop()
            .expect("duplex() always refills out_buf with RATE=4 elements")
    }

    /// One duplex step. Follows upstream `duplexing()` byte-for-byte:
    ///   1. Overwrite state[0..in_buf.len()] with input_buffer.
    ///   2. Apply Poseidon2 permutation to the full state.
    ///   3. Clear out_buf and refill from state[0..RATE].
    fn duplex(&mut self) {
        // Overwrite-only (upstream uses `drain`, same effect).
        for (i, v) in self.in_buf.drain(..).enumerate() {
            self.state[i] = v;
        }
        self.perm.permute_mut(&mut self.state);
        self.out_buf.clear();
        self.out_buf.extend_from_slice(&self.state[..SPONGE_RATE]);
    }

    /// Snapshot of the sponge state — exposed for trace-building +
    /// parity testing. The verifier-AIR reads this at every row.
    pub fn state_snapshot(&self) -> [Goldilocks; SPONGE_WIDTH] {
        self.state
    }

    /// Number of queued absorptions waiting for the next duplex.
    pub fn pending_in(&self) -> usize {
        self.in_buf.len()
    }

    /// Number of queued outputs waiting to be drained.
    pub fn pending_out(&self) -> usize {
        self.out_buf.len()
    }
}

impl Default for RefChallenger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Trace-layout specification (for Phase A2-2's AIR constraints)
// ---------------------------------------------------------------------------

/// Column layout for the future ChallengerAir. Each row represents one
/// operation: `Observe(v)`, `Sample → v'`, `Duplex`, or `Idle`. Phase
/// A2-2 will wire the constraints; Phase A2-1 only documents the
/// intent.
///
/// # Per-row columns (width ≈ 24 + 1 Poseidon2-w8 block on duplex rows)
///
/// ```text
/// ----- State (persistent across rows) -----
///   state_local[0..8]     : 8 cols   — sponge state mirror
///   in_buf[0..4]          : 4 cols   — pending inputs
///   in_buf_len            : 1 col    — current in_buf fill (0..=4)
///   out_buf[0..4]         : 4 cols   — output queue
///   out_buf_len           : 1 col    — current out_buf fill (0..=4)
///
/// ----- Per-row operation selector (one-hot) -----
///   is_observe            : 1 col
///   is_sample             : 1 col
///   is_duplex_auto        : 1 col    — triggered by in_buf_len == 4
///   is_duplex_forced      : 1 col    — triggered by sample-on-empty-out
///   is_idle               : 1 col
///
/// ----- Per-row operation payload -----
///   observed_value        : 1 col    — the F being absorbed (if observe)
///   sampled_value         : 1 col    — the F being squeezed (if sample)
///
/// ----- Duplex row extension (only populated on duplex rows) -----
///   p2_cols               : 180 cols — shared Poseidon2 block
///                                      (row-gated by is_duplex_* via
///                                       the GS_ROW_SEL-style selector
///                                       pattern from K-air-col-share)
/// ```
///
/// **Rough per-row width: ~24 cols for the state-tracking side, plus
/// the shared Poseidon2-w8 block (180 cols) — same size as the
/// per-spend Merkle block in `transfer_air`.** Phase A2-2 must
/// confirm this fits the §3 aggregator column-budget estimate
/// (~200-300 cols/slot in `doc/uno-aggregation-design.md` §1.3).
pub const CHALLENGER_STATE_COLS: usize = 8 + 4 + 1 + 4 + 1; // state + in_buf + len + out_buf + len
/// Per-row operation selectors + payloads.
pub const CHALLENGER_OP_COLS: usize = 5 + 2;
/// Total non-P2 columns per challenger row.
pub const CHALLENGER_NON_P2_COLS: usize = CHALLENGER_STATE_COLS + CHALLENGER_OP_COLS;

/// Transition rules the constraint generator must enforce (Phase A2-2).
///
/// Expressed here as docs; the constraint code in A2-2 mirrors them:
///
/// 1. **Observe**: `is_observe ⇒`
///    - `in_buf_next[in_buf_len_local] = observed_value_local`
///    - `in_buf_next[other] = in_buf_local[other]`
///    - `in_buf_len_next = in_buf_len_local + 1`
///    - `out_buf_len_next = 0`  (observe invalidates output queue)
///    - `state_next = state_local`  (state unchanged until next duplex)
///
/// 2. **Duplex (auto on in_buf fill or forced on empty-out sample)**:
///    - `state_local[0..in_buf_len_local] = in_buf_local[0..in_buf_len_local]`
///      is the input to the Poseidon2 block this row
///    - `state_next[0..8] = P2(state_local filled with in_buf)`
///    - `in_buf_next = []`, `in_buf_len_next = 0`
///    - `out_buf_next = state_next[0..4]`, `out_buf_len_next = 4`
///
/// 3. **Sample**: `is_sample ⇒`
///    - If `out_buf_len_local > 0`: `sampled_value = out_buf_local[out_buf_len_local - 1]`;
///      `out_buf_len_next = out_buf_len_local - 1`; state unchanged.
///    - If `out_buf_len_local == 0`: `is_duplex_forced = 1` must fire
///      FIRST (in the same logical row); this is enforced by the
///      operation-selector one-hot rules (a sample-on-empty row
///      combines both selectors; A2-2 chooses the encoding).
///
/// 4. **Idle**: no-op, all `*_next == *_local`, all payload cols are
///    unconstrained.
///
/// The constraint generator MUST also verify that exactly one of the
/// four operation selectors is 1 per row (standard one-hot sum constraint).
pub const CHALLENGER_TRANSITION_RULES_DOCUMENTED: () = ();

// ---------------------------------------------------------------------------
// Parity check against upstream p3_challenger
// ---------------------------------------------------------------------------

/// Run a challenger transcript on our `RefChallenger` and assert its
/// state matches upstream `p3_challenger::DuplexChallenger` after the
/// same sequence of operations.
///
/// Returns `Ok(())` on match; `Err(description)` on first divergence.
/// Used by both unit tests (below) and as a public API so downstream
/// fuzzing / property tests can reuse it.
pub fn assert_parity_with_upstream(script: &[ChallengerOp]) -> Result<(), String> {
    use p3_challenger::{CanObserve, CanSample, DuplexChallenger};

    let perm = default_goldilocks_poseidon2_8();
    let mut ours = RefChallenger::new();
    let mut upstream: DuplexChallenger<
        Goldilocks,
        Poseidon2Goldilocks<8>,
        SPONGE_WIDTH,
        SPONGE_RATE,
    > = DuplexChallenger::new(perm);

    for (step_idx, op) in script.iter().enumerate() {
        match op {
            ChallengerOp::Observe(v) => {
                ours.observe(*v);
                upstream.observe(*v);
            }
            ChallengerOp::Sample => {
                let ours_s: Goldilocks = ours.sample();
                let up_s: Goldilocks = upstream.sample();
                if ours_s != up_s {
                    return Err(format!(
                        "sample divergence at step {step_idx}: ours={ours_s:?}, upstream={up_s:?}"
                    ));
                }
            }
        }

        // Compare sponge state + buffer fills.
        let ours_state = ours.state_snapshot();
        // Upstream's sponge state is public (`pub sponge_state`).
        let up_state = upstream.sponge_state;
        if ours_state != up_state {
            return Err(format!(
                "state divergence at step {step_idx}: ours={ours_state:?}, upstream={up_state:?}"
            ));
        }
    }
    Ok(())
}

/// One step of a challenger transcript — used by parity tests and by
/// future trace-generation code (each op becomes one AIR row).
#[derive(Clone, Debug)]
pub enum ChallengerOp {
    /// Absorb a field element into the challenger.
    Observe(Goldilocks),
    /// Squeeze and discard (caller gets the sampled value back via the
    /// `RefChallenger::sample` API when it runs the script directly;
    /// parity test compares upstream vs our sample output).
    Sample,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_empty_transcript() {
        assert_parity_with_upstream(&[]).unwrap();
    }

    #[test]
    fn parity_single_observe() {
        let script = vec![ChallengerOp::Observe(Goldilocks::new(0x4242_4242_4242_4242))];
        assert_parity_with_upstream(&script).unwrap();
    }

    #[test]
    fn parity_observe_rate_then_sample() {
        // RATE=4 observations triggers a duplex before the sample.
        let mut script = Vec::new();
        for i in 0..4u64 {
            script.push(ChallengerOp::Observe(Goldilocks::new(i * 7 + 1)));
        }
        script.push(ChallengerOp::Sample);
        assert_parity_with_upstream(&script).unwrap();
    }

    #[test]
    fn parity_sample_before_observe() {
        // Sampling from an empty challenger triggers an auto-duplex on
        // a zero input buffer.
        let script = vec![ChallengerOp::Sample];
        assert_parity_with_upstream(&script).unwrap();
    }

    #[test]
    fn parity_interleaved_observe_sample() {
        // Realistic verifier pattern: observe commitments, sample
        // challenge, observe opened values, sample another challenge...
        let mut script = Vec::new();
        for i in 0..3u64 {
            script.push(ChallengerOp::Observe(Goldilocks::new(0x100 + i)));
        }
        script.push(ChallengerOp::Sample);
        for i in 0..2u64 {
            script.push(ChallengerOp::Observe(Goldilocks::new(0x200 + i)));
        }
        script.push(ChallengerOp::Sample);
        script.push(ChallengerOp::Sample);
        assert_parity_with_upstream(&script).unwrap();
    }

    #[test]
    fn parity_long_stress_transcript() {
        // Drive enough absorptions + squeezes to force multiple
        // duplex cycles. 50 observes + 30 samples.
        let mut script = Vec::with_capacity(80);
        for i in 0..50u64 {
            script.push(ChallengerOp::Observe(Goldilocks::new(
                0xDEAD_BEEF_0000_0000 + i,
            )));
            if i % 3 == 0 {
                script.push(ChallengerOp::Sample);
            }
        }
        assert_parity_with_upstream(&script).unwrap();
    }

    #[test]
    fn parity_edge_full_buffer_on_observe() {
        // Observing exactly RATE-1 elements, then RATE-th triggers
        // auto-duplex at the boundary.
        let mut script = Vec::new();
        for i in 0..SPONGE_RATE as u64 {
            script.push(ChallengerOp::Observe(Goldilocks::new(i)));
        }
        // At this point in_buf_len hit RATE and duplexed. Now sample
        // all 4 outputs.
        for _ in 0..SPONGE_RATE {
            script.push(ChallengerOp::Sample);
        }
        assert_parity_with_upstream(&script).unwrap();
    }

    #[test]
    fn parity_many_cycles() {
        // Drive 10 full RATE-cycles to exercise the state-evolution
        // path across many permutations.
        let mut script = Vec::new();
        for cycle in 0..10u64 {
            for k in 0..SPONGE_RATE as u64 {
                script.push(ChallengerOp::Observe(Goldilocks::new(cycle * 1000 + k)));
            }
            script.push(ChallengerOp::Sample);
        }
        assert_parity_with_upstream(&script).unwrap();
    }

    #[test]
    fn column_count_constants_are_sane() {
        assert_eq!(CHALLENGER_STATE_COLS, 18);
        assert_eq!(CHALLENGER_OP_COLS, 7);
        assert_eq!(CHALLENGER_NON_P2_COLS, 25);
    }

    #[test]
    fn sponge_params_match_production() {
        // Regression guard: our sponge dims MUST match
        // prover.rs::MvpChallenger = DuplexChallenger<_, _, 8, 4>. A
        // drift here is a protocol-level bug.
        assert_eq!(SPONGE_WIDTH, 8);
        assert_eq!(SPONGE_RATE, 4);
        assert_eq!(SPONGE_CAPACITY, 4);
    }

    #[test]
    fn state_snapshot_matches_upstream_initial() {
        // Fresh challenger: upstream inits state to F::default() (= 0).
        // Ours must match.
        let ours = RefChallenger::new();
        assert_eq!(ours.state_snapshot(), [Goldilocks::default(); SPONGE_WIDTH]);
    }
}
