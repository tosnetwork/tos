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

// ---------------------------------------------------------------------------
// Trace builder (Phase A2-2a)
// ---------------------------------------------------------------------------
//
// The trace is a row-major matrix with `CHALLENGER_AIR_WIDTH` columns.
// Each trace row corresponds to exactly one physical AIR operation:
//
//   kind = 0 (OBSERVE) : one absorb
//   kind = 1 (SAMPLE)  : one squeeze from out_buf
//   kind = 2 (DUPLEX)  : one sponge permutation (with in_buf overwrite)
//   kind = 3 (IDLE)    : no-op, pad rows
//
// An `Observe(v)` script op that fills in_buf to RATE compiles to TWO
// trace rows: one OBSERVE row, followed by an implicit DUPLEX row.
// A `Sample` script op whose out_buf is empty compiles to a DUPLEX row
// (with in_buf_len_local == 0) followed by a SAMPLE row.
//
// This split makes every trace row have a SINGLE side-effect. The AIR
// constraints are simpler: one kind-flag selects one set of transition
// rules. This is the Layout B from A2-1's spec docs.

/// Operation kind flag values (one-hot column index inside the trace row).
pub const OP_KIND_OBSERVE: u8 = 0;
pub const OP_KIND_SAMPLE: u8 = 1;
pub const OP_KIND_DUPLEX: u8 = 2;
pub const OP_KIND_IDLE: u8 = 3;
/// Number of distinct row kinds; matches the one-hot selector width.
pub const CHALLENGER_NUM_OP_KINDS: usize = 4;

/// Column offsets inside a ChallengerAir trace row.
///
/// Phase A2-2a pins these constants so the trace builder and the (yet-
/// to-be-landed) A2-2b constraint generator cannot drift.
pub mod col {
    use super::*;

    // ---- Sponge state snapshot (local = "at the START of this row") ----
    /// Offset of state[0].
    pub const STATE0: usize = 0;
    /// Width of the state block = SPONGE_WIDTH (8).
    pub const STATE_END: usize = STATE0 + SPONGE_WIDTH;

    // ---- Input-buffer state (local) ----
    pub const IN_BUF0: usize = STATE_END;
    pub const IN_BUF_END: usize = IN_BUF0 + SPONGE_RATE;
    pub const IN_BUF_LEN: usize = IN_BUF_END;
    /// One-hot decoder of in_buf_len: IN_BUF_LEN_FLAG[i] = 1 iff in_buf_len == i,
    /// for i ∈ {0, 1, 2, 3, 4}. 5 positions.
    pub const IN_BUF_LEN_FLAG0: usize = IN_BUF_LEN + 1;
    pub const IN_BUF_LEN_FLAG_END: usize = IN_BUF_LEN_FLAG0 + (SPONGE_RATE + 1);

    // ---- Output-buffer state (local) ----
    pub const OUT_BUF0: usize = IN_BUF_LEN_FLAG_END;
    pub const OUT_BUF_END: usize = OUT_BUF0 + SPONGE_RATE;
    pub const OUT_BUF_LEN: usize = OUT_BUF_END;
    pub const OUT_BUF_LEN_FLAG0: usize = OUT_BUF_LEN + 1;
    pub const OUT_BUF_LEN_FLAG_END: usize = OUT_BUF_LEN_FLAG0 + (SPONGE_RATE + 1);

    // ---- Per-row op kind (one-hot over CHALLENGER_NUM_OP_KINDS = 4) ----
    pub const KIND0: usize = OUT_BUF_LEN_FLAG_END;
    pub const KIND_END: usize = KIND0 + CHALLENGER_NUM_OP_KINDS;

    // ---- Per-row payload ----
    /// Value absorbed on OBSERVE rows; constrained to 0 on non-OBSERVE rows
    /// (not strictly required for soundness, but simplifies audit).
    pub const OBSERVED_VALUE: usize = KIND_END;
    /// Value squeezed on SAMPLE rows; equal to out_buf_local[out_buf_len_local - 1].
    pub const SAMPLED_VALUE: usize = OBSERVED_VALUE + 1;

    /// Total column width of a ChallengerAir trace row.
    pub const WIDTH: usize = SAMPLED_VALUE + 1;
}

/// Canonical trace width (≤ 35 cols for the framing; the shared Poseidon2-w8
/// block (180 cols) that Phase A2-2b will wire in for DUPLEX rows brings the
/// full slot width to ~215 cols, still within the aggregator's 200–300 cols/
/// slot budget from `doc/uno-aggregation-design.md` §1.3).
pub const CHALLENGER_AIR_WIDTH: usize = col::WIDTH;

/// Populate a trace row in-place from a `RefChallenger` snapshot at the
/// START of the row plus the row's kind + payload.
fn write_state_snapshot(
    row: &mut [Goldilocks],
    state: &[Goldilocks; SPONGE_WIDTH],
    in_buf: &[Goldilocks],
    out_buf: &[Goldilocks],
) {
    // State snapshot.
    for (i, &s) in state.iter().enumerate() {
        row[col::STATE0 + i] = s;
    }

    // in_buf snapshot (pad unused slots with 0).
    for k in 0..SPONGE_RATE {
        row[col::IN_BUF0 + k] = if k < in_buf.len() { in_buf[k] } else { Goldilocks::default() };
    }
    let in_len = in_buf.len();
    row[col::IN_BUF_LEN] = Goldilocks::new(in_len as u64);
    for k in 0..(SPONGE_RATE + 1) {
        row[col::IN_BUF_LEN_FLAG0 + k] =
            if k == in_len { Goldilocks::new(1) } else { Goldilocks::default() };
    }

    // out_buf snapshot — upstream's Vec uses `pop()` (LIFO), so the
    // "front" of the queue as written into the trace is position
    // `out_len - 1` (the top of the stack). We store elements in
    // positional order matching upstream's Vec layout — slot `k` holds
    // the element whose `pop` would be the `out_len - 1 - k`-th sample.
    for k in 0..SPONGE_RATE {
        row[col::OUT_BUF0 + k] =
            if k < out_buf.len() { out_buf[k] } else { Goldilocks::default() };
    }
    let out_len = out_buf.len();
    row[col::OUT_BUF_LEN] = Goldilocks::new(out_len as u64);
    for k in 0..(SPONGE_RATE + 1) {
        row[col::OUT_BUF_LEN_FLAG0 + k] =
            if k == out_len { Goldilocks::new(1) } else { Goldilocks::default() };
    }
}

fn write_kind(row: &mut [Goldilocks], kind: u8) {
    for k in 0..CHALLENGER_NUM_OP_KINDS {
        row[col::KIND0 + k] =
            if k as u8 == kind { Goldilocks::new(1) } else { Goldilocks::default() };
    }
}

/// Build a row-major trace matrix for a given script.
///
/// `trace_height` must be `>= physical_row_count(script)` and power of 2
/// (Plonky3 prover requires pow-2 heights). Extra rows pad with IDLE.
/// Returns `Err(_)` on arithmetic overflow or on a trace_height that's
/// too small / not a power of 2.
pub fn build_trace(
    script: &[ChallengerOp],
    trace_height: usize,
) -> Result<Vec<Goldilocks>, String> {
    if !trace_height.is_power_of_two() {
        return Err(format!("trace_height {trace_height} is not a power of 2"));
    }
    let width = col::WIDTH;
    let mut rows = Vec::<Vec<Goldilocks>>::new();

    // Drive our own state machine step-by-step so each trace row snapshots
    // the state at the START of its logical operation. An auto-duplex
    // after an Observe that fills in_buf is its own row. A forced-duplex
    // before a Sample on empty out_buf is also its own row.
    let ch = RefChallenger::new();
    let mut state = ch.state_snapshot();
    let mut in_buf: Vec<Goldilocks> = Vec::new();
    let mut out_buf: Vec<Goldilocks> = Vec::new();
    let perm = default_goldilocks_poseidon2_8();

    fn emit_row(
        rows: &mut Vec<Vec<Goldilocks>>,
        width: usize,
        row_state: &[Goldilocks; SPONGE_WIDTH],
        row_in: &[Goldilocks],
        row_out: &[Goldilocks],
        kind: u8,
        observed: Goldilocks,
        sampled: Goldilocks,
    ) {
        let mut row = vec![Goldilocks::default(); width];
        write_state_snapshot(&mut row, row_state, row_in, row_out);
        write_kind(&mut row, kind);
        row[col::OBSERVED_VALUE] = observed;
        row[col::SAMPLED_VALUE] = sampled;
        rows.push(row);
    }

    fn do_duplex(
        perm: &Poseidon2Goldilocks<8>,
        state: &mut [Goldilocks; SPONGE_WIDTH],
        in_buf: &mut Vec<Goldilocks>,
        out_buf: &mut Vec<Goldilocks>,
    ) {
        for (i, v) in in_buf.drain(..).enumerate() {
            state[i] = v;
        }
        perm.permute_mut(state);
        out_buf.clear();
        out_buf.extend_from_slice(&state[..SPONGE_RATE]);
    }

    for op in script {
        match op {
            ChallengerOp::Observe(v) => {
                // OBSERVE row: snapshot state BEFORE the observe push.
                emit_row(
                    &mut rows, width, &state, &in_buf, &out_buf,
                    OP_KIND_OBSERVE, *v, Goldilocks::default(),
                );

                // Apply the observe: push v, clear out_buf, check
                // auto-duplex trigger.
                out_buf.clear();
                in_buf.push(*v);

                if in_buf.len() == SPONGE_RATE {
                    // DUPLEX row: snapshot AFTER the observe push,
                    // BEFORE the permutation. The AIR's DUPLEX
                    // transition will use state_local + in_buf_local
                    // to compute what state_next should be via P2 (in
                    // Phase A2-2c).
                    emit_row(
                        &mut rows, width, &state, &in_buf, &out_buf,
                        OP_KIND_DUPLEX, Goldilocks::default(), Goldilocks::default(),
                    );
                    do_duplex(&perm, &mut state, &mut in_buf, &mut out_buf);
                }
            }
            ChallengerOp::Sample => {
                // Forced duplex on empty out_buf: emit the DUPLEX row
                // with state snapshot BEFORE the permutation.
                if out_buf.is_empty() {
                    emit_row(
                        &mut rows, width, &state, &in_buf, &out_buf,
                        OP_KIND_DUPLEX, Goldilocks::default(), Goldilocks::default(),
                    );
                    do_duplex(&perm, &mut state, &mut in_buf, &mut out_buf);
                }
                // Now out_buf has RATE elements. Emit SAMPLE row.
                let sampled = *out_buf.last().expect("out_buf populated by duplex above");
                emit_row(
                    &mut rows, width, &state, &in_buf, &out_buf,
                    OP_KIND_SAMPLE, Goldilocks::default(), sampled,
                );
                out_buf.pop();
            }
        }
    }

    if rows.len() > trace_height {
        return Err(format!(
            "script produced {} physical rows, exceeds trace_height {}",
            rows.len(),
            trace_height
        ));
    }

    // Pad with IDLE rows, carrying the tail state.
    while rows.len() < trace_height {
        emit_row(
            &mut rows, width, &state, &in_buf, &out_buf,
            OP_KIND_IDLE, Goldilocks::default(), Goldilocks::default(),
        );
    }

    // Flatten row-major.
    let mut flat = Vec::with_capacity(trace_height * width);
    for r in rows {
        flat.extend(r);
    }
    Ok(flat)
}

// ---------------------------------------------------------------------------
// Pure-Rust constraint checker — the spec Phase A2-2b ports to AirBuilder<AB>.
// ---------------------------------------------------------------------------

/// Verifies all AIR constraints on a pre-built trace matrix. Returns
/// `Ok(())` if the constraints hold on every row, or the first
/// violated-constraint description.
///
/// Phase A2-2a lands this as a plain-Rust reference of the AIR's
/// `eval` function. Phase A2-2b will port it constraint-for-constraint
/// to the Plonky3 `Air<AB>` trait (mechanical translation — each
/// `check` below becomes `builder.assert_zero(selector · (lhs - rhs))`).
///
/// The checker handles the full state machine (all 4 op kinds) EXCEPT
/// the Poseidon2 permutation identity on DUPLEX rows (that's wired in
/// Phase A2-2c using the same shared-Poseidon2-row-loop pattern as
/// `transfer_air`'s Merkle block).
pub fn check_all_transitions(trace: &[Goldilocks], trace_height: usize) -> Result<(), String> {
    let width = col::WIDTH;
    if trace.len() != trace_height * width {
        return Err(format!(
            "trace length {} != trace_height {} * width {}",
            trace.len(),
            trace_height,
            width
        ));
    }

    let row = |r: usize| -> &[Goldilocks] { &trace[r * width..(r + 1) * width] };
    let fe = Goldilocks::new;
    let zero = Goldilocks::default();
    let one = fe(1);

    for r in 0..trace_height {
        let local = row(r);

        // ---- One-hot: op kind selectors sum to 1 ----
        let mut kind_sum = zero;
        for k in 0..CHALLENGER_NUM_OP_KINDS {
            let flag = local[col::KIND0 + k];
            if flag != zero && flag != one {
                return Err(format!("row {r}: kind flag {k} = {flag:?} not 0/1"));
            }
            kind_sum += flag;
        }
        if kind_sum != one {
            return Err(format!("row {r}: kind one-hot sum = {kind_sum:?}, expected 1"));
        }

        // ---- One-hot: in_buf_len_flags sum to 1, and weighted sum == in_buf_len ----
        let mut in_flag_sum = zero;
        let mut in_weighted = zero;
        for k in 0..=SPONGE_RATE {
            let flag = local[col::IN_BUF_LEN_FLAG0 + k];
            if flag != zero && flag != one {
                return Err(format!("row {r}: in_buf_len_flag {k} not boolean"));
            }
            in_flag_sum += flag;
            in_weighted += flag * fe(k as u64);
        }
        if in_flag_sum != one {
            return Err(format!("row {r}: in_buf_len_flag not one-hot"));
        }
        if in_weighted != local[col::IN_BUF_LEN] {
            return Err(format!(
                "row {r}: in_buf_len ({:?}) != Σ i·in_buf_len_flag[i] ({:?})",
                local[col::IN_BUF_LEN],
                in_weighted
            ));
        }

        // ---- One-hot: out_buf_len_flags sum to 1, and weighted sum == out_buf_len ----
        let mut out_flag_sum = zero;
        let mut out_weighted = zero;
        for k in 0..=SPONGE_RATE {
            let flag = local[col::OUT_BUF_LEN_FLAG0 + k];
            if flag != zero && flag != one {
                return Err(format!("row {r}: out_buf_len_flag {k} not boolean"));
            }
            out_flag_sum += flag;
            out_weighted += flag * fe(k as u64);
        }
        if out_flag_sum != one {
            return Err(format!("row {r}: out_buf_len_flag not one-hot"));
        }
        if out_weighted != local[col::OUT_BUF_LEN] {
            return Err(format!(
                "row {r}: out_buf_len ({:?}) != Σ i·out_buf_len_flag[i] ({:?})",
                local[col::OUT_BUF_LEN],
                out_weighted
            ));
        }

        // ---- Non-OBSERVE rows must have observed_value == 0 (hygiene) ----
        let is_observe = local[col::KIND0 + OP_KIND_OBSERVE as usize];
        let is_sample = local[col::KIND0 + OP_KIND_SAMPLE as usize];
        let is_duplex = local[col::KIND0 + OP_KIND_DUPLEX as usize];
        let is_idle = local[col::KIND0 + OP_KIND_IDLE as usize];

        if is_observe == zero && local[col::OBSERVED_VALUE] != zero {
            return Err(format!(
                "row {r}: non-OBSERVE row has nonzero observed_value {:?}",
                local[col::OBSERVED_VALUE]
            ));
        }
        if is_sample == zero && local[col::SAMPLED_VALUE] != zero {
            return Err(format!(
                "row {r}: non-SAMPLE row has nonzero sampled_value {:?}",
                local[col::SAMPLED_VALUE]
            ));
        }

        // ---- SAMPLE: sampled_value == out_buf[out_buf_len - 1] ----
        if is_sample == one {
            let out_len = local[col::OUT_BUF_LEN];
            if out_len == zero {
                return Err(format!("row {r}: SAMPLE on empty out_buf"));
            }
            // Express sampled_value as Σ_{k=1..=RATE} (out_buf_len_flag[k] · out_buf[k-1]).
            let mut expected = zero;
            for k in 1..=SPONGE_RATE {
                expected += local[col::OUT_BUF_LEN_FLAG0 + k] * local[col::OUT_BUF0 + k - 1];
            }
            if local[col::SAMPLED_VALUE] != expected {
                return Err(format!(
                    "row {r}: SAMPLE value {:?} ≠ out_buf[out_buf_len-1] ({:?})",
                    local[col::SAMPLED_VALUE],
                    expected
                ));
            }
        }

        // ---- DUPLEX: in_buf_len_local can be any {0,1,2,3,4}; no
        //     local-row soundness constraint beyond the one-hots. The
        //     actual P2(state) identity is Phase A2-2c.
        // ----

        // Transition constraints (skip the last row).
        if r + 1 == trace_height {
            continue;
        }
        let next = row(r + 1);

        // ---- OBSERVE transition ----
        // in_buf_next[in_buf_len_local] = observed_value
        // in_buf_next[k] = in_buf_local[k] for k < in_buf_len_local
        // (k > in_buf_len_local slots unconstrained — will be overwritten
        //  on future observes; they're zeroed by the trace builder for
        //  hygiene, but the AIR doesn't force them)
        // in_buf_len_next = in_buf_len_local + 1 (wraps to 0 after RATE
        //  because an auto-duplex fires; split across 2 trace rows)
        // state_next = state_local
        // out_buf_len_next = 0
        if is_observe == one {
            // state_next = state_local
            for i in 0..SPONGE_WIDTH {
                if next[col::STATE0 + i] != local[col::STATE0 + i] {
                    return Err(format!(
                        "row {r}: OBSERVE preserves state, but state[{}] changed",
                        i
                    ));
                }
            }
            // out_buf_next_len = 0
            if next[col::OUT_BUF_LEN] != zero {
                return Err(format!("row {r}: OBSERVE must clear out_buf"));
            }
            // in_buf_next[k] = in_buf_local[k] for k < in_buf_len_local
            // in_buf_next[in_buf_len_local] = observed
            // We express these across all legal in_buf_len values.
            for k in 0..SPONGE_RATE {
                let mut expected = zero;
                // If in_buf_len > k, next[k] = local[k].
                let mut cond_persist = zero;
                for j in (k + 1)..=SPONGE_RATE {
                    cond_persist += local[col::IN_BUF_LEN_FLAG0 + j];
                }
                expected += cond_persist * local[col::IN_BUF0 + k];
                // If in_buf_len == k, next[k] = observed_value.
                let cond_insert = local[col::IN_BUF_LEN_FLAG0 + k];
                expected += cond_insert * local[col::OBSERVED_VALUE];
                // If in_buf_len < k (k > in_buf_len): slot should be 0 per our builder convention.
                // Encoded as: the result so far PLUS zeros. No extra term.
                if next[col::IN_BUF0 + k] != expected {
                    // Relax to tolerate unconstrained trailing positions
                    // only when k > in_buf_len_local (the trace builder
                    // writes 0 here; if the prover writes anything else
                    // we DO want to catch it on the next observe when
                    // the slot becomes position-in-use).
                    // For Phase A2-2a we don't gate on "k > len"; the
                    // builder zeroes unused slots and the checker
                    // insists on it, which is stricter than needed
                    // but easier to audit.
                    return Err(format!(
                        "row {r}: OBSERVE in_buf_next[{}] = {:?}, expected {:?}",
                        k,
                        next[col::IN_BUF0 + k],
                        expected
                    ));
                }
            }
            // in_buf_next_len = (in_buf_len_local + 1) mod (RATE + 1)
            // But actually: after len reaches RATE in the observe row,
            // the NEXT row is a DUPLEX that resets len to 0. So this
            // row's in_buf_next_len is always min(local + 1, RATE).
            // Easier: split on whether local == RATE - 1.
            let local_len = local[col::IN_BUF_LEN];
            let expected_next_len = if local_len == fe((SPONGE_RATE - 1) as u64) {
                fe(SPONGE_RATE as u64)
            } else {
                local_len + fe(1)
            };
            if next[col::IN_BUF_LEN] != expected_next_len {
                return Err(format!(
                    "row {r}: OBSERVE in_buf_next_len = {:?}, expected {:?}",
                    next[col::IN_BUF_LEN],
                    expected_next_len
                ));
            }
        }

        // ---- DUPLEX transition ----
        // in_buf_next = [], in_buf_next_len = 0
        // out_buf_next = state_next[0..RATE], out_buf_next_len = RATE
        // state_next = P2(state_local with in_buf[0..in_buf_len_local] overwritten)
        //   [the permutation identity is Phase A2-2c; here we don't constrain
        //    state_next beyond out_buf_next = state_next[0..RATE].]
        if is_duplex == one {
            if next[col::IN_BUF_LEN] != zero {
                return Err(format!("row {r}: DUPLEX must clear in_buf_len"));
            }
            for k in 0..SPONGE_RATE {
                if next[col::IN_BUF0 + k] != zero {
                    return Err(format!("row {r}: DUPLEX must clear in_buf[{}]", k));
                }
            }
            if next[col::OUT_BUF_LEN] != fe(SPONGE_RATE as u64) {
                return Err(format!(
                    "row {r}: DUPLEX out_buf_next_len = {:?}, expected {}",
                    next[col::OUT_BUF_LEN],
                    SPONGE_RATE
                ));
            }
            for k in 0..SPONGE_RATE {
                if next[col::OUT_BUF0 + k] != next[col::STATE0 + k] {
                    return Err(format!(
                        "row {r}: DUPLEX out_buf_next[{}] = {:?}, state_next[{}] = {:?}",
                        k,
                        next[col::OUT_BUF0 + k],
                        k,
                        next[col::STATE0 + k]
                    ));
                }
            }
        }

        // ---- SAMPLE transition ----
        // state_next = state_local
        // in_buf_next = in_buf_local (state preserved)
        // in_buf_next_len = in_buf_len_local
        // out_buf_next_len = out_buf_len_local - 1
        // out_buf_next[k] = out_buf_local[k] for k < out_buf_next_len
        //                   (the popped top element disappears; the
        //                    remaining stack stays in the same slots)
        if is_sample == one {
            for i in 0..SPONGE_WIDTH {
                if next[col::STATE0 + i] != local[col::STATE0 + i] {
                    return Err(format!("row {r}: SAMPLE preserves state, state[{}] changed", i));
                }
            }
            if next[col::IN_BUF_LEN] != local[col::IN_BUF_LEN] {
                return Err(format!("row {r}: SAMPLE in_buf_len changed"));
            }
            for k in 0..SPONGE_RATE {
                if next[col::IN_BUF0 + k] != local[col::IN_BUF0 + k] {
                    return Err(format!("row {r}: SAMPLE in_buf[{}] changed", k));
                }
            }
            // out_buf_next_len = out_buf_local_len - 1
            let expected = local[col::OUT_BUF_LEN] - fe(1);
            if next[col::OUT_BUF_LEN] != expected {
                return Err(format!(
                    "row {r}: SAMPLE out_buf_next_len = {:?}, expected {:?}",
                    next[col::OUT_BUF_LEN],
                    expected
                ));
            }
            // Remaining out_buf elements stay in place (we pop from the
            // top: positions [0, out_buf_next_len) keep their values).
            for k in 0..SPONGE_RATE {
                let keep_this = {
                    let mut s = zero;
                    for j in (k + 1)..=SPONGE_RATE {
                        s += next[col::OUT_BUF_LEN_FLAG0 + j];
                    }
                    s
                };
                let expected_val = keep_this * local[col::OUT_BUF0 + k];
                // And the popped top position is cleared (k == next_len).
                if next[col::OUT_BUF0 + k] != expected_val {
                    return Err(format!(
                        "row {r}: SAMPLE out_buf_next[{}] = {:?}, expected {:?}",
                        k,
                        next[col::OUT_BUF0 + k],
                        expected_val
                    ));
                }
            }
        }

        // ---- IDLE transition ----
        // Everything stays identical.
        if is_idle == one {
            for c in 0..col::KIND0 {
                // State + in_buf + flags + out_buf must all persist.
                if next[c] != local[c] {
                    return Err(format!("row {r}: IDLE col {} changed", c));
                }
            }
        }
    }

    Ok(())
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

    // ----- Trace-builder + constraint-checker tests (A2-2a) -----

    fn obs(v: u64) -> ChallengerOp {
        ChallengerOp::Observe(Goldilocks::new(v))
    }

    #[test]
    fn trace_width_matches_col_offsets() {
        // Regression guard: if anyone shifts col offsets, the width
        // constant must move with them.
        assert_eq!(CHALLENGER_AIR_WIDTH, col::SAMPLED_VALUE + 1);
        assert_eq!(col::WIDTH, CHALLENGER_AIR_WIDTH);
        // Current width: 8 state + 4 in_buf + 1 len + 5 flags + 4 out_buf +
        //  1 len + 5 flags + 4 kinds + 1 observed + 1 sampled = 34 cols.
        assert_eq!(CHALLENGER_AIR_WIDTH, 34);
    }

    #[test]
    fn trace_empty_script_is_all_idle() {
        let trace = build_trace(&[], 8).unwrap();
        // 8 rows × 34 cols.
        assert_eq!(trace.len(), 8 * CHALLENGER_AIR_WIDTH);
        // Every row has kind = IDLE.
        for r in 0..8 {
            let base = r * CHALLENGER_AIR_WIDTH;
            assert_eq!(
                trace[base + col::KIND0 + OP_KIND_IDLE as usize],
                Goldilocks::new(1)
            );
        }
        // Constraints hold.
        assert!(check_all_transitions(&trace, 8).is_ok());
    }

    #[test]
    fn trace_single_observe_under_rate_is_clean() {
        // 1 observe: 1 OBSERVE row + 7 IDLE rows.
        let script = vec![obs(0x11)];
        let trace = build_trace(&script, 8).unwrap();
        // Row 0: OBSERVE.
        let r0 = &trace[0..CHALLENGER_AIR_WIDTH];
        assert_eq!(r0[col::KIND0 + OP_KIND_OBSERVE as usize], Goldilocks::new(1));
        assert_eq!(r0[col::OBSERVED_VALUE], Goldilocks::new(0x11));
        // Row 1: IDLE.
        let r1 = &trace[CHALLENGER_AIR_WIDTH..2 * CHALLENGER_AIR_WIDTH];
        assert_eq!(r1[col::KIND0 + OP_KIND_IDLE as usize], Goldilocks::new(1));
        // Row 1's in_buf should contain what row 0's observe pushed.
        assert_eq!(r1[col::IN_BUF0], Goldilocks::new(0x11));
        assert_eq!(r1[col::IN_BUF_LEN], Goldilocks::new(1));
        // Constraints hold.
        assert!(check_all_transitions(&trace, 8).is_ok());
    }

    #[test]
    fn trace_observe_rate_triggers_duplex() {
        // 4 observes: 4 OBSERVE rows + 1 DUPLEX row + 3 IDLE rows.
        let script = vec![obs(1), obs(2), obs(3), obs(4)];
        let trace = build_trace(&script, 16).unwrap();
        // Rows 0..4: OBSERVE.
        for r in 0..4 {
            let row = &trace[r * CHALLENGER_AIR_WIDTH..(r + 1) * CHALLENGER_AIR_WIDTH];
            assert_eq!(
                row[col::KIND0 + OP_KIND_OBSERVE as usize],
                Goldilocks::new(1),
                "row {r} should be OBSERVE"
            );
        }
        // Row 4: DUPLEX.
        let r4 = &trace[4 * CHALLENGER_AIR_WIDTH..5 * CHALLENGER_AIR_WIDTH];
        assert_eq!(
            r4[col::KIND0 + OP_KIND_DUPLEX as usize],
            Goldilocks::new(1),
            "row 4 should be DUPLEX"
        );
        assert_eq!(r4[col::IN_BUF_LEN], Goldilocks::new(4));
        // Row 5: IDLE with out_buf populated from the duplex.
        let r5 = &trace[5 * CHALLENGER_AIR_WIDTH..6 * CHALLENGER_AIR_WIDTH];
        assert_eq!(r5[col::KIND0 + OP_KIND_IDLE as usize], Goldilocks::new(1));
        assert_eq!(r5[col::OUT_BUF_LEN], Goldilocks::new(4));
        assert_eq!(r5[col::IN_BUF_LEN], Goldilocks::new(0));
        // Constraints hold.
        assert!(check_all_transitions(&trace, 16).is_ok());
    }

    #[test]
    fn trace_observe_four_then_sample_all_four() {
        // 4 observes trigger duplex; 4 samples drain out_buf.
        let script = vec![
            obs(10), obs(20), obs(30), obs(40),
            ChallengerOp::Sample,
            ChallengerOp::Sample,
            ChallengerOp::Sample,
            ChallengerOp::Sample,
        ];
        let trace = build_trace(&script, 16).unwrap();
        assert!(check_all_transitions(&trace, 16).is_ok());

        // Spot-check: 4 OBSERVE + 1 DUPLEX + 4 SAMPLE = 9 physical rows,
        // rest IDLE.
        let mut op_counts = [0; CHALLENGER_NUM_OP_KINDS];
        for r in 0..16 {
            let row = &trace[r * CHALLENGER_AIR_WIDTH..(r + 1) * CHALLENGER_AIR_WIDTH];
            for k in 0..CHALLENGER_NUM_OP_KINDS {
                if row[col::KIND0 + k] == Goldilocks::new(1) {
                    op_counts[k] += 1;
                }
            }
        }
        assert_eq!(op_counts[OP_KIND_OBSERVE as usize], 4);
        assert_eq!(op_counts[OP_KIND_DUPLEX as usize], 1);
        assert_eq!(op_counts[OP_KIND_SAMPLE as usize], 4);
        assert_eq!(op_counts[OP_KIND_IDLE as usize], 16 - 9);
    }

    #[test]
    fn trace_sample_on_empty_triggers_forced_duplex() {
        // Sample-first with no preceding observes: forces a duplex on
        // empty in_buf, then samples.
        let script = vec![ChallengerOp::Sample];
        let trace = build_trace(&script, 8).unwrap();
        // Row 0: DUPLEX (forced); Row 1: SAMPLE; rest IDLE.
        let r0 = &trace[0..CHALLENGER_AIR_WIDTH];
        assert_eq!(r0[col::KIND0 + OP_KIND_DUPLEX as usize], Goldilocks::new(1));
        assert_eq!(r0[col::IN_BUF_LEN], Goldilocks::new(0)); // empty in_buf at start of forced duplex
        let r1 = &trace[CHALLENGER_AIR_WIDTH..2 * CHALLENGER_AIR_WIDTH];
        assert_eq!(r1[col::KIND0 + OP_KIND_SAMPLE as usize], Goldilocks::new(1));
        // After forced duplex on empty state, out_buf has RATE elements.
        assert_eq!(r1[col::OUT_BUF_LEN], Goldilocks::new(4));
        assert!(check_all_transitions(&trace, 8).is_ok());
    }

    #[test]
    fn trace_matches_refchallenger_sampled_values() {
        // Run the same script through RefChallenger directly and via
        // build_trace; collect the sampled values from both and assert
        // they match.
        let script = vec![
            obs(0x11), obs(0x22), obs(0x33), obs(0x44), // triggers duplex
            ChallengerOp::Sample,
            ChallengerOp::Sample,
            obs(0x55),
            ChallengerOp::Sample, // triggers forced duplex (out_buf was drained? no, still 2 elts)
        ];
        // Get expected samples directly from RefChallenger.
        let mut expected_samples = Vec::new();
        let mut ch = RefChallenger::new();
        for op in &script {
            match op {
                ChallengerOp::Observe(v) => ch.observe(*v),
                ChallengerOp::Sample => expected_samples.push(ch.sample()),
            }
        }

        let trace = build_trace(&script, 16).unwrap();
        let mut trace_samples = Vec::new();
        for r in 0..16 {
            let row = &trace[r * CHALLENGER_AIR_WIDTH..(r + 1) * CHALLENGER_AIR_WIDTH];
            if row[col::KIND0 + OP_KIND_SAMPLE as usize] == Goldilocks::new(1) {
                trace_samples.push(row[col::SAMPLED_VALUE]);
            }
        }
        assert_eq!(trace_samples, expected_samples);
        assert!(check_all_transitions(&trace, 16).is_ok());
    }

    #[test]
    fn checker_rejects_kind_not_one_hot() {
        let mut trace = build_trace(&[obs(1)], 8).unwrap();
        // Zero the kind flag on row 0. Sum is now 0, not 1.
        trace[col::KIND0 + OP_KIND_OBSERVE as usize] = Goldilocks::default();
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_tampered_observed_value() {
        // Build a clean trace, then flip the observed_value on row 0
        // without updating in_buf_next[0] on row 1. The OBSERVE transition
        // rule `in_buf_next[0] == observed_value` should now fail.
        let mut trace = build_trace(&[obs(0xAA)], 8).unwrap();
        trace[col::OBSERVED_VALUE] = Goldilocks::new(0xBB);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_tampered_sample_value() {
        let script = vec![
            obs(1), obs(2), obs(3), obs(4),
            ChallengerOp::Sample,
        ];
        let mut trace = build_trace(&script, 8).unwrap();
        // Row 5 is SAMPLE. Change its sampled_value to junk.
        let sample_row = 5;
        let base = sample_row * CHALLENGER_AIR_WIDTH;
        // Assert the row really is SAMPLE.
        assert_eq!(
            trace[base + col::KIND0 + OP_KIND_SAMPLE as usize],
            Goldilocks::new(1)
        );
        trace[base + col::SAMPLED_VALUE] = Goldilocks::new(0xDEAD);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_duplex_not_clearing_in_buf() {
        let script = vec![obs(1), obs(2), obs(3), obs(4)];
        let mut trace = build_trace(&script, 8).unwrap();
        // Row 5 is the IDLE after the auto-duplex. Tamper the previous
        // row (row 4, DUPLEX) transition — set row 5's in_buf[0] to nonzero.
        trace[5 * CHALLENGER_AIR_WIDTH + col::IN_BUF0] = Goldilocks::new(99);
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn checker_rejects_idle_mutation() {
        let trace_orig = build_trace(&[obs(7)], 8).unwrap();
        let mut trace = trace_orig.clone();
        // Row 2 is IDLE (rows 0 = OBSERVE, 1 = IDLE, 2 = IDLE, ...).
        // Change the state snapshot on row 3 to be different from row 2.
        // The IDLE constraint "everything persists" should catch this.
        let r3_base = 3 * CHALLENGER_AIR_WIDTH;
        trace[r3_base + col::STATE0] = Goldilocks::new(0x1234);
        // But we also need to rebuild the in_buf_len_flag to be consistent
        // (we changed state, not in_buf, so flags would still be valid).
        // Actually the IDLE transition checks columns 0..KIND0, which
        // includes state. So the bare state mutation should trip it.
        assert!(check_all_transitions(&trace, 8).is_err());
    }

    #[test]
    fn trace_fits_pow2_height() {
        // Non-pow-2 trace_height is rejected.
        assert!(build_trace(&[], 7).is_err());
        // Too-small trace_height is rejected: 4 observes produce 4+1 = 5
        // physical rows, which won't fit in height-4.
        assert!(build_trace(&[obs(1), obs(2), obs(3), obs(4)], 4).is_err());
    }
}
