/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! How many bytes a post-quantum proof would weigh for this pool's work.
//!
//! The V1 transaction circuit is 18,107 R1CS constraints, and one Poseidon2
//! t=8 permutation is 363 of them, so the circuit proves roughly fifty
//! permutations. Poseidon2 here uses an x^5 S-box over 65 rounds, so the
//! natural execution trace for that work is about 50 * 65 = 3,250 rows of
//! eight field elements, which pads to 2^12.
//!
//! What is measured is a trace of that shape with degree-five transition
//! constraints -- the same degree an x^5 S-box gives -- because a FRI proof's
//! size is set by the trace dimensions, the constraint degree and the
//! security parameters, not by what the constraints mean. The arithmetic
//! below is therefore deliberately meaningless: it is the right shape.
//!
//! Security is stated with every figure. A STARK proof's size is mostly the
//! FRI query set, so a proof quoted without its security level says nothing.

use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use winterfell::math::{fields::f64::BaseElement, FieldElement, ToElements};
use winterfell::{
    Air, AirContext, Assertion, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions,
    Prover, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
};

/// The first and last row, which is what a verifier is told.
#[derive(Clone)]
struct Boundary {
    start: Vec<BaseElement>,
    end: Vec<BaseElement>,
}

impl ToElements<BaseElement> for Boundary {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = self.start.clone();
        out.extend_from_slice(&self.end);
        out
    }
}

/// `next = cur^5 + 1`, one such constraint per column.
struct WorkAir {
    context: AirContext<BaseElement>,
    boundary: Boundary,
}

impl Air for WorkAir {
    type BaseField = BaseElement;
    type PublicInputs = Boundary;

    fn new(trace_info: TraceInfo, pub_inputs: Boundary, options: ProofOptions) -> Self {
        let width = trace_info.width();
        let degrees = vec![TransitionConstraintDegree::new(5); width];
        WorkAir {
            context: AirContext::new(trace_info, degrees, width * 2, options),
            boundary: pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        for (index, slot) in result.iter_mut().enumerate() {
            let x = current[index];
            let squared = x * x;
            let fourth = squared * squared;
            *slot = next[index] - (fourth * x + E::ONE);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = self.trace_length() - 1;
        let mut out = Vec::new();
        for (index, value) in self.boundary.start.iter().enumerate() {
            out.push(Assertion::single(index, 0, *value));
        }
        for (index, value) in self.boundary.end.iter().enumerate() {
            out.push(Assertion::single(index, last, *value));
        }
        out
    }
}

struct WorkProver {
    options: ProofOptions,
}

impl Prover for WorkProver {
    type BaseField = BaseElement;
    type Air = WorkAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, WorkAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> Boundary {
        let last = trace.length() - 1;
        Boundary {
            start: (0..trace.width()).map(|c| trace.get(c, 0)).collect(),
            end: (0..trace.width()).map(|c| trace.get(c, last)).collect(),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = BaseElement>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &winterfell::matrix::ColMatrix<BaseElement>,
        domain: &StarkDomain<BaseElement>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = BaseElement>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a WorkAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

fn measure(width: usize, length: usize, blowup: usize, queries: usize, grinding: u32) -> Weighed {
    measure_ext(width, length, blowup, queries, grinding, FieldExtension::Quadratic)
}

fn build_trace(width: usize, length: usize) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(width, length);
    trace.fill(
        |state| {
            for (index, slot) in state.iter_mut().enumerate() {
                *slot = BaseElement::new(index as u64 + 1);
            }
        },
        |_step, state| {
            for slot in state.iter_mut() {
                let squared = *slot * *slot;
                *slot = squared * squared * *slot + BaseElement::ONE;
            }
        },
    );
    trace
}

/// What a single measurement reports.
struct Weighed {
    bytes: usize,
    /// Security under the FRI conjecture, which is what most deployments
    /// quote.
    conjectured: u32,
    /// Security that is proven rather than conjectured, in the list-decoding
    /// regime. This is the number a contract holding other people's money
    /// should be sized by, and it is always the smaller of the two.
    proven: u32,
}

/// One measurement: prove a trace of that shape and weigh the proof.
fn measure_ext(
    width: usize,
    length: usize,
    blowup: usize,
    queries: usize,
    grinding: u32,
    extension: FieldExtension,
) -> Weighed {
    let options = ProofOptions::new(
        queries,
        blowup,
        grinding,
        extension,
        8,
        127,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    );
    let prover = WorkProver { options: options.clone() };
    let trace = build_trace(width, length);
    let proof: Proof = prover.prove(trace).expect("prove");
    Weighed {
        bytes: proof.to_bytes().len(),
        conjectured: proof.conjectured_security::<Blake3_256<BaseElement>>().bits(),
        proven: proof.proven_security::<Blake3_256<BaseElement>>().ldr_bits(),
    }
}

/// The proof's own structure, so the query and layer counts a verifier walks
/// are read off it rather than worked out on paper.
fn describe(width: usize, length: usize, blowup: usize, queries: usize) {
    let options = ProofOptions::new(
        queries,
        blowup,
        20,
        FieldExtension::Cubic,
        8,
        127,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    );
    let prover = WorkProver { options: options.clone() };
    let proof = prover.prove(build_trace(width, length)).expect("prove");
    let lde = proof.lde_domain_size();
    println!("trace {width} x {length}, blowup {blowup}, {queries} queries");
    println!("  LDE domain          {lde} (2^{})", lde.trailing_zeros());
    let fri = options.to_fri_options();
    println!("  folding factor      {}", fri.folding_factor());
    println!("  remainder max deg   {}", fri.remainder_max_degree());
    // Layers until the remainder is small enough, and the Merkle depth each
    // one is committed at.
    let folding = fri.folding_factor();
    let mut domain = lde;
    let mut depths = vec![
        (lde as f64).log2() as usize,
        (lde as f64).log2() as usize,
    ];
    let mut layers = 0;
    while domain > fri.remainder_max_degree() + 1 {
        domain /= folding;
        depths.push((domain as f64).log2() as usize);
        layers += 1;
    }
    let total: usize = depths.iter().sum();
    println!("  FRI layers          {layers}");
    println!("  Merkle depths       {depths:?} -> {total} levels a query");
    println!("  levels in total     {} x {total} = {}", queries, queries * total);
    println!("  proof bytes         {}", proof.to_bytes().len());
}

fn main() {
    println!("--- the proof's own structure ---");
    describe(8, 1 << 12, 16, 60);
    println!();

    println!("trace          blowup  queries  grinding  conjectured  proven  proof bytes");
    println!("-------------  ------  -------  --------  -----------  ------  -----------");

    // The shape the pool's own work has: fifty Poseidon2 permutations of
    // sixty-five rounds over an eight-element state.
    let shapes = [
        ("8 x 2^12", 8usize, 1usize << 12),
        ("8 x 2^13", 8, 1 << 13),
        ("16 x 2^12", 16, 1 << 12),
        ("8 x 2^16", 8, 1 << 16),
        ("8 x 2^20", 8, 1 << 20),
    ];
    // Degree-five constraints need a blowup of at least eight.
    let settings = [(8usize, 27usize, 16u32), (8, 54, 16), (16, 30, 20)];

    for (name, width, length) in shapes {
        for (blowup, queries, grinding) in settings {
            let w = measure(width, length, blowup, queries, grinding);
            println!(
                "{name:<13}  {blowup:>6}  {queries:>7}  {grinding:>8}  {:>9} bit  {:>4} bit  {:>9}",
                w.conjectured, w.proven, w.bytes
            );
        }
    }

    // What it takes to reach a security level that is proven rather than
    // conjectured. A pool holding other people's money is the wrong place to
    // be relying on a conjecture, so this is the figure that decides the
    // question -- and it is much more expensive than the one usually quoted.
    println!();
    println!("--- the pool's own shape, 8 x 2^12, searching for proven security ---");
    println!("blowup  queries  grinding  conjectured  proven  proof bytes");
    println!("------  -------  --------  -----------  ------  -----------");
    let mut best: Option<(usize, usize, u32, Weighed)> = None;
    for blowup in [8usize, 16, 32, 64] {
        for queries in [30usize, 60, 90, 120, 160] {
            let w = measure(8, 1 << 12, blowup, queries, 20);
            println!(
                "{blowup:>6}  {queries:>7}  {:>8}  {:>9} bit  {:>4} bit  {:>9}",
                20, w.conjectured, w.proven, w.bytes
            );
            if w.proven >= 100 && best.as_ref().is_none_or(|(_, _, _, b)| w.bytes < b.bytes) {
                best = Some((blowup, queries, 20, w));
            }
        }
    }
    // The plateau above is the extension field, not the query count: the
    // proven bound cannot exceed what the field the verifier samples from can
    // carry. A wider extension is the only lever left.
    println!();
    println!("--- the same shape over a cubic extension ---");
    println!("blowup  queries  conjectured  proven  proof bytes");
    println!("------  -------  -----------  ------  -----------");
    for blowup in [8usize, 16] {
        for queries in [30usize, 60, 90, 120] {
            let w = measure_ext(8, 1 << 12, blowup, queries, 20, FieldExtension::Cubic);
            println!(
                "{blowup:>6}  {queries:>7}  {:>9} bit  {:>4} bit  {:>9}",
                w.conjectured, w.proven, w.bytes
            );
            if w.proven >= 100 && best.as_ref().is_none_or(|(_, _, _, b)| w.bytes < b.bytes) {
                best = Some((blowup, queries, 20, w));
            }
        }
    }

    match best {
        Some((blowup, queries, grinding, w)) => println!(
            "\nsmallest proof at 100 bits of PROVEN security: {} bytes \
             (blowup {blowup}, {queries} queries, grinding {grinding})",
            w.bytes
        ),
        None => println!(
            "\nno setting reached 100 bits of proven security over this field; the \
             extension degree is the ceiling, not the query count"
        ),
    }
}
