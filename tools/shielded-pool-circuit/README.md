# shielded-pool-circuit

The V1 shielded pool circuit: Poseidon2 t=8 gadgets, the section 4 note
relations, the section 5 commitment tree, the section 11 transaction relations
over the frozen section 10 public input vector, and the section 10.1
development proof and verifying key.

The implementation profile is normative for everything here. The Groth16
backend is an implementation choice; the relations, the public input ordering
and the output format are not.

This crate is standalone: it is not a member of the `tosctl` workspace and
carries its own `Cargo.lock` with exact dependency versions, the same way
`crypto/poseidon2/manifest-gen` does.

## Layout

    src/field.rs        the scalar field and its one canonical encoding
    src/params.rs       the frozen Poseidon2 parameters, parsed from
                        crypto/poseidon2/manifest.bin and held to its digest
    src/poseidon2.rs    the permutation and HASH7, out of circuit
    src/domains.rs      the section 1.4 domain separators, derived not tabulated
    src/notes.rs        section 4 and the section 9.3 intent, out of circuit
    src/tree.rs         the 7-ary depth-12 tree and the section 5.1 frontier
    src/gadgets/        the same relations inside the constraint system
    src/circuit.rs      section 11, with one switch per relation
    src/public_inputs.rs the frozen 18-element vector
    src/groth16.rs      setup, proving, the canonical encodings, and the
                        measured pairing equation
    src/scenario.rs     a pool with notes in it, shared by the tests and the
                        development fixture
    crosscheck/         a sibling crate that runs the shielded FunC library in
                        the VM and compares it against these gadgets

## Running

    export TOS_ROOT=$HOME/tos-privacy    # only to locate build/crypto/func
    export PATH=$HOME/.cargo/bin:$PATH
    export CARGO_TERM_COLOR=never

    cargo test                                    # the circuit crate
    cargo run --release --bin gadget-fixture -- fixtures/section45.json
    cargo run --release --bin proof-fixture  -- fixtures/groth16-development.json
    cd crosscheck && cargo test -- --nocapture    # against the real FunC

The cross-check resolves the `.fc` sources from `CARGO_MANIFEST_DIR`, so it
always compiles the library in this checkout. `TOS_ROOT` is used only to find
the `func` and `fift` binaries, which are build outputs. The path it used is
printed on every run.

## What the tests are for

`tests/vectors.rs` holds the gadget against the 21 permutation and 28 hash
known-answer vectors, out of circuit and again with the constraints generated
and the R1CS satisfied. The parameter manifest alone is not enough evidence:
the permutation reads only the diagonal of the internal matrix, so perturbing
the rest changes no output, and dropping a partial round leaves the manifest
byte-identical. Running with one fewer partial round leaves the three manifest
tests green and turns five vector tests red; that is why the vectors are the
check that matters.

`crosscheck/tests/funcs_vs_gadget.rs` is the independent third reading of
section 4. The FunC library and the sandbox reference beside it were written
from the same text by the same hand, so a misreading would live in both. The
comparison is against values the VM produced, and it has its own control case
that shows a wrong expected value is rejected by the same code path.

`tests/circuit_negative.rs` is section 19 gate 3: each relation is removed and
the witness it was blocking is shown accepted, with the exploit named. Three
cases state a baseline, because the witness that exercises them cannot be
built while an earlier relation holds. One case reports a relation as
redundant rather than dressing it up as load-bearing.

`tests/groth16_fixture.rs` is section 10.1: one valid proof plus one each with
`A`, `B`, `C` and a public input mutated, and the pairing equation measured
against six candidate sign and order patterns rather than recalled.

## The development keys are not keys

`src/groth16.rs` draws its proving and verifying keys from a fixed seed. The
toxic waste is therefore known and nothing produced here may verify a real
transaction. Production keys come from the Phase-2 ceremony the profile
requires.
