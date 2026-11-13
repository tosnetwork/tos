# Differential fuzzing and mismatch diagnosis

Fixtures pin the behaviour on contexts someone wrote down; differential fuzzing looks for contexts nobody
wrote down on which two implementations disagree. Every generated context runs through the C++ reference
and a target, and every disagreement is kept as an input file for triage. The reference is never assumed to
be right about a mismatch's cause, only about what the frozen behaviour is.

## Drivers

| Driver | Targets | Use |
|---|---|---|
| `conformance-fuzz` (`fuzz/`, built by `parts/fuzz.cmake`) | two shared libraries exporting `conformance_run_v1` (`ref/conformance-ref.h`), loaded in one process | fast campaigns: about 10,000 vm cases and 700 txn cases per second on one core (both libraries run each case) |
| `conformance-fuzz-libfuzzer` (when the compiler supports `-fsanitize=fuzzer`) | the same, configured from the environment | coverage-guided search; the fuzzer input is the generator's choice stream |
| `runner/fuzz_process.py run` | two programs with the `conformance-ref-cli` line protocol | targets that exist only as a command line, such as an adapter for another node (about 5,000 vm cases per second against two reference CLIs) |

Case `i` of a campaign with seed `S` is built from `(S, i)` alone, so it does not depend on the driver or on
batching. `conformance-fuzz --emit` prints the cases instead of running them, and `fuzz_process.py` takes its
contexts from there: both drivers run the same contexts and name their mismatches alike.

```
# in-process: reference against a target library, seeded from the frozen vm fixtures
build/test/conformance/conformance-fuzz --harness vm \
    --reference build/test/conformance/libconformance-ref.so --target <target.so> \
    --seeds test/conformance/vectors --cases 100000 --seed 1 --out test/conformance/vectors

# command-line targets
python3 test/conformance/runner/fuzz_process.py run --generator build/test/conformance/conformance-fuzz \
    --harness vm --reference build/test/conformance/conformance-ref-cli --target <target-cli> \
    --seeds test/conformance/vectors --cases 100000 --seed 1 --out test/conformance/vectors

# libFuzzer
CONFORMANCE_FUZZ_REFERENCE=build/test/conformance/libconformance-ref.so CONFORMANCE_FUZZ_TARGET=<target.so> \
CONFORMANCE_FUZZ_SEEDS=test/conformance/vectors CONFORMANCE_FUZZ_OUT=<dir> \
    build/test/conformance/conformance-fuzz-libfuzzer -max_total_time=600
```

Both drivers print one summary line (cases, equal, both refused, mismatched, cases per lineage, the
reference's outcome counts, throughput) and exit 0 only when no case mismatched; with `--expect-mismatch`
they exit 0 only when one did. A one-sided refusal (`harness_error`) is a mismatch; two refusals agree
whatever their wording. A library that crashes takes the in-process driver with it; the driver then prints
the case number and the context it was running.

The libraries are opened with local symbol scope and `RTLD_DEEPBIND`, so a reference and another build of the
same code in one process do not bind to each other's symbols.

## Generation

- vm: either a context built from an instruction grammar (stack, arithmetic, comparison, cell, tuple,
  continuation, control-flow, exception, dictionary, gas and context-parameter instructions with their
  immediate arguments; inline and referenced continuations up to depth 3; trailing references entered by
  an implicit JMPREF; some arbitrary bits), or a seed fixture mutated: stack items added, dropped, replaced
  or swapped (integers at the 257-bit and power-of-two edges, NaN, null, cells, slices, nested tuples), gas
  limit, maximum and credit, code bit flips, prefixes, appended or inserted instructions, replaced or
  dropped references and a generated prelude jumping into the original code, c7 (the standard parameter
  tuple and broken shapes), data, flags and global version.
- txn: mutations of seed contexts that keep every cell decodable: `now`, `lt`, the random seed, tick and
  tock swapped, the account balance (rebuilt inside the account cell), the inbound message's value, flags
  and body, and the optional libraries and previous blocks dropped. txn needs seeds;
  `fuzz_process.py rel02-seeds <test-epoch-replay> test/rel02/corpus <out.jsonl>` exports the 576 REL-02
  contexts for that.

`--seeds` takes fixture files (blob references resolved), files of `{"context": ...}` lines, or directories.
The lineage of a case is the seed's family (`vm-endstate`), the stem of a contexts file (`rel02-seeds`), or
`grammar`.

## Mismatch files

`<out>/<harness>/inputs/fuzz-mismatches/<lineage>/<sha256>.json`, where `<sha256>` is the SHA-256 of the
context's canonical JSON (sorted keys, no spaces; the C++ and Python serializers produce the same text). The
file holds the context, both effects, the seed and case index and the two program names
(`vectors/vm/inputs/fuzz-mismatches/README.md`). These are inputs for triage, not fixtures.

## Diagnosis

```
# decode both effects, diff them field by field (the stack item by item), and with trace-enabled builds
# print the first step where the two runs diverge
python3 test/conformance/runner/debug_mismatch.py --reference <cli> --target <cli> <mismatch file>
python3 test/conformance/runner/debug_mismatch.py --reference <cli> --target <cli> --fixture vm/vm-endstate/end-normal

# shrink a mismatching context while the two still disagree
python3 test/conformance/runner/minimize.py --reference <cli> --target <cli> <mismatch file> --out small.json
```

`minimize.py` drops optional fields, stack items and tuple elements, lowers the gas values and cuts the code
to data prefixes, fewer references and hoisted subtrees (vm), or drops the libraries, previous blocks and
StateInit and shortens the message body (txn), keeping each step only while the reference does not refuse
the context and the target still disagrees. A mutant mismatch found by the campaign below shrinks from 510
to 92 bytes: an empty code cell with one empty reference and zero gas, the implicit JMPREF whose cost the
mutant changed.

## VM step trace

Configuring a separate build directory with `-DTOS_VM_STEP_TRACE=ON -DTOS_VM_STEP_TRACE_TEST_BUILD=ON` (default OFF; configuration stops if only the first is set; both are declared in `parts/fuzz.cmake`)
compiles a per-step hook into the VM (`crypto/vm/step-trace.h`): after the step counter is incremented and
before the instruction runs, and after every charged cell load, it calls a sink installed on the thread.
Without the option the hook does not exist in the build. With it, a vm context with `"trace": true` returns
its effects plus `"trace": {"events": [...], "truncated": bool}`: per step the step number, gas consumed,
stack depth, a 16-hex-digit digest of the top value's canonical text and the code position
(`<cell hash prefix>:<bit>:<ref>`), per load the cell hash prefix and whether it was the first load, child VMs
marked. The flag is outside the fixture schema, so no fixture can request it and no comparison sees it; a
build without the hook refuses it. `debug_mismatch.py` checks that a traced run has the same effects as the
untraced one.

## Self-checks (ctest -L conformance)

| Test | Expectation |
|---|---|
| `conformance-fuzz-self` | reference against itself (one loaded instance): 3000 vm cases, no mismatch |
| `conformance-fuzz-twin` | reference against a self-contained copy of the same code: no mismatch |
| `conformance-fuzz-mutant` | reference against the mutant (implicit JMPREF costs one more gas, a copy of `vm.cpp` built only into this library): mismatches found and written |
| `conformance-fuzz-process-self`, `-process-mutant` | the same through the command-line driver; the mutant's mismatch files equal the in-process driver's |
| `conformance-fuzz-txn-twin`, `-txn-mutant` | txn mutations of the REL-02 contexts: no mismatch against the twin, mismatches against the mutant |
| `conformance-fuzz-libfuzzer` | 2000 libFuzzer inputs, reference against the twin, aborting on any mismatch |
| `conformance-fuzz-trace` | with the hook: the first mutant mismatch is located at its first diverging step and the trace leaves the effects unchanged; without it: the trace request is refused |

`runner/test_fuzz.py` checks the Python tools against fake targets, each check with a control that fails.

## Guided fuzzing of the instrumented reference

Configure a separate build directory with `-DCMAKE_C_FLAGS=-fsanitize=fuzzer-no-link` (the same for C++, executable
and shared linker flags) and `-DCONFORMANCE_FUZZ_GUIDED=ON`; then the reference library and its twin carry coverage
instrumentation and libFuzzer is steered by the VM and transaction code an input reaches.

```
python3 test/conformance/fuzz/guided.py campaign --build-dir build-fz --corpus corpus --seconds 900 --forks 8 --seeds <fixtures>
python3 test/conformance/fuzz/guided.py harvest --build-dir build-fz --corpus corpus --seeds <fixtures> --out contexts.jsonl
python3 test/conformance/runner/conformance.py create --reference build/test/conformance/conformance-ref-cli \
    --harness vm --family vm-fuzz-guided --source fuzz contexts.jsonl vectors/vm/fixtures/vm-fuzz-guided.jsonl
```

First campaign (15 min, 8 forks, seeds vm-endstate and vm-opcode-sweep): about 7.55M executions, 25,691 edges,
corpus 7,617, no crash or mismatch; 7,573 distinct contexts frozen as `vm-fuzz-guided`. They raised crypto/vm line
coverage from 62.4% to 63.6% and executed one listed gap (the RIST255_MULBASE inner callback).
