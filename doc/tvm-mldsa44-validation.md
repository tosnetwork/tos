# Native ML-DSA-44 validation and gas calibration

This is the validation contract for PR #101. A test definition is not execution
evidence: the final commit's GitHub Actions jobs and archived outputs must pass.
The account Auth Module, Rust VM port, wallet UI and network activation remain
separate deliverables. This change neither merges the PR nor edits chain config.

## Acceptance matrix

The `Native ML-DSA-44 verification` workflow checks:

- Real pinned ACVP, Wycheproof and independent OpenSSL fixtures through both
  the C++ wrapper and codepage-0 VM instruction. Algorithm-invalid and
  structurally malformed inputs have distinct expected outcomes.
- Exact raw-instruction gas for every in-profile valid/invalid vector, derived
  independently from specification literals: 50,000 base + decoded bytes +
  100/25 first/repeated cell loads + 34 instruction + 5 implicit-return gas.
  Repeated equal cells are identified by representation hash, not pointer.
- Actual FunC **and Tol** public declarations, compiled and assembled into BOCs.
  The complete vector corpus executes through each compiled program. Neither
  program substitutes a test-local PQ declaration for the shipped binding.
- Versions 0..15, exact gas and one-less-than-required gas, swapped operands,
  malformed operands, error-state commitment, and the classic-ignore flag,
  including through the compiled programs rather than just a raw opcode.
- Raw stack underflow/type errors, gas exhaustion during first operand loading,
  bounded byte-chain parsing, BOC roundtrip and eleven paid invocations.
- Six compiling guard mutations: verification, version, base price, byte price,
  message length and context forwarding. Each must fail an assertion rather
  than crash or fail compilation; each restored baseline must pass again.
- Native x86-64/AArch64 runs, a Clang ASan/UBSan wrapper run, and a separate
  ASan/UBSan **actual VM/parser** run. This is not a claim of exhaustive fuzzing.
- Byte-identical manifests and native transcripts across architectures and
  sanitizer builds; both compiled-language transcripts and compiled BOCs are
  also compared across x86-64 and AArch64. Different languages may legitimately
  have different compiler overhead, so their gas is not compared to each other.

Binding failures no longer suppress the independent mutation step. Artifacts
are retained even on failure, but the determinism job still requires all its
upstream checks to succeed. A missing artifact cannot turn this gate green.

## Fixed gas and measured CPU cost

The protocol price remains **50,000 + 1 per decoded byte**, plus ordinary VM
cell load and instruction costs. It is not chosen dynamically, benchmarked by
validators, or changed in response to local CPU type.

`--benchmark` additionally writes `<transcript>.calibration.json`. For each
well-formed public vector (both valid and invalid), it measures the full VM
invocation with seven batches of eight executions and reports the median.
Input cells are constructed outside the timer; VM decoding, verification,
stack handling and a fresh VM load cache remain inside. Source fixtures are
bounded by the public 8,192-byte message profile; this is not a sweep of all
possible adversarial ML-DSA public seeds.

The comparison baseline is the existing TOS Ed25519 implementation over a
32-byte message, using a fixed public TEST key. Ed25519's paid-call tariff is
4,000 gas; its initial free-call allowance is deliberately not used here.
The normalized cost is:

```
(full PQ VM median microseconds / 50,000)
    / (Ed25519 wrapper median microseconds / 4,000)
```

Counting only the PQ base, ignoring additional byte and cell-load charges,
and comparing the complete PQ VM path against only the Ed25519 wrapper are
both conservative. The calibration job requires the worst observed ratio to
be below 1.0. A failure is a review signal; it never changes the fixed opcode
price. Shared-runner noise can affect this performance gate but cannot affect
VM verdicts, gas or state transcripts. Inspect the archived per-case results.

Three workload samples repeat the short valid case, maximum valid case and a
full-length invalid case within a **synthetic 1,000,000-gas budget**. They report
actual gas and median CPU cost, including repeated-cell load discounts. This
budget is a model, not an assertion about the running network's block limit.
It also excludes transaction scheduling, serialization, network and storage
costs; it is not an end-to-end block-throughput benchmark.

## Release boundary

Green native CI establishes the implementation and test matrix above on the
reported runners. It is not NIST/FIPS certification, an independent security
audit, universal hardware performance proof, or completed PQ wallet support.
Before activation, operators must confirm the selected network limits, relayer
funding and fee-abuse design (the base fee exceeds the usual external admission
credit), unsupported Rust-VM routes, and the eventual PQ authentication module.
Production-hardware load testing remains deployment-specific; runner evidence
must not be relabeled as a measurement of an operator's validator machines.
