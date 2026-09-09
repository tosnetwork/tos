# Range-shape review disposition

The independent file-level cryptographic review found no defect in the local
deterministic range verifier. Its caller had an unchecked consistency dependency:
`Vec::resize` could silently truncate commitments if relation construction and
shape metadata diverged. Current valid relation shapes did not trigger truncation.

Before padding, the caller now requires exactly six range commitments for SEND
and checked `2 * k + 4` for COLLECT, and requires that count not exceed the padded
capacity. A disagreement returns the existing internal-contract `ARGUMENTS`
result before modifying the vector. It is not classified as malformed candidate
data. No equation, transcript event, ABI, dependency, or frozen vector changed.

## Evidence

`measurements/uno-v2-range-shape-controls.json` records four individually applied
and restored controls, each with observed and independently reconstructed mutant
SHA-256, restored SHA-256, and a compiled test failure (exit 101):

- Remove exact count checking: a missing constraint is incorrectly accepted.
- Remove padded-capacity checking: six constraints are silently truncated to four.
- Permit excess constraints: an extra commitment is incorrectly accepted.
- Add a commitment in real relation construction: the existing full SEND/COLLECT
  test fails before proof construction, proving the production caller uses the guard.

The positive control preserves all six commitments and appends exactly two
identities. Every rejection leaves the vector unchanged. Restored source SHA-256:
`559132dc5d338dcf9807d5b72270a1304b77a40352d2dca871ad169e4dd86090`.

Final release archive and C++ ABI target were rebuilt with offline Cargo.
CTest passed all five selected gates: `test-uno-crypto-abi-real`,
`test-uno-crypto-rust`, `test-uno-crypto-symbols`,
`test-uno-crypto-kernel-gates`, and `test-uno-crypto-header-guard`.
Rust coverage includes the full supported COLLECT sizes and frozen vectors.
The archived mutation executions are one-time evidence, not a new recurring
mutation facility; the restored Rust test runs through the existing CTest gate.

## Remaining scope

File-level review does not establish completeness of the full application
relations, all five local patch rationales, or absence of RNG throughout the
indirect verification call graph. Those remain separate open audit obligations.
No milestone or live execution acceptance is claimed. Raw review material remains
outside this repository. The in-progress aggregate-fee settlement is separate.
