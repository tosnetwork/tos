# Semantic measurement unit review

Review: Claude Code 2.1.263, read-only against badb29085. Original response is
retained outside this repository in `~/memo/reviews/uno-d3-semantic-unit-review.txt`
and `~/memo/reviews/uno-d3-semantic-unit-followup.txt`. This unit changes a test-only
meter and its checks, not production admission, configuration or wire semantics.

## Disposition

- Accepted: register the lightweight self-test in CTest and the all-tests build
  dependency graph. The timed measurement remains manual. This follows the
  already requested A6-1 CI gate; no new M0 protocol choice is required.
- Accepted: retain explicit diagnostics and exit status for failing arithmetic
  checks. Empty old mutation log files alone were insufficient durable evidence;
  the old recorded timings are not changed or represented as newly measured.
- Accepted: exercise overflow through actual admission, not just standalone
  arithmetic helpers. Metadata with a proof multiplication overflow must reject
  without dereferencing the small fixture buffers. Two individually admissible
  requests with payloads greater than half SIZE_MAX must reject their aggregate,
  publish no usage result and invoke no backend.
- Corrected review suggestion: action_count near SIZE_MAX/2 cannot reach the
  aggregate check because per-request proof sizing already overflows. The test
  uses SIZE_MAX/6312 + 1 actions, validates each request individually, then tests
  the pair. The fixture proves the intended branch is reachable.
- Accepted: validate canonical proof size before computing payload from it;
  explicitly initialize ABI version rather than relying on version zero.
- Preserved limitations: no production cost weights, structural limits or schema
  follow from fixed two-Action data. That remains an open measurement gate, not a
  decision to withhold the measured component data requested by the owner.
- Deferred to a separate measurement unit: clock-floor calibration and strict
  failure handling for unavailable RSS. Existing results explicitly remain
  process high-water values for their recorded binary, not a phase memory bound.

The addition guard subtracts from SIZE_MAX only after both operands have size_t
type, so the minuend is always at least the first operand. Multiplication divides
only after testing the first operand nonzero. Failed operations do not publish an
output. No money arithmetic or production exception mapping changes in this unit.

Self-test backend counts use checked addition. The raw metadata fixtures never
reach the real ABI; their buffer lengths intentionally cannot support their claimed
sizes. Zero-backend assertions and typed Overflow results enforce this boundary.
The standalone run helper's tests do not by themselves prove every production or
measurement caller's ordering; the actual measurement loop remains separately
inspected, not presented as production entry-point coverage.

## Observed red checks

Each mutation was applied independently, built successfully, and then the test
was run with its exit status recorded. All were restored before final tests:

| Removed property | Observed result |
|---|---|
| Admission aggregate-byte checked add | Aggregate case called backend twice; exit 1 |
| Admission proof-size checked multiply | Single-request overflow misclassified; zero backend calls; exit 1 |
| Checked-add helper guard | Aggregate overflow called backend twice; exit 1 |
| Checked-multiply helper guard | Single-request overflow misclassified; exit 1 |
| CTest self-test registration | Actual CTest manifest lacked required entry; exit 1 |
| all-tests build dependency | Actual Ninja graph lacked required executable; exit 1 |

These are local test failures, not consensus rejections or proof-verifier results.
The missing build dependency and missing test registration are tested separately.
Evidence is committed in `measurements/uno-d3-unit-mutations.tar.gz`: six red
logs with diagnostics and explicit exit codes, plus the restored build and CTest
logs (two tests passed). Review transcripts remain outside this repository.

The follow-up review found no blocking code defect and required this durable
archive before submission. Its additional per-request payload-overflow and
shape-predicate witnesses remain deferred to a subsequent test unit. The checked
Action-size multiplication is currently dominated by the larger proof-size
multiplier; retaining checked arithmetic does not imply independent coverage of
that unreachable overflow branch. No claim of complete guard coverage is made.

The subsequent payload-overflow unit closes the per-request witness gap: proof
and Action sizes are separately representable, their sum is not. Replacing only
the payload checked add with raw addition invokes the stub backend once and
exits 1; the restored CTest passes. Four build/test logs are retained in
`measurements/uno-d3-payload-mutations.tar.gz`. These are historical manual
mutation observations, not an automated mutation facility or a recurring CI
mutation gate. The regression self-test itself is registered in CTest.

Read-only review found no blocking issue. Its subtraction-invariant and guard
comment clarifications were applied. The suggested derived denominator remains
the explicit 3156 fixture literal: the 884-byte ABI static assertion and fixture
premise checks make layout drift fail, without introducing unchecked arithmetic.
The transcript is in `~/memo/reviews/uno-d3-payload-overflow-review.txt`.
