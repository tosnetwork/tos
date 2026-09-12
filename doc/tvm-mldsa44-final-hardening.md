# Final validation-gate hardening for the ML-DSA VM PR

This supplement preserves the existing `F93100` ABI, version-16 activation
gate, fixed tariff, pinned backend, full-VM sanitizer and calibration design.
It does not change account code, the cryptographic verifier or chain config.

## Canonical byte-chain negative control

The invalid short-intermediate-cell test must carry the **same 1,312 public-key
bytes** as the successful control, split after the first byte. Prepending a
byte to an otherwise canonical key produces 1,313 bytes: the length guard can
then reject it even if the canonical-chunk guard is removed. That weaker test
does not isolate canonical parsing. The corrected case does.

A seventh guard mutation removes only the full-intermediate-chunk requirement.
It must compile, fail the corrected test assertion, and return to a successful
baseline after restoration. The existing six mutations remain unchanged.

## No silent command-line fallback

The native test binary accepts only the documented argument forms. In
particular, `--cod` must not silently run the raw instruction instead of a
compiled contract. The wrapper-only binary rejects `--code` altogether.
`check_cli.py` first requires real successful corpus executions, then checks
explicit exit-code-1 assertion failures for invalid modes. Crashes or missing
binaries cannot count as expected rejection.

## A required final gate must not be skipped

The `determinism` job always runs its prerequisite check and rejects every
upstream result other than `success`. It also rejects an incomplete prerequisite
set. Without this check, a failed prerequisite can skip the final job, which
GitHub can treat as satisfying a required status check. The byte-for-byte
comparisons remain unchanged and execute only after all required jobs pass.

Changes under `tol/**` now trigger this workflow because it ships and verifies
a public Tol binding. New code and test definitions are not proof of execution:
all seven mutations, CLI rejection tests, native jobs, language bindings and
cross-architecture comparisons must pass on the final pushed commit.
