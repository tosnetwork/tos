# First-seam adapter identity checkpoint

This is a runtime checkpoint on the uncommitted first-seam shape, based on
`3822c76ed`. `source-and-binary.sha256` identifies the measured bytes. It is not
final restored-source regression evidence or an admission/replay acceptance.

The passive GDB observer checks this binary's disassembly before reading the
adapter member at offset 0x610. This is an x86-64 binary-specific observation,
not a portable ABI. `check.py` compares actual nonzero pointer values across
readiness return, old-state unpacking, configuration fetching and release.
There is one bind call, one adapter throughout these stages, and a null member
after release. No proof-admission token exists on this live path yet; this does
not claim live `inspected_by` or execution coverage.

Both configuration callbacks receive the same authenticated `Config` object
and registered engine. Their recorded stacks distinguish readiness binding
from the later `validate_required_workchains` capability/readiness check.
The latter resolves another binding but constructs no adapter. In this fixture
the callback returns a fresh parsed configuration object each time: equal
authenticated input does not imply shared identity of those parsed objects.

The final typed result is local failure at the required-workchain refusal,
before the two remaining collator visitor refusals. No transactions execute
and no candidate is exported. Authenticated genesis/instance installation is
still missing downstream; it is not the directly observed refusal here.
The three validator visitor refusals remain unchanged.

The readiness expectation is now two config callbacks and zero executions;
its diagnostic no longer claims the earliest-readiness stop. Ownership counts
remain numerically 1/2/1 but the last sample is now terminal release, not release
inside the initial binding branch. The new binding sidecar asserts retention
through old-state unpacking and terminal release separately.

The first edited typed-result expectation omitted the existing `collate `
prefix and failed. That test-authoring error is not mutation evidence. Reading
the actual result format corrected it; the final readiness run passes 1/1.
No production source or binary was changed during these diagnostic runs.

The fixture driver's delivery hash is pinned separately in
`../uno-v2-first-seam-controls/final-source-and-binaries.sha256`, together with
the actual indirect executables. The final ordinary regression there includes
the readiness driver. `readiness-final.log` here is only the earlier 1/1
checkpoint; it is not a replacement for the final driver regression.
