# Activation context infrastructure: pre-integration measurements

This is not a completed activation-control unit or live I13e acceptance.
The shared classifier integration is intentionally pending in this source commit.

Twelve isolated Python schema-check removals each fail exactly their designated
unit vector. They are syntax-checked, restored byte-for-byte, and reapplied to
reproduce the archived mutant hash. These synthetic vectors are NOT host state,
transaction, candidate-export or activation observations. See measurement.json.

The separate C++ fixture calls the actual production scoped resolver. Its output
is unchanged raw code/message data, with internally constructed configuration root
hashes. probe-provenance.json binds the committed fixture, actual binary, and
source/compile dependencies. Both enabled/disabled configurations are internal
cell dictionaries, with no deployment configuration source. Source commit
88f91b2a3 and the complete stdout/stderr are available to the shared helper owner
for its real-input self-check. No B classifier is introduced.

Registered/disabled is row 3; unregistered/enabled is row 2. Registered/enabled
resolves successfully. Unregistered/disabled is deliberately left unclassified
rather than normalized to a known message. No zero-transaction or no-export
observation is invented for this resolver-only probe.

## Superseded classification note

The original statement above and in probe-provenance.json that row 1 remained
unclassified is preserved as historical context. The coordinator subsequently
confirmed both earlier failure forms. Shared helper commit c51936148 classifies
rows 1/2 as False, row 3 as True, and success/unknown forms as exceptions. B now
uses shared check_scoped_probe_output and maintains no independent answer table.
The raw stdout and its provenance hashes are unchanged.
