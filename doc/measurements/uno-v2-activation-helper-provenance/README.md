# Shared activation observation calibration

The adjacent stdout/stderr and provenance are unchanged copies of the real
scoped-resolver run supplied by the parallel harness track. The fixture source
commit, binary and production-source hashes are recorded in the provenance.
These are resolver observations, not collator execution or publication evidence.
The copied provenance JSON predates the final row-1 decision; its sentence
calling unregistered/off unknown is historical, not the current expectation.
It remains byte-for-byte intact. The shared four-row check is the answer table.
Column 5 is retained provenance; configuration-pairing assertions belong to the
calling harness rather than this rejection classifier.

The shared helper consumes row 3 (registered, capability off) as activation
rejection and row 2 (unregistered, capability on) as the specifically recognized
earlier block-engine lookup failure. Both numeric codes are observed -7201.

Row 1 is the second explicitly recognized unregistered-engine failure:
`missing workchain engine
Basic:1129206833 for workchain 2` is produced by `resolve()`'s account-compute
lookup. With capability off, the ingress table is empty; in this row neither
an account engine nor a block engine is registered, so `resolve_scoped()` selects that account-compute path rather than
calling `resolve_block()` and its activation check. This is a different failure,
not a different wrapping of activation rejection. Under the owner's final
calibration specification both exact unregistered messages return false; no
prefix pattern or arbitrary engine identity is accepted. Row 4 is success and
throws rather than entering either rejection bucket. All four raw observations
are covered by the colocated self-check. Unknown
future forms likewise throw with the received boundary, code and message.

The helper only accepts explicitly observed error statuses. In particular,
raw registry `Status::Error(message)` has numeric code zero; the numeric code
is not the Status error discriminator. The default API targets the production
scoped resolver, with explicit boundary selection required for other supported
observation formats. No arbitrary prefix removal or generic local-error bucket
is permitted. Source-origin checking and self-checks must run alongside users
of the classifier; neither replaces measurement of the real execution path.

The producer scan on this source found exactly one occurrence:
`crypto/block/workchain-execution-dispatch.cpp:504`, inside
`validate_workchain_block_activation`. The scan covers C++ sources in
crypto/block, validator and validator-engine, not every file in the repository.
The collator prefix is independently checked at its production call site.
Consumers use `check_scoped_probe_output(stdout)` for the four-row expectations;
they must not maintain a second answer table. Run the colocated self-check with
`python3 crypto/test/workchain-activation-rejection.py -v` and reproducible
mutation controls with `python3 crypto/test/workchain-activation-helper-controls.py`.
