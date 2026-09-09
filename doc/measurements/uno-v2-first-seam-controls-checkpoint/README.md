# Superseded checkpoints: not delivery evidence

Do not use any record in this directory as final-source mutation evidence.
The final strengthened test and all rerun controls are in
`../uno-v2-first-seam-controls/`, with their executable restore-audit script.

The initial `checkpoint-combined-entry-indentation` attempt did produce the
intended count-2 failure, but its inverse patch lost four leading spaces:
baseline SHA256 `14cca94c...` differed from the then-restored `b4d19f0a...`.
That audit failure was caught; the original bytes were restored before further
work. This attempt is not counted as successful restoration evidence.

The other six records predate the strengthened input fixture and effects/output
budget scenarios. Some production-header hashes still match current source;
their test-source hashes do not. Matching one header does not make these records
current. The malformed-input negative was replaced with valid framing and a
different candidate so removing the binding guard now causes erroneous acceptance.
Every claimed final control was rerun after that change.
